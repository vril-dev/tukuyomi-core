use super::*;
use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use tokio::sync::Semaphore;
use tokio::sync::oneshot::error::TryRecvError as SlotError;
use tukuyomi_kernel::{Config, Reason};

use crate::inspect::slot::{Pending, deliver, restart_line, submit};
use crate::log::{Format, start_logger};
use crate::rules::routes::Route;

const MS: Duration = Duration::from_millis(1);
const SEC: Duration = Duration::from_secs(1);
const HOUR: Duration = Duration::from_secs(3600);
/// Permits of the inspection pool and bytes of the byte budget in these tests.
const INSPECT: usize = 16;
const BUDGET: usize = 10_000;

/// The generation and the mode that a verdict of `mode` is told to come from.
fn judge(mode: bundle::Mode) -> Judge {
    Judge {
        generation: Fingerprint::from_hex(&[b'7'; 64]).unwrap(),
        mode,
    }
}

/// The outcome of the answer on `slot`.
fn outcome(slot: &mut oneshot::Receiver<Answer>) -> Outcome {
    answer(slot).outcome
}

/// Waits for the answer in a reply slot; fails when the sender goes without one or nothing comes in time.
fn answer<T>(slot: &mut oneshot::Receiver<T>) -> T {
    let until = Instant::now() + 30 * SEC;
    loop {
        match slot.try_recv() {
            Ok(value) => return value,
            Err(SlotError::Empty) => {}
            Err(SlotError::Closed) => panic!("the sender went away without an answer"),
        }
        assert!(Instant::now() < until, "no answer in time");
        thread::sleep(2 * MS);
    }
}

/// The fingerprint that is `n` in every byte.
fn generation(n: u8) -> Fingerprint {
    Fingerprint::from_hex(format!("{n:02x}").repeat(32).as_bytes()).unwrap()
}

fn eventually(what: &str, mut ok: impl FnMut() -> bool) {
    let until = Instant::now() + 30 * SEC;
    while !ok() {
        assert!(Instant::now() < until, "{what}");
        thread::sleep(2 * MS);
    }
}

/// The pools that tickets take their permits from.
struct World {
    inspect: Arc<Semaphore>,
    budget: Arc<Semaphore>,
}

/// A ticket, and what its connection keeps: the reply slot and its share of the body.
struct Made {
    ticket: Ticket,
    answer: oneshot::Receiver<Answer>,
    body: Arc<BodyHold>,
}

impl World {
    fn new() -> World {
        World {
            inspect: Arc::new(Semaphore::new(INSPECT)),
            budget: Arc::new(Semaphore::new(BUDGET)),
        }
    }

    /// A ticket for a GET of `uri` whose body is `n` bytes. It takes one inspection permit and, for the
    /// kernel's copy and for the body, `n` bytes of budget each.
    fn ticket(&self, uri: &'static [u8], n: usize) -> Made {
        let n = u32::try_from(n).unwrap();
        let take = |bytes| self.budget.clone().try_acquire_many_owned(bytes).unwrap();
        let body = Arc::new(BodyHold::new(Bytes::from(vec![b'x'; n as usize]), take(n)));
        let hold = Hold::new(self.inspect.clone().try_acquire_owned().unwrap(), take(n));
        let (reply, answer) = oneshot::channel();
        let req = InspectReq {
            client: "192.0.2.10:40000".parse().unwrap(),
            server: "192.0.2.1:8080".parse().unwrap(),
            method: Bytes::from_static(b"GET"),
            uri: Bytes::from_static(uri),
            headers: vec![(
                Bytes::from_static(b"Host"),
                Bytes::from_static(b"example.test"),
            )],
            body: Arc::clone(&body),
            cut: false,
            proto: b"HTTP/1.1",
        };
        Made {
            ticket: Ticket { req, reply, hold },
            answer,
            body,
        }
    }

    /// Free permits of the inspection pool and free bytes of the budget.
    fn free(&self) -> (usize, usize) {
        (
            self.inspect.available_permits(),
            self.budget.available_permits(),
        )
    }
}

/// What the stand-in kernel saw of one submitted request.
#[derive(Debug, PartialEq, Eq)]
struct Seen {
    client: Vec<u8>,
    client_port: u16,
    server: Vec<u8>,
    server_port: u16,
    method: Vec<u8>,
    uri: Vec<u8>,
    proto: Vec<u8>,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    body: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Call {
    Submit(ReqId),
    Cancel(ReqId),
    Poll,
    Shutdown(Instant),
}

/// A kernel that records every call and answers as the test says.
struct Fake {
    calls: Vec<Call>,
    seen: Vec<Seen>,
    next: ReqId,
    /// Ids to hand out before counting on.
    ids: VecDeque<ReqId>,
    refuse: VecDeque<Refused>,
    /// The results of the next polls, one list for each.
    polls: VecDeque<Vec<(ReqId, Verdict)>>,
    until: Vec<Instant>,
    phase: Phase,
    inc: u32,
    restarts: u32,
    records: usize,
    at_shutdown: Vec<(ReqId, Verdict)>,
    detail: Option<Vec<u8>>,
    /// The deadlines of `shutdown`, seen from outside: a kernel that is retired is stopped on another thread.
    shut: Arc<Mutex<Vec<Instant>>>,
}

impl Fake {
    fn new() -> Fake {
        Fake {
            calls: Vec::new(),
            seen: Vec::new(),
            next: 0,
            ids: VecDeque::new(),
            refuse: VecDeque::new(),
            polls: VecDeque::new(),
            until: Vec::new(),
            phase: Phase::Starting,
            inc: 1,
            restarts: 0,
            records: 0,
            at_shutdown: Vec::new(),
            detail: None,
            shut: Arc::default(),
        }
    }

    fn shutdowns(&self) -> Vec<Instant> {
        self.calls
            .iter()
            .filter_map(|c| match c {
                Call::Shutdown(by) => Some(*by),
                _ => None,
            })
            .collect()
    }
}

impl Kernel for Fake {
    fn create(_cfg: Config) -> Result<Fake, &'static str> {
        Ok(Fake::new())
    }

    fn submit(&mut self, req: &Request<'_>) -> Result<ReqId, Refused> {
        self.seen.push(Seen {
            client: req.client_addr.to_vec(),
            client_port: req.client_port,
            server: req.server_addr.to_vec(),
            server_port: req.server_port,
            method: req.method.to_vec(),
            uri: req.uri.to_vec(),
            proto: req.proto.to_vec(),
            headers: req
                .headers
                .iter()
                .map(|(n, v)| (n.to_vec(), v.to_vec()))
                .collect(),
            body: req.body.to_vec(),
        });
        if let Some(refused) = self.refuse.pop_front() {
            return Err(refused);
        }
        let id = self.ids.pop_front().unwrap_or(self.next);
        self.next = id + 1;
        self.calls.push(Call::Submit(id));
        Ok(id)
    }

    fn cancel(&mut self, id: ReqId) {
        self.calls.push(Call::Cancel(id));
    }

    fn poll(&mut self, until: Instant) -> Vec<(ReqId, Verdict)> {
        self.calls.push(Call::Poll);
        self.until.push(until);
        self.polls.pop_front().unwrap_or_default()
    }

    fn status(&self) -> Status {
        Status {
            phase: self.phase,
            inc: self.inc,
            restarts: self.restarts,
            waiting: 0,
            held: 0,
            records: self.records,
        }
    }

    fn start_detail(&self) -> Option<Vec<u8>> {
        self.detail.clone()
    }

    fn shutdown(&mut self, deadline: Instant) -> Shutdown {
        self.calls.push(Call::Shutdown(deadline));
        self.shut.lock().unwrap().push(deadline);
        // The exit that shutdown confirms numbers the next incarnation.
        self.inc += 1;
        Shutdown {
            results: mem::take(&mut self.at_shutdown),
            phase: Phase::Stopped,
            bye: true,
            exit_confirmed: true,
            dir_removed: true,
            held_left: 0,
            waiting_left: 0,
        }
    }
}

fn limits(slice: Duration) -> Limits {
    Limits {
        slice,
        ready_wait: HOUR,
        stop_inspect: HOUR,
    }
}

/// A driver core on the stand-in kernel, the sender of its channel and the receivers of its signals.
struct Rig {
    core: Core<Fake>,
    tx: Option<SyncSender<Msg>>,
    world: World,
}

impl Rig {
    /// An intake takes `wait_queue + 1` messages; the channel has room for `room`.
    fn new(wait_queue: usize, room: usize) -> Rig {
        let (tx, rx) = sync_channel(room);
        let core = Core::new(
            Slot::new(generation(1), bundle::Mode::Block, Fake::new()),
            SharedRoutes::new(Routes::default()),
            rx,
            Signals::Told { _failed: None },
            start_logger(Format::Json).unwrap(),
            limits(20 * MS),
            30 * MS,
            wait_queue + 1,
        );
        Rig {
            core,
            tx: Some(tx),
            world: World::new(),
        }
    }

    fn send(&self, msg: Msg) {
        let sent = self.tx.as_ref().unwrap().try_send(msg).is_ok();
        assert!(sent, "the channel took no message");
    }

    /// The last sender goes.
    fn close(&mut self) {
        self.tx = None;
    }

    /// Sends a ticket whose connection is gone already.
    fn send_closed(&self) {
        let made = self.world.ticket(b"/", 0);
        drop(made.answer);
        self.send(Msg::Ticket(made.ticket));
    }

    /// Messages that are left in the channel (taking them out).
    fn left(&self) -> usize {
        self.core.rx.try_iter().count()
    }
}

// ---- intake ----

#[test]
fn a_ticket_closed_before_submit_is_dropped_and_gives_back_what_it_held() {
    let mut r = Rig::new(4, 8);
    let live = r.world.ticket(b"/live", 7);
    let gone = r.world.ticket(b"/gone", 9);
    drop(gone.answer);
    drop(gone.body);
    r.send(Msg::Ticket(gone.ticket));
    r.send(Msg::Ticket(live.ticket));
    // one inspection permit each; the body and the copy of each take their bytes
    assert_eq!(r.world.free(), (INSPECT - 2, BUDGET - 14 - 18));
    r.core.intake(None).unwrap();
    let uris: Vec<_> = r
        .core
        .active
        .kernel
        .seen
        .iter()
        .map(|s| s.uri.clone())
        .collect();
    assert_eq!(uris, vec![b"/live".to_vec()]);
    assert_eq!(r.core.active.pending.len(), 1);
    // the one that was never submitted gave back all it held at once; the submitted one holds its own
    assert_eq!(r.world.free(), (INSPECT - 1, BUDGET - 14));
}

#[test]
fn one_intake_takes_at_most_wait_queue_plus_one_messages() {
    // wait_queue 4: five messages; the channel here holds far more than a real one
    let mut r = Rig::new(4, 64);
    for _ in 0..12 {
        r.send_closed();
    }
    r.core.intake(None).unwrap();
    assert_eq!(r.left(), 7);

    // exactly five are taken whole
    let mut r = Rig::new(4, 64);
    for _ in 0..5 {
        r.send_closed();
    }
    r.core.intake(None).unwrap();
    assert_eq!(r.left(), 0);
}

#[test]
fn the_kernel_gets_the_bytes_of_the_ticket() {
    let world = World::new();
    for (client, want_client, port) in [
        ("192.0.2.10:40000", &b"192.0.2.10"[..], 40000),
        ("[::ffff:192.0.2.77]:5000", &b"192.0.2.77"[..], 5000),
    ] {
        let mut made = world.ticket(b"/p?q=1", 4);
        made.ticket.req.client = client.parse().unwrap();
        let mut kernel = Fake::new();
        assert_eq!(submit(&mut kernel, &made.ticket.req), Ok(0));
        assert_eq!(
            kernel.seen,
            vec![Seen {
                client: want_client.to_vec(),
                client_port: port,
                server: b"192.0.2.1".to_vec(),
                server_port: 8080,
                method: b"GET".to_vec(),
                uri: b"/p?q=1".to_vec(),
                proto: b"HTTP/1.1".to_vec(),
                headers: vec![(b"Host".to_vec(), b"example.test".to_vec())],
                body: b"xxxx".to_vec(),
            }]
        );
    }
}

#[test]
fn the_kernel_gets_the_protocol_of_the_request() {
    let world = World::new();
    let mut made = world.ticket(b"/", 0);
    made.ticket.req.proto = b"HTTP/1.0";
    let mut kernel = Fake::new();
    assert_eq!(submit(&mut kernel, &made.ticket.req), Ok(0));
    assert_eq!(kernel.seen[0].proto, b"HTTP/1.0");
}

#[test]
fn a_closed_handle_gives_no_sender_and_the_driver_sees_the_last_sender_go() {
    let (tx, rx) = sync_channel::<Msg>(1);
    let ingress = Ingress::new(tx);
    let watcher = ingress.watch();
    let one = ingress.sender().expect("a sender before the close");
    assert!(!ingress.is_closed() && !*watcher.borrow());
    ingress.close();
    assert!(ingress.sender().is_none());
    assert!(ingress.is_closed() && *watcher.borrow());
    // A request that started before the close still holds its sender; the driver is told when it is dropped.
    assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
    drop(one);
    assert!(matches!(rx.try_recv(), Err(TryRecvError::Disconnected)));
    // Closing again does nothing more.
    ingress.close();
}

// ---- cancel and delivery ----

#[test]
fn cancel_is_called_once_for_each_abandoned_ticket() {
    let mut r = Rig::new(4, 8);
    let a = r.world.ticket(b"/a", 3);
    let b = r.world.ticket(b"/b", 3);
    r.send(Msg::Ticket(a.ticket));
    r.send(Msg::Ticket(b.ticket));
    r.core.round().unwrap();
    assert_eq!(
        r.core.active.kernel.calls,
        vec![Call::Submit(0), Call::Submit(1), Call::Poll]
    );

    // a's connection goes away: one cancel, in front of the next step, and never one for b
    drop(a.answer);
    for _ in 0..3 {
        r.core.round().unwrap();
    }
    assert_eq!(
        r.core.active.kernel.calls,
        vec![
            Call::Submit(0),
            Call::Submit(1),
            Call::Poll,
            Call::Cancel(0),
            Call::Poll,
            Call::Poll,
            Call::Poll
        ]
    );
    // a cancelled ticket keeps what it holds until its result comes out: a and b hold one permit each,
    // and the body and the copy of each take 3 bytes
    assert_eq!(r.world.free(), (INSPECT - 2, BUDGET - 12));

    r.core
        .active
        .kernel
        .polls
        .push_back(vec![(0, Verdict::Uninspectable(Reason::Cancelled))]);
    r.core.round().unwrap();
    // a's permit and copy are back; its body is the connection's until it lets go
    assert_eq!(r.world.free(), (INSPECT - 1, BUDGET - 3 - 6));
    drop(a.body);
    assert_eq!(r.world.free(), (INSPECT - 1, BUDGET - 6));
    assert_eq!(r.core.active.pending.len(), 1);
}

#[test]
fn a_result_goes_to_the_ticket_it_belongs_to() {
    let mut r = Rig::new(4, 8);
    r.core.active.kernel.ids = VecDeque::from([5, 2]);
    let mut a = r.world.ticket(b"/a", 0);
    let mut b = r.world.ticket(b"/b", 0);
    r.send(Msg::Ticket(a.ticket));
    r.send(Msg::Ticket(b.ticket));
    let blocked = Verdict::Block {
        phase: 1,
        rule_id: 9201,
        status: 403,
    };
    r.core
        .active
        .kernel
        .polls
        .push_back(vec![(2, blocked), (5, Verdict::Allow)]);
    r.core.round().unwrap();
    assert_eq!(outcome(&mut a.answer), Outcome::Verdict(Verdict::Allow));
    assert_eq!(outcome(&mut b.answer), Outcome::Verdict(blocked));
    assert!(r.core.active.pending.is_empty());
}

const DETECTED: Verdict = Verdict::Detected {
    rule_id: 949110,
    status: 403,
};

#[test]
fn a_detection_from_a_generation_that_blocks_is_not_inspectable_and_one_that_detects_goes_on() {
    // The generation blocks: the inspector is not believed, and the line is made once, after a step.
    let mut r = Rig::new(4, 8);
    let mut a = r.world.ticket(b"/a", 0);
    let mut b = r.world.ticket(b"/b", 0);
    r.send(Msg::Ticket(a.ticket));
    r.send(Msg::Ticket(b.ticket));
    r.core.intake(None).unwrap();
    r.core
        .active
        .kernel
        .polls
        .push_back(vec![(0, DETECTED), (1, Verdict::Allow)]);
    r.core.active.step(Instant::now()).unwrap();
    let not_inspectable = Verdict::Uninspectable(Reason::Protocol);
    assert_eq!(outcome(&mut a.answer), Outcome::Verdict(not_inspectable));
    assert_eq!(outcome(&mut b.answer), Outcome::Verdict(Verdict::Allow));
    let line = r.core.active.note_turned().expect("the line is made");
    assert!(line.contains(&generation(1).hex()), "{line}");
    assert_eq!(r.core.active.note_turned(), None);

    // The generation detects: the detection goes on as it is, and no line is made.
    let mut r = Rig::new(4, 8);
    r.core.active.mode = bundle::Mode::Detect;
    let mut a = r.world.ticket(b"/a", 0);
    r.send(Msg::Ticket(a.ticket));
    r.core.intake(None).unwrap();
    r.core.active.kernel.polls.push_back(vec![(0, DETECTED)]);
    r.core.active.step(Instant::now()).unwrap();
    assert_eq!(outcome(&mut a.answer), Outcome::Verdict(DETECTED));
    assert_eq!(r.core.active.note_turned(), None);

    // What `shutdown` decides is checked the same way.
    let mut r = Rig::new(4, 8);
    let mut a = r.world.ticket(b"/a", 0);
    r.send(Msg::Ticket(a.ticket));
    r.core.round().unwrap();
    r.core.active.kernel.at_shutdown = vec![(0, DETECTED)];
    r.send(Msg::Stop {
        inspect_by: Instant::now(),
    });
    r.core.round().unwrap().expect("the deadline is reached");
    assert_eq!(outcome(&mut a.answer), Outcome::Verdict(not_inspectable));
}

#[test]
fn a_result_for_an_unknown_request_is_fatal() {
    let world = World::new();
    let mut pending = BTreeMap::new();
    let mut made = world.ticket(b"/", 0);
    pending.insert(
        1,
        Pending {
            ticket: made.ticket,
            cancelled: false,
        },
    );
    // the known result is delivered, the unknown one stops the delivery
    let unknown = Err("result for an unknown request");
    assert_eq!(
        deliver(
            &mut pending,
            &[(1, Verdict::Allow), (2, Verdict::Allow)],
            judge(bundle::Mode::Block)
        ),
        unknown
    );
    // the verdict comes with the generation and the mode of the rules that gave it
    assert_eq!(
        answer(&mut made.answer),
        Answer {
            outcome: Outcome::Verdict(Verdict::Allow),
            by: Some(judge(bundle::Mode::Block)),
        }
    );
    // a result comes out once: the same id again is unknown
    assert_eq!(
        deliver(
            &mut pending,
            &[(1, Verdict::Allow)],
            judge(bundle::Mode::Block)
        ),
        unknown
    );
    assert_eq!(
        deliver(&mut pending, &[], judge(bundle::Mode::Block)),
        Ok(false)
    );
}

#[test]
fn a_duplicate_id_is_fatal() {
    let mut r = Rig::new(4, 8);
    r.core.active.kernel.ids = VecDeque::from([3, 3]);
    let a = r.world.ticket(b"/a", 0);
    let b = r.world.ticket(b"/b", 0);
    r.send(Msg::Ticket(a.ticket));
    r.send(Msg::Ticket(b.ticket));
    assert_eq!(r.core.intake(None), Err("duplicate request id"));
    // the first ticket is still the one in the table
    assert_eq!(r.core.active.pending.len(), 1);
}

// ---- routes ----

fn route(host: Option<&str>, path: &str) -> Route {
    Route::new(host, path).unwrap()
}

/// A table of routes without a host, one for each path.
fn routes(paths: &[&str]) -> Routes {
    Routes::new(paths.iter().map(|path| route(None, path)).collect()).unwrap()
}

#[test]
fn the_shared_routes_follow_the_generation_that_serves() {
    let mut r = Rig::new(4, 8);
    r.core.routes.replace(routes(&["/old/"]));
    let mut told = r.send_switch_with(2, routes(&["/new/"]));
    r.core.round().unwrap();
    // While the new kernel starts, the table is the one of the kernel that serves.
    assert_eq!(*r.core.routes.current(), routes(&["/old/"]));
    r.other().phase = Phase::Ready;
    r.core.round().unwrap();
    assert_eq!(r.core.active.generation, generation(2));
    assert_eq!(*r.core.routes.current(), routes(&["/new/"]));
    assert_eq!(settle(&mut r, &mut told), Switched::Yes);

    // A new kernel that fails to start, or is late, leaves the table as it is.
    let mut told = r.send_switch_with(3, routes(&["/third/"]));
    r.core.round().unwrap();
    r.other().phase = Phase::Failed(Failure::Exit(11));
    assert_eq!(settle(&mut r, &mut told), Switched::No);
    assert_eq!(*r.core.routes.current(), routes(&["/new/"]));
    r.core.limits.ready_wait = Duration::ZERO;
    let mut told = r.send_switch_with(4, routes(&["/fourth/"]));
    assert_eq!(settle(&mut r, &mut told), Switched::No);
    assert_eq!(*r.core.routes.current(), routes(&["/new/"]));
    assert_eq!(r.core.active.generation, generation(2));
}

// ---- the wait rule ----

#[test]
fn the_restart_line_is_given_for_a_new_incarnation_and_not_for_the_same_one() {
    let at = |phase, inc, restarts| Status {
        phase,
        inc,
        restarts,
        waiting: 1,
        held: 2,
        records: 3,
    };
    let starting = |inc, restarts| at(Phase::Starting, inc, restarts);
    // the incarnation the kernel starts with is not a restart; a round in the same one gives no line,
    // whatever else changed
    assert_eq!(restart_line(1, &starting(1, 0)), None);
    assert_eq!(restart_line(1, &at(Phase::Ready, 1, 0)), None);
    assert_eq!(restart_line(4, &starting(4, 9)), None);
    // the next number: one line of fixed text with the new number and the restarts made in all
    assert_eq!(
        restart_line(1, &starting(2, 1)).as_deref(),
        Some("driver: inspector incarnation changed, inc 2, restarts 1")
    );
}

// ---- the signals ----

fn signals() -> (
    Signals,
    oneshot::Receiver<Result<(), Failure>>,
    oneshot::Receiver<Failure>,
) {
    let (ready_tx, ready) = oneshot::channel();
    let (failed_tx, failed) = oneshot::channel();
    let signals = Signals::Waiting {
        ready: ready_tx,
        failed: failed_tx,
    };
    (signals, ready, failed)
}

#[test]
fn ready_is_said_once_and_a_failure_after_it_goes_to_failed_once() {
    let why = Failure::Exit(3);
    let (mut s, mut ready, mut failed) = signals();
    for phase in [
        Phase::Starting,
        Phase::Starting,
        Phase::Ready,
        Phase::Ready,
        Phase::Stopping,
        Phase::Starting,
        Phase::Ready,
    ] {
        s.note(phase);
    }
    assert_eq!(ready.try_recv(), Ok(Ok(())));
    assert!(matches!(ready.try_recv(), Err(SlotError::Closed)));
    // `failed` is open and has nothing to say: closed would read as a lost driver
    assert!(matches!(failed.try_recv(), Err(SlotError::Empty)));

    s.note(Phase::Failed(why));
    s.note(Phase::Failed(why));
    s.note(Phase::Failed(Failure::ReapUnknown));
    assert_eq!(failed.try_recv(), Ok(why));
    assert!(matches!(failed.try_recv(), Err(SlotError::Closed)));
}

// ---- stop and shutdown ----

#[test]
fn after_a_stop_tickets_are_still_submitted_and_shutdown_waits_for_the_ingress_to_close() {
    let mut r = Rig::new(4, 8);
    let mut a = r.world.ticket(b"/a", 0);
    r.send(Msg::Ticket(a.ticket));
    r.core.round().unwrap();

    let by = Instant::now() + HOUR;
    r.send(Msg::Stop { inspect_by: by });
    let mut b = r.world.ticket(b"/b", 0);
    r.send(Msg::Ticket(b.ticket));
    assert!(r.core.round().unwrap().is_none());
    assert_eq!(r.core.mode, Mode::Stopping { inspect_by: by });
    assert_eq!(
        r.core.active.kernel.seen.len(),
        2,
        "the ticket after Stop is submitted"
    );

    // an earlier deadline brings it forward
    let earlier = by - 1800 * SEC;
    r.send(Msg::Stop {
        inspect_by: earlier,
    });
    r.core.round().unwrap();
    assert_eq!(
        r.core.mode,
        Mode::Stopping {
            inspect_by: earlier
        }
    );

    // both results come out, but a sender is left: no shutdown yet
    r.core
        .active
        .kernel
        .polls
        .push_back(vec![(0, Verdict::Allow), (1, Verdict::Allow)]);
    for _ in 0..3 {
        assert!(r.core.round().unwrap().is_none());
    }
    assert!(r.core.active.pending.is_empty());
    assert_eq!(r.core.active.kernel.shutdowns(), vec![]);
    assert_eq!(outcome(&mut a.answer), Outcome::Verdict(Verdict::Allow));
    assert_eq!(outcome(&mut b.answer), Outcome::Verdict(Verdict::Allow));

    // the last sender goes: shutdown is called once, with the earliest deadline
    r.close();
    let done = r.core.round().unwrap().expect("shutdown is due");
    assert_eq!(done.phase, Phase::Stopped);
    assert_eq!(r.core.active.kernel.shutdowns(), vec![earlier]);
    assert_eq!(r.core.mode, Mode::Down);
}

#[test]
fn at_the_stop_deadline_shutdown_is_called_and_a_late_ticket_is_unavailable() {
    let mut r = Rig::new(4, 8);
    let mut a = r.world.ticket(b"/a", 0);
    r.send(Msg::Ticket(a.ticket));
    r.core.round().unwrap();

    let unavailable = Verdict::Uninspectable(Reason::Unavailable);
    r.core.active.kernel.at_shutdown = vec![(0, unavailable)];
    let by = Instant::now();
    r.send(Msg::Stop { inspect_by: by });
    let done = r.core.round().unwrap().expect("the deadline is reached");
    // the result of shutdown is delivered like any other, and the main thread still sees it counted
    assert_eq!(outcome(&mut a.answer), Outcome::Verdict(unavailable));
    assert_eq!(done.results, vec![(0, unavailable)]);
    assert_eq!(r.world.free().0, INSPECT);

    // a ticket that comes later is answered and not submitted; the kernel is not stepped any more
    let mut late = r.world.ticket(b"/late", 0);
    r.send(Msg::Ticket(late.ticket));
    r.close();
    r.core.quiesce().unwrap();
    // No kernel judged it.
    assert_eq!(answer(&mut late.answer), Answer::from(Outcome::Unavailable));
    assert_eq!(r.core.active.kernel.seen.len(), 1);
    assert_eq!(r.core.active.kernel.shutdowns(), vec![by]);
    assert!(matches!(
        r.core.active.kernel.calls.last(),
        Some(Call::Shutdown(_))
    ));
    assert_eq!(r.world.free().0, INSPECT);
}

#[test]
fn a_request_the_kernel_did_not_decide_at_shutdown_is_fatal() {
    let mut r = Rig::new(4, 8);
    let a = r.world.ticket(b"/a", 0);
    r.send(Msg::Ticket(a.ticket));
    r.send(Msg::Stop {
        inspect_by: Instant::now(),
    });
    assert!(matches!(
        r.core.run(),
        End::Fatal("request left after shutdown")
    ));
}

// ---- the thread, with the real supervisor ----

/// A kernel configuration for these tests: the values are the tests' own choice, not defaults.
fn config(root: &Path) -> Config {
    Config {
        inspector: PathBuf::from("/driver-test/inspector"),
        rules: PathBuf::from("/driver-test/rules.conf"),
        rules_sha256: [0; 32],
        tmp_root: root.to_path_buf(),
        gomaxprocs: 2,
        gomemlimit: 256 << 20,
        slots: 2,
        wait_queue: 4,
        records: 8,
        discard_limit: 8,
        tick: 20 * MS,
        hello_wait: 10 * SEC,
        frame_io: 2 * SEC,
        verdict_wait: 10 * SEC,
        wait_deadline: 20 * SEC,
        closed_wait: 10 * SEC,
        stop_after: 30 * SEC,
        drain_wait: 10 * SEC,
        exit_wait: 10 * SEC,
        kill_grace: 5 * SEC,
        restarts: 0,
        restart_window: 60 * SEC,
    }
}

#[test]
fn a_kernel_that_cannot_start_says_so_once_through_ready_and_still_answers() {
    let root = Path::new("/driver-test/missing-root");
    let limits = Limits {
        slice: 5 * MS,
        ready_wait: 10 * SEC,
        stop_inspect: 10 * SEC,
    };
    let mut d = start(
        config(root),
        generation(1),
        bundle::Mode::Block,
        SharedRoutes::new(Routes::default()),
        limits,
        start_logger(Format::Json).unwrap(),
    )
    .unwrap();
    let told = answer(&mut d.ready);
    assert!(matches!(told, Err(Failure::TmpDir(_))), "{told:?}");
    assert!(matches!(d.failed.try_recv(), Err(SlotError::Empty)));

    // the kernel decides a ticket at once as unavailable
    let world = World::new();
    let mut made = world.ticket(b"/", 0);
    assert!(d.ingress.try_send(Msg::Ticket(made.ticket)).is_ok());
    assert_eq!(
        outcome(&mut made.answer),
        Outcome::Verdict(Verdict::Uninspectable(Reason::Unavailable))
    );
    eventually("the ticket gave its permits back", || {
        world.free() == (INSPECT, BUDGET)
    });

    // Stop alone does not end it while a sender is left
    let stop = Msg::Stop {
        inspect_by: Instant::now() + 10 * SEC,
    };
    assert!(d.ingress.try_send(stop).is_ok());
    thread::sleep(100 * MS);
    assert!(matches!(d.end.try_recv(), Err(SlotError::Empty)));
    drop(d.ingress);
    match answer(&mut d.end) {
        End::Done {
            kernel: done,
            retired_clean,
        } => {
            assert!(matches!(done.phase, Phase::Failed(Failure::TmpDir(_))));
            assert!(done.exit_confirmed && done.dir_removed && retired_clean);
        }
        End::Fatal(why) => panic!("fatal: {why}"),
    }
}

// ---- a switch of generation ----

impl Rig {
    /// Sends the order to switch to the generation `n`. The answer comes on the receiver.
    fn send_switch(&self, n: u8) -> oneshot::Receiver<Switched> {
        self.send_switch_with(n, Routes::default())
    }

    /// Sends the order to switch to the generation `n`, whose routes are `routes`.
    fn send_switch_with(&self, n: u8, routes: Routes) -> oneshot::Receiver<Switched> {
        let (reply, told) = oneshot::channel();
        self.send(Msg::Switch(Switch {
            generation: generation(n),
            mode: bundle::Mode::Block,
            routes,
            kernel: config(Path::new("/driver-test/switch-root")),
            reply,
        }));
        told
    }

    /// The kernel that does not get new tickets.
    fn other(&mut self) -> &mut Fake {
        &mut self.core.other().expect("a switch is under way").kernel
    }
}

/// Runs rounds until the main thread is told how the switch ended.
fn settle(r: &mut Rig, told: &mut oneshot::Receiver<Switched>) -> Switched {
    let until = Instant::now() + 30 * SEC;
    loop {
        match told.try_recv() {
            Ok(switched) => return switched,
            Err(SlotError::Empty) => {}
            Err(SlotError::Closed) => panic!("the driver went away without an answer"),
        }
        assert!(Instant::now() < until, "no answer in time");
        r.core.round().unwrap();
        thread::sleep(2 * MS);
    }
}

fn uris(kernel: &Fake) -> Vec<Vec<u8>> {
    kernel.seen.iter().map(|s| s.uri.clone()).collect()
}

#[test]
fn a_ready_generation_gets_the_new_tickets_and_the_old_one_finishes_and_is_stopped() {
    let mut r = Rig::new(4, 8);
    let old_shut = r.core.active.kernel.shut.clone();
    let mut a = r.world.ticket(b"/a", 0);
    r.send(Msg::Ticket(a.ticket));
    r.core.round().unwrap();
    let mut told = r.send_switch(2);
    r.core.round().unwrap();

    // While the new kernel starts, new tickets still go to the old one.
    let mut b = r.world.ticket(b"/b", 0);
    r.send(Msg::Ticket(b.ticket));
    r.core.round().unwrap();
    assert_eq!(
        uris(&r.core.active.kernel),
        [b"/a".to_vec(), b"/b".to_vec()]
    );
    assert!(r.other().seen.is_empty());
    assert_eq!(r.core.active.generation, generation(1));

    // The new kernel is ready and takes the new tickets. Its first id is the id of `a`, which the old kernel holds.
    r.other().phase = Phase::Ready;
    r.other().ids = VecDeque::from([0]);
    r.core.round().unwrap();
    assert_eq!(r.core.active.generation, generation(2));
    let blocked = Verdict::Block {
        phase: 1,
        rule_id: 9204,
        status: 403,
    };
    r.core.active.kernel.polls.push_back(vec![(0, blocked)]);
    r.other()
        .polls
        .push_back(vec![(0, Verdict::Allow), (1, Verdict::Allow)]);
    let mut c = r.world.ticket(b"/c", 0);
    r.send(Msg::Ticket(c.ticket));
    r.core.round().unwrap();
    assert_eq!(uris(&r.core.active.kernel), [b"/c".to_vec()]);
    // Every result went to the request of its own kernel, although two requests have the id 0, and names the
    // generation of that kernel.
    let judged = |slot: &mut oneshot::Receiver<Answer>| {
        let Answer { outcome, by } = answer(slot);
        (outcome, by.map(|judge| judge.generation))
    };
    let allowed = Outcome::Verdict(Verdict::Allow);
    assert_eq!(judged(&mut a.answer), (allowed, Some(generation(1))));
    assert_eq!(judged(&mut b.answer), (allowed, Some(generation(1))));
    assert_eq!(
        judged(&mut c.answer),
        (Outcome::Verdict(blocked), Some(generation(2)))
    );

    // The old kernel holds nothing now: it is stopped, and the main thread is told when it is gone.
    assert_eq!(settle(&mut r, &mut told), Switched::Yes);
    assert_eq!(old_shut.lock().unwrap().len(), 1);
    assert!(r.core.retired_clean);
    assert!(matches!(r.core.switching, Switching::Idle));
}

#[test]
fn an_old_kernel_that_is_out_of_time_is_stopped_at_once_with_its_requests_decided() {
    let mut r = Rig::new(4, 8);
    r.core.limits.stop_inspect = Duration::ZERO;
    let old_shut = r.core.active.kernel.shut.clone();
    let mut a = r.world.ticket(b"/a", 0);
    r.send(Msg::Ticket(a.ticket));
    r.core.round().unwrap();
    let mut told = r.send_switch(2);
    r.core.round().unwrap();
    r.other().phase = Phase::Ready;
    r.core.round().unwrap();
    // The old kernel holds the request and has no time left for it.
    let unavailable = Verdict::Uninspectable(Reason::Unavailable);
    r.other().at_shutdown = vec![(0, unavailable)];
    assert_eq!(settle(&mut r, &mut told), Switched::Yes);
    assert_eq!(outcome(&mut a.answer), Outcome::Verdict(unavailable));
    let deadlines = old_shut.lock().unwrap().clone();
    assert!(deadlines.len() == 1 && deadlines[0] <= Instant::now());
}

#[test]
fn a_ready_generation_is_not_taken_while_the_serving_kernel_has_failed() {
    let mut r = Rig::new(4, 8);
    let _told = r.send_switch_with(2, routes(&["/new/"]));
    r.core.round().unwrap();
    r.other().phase = Phase::Ready;
    r.core.active.kernel.phase = Phase::Failed(Failure::Exit(3));
    r.core.round().unwrap();
    assert_eq!(r.core.active.generation, generation(1));
    assert!(matches!(r.core.switching, Switching::Starting { .. }));
    assert!(r.core.routes.current().is_empty());
}

#[test]
fn a_generation_that_fails_or_is_late_is_stopped_and_the_old_one_serves_on() {
    let mut r = Rig::new(4, 8);
    let (told_by, mut ready, mut failed) = signals();
    r.core.signals = told_by;
    r.core.active.kernel.phase = Phase::Ready;
    r.core.round().unwrap();
    assert_eq!(ready.try_recv(), Ok(Ok(())));

    // A new kernel that fails to start. Its failure is not the failure of the kernel that serves.
    let mut told = r.send_switch(2);
    r.core.round().unwrap();
    let new_shut = r.other().shut.clone();
    r.other().phase = Phase::Failed(Failure::Exit(11));
    r.other().detail = Some(b"tkv0-inspector: start: rules\n".to_vec());
    assert_eq!(settle(&mut r, &mut told), Switched::No);
    assert_eq!(new_shut.lock().unwrap().len(), 1);
    assert!(matches!(failed.try_recv(), Err(SlotError::Empty)));

    // A new kernel that is not ready in time.
    r.core.limits.ready_wait = Duration::ZERO;
    let mut told = r.send_switch(3);
    assert_eq!(settle(&mut r, &mut told), Switched::No);
    assert!(r.core.retired_clean);

    // The old kernel served on all the time.
    assert_eq!(r.core.active.generation, generation(1));
    let mut a = r.world.ticket(b"/a", 0);
    r.send(Msg::Ticket(a.ticket));
    r.core
        .active
        .kernel
        .polls
        .push_back(vec![(0, Verdict::Allow)]);
    r.core.round().unwrap();
    assert_eq!(outcome(&mut a.answer), Outcome::Verdict(Verdict::Allow));
}

#[test]
fn a_stop_during_a_switch_stops_the_new_kernel_at_once_and_lets_the_old_one_finish() {
    // While the new kernel starts.
    let mut r = Rig::new(4, 8);
    let mut told = r.send_switch(2);
    r.core.round().unwrap();
    let new_shut = r.other().shut.clone();
    let by = Instant::now() + HOUR;
    r.send(Msg::Stop { inspect_by: by });
    r.core.round().unwrap();
    assert_eq!(settle(&mut r, &mut told), Switched::No);
    assert_eq!(*new_shut.lock().unwrap(), [by]);
    // A switch that comes now is turned down.
    let mut late = r.send_switch(3);
    r.core.round().unwrap();
    assert_eq!(late.try_recv(), Ok(Switched::No));
    r.close();
    match r.core.run() {
        End::Done { retired_clean, .. } => assert!(retired_clean),
        End::Fatal(why) => panic!("fatal: {why}"),
    }

    // While the old kernel finishes its requests: the stop waits for them until its deadline.
    let mut r = Rig::new(4, 8);
    let old_shut = r.core.active.kernel.shut.clone();
    let mut a = r.world.ticket(b"/a", 0);
    r.send(Msg::Ticket(a.ticket));
    r.core.round().unwrap();
    let mut told = r.send_switch(2);
    r.core.round().unwrap();
    r.other().phase = Phase::Ready;
    r.core.round().unwrap();
    assert_eq!(r.core.active.generation, generation(2));
    let unavailable = Verdict::Uninspectable(Reason::Unavailable);
    r.other().at_shutdown = vec![(0, unavailable)];
    r.send(Msg::Stop {
        inspect_by: Instant::now() + HOUR,
    });
    for _ in 0..3 {
        assert!(r.core.round().unwrap().is_none());
    }
    assert!(old_shut.lock().unwrap().is_empty());
    let by = Instant::now();
    r.send(Msg::Stop { inspect_by: by });
    let done = loop {
        if let Some(done) = r.core.round().unwrap() {
            break done;
        }
    };
    assert_eq!(done.phase, Phase::Stopped);
    assert_eq!(*old_shut.lock().unwrap(), [by]);
    assert_eq!(outcome(&mut a.answer), Outcome::Verdict(unavailable));
    assert_eq!(told.try_recv(), Ok(Switched::Yes));
    assert!(r.core.retired_clean);
}
