use super::*;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use tokio::sync::Semaphore;
use tokio::sync::oneshot::error::TryRecvError as SlotError;
use tukuyomi_kernel::{Config, Reason};

use crate::log::start_logger;

const MS: Duration = Duration::from_millis(1);
const SEC: Duration = Duration::from_secs(1);
const HOUR: Duration = Duration::from_secs(3600);
/// Permits of the inspection pool and bytes of the byte budget in these tests.
const INSPECT: usize = 16;
const BUDGET: usize = 10_000;

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
    answer: oneshot::Receiver<Outcome>,
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

    fn shutdown(&mut self, deadline: Instant) -> Shutdown {
        self.calls.push(Call::Shutdown(deadline));
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
            Fake::new(),
            rx,
            Signals::Told { _failed: None },
            start_logger().unwrap(),
            30 * MS,
            20 * MS,
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
    let uris: Vec<_> = r.core.kernel.seen.iter().map(|s| s.uri.clone()).collect();
    assert_eq!(uris, vec![b"/live".to_vec()]);
    assert_eq!(r.core.pending.len(), 1);
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
        r.core.kernel.calls,
        vec![Call::Submit(0), Call::Submit(1), Call::Poll]
    );

    // a's connection goes away: one cancel, in front of the next step, and never one for b
    drop(a.answer);
    for _ in 0..3 {
        r.core.round().unwrap();
    }
    assert_eq!(
        r.core.kernel.calls,
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
        .kernel
        .polls
        .push_back(vec![(0, Verdict::Uninspectable(Reason::Cancelled))]);
    r.core.round().unwrap();
    // a's permit and copy are back; its body is the connection's until it lets go
    assert_eq!(r.world.free(), (INSPECT - 1, BUDGET - 3 - 6));
    drop(a.body);
    assert_eq!(r.world.free(), (INSPECT - 1, BUDGET - 6));
    assert_eq!(r.core.pending.len(), 1);
}

#[test]
fn a_result_goes_to_the_ticket_it_belongs_to() {
    let mut r = Rig::new(4, 8);
    r.core.kernel.ids = VecDeque::from([5, 2]);
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
        .kernel
        .polls
        .push_back(vec![(2, blocked), (5, Verdict::Allow)]);
    r.core.round().unwrap();
    assert_eq!(answer(&mut a.answer), Outcome::Verdict(Verdict::Allow));
    assert_eq!(answer(&mut b.answer), Outcome::Verdict(blocked));
    assert!(r.core.pending.is_empty());
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
        deliver(&mut pending, &[(1, Verdict::Allow), (2, Verdict::Allow)]),
        unknown
    );
    assert_eq!(answer(&mut made.answer), Outcome::Verdict(Verdict::Allow));
    // a result comes out once: the same id again is unknown
    assert_eq!(deliver(&mut pending, &[(1, Verdict::Allow)]), unknown);
    assert_eq!(deliver(&mut pending, &[]), Ok(()));
}

#[test]
fn a_duplicate_id_is_fatal() {
    let mut r = Rig::new(4, 8);
    r.core.kernel.ids = VecDeque::from([3, 3]);
    let a = r.world.ticket(b"/a", 0);
    let b = r.world.ticket(b"/b", 0);
    r.send(Msg::Ticket(a.ticket));
    r.send(Msg::Ticket(b.ticket));
    assert_eq!(r.core.intake(None), Err("duplicate request id"));
    // the first ticket is still the one in the table
    assert_eq!(r.core.pending.len(), 1);
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
        r.core.kernel.seen.len(),
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
        .kernel
        .polls
        .push_back(vec![(0, Verdict::Allow), (1, Verdict::Allow)]);
    for _ in 0..3 {
        assert!(r.core.round().unwrap().is_none());
    }
    assert!(r.core.pending.is_empty());
    assert_eq!(r.core.kernel.shutdowns(), vec![]);
    assert_eq!(answer(&mut a.answer), Outcome::Verdict(Verdict::Allow));
    assert_eq!(answer(&mut b.answer), Outcome::Verdict(Verdict::Allow));

    // the last sender goes: shutdown is called once, with the earliest deadline
    r.close();
    let done = r.core.round().unwrap().expect("shutdown is due");
    assert_eq!(done.phase, Phase::Stopped);
    assert_eq!(r.core.kernel.shutdowns(), vec![earlier]);
    assert_eq!(r.core.mode, Mode::Down);
}

#[test]
fn at_the_stop_deadline_shutdown_is_called_and_a_late_ticket_is_unavailable() {
    let mut r = Rig::new(4, 8);
    let mut a = r.world.ticket(b"/a", 0);
    r.send(Msg::Ticket(a.ticket));
    r.core.round().unwrap();

    let unavailable = Verdict::Uninspectable(Reason::Unavailable);
    r.core.kernel.at_shutdown = vec![(0, unavailable)];
    let by = Instant::now();
    r.send(Msg::Stop { inspect_by: by });
    let done = r.core.round().unwrap().expect("the deadline is reached");
    // the result of shutdown is delivered like any other, and the main thread still sees it counted
    assert_eq!(answer(&mut a.answer), Outcome::Verdict(unavailable));
    assert_eq!(done.results, vec![(0, unavailable)]);
    assert_eq!(r.world.free().0, INSPECT);

    // a ticket that comes later is answered and not submitted; the kernel is not stepped any more
    let mut late = r.world.ticket(b"/late", 0);
    r.send(Msg::Ticket(late.ticket));
    r.close();
    r.core.quiesce().unwrap();
    assert_eq!(answer(&mut late.answer), Outcome::Unavailable);
    assert_eq!(r.core.kernel.seen.len(), 1);
    assert_eq!(r.core.kernel.shutdowns(), vec![by]);
    assert!(matches!(
        r.core.kernel.calls.last(),
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
    let mut d = start(config(root), 5 * MS, start_logger().unwrap()).unwrap();
    let told = answer(&mut d.ready);
    assert!(matches!(told, Err(Failure::TmpDir(_))), "{told:?}");
    assert!(matches!(d.failed.try_recv(), Err(SlotError::Empty)));

    // the kernel decides a ticket at once as unavailable
    let world = World::new();
    let mut made = world.ticket(b"/", 0);
    assert!(d.ingress.try_send(Msg::Ticket(made.ticket)).is_ok());
    assert_eq!(
        answer(&mut made.answer),
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
        End::Done(done) => {
            assert!(matches!(done.phase, Phase::Failed(Failure::TmpDir(_))));
            assert!(done.exit_confirmed && done.dir_removed);
        }
        End::Fatal(why) => panic!("fatal: {why}"),
    }
}
