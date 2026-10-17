use super::*;
use std::collections::VecDeque;
use std::fs::{self, DirBuilder};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
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
    ready: oneshot::Receiver<Result<(), Failure>>,
    failed: oneshot::Receiver<Failure>,
    world: World,
}

impl Rig {
    /// An intake takes `wait_queue + 1` messages; the channel has room for `room`.
    fn new(wait_queue: usize, room: usize) -> Rig {
        let (tx, rx) = sync_channel(room);
        let (ready_tx, ready) = oneshot::channel();
        let (failed_tx, failed) = oneshot::channel();
        let signals = Signals::Waiting {
            ready: ready_tx,
            failed: failed_tx,
        };
        let core = Core::new(
            Fake::new(),
            rx,
            signals,
            start_logger().unwrap(),
            30 * MS,
            20 * MS,
            wait_queue + 1,
        );
        Rig {
            core,
            tx: Some(tx),
            ready,
            failed,
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
fn a_refused_ticket_is_answered_and_gives_back_what_it_held() {
    let mut r = Rig::new(4, 8);
    r.core
        .kernel
        .refuse
        .push_back(Refused::Unsupported("content-type"));
    let mut made = r.world.ticket(b"/", 5);
    r.send(Msg::Ticket(made.ticket));
    r.core.intake(None).unwrap();
    assert_eq!(
        answer(&mut made.answer),
        Outcome::Refused(Refused::Unsupported("content-type"))
    );
    assert!(r.core.pending.is_empty());
    // the connection still holds its share of the body
    assert_eq!(r.world.free(), (INSPECT, BUDGET - 5));
    drop(made.body);
    assert_eq!(r.world.free(), (INSPECT, BUDGET));
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

    // one more than that stays for the next round
    let mut r = Rig::new(4, 64);
    for _ in 0..6 {
        r.send_closed();
    }
    r.core.intake(None).unwrap();
    assert_eq!(r.left(), 1);

    // a message that was waited for counts against the same five
    let mut r = Rig::new(4, 64);
    for _ in 0..12 {
        r.send_closed();
    }
    let first = r.core.rx.try_recv().unwrap();
    r.core.intake(Some(first)).unwrap();
    assert_eq!(r.left(), 12 - 1 - 4);
}

#[test]
fn an_intake_that_sees_the_close_reads_no_more() {
    let mut r = Rig::new(4, 8);
    r.send_closed();
    r.close();
    r.core.intake(None).unwrap();
    assert!(r.core.closed);
    assert!(r.core.pending.is_empty());
}

#[test]
fn the_kernel_gets_the_bytes_of_the_ticket() {
    let world = World::new();
    for (client, want_client, port) in [
        ("192.0.2.10:40000", &b"192.0.2.10"[..], 40000),
        ("[::ffff:192.0.2.77]:5000", &b"192.0.2.77"[..], 5000),
        ("[2001:db8::1]:6000", &b"2001:db8::1"[..], 6000),
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
fn permits_return_when_the_result_is_taken_and_not_before() {
    let mut r = Rig::new(4, 8);
    let mut made = r.world.ticket(b"/", 10);
    r.send(Msg::Ticket(made.ticket));
    for _ in 0..3 {
        r.core.round().unwrap();
        assert_eq!(r.world.free(), (INSPECT - 1, BUDGET - 20));
    }
    r.core.kernel.polls.push_back(vec![(0, Verdict::Allow)]);
    r.core.round().unwrap();
    assert_eq!(answer(&mut made.answer), Outcome::Verdict(Verdict::Allow));
    // the permit and the copy are back; the body is the connection's until it lets go
    assert_eq!(r.world.free(), (INSPECT, BUDGET - 10));
    drop(made.body);
    assert_eq!(r.world.free(), (INSPECT, BUDGET));
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
fn a_cancelled_result_is_taken_but_not_sent() {
    let world = World::new();
    let mut pending = BTreeMap::new();
    let mut sent = world.ticket(b"/sent", 0);
    let mut taken = world.ticket(b"/taken", 0);
    pending.insert(
        1,
        Pending {
            ticket: sent.ticket,
            cancelled: false,
        },
    );
    pending.insert(
        2,
        Pending {
            ticket: taken.ticket,
            cancelled: true,
        },
    );
    deliver(&mut pending, &[(1, Verdict::Allow), (2, Verdict::Allow)]).unwrap();
    assert!(pending.is_empty());
    assert_eq!(answer(&mut sent.answer), Outcome::Verdict(Verdict::Allow));
    assert!(matches!(taken.answer.try_recv(), Err(SlotError::Closed)));
    assert_eq!(world.free().0, INSPECT);
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
fn the_driver_ends_with_fatal_when_the_kernel_returns_an_unknown_id() {
    let mut r = Rig::new(4, 8);
    r.core.kernel.polls.push_back(vec![(7, Verdict::Allow)]);
    assert!(matches!(
        r.core.run(),
        End::Fatal("result for an unknown request")
    ));
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
fn the_slice_is_cut_to_the_tick_and_never_below_a_millisecond() {
    let slice_of = |slice| {
        let (_tx, rx) = sync_channel(1);
        Core::new(
            Fake::new(),
            rx,
            Signals::Told { _failed: None },
            start_logger().unwrap(),
            50 * MS,
            slice,
            5,
        )
        .slice
    };
    assert_eq!(slice_of(Duration::ZERO), MIN_SLICE);
    assert_eq!(slice_of(20 * MS), 20 * MS);
    assert_eq!(slice_of(50 * MS), 50 * MS);
    assert_eq!(slice_of(HOUR), 50 * MS);
}

#[test]
fn only_a_ready_kernel_without_records_and_tickets_is_idle() {
    let mut r = Rig::new(4, 8);
    assert!(!r.core.idle(), "starting");
    r.core.kernel.phase = Phase::Ready;
    assert!(r.core.idle());
    for phase in [
        Phase::Stopping,
        Phase::Stopped,
        Phase::Failed(Failure::BudgetExhausted),
    ] {
        r.core.kernel.phase = phase;
        assert!(!r.core.idle(), "{phase:?}");
    }
    r.core.kernel.phase = Phase::Ready;
    r.core.kernel.records = 1;
    assert!(!r.core.idle(), "a record is still open");
    r.core.kernel.records = 0;
    r.core.mode = Mode::Stopping {
        inspect_by: Instant::now() + HOUR,
    };
    assert!(!r.core.idle(), "stopping");
    r.core.mode = Mode::Run;
    assert!(r.core.idle());
    let made = r.world.ticket(b"/", 0);
    r.send(Msg::Ticket(made.ticket));
    r.core.intake(None).unwrap();
    assert!(!r.core.idle(), "a ticket waits for its result");
}

#[test]
fn an_idle_round_waits_up_to_the_tick_and_then_steps_for_a_slice() {
    let mut r = Rig::new(4, 8);
    r.core.kernel.phase = Phase::Ready;
    let before = Instant::now();
    r.core.round().unwrap();
    assert!(before.elapsed() >= 30 * MS, "it waited for the tick");
    assert_eq!(r.core.kernel.calls, vec![Call::Poll]);
    // the step is never asked to end before it begins
    assert!(r.core.kernel.until[0] >= before + 20 * MS);
    assert_eq!(r.ready.try_recv(), Ok(Ok(())));

    // a message that is there is taken in the round that wakes for it
    let made = r.world.ticket(b"/", 0);
    r.send(Msg::Ticket(made.ticket));
    r.core.round().unwrap();
    assert_eq!(
        r.core.kernel.calls,
        vec![Call::Poll, Call::Submit(0), Call::Poll]
    );
}

#[test]
fn the_stop_line_has_the_three_counts_and_no_other_text() {
    let status = Status {
        phase: Phase::Ready,
        inc: 9,
        restarts: 8,
        waiting: 1,
        held: 2,
        records: 3,
    };
    assert_eq!(
        stop_line(&status),
        "driver: stop, records 3, held 2, waiting 1"
    );
}

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
    // several tries between two rounds: one line, with the number now
    assert_eq!(
        restart_line(1, &starting(5, 4)).as_deref(),
        Some("driver: inspector incarnation changed, inc 5, restarts 4")
    );
    // a restart that still waits for the window: the number is ahead of the restarts
    assert_eq!(
        restart_line(2, &starting(3, 1)).as_deref(),
        Some("driver: inspector incarnation changed, inc 3, restarts 1")
    );
    // the kernel that may not restart changes its number as well, and then fails
    assert_eq!(
        restart_line(1, &at(Phase::Failed(Failure::BudgetExhausted), 2, 0)).as_deref(),
        Some("driver: inspector incarnation changed, inc 2, restarts 0")
    );
    // the top of the range: the last number is a change, the same number after it is not
    assert_eq!(
        restart_line(u32::MAX - 1, &starting(u32::MAX, u32::MAX)).as_deref(),
        Some("driver: inspector incarnation changed, inc 4294967295, restarts 4294967295")
    );
    assert_eq!(restart_line(u32::MAX, &starting(u32::MAX, u32::MAX)), None);
}

#[test]
fn a_round_takes_in_a_new_incarnation_once() {
    let mut r = Rig::new(4, 8);
    // the number the kernel started with is the one seen; rounds in it change nothing
    assert_eq!(r.core.inc, 1);
    for _ in 0..3 {
        r.core.round().unwrap();
        assert_eq!(r.core.inc, 1);
    }
    // restarts counted alone are not a new incarnation
    r.core.kernel.restarts = 1;
    r.core.round().unwrap();
    assert_eq!(r.core.inc, 1);
    // the round that sees a new number takes it in, and it stays
    r.core.kernel.inc = 2;
    for _ in 0..3 {
        r.core.round().unwrap();
        assert_eq!(r.core.inc, 2);
    }
    // several numbers between two rounds are one change
    r.core.kernel.inc = 6;
    r.core.round().unwrap();
    assert_eq!(r.core.inc, 6);

    // the seen number comes from the kernel, not from a fixed one
    let (_tx, rx) = sync_channel(1);
    let mut kernel = Fake::new();
    kernel.inc = 7;
    let core = Core::new(
        kernel,
        rx,
        Signals::Told { _failed: None },
        start_logger().unwrap(),
        50 * MS,
        20 * MS,
        5,
    );
    assert_eq!(core.inc, 7);
}

#[test]
fn the_exit_that_shutdown_confirms_is_not_a_new_incarnation_of_the_round() {
    let mut r = Rig::new(4, 8);
    r.send(Msg::Stop {
        inspect_by: Instant::now(),
    });
    assert!(r.core.round().unwrap().is_some());
    // the stand-in numbers the next incarnation inside `shutdown`, as the kernel does for the exit it confirms
    assert_eq!((r.core.inc, r.core.kernel.inc), (1, 2));
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

#[test]
fn a_failure_before_ready_goes_to_ready_once_and_not_to_failed() {
    let why = Failure::TmpDir("no root");
    let (mut s, mut ready, mut failed) = signals();
    s.note(Phase::Starting);
    s.note(Phase::Failed(why));
    s.note(Phase::Failed(why));
    s.note(Phase::Ready);
    assert_eq!(ready.try_recv(), Ok(Err(why)));
    assert!(matches!(ready.try_recv(), Err(SlotError::Closed)));
    // still open: the driver keeps the sender while it runs
    assert!(matches!(failed.try_recv(), Err(SlotError::Empty)));
    drop(s);
    assert!(matches!(failed.try_recv(), Err(SlotError::Closed)));
}

#[test]
fn a_round_tells_the_phase_it_ends_in() {
    let mut r = Rig::new(4, 8);
    r.core.round().unwrap();
    assert!(matches!(r.ready.try_recv(), Err(SlotError::Empty)));
    r.core.kernel.phase = Phase::Failed(Failure::BudgetExhausted);
    r.core.round().unwrap();
    r.core.round().unwrap();
    assert_eq!(r.ready.try_recv(), Ok(Err(Failure::BudgetExhausted)));
    assert!(matches!(r.failed.try_recv(), Err(SlotError::Empty)));
}

// ---- stop and shutdown ----

#[test]
fn shutdown_is_due_when_nothing_can_arrive_and_nothing_waits_or_at_the_deadline() {
    let now = Instant::now();
    let later = now + HOUR;
    assert!(!shutdown_due(false, false, later, now));
    assert!(
        !shutdown_due(true, false, later, now),
        "a result is awaited"
    );
    assert!(!shutdown_due(false, true, later, now), "a sender is left");
    assert!(shutdown_due(true, true, later, now));
    // the deadline: the instant itself is due, one millisecond before it is not
    assert!(shutdown_due(false, false, now, now));
    assert!(!shutdown_due(false, false, now + MS, now));
    assert!(shutdown_due(false, false, now, now + MS));
}

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

    // a later deadline cannot extend it; an earlier one brings it forward
    r.send(Msg::Stop {
        inspect_by: by + HOUR,
    });
    r.core.round().unwrap();
    assert_eq!(r.core.mode, Mode::Stopping { inspect_by: by });
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
fn a_closed_ingress_without_a_stop_message_is_a_stop_that_is_due_at_once() {
    let mut r = Rig::new(4, 8);
    let mut a = r.world.ticket(b"/a", 0);
    r.send(Msg::Ticket(a.ticket));
    r.core.round().unwrap();
    let unavailable = Verdict::Uninspectable(Reason::Unavailable);
    r.core.kernel.at_shutdown = vec![(0, unavailable)];
    r.close();
    assert!(r.core.round().unwrap().is_some());
    assert_eq!(r.core.kernel.shutdowns().len(), 1);
    assert_eq!(answer(&mut a.answer), Outcome::Verdict(unavailable));
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

#[test]
fn the_end_is_told_only_after_the_ingress_closed() {
    let r = Rig::new(4, 8);
    let Rig { core, tx, .. } = r;
    let tx = tx.unwrap();
    let (end_tx, mut end) = oneshot::channel();
    let run = thread::spawn(move || core.drive(end_tx));
    assert!(
        tx.try_send(Msg::Stop {
            inspect_by: Instant::now()
        })
        .is_ok()
    );
    thread::sleep(150 * MS);
    assert!(matches!(end.try_recv(), Err(SlotError::Empty)));
    drop(tx);
    assert!(matches!(answer(&mut end), End::Done(_)));
    run.join().unwrap();
}

// ---- the thread, with the real supervisor ----

#[test]
fn the_supervisor_can_move_to_another_thread() {
    fn send<T: Send>() {}
    send::<Supervisor>();
    send::<Msg>();
}

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

/// A fresh 0700 directory, removed with everything in it when dropped.
struct TestDir(PathBuf);

impl TestDir {
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A new 0700 directory `parent/name-<process id>`.
fn scratch(parent: &Path, name: &str) -> TestDir {
    let dir = parent.join(format!("{name}-{}", std::process::id()));
    DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .unwrap_or_else(|e| panic!("cannot create {dir:?}: {e}"));
    // A umask can only remove bits; make the mode exactly 0700.
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    TestDir(dir)
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

#[test]
fn a_configuration_the_kernel_refuses_ends_the_driver_with_fatal() {
    let root = Path::new("/driver-test/root");
    let mut zero_slots = config(root);
    zero_slots.slots = 0;
    let mut d = start(zero_slots, 5 * MS, start_logger().unwrap()).unwrap();
    assert!(matches!(
        answer(&mut d.end),
        End::Fatal("slots is out of range")
    ));
    eventually("ready closes without an answer", || {
        matches!(d.ready.try_recv(), Err(SlotError::Closed))
    });

    // a queue that cannot be counted one more: no panic in start, and the kernel refuses it
    let mut huge = config(root);
    huge.wait_queue = usize::MAX;
    let mut d = start(huge, 5 * MS, start_logger().unwrap()).unwrap();
    assert!(matches!(
        answer(&mut d.end),
        End::Fatal("records is below slots plus wait_queue")
    ));
}

#[test]
fn start_returns_before_the_kernel_is_ready_and_a_stop_ends_a_start_that_never_said_hello() {
    let base = scratch(&std::env::temp_dir(), "driver-silent");
    let root = base.path().join("root");
    DirBuilder::new().mode(0o700).create(&root).unwrap();
    // An inspector that is started and never speaks: the shell becomes `sleep`, so the kernel's own
    // kill ends it.
    let script = base.path().join("silent.sh");
    fs::write(&script, "exec /bin/sleep 120\n").unwrap();
    let mut cfg = config(&root);
    cfg.inspector = PathBuf::from("/bin/sh");
    cfg.rules = script;

    let mut d = start(cfg, 5 * MS, start_logger().unwrap()).unwrap();
    // the hello of this inspector never comes, so no answer can be there yet
    assert!(matches!(d.ready.try_recv(), Err(SlotError::Empty)));
    eventually("the inspector was started", || {
        fs::read_dir(&root).unwrap().count() == 1
    });
    assert!(matches!(d.ready.try_recv(), Err(SlotError::Empty)));

    let stop = Msg::Stop {
        inspect_by: Instant::now() + 10 * SEC,
    };
    assert!(d.ingress.try_send(stop).is_ok());
    drop(d.ingress);
    match answer(&mut d.end) {
        End::Done(done) => {
            assert_eq!(done.phase, Phase::Stopped);
            assert!(done.exit_confirmed && done.dir_removed && !done.bye);
        }
        End::Fatal(why) => panic!("fatal: {why}"),
    }
    assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
}

#[test]
fn the_core_follows_the_incarnations_of_a_kernel_that_restarts_every_window() {
    let base = scratch(&std::env::temp_dir(), "driver-restart");
    let root = base.path().join("root");
    DirBuilder::new().mode(0o700).create(&root).unwrap();
    // Every start fails, for the inspector is not there. One restart is allowed in a window of 50 ms, so the
    // kernel waits for the window and never fails.
    let mut cfg = config(&root);
    cfg.inspector = base.path().join("missing");
    (cfg.restarts, cfg.restart_window) = (1, 50 * MS);
    let (tx, rx) = sync_channel(2);
    let mut core = Core::new(
        Supervisor::new(cfg).unwrap(),
        rx,
        Signals::Told { _failed: None },
        start_logger().unwrap(),
        20 * MS,
        5 * MS,
        5,
    );
    assert_eq!(core.inc, 1);

    let until = Instant::now() + 30 * SEC;
    while core.kernel.status().restarts < 3 {
        assert!(Instant::now() < until, "{:?}", core.kernel.status());
        core.round().unwrap();
        let status = core.kernel.status();
        assert!(!matches!(status.phase, Phase::Failed(_)), "{status:?}");
        // the round has seen the number the kernel has
        assert_eq!(core.inc, status.inc);
    }
    // every restart used a number of its own
    assert!(core.inc >= 4, "{} after three restarts", core.inc);

    // the last sender goes: the kernel is stopped and its directory is removed
    drop(tx);
    let done = loop {
        assert!(Instant::now() < until, "no end");
        if let Some(done) = core.round().unwrap() {
            break done;
        }
    };
    assert_eq!(done.phase, Phase::Stopped);
    assert!(done.exit_confirmed && done.dir_removed);
    assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
}

// ---- with a built inspector ----

fn var(name: &str) -> String {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => v,
        _ => panic!("{name} is not set: this real-process test needs it and is never skipped"),
    }
}

fn sha256_from_hex(s: &str) -> [u8; 32] {
    assert!(
        s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()),
        "TUKUYOMI_TEST_RULES_SHA256 must be 64 hex digits"
    );
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex digits");
    }
    out
}

#[test]
#[ignore = "needs a built inspector"]
fn a_real_inspector_allows_a_plain_get_blocks_the_uri_rule_and_stops_cleanly() {
    let root = scratch(Path::new(&var("TUKUYOMI_TEST_TMP")), "driver-real");
    let mut cfg = config(root.path());
    cfg.inspector = PathBuf::from(var("TUKUYOMI_TEST_INSPECTOR"));
    cfg.rules = PathBuf::from(var("TUKUYOMI_TEST_RULES"));
    cfg.rules_sha256 = sha256_from_hex(&var("TUKUYOMI_TEST_RULES_SHA256"));
    let mut d = start(cfg, 20 * MS, start_logger().unwrap()).unwrap();
    assert_eq!(answer(&mut d.ready), Ok(()));

    let world = World::new();
    let mut plain = world.ticket(b"/", 0);
    assert!(d.ingress.try_send(Msg::Ticket(plain.ticket)).is_ok());
    assert_eq!(answer(&mut plain.answer), Outcome::Verdict(Verdict::Allow));
    let mut probe = world.ticket(b"/block-probe/x", 0);
    assert!(d.ingress.try_send(Msg::Ticket(probe.ticket)).is_ok());
    assert_eq!(
        answer(&mut probe.answer),
        Outcome::Verdict(Verdict::Block {
            phase: 1,
            rule_id: 9201,
            status: 403
        })
    );
    eventually("both tickets gave their permits back", || {
        world.free() == (INSPECT, BUDGET)
    });

    let stop = Msg::Stop {
        inspect_by: Instant::now() + 10 * SEC,
    };
    assert!(d.ingress.try_send(stop).is_ok());
    drop(d.ingress);
    match answer(&mut d.end) {
        End::Done(done) => {
            assert_eq!(done.phase, Phase::Stopped);
            assert!(done.bye && done.exit_confirmed && done.dir_removed);
            assert_eq!((done.held_left, done.waiting_left), (0, 0));
            assert!(done.results.is_empty());
        }
        End::Fatal(why) => panic!("fatal: {why}"),
    }
    // `failed` never spoke
    eventually("failed closes without an answer", || {
        matches!(d.failed.try_recv(), Err(SlotError::Closed))
    });
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}
