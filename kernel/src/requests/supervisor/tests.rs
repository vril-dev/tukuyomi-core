use super::*;
use crate::requests::state::ReturnReason;
use std::fs;
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::atomic::{AtomicU32, Ordering};

const MS: Duration = Duration::from_millis(1);

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

/// A configuration that passes `Config::check` and is never used to start anything.
fn cfg() -> Config {
    Config {
        inspector: PathBuf::from("/test-only/inspector"),
        rules: PathBuf::from("/test-only/rules.conf"),
        rules_sha256: [0; 32],
        tmp_root: PathBuf::from("/test-only/tmp"),
        gomaxprocs: 1,
        gomemlimit: 256 << 20,
        slots: 4,
        wait_queue: 8,
        records: 16,
        discard_limit: 64,
        tick: 20 * MS,
        hello_wait: secs(5),
        frame_io: secs(2),
        verdict_wait: secs(2),
        wait_deadline: secs(3),
        closed_wait: secs(2),
        stop_after: secs(6),
        drain_wait: secs(3),
        exit_wait: secs(3),
        kill_grace: secs(1),
        restarts: 1,
        restart_window: secs(60),
    }
}

const HOST: [(&[u8], &[u8]); 1] = [(b"Host", b"example.test")];

fn with<'a>(uri: &'a [u8], headers: &'a [(&'a [u8], &'a [u8])], body: &'a [u8]) -> Request<'a> {
    Request {
        client_addr: b"192.0.2.10",
        client_port: 49152,
        server_addr: b"192.0.2.1",
        server_port: 8080,
        method: b"GET",
        uri,
        proto: b"HTTP/1.1",
        headers,
        body,
    }
}

fn get(uri: &'static [u8]) -> Request<'static> {
    with(uri, &HOST, b"")
}

fn unavailable() -> Verdict {
    Verdict::Uninspectable(Reason::Unavailable)
}

fn code(c: i32) -> Exit {
    Exit {
        status: ExitStatus::from_raw(c << 8),
        killed: false,
    }
}

fn signal(sig: i32, killed: bool) -> Exit {
    Exit {
        status: ExitStatus::from_raw(sig),
        killed,
    }
}

// ---- pure rules ----

#[test]
fn bounded_is_due_at_once_on_overflow_and_cut_at_the_cap() {
    let t = Instant::now();
    let cap = t + secs(1);
    assert_eq!(bounded(t, 20 * MS, None), t + 20 * MS);
    assert_eq!(bounded(t, secs(5), Some(cap)), cap);
    // a sum that does not fit is due at once, also under a later cap
    assert_eq!(bounded(t, Duration::MAX, None), t);
    assert_eq!(bounded(t, Duration::MAX, Some(cap)), t);
}

#[test]
fn every_decision_has_its_verdict() {
    assert_eq!(verdict_of(Decision::Forward), Verdict::Allow);
    // the status is passed on as it is, a value that is no HTTP status too
    let block = Decision::Block {
        phase: 1,
        rule_id: -1,
        status: 0,
    };
    let want = Verdict::Block {
        phase: 1,
        rule_id: -1,
        status: 0,
    };
    assert_eq!(verdict_of(block), want);
    let cancelled = Verdict::Uninspectable(Reason::Cancelled);
    assert_eq!(verdict_of(Decision::ClientDisconnect), cancelled);
    let rows = [
        (Why::Invalid, Reason::Invalid),
        (Why::QueueFull, Reason::QueueFull),
        (Why::Halted(Halt::Drain), Reason::Unavailable),
        (Why::WaitDeadline, Reason::WaitDeadline),
        (Why::VerdictDeadline, Reason::VerdictDeadline),
        (Why::ConnFault, Reason::InspectorLost),
        (Why::Order, Reason::Protocol),
        (
            Why::TxError { code: 19 },
            Reason::InspectorError { code: 19 },
        ),
        (Why::NotCreated { code: 3 }, Reason::NotCreated { code: 3 }),
    ];
    for (why, reason) in rows {
        let want = Verdict::Uninspectable(reason);
        assert_eq!(verdict_of(Decision::Uninspectable(why)), want, "{why:?}");
    }
}

#[test]
fn next_follows_the_table_in_order() {
    let restart = || End::Restart("x");
    let hello = || End::Fail(Failure::Hello("h"));
    let killed = |status| Exit {
        status: ExitStatus::from_raw(status),
        killed: true,
    };
    // 1. a code of 10, 11 or 14 wins over everything below, also over a kill and an unspent budget
    for c in [10, 11, 14] {
        let fail = Next::Fail(Failure::Exit(c));
        assert_eq!(next(restart(), Some(code(c)), None, 0, 9), fail);
        assert_eq!(next(hello(), Some(code(c)), Some(Halt::Drain), 9, 0), fail);
        assert_eq!(next(End::Bye, Some(code(c)), None, 0, 0), fail);
    }
    let fail = Next::Fail(Failure::Exit(10));
    assert_eq!(next(restart(), Some(killed(10 << 8)), None, 0, 1), fail);
    // a signal is not a code
    assert_eq!(
        next(restart(), Some(signal(10, false)), None, 0, 1),
        Next::Restart
    );
    // 2. the end's own failure
    for exit in [None, Some(code(0)), Some(signal(9, true))] {
        let fail = Next::Fail(Failure::Hello("h"));
        assert_eq!(next(hello(), exit, Some(Halt::Drain), 5, 0), fail);
    }
    // 3. BYE and a clean exit that was not killed; a kill or another code is no clean stop
    assert_eq!(next(End::Bye, Some(code(0)), None, 9, 0), Next::Stopped);
    assert_eq!(next(End::Bye, Some(killed(0)), None, 0, 1), Next::Restart);
    let fail = Next::Fail(Failure::BudgetExhausted);
    assert_eq!(next(End::Bye, Some(code(1)), None, 0, 0), fail);
    // 4. the intake ended by shutdown: stopped, whatever the exit, also with no budget
    for exit in [None, Some(code(0)), Some(code(12)), Some(signal(9, true))] {
        let halt = Some(Halt::Drain);
        assert_eq!(next(restart(), exit, halt, 9, 0), Next::Stopped);
    }
    // 5. numbers used up: exhausted, before the budget
    for h in [Halt::TxExhausted, Halt::IncExhausted, Halt::MsgOverflow] {
        let fail = Next::Fail(Failure::Exhausted);
        assert_eq!(
            next(restart(), Some(code(12)), Some(h), 0, 9),
            fail,
            "{h:?}"
        );
    }
    // 6. no restart at all (`budget == 0`): the end of the supervisor, whatever was made so far
    for exit in [None, Some(code(12)), Some(signal(9, true))] {
        let fail = Next::Fail(Failure::BudgetExhausted);
        assert_eq!(next(restart(), exit, None, 9, 0), fail);
    }
    // 7. otherwise a restart, whatever was made so far: a full window waits, it does not fail
    for (used, budget) in [(0, 1), (u32::MAX, 1), (1000, 1000)] {
        for halted in [None, Some(Halt::NoRestart)] {
            let n = next(restart(), Some(code(12)), halted, used, budget);
            assert_eq!(n, Next::Restart);
        }
    }
    assert_eq!(next(restart(), None, None, 0, 1), Next::Restart);
}

// ---- the restart window ----

#[test]
fn the_restart_window_has_room_until_the_limit_and_then_names_the_time() {
    let (t0, w) = (Instant::now(), secs(10));
    let mut times = VecDeque::new();
    // empty and below the limit: recorded
    assert_eq!(restart_slot(&mut times, t0, 3, w), Slot::Now);
    assert_eq!(restart_slot(&mut times, t0 + secs(1), 3, w), Slot::Now);
    assert_eq!(restart_slot(&mut times, t0 + secs(2), 3, w), Slot::Now);
    assert_eq!(times, [t0, t0 + secs(1), t0 + secs(2)]);
    // full: the oldest plus a window, nothing recorded, the same answer however often it is asked
    for ask in [3, 4, 9] {
        assert_eq!(
            restart_slot(&mut times, t0 + secs(ask), 3, w),
            Slot::Wait(t0 + w)
        );
    }
    assert_eq!(times, [t0, t0 + secs(1), t0 + secs(2)]);
    // a limit of 1 is full after one
    let mut one = VecDeque::new();
    assert_eq!(restart_slot(&mut one, t0, 1, w), Slot::Now);
    assert_eq!(restart_slot(&mut one, t0, 1, w), Slot::Wait(t0 + w));
    // a limit of 0 has no oldest record: nothing is recorded, and the wait is a whole window from now
    let mut none = VecDeque::new();
    assert_eq!(restart_slot(&mut none, t0, 0, w), Slot::Wait(t0 + w));
    assert_eq!(
        restart_slot(&mut none, t0 + w, 0, w),
        Slot::Wait(t0 + w + w)
    );
    assert!(none.is_empty());
}

#[test]
fn the_restart_window_drops_a_record_that_is_a_whole_window_old() {
    let (t0, w, ns) = (Instant::now(), secs(10), Duration::from_nanos(1));
    // one nanosecond short of a whole window: the record stays, so the window is full
    let mut times = VecDeque::from([t0]);
    assert_eq!(
        restart_slot(&mut times, t0 + w - ns, 1, w),
        Slot::Wait(t0 + w)
    );
    assert_eq!(times, [t0]);
    // a whole window: it is dropped and the new time is recorded (the time that was named is a time that works)
    assert_eq!(restart_slot(&mut times, t0 + w, 1, w), Slot::Now);
    assert_eq!(times, [t0 + w]);
    // a window whose end does not fit in an `Instant` has passed: the record is dropped
    let now = t0 + w;
    assert_eq!(restart_slot(&mut times, now, 1, Duration::MAX), Slot::Now);
}

/// An engine after HELLO with one slot and room for one waiting request.
fn engine() -> (Engine, Instant) {
    let t0 = Instant::now();
    let mut e = Engine::new(
        Limits {
            slots: 1,
            wait_queue: 2,
            records: 8,
            discard_limit: 8,
            verdict_wait: secs(2),
            wait_deadline: secs(30),
            closed_wait: secs(2),
            stop_after: secs(6),
        },
        1,
        1,
    );
    e.ready(t0, 1);
    (e, t0)
}

/// One request holds the slot (TX_BEGIN taken), one waits, and the connection has faulted: the state in which
/// a stop ends.
fn faulted() -> (Engine, Instant, ReqId, ReqId) {
    let (mut e, t0) = engine();
    let request = || state::Request {
        begin: vec![1, 2, 3],
        body: Vec::new(),
    };
    let held = e.submit(t0, request()).unwrap();
    let waiting = e.submit(t0, request()).unwrap();
    assert_eq!(e.next_frame(t0).map(|f| f.kind), Some(OutKind::TxBegin));
    e.conn_fault(t0);
    (e, t0, held, waiting)
}

#[test]
fn a_stop_confirms_the_exit_only_when_it_was_seen_and_a_failed_one_ends_the_intake() {
    // Unreaped: the exit is not confirmed, the slot stays held and the waiting request does not wait for a start
    // that will not come; a later confirmed reap of the same incarnation returns the slot once.
    let (mut e, t0, held, waiting) = faulted();
    let tag = StopTag::Unreaped;
    assert_eq!(apply_stop(&mut e, t0, 1, tag), Some(Failure::ReapUnknown));
    assert_eq!((e.incarnation(), e.held_slots(), e.waiting()), (1, 1, 0));
    let halted = Some(Decision::Uninspectable(Why::Halted(Halt::NoRestart)));
    assert_eq!(e.outcome(waiting).unwrap().decision, halted);
    assert!(e.outcome(held).unwrap().returns.is_empty());
    assert_eq!(apply_stop(&mut e, t0, 1, StopTag::Done), None);
    assert_eq!((e.incarnation(), e.held_slots()), (2, 0));
    // DirLeft: the exit is confirmed (the incarnation is used up, the slot is back) but the intake is ended; the
    // same incarnation again does nothing, however it comes.
    let (mut e, t0, held, waiting) = faulted();
    let tag = StopTag::DirLeft;
    assert_eq!(
        apply_stop(&mut e, t0, 1, tag),
        Some(Failure::CleanupUnknown)
    );
    assert_eq!((e.incarnation(), e.held_slots(), e.waiting()), (2, 0, 0));
    assert_eq!(e.outcome(waiting).unwrap().decision, halted);
    assert!(apply_stop(&mut e, t0, 1, tag).is_some());
    assert_eq!(e.outcome(held).unwrap().returns.len(), 1);
    // Done: the slot is back and the request that waited goes on to the next start.
    let (mut e, t0, held, waiting) = faulted();
    assert_eq!(apply_stop(&mut e, t0, 1, StopTag::Done), None);
    assert_eq!((e.incarnation(), e.held_slots(), e.waiting()), (2, 0, 1));
    let returns = vec![(1, ReturnReason::ExitConfirmed)];
    assert_eq!(e.outcome(held).unwrap().returns, returns);
    e.ready(t0, 2);
    assert_eq!(e.outcome(waiting).unwrap().txs, vec![2]);
}

// ---- the public API without a process ----

#[test]
fn a_request_past_its_wait_deadline_is_decided_with_that_reason_at_shutdown() {
    let mut c = cfg();
    (c.tick, c.wait_deadline) = (MS, MS);
    let mut s = Supervisor::new(c).unwrap();
    let a = s.submit(&get(b"/a")).unwrap();
    thread::sleep(20 * MS);
    let sd = s.shutdown(Instant::now());
    assert_eq!(
        sd.results,
        vec![(a, Verdict::Uninspectable(Reason::WaitDeadline))]
    );
}

#[test]
fn a_failed_supervisor_keeps_what_it_owns_and_starts_nothing() {
    let mut s = Supervisor::new(cfg()).unwrap();
    s.fail(
        Instant::now(),
        Failure::CleanupUnknown,
        Some(Leftover::Unidentified),
    );
    let a = s.submit(&get(b"/a")).unwrap();
    assert_eq!(s.status().phase, Phase::Failed(Failure::CleanupUnknown));
    // poll starts nothing and only hands the result over
    assert_eq!(s.poll(Instant::now()), vec![(a, unavailable())]);
    assert!(matches!(s.run, Run::Failed { .. }));
    // an entry that cannot be identified stays, for every later shutdown
    for _ in 0..2 {
        let sd = s.shutdown(Instant::now());
        assert_eq!(sd.phase, Phase::Failed(Failure::CleanupUnknown));
        assert!(sd.exit_confirmed && !sd.dir_removed && !sd.bye);
        assert_eq!(sd.results, vec![]);
    }
    assert!(matches!(
        s.run,
        Run::Failed {
            left: Some(Leftover::Unidentified),
            ..
        }
    ));
}

/// A 0700 directory of its own under the given parent; only an empty one is removed at the end.
struct TempRoot(PathBuf);

impl TempRoot {
    fn under(parent: &Path) -> TempRoot {
        static N: AtomicU32 = AtomicU32::new(0);
        let path = parent.join(format!(
            "sup-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        TempRoot(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn entries(&self) -> usize {
        fs::read_dir(&self.0).unwrap().count()
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.0);
    }
}

#[test]
fn shutdown_retries_the_removal_of_a_directory_left_behind() {
    let root = TempRoot::under(&std::env::temp_dir());
    let dir = StartDir::create(root.path(), 7, 1).ok().expect("created");
    let path = dir.path().to_path_buf();
    let mut s = Supervisor::new(cfg()).unwrap();
    s.fail(
        Instant::now(),
        Failure::CleanupUnknown,
        Some(Leftover::Dir(dir)),
    );
    assert!(path.is_dir());
    let sd = s.shutdown(Instant::now());
    assert_eq!(sd.phase, Phase::Failed(Failure::CleanupUnknown));
    assert!(sd.exit_confirmed && sd.dir_removed);
    assert!(!path.exists());
    assert_eq!(root.entries(), 0);
    // a directory that is no longer the one that was made is not removed, and stays owned
    let dir = StartDir::create(root.path(), 7, 2).ok().expect("created");
    let path = dir.path().to_path_buf();
    fs::remove_dir(&path).unwrap();
    symlink("/test-only/elsewhere", &path).unwrap();
    s.fail(
        Instant::now(),
        Failure::CleanupUnknown,
        Some(Leftover::Dir(dir)),
    );
    for _ in 0..2 {
        let sd = s.shutdown(Instant::now());
        assert_eq!(sd.phase, Phase::Failed(Failure::CleanupUnknown));
        assert!(sd.exit_confirmed && !sd.dir_removed);
    }
    assert!(fs::symlink_metadata(&path).is_ok());
    fs::remove_file(&path).unwrap();
    assert_eq!(root.entries(), 0);
}

/// The next frame the supervisor wrote to the other end of the connection: its kind and the length of its payload.
fn frame_from(peer: &mut UnixStream) -> (u8, usize) {
    let mut head = [0u8; codec::HEADER_LEN];
    peer.read_exact(&mut head).unwrap();
    let len = u32::from_be_bytes([head[8], head[9], head[10], head[11]]);
    let len = usize::try_from(len).unwrap();
    peer.read_exact(&mut vec![0u8; len]).unwrap();
    (head[4], len)
}

/// After the verdict of phase 1 the body frames and BODY_END are queued together, and no answer can come before
/// BODY_END: one step must write them all, and not stop after the first and wait.
#[test]
fn the_frames_of_a_body_are_written_up_to_body_end_in_one_step() {
    let root = TempRoot::under(&std::env::temp_dir());
    let mut c = cfg();
    // The stand-in ends at once; its connection is replaced by one whose other end is the test.
    (c.inspector, c.tmp_root) = (PathBuf::from("/bin/true"), root.path().to_path_buf());
    let mut s = Supervisor::new(c).unwrap();
    let (run, inc) = (child::fresh_run().unwrap(), s.engine.incarnation());
    let mut start = start::launch(&s.cfg, run, inc).ok().expect("started");
    let (mine, mut peer) = UnixStream::pair().unwrap();
    start.stream = mine;
    peer.set_read_timeout(Some(secs(5))).unwrap();
    (s.run_id, s.run) = (Some(run), Run::Ready { start });
    s.engine.ready(Instant::now(), inc);
    // Two body fragments: the largest one and one byte.
    let body = vec![b'a'; codec::MAX_BODY + 1];
    let headers: [(&[u8], &[u8]); 2] = [
        (b"Host", b"example.test"),
        (b"Content-Type", b"application/x-www-form-urlencoded"),
    ];
    let post = Request {
        method: b"POST",
        ..with(b"/", &headers, &body)
    };
    let id = s.submit(&post).unwrap();
    let tx = s.engine.outcome(id).unwrap().txs[0];
    // With an `until` that has passed a step reads nothing, so none of these steps can wait.
    s.step(past());
    assert_eq!(frame_from(&mut peer).0, codec::KIND_TX_BEGIN);
    let now = Instant::now();
    s.engine
        .on_verdict(now, tx, 1, 1, false, 0, 0, &[])
        .unwrap();
    assert_eq!(s.engine.queued(), 3);
    s.step(past());
    assert_eq!(s.engine.queued(), 0);
    let body_frames = [
        (codec::KIND_BODY, codec::MAX_BODY),
        (codec::KIND_BODY, 1),
        (codec::KIND_BODY_END, 0),
    ];
    for want in body_frames {
        assert_eq!(frame_from(&mut peer), want);
    }
    assert!(matches!(s.run, Run::Ready { .. }));
    let sd = s.shutdown(past());
    assert!(sd.exit_confirmed && sd.dir_removed, "{sd:?}");
    assert_eq!(root.entries(), 0);
}

// ---- with a built inspector ----

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
}

fn sha256_from_hex(s: &str) -> [u8; 32] {
    assert!(s.len() == 64 && s.is_ascii(), "64 hex digits are required");
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex digit");
    }
    out
}

/// The configuration of the real inspector from the environment of the test run.
fn real(root: &Path, restarts: u32) -> Config {
    let mut c = cfg();
    c.inspector = PathBuf::from(env("TUKUYOMI_TEST_INSPECTOR"));
    c.rules = PathBuf::from(env("TUKUYOMI_TEST_RULES"));
    c.rules_sha256 = sha256_from_hex(&env("TUKUYOMI_TEST_RULES_SHA256"));
    c.tmp_root = root.to_path_buf();
    c.restarts = restarts;
    c.wait_deadline = secs(20);
    c
}

fn real_root() -> TempRoot {
    TempRoot::under(Path::new(&env("TUKUYOMI_TEST_TMP")))
}

fn soon() -> Instant {
    Instant::now() + 100 * MS
}

fn within(n: u64) -> Instant {
    Instant::now() + secs(n)
}

fn until_ready(s: &mut Supervisor) {
    let guard = within(30);
    while !matches!(s.run, Run::Ready { .. }) {
        assert!(Instant::now() < guard, "no HELLO: {:?}", s.status());
        assert!(!matches!(s.run, Run::Failed { .. }), "{:?}", s.status());
        s.step(soon());
    }
}

/// The end of every test: the shutdown leaves nothing owned and nothing in the root.
fn finish(mut s: Supervisor, root: &TempRoot) -> Shutdown {
    let sd = s.shutdown(within(10));
    assert!(sd.exit_confirmed && sd.dir_removed, "{sd:?}");
    assert_eq!((sd.held_left, sd.waiting_left), (0, 0));
    assert_eq!(root.entries(), 0);
    sd
}

/// Kills the started inspector and steps until the loss is seen: the supervisor is stopping it.
fn until_lost(s: &mut Supervisor) {
    let Run::Ready { start } = &mut s.run else {
        panic!("not ready");
    };
    start.kill_now().unwrap();
    let guard = within(30);
    while !matches!(s.run, Run::Stopping { .. }) {
        assert!(Instant::now() < guard, "loss not seen: {:?}", s.status());
        let _ = s.check(Instant::now());
        let _ = s.read_step(soon());
    }
    // Our end of the connection was found closed: the start ends as a restart.
    assert!(matches!(
        &s.run,
        Run::Stopping {
            end: End::Restart("recv"),
            ..
        }
    ));
}

#[test]
#[ignore = "needs a built inspector"]
fn a_request_in_flight_at_shutdown_gets_its_verdict() {
    let root = real_root();
    let mut s = Supervisor::new(real(root.path(), 0)).unwrap();
    until_ready(&mut s);
    let a = s.submit(&get(b"/")).unwrap();
    let sd = s.shutdown(within(10));
    assert_eq!(sd.results, vec![(a, Verdict::Allow)]);
    assert!(sd.bye && sd.exit_confirmed && sd.dir_removed);
    assert_eq!(sd.phase, Phase::Stopped);
    assert_eq!(s.status().inc, 2);
    assert_eq!(root.entries(), 0);
    // nothing starts afterwards, and a new request is decided at once
    let b = s.submit(&get(b"/")).unwrap();
    assert_eq!(s.poll(Instant::now()), vec![(b, unavailable())]);
    assert_eq!(s.status().inc, 2);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_loss_moves_only_the_request_whose_begin_was_not_taken_to_the_next_start() {
    let root = real_root();
    let mut c = real(root.path(), 1);
    (c.slots, c.wait_deadline) = (4, secs(20));
    let mut s = Supervisor::new(c).unwrap();
    let (a, b) = (
        s.submit(&get(b"/a")).unwrap(),
        s.submit(&get(b"/b")).unwrap(),
    );
    until_ready(&mut s);
    // The first TX_BEGIN (request a) is written. Then no frame is written until a's phase 1 VERDICT is in.
    assert!(s.write_step().is_continue());
    assert_eq!(s.engine.outcome(a).unwrap().txs, vec![1]);
    assert_eq!(s.engine.outcome(b).unwrap().txs, vec![2]);
    let guard = within(30);
    while !s.engine.outcome(a).unwrap().created {
        assert!(Instant::now() < guard, "no verdict: {:?}", s.status());
        assert!(s.check(Instant::now()).is_continue());
        assert!(s.read_step(soon()).is_continue());
    }
    // The inspector is lost with b's TX_BEGIN still in the writer queue; nothing is written any more.
    until_lost(&mut s);
    // The reap and the restart, with neither `poll` nor `next_done`: the records are read as they are.
    loop {
        assert!(Instant::now() < guard, "{:?}", s.status());
        s.step(soon());
        if s.engine.outcome(b).unwrap().decision.is_some() && s.engine.held_slots() == 0 {
            break;
        }
    }
    let (oa, ob) = (s.engine.outcome(a).unwrap(), s.engine.outcome(b).unwrap());
    // a: taken, so lost, never sent again
    assert_eq!(oa.decision, Some(Decision::Uninspectable(Why::ConnFault)));
    assert_eq!(oa.txs, vec![1]);
    assert_eq!(oa.returns, vec![(1, ReturnReason::ExitConfirmed)]);
    // b: not taken, so it waited for the next start and was inspected there
    assert_eq!(ob.decision, Some(Decision::Forward));
    assert_eq!(ob.txs, vec![2, 3]);
    assert_eq!(
        ob.returns,
        vec![(2, ReturnReason::BeforeBegin), (3, ReturnReason::Closed)]
    );
    assert_eq!(s.status().restarts, 1);
    assert_eq!(root.entries(), 1);
    // Each result is delivered once, in the order they were decided, by the shutdown.
    let sd = finish(s, &root);
    let lost = Verdict::Uninspectable(Reason::InspectorLost);
    assert_eq!(sd.results, vec![(a, lost), (b, Verdict::Allow)]);
    assert_eq!(sd.phase, Phase::Stopped);
}

#[test]
fn a_tmp_root_that_does_not_exist_ends_the_supervisor_at_the_first_start() {
    // `cfg()` names a root that is not there: the start is refused before anything is made
    let mut s = Supervisor::new(cfg()).unwrap();
    let a = s.submit(&get(b"/")).unwrap();
    assert_eq!(s.poll(Instant::now()), vec![(a, unavailable())]);
    let st = s.status();
    assert!(
        matches!(st.phase, Phase::Failed(Failure::TmpDir(_))),
        "{st:?}"
    );
    // the incarnation of the try is used up, and the try is not a restart
    assert_eq!((st.inc, st.restarts, st.waiting, st.held), (2, 0, 0, 0));
    let sd = s.shutdown(Instant::now());
    assert!(sd.exit_confirmed && sd.dir_removed);
    assert_eq!(sd.phase, st.phase);
}

/// An inspector that refuses its rules says why in `start-failure` and exits 11: the supervisor fails for good and
/// hands the line over, as it was written. The stand-in is a script run by `/bin/sh`.
#[test]
fn a_refusing_inspector_leaves_its_line_as_the_start_detail() {
    let root = TempRoot::under(&std::env::temp_dir());
    let fixtures = TempRoot::under(&std::env::temp_dir());
    let script = fixtures.path().join("inspector.sh");
    fs::write(
        &script,
        "printf 'tkv0-inspector: start: rules: x\\n' > \"$TMPDIR/start-failure\"\nexit 11\n",
    )
    .unwrap();
    let mut c = cfg();
    c.inspector = PathBuf::from("/bin/sh");
    c.rules = script.clone();
    c.tmp_root = root.path().to_path_buf();
    c.restarts = 0;
    let mut s = Supervisor::new(c).unwrap();
    assert_eq!(s.start_detail(), None);
    let guard = within(30);
    while !matches!(s.status().phase, Phase::Failed(_)) {
        assert!(Instant::now() < guard, "no failure: {:?}", s.status());
        s.poll(soon());
    }
    assert_eq!(s.status().phase, Phase::Failed(Failure::Exit(11)));
    let line = b"tkv0-inspector: start: rules: x\n".to_vec();
    assert_eq!(s.start_detail(), Some(line.clone()));
    // The detail stays after the shutdown, and nothing is left in the root.
    let sd = s.shutdown(within(10));
    assert!(sd.exit_confirmed && sd.dir_removed, "{sd:?}");
    assert_eq!(s.start_detail(), Some(line));
    assert_eq!(root.entries(), 0);
    fs::remove_file(&script).unwrap();
}

fn past() -> Instant {
    Instant::now().checked_sub(MS).unwrap()
}

#[test]
#[ignore = "needs a built inspector"]
fn a_shutdown_past_its_deadline_kills_at_once_and_decides_everything() {
    let root = real_root();
    // TX_BEGIN still in the writer queue: nothing was sent, so the request is only unavailable
    let mut s = Supervisor::new(real(root.path(), 0)).unwrap();
    until_ready(&mut s);
    let a = s.submit(&get(b"/")).unwrap();
    let sd = s.shutdown(past());
    assert_eq!(sd.results, vec![(a, unavailable())]);
    assert_eq!(sd.phase, Phase::Stopped);
    assert!(!sd.bye && sd.exit_confirmed && sd.dir_removed);
    assert_eq!(root.entries(), 0);
    // TX_BEGIN taken and written: the verdict is not read any more, so it is lost, and not sent again
    let mut s = Supervisor::new(real(root.path(), 0)).unwrap();
    until_ready(&mut s);
    let b = s.submit(&get(b"/")).unwrap();
    assert!(s.write_step().is_continue());
    let sd = s.shutdown(past());
    assert_eq!(
        sd.results,
        vec![(b, Verdict::Uninspectable(Reason::InspectorLost))]
    );
    assert_eq!(sd.phase, Phase::Stopped);
    assert!(!sd.bye && sd.exit_confirmed && sd.dir_removed);
    assert_eq!(root.entries(), 0);
    assert_eq!(s.status().restarts, 0);
}

#[test]
#[ignore = "needs a built inspector"]
fn dropping_a_running_supervisor_stops_it_and_removes_its_directory() {
    let root = real_root();
    let mut s = Supervisor::new(real(root.path(), 0)).unwrap();
    until_ready(&mut s);
    assert_eq!(root.entries(), 1);
    drop(s);
    assert_eq!(root.entries(), 0);
}
