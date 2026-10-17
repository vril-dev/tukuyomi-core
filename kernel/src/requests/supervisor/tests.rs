use super::*;
use crate::requests::state::ReturnReason;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
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
    // no cap
    assert_eq!(bounded(t, 20 * MS, None), t + 20 * MS);
    assert_eq!(bounded(t, Duration::MAX, None), t);
    // a cap
    assert_eq!(bounded(t, 20 * MS, Some(cap)), t + 20 * MS);
    assert_eq!(bounded(t, secs(5), Some(cap)), cap);
    assert_eq!(bounded(t, cap - t, Some(cap)), cap);
    // a sum that does not fit is due at once, also under a later cap
    assert_eq!(bounded(t, Duration::MAX, Some(cap)), t);
    // a cap that has passed wins
    if let Some(past) = t.checked_sub(secs(1)) {
        assert_eq!(bounded(t, 20 * MS, Some(past)), past);
        assert_eq!(bounded(t, Duration::MAX, Some(past)), past);
    }
}

#[test]
fn every_decision_has_its_verdict() {
    let halts = [
        Halt::TxExhausted,
        Halt::IncExhausted,
        Halt::MsgOverflow,
        Halt::Drain,
        Halt::NoRestart,
    ];
    assert_eq!(verdict_of(Decision::Forward), Verdict::Allow);
    assert_eq!(
        verdict_of(Decision::Block {
            phase: 2,
            rule_id: 9202,
            status: 403
        }),
        Verdict::Block {
            phase: 2,
            rule_id: 9202,
            status: 403
        }
    );
    // the status is passed on as it is, a value that is no HTTP status too
    assert_eq!(
        verdict_of(Decision::Block {
            phase: 1,
            rule_id: -1,
            status: 0
        }),
        Verdict::Block {
            phase: 1,
            rule_id: -1,
            status: 0
        }
    );
    assert_eq!(
        verdict_of(Decision::ClientDisconnect),
        Verdict::Uninspectable(Reason::Cancelled)
    );
    let rows = [
        (Why::Invalid, Reason::Invalid),
        (Why::QueueFull, Reason::QueueFull),
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
        assert_eq!(
            verdict_of(Decision::Uninspectable(why)),
            Verdict::Uninspectable(reason),
            "{why:?}"
        );
    }
    for h in halts {
        assert_eq!(
            verdict_of(Decision::Uninspectable(Why::Halted(h))),
            unavailable(),
            "{h:?}"
        );
    }
}

#[test]
fn every_out_kind_has_the_kind_codec_sends() {
    let all = [
        (OutKind::TxBegin, codec::KIND_TX_BEGIN),
        (OutKind::Body, codec::KIND_BODY),
        (OutKind::BodyEnd, codec::KIND_BODY_END),
        (OutKind::TxEnd(3), codec::KIND_TX_END),
    ];
    for (k, w) in all {
        assert_eq!(wire_kind(k), w);
    }
}

#[test]
fn next_follows_the_table_in_order() {
    let restart = || End::Restart("x");
    let halts = [
        None,
        Some(Halt::Drain),
        Some(Halt::TxExhausted),
        Some(Halt::NoRestart),
    ];
    // 1. a code of 10, 11 or 14 wins over everything below, also over a kill and an unspent budget
    for c in [10, 11, 14] {
        for halted in halts {
            let fail = Next::Fail(Failure::Exit(c));
            assert_eq!(next(restart(), Some(code(c)), halted, 0, 9), fail);
            assert_eq!(
                next(End::Fail(Failure::Hello("h")), Some(code(c)), halted, 9, 0),
                fail
            );
            assert_eq!(next(End::Bye, Some(code(c)), halted, 0, 0), fail);
        }
    }
    let killed_10 = Exit {
        status: ExitStatus::from_raw(10 << 8),
        killed: true,
    };
    assert_eq!(
        next(restart(), Some(killed_10), None, 0, 1),
        Next::Fail(Failure::Exit(10))
    );
    // a signal is not a code, and neither is no process
    assert_eq!(
        next(restart(), Some(signal(10, false)), None, 0, 1),
        Next::Restart
    );
    // 2. the end's own failure
    for exit in [None, Some(code(0)), Some(code(12)), Some(signal(9, true))] {
        for halted in halts {
            assert_eq!(
                next(End::Fail(Failure::Hello("h")), exit, halted, 5, 0),
                Next::Fail(Failure::Hello("h"))
            );
        }
    }
    // 3. BYE and a clean exit that was not killed
    assert_eq!(next(End::Bye, Some(code(0)), None, 9, 0), Next::Stopped);
    assert_eq!(
        next(End::Bye, Some(code(0)), Some(Halt::TxExhausted), 9, 0),
        Next::Stopped
    );
    // BYE with a kill or another code is no clean stop: the rows below decide
    let killed_0 = Exit {
        status: ExitStatus::from_raw(0),
        killed: true,
    };
    assert_eq!(next(End::Bye, Some(killed_0), None, 0, 1), Next::Restart);
    assert_eq!(next(End::Bye, Some(code(1)), None, 0, 1), Next::Restart);
    assert_eq!(
        next(End::Bye, Some(code(1)), None, 0, 0),
        Next::Fail(Failure::BudgetExhausted)
    );
    assert_eq!(
        next(End::Bye, Some(code(1)), Some(Halt::Drain), 0, 0),
        Next::Stopped
    );
    // 4. the intake ended by shutdown: stopped, whatever the exit, also with no budget
    for exit in [
        None,
        Some(code(0)),
        Some(code(1)),
        Some(code(2)),
        Some(code(12)),
        Some(code(13)),
        Some(signal(9, true)),
        Some(signal(11, false)),
    ] {
        assert_eq!(
            next(restart(), exit, Some(Halt::Drain), 9, 0),
            Next::Stopped
        );
        assert_eq!(
            next(restart(), exit, Some(Halt::Drain), 0, 9),
            Next::Stopped
        );
    }
    // 5. numbers used up: exhausted, before the budget
    for h in [Halt::TxExhausted, Halt::IncExhausted, Halt::MsgOverflow] {
        for (used, budget) in [(0, 9), (9, 0)] {
            assert_eq!(
                next(restart(), Some(code(12)), Some(h), used, budget),
                Next::Fail(Failure::Exhausted),
                "{h:?}"
            );
            assert_eq!(
                next(End::Bye, Some(code(1)), Some(h), used, budget),
                Next::Fail(Failure::Exhausted),
                "{h:?}"
            );
        }
    }
    // 6. no restart at all (`budget == 0`): the end of the supervisor, whatever was made so far
    for used in [0, 1, 9, u32::MAX] {
        for exit in [None, Some(code(0)), Some(code(12)), Some(signal(9, true))] {
            for halted in [None, Some(Halt::NoRestart)] {
                assert_eq!(
                    next(restart(), exit, halted, used, 0),
                    Next::Fail(Failure::BudgetExhausted),
                    "{used}"
                );
            }
        }
    }
    // 7. otherwise a restart, whatever was made so far: a full window waits, it does not fail
    for (used, budget) in [
        (0, 1),
        (1, 1),
        (2, 1),
        (u32::MAX, 1),
        (0, 2),
        (999, 1000),
        (1000, 1000),
        (u32::MAX - 1, u32::MAX),
        (u32::MAX, u32::MAX),
    ] {
        assert_eq!(
            next(restart(), Some(code(12)), None, used, budget),
            Next::Restart,
            "{used} {budget}"
        );
    }
    // any exit, also none (a try to start that failed)
    for exit in [
        None,
        Some(code(0)),
        Some(code(2)),
        Some(code(12)),
        Some(code(13)),
        Some(code(99)),
        Some(signal(9, true)),
        Some(signal(11, false)),
    ] {
        assert_eq!(next(restart(), exit, None, 0, 1), Next::Restart);
        assert_eq!(
            next(restart(), exit, Some(Halt::NoRestart), 0, 1),
            Next::Restart
        );
    }
    assert_eq!(
        next(restart(), None, None, u32::MAX - 1, u32::MAX),
        Next::Restart
    );
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
    // only the records that are old go, all of them if all are
    let all = [t0, t0 + secs(1), t0 + secs(2)];
    let mut times = VecDeque::from(all);
    assert_eq!(restart_slot(&mut times, t0 + secs(10), 3, w), Slot::Now);
    assert_eq!(times, [t0 + secs(1), t0 + secs(2), t0 + secs(10)]);
    let mut times = VecDeque::from(all);
    assert_eq!(
        restart_slot(&mut times, t0 + secs(10), 2, w),
        Slot::Wait(t0 + secs(11))
    );
    assert_eq!(times, [t0 + secs(1), t0 + secs(2)]);
    let mut times = VecDeque::from(all);
    assert_eq!(restart_slot(&mut times, t0 + secs(12), 3, w), Slot::Now);
    assert_eq!(times, [t0 + secs(12)]);
}

#[test]
fn the_restart_window_treats_a_sum_that_does_not_fit_as_passed() {
    let t0 = Instant::now();
    // a window so long that its end does not fit in an `Instant`: the record has passed, so it is dropped and
    // the window has room, however full it was
    let mut times = VecDeque::from([t0]);
    assert_eq!(restart_slot(&mut times, t0, 1, Duration::MAX), Slot::Now);
    assert_eq!(times, [t0]);
    // a window whose end fits still keeps the record
    let mut times = VecDeque::from([t0]);
    assert_eq!(
        restart_slot(&mut times, t0, 1, secs(1)),
        Slot::Wait(t0 + secs(1))
    );
}

#[test]
fn the_restart_window_allows_no_more_than_its_limit_in_any_window() {
    let (t0, w, limit) = (Instant::now(), secs(10), 3);
    let mut times = VecDeque::new();
    let mut made = Vec::new();
    for i in 0..100 {
        let now = t0 + secs(i);
        if restart_slot(&mut times, now, limit, w) == Slot::Now {
            made.push(now);
        }
        assert!(times.len() <= 3);
    }
    // three at once and three more as soon as the oldest leaves the window, ten times
    assert_eq!(made.len(), 30);
    for &m in &made {
        let inside = made.iter().filter(|&&x| x <= m && m < x + w).count();
        assert!(
            inside <= 3,
            "{inside} restarts in the window that ends at {m:?}"
        );
    }
    assert_eq!(made[3], t0 + w);
}

/// A supervisor whose window is full: the restart wanted at `t0` found room, the second one did not.
fn window_full(window: Duration) -> (Supervisor, Instant) {
    let mut c = cfg();
    (c.tick, c.wait_deadline, c.restarts, c.restart_window) = (MS, 50 * MS, 1, window);
    let mut s = Supervisor::new(c).unwrap();
    let t0 = Instant::now();
    s.proceed(t0, Next::Restart);
    assert!(matches!(s.run, Run::Down));
    assert_eq!((s.status().restarts, s.not_before), (1, None));
    s.proceed(t0, Next::Restart);
    (s, t0)
}

#[test]
fn a_full_window_keeps_down_and_the_requests_keep_their_deadlines() {
    let (mut s, t0) = window_full(secs(30));
    let a = s.submit(&get(b"/a")).unwrap();
    // the second restart is not made: not counted, and the time before which nothing starts is held
    assert!(matches!(s.run, Run::Down));
    assert_eq!(
        (s.status().restarts, s.not_before),
        (1, Some(t0 + secs(30)))
    );
    assert_eq!(s.status().phase, Phase::Starting);
    // a step starts nothing; the clock runs, so the request ends at its own deadline, not at the window
    thread::sleep(60 * MS);
    s.step(Instant::now());
    assert!(matches!(s.run, Run::Down) && s.run_id.is_none());
    assert_eq!(
        s.poll(Instant::now()),
        vec![(a, Verdict::Uninspectable(Reason::WaitDeadline))]
    );
    assert_eq!(
        (s.status().restarts, s.not_before),
        (1, Some(t0 + secs(30)))
    );
    // a request that comes now waits as well, and a shutdown stops the wait at once: it starts nothing and
    // the restart that was waiting is not counted
    let b = s.submit(&get(b"/b")).unwrap();
    let sd = s.shutdown(Instant::now());
    assert_eq!(sd.results, vec![(b, unavailable())]);
    assert_eq!(sd.phase, Phase::Stopped);
    assert!(!sd.bye && sd.exit_confirmed && sd.dir_removed);
    assert_eq!((sd.held_left, sd.waiting_left), (0, 0));
    assert!(s.run_id.is_none());
    let st = s.status();
    assert_eq!((st.phase, st.inc, st.restarts), (Phase::Stopped, 1, 1));
}

#[test]
fn a_restart_that_is_due_is_recorded_counted_and_started() {
    let (mut s, t0) = window_full(40 * MS);
    let due = s.not_before.unwrap();
    assert_eq!(due, t0 + 40 * MS);
    assert_eq!((s.status().restarts, s.not_before), (1, Some(due)));
    // from the time: the oldest record is a whole window old, so the window has room again; the try is
    // made (`cfg()` names a tmp root that is not there, so it ends at once, before anything is made)
    thread::sleep(50 * MS);
    assert!(Instant::now() >= due);
    s.step(Instant::now());
    let st = s.status();
    assert!(
        matches!(st.phase, Phase::Failed(Failure::TmpDir(_))),
        "{st:?}"
    );
    assert_eq!((st.restarts, st.inc), (2, 2));
    assert_eq!(s.not_before, None);
    assert_eq!(s.restart_times.len(), 1);
    assert!(s.restart_times[0] >= due);
    let sd = s.shutdown(Instant::now());
    assert!(sd.exit_confirmed && sd.dir_removed);
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
fn an_unreaped_stop_keeps_the_slot_and_ends_the_intake() {
    let (mut e, t0, held, waiting) = faulted();
    assert_eq!(
        apply_stop(&mut e, t0, 1, StopTag::Unreaped),
        Some(Failure::ReapUnknown)
    );
    // the exit is not confirmed: the incarnation is the same, the slot is held, nothing is returned
    assert_eq!((e.incarnation(), e.held_slots(), e.waiting()), (1, 1, 0));
    let o = e.outcome(held).unwrap();
    assert_eq!(o.decision, Some(Decision::Uninspectable(Why::ConnFault)));
    assert!(o.returns.is_empty());
    // the waiting request does not wait for a start that will not come
    assert_eq!(
        e.outcome(waiting).unwrap().decision,
        Some(Decision::Uninspectable(Why::Halted(Halt::NoRestart)))
    );
    assert_eq!(
        e.next_done().map(|(i, d)| (i, verdict_of(d))),
        Some((held, Verdict::Uninspectable(Reason::InspectorLost)))
    );
    assert_eq!(
        e.next_done().map(|(i, d)| (i, verdict_of(d))),
        Some((waiting, unavailable()))
    );
    // a later confirmed reap of the same incarnation returns the slot once
    assert_eq!(apply_stop(&mut e, t0, 1, StopTag::Done), None);
    assert_eq!((e.incarnation(), e.held_slots()), (2, 0));
    assert!(
        e.outcome(held).is_none(),
        "delivered, so it goes with the slot"
    );
}

#[test]
fn a_stop_that_left_the_directory_counts_the_exit_once() {
    let (mut e, t0, held, waiting) = faulted();
    assert_eq!(
        apply_stop(&mut e, t0, 1, StopTag::DirLeft),
        Some(Failure::CleanupUnknown)
    );
    // the exit is confirmed: the incarnation is used up, the slot is back, the intake is ended
    assert_eq!((e.incarnation(), e.held_slots(), e.waiting()), (2, 0, 0));
    assert_eq!(
        e.outcome(held).unwrap().returns,
        vec![(1, ReturnReason::ExitConfirmed)]
    );
    assert_eq!(
        e.outcome(waiting).unwrap().decision,
        Some(Decision::Uninspectable(Why::Halted(Halt::NoRestart)))
    );
    // the same incarnation again does nothing, however it comes
    e.exit_confirmed(t0, 1);
    assert_eq!(apply_stop(&mut e, t0, 1, StopTag::Done), None);
    assert!(apply_stop(&mut e, t0, 1, StopTag::DirLeft).is_some());
    assert_eq!((e.incarnation(), e.held_slots()), (2, 0));
    assert_eq!(e.outcome(held).unwrap().returns.len(), 1);
}

#[test]
fn a_confirmed_stop_returns_the_slot_and_numbers_the_next_start() {
    let (mut e, t0, held, waiting) = faulted();
    assert_eq!(apply_stop(&mut e, t0, 1, StopTag::Done), None);
    assert_eq!((e.incarnation(), e.held_slots(), e.waiting()), (2, 0, 1));
    assert_eq!(
        e.outcome(held).unwrap().returns,
        vec![(1, ReturnReason::ExitConfirmed)]
    );
    // the request that waited goes on to the next start with its own deadline
    assert_eq!(e.outcome(waiting).unwrap().decision, None);
    e.ready(t0, 2);
    assert_eq!(e.outcome(waiting).unwrap().txs, vec![2]);
    assert_eq!(apply_stop(&mut e, t0, 1, StopTag::Done), None);
    assert_eq!(e.incarnation(), 2);
}

// ---- the public API without a process ----

#[test]
fn a_supervisor_starts_nothing_and_refuses_a_bad_configuration() {
    let s = Supervisor::new(cfg()).unwrap();
    assert_eq!(
        s.status(),
        Status {
            phase: Phase::Starting,
            inc: 1,
            restarts: 0,
            waiting: 0,
            held: 0,
            records: 0
        }
    );
    let mut bad = cfg();
    bad.discard_limit = u32::MAX;
    assert_eq!(
        Supervisor::new(bad).err(),
        Some(ConfigError("discard_limit must be below u32::MAX"))
    );
}

#[test]
fn shutdown_before_any_start_decides_the_request_and_starts_nothing() {
    let mut s = Supervisor::new(cfg()).unwrap();
    let a = s.submit(&get(b"/a")).unwrap();
    assert_eq!(a, 0);
    let sd = s.shutdown(Instant::now());
    assert_eq!(sd.results, vec![(a, unavailable())]);
    assert_eq!(sd.phase, Phase::Stopped);
    assert!(!sd.bye && sd.exit_confirmed && sd.dir_removed);
    assert_eq!((sd.held_left, sd.waiting_left), (0, 0));
    let st = s.status();
    assert_eq!((st.phase, st.inc, st.restarts), (Phase::Stopped, 1, 0));
    // again: nothing is delivered twice
    let sd = s.shutdown(Instant::now());
    assert_eq!(sd.results, vec![]);
    assert_eq!(sd.phase, Phase::Stopped);
    // after it: a record at once, delivered once, nothing started
    let b = s.submit(&get(b"/b")).unwrap();
    assert_eq!(b, 1);
    assert_eq!(s.poll(Instant::now()), vec![(b, unavailable())]);
    assert_eq!(s.poll(Instant::now()), vec![]);
    assert_eq!(s.status().inc, 1);
    assert!(matches!(s.run, Run::Stopped));
}

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
    // a cancel decides at once, an unknown or delivered id is ignored
    let mut s = Supervisor::new(cfg()).unwrap();
    let a = s.submit(&get(b"/a")).unwrap();
    let b = s.submit(&get(b"/b")).unwrap();
    s.cancel(a);
    s.cancel(99);
    let sd = s.shutdown(Instant::now());
    assert_eq!(
        sd.results,
        vec![
            (a, Verdict::Uninspectable(Reason::Cancelled)),
            (b, unavailable())
        ]
    );
    s.cancel(a);
    s.cancel(b);
    assert_eq!(s.shutdown(Instant::now()).results, vec![]);
}

#[test]
fn requests_that_cannot_be_inspected_faithfully_are_refused_in_order() {
    let refused = |r: Request<'_>| {
        let mut s = Supervisor::new(cfg()).unwrap();
        let e = s.submit(&r).unwrap_err();
        assert_eq!(s.status().records, 0, "no record for {e:?}");
        e
    };
    let unsupported = |why| Refused::Unsupported(why);
    let big = vec![b'a'; (codec::MAX_DECLARED as usize) + 1];
    // 1. the protocol's limit comes first, whatever else is wrong
    let te: [(&[u8], &[u8]); 1] = [(b"Transfer-Encoding", b"chunked")];
    assert_eq!(
        refused(with(b"/", &te, &big)),
        unsupported("body over the protocol limit")
    );
    // 2. coded bodies, whatever the case of the name
    for name in [
        &b"Transfer-Encoding"[..],
        b"transfer-encoding",
        b"TRANSFER-ENCODING",
    ] {
        let h: [(&[u8], &[u8]); 1] = [(name, b"chunked")];
        assert_eq!(
            refused(with(b"/", &h, b"")),
            unsupported("transfer-encoding")
        );
    }
    let ce: [(&[u8], &[u8]); 1] = [(b"content-ENCODING", b"gzip")];
    assert_eq!(
        refused(with(b"/", &ce, b"")),
        unsupported("content-encoding")
    );
    let both: [(&[u8], &[u8]); 2] = [(b"Content-Encoding", b"gzip"), (b"Transfer-Encoding", b"x")];
    assert_eq!(
        refused(with(b"/", &both, b"")),
        unsupported("transfer-encoding")
    );
    // 3. Content-Length: one, digits only, and the length of the body
    let cl = |v: &'static [u8]| -> [(&'static [u8], &'static [u8]); 1] { [(b"Content-Length", v)] };
    for bad in [
        &b""[..],
        b"1",
        b"+0",
        b"0 ",
        b" 0",
        b"0x0",
        b"-0",
        b"99999999999999999999999",
    ] {
        assert_eq!(
            refused(with(b"/", &cl(bad), b"")),
            unsupported("content-length"),
            "{bad:?}"
        );
    }
    let two: [(&[u8], &[u8]); 2] = [(b"Content-Length", b"0"), (b"content-length", b"0")];
    assert_eq!(
        refused(with(b"/", &two, b"")),
        unsupported("content-length")
    );
    // 4. a body needs exactly one Content-Type of the kinds the inspector parses
    let none: [(&[u8], &[u8]); 1] = [(b"Content-Length", b"3")];
    assert_eq!(
        refused(with(b"/", &none, b"a=b")),
        unsupported("content-type")
    );
    // application/ + a name of `len` characters + +json
    let json_named = |len: usize| [&b"application/"[..], &vec![b'a'; len], b"+json"].concat();
    let too_long = json_named(123);
    for bad in [
        &b"application/xml"[..],
        b"text/plain",
        b"",
        b"application/x-www-form-urlencoded2",
        b"multipart/mixed",
        b"application/json2",
        b"application/jsonp",
        b"text/json",
        // application/<name>+json: no name, a first character that is not a letter or digit, a character
        // outside the set, the name Coraza reads as urlencoded (also in any case), another type, another end,
        // a name one character too long
        b"application/+json",
        b"application/.x+json",
        b"application/-x+json",
        b"application/a+b+json",
        b"application/x/y+json",
        b"application/\xc3\xa9+json",
        b"application/x-www-form-urlencoded+json",
        b"Application/X-WWW-Form-Urlencoded+JSON",
        b"application/x-www-form-urlencoded-x+json",
        b"text/x+json",
        b"application/x+json2",
        b"application/x+jsonp",
        &too_long[..],
    ] {
        let h: [(&[u8], &[u8]); 2] = [(b"Content-Length", b"3"), (b"Content-Type", bad)];
        assert_eq!(
            refused(with(b"/", &h, b"a=b")),
            unsupported("content-type"),
            "{bad:?}"
        );
    }
    let twice: [(&[u8], &[u8]); 3] = [
        (b"Content-Length", b"3"),
        (b"Content-Type", b"application/x-www-form-urlencoded"),
        (b"content-type", b"application/x-www-form-urlencoded"),
    ];
    assert_eq!(
        refused(with(b"/", &twice, b"a=b")),
        unsupported("content-type")
    );
    let mixed: [(&[u8], &[u8]); 3] = [
        (b"Content-Length", b"3"),
        (b"Content-Type", b"application/json"),
        (b"content-type", b"application/x-www-form-urlencoded"),
    ];
    assert_eq!(
        refused(with(b"/", &mixed, b"a=b")),
        unsupported("content-type")
    );
    // what TX_BEGIN cannot carry is refused right after the protocol's limit (1), before the header rules (2 to 4)
    let long_uri = vec![b'a'; 5000];
    assert_eq!(
        refused(with(&long_uri, &HOST, b"")),
        Refused::Invalid("uri length out of range")
    );
    assert_eq!(
        refused(with(&long_uri, &te, b"")),
        Refused::Invalid("uri length out of range")
    );
    assert_eq!(
        refused(Request {
            method: b"",
            ..get(b"/")
        }),
        Refused::Invalid("method length out of range")
    );
    // accepted: the two form types, in any case, with parameters and spaces; an empty body needs no type
    let mut s = Supervisor::new(cfg()).unwrap();
    let ok = |ct: &'static [u8]| -> [(&'static [u8], &'static [u8]); 2] {
        [(b"Content-Length", b"3"), (b"Content-Type", ct)]
    };
    for ct in [
        &b"application/x-www-form-urlencoded"[..],
        b"Application/X-WWW-Form-Urlencoded; charset=UTF-8",
        b"  multipart/form-data ; boundary=x",
    ] {
        s.submit(&with(b"/", &ok(ct), b"a=b")).unwrap();
    }
    let zero: [(&[u8], &[u8]); 1] = [(b"Content-Length", b"0")];
    s.submit(&with(b"/", &zero, b"")).unwrap();
    assert_eq!(s.status().records, 4);
    // accepted: application/json, in any case, with parameters, spaces and tabs
    let mut j = Supervisor::new(cfg()).unwrap();
    for ct in [
        &b"application/json"[..],
        b"Application/JSON; charset=UTF-8",
        b"application/json;charset=utf-8",
        b"  application/json  ",
        b"\tapplication/json\t ; x=y",
    ] {
        j.submit(&with(b"/", &ok(ct), b"[1]")).unwrap();
    }
    assert_eq!(j.status().records, 5);
    // accepted: application/<name>+json, in any case, with parameters; a name of 1 character, one that starts
    // with a digit, one short of the urlencoded name by a character, and the longest name
    let mut n = Supervisor::new(cfg()).unwrap();
    let longest = json_named(122);
    for ct in [
        &b"application/vnd.api+json"[..],
        b"application/problem+json",
        b"application/merge-patch+json",
        b"Application/VND.API+JSON; charset=utf-8",
        b"application/a+json",
        b"application/1x+json",
        b"application/x-www-form-urlencode+json",
        &longest[..],
    ] {
        let h: [(&[u8], &[u8]); 2] = [(b"Content-Length", b"3"), (b"Content-Type", ct)];
        n.submit(&with(b"/", &h, b"[1]")).unwrap();
    }
    assert_eq!(n.status().records, 8);
    // the limit itself, in the largest number of fragments
    let max = vec![b'a'; codec::MAX_DECLARED as usize];
    let h: [(&[u8], &[u8]); 2] = [
        (b"Content-Length", b"1048576"),
        (b"Content-Type", b"application/x-www-form-urlencoded"),
    ];
    s.submit(&with(b"/", &h, &max)).unwrap();
}

#[test]
fn a_full_record_table_refuses_without_a_record() {
    let mut c = cfg();
    (c.slots, c.wait_queue, c.records) = (1, 1, 2);
    let mut s = Supervisor::new(c).unwrap();
    s.submit(&get(b"/a")).unwrap();
    // the queue is full: a record, decided at once
    let b = s.submit(&get(b"/b")).unwrap();
    assert_eq!(s.submit(&get(b"/c")), Err(Refused::Full));
    assert_eq!(s.status().records, 2);
    let sd = s.shutdown(Instant::now());
    assert_eq!(
        sd.results,
        vec![
            (b, Verdict::Uninspectable(Reason::QueueFull)),
            (0, unavailable())
        ]
    );
    // delivered and nothing held: room again, and the numbers go on
    assert_eq!(s.submit(&get(b"/d")), Ok(2));
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

#[test]
#[ignore = "needs a built inspector"]
fn a_request_is_allowed_and_a_shutdown_ends_with_bye() {
    let root = real_root();
    let mut s = Supervisor::new(real(root.path(), 0)).unwrap();
    let a = s.submit(&get(b"/")).unwrap();
    let guard = within(30);
    let mut got = Vec::new();
    while got.is_empty() {
        assert!(Instant::now() < guard, "no result: {:?}", s.status());
        got = s.poll(soon());
    }
    assert_eq!(got, vec![(a, Verdict::Allow)]);
    assert_eq!(s.status().phase, Phase::Ready);
    assert!(root.entries() == 1);
    let sd = finish(s, &root);
    assert!(sd.bye);
    assert_eq!(sd.phase, Phase::Stopped);
    assert_eq!(sd.results, vec![]);
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
fn a_hello_past_its_deadline_is_a_restart_without_luck() {
    let root = real_root();
    let mut s = Supervisor::new(real(root.path(), 0)).unwrap();
    let a = s.submit(&get(b"/")).unwrap();
    // Down -> launch -> Hello
    s.step(soon());
    let Run::Hello { start, until } = &mut s.run else {
        panic!("not waiting for HELLO");
    };
    // a time that has passed whatever the scheduler did
    *until = start.started.checked_sub(Duration::from_nanos(1)).unwrap();
    s.step(soon());
    assert!(matches!(&s.run, Run::Stopping { end: End::Restart(why), .. } if *why == "hello wait"));
    let guard = within(30);
    while !matches!(s.run, Run::Failed { .. }) {
        assert!(Instant::now() < guard, "{:?}", s.status());
        s.step(soon());
    }
    let st = s.status();
    assert_eq!(st.phase, Phase::Failed(Failure::BudgetExhausted));
    assert_eq!((st.restarts, st.waiting, st.held), (0, 0, 0));
    assert_eq!(s.poll(Instant::now()), vec![(a, unavailable())]);
    // the directory of the start is gone with the process
    assert_eq!(root.entries(), 0);
    let sd = finish(s, &root);
    assert_eq!(sd.phase, Phase::Failed(Failure::BudgetExhausted));
    // With a restart in the window the same stop is only a restart: the next start is made and inspects.
    let mut s = Supervisor::new(real(root.path(), 1)).unwrap();
    let a = s.submit(&get(b"/")).unwrap();
    s.step(soon());
    let Run::Hello { start, until } = &mut s.run else {
        panic!("not waiting for HELLO");
    };
    *until = start.started.checked_sub(Duration::from_nanos(1)).unwrap();
    s.step(soon());
    assert!(matches!(&s.run, Run::Stopping { end: End::Restart(why), .. } if *why == "hello wait"));
    until_ready(&mut s);
    let st = s.status();
    assert_eq!((st.phase, st.inc, st.restarts), (Phase::Ready, 2, 1));
    let guard = within(30);
    let mut got = Vec::new();
    while got.is_empty() {
        assert!(Instant::now() < guard, "no result: {:?}", s.status());
        got = s.poll(soon());
    }
    assert_eq!(got, vec![(a, Verdict::Allow)]);
    let sd = finish(s, &root);
    assert!(sd.bye);
    assert_eq!(sd.phase, Phase::Stopped);
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
    let run_id = s.run_id.unwrap();
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
    let Run::Ready { start } = &mut s.run else {
        panic!("not ready");
    };
    start.kill_now().unwrap();
    while !matches!(s.run, Run::Stopping { .. }) {
        assert!(Instant::now() < guard, "loss not seen: {:?}", s.status());
        let _ = s.check(Instant::now());
        let _ = s.read_step(soon());
    }
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
    assert!(
        !root
            .path()
            .join(format!("insp-{run_id:016x}-{:08x}", 1))
            .exists()
    );
    assert_eq!(root.entries(), 1);
    // Delivered once each, in the order they were decided; a delivered record with no slot is gone.
    assert_eq!(
        s.engine.next_done().map(|(i, d)| (i, verdict_of(d))),
        Some((a, Verdict::Uninspectable(Reason::InspectorLost)))
    );
    assert_eq!(
        s.engine.next_done().map(|(i, d)| (i, verdict_of(d))),
        Some((b, Verdict::Allow))
    );
    assert!(s.engine.next_done().is_none());
    assert!(s.engine.outcome(a).is_none() && s.engine.outcome(b).is_none());
    let sd = finish(s, &root);
    assert_eq!(sd.results, vec![]);
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
fn a_shutdown_while_hello_is_awaited_stops_the_start() {
    let root = real_root();
    let mut s = Supervisor::new(real(root.path(), 3)).unwrap();
    let a = s.submit(&get(b"/")).unwrap();
    s.step(soon());
    assert!(matches!(s.run, Run::Hello { .. }));
    let sd = s.shutdown(within(10));
    assert_eq!(sd.results, vec![(a, unavailable())]);
    assert_eq!(sd.phase, Phase::Stopped);
    assert!(!sd.bye && sd.exit_confirmed && sd.dir_removed);
    let st = s.status();
    assert_eq!(
        (st.inc, st.restarts),
        (2, 0),
        "no restart after the intake ended"
    );
    assert_eq!(root.entries(), 0);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_shutdown_in_a_stop_in_progress_does_not_start_again() {
    let root = real_root();
    let mut s = Supervisor::new(real(root.path(), 3)).unwrap();
    let (a, b) = (
        s.submit(&get(b"/a")).unwrap(),
        s.submit(&get(b"/b")).unwrap(),
    );
    until_ready(&mut s);
    assert!(s.write_step().is_continue());
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
    // a was taken: lost with the connection. b waits for the next start, which the shutdown forbids.
    let sd = s.shutdown(past());
    assert_eq!(
        sd.results,
        vec![
            (a, Verdict::Uninspectable(Reason::InspectorLost)),
            (b, unavailable())
        ]
    );
    assert_eq!(sd.phase, Phase::Stopped);
    assert!(!sd.bye && sd.exit_confirmed && sd.dir_removed);
    let st = s.status();
    assert_eq!((st.inc, st.restarts), (2, 0));
    assert_eq!(root.entries(), 0);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_hello_that_does_not_match_ends_the_supervisor_for_good() {
    let root = real_root();
    let mut c = real(root.path(), 3);
    c.rules_sha256[0] ^= 1;
    let mut s = Supervisor::new(c).unwrap();
    let a = s.submit(&get(b"/")).unwrap();
    let guard = within(30);
    while !matches!(s.run, Run::Failed { .. }) {
        assert!(Instant::now() < guard, "{:?}", s.status());
        s.step(soon());
    }
    let st = s.status();
    assert_eq!(
        st.phase,
        Phase::Failed(Failure::Hello("hello rules sha256 differs"))
    );
    assert_eq!((st.inc, st.restarts), (2, 0));
    assert_eq!(s.poll(Instant::now()), vec![(a, unavailable())]);
    assert_eq!(root.entries(), 0);
    finish(s, &root);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_start_that_cannot_run_ends_the_supervisor_when_it_may_not_restart() {
    let root = real_root();
    let mut c = real(root.path(), 0);
    c.inspector = root.path().join("missing");
    let mut s = Supervisor::new(c).unwrap();
    let a = s.submit(&get(b"/")).unwrap();
    let guard = within(30);
    while !matches!(s.run, Run::Failed { .. }) {
        assert!(Instant::now() < guard, "{:?}", s.status());
        s.step(soon());
    }
    let st = s.status();
    assert_eq!(st.phase, Phase::Failed(Failure::BudgetExhausted));
    // the one try used up its incarnation, and it was not a restart
    assert_eq!((st.inc, st.restarts), (2, 0));
    assert_eq!(s.poll(Instant::now()), vec![(a, unavailable())]);
    assert_eq!(root.entries(), 0);
    finish(s, &root);
}

/// Every start of this supervisor fails (`inspector`). One restart is allowed in a window of 300 ms. It runs
/// through two whole windows and must never fail, never restart faster than once a window (the number of
/// restarts is at most one more than the windows that have passed), keep its incarnations in step with the
/// restarts, and leave a request that waits to its own deadline. A shutdown ends the wait and decides the
/// request that waits then.
fn fails_every_start_but_waits_for_the_window(root: &TempRoot, inspector: PathBuf) {
    let mut c = real(root.path(), 1);
    c.inspector = inspector;
    (c.restart_window, c.wait_deadline) = (300 * MS, 400 * MS);
    let window = c.restart_window;
    let mut s = Supervisor::new(c).unwrap();
    let started = Instant::now();
    let a = s.submit(&get(b"/")).unwrap();
    let guard = within(30);
    let mut got = Vec::new();
    while s.status().restarts < 3 {
        assert!(Instant::now() < guard, "{:?}", s.status());
        got.extend(s.poll(soon()));
        let st = s.status();
        assert!(
            matches!(st.phase, Phase::Starting | Phase::Stopping),
            "{st:?}"
        );
        assert!(
            u128::from(st.restarts) <= 1 + started.elapsed().as_nanos() / window.as_nanos(),
            "{st:?}"
        );
        assert!(
            (st.restarts + 1..=st.restarts + 2).contains(&st.inc),
            "{st:?}"
        );
    }
    assert!(started.elapsed() >= 2 * window);
    assert_eq!(got, vec![(a, Verdict::Uninspectable(Reason::WaitDeadline))]);
    let b = s.submit(&get(b"/")).unwrap();
    let sd = finish(s, root);
    assert_eq!(sd.results, vec![(b, unavailable())]);
    assert_eq!(sd.phase, Phase::Stopped);
    assert!(!sd.bye);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_start_that_cannot_run_is_tried_again_once_a_window_and_never_fails() {
    let root = real_root();
    fails_every_start_but_waits_for_the_window(&root, root.path().join("missing"));
}

#[test]
#[ignore = "needs a built inspector"]
fn a_start_that_ends_before_hello_is_tried_again_once_a_window_and_never_fails() {
    let root = real_root();
    // exits at once, whatever it is given: the connection ends before any HELLO
    fails_every_start_but_waits_for_the_window(&root, PathBuf::from("/bin/true"));
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

#[test]
#[ignore = "needs a built inspector"]
fn a_start_that_ends_before_hello_ends_the_supervisor_when_it_may_not_restart() {
    let root = real_root();
    let mut c = real(root.path(), 0);
    // exits at once, whatever it is given: the connection ends before any HELLO
    c.inspector = PathBuf::from("/bin/true");
    let mut s = Supervisor::new(c).unwrap();
    let a = s.submit(&get(b"/")).unwrap();
    let guard = within(30);
    while !matches!(s.run, Run::Failed { .. }) {
        assert!(Instant::now() < guard, "{:?}", s.status());
        s.step(soon());
    }
    let st = s.status();
    assert_eq!(st.phase, Phase::Failed(Failure::BudgetExhausted));
    assert_eq!((st.inc, st.restarts), (2, 0));
    assert_eq!(s.poll(Instant::now()), vec![(a, unavailable())]);
    assert_eq!(root.entries(), 0);
    finish(s, &root);
}
