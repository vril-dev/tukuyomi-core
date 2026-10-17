use std::sync::mpsc::TryRecvError;
use std::thread;
use std::time::{Duration, Instant};

use crate::support::*;

#[test]
#[ignore = "needs a built inspector"]
fn killing_the_inspector_during_an_inspection_gives_503_and_no_upstream_connection() {
    // One restart in the budget: without it the kernel would give up, and the proxy would stop on that failure.
    let knobs = Knobs {
        restarts: 1,
        ..Knobs::slow()
    };
    let mut proxy = Proxy::start("kill_inspector", knobs);
    let victim = proxy.inspector();
    let mut sock = proxy.start_slow(&post_form("/submit", &padded_form("ok", MAX_BODY)));
    run_kill("KILL", victim);
    let answer = collect(&mut sock, Instant::now());
    assert_empty_answer(&answer, 503);
    proxy
        .records
        .conn("the 503 record", |l| l.contains(": failed 503 inspector "));
    assert_eq!(proxy.upstream.connections(), 0);

    // The kernel started a new inspector, and a normal request passes through it.
    let after = exchange(proxy.port, &get("/after"));
    assert_eq!(after.status(), 200, "answer: {:?}", after.text());
    let replacement = proxy.wait_inspector(Some(victim));
    assert_ne!(replacement, victim);
    assert_eq!(proxy.finish(1), StopCounts::NONE);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_second_kill_within_the_restart_window_gives_503_until_the_window_has_passed() {
    // One restart in each window. The window is long, because two times have to fit into it with room to spare:
    // the time to the second kill (a restart and a request through the new inspector, normally well under a
    // second), and then the wait of a request for its verdict (`wait_deadline`, 5 s), which must end while the
    // kernel is still waiting. `wait_deadline` stays at 5 s because the request that follows the first kill has to
    // wait for the restart, hello included, within it; a shorter window would make the scene depend on the speed
    // of the host.
    let window = Duration::from_secs(15);
    let knobs = Knobs {
        restarts: 1,
        restart_window_ms: 15_000,
        ..Knobs::slow()
    };
    let wait_deadline = Duration::from_millis(knobs.wait_deadline_ms);
    let mut proxy = Proxy::start("restart_window", knobs);
    let records = proxy.records.clone();
    let incarnation = |l: &str| l.starts_with("driver: inspector incarnation changed, ");
    let first = proxy.inspector();
    let mut sock = proxy.start_slow(&post_form("/submit", &padded_form("ok", MAX_BODY)));

    // The first kill. The kernel records the restart after the kill, so its window cannot be over before
    // `killed` and a whole window have passed.
    let killed = Instant::now();
    run_kill("KILL", first);
    let answer = collect(&mut sock, killed);
    assert_empty_answer(&answer, 503);
    records.conn("the 503 record", |l| l.contains(": failed 503 inspector "));
    assert_eq!(proxy.upstream.connections(), 0);

    // The window had room: the kernel started an inspector, and a normal request passes through it.
    let after = exchange(proxy.port, &get("/after"));
    assert_eq!(after.status(), 200, "answer: {:?}", after.text());
    let second = proxy.wait_inspector(Some(first));
    assert_ne!(second, first);
    assert_eq!(proxy.upstream.connections(), 1);
    assert!(
        killed.elapsed() < window / 2,
        "the host is too slow for this scene: {:?} to restart the inspector, with a window of {window:?}",
        killed.elapsed()
    );

    // The second kill, right away: the window holds its one restart. The record of the new incarnation shows that
    // the kernel has seen the end of the second inspector.
    run_kill("KILL", second);
    let lines = records.wait_lines("the two incarnation records", 2, incarnation);
    assert_eq!(
        lines.iter().map(|l| numbers_in(l)).collect::<Vec<_>>(),
        // The incarnation, and the restarts made in all: the second end did not make one.
        [[2, 1], [3, 1]],
        "records: {lines:#?}"
    );

    // While the kernel waits, requests wait for their own deadline and are answered 503. Two at once, so that the
    // wait is the one deadline.
    let port = proxy.port;
    let waiting: Vec<Reply> = thread::scope(|scope| {
        let clients: Vec<_> = (0..2)
            .map(|_| scope.spawn(move || exchange(port, &get("/during"))))
            .collect();
        clients
            .into_iter()
            .map(|client| client.join().expect("a client panicked"))
            .collect()
    });
    assert!(
        Instant::now() < killed + window,
        "the host is too slow for this scene: the answers came after the window may have passed"
    );
    for reply in &waiting {
        assert_empty_answer(reply, 503);
        assert!(
            reply.took >= wait_deadline,
            "the answer came after {:?}, before the wait deadline of {wait_deadline:?}",
            reply.took
        );
    }
    records.conns("the two 503 records", 2, |l| {
        l.contains(": failed 503 inspection wait deadline ")
    });
    assert_eq!(proxy.upstream.connections(), 1);
    // The kernel waits without a process, and the proxy is still there.
    assert!(
        children_of(proxy.pid)
            .into_iter()
            .all(|pid| !is_inspector(pid)),
        "an inspector is running inside the window"
    );
    assert!(
        matches!(proxy.exit.try_recv(), Err(TryRecvError::Empty)),
        "the proxy ended; its records: {:#?}",
        records.lines()
    );

    // The window passes: the kernel starts the inspector again, not before, and a request passes.
    let third = proxy.wait_inspector(Some(second));
    assert_ne!(third, second);
    let started = Instant::now();
    assert!(
        started >= killed + window,
        "the inspector was started again {:?} after the first kill, inside the window of {window:?}",
        started.duration_since(killed)
    );
    let again = exchange(proxy.port, &get("/again"));
    assert_eq!(again.status(), 200, "answer: {:?}", again.text());
    assert_eq!(proxy.upstream.connections(), 2);

    // The restarts made no other incarnation record, and the proxy was never in a failed state.
    let lines = records.lines();
    assert_eq!(
        lines.iter().filter(|l| incarnation(l)).count(),
        2,
        "records: {lines:#?}"
    );
    assert_eq!(proxy.finish(2), StopCounts::NONE);
}
