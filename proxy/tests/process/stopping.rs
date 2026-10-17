use std::io::Write;
use std::time::Duration;

use crate::support::*;

// ---------------------------------------------------------------------------------------------------------
// Stopping on SIGTERM
// ---------------------------------------------------------------------------------------------------------

#[test]
#[ignore = "needs a built inspector"]
fn sigterm_lets_an_in_flight_request_finish_and_the_proxy_exits_within_stop_wait() {
    let proxy = Proxy::start("sigterm_in_flight", Knobs::slow());
    let mut sock = proxy.start_slow(&post_form("/submit", &padded_form("ok", MAX_BODY)));
    let since = proxy.term();

    // The inspection goes on after the signal, the request is forwarded, and its answer comes back whole.
    let answer = collect(&mut sock, since);
    assert_eq!(answer.status(), 200, "answer: {:?}", answer.text());
    assert_eq!(answer.message().body, UPSTREAM_BODY.as_bytes());
    let requests = proxy.upstream.requests();
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0].len() > MAX_BODY,
        "the upstream got {} bytes",
        requests[0].len()
    );

    let counts = proxy.finish_after_term(since, 1);
    assert!(
        counts.records >= 1,
        "the request was in flight when the stop began: {counts:?}"
    );
}

// ---------------------------------------------------------------------------------------------------------
// Signals, and what a stop does to new and to running connections
// ---------------------------------------------------------------------------------------------------------

/// Serves one request, sends the signal and checks that the proxy ends as it does for SIGTERM: exit code 0, the
/// kernel stopped cleanly, nothing left.
fn a_signal_ends_the_proxy(test: &str, signal: &str, name: &str) {
    let proxy = Proxy::start(test, Knobs::quick());
    let served = exchange(proxy.port, &get("/before"));
    assert_eq!(served.status(), 200, "answer: {:?}", served.text());
    let since = proxy.signal(signal);
    assert_eq!(proxy.finish_after_signal(name, since, 1), StopCounts::NONE);
}

#[test]
#[ignore = "needs a built inspector"]
fn sigint_stops_the_proxy_with_exit_code_0() {
    a_signal_ends_the_proxy("sigint", "INT", "SIGINT");
}

#[test]
#[ignore = "needs a built inspector"]
fn sighup_stops_the_proxy_with_exit_code_0() {
    a_signal_ends_the_proxy("sighup", "HUP", "SIGHUP");
}

#[test]
#[ignore = "needs a built inspector"]
fn a_second_signal_during_the_stop_is_only_logged_and_the_exit_code_stays_0() {
    let proxy = Proxy::start("second_signal", Knobs::slow());
    let records = proxy.records.clone();
    let mut sock = proxy.start_slow(&post_form("/submit", &padded_form("ok", MAX_BODY)));
    let since = proxy.term();
    records.wait_line("the first stop record", |l| l == "stop: SIGTERM");

    // One signal at a time, each seen in the records before the next is sent: signals of one kind that are
    // pending together count as one.
    for (signal, name) in [("INT", "SIGINT"), ("HUP", "SIGHUP"), ("TERM", "SIGTERM")] {
        proxy.signal(signal);
        let again = format!("stop: {name} again");
        records.wait_line(&again, |l| l == again);
    }

    // The stop went on as it was: the request in flight is forwarded and answered whole.
    let answer = collect(&mut sock, since);
    assert_eq!(answer.status(), 200, "answer: {:?}", answer.text());
    assert_eq!(answer.message().body, UPSTREAM_BODY.as_bytes());
    let counts = proxy.finish_after_term(since, 1);
    assert!(
        counts.records >= 1,
        "the request was in flight when the stop began: {counts:?}"
    );

    // One stop, begun by the first signal: the others did not begin another.
    let lines = records.lines();
    let count = |want: &str| lines.iter().filter(|l| l.as_str() == want).count();
    assert_eq!(count("stop: SIGTERM"), 1, "records: {lines:#?}");
    assert_eq!(count("stop: SIGINT"), 0, "records: {lines:#?}");
    assert_eq!(count("stop: SIGHUP"), 0, "records: {lines:#?}");
    let begun = |prefix: &str| lines.iter().filter(|l| l.starts_with(prefix)).count();
    assert_eq!(begun("driver: stop, records "), 1, "records: {lines:#?}");
    assert_eq!(begun("stop: kernel "), 1, "records: {lines:#?}");
}

#[test]
#[ignore = "needs a built inspector"]
fn after_sigterm_new_connections_are_turned_away_and_the_request_in_flight_finishes() {
    let proxy = Proxy::start("listener_closed", Knobs::slow());
    let mut sock = proxy.start_slow(&post_form("/submit", &padded_form("ok", MAX_BODY)));
    let since = proxy.term();
    // The listener is closed right after this record is queued.
    proxy
        .records
        .wait_line("the stop record", |l| l == "stop: SIGTERM");
    assert_turned_away(proxy.port);

    // The inspection goes on, the request is forwarded and answered whole; the new connection did not reach the
    // upstream (the count at the end is the one of the request in flight).
    let answer = collect(&mut sock, since);
    assert_eq!(answer.status(), 200, "answer: {:?}", answer.text());
    assert_eq!(answer.message().body, UPSTREAM_BODY.as_bytes());
    proxy.finish_after_term(since, 1);
}

#[test]
#[ignore = "needs a built inspector"]
fn stop_wait_aborts_a_connection_that_outlives_it_and_the_proxy_still_exits() {
    // stop_wait is above stop_inspect plus the kernel's kill grace (1 s and 2 s).
    let knobs = Knobs {
        stop_inspect_ms: 1_000,
        stop_wait_ms: 4_000,
        ..Knobs::quick()
    };
    let stop_wait = Duration::from_millis(knobs.stop_wait_ms);
    let within = stop_wait + Duration::from_millis(KILL_GRACE_MS) + MARGIN;
    let proxy = Proxy::start("stop_wait_abort", knobs);
    let records = proxy.records.clone();
    proxy.upstream.behave(Behaviour::Drip);
    let mut sock = connect(proxy.port);
    sock.write_all(&get("/drip")).expect("send the request");
    // The answer streams when the signal comes, and its end is never near.
    let mut raw = read_until(&mut sock, b"\r\n\r\nx");
    let since = proxy.term();
    raw.extend_from_slice(&read_to_close(&mut sock));
    let closed_after = since.elapsed();
    let cut = Reply {
        raw,
        took: closed_after,
    };
    let answer = cut.message();
    assert_eq!(answer.status(), 200, "answer: {:?}", cut.text());
    assert!(
        answer.body.len() > 1 && answer.body.len() < DRIP_PROMISE,
        "the client got {} body bytes of {DRIP_PROMISE}",
        answer.body.len()
    );
    // The stop waited for the connection for stop_wait and then ended it.
    assert!(
        closed_after + 100 * MS >= stop_wait,
        "the connection ended {closed_after:?} after the signal; stop_wait is {stop_wait:?}"
    );
    assert!(
        closed_after < within,
        "the connection ended {closed_after:?} after the signal; the limit is {within:?}"
    );

    // The exit code of a stop by a signal whose kernel ended cleanly is 0, whether or not a connection had to be
    // aborted. `finish_within` fails with the status if it is another code.
    let (counts, took) = proxy.finish_within("SIGTERM", since, within, 1);
    assert_eq!(counts, StopCounts::NONE);
    assert!(
        took + 100 * MS >= stop_wait,
        "the proxy exited {took:?} after the signal; stop_wait is {stop_wait:?}"
    );
    let lines = records.lines();
    assert!(
        lines
            .iter()
            .any(|l| l == "stop: the remaining connections are aborted"),
        "no record of the abort: {lines:#?}"
    );
}

#[test]
#[ignore = "needs a built inspector"]
fn a_kernel_that_is_not_ready_when_ready_wait_ends_stops_the_proxy_with_exit_code_1_and_it_never_listens()
 {
    // The stand-in never says hello. The restart budget is large, so the kernel is starting again when ready_wait
    // passes: it has neither failed nor become ready.
    let knobs = Knobs {
        stand_in: true,
        hello_wait_ms: 1_000,
        ready_wait_ms: 1_500,
        restarts: 50,
        ..Knobs::quick()
    };
    let ready_wait = Duration::from_millis(knobs.ready_wait_ms);
    let mut proxy = Proxy::spawn("ready_wait", knobs);
    proxy
        .records
        .wait_line("the configuration to be accepted", |l| {
            l == "start: configuration accepted"
        });
    proxy.wait_stand_in();
    // Nothing listens while the kernel starts.
    assert_turned_away(proxy.port);

    let started = proxy.started;
    let (status, took) = proxy.wait_exit(started, ready_wait + MARGIN);
    let lines = proxy.records.lines();
    assert_eq!(
        status.code(),
        Some(1),
        "exit status {status}; records: {lines:#?}"
    );
    assert!(
        took >= ready_wait,
        "the proxy ended after {took:?}; ready_wait is {ready_wait:?}"
    );
    assert!(
        took < ready_wait + MARGIN,
        "the proxy ended after {took:?}; ready_wait is {ready_wait:?}"
    );
    // The cause is the wait, not a failure of the kernel, and the proxy never got as far as listening.
    assert!(
        lines
            .iter()
            .any(|l| l == "stop: the kernel was not ready in time"),
        "records: {lines:#?}"
    );
    assert!(
        !lines.iter().any(|l| l.contains("kernel failed")
            || l == "start: the kernel is ready"
            || l == "start: listening"),
        "records: {lines:#?}"
    );
    // The kernel ended the start that was running, and nothing is left of it.
    assert!(
        lines.iter().any(|l| l.starts_with(
            "stop: kernel Stopped, bye false, exit_confirmed true, dir_removed true, held_left 0, waiting_left 0"
        )),
        "the kernel did not stop cleanly: {lines:#?}"
    );
    assert_gone(&proxy.inspectors);
    assert_turned_away(proxy.port);
    proxy.clear_root(&["config.json", STAND_IN]);
    proxy.upstream.stop();
    assert_eq!(proxy.upstream.connections(), 0);
}
