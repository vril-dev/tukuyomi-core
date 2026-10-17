use std::io::Write;
use std::thread;
use std::time::Instant;

use crate::support::*;

#[test]
#[ignore = "needs a built inspector"]
fn the_head_deadline_gives_408_and_the_connection_permits_come_back() {
    let knobs = Knobs {
        max_conns: 2,
        head_read_ms: 1_500,
        ..Knobs::quick()
    };
    let proxy = Proxy::start("head_deadline", knobs);
    // Two connections that never finish their head hold both permits.
    let partial = b"GET /slow HTTP/1.1\r\nHost: example.test\r\n";
    let started = Instant::now();
    let mut a = connect(proxy.port);
    a.write_all(partial).expect("send half a head");
    let mut b = connect(proxy.port);
    b.write_all(partial).expect("send half a head");

    // A third request is not accepted before a permit is back, so it is answered only after the deadline.
    let third = exchange(proxy.port, &get("/third"));
    assert_eq!(third.status(), 200, "answer: {:?}", third.text());
    assert!(
        third.took >= SEC,
        "the third request was answered after {:?}; it should have waited for a permit",
        third.took
    );
    for sock in [&mut a, &mut b] {
        let late = collect(sock, started);
        assert_empty_answer(&late, 408);
        assert!(late.took >= SEC, "408 after {:?}", late.took);
    }
    proxy.records.conns("two head-deadline records", 2, |l| {
        l.contains(": rejected 408 head not received in time ")
    });
    assert_eq!(proxy.finish(1), StopCounts::NONE);
}

#[test]
#[ignore = "needs a built inspector"]
fn the_body_deadline_gives_408_and_the_byte_budget_comes_back() {
    let knobs = Knobs {
        max_buffered_bytes: MIN_BUFFERED,
        body_read_ms: 3_000,
        ..Knobs::quick()
    };
    let proxy = Proxy::start("body_deadline", knobs);
    // Two requests that declare the largest body and send a little of it hold all but 24 KiB of the budget.
    let stalled = || {
        let mut sock = connect(proxy.port);
        let head = format!(
            "POST /stall HTTP/1.1\r\nHost: example.test\r\nContent-Type: {URLENCODED}\r\nContent-Length: {MAX_BODY}\r\n\r\n"
        );
        sock.write_all(head.as_bytes()).expect("send the head");
        sock.write_all(&padded_form("ok", 100))
            .expect("send a little of the body");
        sock
    };
    let started = Instant::now();
    let mut a = stalled();
    let mut b = stalled();

    // A 30 KiB body that the rule blocks needs more than is left. It is refused for the budget (503) once the
    // two requests above hold theirs; before that it reaches the rule (403), so it is sent again.
    let small = post_form("/small", &padded_form("block", 30 * 1024));
    let refused = loop {
        let reply = exchange(proxy.port, &small);
        match reply.status() {
            503 => break reply,
            403 => {}
            other => panic!("status {other}: {:?}", reply.text()),
        }
        assert!(
            started.elapsed() < 2 * SEC,
            "the stalled requests did not take the budget"
        );
        thread::sleep(20 * MS);
    };
    assert_empty_answer(&refused, 503);
    proxy.records.conn("the budget record", |l| {
        l.contains(": failed 503 byte budget exhausted ")
    });
    for sock in [&mut a, &mut b] {
        let late = collect(sock, started);
        assert_empty_answer(&late, 408);
        assert!(late.took >= 2 * SEC, "408 after {:?}", late.took);
    }
    proxy.records.conns("two body-deadline records", 2, |l| {
        l.contains(": rejected 408 body not received in time ")
    });

    // The budget is back: the same request now reaches the rule, and a normal one passes.
    let again = exchange(proxy.port, &small);
    assert_empty_answer(&again, 403);
    let normal = exchange(proxy.port, &get("/after"));
    assert_eq!(normal.status(), 200, "answer: {:?}", normal.text());
    assert_eq!(proxy.finish(1), StopCounts::NONE);
}

#[test]
#[ignore = "needs a built inspector"]
fn the_upstream_header_deadline_gives_502_and_the_resources_come_back() {
    let knobs = Knobs {
        max_buffered_bytes: MIN_BUFFERED,
        upstream_header_ms: 1_500,
        ..Knobs::quick()
    };
    let proxy = Proxy::start("upstream_header_deadline", knobs);
    proxy.upstream.behave(Behaviour::Silent);
    // 600 KiB twice cannot be held at once with the minimum budget (each takes the body and the kernel's copy),
    // so the second request passes only if the first gave its bytes back.
    let big = post_form("/slow", &padded_form("ok", 600 * 1024));
    let first = exchange(proxy.port, &big);
    assert_empty_answer(&first, 502);
    assert!(first.took >= SEC, "502 after {:?}", first.took);
    proxy.records.conn("the 502 record", |l| {
        l.contains(": failed 502 upstream response head failed ")
    });
    proxy
        .upstream
        .seen
        .arrived
        .wait_for("the request at the upstream", 1);
    // The proxy dropped its connection to the upstream.
    proxy
        .upstream
        .seen
        .closed
        .wait_for("the proxy to close its upstream connection", 1);

    proxy.upstream.behave(Behaviour::Reply);
    let second = exchange(proxy.port, &big);
    assert_eq!(second.status(), 200, "answer: {:?}", second.text());
    assert_eq!(proxy.finish(2), StopCounts::NONE);
}

#[test]
#[ignore = "needs a built inspector"]
fn the_response_idle_deadline_cuts_a_stalled_answer_without_its_end() {
    let knobs = Knobs {
        response_idle_ms: 1_500,
        ..Knobs::quick()
    };
    let proxy = Proxy::start("response_idle_deadline", knobs);
    proxy.upstream.behave(Behaviour::Cut);
    let cut = exchange(proxy.port, &get("/cut"));
    let answer = cut.message();
    assert_eq!(answer.status(), 200, "answer: {:?}", cut.text());
    // Three of the ten promised bytes arrived, and the connection was closed after the idle time.
    assert_eq!(answer.values("content-length"), ["10"]);
    assert_eq!(answer.body, b"abc");
    assert!(cut.took >= SEC, "closed after {:?}", cut.took);
    proxy.records.conn("the cut-off record", |l| {
        l.contains(": forwarded 200 closed while the response was sent ")
    });
    proxy
        .upstream
        .seen
        .closed
        .wait_for("the proxy to close its upstream connection", 1);

    proxy.upstream.behave(Behaviour::Reply);
    let next = exchange(proxy.port, &get("/after"));
    assert_eq!(next.status(), 200, "answer: {:?}", next.text());
    assert_eq!(proxy.finish(2), StopCounts::NONE);
}
