use std::io::Write;
use std::time::{Duration, Instant};

use crate::support::*;

// ---------------------------------------------------------------------------------------------------------
// Forwarding, a rule block and a stopped upstream
// ---------------------------------------------------------------------------------------------------------

#[test]
#[ignore = "needs a built inspector"]
fn an_allowed_get_is_forwarded_without_hop_by_hop_fields_and_with_forwarding_fields() {
    let proxy = Proxy::start("forward_get", Knobs::quick());
    let request = concat!(
        "GET /ok?q=1 HTTP/1.1\r\n",
        "Host: example.test\r\n",
        "X-Keep: kept\r\n",
        "X-Forwarded-For: 203.0.113.7\r\n",
        "X-Forwarded-Host: spoofed.test\r\n",
        "X-Forwarded-Proto: https\r\n",
        "Connection: keep-alive, X-Hop\r\n",
        "X-Hop: 1\r\n",
        "Keep-Alive: timeout=5\r\n",
        "Proxy-Connection: keep-alive\r\n",
        "Proxy-Authorization: Basic eDp5\r\n",
        "TE: trailers\r\n",
        "Trailer: X-Late\r\n",
        "Upgrade: h2c\r\n",
        "\r\n"
    );
    let reply = exchange(proxy.port, request.as_bytes());
    let answer = reply.message();
    assert_eq!(answer.status(), 200, "answer: {:?}", reply.text());
    assert_eq!(answer.body, UPSTREAM_BODY.as_bytes());
    // The upstream's own hop-by-hop fields, and the field it listed in `Connection`, do not reach the client.
    assert_eq!(answer.values("x-up"), ["visible"]);
    assert!(
        !answer.names().contains(&"keep-alive") && !answer.names().contains(&"x-up-hop"),
        "answer fields: {:?}",
        answer.names()
    );
    assert_eq!(answer.values("connection"), ["close"]);

    proxy
        .upstream
        .seen
        .arrived
        .wait_for("the upstream's request", 1);
    let requests = proxy.upstream.requests();
    assert_eq!(requests.len(), 1);
    let seen = Message::parse(&requests[0]);
    assert_eq!(seen.start, "GET /ok?q=1 HTTP/1.1");
    for name in [
        "keep-alive",
        "proxy-connection",
        "proxy-authorization",
        "proxy-authenticate",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "expect",
        "x-hop",
    ] {
        assert!(
            !seen.names().contains(&name),
            "the upstream saw {name}: {:?}",
            seen.fields
        );
    }
    // The proxy ends the upstream connection itself, and says so once.
    assert_eq!(seen.values("connection"), ["close"]);
    assert_eq!(seen.values("host"), ["example.test"]);
    assert_eq!(seen.values("x-keep"), ["kept"]);
    assert_eq!(seen.values("x-forwarded-for"), ["203.0.113.7, 127.0.0.1"]);
    assert_eq!(seen.values("x-forwarded-host"), ["example.test"]);
    assert_eq!(seen.values("x-forwarded-proto"), ["http"]);
    assert!(seen.body.is_empty());

    proxy.records.conn("the forwarded record", |l| {
        l.contains(": forwarded 200 forwarded rule - ")
    });
    assert_eq!(proxy.finish(1), StopCounts::NONE);
}

#[test]
#[ignore = "needs a built inspector"]
fn the_uri_rule_blocks_with_its_status_and_the_upstream_is_not_contacted() {
    let proxy = Proxy::start("uri_block", Knobs::quick());
    let blocked = exchange(proxy.port, &get("/block-probe/x"));
    assert_empty_answer(&blocked, 403);
    proxy.records.conn("the blocked record", |l| {
        l.contains(": blocked 403 blocked by a rule rule 9201 ")
    });
    assert_eq!(proxy.upstream.connections(), 0);

    // A request the rule does not match passes on the same proxy.
    let passed = exchange(proxy.port, &get("/other"));
    assert_eq!(passed.status(), 200);
    assert_eq!(passed.message().body, UPSTREAM_BODY.as_bytes());
    assert_eq!(proxy.finish(1), StopCounts::NONE);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_stopped_upstream_gives_502() {
    let mut proxy = Proxy::start("upstream_stopped", Knobs::quick());
    let first = exchange(proxy.port, &get("/up"));
    assert_eq!(first.status(), 200);

    // The listener is closed: the port refuses connections now.
    proxy.upstream.stop();
    let second = exchange(proxy.port, &get("/down"));
    assert_empty_answer(&second, 502);
    proxy.records.conn("the 502 record", |l| {
        l.contains(": failed 502 upstream connection failed ")
    });
    assert_eq!(proxy.finish(1), StopCounts::NONE);
}

// ---------------------------------------------------------------------------------------------------------
// What the upstream's answer becomes
// ---------------------------------------------------------------------------------------------------------

#[test]
#[ignore = "needs a built inspector"]
fn a_head_answer_keeps_its_content_length_and_has_no_body() {
    let proxy = Proxy::start("head_answer", Knobs::quick());
    // A HEAD answer promises a body that it does not carry; the length is the one the upstream sent.
    proxy.upstream.behave(Behaviour::Raw(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 10\r\n\r\n".to_vec(),
    ));
    let reply = exchange(
        proxy.port,
        b"HEAD /head HTTP/1.1\r\nHost: example.test\r\n\r\n",
    );
    let answer = reply.message();
    assert_eq!(answer.status(), 200, "answer: {:?}", reply.text());
    assert_eq!(
        answer.values("content-length"),
        ["10"],
        "answer: {:?}",
        reply.text()
    );
    assert_eq!(answer.values("connection"), ["close"]);
    assert!(answer.body.is_empty(), "answer: {:?}", reply.text());

    proxy
        .upstream
        .seen
        .arrived
        .wait_for("the upstream's request", 1);
    let requests = proxy.upstream.requests();
    assert_eq!(Message::parse(&requests[0]).start, "HEAD /head HTTP/1.1");
    proxy.records.conn("the forwarded record", |l| {
        l.contains(": forwarded 200 forwarded ")
    });
    assert_eq!(proxy.finish(1), StopCounts::NONE);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_304_answer_to_a_get_has_no_content_length_and_no_body() {
    let proxy = Proxy::start("answer_304", Knobs::quick());
    // The upstream promises a length on its 304, as it may. The server side of the proxy does not write a length
    // for an answer to a GET that has no body, so the client gets none (unlike a HEAD answer, which keeps it).
    proxy.upstream.behave(Behaviour::Raw(
        b"HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\nContent-Length: 10\r\n\r\n".to_vec(),
    ));
    let reply = exchange(proxy.port, &get("/not-modified"));
    let answer = reply.message();
    assert_eq!(answer.status(), 304, "answer: {:?}", reply.text());
    assert_eq!(answer.values("etag"), ["\"v1\""]);
    assert_eq!(answer.values("connection"), ["close"]);
    assert!(answer.body.is_empty(), "answer: {:?}", reply.text());
    assert!(
        answer.values("content-length").is_empty(),
        "answer: {:?}",
        reply.text()
    );
    assert!(
        !answer.names().contains(&"transfer-encoding"),
        "answer: {:?}",
        reply.text()
    );

    proxy
        .upstream
        .seen
        .arrived
        .wait_for("the upstream's request", 1);
    let requests = proxy.upstream.requests();
    assert_eq!(
        Message::parse(&requests[0]).start,
        "GET /not-modified HTTP/1.1"
    );
    proxy.records.conn("the forwarded record", |l| {
        l.contains(": forwarded 304 forwarded ")
    });
    assert_eq!(proxy.finish(1), StopCounts::NONE);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_200_answer_gets_the_length_of_the_body_that_is_sent() {
    let proxy = Proxy::start("answer_200_length", Knobs::quick());
    // The proxy drops the length of the upstream, and the client gets the length of the body that is sent. The
    // upstream writes its length with leading zeros, which hyper would not write.
    let length = format!("00{}", UPSTREAM_BODY.len());
    proxy.upstream.behave(Behaviour::Raw(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {length}\r\n\r\n{UPSTREAM_BODY}"
        )
        .into_bytes(),
    ));
    let reply = exchange(proxy.port, &get("/full"));
    let answer = reply.message();
    assert_eq!(answer.status(), 200, "answer: {:?}", reply.text());
    assert_eq!(
        answer.values("content-length"),
        [UPSTREAM_BODY.len().to_string()],
        "answer: {:?}",
        reply.text()
    );
    assert_eq!(answer.body, UPSTREAM_BODY.as_bytes());
    proxy.records.conn("the forwarded record", |l| {
        l.contains(": forwarded 200 forwarded ")
    });
    assert_eq!(proxy.finish(1), StopCounts::NONE);
}

#[test]
#[ignore = "needs a built inspector"]
fn invalid_upstream_answers_give_502_and_nothing_of_them_reaches_the_client() {
    let proxy = Proxy::start("upstream_invalid", Knobs::quick());
    // Every answer has the word `leak` in a place that the client must not see, and each is refused for the
    // reason that the record names. The last one is a head of interim answers that is longer than the proxy reads.
    let mut flood = b"HTTP/1.1 100 Continue\r\n\r\n".repeat(2 * UPSTREAM_HEAD_WIRE / 25);
    flood.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nleak");
    let invalid = "upstream response invalid";
    let cases: [(&str, Vec<u8>, &str); 4] = [
        (
            "status 600",
            b"HTTP/1.1 600 Leak\r\nContent-Length: 4\r\n\r\nleak".to_vec(),
            invalid,
        ),
        (
            "transfer-encoding with content-length",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n4\r\nleak\r\n0\r\n\r\n"
                .to_vec(),
            invalid,
        ),
        (
            "a connection field that names content-length",
            b"HTTP/1.1 200 OK\r\nConnection: close, Content-Length\r\nContent-Length: 4\r\n\r\nleak"
                .to_vec(),
            invalid,
        ),
        (
            "a head over the cap through 100 Continue lines",
            flood,
            "upstream response head failed",
        ),
    ];
    let mut reasons: Vec<&str> = Vec::new();
    for (n, (what, answer, reason)) in cases.into_iter().enumerate() {
        proxy.upstream.behave(Behaviour::Raw(answer));
        let reply = exchange(proxy.port, &get("/invalid"));
        assert_empty_answer(&reply, 502);
        let text = reply.text().to_ascii_lowercase();
        for word in ["leak", "chunked", "continue"] {
            assert!(!text.contains(word), "{what}: answer: {text:?}");
        }
        reasons.push(reason);
        let wanted = format!(": failed 502 {reason} ");
        let same = reasons.iter().filter(|r| **r == reason).count();
        proxy.records.conns(what, same, |l| l.contains(&wanted));
        // The proxy dropped its connection to the upstream.
        proxy.upstream.seen.closed.wait_for(what, n + 1);
    }

    // Not a state of the proxy: a normal answer passes afterwards.
    proxy.upstream.behave(Behaviour::Reply);
    let after = exchange(proxy.port, &get("/after"));
    assert_eq!(after.status(), 200, "answer: {:?}", after.text());
    assert_eq!(proxy.finish(5), StopCounts::NONE);
}

// ---------------------------------------------------------------------------------------------------------
// A response cut by the connection time
// ---------------------------------------------------------------------------------------------------------

#[test]
#[ignore = "needs a built inspector"]
fn conn_total_cuts_a_response_that_streams_slowly_without_end() {
    let knobs = Knobs::short();
    let conn_total = Duration::from_millis(knobs.conn_total_ms);
    let proxy = Proxy::start("conn_total", knobs);
    proxy.upstream.behave(Behaviour::Drip);
    let start = Instant::now();
    let mut sock = connect(proxy.port);
    sock.write_all(&get("/drip")).expect("send the request");
    // The head and the first body byte: the answer streams. The upstream sends a byte every 200 ms and the idle
    // time is longer than that, so only the connection time can end it.
    let mut raw = read_until(&mut sock, b"\r\n\r\nx");
    raw.extend_from_slice(&read_to_close(&mut sock));
    let cut = Reply {
        raw,
        took: start.elapsed(),
    };
    let answer = cut.message();
    assert_eq!(answer.status(), 200, "answer: {:?}", cut.text());
    assert_eq!(answer.values("content-length"), [DRIP_PROMISE.to_string()]);
    assert!(
        answer.body.len() > 1 && answer.body.len() < DRIP_PROMISE,
        "the client got {} body bytes of {DRIP_PROMISE}",
        answer.body.len()
    );
    assert!(answer.body.iter().all(|&b| b == b'x'));
    assert!(
        cut.took + 50 * MS >= conn_total,
        "cut off after {:?}; conn_total is {conn_total:?}",
        cut.took
    );
    assert!(
        cut.took < conn_total + MARGIN,
        "cut off after {:?}; conn_total is {conn_total:?}",
        cut.took
    );
    proxy.records.conn("the cut-off record", |l| {
        l.contains(": forwarded 200 closed while the response was sent ")
    });
    // The proxy closed its upstream connection with it.
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
