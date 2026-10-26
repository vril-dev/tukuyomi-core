use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::{Duration, Instant};

use crate::support::*;

/// Knobs for a proxy that keeps a connection after a response.
fn kept() -> Knobs {
    Knobs {
        keepalive_timeout_ms: 60_000,
        ..Knobs::quick()
    }
}

/// Knobs for a proxy that keeps the connections to the upstream too, and an upstream that lets it.
fn reusing() -> Knobs {
    Knobs {
        upstream_keepalive: 32,
        upstream_keeps: true,
        ..kept()
    }
}

/// Reads one response with a `Content-Length` from a connection that stays open: its head and exactly its body.
fn read_response(sock: &mut TcpStream) -> Message {
    sock.set_read_timeout(Some(30 * SEC))
        .expect("set the read timeout");
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = find(&raw, b"\r\n\r\n") {
            let head = Message::parse(&raw[..end + 4]);
            let length: usize = head
                .values("content-length")
                .first()
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(|| panic!("no length in {:?}", head.fields));
            if raw.len() >= end + 4 + length {
                assert_eq!(raw.len(), end + 4 + length, "bytes after the response");
                return Message::parse(&raw);
            }
        }
        match sock.read(&mut chunk) {
            Ok(0) => panic!("the proxy closed after {:?}", String::from_utf8_lossy(&raw)),
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
            Err(e) => panic!("read failed after {:?}: {e}", String::from_utf8_lossy(&raw)),
        }
    }
}

/// Reads until the proxy ends the connection. A reset is a failure here: the answer must not be taken away.
fn read_until_end(sock: &mut TcpStream) -> Vec<u8> {
    sock.set_read_timeout(Some(30 * SEC))
        .expect("set the read timeout");
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match sock.read(&mut chunk) {
            Ok(0) => return raw,
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
            Err(e) => panic!("the connection failed after {} bytes: {e}", raw.len()),
        }
    }
}

#[test]
#[ignore = "needs a built inspector"]
fn requests_share_one_connection_to_the_upstream_and_do_not_ask_it_to_close() {
    let proxy = Proxy::start("upstream_reuse", reusing());

    // Three requests on one client connection, and one more on another client connection.
    let mut sock = connect(proxy.port);
    for path in ["/one", "/two", "/three"] {
        sock.write_all(&get(path)).expect("send a request");
        let answer = read_response(&mut sock);
        assert_eq!(answer.status(), 200);
        assert_eq!(answer.body, UPSTREAM_BODY.as_bytes());
    }
    drop(sock);
    let mut sock = connect(proxy.port);
    sock.write_all(&get("/four")).expect("send a request");
    assert_eq!(read_response(&mut sock).status(), 200);
    drop(sock);

    assert_eq!(proxy.upstream.requests().len(), 4);
    assert_eq!(proxy.upstream.connections(), 1);
    for request in proxy.upstream.requests() {
        assert!(Message::parse(&request).values("connection").is_empty());
    }
    proxy.records.conns("four forwarded records", 4, |l| {
        is_answer(l, "forwarded", 200, "forwarded") && no(l, "rule")
    });
    proxy.finish(1);
}

#[test]
#[ignore = "needs a built inspector"]
fn one_connection_carries_several_requests_in_order_and_a_refusal_does_not_lose_its_answer() {
    let proxy = Proxy::start("keep_alive", kept());

    // A GET, a POST, a request that a rule blocks, and a GET, one after the other on one connection.
    let mut sock = connect(proxy.port);
    let mut statuses = Vec::new();
    for request in [
        get("/one"),
        post_form("/two", b"ok=1"),
        get("/block-probe/x"),
        get("/three"),
    ] {
        sock.write_all(&request).expect("send a request");
        let answer = read_response(&mut sock);
        // None of the answers ends the connection.
        assert!(
            answer.values("connection").is_empty(),
            "fields: {:?}",
            answer.fields
        );
        statuses.push(answer.status());
    }
    assert_eq!(statuses, [200, 200, 403, 200]);
    let seen: Vec<String> = proxy
        .upstream
        .requests()
        .iter()
        .map(|r| Message::parse(r).start)
        .collect();
    assert_eq!(
        seen,
        [
            "GET /one HTTP/1.1",
            "POST /two HTTP/1.1",
            "GET /three HTTP/1.1"
        ]
    );
    assert_eq!(Message::parse(&proxy.upstream.requests()[1]).body, b"ok=1");
    proxy.records.conns("three forwarded records", 3, |l| {
        is_answer(l, "forwarded", 200, "forwarded") && no(l, "rule")
    });
    proxy
        .records
        .conn("the blocked record", |l| blocked_by(l, 9201));
    drop(sock);

    // A bad second head ends the connection after the answer to the first request, whole, and has no answer.
    let mut sock = connect(proxy.port);
    let mut both = get("/four");
    both.extend_from_slice(
        b"POST /bad HTTP/1.1\r\nHost: example.test\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab",
    );
    sock.write_all(&both).expect("send both requests");
    let raw = read_until_end(&mut sock);
    let answer = Message::parse(&raw);
    assert_eq!(
        answer.status(),
        200,
        "answer: {:?}",
        String::from_utf8_lossy(&raw)
    );
    assert_eq!(answer.body, UPSTREAM_BODY.as_bytes());
    proxy.records.conn("the refused head", |l| {
        shows(l, "closed", 0, "malformed request head")
    });
    drop(sock);

    // An HTTP/1.0 request is inspected as such, answered as such, and ends the connection.
    let old = exchange(
        proxy.port,
        b"GET /old HTTP/1.0\r\nHost: example.test\r\nConnection: keep-alive\r\n\r\n",
    );
    assert!(
        old.raw.starts_with(b"HTTP/1.0 200 "),
        "answer: {:?}",
        old.text()
    );
    assert_eq!(old.message().values("connection"), ["close"]);
    assert_eq!(old.message().body, UPSTREAM_BODY.as_bytes());
    let blocked = exchange(
        proxy.port,
        b"GET /block-probe/old HTTP/1.0\r\nHost: example.test\r\n\r\n",
    );
    assert!(
        blocked.raw.starts_with(b"HTTP/1.0 403 "),
        "answer: {:?}",
        blocked.text()
    );

    // A refusal before the body was read: the client is still sending when it is answered, and it reads the whole
    // answer and then the end of the connection, not a reset.
    let mut sock = connect(proxy.port);
    let head = format!(
        "POST /big HTTP/1.1\r\nHost: example.test\r\nContent-Type: {URLENCODED}\r\nContent-Length: {}\r\n\r\n",
        MAX_BODY + 1
    );
    sock.write_all(head.as_bytes()).expect("send the head");
    sock.write_all(&vec![b'a'; 60_000]).expect("send some body");
    let answer = read_response(&mut sock);
    assert_eq!(answer.status(), 413);
    assert_eq!(answer.values("connection"), ["close"]);
    sock.write_all(&vec![b'b'; 100_000])
        .expect("the proxy still reads what the client sends");
    sock.shutdown(Shutdown::Write).expect("end the sending");
    assert!(read_until_end(&mut sock).is_empty());
    proxy.records.conn("the 413 record", |l| {
        is_answer(l, "rejected", 413, "body over the limit")
    });
    drop(sock);

    proxy.finish(5);
}

#[test]
#[ignore = "needs a built inspector"]
fn an_idle_connection_ends_at_once_when_the_proxy_is_told_to_stop() {
    let proxy = Proxy::start("keep_alive_stop", kept());
    let mut sock = connect(proxy.port);
    sock.write_all(&get("/idle")).expect("send the request");
    assert_eq!(read_response(&mut sock).status(), 200);
    // The connection waits for its next request, and its wait is a minute.
    let since = proxy.term();
    assert!(read_until_end(&mut sock).is_empty());
    let ended = since.elapsed();
    assert!(
        ended < Duration::from_secs(10),
        "the idle connection ended after {ended:?}"
    );
    let counts = proxy.finish_after_term(since, 1);
    assert_eq!(counts, [0, 0, 0], "the kernel held something at the stop");
}

#[test]
#[ignore = "needs a built inspector"]
fn empty_lines_between_requests_are_ignored_up_to_two() {
    let proxy = Proxy::start("keep_alive_empty_lines", kept());
    let mut sock = connect(proxy.port);
    // A client that adds a line end after a body: the request behind it is still served.
    let mut input = post_form("/one", b"ok=1");
    input.extend_from_slice(b"\r\n\r\n");
    input.extend_from_slice(&get("/two"));
    sock.write_all(&input).expect("send the requests");
    assert_eq!(read_response(&mut sock).status(), 200);
    assert_eq!(read_response(&mut sock).status(), 200);
    // Three empty lines in front of a head close the connection, and the head is not answered.
    sock.write_all(b"\r\n\r\n\r\n").expect("send empty lines");
    sock.write_all(&get("/three")).expect("send a request");
    assert!(read_until_end(&mut sock).is_empty());
    drop(sock);
    let seen: Vec<String> = proxy
        .upstream
        .requests()
        .iter()
        .map(|r| Message::parse(r).start)
        .collect();
    assert_eq!(seen, ["POST /one HTTP/1.1", "GET /two HTTP/1.1"]);
    proxy.finish(2);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_connection_that_waits_for_a_request_is_closed_when_a_new_one_finds_every_permit_in_use() {
    let knobs = Knobs {
        max_conns: 2,
        ..kept()
    };
    let proxy = Proxy::start("keep_alive_permits", knobs);
    // Two connections have had their answer and wait for the next request, for a minute.
    let mut idle: Vec<TcpStream> = ["/idle-a", "/idle-b"]
        .iter()
        .map(|path| {
            let mut sock = connect(proxy.port);
            sock.write_all(&get(path)).expect("send a request");
            assert_eq!(read_response(&mut sock).status(), 200);
            sock
        })
        .collect();
    // A third connection finds no permit: the waiting ones are closed and it is served, long before the minute.
    let started = Instant::now();
    let third = exchange(
        proxy.port,
        b"GET /third HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(third.status(), 200, "answer: {:?}", third.text());
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the third connection was served after {:?}",
        started.elapsed()
    );
    for sock in &mut idle {
        assert!(read_until_end(sock).is_empty());
    }
    proxy.finish(3);
}
