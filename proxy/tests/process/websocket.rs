use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::support::*;

/// One group, `main`, and one route that holds for every request and lets a WebSocket through.
pub(crate) fn open_route(addresses: &[SocketAddr]) -> Value {
    json!({
        "resolve_timeout_ms": RESOLVE_TIMEOUT_MS,
        "upstreams": {"main": {"servers": [server(addresses[0])]}},
        "routes": [
            {"upstream": "main", "stream": {"idle_ms": 5_000, "total_ms": 20_000, "websocket": true}},
        ],
        "default_upstream": "",
    })
}

fn handshake(path: &str) -> Vec<u8> {
    format!(
        "GET {path} HTTP/1.1\r\nHost: example.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
    .into_bytes()
}

/// Reads from `sock` into `held` until `until` holds for what `held` has.
fn read_up_to(sock: &mut TcpStream, held: &mut Vec<u8>, until: impl Fn(&[u8]) -> bool) {
    let deadline = Instant::now() + 30 * SEC;
    let mut chunk = [0u8; 4096];
    while !until(held) {
        let left = deadline.saturating_duration_since(Instant::now());
        assert!(
            !left.is_zero(),
            "nothing came; got {:?}",
            String::from_utf8_lossy(held)
        );
        sock.set_read_timeout(Some(left))
            .expect("set the read timeout");
        match sock.read(&mut chunk) {
            Ok(0) => panic!("the proxy closed; got {:?}", String::from_utf8_lossy(held)),
            Ok(n) => held.extend_from_slice(&chunk[..n]),
            Err(e) => panic!("read from the proxy failed: {e}"),
        }
    }
}

#[test]
#[ignore = "needs a built inspector"]
fn a_websocket_goes_through_and_a_handshake_that_a_rule_blocks_does_not() {
    let knobs = Knobs {
        forward: open_route,
        ..Knobs::quick()
    };
    let proxy = Proxy::start("websocket", knobs);

    // The handshake is inspected like any request: the rule for the URI blocks it, and the upstream is not asked.
    let blocked = exchange(proxy.port, &handshake("/block-probe/ws"));
    assert_empty_answer(&blocked, 403);
    proxy
        .records
        .conn("the blocked record", |l| blocked_by(l, 9201));
    assert_eq!(proxy.upstream.connections(), 0);

    // Another handshake gets its 101, and then whatever either side sends reaches the other.
    let mut sock = connect(proxy.port);
    sock.write_all(&handshake("/chat"))
        .expect("send the handshake");
    let mut held = Vec::new();
    read_up_to(&mut sock, &mut held, |bytes| {
        find(bytes, b"\r\n\r\n").is_some()
    });
    let reply = Message::parse(&held);
    assert_eq!(
        reply.status(),
        101,
        "answer: {:?}",
        String::from_utf8_lossy(&held)
    );
    assert_eq!(reply.values("upgrade"), ["websocket"]);
    assert_eq!(reply.values("connection"), ["upgrade"]);
    assert_eq!(
        reply.values("sec-websocket-accept"),
        ["s3pPLMBiTxaQ9kYGzzhZRbK+xOo="]
    );
    held.clear();
    sock.write_all(b"hello, upstream").expect("send");
    read_up_to(&mut sock, &mut held, |bytes| {
        bytes.len() >= b"hello, upstream".len()
    });
    assert_eq!(held, b"hello, upstream");
    proxy.records.conn("the record of the 101", |l| {
        is_answer(l, "forwarded", 101, "forwarded") && no(l, "rule")
    });

    // The client ends its side; the upstream ends its own, and the proxy writes a line for the tunnel.
    sock.shutdown(std::net::Shutdown::Write)
        .expect("end the writing side");
    assert!(read_to_close(&mut sock).is_empty());
    proxy.records.conn("the record of the tunnel", |l| {
        l["type"] == "tunnel"
            && l["end"] == "closed"
            && l["client"] == "127.0.0.1"
            && l["upstream"] == "main"
            && l.get("server").is_some()
            && l["to_upstream"] == 15
            && l["from_upstream"] == 15
    });

    let requests = proxy.upstream.requests();
    assert_eq!(requests.len(), 1);
    let seen = Message::parse(&requests[0]);
    assert_eq!(seen.start, "GET /chat HTTP/1.1");
    assert_eq!(seen.values("connection"), ["upgrade"]);
    assert_eq!(seen.values("upgrade"), ["websocket"]);
    assert_eq!(
        seen.values("sec-websocket-key"),
        ["dGhlIHNhbXBsZSBub25jZQ=="]
    );
    proxy.finish(1);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_tunnel_is_not_ended_by_the_stop_and_is_cut_when_the_time_to_finish_ends() {
    // The connections get 4 s after the signal to finish.
    let knobs = Knobs {
        forward: open_route,
        stop_inspect_ms: 1_000,
        stop_wait_ms: 4_000,
        ..Knobs::quick()
    };
    let mut proxy = Proxy::start("websocket_stop", knobs);
    let mut sock = connect(proxy.port);
    sock.write_all(&handshake("/chat"))
        .expect("send the handshake");
    let mut held = Vec::new();
    read_up_to(&mut sock, &mut held, |bytes| {
        find(bytes, b"\r\n\r\n").is_some()
    });
    assert_eq!(Message::parse(&held).status(), 101);
    held.clear();

    // The signal does not end the tunnel: bytes still go both ways after it.
    let since = proxy.term();
    sock.write_all(b"after the signal").expect("send");
    read_up_to(&mut sock, &mut held, |bytes| bytes.len() >= 16);
    assert_eq!(held, b"after the signal");

    // The end of the time to finish aborts it, and the proxy stops then.
    assert!(read_to_close(&mut sock).is_empty());
    let (status, took) = proxy.wait_exit(since, 60 * SEC);
    let lines = proxy.records.lines();
    let records = proxy.records.all();
    assert_eq!(status.code(), Some(0), "records: {lines:#?}");
    assert!(
        took >= Duration::from_millis(3_900),
        "the proxy stopped after {took:?}"
    );
    assert!(
        records.iter().any(|r| {
            r["type"] == "tunnel"
                && r["end"] == "stop"
                && r["to_upstream"] == 16
                && r["from_upstream"] == 16
        }),
        "records: {lines:#?}"
    );
    assert!(
        lines.iter().any(|l| l.starts_with(
            "stop: kernel Stopped, bye true, exit_confirmed true, dir_removed true, held_left 0, waiting_left 0"
        )),
        "records: {lines:#?}"
    );
    assert_gone(&proxy.inspectors);
    proxy.clear_root(&["config.json", STORE]);
}
