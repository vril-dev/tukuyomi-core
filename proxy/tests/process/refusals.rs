use std::io::Write;
use std::time::Instant;

use crate::support::*;

#[test]
#[ignore = "needs a built inspector"]
fn transfer_encoding_with_content_length_gives_400_and_no_upstream_connection() {
    let proxy = Proxy::start("te_and_cl", Knobs::quick());
    // Both orders: the second is the one that a parser which drops the length after the coding would hide.
    for fields in [
        "Transfer-Encoding: chunked\r\nContent-Length: 11\r\n",
        "Content-Length: 11\r\nTransfer-Encoding: chunked\r\n",
    ] {
        let request = format!(
            "POST /x HTTP/1.1\r\nHost: example.test\r\nContent-Type: {URLENCODED}\r\n{fields}\r\nb\r\nprobe=block\r\n0\r\n\r\n"
        );
        let reply = exchange(proxy.port, request.as_bytes());
        assert_empty_answer(&reply, 400);
    }
    proxy.records.conns("two malformed-head records", 2, |l| {
        l.contains(": rejected 400 malformed request head ")
    });
    assert_eq!(proxy.upstream.connections(), 0);
    assert_eq!(proxy.finish(0), StopCounts::NONE);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_content_length_over_the_limit_gives_413_and_no_100_continue() {
    let proxy = Proxy::start("too_large", Knobs::quick());

    // A control: a request within the limit that asks for it gets its 100 Continue, so the missing one below means
    // something. The upstream does not see the Expect field.
    let head = format!(
        "POST /ok HTTP/1.1\r\nHost: example.test\r\nContent-Type: {URLENCODED}\r\nContent-Length: 8\r\nExpect: 100-continue\r\n\r\n"
    );
    let mut sock = connect(proxy.port);
    let start = Instant::now();
    sock.write_all(head.as_bytes()).expect("send the head");
    let interim = read_until(&mut sock, b"\r\n\r\n");
    assert_eq!(interim, b"HTTP/1.1 100 Continue\r\n\r\n");
    sock.write_all(b"probe=ok").expect("send the body");
    let allowed = collect(&mut sock, start);
    assert_eq!(allowed.status(), 200, "answer: {:?}", allowed.text());
    let requests = proxy.upstream.requests();
    let seen = Message::parse(&requests[0]);
    assert!(
        !seen.names().contains(&"expect"),
        "fields: {:?}",
        seen.fields
    );
    assert_eq!(seen.body, b"probe=ok");

    // Over the limit by one byte: the answer is 413 at once, and no 100 Continue is sent for a body that
    // cannot be taken.
    let head = format!(
        "POST /big HTTP/1.1\r\nHost: example.test\r\nContent-Type: {URLENCODED}\r\nContent-Length: {}\r\nExpect: 100-continue\r\n\r\n",
        MAX_BODY + 1
    );
    let refused = exchange(proxy.port, head.as_bytes());
    assert!(
        !refused.text().contains("100 Continue"),
        "answer: {:?}",
        refused.text()
    );
    assert_empty_answer(&refused, 413);
    proxy.records.conn("the 413 record", |l| {
        l.contains(": rejected 413 body over the limit ")
    });
    assert_eq!(proxy.upstream.connections(), 1);
    assert_eq!(proxy.finish(1), StopCounts::NONE);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_broken_chunked_body_and_a_non_empty_trailer_give_400() {
    let proxy = Proxy::start("chunked_400", Knobs::quick());
    let cases: [(&[u8], &str); 3] = [
        (b"zz\r\nabc\r\n0\r\n\r\n", "malformed body"),
        (b"3\r\nabcXX0\r\n\r\n", "malformed body"),
        (
            &chunked_body(&[b"abc"], b"X-Late: v\r\n"),
            "request trailers not supported",
        ),
    ];
    for (body, reason) in cases {
        let reply = exchange(proxy.port, &chunked_request("/submit", body));
        assert_empty_answer(&reply, 400);
        proxy
            .records
            .conn(reason, |l| l.contains(&format!(": rejected 400 {reason} ")));
    }
    assert_eq!(proxy.upstream.connections(), 0);
    assert_eq!(proxy.finish(0), StopCounts::NONE);
}

#[test]
#[ignore = "needs a built inspector"]
fn bodies_of_other_types_and_encoded_bodies_give_415() {
    let proxy = Proxy::start("media_415", Knobs::quick());
    // Bodies with a length whose type is not inspected. Each is valid for its type: the type alone decides, and
    // the head is refused before any body is read.
    let typed = |content_type: &str, body: &[u8]| post_typed("/t", content_type, body);
    // A body with a coding that is not decoded, under either inspected type. The body is a real gzip member, so
    // that the coding alone decides: only the exact value `gzip` is taken, whatever follows or precedes it.
    let member = gzip(b"probe=ok");
    let coded = |content_type: &str, coding: &str| post_coded("/e", content_type, coding, &member);
    // JSON next to another type is not one type.
    let two_types = {
        let body = b"{\"probe\":\"ok\"}";
        let mut request = format!(
            "POST /two HTTP/1.1\r\nHost: example.test\r\nContent-Type: {JSON}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        request.extend_from_slice(body);
        request
    };
    // A chunked body is refused only once it has been read and is known to be there.
    let chunked_text = chunked_typed("/c", "text/plain", &chunked_body(&[b"hello"], b""));
    let mut requests = vec![
        typed("application/xml", b"<probe>ok</probe>"),
        typed("text/plain", b"probe=ok"),
        typed("text/x+json", b"{\"probe\":\"ok\"}"),
        two_types,
        chunked_text,
    ];
    // The last value holds a second `Content-Encoding` line: a list in one line and a repeated line are refused
    // alike.
    for coding in [
        "x-gzip",
        "deflate",
        "br",
        "gzip, gzip",
        "gzip\r\nContent-Encoding: gzip",
    ] {
        for content_type in [URLENCODED, JSON] {
            requests.push(coded(content_type, coding));
        }
    }
    let count = requests.len();
    for request in requests {
        let reply = exchange(proxy.port, &request);
        assert_empty_answer(&reply, 415);
    }
    proxy.records.conns("the 415 records", count, |l| {
        l.contains(": rejected 415 body type not supported ")
    });
    assert_eq!(proxy.upstream.connections(), 0);

    // Not a state of the proxy: a normal request still passes.
    let normal = exchange(proxy.port, &get("/after"));
    assert_eq!(normal.status(), 200, "answer: {:?}", normal.text());
    assert_eq!(proxy.finish(1), StopCounts::NONE);
}
