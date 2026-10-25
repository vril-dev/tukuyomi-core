use std::io::{Read, Write};

use crate::support::*;

#[test]
#[ignore = "needs a built inspector"]
fn a_urlencoded_body_rule_blocks_a_chunked_body_and_a_clean_one_is_forwarded_with_a_length() {
    let proxy = Proxy::start("body_block_chunked", Knobs::quick());
    // The rule's argument is split over two chunks: the body is decoded before it is inspected.
    let blocked = exchange(
        proxy.port,
        &chunked_request("/submit", &chunked_body(&[b"pro", b"be=block"], b"")),
    );
    assert_empty_answer(&blocked, 403);
    proxy.records.conn("the blocked record", |l| {
        l.contains(": blocked 403 blocked by a rule rule 9202 ")
    });
    assert_eq!(proxy.upstream.connections(), 0);

    let passed = exchange(
        proxy.port,
        &chunked_request("/submit", &chunked_body(&[b"pro", b"be=ok"], b"")),
    );
    assert_eq!(passed.status(), 200, "answer: {:?}", passed.text());
    let requests = proxy.upstream.requests();
    assert_eq!(requests.len(), 1);
    // What was inspected is what was forwarded: the decoded body, with its length and without the coding.
    let seen = Message::parse(&requests[0]);
    assert!(
        !seen.names().contains(&"transfer-encoding"),
        "fields: {:?}",
        seen.fields
    );
    assert_eq!(seen.values("content-length"), ["8"]);
    assert_eq!(seen.body, b"probe=ok");
    proxy.finish(1);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_json_body_rule_blocks_a_body_with_a_content_length_and_a_clean_one_is_forwarded_byte_for_byte()
{
    let proxy = Proxy::start("json_length", Knobs::quick());
    let blocked = exchange(
        proxy.port,
        &post_typed("/api", JSON, BLOCKED_JSON.as_bytes()),
    );
    assert_empty_answer(&blocked, 403);
    proxy
        .records
        .conn("the blocked record", |l| l.contains(&blocked_by(9203)));
    assert_eq!(proxy.upstream.connections(), 0);

    let clean = CLEAN_JSON.as_bytes();
    let passed = exchange(proxy.port, &post_typed("/api", JSON, clean));
    assert_eq!(passed.status(), 200, "answer: {:?}", passed.text());
    assert_eq!(passed.message().body, UPSTREAM_BODY.as_bytes());
    assert_eq!(proxy.upstream.connections(), 1);
    assert_eq!(proxy.upstream.requests().len(), 1);
    assert_forwarded_json(&proxy, 0, "POST /api HTTP/1.1", JSON, clean);
    proxy.records.conn("the forwarded record", |l| {
        l.contains(": forwarded 200 forwarded ")
    });
    proxy.finish(1);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_gzip_urlencoded_body_is_inspected_decoded_and_a_clean_one_is_forwarded_decoded() {
    let proxy = Proxy::start("gzip_form", Knobs::quick());
    // The rule can only match the argument in the decoded body.
    let reply = exchange(
        proxy.port,
        &post_coded(
            "/submit",
            URLENCODED,
            "GZip",
            &gzip(&padded_form("block", 300)),
        ),
    );
    assert_empty_answer(&reply, 403);
    proxy
        .records
        .conn("the blocked record", |l| l.contains(&blocked_by(9202)));
    assert_eq!(proxy.upstream.connections(), 0);

    // A clean body whose decoded form is much longer than its coded form: the length that reaches the upstream
    // is the decoded one, and its bytes are the decoded ones.
    let plain = padded_form("ok", 4096);
    let coded = gzip(&plain);
    assert!(coded.len() * 4 < plain.len(), "the body compresses well");
    let passed = exchange(
        proxy.port,
        &post_coded("/submit", URLENCODED, "gzip", &coded),
    );
    assert_eq!(passed.status(), 200, "answer: {:?}", passed.text());
    assert_forwarded_decoded(&proxy, 0, "POST /submit HTTP/1.1", URLENCODED, &plain);

    // The same through the chunked coding: one length, no chunked framing, no coding.
    let chunked = exchange(
        proxy.port,
        &chunked_coded("/submit", URLENCODED, "gzip", &coded),
    );
    assert_eq!(chunked.status(), 200, "answer: {:?}", chunked.text());
    assert_forwarded_decoded(&proxy, 1, "POST /submit HTTP/1.1", URLENCODED, &plain);
    proxy.finish(2);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_gzip_body_that_decodes_to_more_than_the_limit_gives_413_and_no_upstream_connection() {
    let proxy = Proxy::start("gzip_413", Knobs::quick());
    // The coded body is far below the limit on the coded length: only the decoded length can be refused. The rule
    // would block it, so a 413 means nothing was inspected.
    let over = gzip(&padded_form("block", MAX_BODY + 1));
    assert!(over.len() < 64 * 1024);
    let reply = exchange(proxy.port, &post_coded("/big", URLENCODED, "gzip", &over));
    assert_empty_answer(&reply, 413);
    proxy.records.conn("the 413 record", |l| {
        l.contains(": rejected 413 decoded body over the limit ")
    });
    assert_eq!(proxy.upstream.connections(), 0);

    // A body that decodes to the limit exactly is taken, and the upstream gets all of it.
    let at_limit = padded_form("ok", MAX_BODY);
    let passed = exchange(
        proxy.port,
        &post_coded("/big", URLENCODED, "gzip", &gzip(&at_limit)),
    );
    assert_eq!(passed.status(), 200, "answer: {:?}", passed.text());
    assert_forwarded_decoded(&proxy, 0, "POST /big HTTP/1.1", URLENCODED, &at_limit);
    proxy.finish(1);
}

/// A JSON body of exactly `total` bytes: a member `probe` that is `probe`, then a long string, so that the first bytes
/// end in the middle of the string.
fn padded_json(probe: &str, total: usize) -> Vec<u8> {
    let mut body = format!("{{\"probe\": \"{probe}\", \"pad\": \"").into_bytes();
    body.resize(total - 2, b'a');
    body.extend_from_slice(b"\"}");
    body
}

#[test]
#[ignore = "needs a built inspector"]
fn an_attack_in_the_first_bytes_of_a_long_body_is_blocked_and_one_behind_them_is_not_inspected() {
    let proxy = Proxy::start("long_attack", Knobs::long_bodies());
    // The attack is in the 16 KiB that are inspected: 403, whatever the framing, and nothing reaches the upstream.
    let blocked = padded_form("block", 150_000);
    let reply = exchange(proxy.port, &post_form("/up", &blocked));
    assert_empty_answer(&reply, 403);
    let reply = exchange(
        proxy.port,
        &chunked_request(
            "/up",
            &chunked_body(&[&blocked[..50_000], &blocked[50_000..]], b""),
        ),
    );
    assert_empty_answer(&reply, 403);
    proxy
        .records
        .conns("the blocked records", 2, |l| l.contains(&blocked_by(9202)));
    assert_eq!(proxy.upstream.connections(), 0);

    // The same argument behind the 16 KiB is not looked at: the body goes through whole.
    let mut behind = padded_form("ok", 100_000);
    behind.extend_from_slice(b"&probe=block");
    let reply = exchange(proxy.port, &post_form("/up", &behind));
    assert_eq!(reply.status(), 200, "answer: {:?}", reply.text());
    let requests = proxy.upstream.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(Message::parse(&requests[0]).body, behind);
    proxy.finish(1);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_json_body_that_is_cut_is_forwarded_whole_and_byte_for_byte_and_is_not_blocked_for_failing_to_parse()
 {
    let proxy = Proxy::start("long_json", Knobs::long_bodies());
    // The first 16 KiB end inside a string, which is no JSON; the whole body is. It is cut, so it is not blocked.
    let long = padded_json("ok", 2 << 20);
    let reply = exchange(proxy.port, &post_typed("/api", JSON, &long));
    assert_eq!(reply.status(), 200, "answer: {:?}", reply.text());
    assert_forwarded_json(&proxy, 0, "POST /api HTTP/1.1", JSON, &long);
    let line = proxy.records.conn("the cut record", |l| {
        l.contains(": forwarded 200 forwarded ") && l.contains(" inspected 16384 cut")
    });
    assert!(
        line.ends_with(&format!(" body {} inspected 16384 cut", long.len())),
        "{line}"
    );

    // A body that is short enough to be inspected whole, and is broken, is blocked as it always was.
    let mut broken = padded_json("ok", 4096);
    broken.truncate(4000);
    let reply = exchange(proxy.port, &post_typed("/api", JSON, &broken));
    assert_empty_answer(&reply, 403);
    proxy
        .records
        .conn("the broken record", |l| l.contains(&blocked_by(4000001)));

    // An attack in the first bytes of a cut body is blocked.
    let attack = padded_json("block", 150_000);
    let reply = exchange(proxy.port, &post_typed("/api", JSON, &attack));
    assert_empty_answer(&reply, 403);
    proxy
        .records
        .conn("the blocked record", |l| l.contains(&blocked_by(9203)));
    proxy.finish(1);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_long_chunked_body_reaches_the_upstream_chunked_and_whole_and_one_over_the_limit_is_cut_off() {
    let knobs = Knobs {
        max_body: 4 << 20,
        ..Knobs::long_bodies()
    };
    let proxy = Proxy::start("long_chunked", knobs);
    let body = padded_form("fine", 3 << 20);
    let pieces: Vec<&[u8]> = body.chunks(100_000).collect();
    let reply = exchange(
        proxy.port,
        &chunked_request("/up", &chunked_body(&pieces, b"")),
    );
    assert_eq!(reply.status(), 200, "answer: {:?}", reply.text());
    let requests = proxy.upstream.requests();
    assert_eq!(requests.len(), 1);
    let seen = Message::parse(&requests[0]);
    assert_eq!(seen.values("transfer-encoding"), ["chunked"]);
    assert!(seen.values("content-length").is_empty());
    assert_eq!(unchunk(&seen.body), body);

    // A body over the limit is passed on up to it; then the request to the upstream is dropped, and so is the
    // connection of the client, which gets no answer.
    let over = padded_form("fine", (4 << 20) + 1);
    let pieces: Vec<&[u8]> = over.chunks(100_000).collect();
    let mut sock = connect(proxy.port);
    // The proxy closes the connection while the client is still sending, so the writes may fail.
    let _ = sock.write_all(&chunked_request("/up", &chunked_body(&pieces, b"")));
    let mut answer = Vec::new();
    let _ = sock.set_read_timeout(Some(10 * SEC));
    let _ = sock.read_to_end(&mut answer);
    assert!(
        answer.is_empty(),
        "answer: {:?}",
        String::from_utf8_lossy(&answer)
    );
    proxy.records.conn("the closed record", |l| {
        l.contains(": closed 0 body over the limit while it was sent on ")
    });
    assert_eq!(proxy.upstream.requests().len(), 1);
    proxy.finish(2);
}

/// The data of a body in the chunked coding.
fn unchunk(mut wire: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let end = find(wire, b"\r\n").expect("a chunk size");
        let size = usize::from_str_radix(std::str::from_utf8(&wire[..end]).unwrap(), 16).unwrap();
        wire = &wire[end + 2..];
        if size == 0 {
            return out;
        }
        out.extend_from_slice(&wire[..size]);
        wire = &wire[size + 2..];
    }
}
