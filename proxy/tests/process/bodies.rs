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
