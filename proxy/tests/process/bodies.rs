use crate::support::*;

// ---------------------------------------------------------------------------------------------------------
// Bodies
// ---------------------------------------------------------------------------------------------------------

#[test]
#[ignore = "needs a built inspector"]
fn a_urlencoded_body_rule_blocks_a_body_with_a_content_length() {
    let proxy = Proxy::start("body_block_length", Knobs::quick());
    let blocked = exchange(proxy.port, &post_form("/submit", b"probe=block"));
    assert_empty_answer(&blocked, 403);
    proxy.records.conn("the blocked record", |l| {
        l.contains(": blocked 403 blocked by a rule rule 9202 ")
    });
    assert_eq!(proxy.upstream.connections(), 0);

    let passed = exchange(proxy.port, &post_form("/submit", b"probe=ok"));
    assert_eq!(passed.status(), 200, "answer: {:?}", passed.text());
    let requests = proxy.upstream.requests();
    assert_eq!(requests.len(), 1);
    let seen = Message::parse(&requests[0]);
    assert_eq!(seen.start, "POST /submit HTTP/1.1");
    assert_eq!(seen.values("content-length"), ["8"]);
    assert_eq!(seen.body, b"probe=ok");
    assert_eq!(proxy.finish(1), StopCounts::NONE);
}

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
    assert_eq!(proxy.finish(1), StopCounts::NONE);
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
    assert_eq!(proxy.finish(1), StopCounts::NONE);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_json_body_rule_blocks_a_chunked_body_and_a_clean_one_is_forwarded_with_a_length() {
    let proxy = Proxy::start("json_chunked", Knobs::quick());
    // The value that the rule matches is split over two chunks: the body is decoded before it is inspected.
    let blocked = exchange(
        proxy.port,
        &chunked_typed(
            "/api",
            JSON,
            &chunked_body(&[b"{\"probe\":\"bl", b"ock\"}"], b""),
        ),
    );
    assert_empty_answer(&blocked, 403);
    proxy
        .records
        .conn("the blocked record", |l| l.contains(&blocked_by(9203)));
    assert_eq!(proxy.upstream.connections(), 0);

    // The clean body is cut inside the value `ok` and inside the three bytes of one character.
    let clean = CLEAN_JSON.as_bytes();
    let in_value = find(clean, b"\"ok\"").expect("the value is in the body") + 2;
    let in_character =
        find(clean, "\u{4e2d}".as_bytes()).expect("the character is in the body") + 1;
    assert!(in_value < in_character);
    let chunks = [
        &clean[..in_value],
        &clean[in_value..in_character],
        &clean[in_character..],
    ];
    let passed = exchange(
        proxy.port,
        &chunked_typed("/api", JSON, &chunked_body(&chunks, b"")),
    );
    assert_eq!(passed.status(), 200, "answer: {:?}", passed.text());
    assert_eq!(passed.message().body, UPSTREAM_BODY.as_bytes());
    assert_eq!(proxy.upstream.connections(), 1);
    // What was inspected is what was forwarded: the decoded body, with its length and without the coding.
    assert_eq!(proxy.upstream.requests().len(), 1);
    assert_forwarded_json(&proxy, 0, "POST /api HTTP/1.1", JSON, clean);
    assert_eq!(proxy.finish(1), StopCounts::NONE);
}

#[test]
#[ignore = "needs a built inspector"]
fn invalid_json_and_a_body_with_a_byte_order_mark_are_blocked_without_an_upstream_connection() {
    let proxy = Proxy::start("json_invalid", Knobs::quick());
    // No body here says `block`, so the only rule that can answer is the one for a body that cannot be parsed.
    let with_mark = [b"\xEF\xBB\xBF".as_slice(), b"{\"probe\":\"ok\"}"].concat();
    let cases: [(&str, Vec<u8>); 4] = [
        ("a body that ends inside a member", b"{\"probe\":".to_vec()),
        ("a trailing comma", b"{\"probe\":\"ok\",}".to_vec()),
        ("text after the value", b"{\"probe\":\"ok\"}x".to_vec()),
        ("a UTF-8 byte order mark", with_mark),
    ];
    for (n, (what, body)) in cases.into_iter().enumerate() {
        let reply = exchange(proxy.port, &post_typed("/api", JSON, &body));
        assert_empty_answer(&reply, 403);
        // Every earlier case wrote the same line, so the count grows with each case.
        proxy
            .records
            .conns(what, n + 1, |l| l.contains(&blocked_by(4_000_001)));
        assert_eq!(proxy.upstream.connections(), 0, "{what}");
    }
    let lines = proxy.records.lines();
    assert!(
        !lines.iter().any(|l| l.contains("rule 9203")),
        "records: {lines:#?}"
    );

    // Not a state of the proxy: a clean JSON body still passes.
    let passed = exchange(proxy.port, &post_typed("/api", JSON, CLEAN_JSON.as_bytes()));
    assert_eq!(passed.status(), 200, "answer: {:?}", passed.text());
    assert_eq!(proxy.finish(1), StopCounts::NONE);
}

#[test]
#[ignore = "needs a built inspector"]
fn the_spellings_of_the_json_type_that_the_proxy_takes_are_inspected() {
    let proxy = Proxy::start("json_spellings", Knobs::quick());
    // The part before the first `;` is compared without its blanks and tabs and without regard to case.
    let spellings = [
        "Application/JSON; charset=UTF-8",
        " \t application/json \t",
        "application/json \t; charset=utf-8",
        "APPLICATION/JSON;charset=utf-8",
    ];
    for (n, spelling) in spellings.into_iter().enumerate() {
        // The rule has to be the one that answers: a spelling that the inspector did not take for JSON would be
        // forwarded (or fail on the body processor), not blocked by it.
        let reply = exchange(
            proxy.port,
            &post_typed("/api", spelling, BLOCKED_JSON.as_bytes()),
        );
        assert_empty_answer(&reply, 403);
        proxy
            .records
            .conns(spelling, n + 1, |l| l.contains(&blocked_by(9203)));
        assert_eq!(proxy.upstream.connections(), 0, "{spelling:?}");
    }

    // A clean body with the first spelling is forwarded with that type as it was sent.
    let clean = CLEAN_JSON.as_bytes();
    let passed = exchange(proxy.port, &post_typed("/api", spellings[0], clean));
    assert_eq!(passed.status(), 200, "answer: {:?}", passed.text());
    assert_eq!(proxy.upstream.connections(), 1);
    assert_forwarded_json(&proxy, 0, "POST /api HTTP/1.1", spellings[0], clean);
    assert_eq!(proxy.finish(1), StopCounts::NONE);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_json_content_type_without_a_body_is_forwarded() {
    let proxy = Proxy::start("json_no_body", Knobs::quick());
    // A GET has no body and no length, and a POST says that its body is empty. The type is not looked at in
    // either case: there is nothing to parse.
    let get_json =
        format!("GET /empty HTTP/1.1\r\nHost: example.test\r\nContent-Type: {JSON}\r\n\r\n");
    let reply = exchange(proxy.port, get_json.as_bytes());
    assert_eq!(reply.status(), 200, "answer: {:?}", reply.text());
    assert_eq!(reply.message().body, UPSTREAM_BODY.as_bytes());
    assert_eq!(proxy.upstream.connections(), 1);
    let reply = exchange(proxy.port, &post_typed("/empty", JSON, b""));
    assert_eq!(reply.status(), 200, "answer: {:?}", reply.text());
    assert_eq!(reply.message().body, UPSTREAM_BODY.as_bytes());
    assert_eq!(proxy.upstream.connections(), 2);

    let requests = proxy.upstream.requests();
    assert_eq!(requests.len(), 2);
    let seen = Message::parse(&requests[0]);
    assert_eq!(seen.start, "GET /empty HTTP/1.1");
    assert_eq!(seen.values("content-type"), [JSON]);
    assert!(
        seen.values("content-length").is_empty(),
        "fields: {:?}",
        seen.fields
    );
    assert!(seen.body.is_empty());
    assert_forwarded_json(&proxy, 1, "POST /empty HTTP/1.1", JSON, b"");
    proxy.records.conns("two forwarded records", 2, |l| {
        l.contains(": forwarded 200 forwarded ")
    });
    assert_eq!(proxy.finish(2), StopCounts::NONE);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_gzip_urlencoded_body_is_inspected_decoded_and_a_clean_one_is_forwarded_decoded() {
    let proxy = Proxy::start("gzip_form", Knobs::quick());
    // The coding is the value `gzip` in any case and with blanks around it. The rule has to be the one that
    // answers: it can only match the argument in the decoded body.
    let spellings = ["gzip", "GZip", " \t gzip \t"];
    for (n, spelling) in spellings.into_iter().enumerate() {
        let reply = exchange(
            proxy.port,
            &post_coded(
                "/submit",
                URLENCODED,
                spelling,
                &gzip(&padded_form("block", 300)),
            ),
        );
        assert_empty_answer(&reply, 403);
        proxy
            .records
            .conns(spelling, n + 1, |l| l.contains(&blocked_by(9202)));
        assert_eq!(proxy.upstream.connections(), 0, "{spelling:?}");
    }
    // The same through the chunked coding, with the stream cut into pieces.
    let reply = exchange(
        proxy.port,
        &chunked_coded(
            "/submit",
            URLENCODED,
            "gzip",
            &gzip(&padded_form("block", 300)),
        ),
    );
    assert_empty_answer(&reply, 403);
    proxy.records.conns("the chunked blocked record", 4, |l| {
        l.contains(&blocked_by(9202))
    });
    assert_eq!(proxy.upstream.connections(), 0);
    assert!(proxy.upstream.requests().is_empty());

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
    assert_eq!(passed.message().body, UPSTREAM_BODY.as_bytes());
    assert_eq!(proxy.upstream.connections(), 1);
    assert_eq!(proxy.upstream.requests().len(), 1);
    assert_forwarded_decoded(&proxy, 0, "POST /submit HTTP/1.1", URLENCODED, &plain);

    // The same through the chunked coding: one length, no chunked framing, no coding.
    let chunked = exchange(
        proxy.port,
        &chunked_coded("/submit", URLENCODED, "gzip", &coded),
    );
    assert_eq!(chunked.status(), 200, "answer: {:?}", chunked.text());
    assert_eq!(proxy.upstream.connections(), 2);
    assert_eq!(proxy.upstream.requests().len(), 2);
    assert_forwarded_decoded(&proxy, 1, "POST /submit HTTP/1.1", URLENCODED, &plain);
    proxy.records.conns("two forwarded records", 2, |l| {
        l.contains(": forwarded 200 forwarded ")
    });
    assert_eq!(proxy.finish(2), StopCounts::NONE);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_gzip_json_body_is_inspected_decoded_and_a_clean_one_is_forwarded_decoded() {
    let proxy = Proxy::start("gzip_json", Knobs::quick());
    let reply = exchange(
        proxy.port,
        &post_coded("/api", JSON, "gzip", &gzip(BLOCKED_JSON.as_bytes())),
    );
    assert_empty_answer(&reply, 403);
    proxy
        .records
        .conns("the blocked record", 1, |l| l.contains(&blocked_by(9203)));
    let reply = exchange(
        proxy.port,
        &chunked_coded("/api", JSON, "gzip", &gzip(BLOCKED_JSON.as_bytes())),
    );
    assert_empty_answer(&reply, 403);
    proxy.records.conns("the chunked blocked record", 2, |l| {
        l.contains(&blocked_by(9203))
    });
    assert_eq!(proxy.upstream.connections(), 0);
    assert!(proxy.upstream.requests().is_empty());

    // The clean body has escapes, non-ASCII text and a final line feed: it reaches the upstream byte for byte.
    let clean = CLEAN_JSON.as_bytes();
    let coded = gzip(clean);
    let passed = exchange(proxy.port, &post_coded("/api", JSON, "gzip", &coded));
    assert_eq!(passed.status(), 200, "answer: {:?}", passed.text());
    assert_eq!(proxy.upstream.connections(), 1);
    assert_forwarded_decoded(&proxy, 0, "POST /api HTTP/1.1", JSON, clean);
    let chunked = exchange(proxy.port, &chunked_coded("/api", JSON, "gzip", &coded));
    assert_eq!(chunked.status(), 200, "answer: {:?}", chunked.text());
    assert_eq!(proxy.upstream.connections(), 2);
    assert_forwarded_decoded(&proxy, 1, "POST /api HTTP/1.1", JSON, clean);
    assert_eq!(proxy.upstream.requests().len(), 2);
    assert_eq!(proxy.finish(2), StopCounts::NONE);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_gzip_body_that_decodes_to_more_than_the_limit_gives_413_and_no_upstream_connection() {
    let proxy = Proxy::start("gzip_413", Knobs::quick());
    // Each coded body is a few hundred bytes to a few tens of KiB, far below the limit on the coded length: only
    // the decoded length can be refused. The rule would block each of them, so a 413 means nothing was inspected.
    let over = padded_form("block", MAX_BODY + 1);
    let bomb = vec![b'a'; 8 * MAX_BODY];
    let coded_over = gzip(&over);
    let coded_bomb = gzip(&bomb);
    assert!(coded_over.len() < 64 * 1024 && coded_bomb.len() < 64 * 1024);
    let requests = [
        (
            "one byte over the limit",
            post_coded("/big", URLENCODED, "gzip", &coded_over),
        ),
        (
            "one byte over the limit, chunked",
            chunked_coded("/big", URLENCODED, "gzip", &coded_over),
        ),
        (
            "8 times the limit",
            post_coded("/big", URLENCODED, "gzip", &coded_bomb),
        ),
        (
            "8 times the limit, chunked",
            chunked_coded("/big", URLENCODED, "gzip", &coded_bomb),
        ),
    ];
    for (n, (what, request)) in requests.into_iter().enumerate() {
        let reply = exchange(proxy.port, &request);
        assert_empty_answer(&reply, 413);
        proxy.records.conns(what, n + 1, |l| {
            l.contains(": rejected 413 decoded body over the limit ")
        });
        assert_eq!(proxy.upstream.connections(), 0, "{what}");
    }
    assert!(proxy.upstream.requests().is_empty());

    // A body that decodes to the limit exactly is taken, and the upstream gets all of it.
    let at_limit = padded_form("ok", MAX_BODY);
    let passed = exchange(
        proxy.port,
        &post_coded("/big", URLENCODED, "gzip", &gzip(&at_limit)),
    );
    assert_eq!(passed.status(), 200, "answer: {:?}", passed.text());
    assert_eq!(proxy.upstream.connections(), 1);
    assert_forwarded_decoded(&proxy, 0, "POST /big HTTP/1.1", URLENCODED, &at_limit);
    assert_eq!(proxy.finish(1), StopCounts::NONE);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_corrupt_gzip_body_or_data_after_its_member_gives_400_and_no_upstream_connection() {
    let proxy = Proxy::start("gzip_400", Knobs::quick());
    // Every plain body would be blocked by the rule, so a 400 means that nothing was inspected.
    let plain = padded_form("block", 300);
    let member = gzip(&plain);
    let trailer = member.len() - 8;
    let mut bad_crc = member.clone();
    bad_crc[trailer] ^= 0xff;
    let mut bad_length = member.clone();
    bad_length[member.len() - 1] ^= 0xff;
    let after_junk = [member.as_slice(), b"junk"].concat();
    let after_zero = [member.as_slice(), &[0u8]].concat();
    let after_member = [member.as_slice(), gzip(b"probe=ok").as_slice()].concat();
    const MALFORMED: &str = "malformed gzip body";
    const AFTER: &str = "data after the gzip member";
    let rows: Vec<(&str, &str, Vec<u8>)> = vec![
        (
            "not a gzip stream",
            MALFORMED,
            post_coded("/g", URLENCODED, "gzip", &plain),
        ),
        (
            "cut in the trailer",
            MALFORMED,
            post_coded("/g", URLENCODED, "gzip", &member[..member.len() - 4]),
        ),
        (
            "cut after the header",
            MALFORMED,
            post_coded("/g", URLENCODED, "gzip", &member[..10]),
        ),
        (
            "a wrong checksum",
            MALFORMED,
            post_coded("/g", URLENCODED, "gzip", &bad_crc),
        ),
        (
            "a wrong checksum, chunked",
            MALFORMED,
            chunked_coded("/g", URLENCODED, "gzip", &bad_crc),
        ),
        (
            "a wrong length",
            MALFORMED,
            post_coded("/g", URLENCODED, "gzip", &bad_length),
        ),
        (
            "a few bytes after the member",
            AFTER,
            post_coded("/g", URLENCODED, "gzip", &after_junk),
        ),
        (
            "a zero byte after the member",
            AFTER,
            post_coded("/g", URLENCODED, "gzip", &after_zero),
        ),
        (
            "a second member",
            AFTER,
            post_coded("/g", URLENCODED, "gzip", &after_member),
        ),
        (
            "a second member, chunked",
            AFTER,
            chunked_coded("/g", URLENCODED, "gzip", &after_member),
        ),
        (
            "an empty chunked body",
            "empty gzip body",
            chunked_coded("/g", URLENCODED, "gzip", b""),
        ),
        (
            "a length of zero",
            "malformed request head",
            post_coded("/g", URLENCODED, "gzip", b""),
        ),
    ];
    for (n, (what, reason, request)) in rows.iter().enumerate() {
        let reply = exchange(proxy.port, request);
        assert_empty_answer(&reply, 400);
        // The records of the rows before this one that gave the same reason are there as well.
        let same = rows[..=n].iter().filter(|row| row.1 == *reason).count();
        proxy.records.conns(what, same, |l| {
            l.contains(&format!(": rejected 400 {reason} "))
        });
        assert_eq!(proxy.upstream.connections(), 0, "{what}");
    }
    assert!(proxy.upstream.requests().is_empty());

    // Not a state of the proxy: a good stream still passes.
    let passed = exchange(
        proxy.port,
        &post_coded("/g", URLENCODED, "gzip", &gzip(b"probe=ok")),
    );
    assert_eq!(passed.status(), 200, "answer: {:?}", passed.text());
    assert_forwarded_decoded(&proxy, 0, "POST /g HTTP/1.1", URLENCODED, b"probe=ok");
    assert_eq!(proxy.finish(1), StopCounts::NONE);
}

// ---------------------------------------------------------------------------------------------------------
// Bodies of the multipart type
// ---------------------------------------------------------------------------------------------------------

const MULTIPART: &str = "multipart/form-data; boundary=xx";

/// A multipart body with one text field for each pair, in order, and the closing delimiter.
fn multipart_body(fields: &[(&str, &str)]) -> Vec<u8> {
    let mut body = String::new();
    for (name, value) in fields {
        body.push_str("--xx\r\nContent-Disposition: form-data; name=\"");
        body.push_str(name);
        body.push_str("\"\r\n\r\n");
        body.push_str(value);
        body.push_str("\r\n");
    }
    body.push_str("--xx--\r\n");
    body.into_bytes()
}

fn post_multipart(path: &str, body: &[u8]) -> Vec<u8> {
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: example.test\r\nContent-Type: {MULTIPART}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(body);
    request
}

#[test]
#[ignore = "needs a built inspector"]
fn a_multipart_body_with_the_blocked_field_is_blocked_and_a_clean_one_is_forwarded_byte_for_byte() {
    let proxy = Proxy::start("multipart", Knobs::quick());
    // The field is the second of two, so the body is parsed as multipart and not just looked at from its start.
    let blocked = exchange(
        proxy.port,
        &post_multipart(
            "/upload",
            &multipart_body(&[("note", "hello"), ("probe", "block")]),
        ),
    );
    assert_empty_answer(&blocked, 403);
    proxy.records.conn("the blocked record", |l| {
        l.contains(": blocked 403 blocked by a rule rule 9202 ")
    });
    assert_eq!(proxy.upstream.connections(), 0);

    // A value with a line break and non-ASCII text, and an empty one: the upstream gets every byte.
    let clean = multipart_body(&[
        ("note", "two lines\r\nsecond line, \u{e9}\u{4e2d}"),
        ("probe", "ok"),
        ("empty", ""),
    ]);
    let passed = exchange(proxy.port, &post_multipart("/upload", &clean));
    assert_eq!(passed.status(), 200, "answer: {:?}", passed.text());
    let requests = proxy.upstream.requests();
    assert_eq!(requests.len(), 1);
    let seen = Message::parse(&requests[0]);
    assert_eq!(seen.start, "POST /upload HTTP/1.1");
    assert_eq!(seen.values("content-type"), [MULTIPART]);
    assert_eq!(seen.values("content-length"), [clean.len().to_string()]);
    assert!(
        !seen.names().contains(&"transfer-encoding"),
        "fields: {:?}",
        seen.fields
    );
    assert_eq!(seen.body, clean);
    assert_eq!(proxy.finish(1), StopCounts::NONE);
}
