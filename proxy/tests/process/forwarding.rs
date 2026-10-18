use crate::support::*;

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
        "X-Real-IP: 203.0.113.7\r\n",
        "Forwarded: for=203.0.113.7\r\n",
        "X_Forwarded_For: 203.0.113.7\r\n",
        "X-Client-IP: 203.0.113.7\r\n",
        "Connection: keep-alive, X-Hop\r\n",
        "X-Hop: 1\r\n",
        "Keep-Alive: timeout=5\r\n",
        "TE: trailers\r\n",
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

    let requests = proxy.upstream.requests();
    assert_eq!(requests.len(), 1);
    let seen = Message::parse(&requests[0]);
    assert_eq!(seen.start, "GET /ok?q=1 HTTP/1.1");
    // Nobody is trusted here: what the client says about itself is dropped.
    for name in [
        "keep-alive",
        "te",
        "upgrade",
        "x-hop",
        "x-real-ip",
        "forwarded",
        "x_forwarded_for",
        "x-client-ip",
    ] {
        assert!(
            !seen.names().contains(&name),
            "the upstream saw {name}: {:?}",
            seen.fields
        );
    }
    // The proxy ends the upstream connection itself, and says so once.
    assert_eq!(seen.values("connection"), ["close"]);
    assert_eq!(seen.values("x-keep"), ["kept"]);
    assert_eq!(seen.values("x-forwarded-for"), ["127.0.0.1"]);
    assert_eq!(seen.values("x-forwarded-host"), ["example.test"]);
    assert_eq!(seen.values("x-forwarded-proto"), ["http"]);

    proxy.records.conn("the forwarded record", |l| {
        l.contains(": forwarded 200 forwarded rule - ")
    });
    proxy.finish(1);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_trusted_peer_names_the_client_and_the_inspection_the_upstream_and_the_record_agree() {
    let knobs = Knobs {
        trusted_proxies: vec!["127.0.0.0/8".to_string()],
        ..Knobs::quick()
    };
    let proxy = Proxy::start("trusted_peer", knobs);
    let request = |path: &str, chain: &str| {
        format!(
            "GET {path} HTTP/1.1\r\nHost: example.test\r\nX-Forwarded-For: {chain}\r\nX-Real-IP: 198.51.100.7\r\nX-Forwarded-Proto: https\r\n\r\n"
        )
    };
    // The test peer is 127.0.0.1, which is trusted. The client is the first address from the right that is not
    // trusted. The inspection accepts an address without a port of its own (a refused one would not be a 200).
    let allowed = exchange(
        proxy.port,
        request("/ok", "203.0.113.1, 198.51.100.7, 127.0.0.9").as_bytes(),
    );
    assert_eq!(allowed.status(), 200, "answer: {:?}", allowed.text());
    let seen = Message::parse(&proxy.upstream.requests()[0]);
    assert_eq!(
        seen.values("x-forwarded-for"),
        ["203.0.113.1, 198.51.100.7, 127.0.0.9, 127.0.0.1"]
    );
    assert_eq!(seen.values("x-real-ip"), ["198.51.100.7"]);
    assert_eq!(seen.values("x-forwarded-proto"), ["https"]);
    proxy.records.conn("the forwarded record", |l| {
        l.contains(": forwarded 200 forwarded rule - ")
            && l.contains(" client 198.51.100.7 upstream main/")
    });

    // A blocked request is recorded under the same client.
    let blocked = exchange(
        proxy.port,
        request("/block-probe/x", "198.51.100.8").as_bytes(),
    );
    assert_empty_answer(&blocked, 403);
    proxy.records.conn("the blocked record", |l| {
        l.contains(&blocked_by(9201)) && l.ends_with(" client 198.51.100.8")
    });

    // An entry that is not an address leaves the peer as the client.
    let odd = exchange(
        proxy.port,
        request("/ok", "198.51.100.9, nonsense").as_bytes(),
    );
    assert_eq!(odd.status(), 200, "answer: {:?}", odd.text());
    proxy.records.conn("the record of the odd chain", |l| {
        l.contains(": forwarded 200 forwarded rule - ")
            && l.contains(" client 127.0.0.1 upstream main/")
    });

    // A name with an underscore says nothing, not even from a trusted peer: it is not inspected, not forwarded,
    // and the client stays the peer (the record of the odd chain above is the other one under the peer).
    let spoken = exchange(
        proxy.port,
        b"GET /ok HTTP/1.1\r\nHost: example.test\r\nX_Forwarded_For: 198.51.100.66\r\n\r\n",
    );
    assert_eq!(spoken.status(), 200, "answer: {:?}", spoken.text());
    let seen = Message::parse(&proxy.upstream.requests()[2]);
    assert!(
        !seen.names().contains(&"x_forwarded_for"),
        "the upstream saw: {:?}",
        seen.fields
    );
    assert_eq!(seen.values("x-forwarded-for"), ["127.0.0.1"]);
    proxy.records.conns("the records under the peer", 2, |l| {
        l.contains(": forwarded 200 forwarded rule - ")
            && l.contains(" client 127.0.0.1 upstream main/")
    });
    proxy.finish(3);
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
    proxy.finish(1);
}
