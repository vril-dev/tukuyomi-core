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
    for name in ["keep-alive", "te", "upgrade", "x-hop"] {
        assert!(
            !seen.names().contains(&name),
            "the upstream saw {name}: {:?}",
            seen.fields
        );
    }
    // The proxy ends the upstream connection itself, and says so once.
    assert_eq!(seen.values("connection"), ["close"]);
    assert_eq!(seen.values("x-keep"), ["kept"]);
    assert_eq!(seen.values("x-forwarded-for"), ["203.0.113.7, 127.0.0.1"]);
    assert_eq!(seen.values("x-forwarded-host"), ["example.test"]);
    assert_eq!(seen.values("x-forwarded-proto"), ["http"]);

    proxy.records.conn("the forwarded record", |l| {
        l.contains(": forwarded 200 forwarded rule - ")
    });
    proxy.finish(1);
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
