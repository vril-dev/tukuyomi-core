use std::net::SocketAddr;

use serde_json::{Value, json};

use crate::support::*;

/// One group, `main`, with one server that is written as a name: `localhost` and the port of the first upstream.
fn named(addresses: &[SocketAddr]) -> Value {
    json!({
        "resolve_timeout_ms": RESOLVE_TIMEOUT_MS,
        "upstreams": {"main": {"servers": [server(format!("localhost:{}", addresses[0].port()))]}},
        "routes": [],
        "default_upstream": "main",
    })
}

/// One group, `main`, with a server whose name no one can look up.
fn unknown(_: &[SocketAddr]) -> Value {
    json!({
        "resolve_timeout_ms": 3_000,
        "upstreams": {"main": {"servers": [server("no-such-host.invalid:80")]}},
        "routes": [],
        "default_upstream": "main",
    })
}

/// One group, `main`, and three routes: `/api/` of `app.test`, which edits the request and the response;
/// `/pub/`, which sends the request on under a path that the inspection would block; and `/private/`, for the
/// clients of one network only.
fn edited(addresses: &[SocketAddr]) -> Value {
    json!({
        "resolve_timeout_ms": RESOLVE_TIMEOUT_MS,
        "upstreams": {"main": {"servers": [server(addresses[0])]}},
        "routes": [
            {
                "host": "app.test",
                "path": "/api/",
                "upstream": "main",
                "rewrite": {
                    "host": "inner.test:8080",
                    "path": "/v2/",
                    "query": {
                        "remove": ["debug"],
                        "set": [{"name": "src", "value": "edge"}],
                    },
                    "request_headers": {
                        "remove": ["X-Drop"],
                        "set": [{"name": "X-Edge", "value": "1"}],
                    },
                    "response_headers": {
                        "remove": ["X-Up"],
                        "add": [{"name": "X-Served-By", "value": "edge"}],
                    },
                },
            },
            {"path": "/pub/", "upstream": "main", "rewrite": {"path": "/block-probe/"}},
            {
                "path": "/private/",
                "upstream": "main",
                "access": {"allow_cidrs": ["192.0.2.0/24"]},
            },
        ],
        "default_upstream": "main",
    })
}

fn get_host(host: &str, path: &str, extra: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n{extra}\r\n").into_bytes()
}

#[test]
#[ignore = "needs a built inspector"]
fn a_server_written_as_a_name_is_looked_up_at_the_start_and_reached() {
    let knobs = Knobs {
        forward: named,
        ..Knobs::quick()
    };
    let proxy = Proxy::start("named_server", knobs);
    let port = proxy.upstream.addr().port();
    // The record of the start shows what the name came to. `localhost` may have an IPv6 address too, at which
    // nothing listens: the request goes on to the next server then.
    let begin = format!("start: upstream main localhost:{port} resolved to ");
    let lines = proxy.records.lines();
    let found = lines.iter().find(|l| l.starts_with(&begin));
    let found = found.unwrap_or_else(|| panic!("no record of the lookup in {lines:#?}"));
    assert!(found.contains(&format!("127.0.0.1:{port}")), "{found}");
    let reply = exchange(proxy.port, &get("/named"));
    assert_eq!(reply.status(), 200, "answer: {:?}", reply.text());
    assert_eq!(reply.message().body, UPSTREAM_BODY.as_bytes());
    let requests = proxy.upstream.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(Message::parse(&requests[0]).start, "GET /named HTTP/1.1");
    let server = format!("127.0.0.1:{port}");
    proxy.records.conn("the record names the address", |l| {
        is_answer(l, "forwarded", 200, "forwarded")
            && no(l, "rule")
            && l["upstream"] == "main"
            && l["server"] == server.as_str()
    });
    proxy.finish(1);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_name_that_cannot_be_looked_up_ends_the_start_with_exit_code_1_and_no_listener() {
    let knobs = Knobs {
        forward: unknown,
        ..Knobs::quick()
    };
    let mut proxy = Proxy::spawn("unknown_name", knobs);
    let started = proxy.started;
    let (status, _) = proxy.wait_exit(started, MARGIN);
    let lines = proxy.records.lines();
    assert_eq!(
        status.code(),
        Some(1),
        "exit status {status}; records: {lines:#?}"
    );
    assert_eq!(lines.len(), 2, "records: {lines:#?}");
    assert_eq!(lines[0], "start: configuration accepted");
    let refusal = &lines[1];
    assert!(
        refusal.starts_with("start: upstream refused: ")
            && refusal.ends_with("(upstream main, server 1)"),
        "{refusal}"
    );
    assert_turned_away(proxy.port);
    proxy.clear_root(&["config.json", STORE]);
    proxy.upstream.stop();
    assert_eq!(proxy.upstream.connections(), 0);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_route_edits_the_request_after_the_inspection_and_the_response_and_turns_other_clients_away() {
    let knobs = Knobs {
        forward: edited,
        ..Knobs::quick()
    };
    let proxy = Proxy::start("route_edits", knobs);

    // The edited route: the upstream gets the new path, the query without `debug` and with `src`, the new
    // `Host` and the set field, and not the field that was taken out; the client gets the added field and not
    // the one that was taken out.
    let request = get_host(
        "app.test",
        "/api/items/1?debug=1&keep=%41",
        "X-Drop: yes\r\n",
    );
    let reply = exchange(proxy.port, &request);
    let answer = reply.message();
    assert_eq!(answer.status(), 200, "answer: {:?}", reply.text());
    assert_eq!(answer.values("x-served-by"), ["edge"]);
    assert!(answer.values("x-up").is_empty(), "{:?}", answer.names());
    let requests = proxy.upstream.requests();
    let seen = Message::parse(&requests[0]);
    assert_eq!(seen.start, "GET /v2/items/1?keep=%41&src=edge HTTP/1.1");
    assert_eq!(seen.values("host"), ["inner.test:8080"]);
    assert_eq!(seen.values("x-forwarded-host"), ["app.test"]);
    assert_eq!(seen.values("x-edge"), ["1"]);
    assert!(seen.values("x-drop").is_empty(), "{:?}", seen.fields);

    // The inspection sees the path the client wrote: the path that the route sends on is one that a rule blocks,
    // and the request goes through; the same path written by the client is blocked.
    let reply = exchange(proxy.port, &get_host("app.test", "/pub/a", ""));
    assert_eq!(reply.status(), 200, "answer: {:?}", reply.text());
    assert_eq!(
        Message::parse(&proxy.upstream.requests()[1]).start,
        "GET /block-probe/a HTTP/1.1"
    );
    let reply = exchange(proxy.port, &get_host("app.test", "/block-probe/a", ""));
    assert_eq!(reply.status(), 403, "answer: {:?}", reply.text());

    // A client outside the networks of the route is turned away, and the upstream is not asked.
    let reply = exchange(proxy.port, &get_host("app.test", "/private/x", ""));
    assert_empty_answer(&reply, 403);
    proxy
        .records
        .conn("the record of the turned away client", |l| {
            is_answer(l, "rejected", 403, "denied by route access") && no(l, "upstream")
        });
    // So is a request that writes the same path another way, which the route for `/private/` does not hold for, and
    // one for the path just before it.
    for path in ["/priv%61te/x", "/private"] {
        let reply = exchange(proxy.port, &get_host("app.test", path, ""));
        assert_empty_answer(&reply, 403);
    }
    assert_eq!(proxy.upstream.requests().len(), 2);
    proxy.finish(2);
}
