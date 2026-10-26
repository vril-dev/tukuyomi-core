use std::net::SocketAddr;

use serde_json::{Value, json};

use crate::support::*;

fn get_for(host: &str, path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n").into_bytes()
}

/// Three groups with a server each: `web` for the host `example.test`, `api` for `api.example.test`, and `files` for
/// the paths below `/files/` of `example.test`. There is no default group.
fn three_groups(addresses: &[SocketAddr]) -> Value {
    json!({
        "resolve_timeout_ms": RESOLVE_TIMEOUT_MS,
        "upstreams": {
            "web": {"servers": [server(addresses[0])]},
            "api": {"servers": [server(addresses[1])]},
            "files": {"servers": [server(addresses[2])]},
        },
        "routes": [
            {"host": "api.example.test", "upstream": "api"},
            {"host": "example.test", "path": "/files/", "upstream": "files"},
            {"host": "example.test", "upstream": "web"},
        ],
        "default_upstream": "",
    })
}

/// One group of two servers, the second the first upstream; the first is the one that the test stops.
fn two_servers(addresses: &[SocketAddr]) -> Value {
    json!({
        "resolve_timeout_ms": RESOLVE_TIMEOUT_MS,
        "upstreams": {"main": {"servers": [server(addresses[1]), server(addresses[0])]}},
        "routes": [],
        "default_upstream": "main",
    })
}

fn first_lines(requests: &[Vec<u8>]) -> Vec<String> {
    requests.iter().map(|r| Message::parse(r).start).collect()
}

#[test]
#[ignore = "needs a built inspector"]
fn two_hosts_and_two_paths_go_to_different_upstreams_and_an_unknown_host_gets_404() {
    let knobs = Knobs {
        upstreams: 3,
        forward: three_groups,
        ..Knobs::quick()
    };
    let proxy = Proxy::start("route_groups", knobs);
    // The host decides before the path, and the port of the host does not matter.
    let api = exchange(proxy.port, &get_for("api.example.test:8080", "/files/x"));
    let files = exchange(proxy.port, &get_for("example.test", "/files/a.txt"));
    let web = exchange(proxy.port, &get_for("EXAMPLE.test", "/other"));
    for reply in [&api, &files, &web] {
        assert_eq!(reply.status(), 200, "answer: {:?}", reply.text());
        assert_eq!(reply.message().body, UPSTREAM_BODY.as_bytes());
    }
    assert_eq!(
        first_lines(&proxy.upstream.requests()),
        ["GET /other HTTP/1.1"]
    );
    assert_eq!(
        first_lines(&proxy.others[0].requests()),
        ["GET /files/x HTTP/1.1"]
    );
    assert_eq!(
        first_lines(&proxy.others[1].requests()),
        ["GET /files/a.txt HTTP/1.1"]
    );
    for (group, up) in [
        ("web", &proxy.upstream),
        ("api", &proxy.others[0]),
        ("files", &proxy.others[1]),
    ] {
        let server = up.addr().to_string();
        proxy.records.conn(&format!("the record of {group}"), |l| {
            is_answer(l, "forwarded", 200, "forwarded")
                && no(l, "rule")
                && l["upstream"] == group
                && l["server"] == server.as_str()
        });
    }

    // No route holds for another host and there is no default group: 404, and no upstream is asked.
    let stranger = exchange(proxy.port, &get_for("stranger.test", "/files/a.txt"));
    assert_empty_answer(&stranger, 404);
    proxy.records.conn("the record of the 404", |l| {
        is_answer(l, "rejected", 404, "no route matches") && no(l, "upstream")
    });
    assert_eq!(proxy.upstream.requests().len(), 1);
    assert_eq!(proxy.others[0].requests().len(), 1);
    assert_eq!(proxy.others[1].requests().len(), 1);
    proxy.finish(1);
}

#[test]
#[ignore = "needs a built inspector"]
fn with_one_server_of_a_group_stopped_the_requests_go_to_the_other() {
    let knobs = Knobs {
        upstreams: 2,
        forward: two_servers,
        ..Knobs::quick()
    };
    let mut proxy = Proxy::start("group_failover", knobs);
    // The first server of the group refuses the connection from now on.
    proxy.others[0].stop();
    for path in ["/one", "/two", "/three", "/four"] {
        let reply = exchange(proxy.port, &get(path));
        assert_eq!(reply.status(), 200, "{path}: {:?}", reply.text());
        assert_eq!(reply.message().body, UPSTREAM_BODY.as_bytes());
    }
    assert_eq!(proxy.upstream.requests().len(), 4);
    assert!(proxy.others[0].requests().is_empty());
    // The first request found the stopped server first and went on, so every record names the other server.
    let server = proxy.upstream.addr().to_string();
    proxy.records.conns("four forwarded records", 4, |l| {
        is_answer(l, "forwarded", 200, "forwarded")
            && no(l, "rule")
            && l["upstream"] == "main"
            && l["server"] == server.as_str()
    });
    proxy.finish(4);
}
