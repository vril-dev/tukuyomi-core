use std::collections::BTreeSet;
use std::net::SocketAddr;

use serde_json::{Value, json};

use crate::support::*;

pub(crate) fn get_for(host: &str, path: &str) -> Vec<u8> {
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

/// Three groups with a server each: `web` for the paths below `/`, `api` for those that have a version (`/v2/`) in
/// them, and `files` for the paths below `/files/`, which comes first by its priority. There is no default group.
fn by_pattern(addresses: &[SocketAddr]) -> Value {
    json!({
        "resolve_timeout_ms": RESOLVE_TIMEOUT_MS,
        "upstreams": {
            "web": {"servers": [server(addresses[0])]},
            "api": {"servers": [server(addresses[1])]},
            "files": {"servers": [server(addresses[2])]},
        },
        "routes": [
            {"path_regex": "/v[0-9]+/", "upstream": "api"},
            {"path": "/files/", "priority": -1, "upstream": "files"},
            {"path": "/", "upstream": "web"},
        ],
        "default_upstream": "",
    })
}

/// One group of two servers, the second the first upstream; the first is the one that the test stops.
pub(crate) fn two_servers(addresses: &[SocketAddr]) -> Value {
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

#[test]
#[ignore = "needs a built inspector"]
fn a_route_with_a_path_regex_and_a_route_with_a_priority_go_to_their_groups() {
    let knobs = Knobs {
        upstreams: 3,
        forward: by_pattern,
        ..Knobs::quick()
    };
    let proxy = Proxy::start("route_pattern", knobs);
    // The path regex is before the prefix `/`, the priority before the path regex, and the prefix holds for the rest.
    for path in ["/api/v2/x", "/files/v2/x", "/other"] {
        let reply = exchange(proxy.port, &get(path));
        assert_eq!(reply.status(), 200, "{path}: {:?}", reply.text());
        assert_eq!(reply.message().body, UPSTREAM_BODY.as_bytes());
    }
    assert_eq!(
        first_lines(&proxy.upstream.requests()),
        ["GET /other HTTP/1.1"]
    );
    assert_eq!(
        first_lines(&proxy.others[0].requests()),
        ["GET /api/v2/x HTTP/1.1"]
    );
    assert_eq!(
        first_lines(&proxy.others[1].requests()),
        ["GET /files/v2/x HTTP/1.1"]
    );
    proxy.finish(1);
}

/// One group of three servers that the client address chooses among.
fn hashed_by_client(addresses: &[SocketAddr]) -> Value {
    json!({
        "resolve_timeout_ms": RESOLVE_TIMEOUT_MS,
        "upstreams": {"main": {
            "servers": [server(addresses[0]), server(addresses[1]), server(addresses[2])],
            "balance": "hash",
            "hash_policy": "client_ip",
        }},
        "routes": [],
        "default_upstream": "main",
    })
}

#[test]
#[ignore = "needs a built inspector"]
fn a_group_with_balance_hash_sends_a_client_to_the_same_server_each_time() {
    let knobs = Knobs {
        upstreams: 3,
        forward: hashed_by_client,
        trusted_proxies: vec!["127.0.0.0/8".to_string()],
        ..Knobs::quick()
    };
    let proxy = Proxy::start("balance_hash", knobs);
    // The test peer is trusted, so the client is the address that its `X-Forwarded-For` names; the path says which of
    // the requests it was. Each of 16 clients asks twice.
    for round in 0..2 {
        for client in 1..=16 {
            let request = format!(
                "GET /c{client}-{round} HTTP/1.1\r\nHost: example.test\r\nX-Forwarded-For: 198.51.100.{client}\r\n\r\n"
            );
            let reply = exchange(proxy.port, request.as_bytes());
            assert_eq!(reply.status(), 200, "client {client}: {:?}", reply.text());
        }
    }
    let seen: Vec<Vec<String>> = [&proxy.upstream, &proxy.others[0], &proxy.others[1]]
        .iter()
        .map(|up| first_lines(&up.requests()))
        .collect();
    let went = |client: usize, round: usize| {
        let line = format!("GET /c{client}-{round} HTTP/1.1");
        let at: Vec<usize> = (0..3).filter(|&s| seen[s].contains(&line)).collect();
        assert_eq!(at.len(), 1, "{line}: {at:?}");
        at[0]
    };
    let mut used = BTreeSet::new();
    for client in 1..=16 {
        let first = went(client, 0);
        assert_eq!(went(client, 1), first, "client {client}");
        used.insert(first);
    }
    // 16 clients are not all of one server's: the key is the client and not the test peer, which is always the same.
    assert!(used.len() > 1, "every client went to one server");
    proxy.finish(seen[0].len());
}
