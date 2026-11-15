//! The `access`, the `rate_limit` and the `geo` of the configuration in a real process.
//!
//! The objects are added to the configuration of the test before the proxy starts. The status listener is at a free
//! loopback port, where the test reads the counts at `/metrics`.

use std::fs;

use serde_json::{Value, json};
use tukuyomi_proxy::rules::bundle::sha256;

use crate::support::*;

/// A proxy that is listening, with these objects added at the top of its configuration and its status listener at the
/// port that is returned.
fn policed(test: &str, objects: Vec<(&'static str, Value)>) -> (Proxy, u16) {
    let port = free_port();
    let proxy = Proxy::start_with(test, Knobs::quick(), |root| {
        add_object(
            root,
            "status",
            json!({ "listen": format!("127.0.0.1:{port}") }),
        );
        for (key, value) in objects {
            add_object(root, key, value);
        }
    });
    (proxy, port)
}

/// The page at `/metrics`.
fn metrics(port: u16) -> String {
    let reply = exchange(port, &get("/metrics"));
    assert_eq!(reply.status(), 200, "answer: {:?}", reply.text());
    String::from_utf8(reply.message().body).expect("the page is text")
}

fn assert_line(page: &str, line: &str) {
    assert!(page.lines().any(|have| have == line), "{line} in {page}");
}

#[test]
#[ignore = "needs a built inspector"]
fn a_client_over_the_rate_limit_gets_429_with_retry_after_and_the_metrics_show_the_refusals() {
    // Two requests pass at once, then one a second.
    let limit = json!({"rate": 1, "burst": 1, "keys": 1024});
    let (proxy, status) = policed("rate_limit", vec![("rate_limit", limit)]);
    for _ in 0..2 {
        let reply = exchange(proxy.port, &get("/ok"));
        assert_eq!(reply.status(), 200, "answer: {:?}", reply.text());
    }
    let refused = exchange(proxy.port, &get("/ok"));
    assert_empty_answer(&refused, 429);
    assert_eq!(refused.message().values("retry-after"), ["1"]);
    proxy.records.conn("the 429 record", |l| {
        is_answer(l, "rejected", 429, "too many requests")
    });

    let page = metrics(status);
    assert_line(
        &page,
        "tukuyomi_policy_refusals_total{policy=\"rate_limit\"} 1",
    );
    assert_line(&page, "tukuyomi_policy_refusals_total{policy=\"access\"} 0");
    assert_line(&page, "tukuyomi_rate_limit_keys 1");
    assert_line(&page, "tukuyomi_rate_limit_evicted_total 0");
    // The refused request was not forwarded.
    proxy.finish(2);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_client_outside_the_allow_list_of_the_configuration_gets_403_and_the_record_shows_why() {
    let access = json!({"allow_cidrs": ["10.0.0.0/8"]});
    let (proxy, status) = policed("global_access", vec![("access", access)]);
    let refused = exchange(proxy.port, &get("/ok"));
    assert_empty_answer(&refused, 403);
    proxy.records.conn("the 403 record", |l| {
        is_answer(l, "rejected", 403, "denied by access")
    });

    let page = metrics(status);
    assert_line(&page, "tukuyomi_policy_refusals_total{policy=\"access\"} 1");
    assert_line(
        &page,
        "tukuyomi_policy_refusals_total{policy=\"rate_limit\"} 0",
    );
    proxy.finish(0);
}

/// A text of at most 28 bytes in the form of the MaxMind DB data section.
fn db_text(text: &str) -> Vec<u8> {
    let mut out = vec![0x40 | u8::try_from(text.len()).expect("a short text")];
    out.extend(text.bytes());
    out
}

/// A country database of IPv4 addresses with one node: the addresses from 128.0.0.0 on are in JP, and the ones below
/// it (the loopback addresses among them) are in no country.
fn country_db() -> Vec<u8> {
    let mut data = vec![0xE1];
    data.extend(db_text("country"));
    data.push(0xE1);
    data.extend(db_text("iso_code"));
    data.extend(db_text("JP"));
    let mut metadata = vec![0xE5];
    for (key, value) in [
        ("binary_format_major_version", vec![0xA1, 2]),
        ("database_type", db_text("Test-Country")),
        ("ip_version", vec![0xA1, 4]),
        ("node_count", vec![0xC1, 1]),
        ("record_size", vec![0xA1, 24]),
    ] {
        metadata.extend(db_text(key));
        metadata.extend(value);
    }
    // The left record is the number of nodes (nothing is known), the right one is the data at offset 0 (1 + 16).
    let mut file = vec![0, 0, 1, 0, 0, 17];
    file.extend([0; 16]);
    file.extend(data);
    file.extend(b"\xAB\xCD\xEFMaxMind.com");
    file.extend(metadata);
    file
}

/// A proxy that is listening with the database above in its `geo` and this `access`. The database is read when the
/// proxy starts, so the file is removed once it listens.
fn with_countries(test: &str, access: Value) -> Proxy {
    let file = country_db();
    let digest: String = sha256(&file)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let proxy = Proxy::start_with(test, Knobs::quick(), |root| {
        let path = root.join("country.mmdb");
        fs::write(&path, &file).expect("write the database");
        add_object(
            root,
            "geo",
            json!({ "country_db": path.to_string_lossy(), "sha256": digest }),
        );
        add_object(root, "access", access);
    });
    fs::remove_file(proxy.root().join("country.mmdb")).expect("remove the database");
    proxy
}

#[test]
#[ignore = "needs a built inspector"]
fn the_lists_of_countries_judge_a_client_that_the_database_does_not_cover_as_unknown() {
    // The loopback client is in no country: a list that allows only JP turns it away, and a list that denies JP does
    // not.
    let proxy = with_countries("allow_countries", json!({"allow_countries": ["JP"]}));
    let refused = exchange(proxy.port, &get("/ok"));
    assert_empty_answer(&refused, 403);
    proxy.records.conn("the 403 record", |l| {
        is_answer(l, "rejected", 403, "denied by access")
    });
    proxy.finish(0);

    let proxy = with_countries("deny_countries", json!({"deny_countries": ["JP"]}));
    let reply = exchange(proxy.port, &get("/ok"));
    assert_eq!(reply.status(), 200, "answer: {:?}", reply.text());
    proxy.finish(1);
}

/// A GET of `/ok` with the `Host` `host`.
fn get_for(host: &str) -> Vec<u8> {
    format!("GET /ok HTTP/1.1\r\nHost: {host}\r\n\r\n").into_bytes()
}

#[test]
#[ignore = "needs a built inspector"]
fn each_host_policy_holds_for_its_hosts_and_a_host_that_cannot_be_read_meets_every_access() {
    let policies = |rate: u32| {
        json!([
            {"name": "a", "hosts": ["a.example"], "rate_limit": {"rate": rate, "burst": 0, "keys": 1024}},
            {"name": "b", "hosts": ["b.example"], "access": {"allow_cidrs": ["127.0.0.0/8"]}},
            {"name": "c", "hosts": ["c.example"], "access": {}, "rate_limit": {}},
            {"name": "d", "hosts": ["d.example"], "access": {"deny_cidrs": ["127.0.0.0/8"]}},
        ])
    };
    let (proxy, status) = policed(
        "host_policies",
        vec![
            ("rate_limit", json!({"rate": 1, "burst": 1, "keys": 1024})),
            ("host_policies", policies(1)),
        ],
    );
    let ask = |host: &str| exchange(proxy.port, &get_for(host));
    // A counts in a table of its own: one request, then 429.
    assert_eq!(ask("a.example").status(), 200);
    assert_empty_answer(&ask("a.example"), 429);
    // B leaves the rate limit out, and shares the table of the configuration with a host that has no policy: two
    // requests, then 429.
    assert_eq!(ask("b.example").status(), 200);
    assert_eq!(ask("example.test").status(), 200);
    assert_empty_answer(&ask("b.example"), 429);
    // C is counted nowhere, so the full table of the configuration does not turn it away.
    for _ in 0..2 {
        assert_eq!(ask("c.example").status(), 200);
    }
    // D turns the client away, also with a `Host` that cannot be read, which the default group would serve.
    for host in ["d.example", "d.example:0443"] {
        assert_empty_answer(&ask(host), 403);
    }
    proxy.records.conns("the 403 records", 2, |l| {
        is_answer(l, "rejected", 403, "denied by access")
    });
    let page = metrics(status);
    // The client in the table of the configuration and in the table of A.
    assert_line(&page, "tukuyomi_rate_limit_keys 2");
    assert_line(
        &page,
        "tukuyomi_policy_refusals_total{policy=\"rate_limit\"} 2",
    );
    assert_line(&page, "tukuyomi_policy_refusals_total{policy=\"access\"} 2");

    // Read again with another rate for A: its table counts from nothing, and the table of the configuration goes on.
    add_object(proxy.root(), "host_policies", policies(2));
    proxy.signal("HUP");
    proxy.records.wait_lines("the replacement", 1, |l| {
        l.starts_with("reload: configuration replaced ")
    });
    let lines = proxy.records.lines();
    let anew = "reload: rate limit table of host policy a started anew";
    assert!(lines.iter().any(|l| l == anew), "{lines:#?}");
    let configuration = "reload: rate limit table started anew";
    assert!(!lines.iter().any(|l| l == configuration), "{lines:#?}");
    assert_line(&metrics(status), "tukuyomi_rate_limit_keys 1");
    proxy.finish(5);
}
