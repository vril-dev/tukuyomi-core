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
