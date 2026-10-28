//! The `access` and the `rate_limit` of the configuration in a real process.
//!
//! The objects are added to the configuration of the test before the proxy starts. The status listener is at a free
//! loopback port, where the test reads the counts at `/metrics`.

use serde_json::{Value, json};

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
