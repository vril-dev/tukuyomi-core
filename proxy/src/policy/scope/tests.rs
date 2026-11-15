use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use super::*;
use crate::config;
use crate::log::counters::Counters;
use crate::policy::{Refusal, check};

const NONE: Country = Country::Unknown;

/// `value` read in the form of `T`; none for `null`, a key that is left out.
fn read<T: DeserializeOwned>(value: &Value) -> Option<T> {
    (!value.is_null())
        .then(|| serde_json::from_value(value.clone()).expect("the form of the object"))
}

/// The policy of a configuration with the `access`, the `rate_limit` and the `host_policies` of `policy`, checked as
/// those of a version are, whose tables follow those of `earlier`.
fn scopes(policy: Value, earlier: Option<&Scopes>) -> Scopes {
    let config = config::routed(
        read(&policy["access"]),
        read(&policy["rate_limit"]),
        read(&policy["host_policies"]),
        None,
        None,
    )
    .expect("a policy that passes the check");
    Scopes::new(config, earlier)
}

/// What the policy says of a request with the `Host` `host` from `client`, which is in `country`.
fn ask(scopes: &Scopes, host: &str, client: &str, country: Country) -> Result<(), Refusal> {
    let client = client.parse().unwrap();
    check(
        scopes.scope(Some(host.as_bytes())),
        &Counters::start(),
        client,
        country,
    )
}

#[test]
fn a_host_policy_is_found_by_the_host_as_a_route_is_and_holds_in_the_place_of_the_configuration() {
    let scopes = scopes(
        json!({
            "access": {"deny_cidrs": ["10.0.0.0/8"]},
            "host_policies": [
                {"name": "wild", "hosts": ["*.example.test"], "access": {"deny_cidrs": ["192.0.2.0/24"]}},
                {"name": "app", "hosts": ["app.example.test"], "access": {}},
            ],
        }),
        None,
    );
    // Each of the three turns away a client that the other two let through.
    let (denied_here, denied_there) = ("10.0.0.1", "192.0.2.1");
    // The name comes before the `*.` host, and the case of the `Host`, one `.` at its end and its port do not count.
    for host in [
        "app.example.test",
        "App.Example.Test.",
        "app.example.test:8443",
    ] {
        assert_eq!(ask(&scopes, host, denied_there, NONE), Ok(()), "{host}");
        assert_eq!(ask(&scopes, host, denied_here, NONE), Ok(()), "{host}");
    }
    // The `*.` host holds for a name of one label or more in front of it, in the place of the configuration.
    for host in ["www.example.test", "a.b.example.test"] {
        assert_eq!(ask(&scopes, host, denied_there, NONE), Err(Refusal::Access));
        assert_eq!(ask(&scopes, host, denied_here, NONE), Ok(()));
    }
    // A host that no policy names, the rest of a `*.` host alone among them, is asked by the configuration.
    for host in ["other.test", "example.test"] {
        assert_eq!(ask(&scopes, host, denied_here, NONE), Err(Refusal::Access));
        assert_eq!(ask(&scopes, host, denied_there, NONE), Ok(()));
    }
}

#[test]
fn a_request_whose_host_cannot_be_read_has_to_pass_every_access_and_is_counted_in_every_table() {
    let limit = json!({"rate": 1, "burst": 0, "keys": 1024});
    let scopes = scopes(
        json!({
            "access": {"deny_cidrs": ["10.0.0.0/8"]},
            "rate_limit": limit,
            "host_policies": [
                {"name": "a", "hosts": ["a.test"], "access": {"deny_cidrs": ["192.0.2.0/24"]}, "rate_limit": limit},
                {"name": "off", "hosts": ["off.test"], "access": {}, "rate_limit": {}},
            ],
        }),
        None,
    );
    let (denied_here, denied_there) = ("10.0.0.1", "192.0.2.1");
    assert_eq!(ask(&scopes, "a.test", denied_here, NONE), Ok(()));
    // Unread, the same host is turned away by the access of the policy and by that of the configuration.
    for host in ["a.test:", "a.test:0443", "a_test", "a.test.."] {
        assert_eq!(
            ask(&scopes, host, denied_there, NONE),
            Err(Refusal::Access),
            "{host}"
        );
        assert_eq!(
            ask(&scopes, host, denied_here, NONE),
            Err(Refusal::Access),
            "{host}"
        );
    }
    let counters = Counters::start();
    let none = check(
        scopes.scope(None),
        &counters,
        denied_there.parse().unwrap(),
        NONE,
    );
    assert_eq!(none, Err(Refusal::Access));

    // A client that every access lets is counted in the table of the configuration and in that of the policy.
    let client = "203.0.113.1";
    assert_eq!(ask(&scopes, "a.test:0443", client, NONE), Ok(()));
    assert_eq!(
        ask(&scopes, "a.test", client, NONE),
        Err(Refusal::RateLimit(1))
    );
    assert_eq!(
        ask(&scopes, "other.test", client, NONE),
        Err(Refusal::RateLimit(1))
    );
    // The table of the configuration counts that client, and the one of the policy that client and the first one;
    // the policy that is off has none.
    assert_eq!(scopes.keys(), 3);
}

#[test]
fn a_policy_that_is_off_neither_turns_away_nor_counts_and_one_that_inherits_shares_the_table() {
    let scopes = scopes(
        json!({
            "access": {"deny_cidrs": ["10.0.0.0/8"]},
            "rate_limit": {"rate": 1, "burst": 1, "keys": 1024},
            "host_policies": [
                {"name": "off", "hosts": ["off.test"], "access": {}, "rate_limit": {}},
                {"name": "b", "hosts": ["b.test"], "access": {"allow_cidrs": ["192.0.2.0/24"]}},
                {"name": "c", "hosts": ["c.test"], "access": {"allow_cidrs": ["192.0.2.0/24"]}},
                {"name": "own", "hosts": ["own.test"], "rate_limit": {"rate": 1, "burst": 0, "keys": 1024}},
            ],
        }),
        None,
    );
    // A client that the configuration turns away is let through, as often as it comes, and counted nowhere.
    for _ in 0..3 {
        assert_eq!(ask(&scopes, "off.test", "10.0.0.1", NONE), Ok(()));
    }
    assert_eq!(scopes.keys(), 0);
    // Two policies that leave the rate limit out share the table of the configuration: two pass at once, and then
    // the next of either is refused.
    let client = "192.0.2.1";
    assert_eq!(ask(&scopes, "b.test", client, NONE), Ok(()));
    assert_eq!(ask(&scopes, "c.test", client, NONE), Ok(()));
    assert_eq!(
        ask(&scopes, "b.test", client, NONE),
        Err(Refusal::RateLimit(1))
    );
    assert_eq!(
        ask(&scopes, "other.test", client, NONE),
        Err(Refusal::RateLimit(1))
    );
    // A policy with a table of its own, or with none, does not meet the refusal of the full table.
    assert_eq!(ask(&scopes, "own.test", client, NONE), Ok(()));
    assert_eq!(ask(&scopes, "off.test", client, NONE), Ok(()));
    assert_eq!(scopes.keys(), 2);
}

#[test]
fn a_host_policy_turns_a_client_away_by_its_country() {
    let scopes = scopes(
        json!({"host_policies": [{"name": "a", "hosts": ["a.test"], "access": {"deny_countries": ["JP"]}}]}),
        None,
    );
    let (jp, us) = (Country::Known(*b"JP"), Country::Known(*b"US"));
    let client = "203.0.113.1";
    assert_eq!(ask(&scopes, "a.test", client, jp), Err(Refusal::Access));
    assert_eq!(ask(&scopes, "a.test", client, us), Ok(()));
    assert_eq!(ask(&scopes, "b.test", client, jp), Ok(()));
}

#[test]
fn the_table_of_a_host_policy_goes_on_by_its_name_and_its_numbers_when_the_configuration_is_read_again()
 {
    let policy = |name: &str, hosts: Value, rate: u32| {
        let limit = json!({"rate": rate, "burst": 0, "keys": 1024});
        json!({"host_policies": [{"name": name, "hosts": hosts, "rate_limit": limit}]})
    };
    let client = "192.0.2.1";
    let first = scopes(policy("a", json!(["a.test"]), 1), None);
    assert_eq!(ask(&first, "a.test", client, NONE), Ok(()));
    assert_eq!(
        ask(&first, "a.test", client, NONE),
        Err(Refusal::RateLimit(1))
    );
    // The same name and the same numbers: the client is still over the limit, and no table starts anew.
    let same = scopes(policy("a", json!(["a.test"]), 1), Some(&first));
    assert_eq!(
        ask(&same, "a.test", client, NONE),
        Err(Refusal::RateLimit(1))
    );
    assert_eq!(same.anew(&first).count(), 0);
    // Other hosts only: the same.
    let moved = scopes(policy("a", json!(["b.test", "c.test"]), 1), Some(&same));
    assert_eq!(
        ask(&moved, "b.test", client, NONE),
        Err(Refusal::RateLimit(1))
    );
    assert_eq!(moved.anew(&same).count(), 0);
    // More clients than the table holds, so that some are dropped while their number is still in force.
    for at in 0..1025u16 {
        let [high, low] = at.to_be_bytes();
        let _ = moved
            .scope(Some(b"b.test"))
            .admit(IpAddr::from([10, 0, high, low]));
    }
    let evicted = moved.evicted();
    // Another rate, or another name: the table counts from nothing, and it is told by the name of its policy. The
    // clients that the old table dropped stay in the sum.
    let faster = scopes(policy("a", json!(["b.test"]), 2), Some(&moved));
    assert_eq!(ask(&faster, "b.test", client, NONE), Ok(()));
    assert_eq!(faster.anew(&moved).collect::<Vec<_>>(), [Some("a")]);
    assert_eq!((evicted > 0, faster.evicted()), (true, evicted));
    let renamed = scopes(policy("b", json!(["b.test"]), 2), Some(&faster));
    assert_eq!(ask(&renamed, "b.test", client, NONE), Ok(()));
    assert_eq!(renamed.anew(&faster).collect::<Vec<_>>(), [Some("b")]);
    // The table of the configuration is told apart from those of the policies.
    let global = json!({"rate_limit": {"rate": 1, "burst": 0, "keys": 1024}});
    assert_eq!(
        scopes(global, Some(&renamed))
            .anew(&renamed)
            .collect::<Vec<_>>(),
        [None]
    );
}
