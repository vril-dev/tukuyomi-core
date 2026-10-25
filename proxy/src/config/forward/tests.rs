use serde_json::{Value, json};

use super::*;

fn server(address: &str) -> Value {
    json!({
        "address": address,
        "weight": 1,
        "max_fails": 1,
        "fail_timeout_ms": 1000,
        "backup": false,
    })
}

/// The `forward` object with the one group `g`.
fn forward(group: Value) -> Value {
    json!({
        "resolve_timeout_ms": 1000,
        "upstreams": {"g": group},
        "routes": [],
        "default_upstream": "g",
    })
}

fn load(value: Value) -> Result<ForwardSettings, ConfigError> {
    let raw: RawForward = serde_json::from_value(value).map_err(|e| super::super::refusal(&e))?;
    check(raw, &[], 1 << 20)
}

/// The group `g` with a server at `address` and this `tls`.
fn with_tls(address: &str, tls: Value) -> Result<ForwardSettings, ConfigError> {
    load(forward(json!({"servers": [server(address)], "tls": tls})))
}

fn refusal(result: Result<ForwardSettings, ConfigError>) -> &'static str {
    result.expect_err("the object was taken").0
}

#[test]
fn a_group_may_have_tls_with_a_file_of_authorities_and_a_name_that_may_be_left_out() {
    let plain = load(forward(json!({"servers": [server("192.0.2.1:443")]}))).unwrap();
    assert_eq!(plain.groups[0].tls, None);
    let by = |settings: Settings| Some(settings);
    let taken = with_tls("192.0.2.1:443", json!({"ca_file": "/etc/ca.pem"})).unwrap();
    assert_eq!(
        taken.groups[0].tls,
        by(Settings {
            ca_file: PathBuf::from("/etc/ca.pem"),
            server_name: None,
        })
    );
    let named = json!({"ca_file": "/etc/ca.pem", "server_name": "api.test"});
    assert_eq!(
        with_tls("192.0.2.1:443", named).unwrap().groups[0].tls,
        by(Settings {
            ca_file: PathBuf::from("/etc/ca.pem"),
            server_name: Some("api.test".to_string()),
        })
    );
}

#[test]
fn tls_needs_its_file_has_no_other_key_and_is_never_null() {
    let address = "192.0.2.1:443";
    assert_eq!(
        refusal(with_tls(address, json!({}))),
        "configuration has a missing key"
    );
    assert_eq!(
        refusal(with_tls(
            address,
            json!({"ca_file": "/etc/ca.pem", "verify": false})
        )),
        "configuration has an unknown key"
    );
    // `null` is a value of the wrong type, in place of the object and of the name: it must not turn TLS off, or
    // take the name of the server in place of the name of the group.
    let wrong = "configuration has a value of the wrong type";
    assert_eq!(refusal(with_tls(address, Value::Null)), wrong);
    assert_eq!(
        refusal(with_tls(
            address,
            json!({"ca_file": "/etc/ca.pem", "server_name": null})
        )),
        wrong
    );
    assert_eq!(refusal(with_tls(address, json!({"ca_file": null}))), wrong);
    assert_eq!(refusal(with_tls(address, json!([]))), wrong);
}

#[test]
fn the_file_of_authorities_is_an_absolute_clean_path_of_at_most_3840_bytes() {
    let path = "an upstream tls ca_file is not an absolute clean path of at most 3840 bytes";
    let by = |ca_file: &str| with_tls("192.0.2.1:443", json!({"ca_file": ca_file}));
    let at_limit = format!("/{}", "a".repeat(3839));
    assert!(by(&at_limit).is_ok());
    assert_eq!(refusal(by(&format!("{at_limit}a"))), path);
    for bad in [
        "",
        "ca.pem",
        "/etc/../ca.pem",
        "/etc/./ca.pem",
        "/etc//ca.pem",
        "/etc/ca.pem/",
        "/",
    ] {
        assert_eq!(refusal(by(bad)), path, "{bad:?}");
    }
}

#[test]
fn a_name_that_a_server_is_checked_for_must_be_one_that_tls_can_use() {
    let name = "an upstream tls server_name is not a name that TLS can use";
    let own = "a server name of an upstream with tls is not a name that TLS can use";
    let by = |server_name: &str| {
        with_tls(
            "192.0.2.1:443",
            json!({"ca_file": "/etc/ca.pem", "server_name": server_name}),
        )
    };
    // The form of a server name, and a label that TLS takes.
    for good in ["api.test", "a_b.test", "a-b.test", "x"] {
        assert!(by(good).is_ok(), "{good}");
    }
    // Not a name: empty, an address, capitals, an empty label, a label of more than 63 bytes; a label that starts
    // or ends with `-`, which the form of a server name allows and TLS does not.
    for bad in [
        "",
        "192.0.2.1",
        "::1",
        "API.test",
        "a..test",
        "a.test.",
        "-a.test",
        "a-.test",
    ] {
        assert_eq!(refusal(by(bad)), name, "{bad:?}");
    }
    assert_eq!(refusal(by(&format!("{}.test", "a".repeat(64)))), name);
    // Without a `server_name` the name of each server is the name: a server written with an address has none to
    // be wrong, and with a `server_name` the names of the servers are not looked at.
    let servers = |address: &str, tls: Value| {
        load(forward(
            json!({"servers": [server("192.0.2.1:443"), server(address)], "tls": tls}),
        ))
    };
    let ca = json!({"ca_file": "/etc/ca.pem"});
    assert!(servers("app.test:443", ca.clone()).is_ok());
    assert_eq!(refusal(servers("a-.test:443", ca)), own);
    let named = json!({"ca_file": "/etc/ca.pem", "server_name": "api.test"});
    assert!(servers("a-.test:443", named).is_ok());
    // A group without `tls` takes such a name as it always did.
    assert!(load(forward(json!({"servers": [server("a-.test:443")]}))).is_ok());
}

#[test]
fn a_route_may_lower_the_limit_on_the_body_and_not_raise_it() {
    // The limit of the proxy is 1 MiB in `load`.
    let with = |max_body: Value| {
        let mut object = forward(json!({"servers": [server("192.0.2.1:80")]}));
        object["routes"] = json!([{"path": "/login/", "upstream": "g", "max_body": max_body}]);
        load(object)
    };
    let limit =
        |loaded: ForwardSettings| loaded.routes.targets().map(|route| route.max_body).next();
    assert_eq!(limit(with(json!(1u64 << 20)).unwrap()), Some(Some(1 << 20)));
    assert_eq!(limit(with(json!(0)).unwrap()), Some(Some(0)));
    assert_eq!(
        refusal(with(json!((1u64 << 20) + 1))),
        "a route max_body is above the max_body of the proxy"
    );
    // A route that says nothing has no limit of its own; a value of another type or `null` is no limit either.
    let mut object = forward(json!({"servers": [server("192.0.2.1:80")]}));
    object["routes"] = json!([{"path": "/login/", "upstream": "g"}]);
    assert_eq!(limit(load(object).unwrap()), Some(None));
    let wrong = "configuration has a value of the wrong type";
    for bad in [Value::Null, json!("1024"), json!(-1)] {
        assert_eq!(refusal(with(bad.clone())), wrong, "{bad:?}");
    }
}
