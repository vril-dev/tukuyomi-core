use std::path::PathBuf;

use serde_json::{Value, json};

use tukuyomi_kernel::Engine;

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

/// The kernel values of a file whose `kernel` object has these keys besides the ones every file has.
fn kernel_with(extra: Value) -> KernelSettings {
    let mut object = json!({
        "inspector": "/opt/tukuyomi/inspector", "tmp_root": "/var/lib/tukuyomi/tmp", "gomaxprocs": 2,
        "gomemlimit": 1073741824u64, "slots": 4, "wait_queue": 16, "records": 20, "discard_limit": 4,
        "tick_ms": 100, "hello_wait_ms": 5000, "frame_io_ms": 1000, "verdict_wait_ms": 2000,
        "wait_deadline_ms": 3000, "closed_wait_ms": 2000, "stop_after_ms": 2000, "drain_wait_ms": 1000,
        "exit_wait_ms": 1000, "kill_grace_ms": 1000, "restarts": 3, "restart_window_ms": 60000,
    });
    for (key, value) in extra.as_object().unwrap() {
        object[key] = value.clone();
    }
    let raw = serde_json::from_value(object).unwrap();
    super::super::kernel::settings(raw, std::path::Path::new("/var/lib/tukuyomi/rules")).unwrap()
}

/// The kernel values of a file that has an inspector for ModSecurity too.
fn kernel_modsecurity(extra: Value) -> KernelSettings {
    let mut extra = extra;
    extra["engines"] = json!({"modsecurity": {"inspector": "/opt/tukuyomi/inspector-modsecurity"}});
    kernel_with(extra)
}

fn load_with(value: Value, kernel: &KernelSettings) -> Result<ForwardSettings, ConfigError> {
    let raw: RawForward = serde_json::from_value(value).map_err(|e| super::super::refusal(&e))?;
    check(raw, &[], 1 << 20, kernel)
}

fn load(value: Value) -> Result<ForwardSettings, ConfigError> {
    load_with(value, &kernel_with(json!({})))
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
            authorities: Authorities::File(PathBuf::from("/etc/ca.pem")),
            server_name: None,
        })
    );
    let named = json!({"ca_file": "/etc/ca.pem", "server_name": "api.test"});
    assert_eq!(
        with_tls("192.0.2.1:443", named).unwrap().groups[0].tls,
        by(Settings {
            authorities: Authorities::File(PathBuf::from("/etc/ca.pem")),
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

/// The groups `a` and `b`, with these two objects.
fn two_groups(a: Value, b: Value) -> Value {
    let mut object = forward(a);
    object["upstreams"] = json!({"a": object["upstreams"]["g"].clone(), "b": b});
    object["default_upstream"] = json!("a");
    object
}

#[test]
fn a_group_has_the_engine_it_names_or_the_default_one() {
    let group = |engine: Value| {
        let mut group = json!({"servers": [server("192.0.2.1:80")]});
        if !engine.is_null() {
            group["engine"] = engine;
        }
        forward(group)
    };
    let engine_of = |loaded: ForwardSettings| loaded.groups[0].engine;
    let kernel = kernel_modsecurity(json!({}));
    let named = |engine: &str| engine_of(load_with(group(json!(engine)), &kernel).unwrap());
    assert_eq!(named("coraza"), Engine::Coraza);
    assert_eq!(named("modsecurity"), Engine::ModSecurity);
    // A group that names none has the default engine of the file.
    assert_eq!(
        engine_of(load_with(group(Value::Null), &kernel).unwrap()),
        Engine::Coraza
    );
    let by_default = kernel_modsecurity(json!({"default_engine": "modsecurity"}));
    assert_eq!(
        engine_of(load_with(group(Value::Null), &by_default).unwrap()),
        Engine::ModSecurity
    );
    assert_eq!(
        engine_of(load_with(group(json!("coraza")), &by_default).unwrap()),
        Engine::Coraza
    );
    // The name is the lowercase one, exactly, and a value that is not text is the wrong type.
    let bad = "an upstream engine is not coraza or modsecurity";
    for name in ["Coraza", ""] {
        assert_eq!(
            refusal(load_with(group(json!(name)), &kernel)),
            bad,
            "{name:?}"
        );
    }
    let wrong = "configuration has a value of the wrong type";
    for value in [json!(1), json!(["coraza"])] {
        assert_eq!(refusal(load_with(group(value), &kernel)), wrong);
    }
}

#[test]
fn the_engine_of_a_group_needs_an_inspector_in_the_file() {
    let group =
        |engine: &str| forward(json!({"servers": [server("192.0.2.1:80")], "engine": engine}));
    let missing = "kernel.engines has no inspector for the engine of an upstream";
    assert_eq!(refusal(load(group("modsecurity"))), missing);
    assert!(load(group("coraza")).is_ok());
    assert!(load_with(group("modsecurity"), &kernel_modsecurity(json!({}))).is_ok());
}

#[test]
fn two_groups_with_a_server_at_the_same_address_have_the_same_engine() {
    let kernel = kernel_modsecurity(json!({}));
    let one = |address: &str| json!({"servers": [server(address)], "engine": "coraza"});
    let other = |servers: Vec<Value>, engine: &str| json!({"servers": servers, "engine": engine});
    let apart = "two upstreams with a server at the same address have different engines";
    let load = |value: Value| load_with(value, &kernel);
    // The same address, written as a name or as an IP literal, is refused with another engine and taken with the
    // same one; a different address, or the same name at another port, is taken with any.
    assert_eq!(
        refusal(load(two_groups(
            one("192.0.2.1:80"),
            other(vec![server("192.0.2.1:80")], "modsecurity")
        ))),
        apart
    );
    assert!(
        load(two_groups(
            one("192.0.2.1:80"),
            other(vec![server("192.0.2.1:80")], "coraza")
        ))
        .is_ok()
    );
    assert!(
        load(two_groups(
            one("192.0.2.1:80"),
            other(vec![server("192.0.2.1:81")], "modsecurity")
        ))
        .is_ok()
    );
    assert_eq!(
        refusal(load(two_groups(
            one("app.test:80"),
            other(vec![server("app.test:80")], "modsecurity")
        ))),
        apart
    );
    // One server in common among several is enough, and an IPv4 address is the same address as its IPv6 form.
    assert_eq!(
        refusal(load(two_groups(
            one("192.0.2.1:80"),
            other(
                vec![server("192.0.2.9:80"), server("192.0.2.1:80")],
                "modsecurity"
            )
        ))),
        apart
    );
    assert_eq!(
        refusal(load(two_groups(
            one("192.0.2.1:80"),
            other(vec![server("[::ffff:192.0.2.1]:80")], "modsecurity")
        ))),
        apart
    );
    // A group that names no engine has the default one, and the check is made on that.
    let by_default = |default: &str| {
        load_with(
            two_groups(
                json!({"servers": [server("192.0.2.1:80")]}),
                other(vec![server("192.0.2.1:80")], "modsecurity"),
            ),
            &kernel_modsecurity(json!({"default_engine": default})),
        )
    };
    assert_eq!(refusal(by_default("coraza")), apart);
    assert!(by_default("modsecurity").is_ok());
}

/// The `forward` object with the group `g` and these routes.
fn with_routes(routes: Value) -> Value {
    let mut object = forward(json!({"servers": [server("192.0.2.1:80")]}));
    object["routes"] = routes;
    object
}

/// The `forward` object with the group `g` and one route to it that has these keys besides `upstream`.
fn with_route(keys: Value) -> Value {
    let mut route = json!({"upstream": "g"});
    for (key, value) in keys.as_object().unwrap() {
        route[key] = value.clone();
    }
    with_routes(json!([route]))
}

#[test]
fn a_route_may_have_a_path_regex_in_place_of_its_path_and_a_priority() {
    let loaded = load(with_routes(json!([
        {"path_regex": "^/api/v[0-9]+/", "upstream": "g"},
        {"path": "/api/", "priority": -5, "upstream": "g"},
        {"path": "/", "priority": 1000, "upstream": "g"},
    ])))
    .unwrap();
    let rules: Vec<_> = loaded
        .routes
        .rules()
        .map(|rule| (rule.path(), rule.path_regex(), rule.priority()))
        .collect();
    assert_eq!(
        rules,
        [
            (None, Some("^/api/v[0-9]+/"), 0),
            (Some("/api/"), None, -5),
            (Some("/"), None, 1000)
        ]
    );
    // Both of them is a refusal, and so is a value that is not text or not a whole number, `null` included.
    let both = json!({"path": "/a", "path_regex": "^/a"});
    assert_eq!(
        refusal(load(with_route(both))),
        "a route has both a path and a path regex"
    );
    let wrong = "configuration has a value of the wrong type";
    for bad in [
        json!({"path_regex": 5}),
        json!({"path_regex": null}),
        json!({"priority": 1.5}),
        json!({"priority": "1"}),
        json!({"priority": null}),
    ] {
        assert_eq!(refusal(load(with_route(bad.clone()))), wrong, "{bad}");
    }
}

#[test]
fn a_route_with_a_path_regex_has_no_access_list_and_no_path_to_rewrite_and_at_most_32_have_one() {
    let list = json!({"deny_cidrs": ["10.0.0.0/8"]});
    let regex = json!({"path_regex": "^/a"});
    let with = |key: &str, value: Value| {
        let mut keys = regex.clone();
        keys[key] = value;
        load(with_route(keys))
    };
    assert_eq!(
        refusal(with("access", list.clone())),
        "a route with a path regex has an access list"
    );
    // A list that turns nobody away is no list, as for the rule on the port of a host.
    assert!(with("access", json!({"allow_cidrs": []})).is_ok());
    assert_eq!(
        refusal(with("rewrite", json!({"path": "/v2/"}))),
        "a rewrite path is set on a route with a path regex"
    );
    assert!(with("rewrite", json!({"host": "inner.test"})).is_ok());
    // The port of a host is refused when a route has an access list, in a route with a path regex too.
    let ported = with_routes(json!([
        {"host": "h.test:8080", "path_regex": "^/a", "upstream": "g"},
        {"path": "/p/", "upstream": "g", "access": list},
    ]));
    assert_eq!(
        refusal(load(ported)),
        "a route host has a port while a route has an access list"
    );
    // At most 32 routes have a path regex; the routes with a path are not counted.
    let regexes = |n: usize| {
        let mut routes: Vec<Value> = (0..n)
            .map(|i| json!({"path_regex": format!("^/r{i}$"), "upstream": "g"}))
            .collect();
        routes.push(json!({"path": "/p/", "upstream": "g"}));
        with_routes(Value::Array(routes))
    };
    assert!(load(regexes(32)).is_ok());
    assert_eq!(
        refusal(load(regexes(33))),
        "routes has more than 32 entries with a path regex"
    );
}
