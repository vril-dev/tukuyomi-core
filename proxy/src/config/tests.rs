use super::*;
use crate::forward::client_ip::{Access, Country};
use crate::policy::mmdb::tests::{Record, database, database_of};
use serde_json::Value;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::sync::atomic::{AtomicU32, Ordering};

const BASE: &str = r#"{"proxy":{"listeners":[{"address":"127.0.0.1:8080"}],"max_conns":1024,"max_head_bytes":8192,"max_body":1048576,"inspect_body":1048576,"max_body_wire":2097152,"max_buffered_bytes":8388608,"upstream_max_headers":100,"upstream_max_head_bytes":16384,"upstream_head_wire":65536,"drive_slice_ms":50,"ready_wait_ms":10000,"head_read_ms":10000,"body_read_ms":30000,"inspect_wait_ms":30000,"upstream_connect_ms":5000,"upstream_header_ms":30000,"request_total_ms":60000,"response_idle_ms":60000,"conn_total_ms":120000,"stop_inspect_ms":5000,"stop_wait_ms":10000,"keepalive_timeout_ms":75000,"keepalive_requests":1000,"keepalive_time_ms":60000,"lingering_time_ms":30000,"lingering_timeout_ms":5000,"lingering_bytes":262144,"trusted_proxies":[],"upstream_keepalive":32,"upstream_keepalive_timeout_ms":60000,"upstream_keepalive_requests":1000},"forward":{"resolve_timeout_ms":30000,"upstreams":{"main":{"servers":[{"address":"127.0.0.1:9000","weight":1,"max_fails":1,"fail_timeout_ms":10000,"backup":false}]},"api":{"servers":[{"address":"127.0.0.1:9001","weight":3,"max_fails":2,"fail_timeout_ms":5000,"backup":false},{"address":"127.0.0.1:9002","weight":1,"max_fails":0,"fail_timeout_ms":5000,"backup":true}]}},"routes":[{"host":"api.example.test","path":"/v1/","upstream":"api"}],"default_upstream":"main"},"kernel":{"inspector":"/opt/tukuyomi/inspector","tmp_root":"/var/lib/tukuyomi/tmp","gomaxprocs":2,"gomemlimit":1073741824,"slots":4,"wait_queue":16,"records":20,"discard_limit":4,"tick_ms":100,"hello_wait_ms":5000,"frame_io_ms":1000,"verdict_wait_ms":2000,"wait_deadline_ms":3000,"closed_wait_ms":2000,"stop_after_ms":2000,"drain_wait_ms":1000,"exit_wait_ms":1000,"kill_grace_ms":1000,"restarts":3,"restart_window_ms":60000},"rules":{"store":{"kind":"file","dir":"/var/lib/tukuyomi/rules"}}}"#;

/// Marks a value that must never appear in an error sentence.
const MARK: &str = "qqmark";

/// Where in the document (a JSON pointer to an object), the key, and the new value.
type Edit = (&'static str, &'static str, Value);

fn p(key: &'static str, value: impl Into<Value>) -> Edit {
    ("/proxy", key, value.into())
}

fn k(key: &'static str, value: impl Into<Value>) -> Edit {
    ("/kernel", key, value.into())
}

fn s(key: &'static str, value: impl Into<Value>) -> Edit {
    ("/rules/store", key, value.into())
}

fn f(key: &'static str, value: impl Into<Value>) -> Edit {
    ("/forward", key, value.into())
}

/// A key of the first server of the group `api`.
fn sv(key: &'static str, value: impl Into<Value>) -> Edit {
    ("/forward/upstreams/api/servers/0", key, value.into())
}

/// The `listeners` of the `proxy` object.
fn listeners(value: Value) -> Edit {
    p("listeners", value)
}

/// One plain listener at `address`.
fn at(address: &str) -> Edit {
    listeners(serde_json::json!([{ "address": address }]))
}

/// A listener at `address` that ends TLS with one certificate for `hosts`.
fn tls_listener(address: &str, hosts: &[&str]) -> Value {
    serde_json::json!({
        "address": address,
        "tls": {
            "min_version": "1.2",
            "certificates": [{
                "cert_file": "/etc/tukuyomi/tls/a.pem",
                "key_file": "/etc/tukuyomi/tls/a.key",
                "hosts": hosts,
            }],
        },
    })
}

fn tls_listeners(address: &str, hosts: &[&str]) -> Value {
    serde_json::json!([tls_listener(address, hosts)])
}

fn base() -> Value {
    serde_json::from_str(BASE).unwrap()
}

fn doc(edits: &[Edit]) -> Vec<u8> {
    let mut value = base();
    for (at, key, new) in edits {
        value.pointer_mut(at).unwrap()[*key] = new.clone();
    }
    value.to_string().into_bytes()
}

fn pass(edits: &[Edit]) {
    let result = parse(&doc(edits));
    assert!(result.is_ok(), "{edits:?}: {:?}", result.err());
}

fn refuse(edits: &[Edit], sentence: &str) {
    let result = parse(&doc(edits));
    assert_eq!(
        result.as_ref().err().map(|e| e.0),
        Some(sentence),
        "{edits:?}"
    );
}

fn refuse_text(text: &str, sentence: &str) {
    assert_eq!(
        parse(text.as_bytes()).err().map(|e| e.0),
        Some(sentence),
        "{text:.60}"
    );
}

#[test]
fn the_base_document_loads_with_every_value_converted() {
    let loaded = parse(BASE.as_bytes()).unwrap();
    let (proxy, kernel) = (&loaded.proxy, &loaded.kernel.0);
    assert_eq!(
        proxy.listeners,
        [ListenerConfig {
            address: "127.0.0.1:8080".parse().unwrap(),
            kind: ListenerKind::Plain,
        }]
    );
    assert_eq!(proxy.max_buffered_bytes, 8 << 20);
    assert_eq!(proxy.drive_slice, Duration::from_millis(50));
    assert_eq!(proxy.stop_wait, Duration::from_millis(10_000));
    assert_eq!(proxy.keepalive_timeout, Duration::from_millis(75_000));
    assert_eq!(proxy.keepalive_requests, 1000);
    assert_eq!(proxy.keepalive_time, Duration::from_millis(60_000));
    assert_eq!(proxy.lingering_time, Duration::from_millis(30_000));
    assert_eq!(proxy.lingering_timeout, Duration::from_millis(5_000));
    assert_eq!(proxy.lingering_bytes, 262_144);
    assert!(proxy.trusted_proxies.is_empty());
    assert_eq!(proxy.upstream_keepalive, 32);
    assert_eq!(
        proxy.upstream_keepalive_timeout,
        Duration::from_millis(60_000)
    );
    assert_eq!(proxy.upstream_keepalive_requests, 1000);
    let forward = &loaded.forward;
    let names: Vec<&str> = forward.groups.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(names, ["main", "api"]);
    assert_eq!(forward.default, Some(0));
    assert_eq!(
        forward.groups[1].servers,
        [
            ServerConfig {
                address: Address::Literal("127.0.0.1:9001".parse().unwrap()),
                weight: 3,
                max_fails: 2,
                fail_timeout: Duration::from_millis(5000),
                backup: false,
            },
            ServerConfig {
                address: Address::Literal("127.0.0.1:9002".parse().unwrap()),
                weight: 1,
                max_fails: 0,
                fail_timeout: Duration::from_millis(5000),
                backup: true,
            },
        ]
    );
    // The route holds for its host in any case and with any port, and for paths below its path.
    let group = |host: &[u8], target: &[u8]| {
        forward
            .routes
            .find(Some(host), target)
            .map(|route| route.group)
    };
    assert_eq!(group(b"API.example.test:80", b"/v1/x"), Some(1));
    assert_eq!(group(b"api.example.test", b"/v2/x"), None);
    assert_eq!(group(b"other.test", b"/v1/x"), None);
    assert_eq!(forward.resolve_timeout, Duration::from_millis(30_000));
    assert_eq!(kernel.inspector, PathBuf::from("/opt/tukuyomi/inspector"));
    // The directory and the fingerprint of a generation are not in the file: the check ran with placeholders.
    assert_eq!(
        kernel.rules,
        PathBuf::from("/var/lib/tukuyomi/rules/generations")
    );
    assert_eq!(kernel.rules_sha256, [0; 32]);
    assert_eq!(kernel.tick, Duration::from_millis(100));
    assert_eq!((kernel.discard_limit, kernel.restarts), (4, 3));
    assert_eq!(
        loaded.store,
        StoreConfig::File {
            dir: PathBuf::from("/var/lib/tukuyomi/rules")
        }
    );
}

#[test]
fn the_file_is_at_most_256_kib_and_utf8() {
    let at_limit = format!("{BASE}{}", " ".repeat(262_144 - BASE.len()));
    assert!(parse(at_limit.as_bytes()).is_ok());
    refuse_text(
        &format!("{at_limit} "),
        "configuration file is over 256 KiB",
    );

    let mut bytes = BASE
        .replace("/opt/tukuyomi/inspector", "/opt/qqmark")
        .into_bytes();
    let at = bytes.windows(6).position(|w| w == MARK.as_bytes()).unwrap();
    bytes[at] = 0xff;
    assert_eq!(
        parse(&bytes).err(),
        Some(ConfigError("configuration file is not UTF-8"))
    );
}

#[test]
fn broken_json_is_refused_with_one_sentence() {
    let sentence = "configuration is not valid JSON";
    for text in ["", "{", "{'proxy':{}}"] {
        refuse_text(text, sentence);
    }
    refuse_text(&format!("{BASE} x"), sentence);
    refuse_text(&BASE[..BASE.len() - 1], sentence);
}

#[test]
fn a_missing_key_is_refused_in_every_object() {
    let sentence = "configuration has a missing key";
    refuse_text("{}", sentence);
    for (parent, name) in [
        ("", "rules"),
        ("/rules", "store"),
        ("/proxy", "max_conns"),
        ("/forward", "default_upstream"),
        ("/forward", "resolve_timeout_ms"),
        ("/forward/upstreams/api", "servers"),
        ("/forward/upstreams/api/servers/0", "weight"),
        ("/forward/routes/0", "upstream"),
        ("/kernel", "tick_ms"),
        ("/rules/store", "dir"),
    ] {
        let mut value = base();
        let object = if parent.is_empty() {
            &mut value
        } else {
            value.pointer_mut(parent).unwrap()
        };
        object.as_object_mut().unwrap().remove(name);
        refuse_text(&value.to_string(), sentence);
    }
}

#[test]
fn an_unknown_key_is_refused_in_every_object() {
    let sentence = "configuration has an unknown key";
    let mut value = base();
    value["qqmark"] = Value::from(1);
    refuse_text(&value.to_string(), sentence);
    refuse(&[p("qqmark", 1)], sentence);
    refuse(&[f("qqmark", 1)], sentence);
    refuse(&[sv("qqmark", 1)], sentence);
    refuse(&[k("qqmark", 1)], sentence);
    // The kernel object has no rules path and no fingerprint: they come from the rules store.
    refuse(&[k("rules", "/etc/tukuyomi/rules")], sentence);
    refuse(&[k("rules_sha256", "0123456789abcdef".repeat(4))], sentence);
}

#[test]
fn a_repeated_key_is_refused_even_with_the_same_value() {
    refuse_text(
        &BASE.replacen("\"proxy\":{", "\"proxy\":{\"max_conns\":1024,", 1),
        "configuration has a repeated key",
    );
}

#[test]
fn a_value_of_the_wrong_type_is_refused_for_every_key() {
    let sentence = "configuration has a value of the wrong type";
    for (path, key, wrong) in [
        ("/proxy", "listeners", Value::from(5)),
        ("/proxy", "max_conns", Value::from("5")),
        ("/forward", "default_upstream", Value::from(5)),
        ("/forward", "resolve_timeout_ms", Value::from("5")),
        (
            "/forward/upstreams/api/servers/0",
            "weight",
            Value::from("1"),
        ),
        ("/forward/upstreams/api/servers/0", "backup", Value::from(0)),
        (
            "/forward/upstreams/api/servers/0",
            "weight",
            Value::from(1.5),
        ),
        ("/kernel", "tick_ms", Value::Null),
        ("/rules/store", "dir", Value::from(true)),
    ] {
        let mut value = base();
        value.pointer_mut(path).unwrap()[key] = wrong;
        refuse_text(&value.to_string(), sentence);
    }
    // A number of the right kind but outside the type, a fraction, a negative count.
    refuse(&[k("gomaxprocs", 65536)], sentence);
    refuse(&[p("max_conns", 5.0)], sentence);
    refuse(&[p("max_conns", -1)], sentence);
    pass(&[k("gomaxprocs", 65535)]);
}

#[test]
fn an_array_never_stands_in_for_an_object() {
    let sentence = "configuration has a value of the wrong type";
    for path in ["/proxy", "/rules/store"] {
        let mut positional = base();
        let values: Vec<Value> = base()
            .pointer(path)
            .unwrap()
            .as_object()
            .unwrap()
            .values()
            .cloned()
            .collect();
        *positional.pointer_mut(path).unwrap() = Value::Array(values);
        refuse_text(&positional.to_string(), sentence);
    }
    refuse_text("null", sentence);
    // Neither does an array stand in for a server, a route, or the object of the groups.
    let mut value = base();
    value["forward"]["upstreams"]["api"]["servers"][0] =
        serde_json::json!(["127.0.0.1:9001", 3, 2, 5000, false]);
    refuse_text(&value.to_string(), sentence);
    let mut value = base();
    value["forward"]["routes"][0] = serde_json::json!(["api.example.test", "/v1/", "api"]);
    refuse_text(&value.to_string(), sentence);
    let mut value = base();
    value["forward"]["upstreams"] = serde_json::json!([]);
    refuse_text(&value.to_string(), sentence);
}

#[test]
fn errors_never_carry_a_value_or_a_key_from_the_file() {
    let mut cases: Vec<Vec<u8>> = vec![
        doc(&[listeners(serde_json::json!([{"address": MARK}]))]),
        doc(&[listeners(
            serde_json::json!([{"address": "127.0.0.1:1", "redirect": {"https_port": MARK}}]),
        )]),
        doc(&[listeners(tls_listeners("127.0.0.1:1", &["qqmark!"]))]),
        doc(&[p("max_conns", MARK)]),
        doc(&[p(MARK, 1)]),
        doc(&[k("inspector", MARK)]),
        doc(&[k("tmp_root", MARK)]),
        doc(&[f("default_upstream", MARK)]),
        doc(&[sv("address", MARK)]),
        with_route(serde_json::json!({"upstream": "api", "access": {"deny_cidrs": [MARK]}})),
        with_route(serde_json::json!({"upstream": "api", "rewrite": {"host": "qqmark!"}})),
        BASE.replace("\"api\"", "\"qqmark!\"").into_bytes(),
        format!("{BASE}{MARK}").into_bytes(),
        format!("{{\"{MARK}\":1,\"{MARK}\":2}}").into_bytes(),
    ];
    let mut not_utf8 = MARK.as_bytes().to_vec();
    not_utf8.push(0xff);
    cases.push(not_utf8);
    for case in &cases {
        let e = parse(case).expect_err("every case is refused");
        assert!(!e.0.contains(MARK), "{}", e.0);
        assert!(e.0.is_ascii() && e.0.len() < 80, "{}", e.0);
    }
}

#[test]
fn addresses_are_ip_literals_with_a_port_and_differ() {
    let bad = "a listener address is not an IP address and port";
    for text in ["localhost:8080", "127.0.0.1", "127.0.0.1:65536"] {
        refuse(&[at(text)], bad);
    }
    pass(&[at("127.0.0.1:65535")]);
    pass(&[at("[::1]:8080")]);
    refuse(&[at("127.0.0.1:0")], "a listener port is 0");
    refuse(
        &[sv("address", "127.0.0.1")],
        "a server address is not an IP address and port, or a name and port",
    );
    refuse(&[sv("address", "127.0.0.1:0")], "a server port is 0");

    let same = "a listener and a server are the same address";
    refuse(&[sv("address", "127.0.0.1:8080")], same);
    refuse(&[sv("address", "[::ffff:127.0.0.1]:8080")], same);
    pass(&[sv("address", "127.0.0.1:8081")]);
    pass(&[sv("address", "[::1]:8080")]);

    // An unspecified address is every address of the host, so a server at a loopback address and the port is the
    // proxy itself; another address, and another port, are not.
    for listen in ["0.0.0.0:8080", "[::]:8080"] {
        for server in ["127.0.0.1:8080", "127.0.0.2:8080", "[::1]:8080"] {
            refuse(&[at(listen), sv("address", server)], same);
        }
        pass(&[at(listen), sv("address", "127.0.0.1:8081")]);
        pass(&[at(listen), sv("address", "192.0.2.1:8080")]);
    }
    // A server may not be any of the listeners.
    let two = listeners(
        serde_json::json!([{"address": "127.0.0.1:8080"}, {"address": "127.0.0.1:8081"}]),
    );
    refuse(&[two.clone(), sv("address", "127.0.0.1:8081")], same);
    pass(&[two, sv("address", "127.0.0.1:8082")]);
}

#[test]
fn listeners_are_one_to_eight_and_differ() {
    let count = |n: u16| {
        let list: Vec<Value> = (0..n)
            .map(|i| serde_json::json!({ "address": format!("127.0.0.1:{}", 7000 + i) }))
            .collect();
        listeners(Value::Array(list))
    };
    pass(&[count(1)]);
    pass(&[count(8)]);
    let sentence = "listeners has no listener or more than 8";
    refuse(&[count(0)], sentence);
    refuse(&[count(9)], sentence);
    let same = "two listeners have the same address, or one is an unspecified address at the port of the other";
    let pair =
        |a: &str, b: &str| listeners(serde_json::json!([{ "address": a }, { "address": b }]));
    refuse(&[pair("127.0.0.1:7000", "127.0.0.1:7000")], same);
    refuse(&[pair("127.0.0.1:7000", "[::ffff:127.0.0.1]:7000")], same);
    refuse(&[pair("0.0.0.0:7000", "127.0.0.1:7000")], same);
    refuse(&[pair("[::1]:7000", "[::]:7000")], same);
    pass(&[pair("127.0.0.1:7000", "127.0.0.1:7001")]);
    pass(&[pair("127.0.0.1:7000", "127.0.0.2:7000")]);
}

#[test]
fn a_listener_is_plain_tls_or_a_redirect_and_a_redirect_needs_tls() {
    let tls = tls_listener("127.0.0.1:9443", &["a.example"]);
    let redirect = |port: u64| serde_json::json!({"address": "127.0.0.1:9080", "redirect": {"https_port": port}});
    pass(&[listeners(Value::Array(vec![redirect(443), tls.clone()]))]);
    let both = serde_json::json!({
        "address": "127.0.0.1:9080",
        "redirect": {"https_port": 443},
        "tls": tls["tls"].clone(),
    });
    refuse(
        &[listeners(Value::Array(vec![both, tls.clone()]))],
        "a listener has both tls and redirect",
    );
    // A redirect needs a listener with tls to point at, and some listener has to serve requests.
    refuse(
        &[listeners(Value::Array(vec![redirect(443)]))],
        "no listener is plain or has tls",
    );
    refuse(
        &[listeners(serde_json::json!([
            {"address": "127.0.0.1:9000"},
            redirect(443),
        ]))],
        "a redirect listener needs a listener with tls",
    );
    for port in [0, 65536] {
        refuse(
            &[listeners(Value::Array(vec![redirect(port), tls.clone()]))],
            "a redirect https_port is not 1 to 65535",
        );
    }
    pass(&[listeners(Value::Array(vec![redirect(65535), tls]))]);
}

#[test]
fn the_tls_settings_are_checked_in_form_only() {
    let one = |hosts: &[&str]| listeners(tls_listeners("127.0.0.1:9443", hosts));
    pass(&[one(&["a.example", "*.a.example", "localhost"])]);
    let host = "a tls host is not a name, or * and a name";
    for bad in [
        "192.0.2.1",
        "[::1]",
        "127.1",
        "*",
        "*.",
        "a.*.example",
        "*a.example",
        "**.example",
        "A.example",
        "a_b.example",
        "a..example",
        "a.example.",
        "a.example:443",
    ] {
        refuse(&[one(&[bad])], host);
    }
    refuse(
        &[one(&["a.example", "a.example"])],
        "a tls host is written twice in a listener",
    );
    refuse(&[one(&[])], "a certificate has no host or more than 64");
    let many: Vec<String> = (0..65).map(|i| format!("h{i}.example")).collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    refuse(&[one(&many)], "a certificate has no host or more than 64");
    pass(&[one(&many[..64])]);
    // The same host may be written in two listeners.
    pass(&[listeners(serde_json::json!([
        tls_listener("127.0.0.1:9443", &["a.example"]),
        tls_listener("127.0.0.1:9444", &["a.example"]),
    ]))]);

    let with = |change: &dyn Fn(&mut Value)| {
        let mut list = tls_listeners("127.0.0.1:9443", &["a.example"]);
        change(&mut list[0]["tls"]);
        listeners(list)
    };
    let min = "tls min_version is not 1.2 or 1.3";
    pass(&[with(&|tls| tls["min_version"] = Value::from("1.3"))]);
    for bad in ["1.1", "1.0", "TLS1.2", "1.2 ", ""] {
        refuse(&[with(&|tls| tls["min_version"] = Value::from(bad))], min);
    }
    let certificate = |n: usize| {
        with(&|tls| {
            let one = tls["certificates"][0].clone();
            let mut all = Vec::new();
            for i in 0..n {
                let mut next = one.clone();
                next["hosts"] = serde_json::json!([format!("c{i}.example")]);
                all.push(next);
            }
            tls["certificates"] = Value::Array(all);
        })
    };
    pass(&[certificate(16)]);
    let count = "tls has no certificate or more than 16";
    refuse(&[certificate(17)], count);
    refuse(&[certificate(0)], count);
    // The files are absolute clean paths of at most 3840 bytes.
    let path = "a tls cert_file or key_file is not an absolute clean path of at most 3840 bytes";
    let long = format!("/{}", "a".repeat(3839));
    pass(&[with(&|tls| {
        tls["certificates"][0]["key_file"] = Value::from(long.clone())
    })]);
    for bad in [
        "a.pem",
        "/etc/../a.pem",
        "/etc//a.pem",
        "/etc/a.pem/",
        "",
        &format!("/{}", "a".repeat(3840)),
    ] {
        refuse(
            &[with(&|tls| {
                tls["certificates"][0]["cert_file"] = Value::from(bad)
            })],
            path,
        );
        refuse(
            &[with(&|tls| {
                tls["certificates"][0]["key_file"] = Value::from(bad)
            })],
            path,
        );
    }
}

/// The base document with these routes.
fn with_routes(routes: Vec<Value>) -> Vec<u8> {
    doc(&[f("routes", Value::Array(routes))])
}

/// A route for the group `api` at this host, with this `access` object.
fn route_at(host: &str, access: Value) -> Value {
    serde_json::json!({"host": host, "upstream": "api", "access": access})
}

#[test]
fn when_a_route_has_an_access_list_no_route_has_a_port_in_its_host() {
    let sentence = Some("a route host has a port while a route has an access list");
    let list = serde_json::json!({"deny_cidrs": ["10.0.0.0/8"]});
    let allow = serde_json::json!({"allow_cidrs": ["10.0.0.0/8"]});
    // A port in the host of the route that has the list, or of another route, in either order.
    for host in ["h.test:8080", "*.h.test:80"] {
        for access in [list.clone(), allow.clone()] {
            let own = vec![route_at(host, access.clone())];
            assert_eq!(refusal_of(&with_routes(own)), sentence, "{host}");
            let other = route_at(host, serde_json::json!({}));
            let guarded = route_at("g.test", access.clone());
            let both = vec![other.clone(), guarded.clone()];
            assert_eq!(refusal_of(&with_routes(both)), sentence, "{host}");
            let both = vec![guarded, other];
            assert_eq!(refusal_of(&with_routes(both)), sentence, "{host}");
        }
    }
    // A route without a path or a host, and a route with a port and no route with a list, are loaded; so is a port
    // with lists that turn nobody away.
    let bare = serde_json::json!({"upstream": "api", "access": list});
    let both = vec![bare, route_at("g.test", serde_json::json!({}))];
    assert_eq!(refusal_of(&with_routes(both)), None);
    let ported = route_at("h.test:8080", serde_json::json!({}));
    assert_eq!(refusal_of(&with_routes(vec![ported.clone()])), None);
    let empty = route_at("g.test", serde_json::json!({"allow_cidrs": []}));
    assert_eq!(refusal_of(&with_routes(vec![ported, empty])), None);
}

#[test]
fn the_path_of_a_route_with_an_access_list_is_in_canonical_form() {
    let route = |path: &str, access: Value| {
        with_route(serde_json::json!({"path": path, "upstream": "api", "access": access}))
    };
    let list = serde_json::json!({"deny_cidrs": ["10.0.0.0/8"]});
    let sentence = Some(
        "a route with an access list has an escape in its path that is lowercase or is for a byte that needs no escape",
    );
    // Lowercase digits, and the escape of a byte that a path holds as it is.
    for path in ["/%e3%81%82/", "/%61dmin/", "/a%7E/", "/a/%2c"] {
        assert_eq!(refusal_of(&route(path, list.clone())), sentence, "{path}");
        // The same path loads for a route that has no list, or only an empty one.
        assert_eq!(
            refusal_of(&route(path, serde_json::json!({}))),
            None,
            "{path}"
        );
    }
    for path in ["/%E3%81%82/", "/a%20b/", "/admin/", "/a%7B"] {
        assert_eq!(refusal_of(&route(path, list.clone())), None, "{path}");
    }
}

#[test]
fn counts_and_sizes_are_inside_their_bounds() {
    let out = |key: &str| format!("{key} is out of range");
    // key, lowest passing value, highest passing value
    for (key, low, high) in [
        ("max_head_bytes", 1024, 32768),
        ("upstream_max_headers", 1, 1024),
        ("keepalive_requests", 1, 1_000_000),
        ("upstream_keepalive_requests", 1, 1_000_000),
        ("lingering_bytes", 1, 4 << 20),
    ] {
        pass(&[p(key, low)]);
        pass(&[p(key, high)]);
        refuse(&[p(key, low - 1)], &out(key));
        refuse(&[p(key, high + 1)], &out(key));
    }

    // upstream_keepalive: 0 (no connection is kept) to 1024.
    let key = "upstream_keepalive";
    pass(&[p(key, 0)]);
    pass(&[p(key, 1024)]);
    refuse(&[p(key, 1025)], &out(key));

    // max_conns: 1 to 65536. The lowest value needs a wait_queue of 1 (checked as a relation below).
    let key = "max_conns";
    refuse(&[p(key, 0)], &out(key));
    pass(&[p(key, 1), k("wait_queue", 1)]);
    pass(&[p(key, 65536)]);
    refuse(&[p(key, 65537)], &out(key));

    // max_body: 1 KiB to 4 GiB, which is far above the 1 MiB that the kernel inspects.
    let key = "max_body";
    refuse(&[p(key, 1023)], &out(key));
    pass(&[p(key, 1024), p("inspect_body", 1024)]);
    pass(&[p(key, 4u64 << 30), p("max_body_wire", 4u64 << 30)]);
    refuse(&[p(key, (4u64 << 30) + 1)], &out(key));

    // inspect_body: 1 KiB to the 1 MiB that the kernel takes, and not above max_body.
    let key = "inspect_body";
    refuse(&[p(key, 1023)], &out(key));
    pass(&[p(key, 1024)]);
    pass(&[p(key, 1u64 << 20)]);
    refuse(&[p(key, (1u64 << 20) + 1)], &out(key));
    refuse(
        &[p("max_body", 4096), p(key, 4097)],
        "inspect_body is above max_body",
    );
    pass(&[p("max_body", 4096), p(key, 4096)]);

    // max_body_wire: from max_body (1 MiB here) to 2 * max_body + 4 MiB.
    let key = "max_body_wire";
    refuse(&[p(key, (1u64 << 20) - 1)], &out(key));
    pass(&[p(key, 1u64 << 20)]);
    pass(&[p(key, 6u64 << 20)]);
    refuse(&[p(key, (6u64 << 20) + 1)], &out(key));

    // max_buffered_bytes: from 2 * inspect_body + 24 KiB (the fields) + 32 KiB (a piece of the rest of the body) to
    // 4 GiB.
    let key = "max_buffered_bytes";
    let least = 2 * (1u64 << 20) + 56 * 1024;
    refuse(&[p(key, least - 1)], &out(key));
    pass(&[p(key, least)]);
    pass(&[p(key, 4u64 << 30)]);
    refuse(&[p(key, (4u64 << 30) + 1)], &out(key));
    let least = 2 * 1024 + 56 * 1024;
    refuse(&[p("inspect_body", 1024), p(key, least - 1)], &out(key));
    pass(&[p("inspect_body", 1024), p(key, least)]);

    let key = "upstream_max_head_bytes";
    refuse(&[p(key, 8191)], &out(key));
    pass(&[p(key, 8192)]);
    pass(&[p(key, 1u64 << 20), p("upstream_head_wire", 2u64 << 20)]);
    refuse(&[p(key, (1u64 << 20) + 1)], &out(key));

    // upstream_head_wire: from 2 * max(8192, upstream_max_head_bytes) to 4 MiB.
    let key = "upstream_head_wire";
    refuse(&[p(key, 32767)], &out(key));
    pass(&[p(key, 32768)]);
    pass(&[p(key, 4u64 << 20)]);
    refuse(&[p(key, (4u64 << 20) + 1)], &out(key));
}

#[test]
fn every_proxy_time_is_between_1_ms_and_3600_s() {
    for key in [
        "drive_slice_ms",
        "ready_wait_ms",
        "head_read_ms",
        "body_read_ms",
        "inspect_wait_ms",
        "upstream_connect_ms",
        "upstream_header_ms",
        "request_total_ms",
        "response_idle_ms",
        "stop_inspect_ms",
        "stop_wait_ms",
        "keepalive_time_ms",
        "upstream_keepalive_timeout_ms",
        "lingering_time_ms",
        "lingering_timeout_ms",
    ] {
        let sentence = format!("{key} is out of range");
        refuse(&[p(key, 0)], &sentence);
        refuse(&[p(key, 3_600_001)], &sentence);
    }
    pass(&[
        p("drive_slice_ms", 1),
        p("response_idle_ms", 1),
        p("upstream_keepalive_timeout_ms", 1),
    ]);
    pass(&[
        p("ready_wait_ms", 3_600_000),
        p("inspect_wait_ms", 3_600_000),
        p("request_total_ms", 3_600_000),
        p("conn_total_ms", 7_200_000),
        p("stop_wait_ms", 3_600_000),
        p("keepalive_time_ms", 3_600_000),
        p("lingering_time_ms", 3_600_000),
    ]);
}

#[test]
fn trusted_proxies_is_a_list_of_networks_that_may_be_empty() {
    let bad = "trusted_proxies has an entry that is not a network";
    pass(&[p("trusted_proxies", Value::Array(Vec::new()))]);
    let loaded = parse(&doc(&[p(
        "trusted_proxies",
        serde_json::json!(["10.0.0.0/8", "2001:db8::/32", "192.0.2.7/32"]),
    )]))
    .unwrap();
    let nets = &loaded.proxy.trusted_proxies;
    assert_eq!(nets.len(), 3);
    assert!(nets[0].contains("10.9.9.9".parse().unwrap()));
    assert!(nets[1].contains("2001:db8::7".parse().unwrap()));
    assert!(!nets[2].contains("192.0.2.8".parse().unwrap()));
    // An entry is refused: one that is not a network, and one with a bit below the prefix.
    for entry in [
        Value::from("10.0.0.0"),
        Value::from("10.0.0.1/8"),
        Value::from("10.0.0.0/33"),
        Value::from("localhost/8"),
        Value::from(""),
        Value::from(MARK),
    ] {
        refuse(&[p("trusted_proxies", Value::Array(vec![entry]))], bad);
    }
    let wrong = "configuration has a value of the wrong type";
    refuse(
        &[p("trusted_proxies", Value::Array(vec![Value::from(8)]))],
        wrong,
    );
    refuse(&[p("trusted_proxies", "10.0.0.0/8")], wrong);
    refuse(&[p("trusted_proxies", Value::Null)], wrong);
    // The list has at most 256 networks.
    let many = |n: usize| Value::Array(vec![Value::from("10.0.0.0/8"); n]);
    pass(&[p("trusted_proxies", many(256))]);
    refuse(
        &[p("trusted_proxies", many(257))],
        "trusted_proxies has more than 256 entries",
    );
    // The refusal carries nothing from the file.
    let e = parse(&doc(&[p(
        "trusted_proxies",
        Value::Array(vec![MARK.into()]),
    )]))
    .unwrap_err();
    assert!(!e.0.contains(MARK));
}

#[test]
fn the_connection_time_is_between_1_ms_and_24_h() {
    let sentence = "conn_total_ms is out of range";
    refuse(&[p("conn_total_ms", 0)], sentence);
    pass(&[p("conn_total_ms", 86_400_000)]);
    refuse(&[p("conn_total_ms", 86_400_001)], sentence);
}

#[test]
fn the_keep_alive_wait_is_between_0_and_3600_s_and_0_means_no_keep_alive() {
    let sentence = "keepalive_timeout_ms is out of range";
    pass(&[p("keepalive_timeout_ms", 0)]);
    pass(&[
        p("keepalive_timeout_ms", 3_600_000),
        p("conn_total_ms", 3_600_000),
    ]);
    refuse(&[p("keepalive_timeout_ms", 3_600_001)], sentence);
    let loaded = parse(&doc(&[p("keepalive_timeout_ms", 0)])).unwrap();
    assert_eq!(loaded.proxy.keepalive_timeout, Duration::ZERO);
}

#[test]
fn a_server_is_checked_at_the_limits_of_its_numbers() {
    let weight = "a server weight is out of range";
    pass(&[sv("weight", 1)]);
    pass(&[sv("weight", 100)]);
    refuse(&[sv("weight", 0)], weight);
    refuse(&[sv("weight", 101)], weight);
    let fails = "a server max_fails is out of range";
    pass(&[sv("max_fails", 0)]);
    pass(&[sv("max_fails", 100)]);
    refuse(&[sv("max_fails", 101)], fails);
    let time = "a server fail_timeout_ms is out of range";
    pass(&[sv("fail_timeout_ms", 1)]);
    pass(&[sv("fail_timeout_ms", 3_600_000)]);
    refuse(&[sv("fail_timeout_ms", 0)], time);
    refuse(&[sv("fail_timeout_ms", 3_600_001)], time);
}

/// The base document with the group `api` called `name`, which the one route names.
fn named(name: &str) -> Vec<u8> {
    let mut value = base();
    let group = value["forward"]["upstreams"]
        .as_object_mut()
        .unwrap()
        .remove("api")
        .unwrap();
    value["forward"]["upstreams"][name] = group;
    value["forward"]["routes"][0]["upstream"] = Value::from(name);
    value.to_string().into_bytes()
}

#[test]
fn the_names_and_the_numbers_of_groups_servers_and_routes_are_bounded() {
    let name = "an upstream name is not 1 to 64 letters, digits, - and _";
    for good in ["a", "A_b-9", &"x".repeat(64)] {
        assert!(parse(&named(good)).is_ok(), "{good}");
    }
    for bad in ["", "a b", "a.b", "a/b", "é", &"x".repeat(65)] {
        assert_eq!(parse(&named(bad)).err().map(|e| e.0), Some(name), "{bad:?}");
    }

    // 64 groups pass, 65 do not, and none does not either.
    let groups = |n: usize| {
        let mut value = base();
        let one = value["forward"]["upstreams"]["main"].clone();
        let list: serde_json::Map<String, Value> =
            (0..n).map(|i| (format!("g{i}"), one.clone())).collect();
        value["forward"]["upstreams"] = Value::Object(list);
        value["forward"]["routes"] = Value::Array(Vec::new());
        value["forward"]["default_upstream"] = Value::from("");
        value.to_string().into_bytes()
    };
    let sentence = "upstreams has no group or more than 64 groups";
    assert!(parse(&groups(64)).is_ok());
    for n in [0, 65] {
        assert_eq!(parse(&groups(n)).err().map(|e| e.0), Some(sentence), "{n}");
    }

    let servers = |n: usize| {
        let mut value = base();
        let one = value["forward"]["upstreams"]["main"]["servers"][0].clone();
        value["forward"]["upstreams"]["main"]["servers"] = Value::Array(vec![one; n]);
        value.to_string().into_bytes()
    };
    let sentence = "an upstream has no server or more than 64 servers";
    assert!(parse(&servers(64)).is_ok());
    for n in [0, 65] {
        assert_eq!(parse(&servers(n)).err().map(|e| e.0), Some(sentence), "{n}");
    }

    let routes = |n: usize| {
        let routes: Vec<Value> = (0..n)
            .map(|i| serde_json::json!({"path": format!("/r{i}"), "upstream": "main"}))
            .collect();
        doc(&[f("routes", Value::Array(routes))])
    };
    assert!(parse(&routes(1024)).is_ok());
    assert_eq!(
        parse(&routes(1025)).err().map(|e| e.0),
        Some("routes has more than 1024 entries")
    );
}

#[test]
fn a_route_names_a_group_that_is_there_and_is_a_rule_that_holds() {
    let undefined = "a route names an upstream that is not defined";
    let route = |value: Value| f("routes", Value::Array(vec![value]));
    refuse(
        &[route(serde_json::json!({"upstream": "qqmark"}))],
        undefined,
    );
    refuse(
        &[f("default_upstream", "qqmark")],
        "default_upstream names an upstream that is not defined",
    );
    // No default group: a request that no route holds for gets 404.
    let loaded = parse(&doc(&[f("default_upstream", "")])).unwrap();
    assert_eq!(loaded.forward.default, None);

    // A route may have neither host nor path, a path of `/`, and a wildcard host.
    for good in [
        serde_json::json!({"upstream": "api"}),
        serde_json::json!({"path": "/", "upstream": "api"}),
        serde_json::json!({"host": "*.example.test:8080", "upstream": "api"}),
    ] {
        pass(&[route(good)]);
    }
    for (bad, sentence) in [
        (
            serde_json::json!({"path": "", "upstream": "api"}),
            "a route path is not 1 to 255 bytes",
        ),
        (
            serde_json::json!({"path": "/a/../b", "upstream": "api"}),
            "a route path can be read in more than one way",
        ),
        (
            serde_json::json!({"host": "Example.test", "upstream": "api"}),
            "a route host is malformed",
        ),
        (
            serde_json::json!({"host": "*", "upstream": "api"}),
            "a route host is malformed",
        ),
    ] {
        refuse(&[route(bad)], sentence);
    }
    let twice = serde_json::json!({"path": "/a/", "upstream": "api"});
    refuse(
        &[f("routes", Value::Array(vec![twice.clone(), twice]))],
        "two routes have the same host and path",
    );

    // A group name that is repeated is a repeated key.
    let repeated = BASE.replacen(
        "\"upstreams\":{",
        "\"upstreams\":{\"main\":{\"servers\":[]},",
        1,
    );
    refuse_text(&repeated, "configuration has a repeated key");
}

#[test]
fn the_kernel_object_is_converted_and_checked_by_the_kernel() {
    // The kernel's own sentences come through unchanged.
    refuse(
        &[k("inspector", "inspector")],
        "inspector path is not an absolute clean path",
    );
    refuse(&[k("slots", 5)], "slots is out of range");
    refuse(
        &[k("records", 19)],
        "records is below slots plus wait_queue",
    );
    pass(&[k("records", 20)]);
    // A kernel fault is reported before a relation that the same value would also break.
    refuse(
        &[k("tick_ms", 1001), p("drive_slice_ms", 2000)],
        "tick is above the longest tick",
    );
}

#[test]
fn each_relation_between_the_two_objects_has_a_boundary() {
    // drive_slice <= tick (100 ms)
    refuse(
        &[p("drive_slice_ms", 101)],
        "drive_slice_ms is above the kernel tick",
    );
    pass(&[p("drive_slice_ms", 100)]);
    // ready_wait >= hello_wait (5000 ms)
    refuse(
        &[p("ready_wait_ms", 4999)],
        "ready_wait_ms is below the kernel hello_wait",
    );
    pass(&[p("ready_wait_ms", 5000)]);
    // head_read, body_read <= request_total (60000 ms)
    for key in ["head_read_ms", "body_read_ms"] {
        refuse(
            &[p(key, 60001)],
            &format!("{key} is above request_total_ms"),
        );
        pass(&[p(key, 60000)]);
    }
    // upstream_connect + upstream_header < request_total (5000 + 30000 against 60000 ms): the limit of a stage
    // must come before the end of the request time, or a server that holds the stage up is never counted.
    let stages = "upstream_connect_ms plus upstream_header_ms is not below request_total_ms";
    refuse(&[p("upstream_header_ms", 55_000)], stages);
    pass(&[p("upstream_header_ms", 54_999)]);
    refuse(&[p("upstream_connect_ms", 30_000)], stages);
    pass(&[p("upstream_connect_ms", 29_999)]);
    refuse(&[p("request_total_ms", 35_000)], stages);
    pass(&[p("request_total_ms", 35_001)]);
    // request_total, response_idle <= conn_total (120000 ms)
    refuse(
        &[p("request_total_ms", 120_001)],
        "request_total_ms is above conn_total_ms",
    );
    pass(&[p("request_total_ms", 119_999), p("keepalive_time_ms", 1)]);
    refuse(
        &[p("response_idle_ms", 120_001)],
        "response_idle_ms is above conn_total_ms",
    );
    // upstream_keepalive_timeout <= response_idle (60000 ms)
    refuse(
        &[p("upstream_keepalive_timeout_ms", 60_001)],
        "upstream_keepalive_timeout_ms is above response_idle_ms",
    );
    pass(&[p("upstream_keepalive_timeout_ms", 60_000)]);
    // keepalive_timeout <= conn_total (120000 ms)
    refuse(
        &[p("keepalive_timeout_ms", 120_001)],
        "keepalive_timeout_ms is above conn_total_ms",
    );
    pass(&[p("keepalive_timeout_ms", 120_000)]);
    // keepalive_time + request_total <= conn_total (60000 + 60000 = 120000 ms): a request that starts before
    // keepalive_time is over before the connection time is.
    let sum = "keepalive_time_ms plus request_total_ms is above conn_total_ms";
    refuse(&[p("keepalive_time_ms", 60_001)], sum);
    refuse(&[p("request_total_ms", 60_001)], sum);
    pass(&[p("keepalive_time_ms", 60_000)]);
    // One hour of keep-alive time needs the hour and the request time.
    pass(&[
        p("keepalive_time_ms", 3_600_000),
        p("conn_total_ms", 3_660_000),
    ]);
    refuse(
        &[
            p("keepalive_time_ms", 3_600_000),
            p("conn_total_ms", 3_659_999),
        ],
        sum,
    );
    // lingering_timeout <= lingering_time (30000 ms)
    refuse(
        &[p("lingering_timeout_ms", 30_001)],
        "lingering_timeout_ms is above lingering_time_ms",
    );
    pass(&[p("lingering_timeout_ms", 30_000)]);
    // stop_inspect < stop_wait, stop_wait > stop_inspect + kill_grace (5000 + 1000 ms)
    let below = "stop_inspect_ms is not below stop_wait_ms";
    let plus = "stop_wait_ms is not above stop_inspect_ms plus kill_grace";
    refuse(&[p("stop_wait_ms", 5000)], below);
    refuse(&[p("stop_wait_ms", 6000)], plus);
    pass(&[p("stop_wait_ms", 6001)]);
    // wait_queue (16) <= max_conns
    let queue = "wait_queue is above max_conns";
    refuse(&[p("max_conns", 15)], queue);
    pass(&[p("max_conns", 16)]);
    // The kernel's own checks come first: a queue of 0 is not this relation.
    refuse(&[p("max_conns", 16), k("wait_queue", 0)], "wait_queue is 0");
}

#[test]
fn inspect_wait_covers_the_kernel_time_for_one_inspection() {
    // wait_deadline + 2 * verdict_wait + 18 * (drive_slice + frame_io)
    // = 3000 + 2 * 2000 + 18 * (50 + 1000) = 25900 ms
    let low = "inspect_wait_ms is below the kernel inspection time";
    refuse(&[p("inspect_wait_ms", 25899)], low);
    pass(&[p("inspect_wait_ms", 25900)]);
    refuse(
        &[p("inspect_wait_ms", 25900), k("wait_deadline_ms", 3001)],
        low,
    );
    // The same value cannot also exceed request_total (60000 ms).
    refuse(
        &[p("inspect_wait_ms", 60001)],
        "inspect_wait_ms is above request_total_ms",
    );
    pass(&[p("inspect_wait_ms", 60000)]);

    let kernel = parse(BASE.as_bytes()).unwrap().kernel.0;
    assert_eq!(inspect_floor(&kernel, Duration::MAX), None);
}

/// A fresh 0700 directory under the temp directory (`TMPDIR`), removed with everything in it when dropped.
struct TestDir(PathBuf);

impl TestDir {
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn scratch() -> TestDir {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "tukuyomi-proxy-config-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    // A umask can only remove bits; make the mode exactly 0700.
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    TestDir(dir)
}

#[test]
fn load_reads_a_regular_file_of_at_most_256_kib() {
    let dir = scratch();
    let file = dir.path().join("config.json");
    fs::write(&file, format!("{BASE}{}", " ".repeat(262_144 - BASE.len()))).unwrap();
    assert!(load(&file).is_ok());
    fs::write(&file, format!("{BASE}{}", " ".repeat(262_145 - BASE.len()))).unwrap();
    assert_eq!(
        load(&file).err(),
        Some(ConfigError("configuration file is over 256 KiB"))
    );

    assert_eq!(
        load(&dir.path().join("absent.json")).err(),
        Some(ConfigError("configuration file cannot be read"))
    );
    assert_eq!(
        load(dir.path()).err(),
        Some(ConfigError("configuration file is not a regular file"))
    );
}

#[test]
fn the_rules_store_kind_is_file_and_nothing_else() {
    pass(&[s("kind", "file")]);
    refuse(&[s("kind", "db")], "rules store kind is not supported");
}

#[test]
fn the_rules_store_dir_is_an_absolute_clean_path() {
    pass(&[s("dir", "/a")]);
    refuse(
        &[s("dir", "rules")],
        "rules store dir is not an absolute clean path",
    );
}

#[test]
fn the_rules_store_dir_is_at_most_3840_bytes() {
    let at = format!("/{}", "a".repeat(3839));
    pass(&[s("dir", at.as_str())]);
    refuse(
        &[s("dir", format!("{at}a"))],
        "rules store dir is over 3840 bytes",
    );
}

#[test]
fn a_generation_completes_the_kernel_values_and_is_checked_again() {
    let loaded = parse(BASE.as_bytes()).unwrap();
    let generation = Fingerprint::from_hex("0123456789abcdef".repeat(4).as_bytes()).unwrap();
    let dir = PathBuf::from(format!(
        "/var/lib/tukuyomi/rules/generations/{}",
        generation.hex()
    ));
    let kernel = loaded
        .kernel
        .for_generation(dir.clone(), generation)
        .unwrap();
    assert_eq!(kernel.rules, dir);
    assert_eq!(kernel.rules_sha256, generation.bytes());
    // The kernel checks the directory again: a relative one is refused.
    let result = loaded
        .kernel
        .for_generation(PathBuf::from("rules"), generation);
    assert_eq!(
        result.err(),
        Some(ConfigError("rules path is not an absolute clean path"))
    );
}

/// The base document with this route as the only route.
fn with_route(route: Value) -> Vec<u8> {
    doc(&[f("routes", Value::Array(vec![route]))])
}

/// The sentence with which the document is refused, or none if it loads.
fn refusal_of(bytes: &[u8]) -> Option<&'static str> {
    parse(bytes).err().map(|e| e.0)
}

#[test]
fn the_time_to_look_up_the_names_runs_from_1_ms_to_3600_s() {
    let key = "resolve_timeout_ms";
    let sentence = "resolve_timeout_ms is out of range";
    pass(&[f(key, 1)]);
    pass(&[f(key, 3_600_000)]);
    refuse(&[f(key, 0)], sentence);
    refuse(&[f(key, 3_600_001)], sentence);
}

#[test]
fn a_server_address_is_an_ip_literal_or_a_name_with_a_port() {
    let address = |text: &str| sv("address", text);
    let label = "a".repeat(63);
    let longest = format!("{label}.{label}.{label}.{}", "a".repeat(61));
    assert_eq!(longest.len(), 253);
    // A name of 253 bytes and a label of 63 bytes are the longest.
    let good: Vec<String> = vec![
        "app.test:80".into(),
        "a:1".into(),
        "db_1.internal:65535".into(),
        "x-y.z:8080".into(),
        "_x.test:80".into(),
        "localhost:8080".into(),
        format!("{label}:80"),
        format!("{longest}:80"),
    ];
    for text in &good {
        pass(&[address(text)]);
    }
    // Uppercase, an empty label, a last label that does not start with a letter (an OS reads `127.1` and
    // `0x7f000001` as addresses), and a name or a label one byte over.
    let malformed: Vec<String> = vec![
        "App.test:80".into(),
        ".app.test:80".into(),
        "app..test:80".into(),
        "app.test.:80".into(),
        "-:80".into(),
        "a b:80".into(),
        "app._test:80".into(),
        ":80".into(),
        "127.1:80".into(),
        "0x7f000001:80".into(),
        "2130706433:80".into(),
        "0177.0.0.1:80".into(),
        "app.1:80".into(),
        format!("{}:80", "a".repeat(64)),
        format!("{longest}a:80"),
    ];
    for text in &malformed {
        refuse(&[address(text)], "a server name is malformed");
    }
    for text in [
        "app.test:0",
        "app.test:08",
        "app.test:65536",
        "app.test:",
        "app.test:80x",
        "app.test:-1",
        "app.test: 80",
        "app.test:+80",
        "app.test:80:80",
    ] {
        refuse(&[address(text)], "a server port is not 1 to 65535");
    }
    let shape = "a server address is not an IP address and port, or a name and port";
    for text in ["", "app.test", "127.0.0.1", MARK] {
        refuse(&[address(text)], shape);
    }
    // An IP literal is not unspecified, not a multicast address and not at port 0.
    refuse(&[address("127.0.0.1:0")], "a server port is 0");
    let unusable = "a server address is unspecified or a multicast address";
    for text in [
        "0.0.0.0:80",
        "[::]:80",
        "224.0.0.1:80",
        "239.255.255.255:80",
        "[ff02::1]:80",
        "[::ffff:0.0.0.0]:80",
        "[::ffff:224.0.0.1]:80",
    ] {
        refuse(&[address(text)], unusable);
    }
    pass(&[address("223.255.255.255:80")]);
    pass(&[address("[2001:db8::1]:80")]);
    // A name is kept as it was written: nothing is looked up when the file is loaded.
    let loaded = parse(&doc(&[address("app.test:80")])).unwrap();
    let api = loaded
        .forward
        .groups
        .iter()
        .find(|g| g.name == "api")
        .unwrap();
    assert_eq!(
        api.servers[0].address,
        Address::Name {
            name: "app.test".to_string(),
            port: 80
        }
    );
}

#[test]
fn the_access_of_a_route_is_two_lists_of_at_most_256_networks() {
    let route =
        |access: Value| with_route(serde_json::json!({"upstream": "api", "access": access}));
    let access_of = |bytes: &[u8]| {
        let loaded = parse(bytes).unwrap();
        loaded
            .forward
            .routes
            .find(Some(b"h.test"), b"/")
            .unwrap()
            .access
            .clone()
    };
    let both = serde_json::json!({
        "deny_cidrs": ["10.0.0.0/8"],
        "allow_cidrs": ["10.1.0.0/16", "192.0.2.0/24"],
    });
    let access = access_of(&route(both));
    let permits = |text: &str| access.permits(text.parse().unwrap(), Country::Unknown);
    // Deny first; then only the networks of allow.
    assert!(!permits("10.1.2.3"));
    assert!(permits("192.0.2.5"));
    assert!(!permits("198.51.100.1"));
    let empty = access_of(&route(serde_json::json!({})));
    assert!(empty.permits("203.0.113.1".parse().unwrap(), Country::Unknown));

    let list = |key: &str, n: usize| {
        let mut object = serde_json::Map::new();
        object.insert(
            key.to_string(),
            Value::Array(vec![Value::from("10.0.0.0/8"); n]),
        );
        Value::Object(object)
    };
    for key in ["deny_cidrs", "allow_cidrs"] {
        assert_eq!(refusal_of(&route(list(key, 256))), None);
        assert_eq!(
            refusal_of(&route(list(key, 257))),
            Some("access has a list of more than 256 networks")
        );
    }
    for bad in ["10.0.0.1/8", "10.0.0.0", "", MARK] {
        assert_eq!(
            refusal_of(&route(serde_json::json!({"deny_cidrs": [bad]}))),
            Some("access has an entry that is not a network"),
            "{bad:?}"
        );
    }
    let unknown = "configuration has an unknown key";
    let wrong = "configuration has a value of the wrong type";
    for (access, sentence) in [
        (serde_json::json!({"allow": []}), unknown),
        (serde_json::json!([]), wrong),
        (serde_json::json!({"deny_cidrs": "10.0.0.0/8"}), wrong),
        (serde_json::json!({"deny_cidrs": null}), wrong),
    ] {
        assert_eq!(
            refusal_of(&route(access.clone())),
            Some(sentence),
            "{access}"
        );
    }
}

#[test]
fn the_edits_of_a_route_are_read_and_checked_when_the_file_is_loaded() {
    let rewrite = |edits: Value| {
        with_route(serde_json::json!({"path": "/api/", "upstream": "api", "rewrite": edits}))
    };
    let full = serde_json::json!({
        "host": "inner.test:8080",
        "path": "/v2/",
        "query": {
            "remove": ["a"],
            "remove_prefixes": ["utm_"],
            "set": [{"name": "s", "value": "1"}],
            "add": [{"name": "k", "value": "v"}],
        },
        "request_headers": {
            "remove": ["X-Drop"],
            "set": [{"name": "X-Edge", "value": "1"}],
            "add": [{"name": "X-Added", "value": "a"}],
        },
        "response_headers": {
            "remove": ["Server"],
            "set": [],
            "add": [{"name": "X-Served-By", "value": "edge"}],
        },
    });
    let mut good = vec![
        full,
        serde_json::json!({}),
        serde_json::json!({"query": {}}),
        serde_json::json!({"response_headers": {"remove": ["Server"]}}),
    ];
    good.push(serde_json::json!({"request_headers": {"add": (0..32)
        .map(|i| serde_json::json!({"name": format!("x-{i}"), "value": "v"}))
        .collect::<Vec<_>>()}}));
    for edits in good {
        assert_eq!(refusal_of(&rewrite(edits.clone())), None, "{edits}");
    }

    let field = "a request field name is not allowed in the edits";
    let value = "a field value is over 4096 bytes or has a character that is not allowed";
    let query_name = "a query name is not 1 to 256 bytes of letters, digits and - . _ ~";
    let unknown = "configuration has an unknown key";
    let wrong = "configuration has a value of the wrong type";
    let mut bad = vec![
        (
            serde_json::json!({"host": "*.inner.test"}),
            "a rewrite host is malformed",
        ),
        (
            serde_json::json!({"path": "/v2"}),
            "a rewrite path for a route path that ends in / does not end in /",
        ),
        (
            serde_json::json!({"path": "/a/../b/"}),
            "a rewrite path is malformed",
        ),
        (
            serde_json::json!({"request_headers": {"set": [{"name": "Host", "value": "x"}]}}),
            field,
        ),
        (
            serde_json::json!({"request_headers": {"remove": ["x_y"]}}),
            field,
        ),
        (
            serde_json::json!({"response_headers": {"add": [{"name": "Set-Cookie", "value": "a=b"}]}}),
            "a response field name is not allowed in the edits",
        ),
        (
            serde_json::json!({"request_headers": {"set": [{"name": "X-A", "value": "a\r\nX-B: b"}]}}),
            value,
        ),
        (
            serde_json::json!({"request_headers": {"remove": ["X-A"], "set": [{"name": "x-a", "value": "1"}]}}),
            "a field name is edited more than once",
        ),
        (
            serde_json::json!({"query": {"set": [{"name": "a=b", "value": "1"}]}}),
            query_name,
        ),
        (
            serde_json::json!({"query": {"add": [{"name": "a", "value": "x y"}]}}),
            "a query value is over 4096 bytes or has a character that is not allowed",
        ),
        (
            serde_json::json!({"query": {"remove": ["a"], "add": [{"name": "a", "value": "1"}]}}),
            "a query name is edited more than once",
        ),
        (serde_json::json!({"unknown": 1}), unknown),
        (serde_json::json!({"query": {"unknown": 1}}), unknown),
        (serde_json::json!({"query": []}), wrong),
        (
            serde_json::json!({"request_headers": {"add": [["X-A", "1"]]}}),
            wrong,
        ),
        (
            serde_json::json!({"request_headers": {"add": [{"name": "X-A"}]}}),
            "configuration has a missing key",
        ),
        (serde_json::json!({"host": 5}), wrong),
    ];
    bad.push((
        serde_json::json!({"request_headers": {"add": (0..33)
            .map(|i| serde_json::json!({"name": format!("x-{i}"), "value": "v"}))
            .collect::<Vec<_>>()}}),
        "the field edits have more than 32 items",
    ));
    for (edits, sentence) in bad {
        assert_eq!(
            refusal_of(&rewrite(edits.clone())),
            Some(sentence),
            "{edits}"
        );
    }
    // A path edit needs a route that has a path.
    let no_path = with_route(serde_json::json!({"upstream": "api", "rewrite": {"path": "/v2/"}}));
    assert_eq!(
        refusal_of(&no_path),
        Some("a rewrite path is set on a route that has no path")
    );
}

#[test]
fn the_stream_of_a_route_has_all_its_keys_and_times_from_1_ms_to_24_h_with_idle_not_above_total() {
    let route =
        |stream: Value| with_route(serde_json::json!({"upstream": "api", "stream": stream}));
    let stream_of = |bytes: &[u8]| {
        let loaded = parse(bytes).unwrap();
        loaded
            .forward
            .routes
            .find(Some(b"h.test"), b"/")
            .unwrap()
            .stream
    };
    let times = |idle_ms: u64, total_ms: u64| serde_json::json!({"idle_ms": idle_ms, "total_ms": total_ms, "websocket": false});
    assert_eq!(
        stream_of(&route(serde_json::json!({
            "idle_ms": 1000, "total_ms": 86_400_000, "websocket": true
        }))),
        Some(Stream {
            idle: Duration::from_secs(1),
            total: Duration::from_secs(86_400),
            websocket: true,
        })
    );
    assert_eq!(
        stream_of(&with_route(serde_json::json!({"upstream": "api"}))),
        None
    );

    // The times are at the limits, and one past them.
    for (idle, total) in [(1, 1), (5, 5), (1, 86_400_000), (86_400_000, 86_400_000)] {
        assert_eq!(
            refusal_of(&route(times(idle, total))),
            None,
            "{idle} {total}"
        );
    }
    let range = "a stream idle_ms or total_ms is out of range";
    for (idle, total) in [(0, 5), (1, 0), (1, 86_400_001)] {
        assert_eq!(
            refusal_of(&route(times(idle, total))),
            Some(range),
            "{idle} {total}"
        );
    }
    assert_eq!(
        refusal_of(&route(times(6, 5))),
        Some("a stream idle_ms is above its total_ms")
    );
    // Every key is there, and nothing else.
    let missing = "configuration has a missing key";
    let unknown = "configuration has an unknown key";
    let wrong = "configuration has a value of the wrong type";
    for (stream, sentence) in [
        (serde_json::json!({"idle_ms": 1, "total_ms": 2}), missing),
        (
            serde_json::json!({"total_ms": 2, "websocket": true}),
            missing,
        ),
        (serde_json::json!({}), missing),
        (
            serde_json::json!({"idle_ms": 1, "total_ms": 2, "websocket": true, "x": 1}),
            unknown,
        ),
        (
            serde_json::json!({"idle_ms": 1, "total_ms": 2, "websocket": "yes"}),
            wrong,
        ),
        (serde_json::json!([1, 2, true]), wrong),
    ] {
        assert_eq!(
            refusal_of(&route(stream.clone())),
            Some(sentence),
            "{stream}"
        );
    }
}

#[test]
fn a_key_that_may_be_left_out_is_refused_when_it_is_null() {
    let wrong = "configuration has a value of the wrong type";
    // serde would read null as a key that is left out: TLS would be off, or the host or the access list gone.
    for key in ["tls", "redirect"] {
        let mut listener = serde_json::json!({"address": "127.0.0.1:9100"});
        listener[key] = Value::Null;
        refuse(&[listeners(Value::Array(vec![listener]))], wrong);
    }
    for key in ["host", "path", "access", "rewrite", "stream"] {
        let mut route = serde_json::json!({"upstream": "api"});
        route[key] = Value::Null;
        assert_eq!(refusal_of(&with_route(route)), Some(wrong), "{key}");
    }
    for key in [
        "host",
        "path",
        "query",
        "request_headers",
        "response_headers",
    ] {
        let mut edits = serde_json::json!({});
        edits[key] = Value::Null;
        let route = serde_json::json!({"path": "/api/", "upstream": "api", "rewrite": edits});
        assert_eq!(refusal_of(&with_route(route)), Some(wrong), "{key}");
    }
    // Left out, the same keys are fine.
    pass(&[at("127.0.0.1:9100")]);
    let route = serde_json::json!({"upstream": "api", "rewrite": {}});
    assert_eq!(refusal_of(&with_route(route)), None);
}

// ---- acme ----

fn acme_object() -> Value {
    serde_json::json!({
        "directory_url": "https://ca.example/directory",
        "contact_email": "ops@example.test",
        "account_key_file": "/etc/tukuyomi/acme/account.key",
        "challenge_dir": "/var/lib/tukuyomi/challenges",
        "ca_file": "/etc/tukuyomi/acme/ca.pem",
        "timeout_ms": 60000,
    })
}

/// A listener that ends TLS with one certificate that has `acme`, for `hosts`.
fn acme_tls(hosts: &[&str], acme: Value) -> Value {
    serde_json::json!({
        "address": "127.0.0.1:443",
        "tls": {
            "min_version": "1.2",
            "certificates": [{
                "cert_file": "/etc/tukuyomi/tls/a.pem",
                "key_file": "/etc/tukuyomi/tls/a.key",
                "hosts": hosts,
                "acme": acme,
            }],
        },
    })
}

/// A plain listener, a listener with a certificate that has `acme`, and the `acme` object `object`.
fn with_acme(object: Value) -> [Edit; 2] {
    let renew = serde_json::json!({"renew_before_days": 30});
    [
        listeners(serde_json::json!([
            {"address": "127.0.0.1:80"},
            acme_tls(&["a.example", "b.example"], renew),
        ])),
        ("", "acme", object),
    ]
}

#[test]
fn the_acme_object_and_the_certificates_with_acme_go_together_and_need_a_listener_for_the_challenge()
 {
    let loaded = parse(&doc(&with_acme(acme_object()))).unwrap();
    let acme = loaded.acme.unwrap();
    assert_eq!(acme.directory_url, "https://ca.example/directory");
    assert_eq!(acme.contact_email, "ops@example.test");
    assert_eq!(
        acme.account_key_file,
        Path::new("/etc/tukuyomi/acme/account.key")
    );
    assert_eq!(
        acme.challenge_dir,
        Path::new("/var/lib/tukuyomi/challenges")
    );
    assert_eq!(acme.ca_file, Path::new("/etc/tukuyomi/acme/ca.pem"));
    assert_eq!(acme.timeout, Duration::from_millis(60_000));
    let ListenerKind::Tls(tls) = &loaded.proxy.listeners[1].kind else {
        panic!("not a TLS listener");
    };
    assert_eq!(
        tls.certificates[0].acme,
        Some(CertificateAcme {
            renew_before_days: 30
        })
    );
    // No acme anywhere: none in the result.
    assert!(parse(BASE.as_bytes()).unwrap().acme.is_none());

    // A certificate with acme and no object; an object and no certificate with acme.
    let [only_listeners, _] = with_acme(acme_object());
    refuse(
        &[only_listeners],
        "a certificate has acme but the configuration has no acme object",
    );
    refuse(
        &[("", "acme", acme_object())],
        "the configuration has an acme object but no certificate has acme",
    );
    refuse(
        &[
            tls_listener_edit(&["a.example"]),
            ("", "acme", acme_object()),
        ],
        "the configuration has an acme object but no certificate has acme",
    );
    // The CA asks over plain HTTP, so a listener has to take that: a plain one, or one that redirects.
    let renew = serde_json::json!({"renew_before_days": 30});
    let only_tls = || listeners(serde_json::json!([acme_tls(&["a.example"], renew.clone())]));
    refuse(
        &[only_tls(), ("", "acme", acme_object())],
        "a certificate with acme needs a plain or a redirect listener for the challenge",
    );
    let redirecting = serde_json::json!([
        acme_tls(&["a.example"], renew.clone()),
        {"address": "127.0.0.1:80", "redirect": {"https_port": 443}},
    ]);
    pass(&[listeners(redirecting), ("", "acme", acme_object())]);

    // The files that the command writes and reads are all different files.
    let not_all_different = "the account key file, the ca_file and the cert and key files of the certificates with acme are not all different";
    for (key, file) in [
        ("account_key_file", "/etc/tukuyomi/tls/a.key"),
        ("ca_file", "/etc/tukuyomi/tls/a.pem"),
        ("ca_file", "/etc/tukuyomi/acme/account.key"),
    ] {
        let mut object = acme_object();
        object[key] = file.into();
        refuse(&with_acme(object), not_all_different);
    }
}

#[test]
fn no_file_of_the_command_or_of_a_certificate_is_directly_inside_the_challenge_directory() {
    let refused = "the account key file, the ca_file or a cert or key file of a certificate is directly inside challenge_dir";
    let dir = "/var/lib/tukuyomi/challenges";
    // The six files, in the order of the account key, the CA, then the cert and key of a certificate with acme and of
    // one without.
    let outside = [
        "/etc/tukuyomi/acme/account.key",
        "/etc/tukuyomi/acme/ca.pem",
        "/etc/tukuyomi/tls/a.pem",
        "/etc/tukuyomi/tls/a.key",
        "/etc/tukuyomi/tls/m.pem",
        "/etc/tukuyomi/tls/m.key",
    ];
    let edits = |files: [String; 6]| {
        let [account, ca, a_cert, a_key, m_cert, m_key] = files;
        let mut object = acme_object();
        object["account_key_file"] = account.into();
        object["ca_file"] = ca.into();
        let certificates = serde_json::json!([
            {"cert_file": a_cert, "key_file": a_key, "hosts": ["a.example"], "acme": {"renew_before_days": 30}},
            {"cert_file": m_cert, "key_file": m_key, "hosts": ["m.example"]},
        ]);
        [
            listeners(serde_json::json!([
                {"address": "127.0.0.1:80"},
                {"address": "127.0.0.1:443", "tls": {"min_version": "1.2", "certificates": certificates}},
            ])),
            ("", "acme", object),
        ]
    };
    pass(&edits(outside.map(String::from)));
    for at in 0..outside.len() {
        let mut files = outside.map(String::from);
        files[at] = format!("{dir}/f");
        refuse(&edits(files), refused);
    }
    // Only the files of the directory itself are answered with: one in a directory below it is fine.
    pass(&edits(std::array::from_fn(|i| format!("{dir}/below/{i}"))));
}

#[test]
fn every_value_of_the_acme_object_is_checked_and_the_first_one_past_a_bound_is_refused() {
    let mut cases: Vec<(&str, Value, Option<&str>)> = Vec::new();
    let url = |tail: usize| Value::from(format!("https://ca.example/{}", "x".repeat(tail)));
    let longest = 2048 - "https://ca.example/".len();
    let wrong_url = "acme directory_url is not an https URL of at most 2048 bytes";
    cases.push(("directory_url", url(longest), None));
    cases.push(("directory_url", url(longest + 1), Some(wrong_url)));
    for bad in [
        "http://ca.example/dir",
        "https://",
        "https://ca.example/a b",
        "ca.example/dir",
        "https://ca.example/\u{e9}",
    ] {
        cases.push(("directory_url", bad.into(), Some(wrong_url)));
    }
    let wrong_email = "acme contact_email is not an address of at most 254 bytes";
    let email_of = |len: usize| Value::from(format!("{}@{}.test", "a".repeat(len), "d".repeat(60)));
    cases.push(("contact_email", "ops@example.test".into(), None));
    cases.push(("contact_email", "a.b-c_d+e@mail.example.test".into(), None));
    cases.push(("contact_email", email_of(64), None));
    cases.push(("contact_email", email_of(65), Some(wrong_email)));
    for bad in [
        "",
        "ops",
        "ops@",
        "@example.test",
        "ops@example",
        "ops@@example.test",
        "ops@exa mple.test",
        "ops@example.test?cc=x",
        "ops,x@example.test",
        "o ps@example.test",
        "ops@-example.test",
        "ops@example..test",
        "ops@.example.test",
        "ops@example.test.",
        "ops@exa_mple.test",
    ] {
        cases.push(("contact_email", bad.into(), Some(wrong_email)));
    }
    let wrong_path = "an acme account_key_file, challenge_dir or ca_file is not an absolute clean path of at most 3840 bytes";
    for key in ["account_key_file", "challenge_dir", "ca_file"] {
        cases.push((key, "/etc/tukuyomi/x".into(), None));
        cases.push((key, format!("/{}", "x".repeat(3839)).into(), None));
        cases.push((
            key,
            format!("/{}", "x".repeat(3840)).into(),
            Some(wrong_path),
        ));
        for bad in ["x", "/", "/a/../b", "/a//b", "/a/", "/a/./b", ""] {
            cases.push((key, bad.into(), Some(wrong_path)));
        }
    }
    let wrong_time = "acme timeout_ms is not 1 to 600000";
    for (ms, ok) in [(1, true), (600_000, true), (0, false), (600_001, false)] {
        cases.push(("timeout_ms", ms.into(), (!ok).then_some(wrong_time)));
    }
    for (key, value, sentence) in cases {
        let mut object = acme_object();
        object[key] = value.clone();
        let edits = with_acme(object);
        match sentence {
            None => pass(&edits),
            Some(sentence) => refuse(&edits, sentence),
        }
    }
    // A key that is left out, one that is not known, and null.
    let mut object = acme_object();
    object.as_object_mut().unwrap().remove("timeout_ms");
    refuse(&with_acme(object), "configuration has a missing key");
    let mut object = acme_object();
    object["extra"] = 1.into();
    refuse(&with_acme(object), "configuration has an unknown key");
    refuse(
        &with_acme(Value::Null),
        "configuration has a value of the wrong type",
    );
}

#[test]
fn a_certificate_with_acme_has_names_only_and_renews_1_to_60_days_before_the_end() {
    let renew = |days: Value| serde_json::json!({"renew_before_days": days});
    let tls = |hosts: &[&str], acme: Value| {
        [
            listeners(serde_json::json!([{"address": "127.0.0.1:80"}, acme_tls(hosts, acme)])),
            ("", "acme", acme_object()),
        ]
    };
    for days in [1, 30, 60] {
        pass(&tls(&["a.example"], renew(days.into())));
    }
    for days in [0, 61] {
        refuse(
            &tls(&["a.example"], renew(days.into())),
            "acme renew_before_days is not 1 to 60",
        );
    }
    refuse(
        &tls(&["a.example"], renew((-1).into())),
        "configuration has a value of the wrong type",
    );
    refuse(
        &tls(&["a.example"], renew("30".into())),
        "configuration has a value of the wrong type",
    );
    // HTTP-01 proves a name, not a wildcard and not an address.
    refuse(
        &tls(&["a.example", "*.a.example"], renew(30.into())),
        "a certificate with acme has a wildcard host",
    );
    refuse(
        &tls(&["192.0.2.1"], renew(30.into())),
        "a tls host is not a name, or * and a name",
    );
    // The same wildcard is fine in a certificate that is put in place by hand.
    pass(&[tls_listener_edit(&["*.a.example"])]);
    // The key of the object, left out or unknown, and null (which would make the certificate a manual one).
    refuse(
        &tls(&["a.example"], serde_json::json!({})),
        "configuration has a missing key",
    );
    refuse(
        &tls(
            &["a.example"],
            serde_json::json!({"renew_before_days": 30, "mode": "auto"}),
        ),
        "configuration has an unknown key",
    );
    refuse(
        &tls(&["a.example"], Value::Null),
        "configuration has a value of the wrong type",
    );
    refuse(
        &[("", "acme", Value::Null)],
        "configuration has a value of the wrong type",
    );
}

fn tls_listener_edit(hosts: &[&str]) -> Edit {
    listeners(tls_listeners("127.0.0.1:443", hosts))
}

#[test]
fn a_file_of_a_certificate_without_acme_is_no_file_of_the_command() {
    let refused = "a cert or key file of a certificate without acme is a file of the command or of a certificate with acme";
    let config = |manual_key: &str| {
        let certificates = serde_json::json!([
            {"cert_file": "/etc/tukuyomi/tls/a.pem", "key_file": "/etc/tukuyomi/tls/a.key", "hosts": ["a.example"], "acme": {"renew_before_days": 30}},
            {"cert_file": "/etc/tukuyomi/tls/m.pem", "key_file": manual_key, "hosts": ["m.example"]},
        ]);
        [
            listeners(serde_json::json!([
                {"address": "127.0.0.1:80"},
                {"address": "127.0.0.1:443", "tls": {"min_version": "1.2", "certificates": certificates}},
            ])),
            ("", "acme", acme_object()),
        ]
    };
    pass(&config("/etc/tukuyomi/tls/m.key"));
    refuse(&config("/etc/tukuyomi/acme/account.key"), refused);
    refuse(&config("/etc/tukuyomi/tls/a.key"), refused);
}

// ---- status ----

fn status(listen: &str) -> Edit {
    ("", "status", serde_json::json!({ "listen": listen }))
}

#[test]
fn the_status_object_is_left_out_or_names_a_loopback_address_that_no_listener_has() {
    // Left out: no listener. Written: the address, which is no listener of the 1 to 8.
    assert!(parse(BASE.as_bytes()).unwrap().status.is_none());
    let loaded = parse(&doc(&[status("127.0.0.1:9180")])).unwrap();
    assert_eq!(
        loaded.status,
        Some(StatusConfig {
            listen: "127.0.0.1:9180".parse().unwrap()
        })
    );
    assert_eq!(loaded.proxy.listeners.len(), 1);
    pass(&[status("[::1]:9180")]);
    pass(&[status("127.5.6.7:9180")]);
    // The port of a listener on another address is free.
    pass(&[status("127.0.0.2:8080")]);

    let not_loopback = "status listen is not a loopback address";
    for listen in [
        "0.0.0.0:9180",
        "[::]:9180",
        "192.0.2.1:9180",
        "[::ffff:127.0.0.1]:9180",
    ] {
        refuse(&[status(listen)], not_loopback);
    }
    refuse(
        &[status("localhost:9180")],
        "status listen is not an IP address and port",
    );
    refuse(&[status("127.0.0.1:0")], "status listen port is 0");

    // The address of a listener, and a listener that is unspecified at the port.
    let clash = "status listen is the address of a listener, or one is an unspecified address at the port of the other";
    refuse(&[status("127.0.0.1:8080")], clash);
    refuse(&[at("0.0.0.0:9180"), status("127.0.0.1:9180")], clash);
    refuse(&[at("[::]:9180"), status("[::1]:9180")], clash);
    pass(&[at("0.0.0.0:9181"), status("127.0.0.1:9180")]);

    // The object has the one key `listen`, as an object.
    refuse(
        &[("", "status", serde_json::json!({}))],
        "configuration has a missing key",
    );
    refuse(
        &[(
            "",
            "status",
            serde_json::json!({"listen": "127.0.0.1:9180", "path": "/"}),
        )],
        "configuration has an unknown key",
    );
    refuse(
        &[("", "status", serde_json::json!(["127.0.0.1:9180"]))],
        "configuration has a value of the wrong type",
    );
    refuse(
        &[("", "status", Value::Null)],
        "configuration has a value of the wrong type",
    );
}

#[test]
fn a_server_may_not_be_at_the_status_address() {
    // Like the address of a listener: a route to it would send the requests of clients to the status listener.
    let same = "a listener and a server are the same address";
    refuse(
        &[status("127.0.0.1:9180"), sv("address", "127.0.0.1:9180")],
        same,
    );
    refuse(
        &[
            status("127.0.0.1:9180"),
            sv("address", "[::ffff:127.0.0.1]:9180"),
        ],
        same,
    );
    pass(&[status("127.0.0.1:9180"), sv("address", "127.0.0.1:9181")]);
    pass(&[status("127.0.0.1:9180"), sv("address", "127.0.0.2:9180")]);
}

// ---- records ----

fn records(key: &'static str, value: impl Into<Value>) -> Edit {
    let mut object = serde_json::json!({ "dir": "/var/lib/tukuyomi/records", "file_bytes": 1 << 20, "files": 2 });
    object[key] = value.into();
    ("", "records", object)
}

#[test]
fn the_records_object_is_left_out_or_has_a_clean_dir_a_size_and_a_count() {
    assert!(parse(BASE.as_bytes()).unwrap().records.is_none());
    let loaded = parse(&doc(&[records("files", 64)])).unwrap();
    assert_eq!(
        loaded.records,
        Some(RecordsConfig {
            dir: PathBuf::from("/var/lib/tukuyomi/records"),
            file_bytes: 1 << 20,
            files: 64,
        })
    );

    // Each limit and the first value past it.
    let size = "records file_bytes is not 1 MiB to 1 GiB";
    pass(&[records("file_bytes", MIB)]);
    pass(&[records("file_bytes", GIB)]);
    refuse(&[records("file_bytes", MIB - 1)], size);
    refuse(&[records("file_bytes", GIB + 1)], size);
    let count = "records files is not 2 to 64";
    pass(&[records("files", 2)]);
    refuse(&[records("files", 1)], count);
    refuse(&[records("files", 65)], count);
    let dir = "records dir is not an absolute clean path of at most 3840 bytes";
    pass(&[records("dir", format!("/{}", "d".repeat(3839)))]);
    refuse(&[records("dir", format!("/{}", "d".repeat(3840)))], dir);
    for bad in ["records", "/var/lib/../records", "/var/lib/records/", "/"] {
        refuse(&[records("dir", bad)], dir);
    }

    // Every key, as an object, and never null.
    refuse(
        &[(
            "",
            "records",
            serde_json::json!({"dir": "/var/lib/r", "files": 2}),
        )],
        "configuration has a missing key",
    );
    refuse(
        &[records("path", "/var/lib/r")],
        "configuration has an unknown key",
    );
    refuse(
        &[records("files", Value::Null)],
        "configuration has a value of the wrong type",
    );
    refuse(
        &[("", "records", Value::Null)],
        "configuration has a value of the wrong type",
    );
}

// ---- access and rate_limit ----

fn rate_limit(key: &'static str, value: impl Into<Value>) -> Edit {
    let mut object = serde_json::json!({ "rate": 100, "burst": 20, "keys": 4096 });
    object[key] = value.into();
    ("", "rate_limit", object)
}

fn global_access(key: &'static str, value: impl Into<Value>) -> Edit {
    ("", "access", serde_json::json!({ key: value.into() }))
}

#[test]
fn the_access_and_rate_limit_objects_are_left_out_or_have_their_values_in_range() {
    assert_eq!(
        parse(BASE.as_bytes()).unwrap().policy,
        PolicyConfig::default()
    );
    let net = |text: &str| Cidr::parse(text).unwrap();
    let loaded = parse(&doc(&[
        (
            "",
            "access",
            serde_json::json!({"deny_cidrs": ["10.0.0.0/8"], "allow_cidrs": ["10.1.0.0/16"]}),
        ),
        rate_limit(
            "exempt_cidrs",
            serde_json::json!(["127.0.0.1/32", "::1/128"]),
        ),
    ]))
    .unwrap();
    assert_eq!(
        loaded.policy.access,
        Access::new(vec![net("10.0.0.0/8")], vec![net("10.1.0.0/16")])
    );
    assert_eq!(
        loaded.policy.rate_limit,
        Some(RateLimitConfig {
            rate: 100,
            burst: 20,
            keys: 4096,
            exempt: vec![net("127.0.0.1/32"), net("::1/128")],
        })
    );

    // Each limit and the first value past it.
    let rate = "rate_limit rate is not 1 to 100000";
    pass(&[rate_limit("rate", 1)]);
    pass(&[rate_limit("rate", 100_000)]);
    refuse(&[rate_limit("rate", 0)], rate);
    refuse(&[rate_limit("rate", 100_001)], rate);
    let burst = "rate_limit burst is not 0 to 100000";
    pass(&[rate_limit("burst", 0)]);
    pass(&[rate_limit("burst", 100_000)]);
    refuse(&[rate_limit("burst", 100_001)], burst);
    let keys = "rate_limit keys is not 1024 to 1048576";
    pass(&[rate_limit("keys", 1024)]);
    pass(&[rate_limit("keys", 1 << 20)]);
    refuse(&[rate_limit("keys", 1023)], keys);
    refuse(&[rate_limit("keys", (1 << 20) + 1)], keys);
    let many = "rate_limit exempt_cidrs has more than 256 entries";
    let list = |n: usize| serde_json::json!(vec!["127.0.0.1/32"; n]);
    pass(&[rate_limit("exempt_cidrs", list(256))]);
    refuse(&[rate_limit("exempt_cidrs", list(257))], many);
    refuse(
        &[rate_limit("exempt_cidrs", serde_json::json!(["127.0.0.1"]))],
        "rate_limit exempt_cidrs has an entry that is not a network",
    );
    // The access of the configuration is read as the access of a route is.
    pass(&[global_access("deny_cidrs", list(256))]);
    refuse(
        &[global_access("allow_cidrs", list(257))],
        "access has a list of more than 256 networks",
    );
    refuse(
        &[global_access(
            "deny_cidrs",
            serde_json::json!(["10.0.0.1/8"]),
        )],
        "access has an entry that is not a network",
    );

    // Every key of the rate limit but `exempt_cidrs`, as an object, and never null.
    refuse(
        &[(
            "",
            "rate_limit",
            serde_json::json!({"rate": 100, "burst": 20}),
        )],
        "configuration has a missing key",
    );
    refuse(
        &[rate_limit("per_second", 5)],
        "configuration has an unknown key",
    );
    refuse(
        &[global_access("countries", serde_json::json!(["JP"]))],
        "configuration has an unknown key",
    );
    for edit in [
        rate_limit("rate", Value::Null),
        ("", "rate_limit", Value::Null),
        ("", "access", Value::Null),
        ("", "access", serde_json::json!([])),
    ] {
        refuse(&[edit], "configuration has a value of the wrong type");
    }
}

// ---- countries and geo ----

const GEO_SHA256: &str = "abababababababababababababababababababababababababababababababab";

fn geo(path: &str, sha256: &str) -> Edit {
    (
        "",
        "geo",
        serde_json::json!({ "country_db": path, "sha256": sha256 }),
    )
}

fn countries_access(deny: Value, allow: Value) -> Edit {
    (
        "",
        "access",
        serde_json::json!({ "deny_countries": deny, "allow_countries": allow }),
    )
}

#[test]
fn the_access_has_lists_of_at_most_256_countries_that_are_codes_or_unknown_and_they_need_geo() {
    let jp = Country::Known(*b"JP");
    let loaded = parse(&doc(&[
        geo("/etc/tukuyomi/country.mmdb", GEO_SHA256),
        countries_access(
            serde_json::json!(["JP", "UNKNOWN"]),
            serde_json::json!(["US"]),
        ),
    ]))
    .unwrap();
    assert_eq!(
        loaded.policy.access,
        Access::new(Vec::new(), Vec::new())
            .with_countries(vec![jp, Country::Unknown], vec![Country::Known(*b"US")])
    );
    // The file is not read when the configuration is parsed.
    assert_eq!(
        loaded.policy.geo,
        Some(GeoConfig {
            country_db: PathBuf::from("/etc/tukuyomi/country.mmdb"),
            sha256: [0xab; 32],
        })
    );
    assert_eq!(loaded.policy.country, None);

    // Each list and the first entry past 256; the same sentences for the access of a route.
    let geo_edit = || geo("/a", GEO_SHA256);
    let many = |n: usize| serde_json::json!(vec!["JP"; n]);
    let none = serde_json::json!([]);
    for (deny, allow) in [
        (many(256), none.clone()),
        (none.clone(), many(256)),
        (many(256), many(256)),
    ] {
        pass(&[geo_edit(), countries_access(deny, allow)]);
    }
    let sentence = "access has a list of more than 256 countries";
    refuse(
        &[geo_edit(), countries_access(many(257), none.clone())],
        sentence,
    );
    refuse(
        &[geo_edit(), countries_access(none.clone(), many(257))],
        sentence,
    );
    let route = |access: Value| {
        let route = serde_json::json!({"upstream": "api", "access": access});
        doc(&[geo_edit(), f("routes", Value::Array(vec![route]))])
    };
    assert_eq!(
        refusal_of(&route(serde_json::json!({"deny_countries": many(257)}))),
        Some(sentence)
    );
    assert_eq!(
        refusal_of(&route(serde_json::json!({"allow_countries": many(256)}))),
        None
    );
    for bad in [
        "jp", "Jp", "JPN", "J", "", "J1", "unknown", "UNKNOWN ", MARK,
    ] {
        let sentence = "access has an entry that is not a country";
        refuse(
            &[
                geo_edit(),
                countries_access(serde_json::json!([bad]), none.clone()),
            ],
            sentence,
        );
        assert_eq!(
            refusal_of(&route(serde_json::json!({"allow_countries": [bad]}))),
            Some(sentence),
            "{bad:?}"
        );
    }

    // A list of countries needs `geo`, in the access of the configuration and in that of a route.
    let needs = "access has a list of countries while geo is left out";
    refuse(
        &[countries_access(serde_json::json!(["JP"]), none.clone())],
        needs,
    );
    refuse(
        &[countries_access(none.clone(), serde_json::json!(["JP"]))],
        needs,
    );
    let guarded = serde_json::json!({"upstream": "api", "access": {"deny_countries": ["JP"]}});
    assert_eq!(refusal_of(&with_route(guarded)), Some(needs));
    // Empty lists do not, and `geo` alone is fine.
    pass(&[countries_access(none.clone(), none.clone())]);
    pass(&[geo_edit()]);
    assert_eq!(
        refusal_of(&route(serde_json::json!({"deny_countries": ["JP"]}))),
        None
    );
}

#[test]
fn a_route_with_only_a_list_of_countries_is_a_route_with_an_access_list() {
    let with = |route: Value| {
        doc(&[
            geo("/a", GEO_SHA256),
            f("routes", Value::Array(vec![route])),
        ])
    };
    let access = serde_json::json!({"allow_countries": ["JP"]});
    // The canonical form of the path and the absence of a port in the hosts are asked of such a route as of any other.
    let lowercase = serde_json::json!({"path": "/%61dmin/", "upstream": "api", "access": access});
    assert_eq!(
        refusal_of(&with(lowercase)),
        Some(
            "a route with an access list has an escape in its path that is lowercase or is for a byte that needs no escape"
        )
    );
    let ported = serde_json::json!({"host": "h.test:8080", "upstream": "api", "access": access});
    assert_eq!(
        refusal_of(&with(ported)),
        Some("a route host has a port while a route has an access list")
    );
    let other = serde_json::json!({"host": "h.test:8080", "upstream": "api"});
    assert_eq!(refusal_of(&with(other)), None);
}

#[test]
fn geo_has_an_absolute_clean_path_and_a_sha256_of_64_lower_case_digits() {
    pass(&[geo("/a", GEO_SHA256)]);
    pass(&[geo(&format!("/{}", "a".repeat(4000)), GEO_SHA256)]);
    let path = "geo country_db is not an absolute clean path";
    let long = format!("/{}", "a".repeat(4096));
    for bad in ["", "a.mmdb", "/a/../b", "/a//b", "/a/", "/a/./b", &long] {
        refuse(&[geo(bad, GEO_SHA256)], path);
    }
    let digits = "geo sha256 is not 64 lower-case hexadecimal digits";
    let (short, long, upper) = (
        &GEO_SHA256[1..],
        format!("{GEO_SHA256}a"),
        GEO_SHA256.to_uppercase(),
    );
    let (not_hex, newline) = (format!("{short}g"), format!("{GEO_SHA256}\n"));
    for bad in ["", short, &long, &upper, &not_hex, &newline, MARK] {
        refuse(&[geo("/a", bad)], digits);
    }
    // Both keys, an object, and nothing else.
    let wrong = "configuration has a value of the wrong type";
    refuse(
        &[("", "geo", serde_json::json!({"country_db": "/a"}))],
        "configuration has a missing key",
    );
    refuse(
        &[("", "geo", serde_json::json!({"sha256": GEO_SHA256}))],
        "configuration has a missing key",
    );
    refuse(
        &[(
            "",
            "geo",
            serde_json::json!({"country_db": "/a", "sha256": GEO_SHA256, "url": "x"}),
        )],
        "configuration has an unknown key",
    );
    for bad in [Value::Null, serde_json::json!([]), serde_json::json!("/a")] {
        refuse(&[("", "geo", bad)], wrong);
    }
}

fn hex(bytes: [u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Loads the base document with these edits from a file in `dir`.
fn loaded_from(dir: &TestDir, edits: &[Edit]) -> Result<Loaded, ConfigError> {
    let file = dir.path().join("config.json");
    fs::write(&file, doc(edits)).unwrap();
    load(&file)
}

#[test]
fn load_reads_the_country_database_checks_its_sha256_and_keeps_it_only_for_a_list_of_countries() {
    let dir = scratch();
    let db = dir.path().join("country.mmdb");
    let path = db.to_str().unwrap().to_owned();
    let file = database(true, 24, &[("203.0.113.0/24", Record::Country("JP"))]);
    fs::write(&db, &file).unwrap();
    let sha = hex(crate::rules::bundle::sha256(&file));
    let lists = countries_access(serde_json::json!(["JP"]), serde_json::json!([]));

    let loaded = loaded_from(&dir, &[geo(&path, &sha), lists.clone()]).unwrap();
    let country = loaded.policy.country.expect("the database is kept");
    assert_eq!(
        country.country("203.0.113.9".parse().unwrap()),
        Country::Known(*b"JP")
    );
    // It is read and checked also where no list needs it, and then it is not kept.
    let loaded = loaded_from(&dir, &[geo(&path, &sha)]).unwrap();
    assert_eq!(
        (loaded.policy.country, loaded.policy.geo.is_some()),
        (None, true)
    );
    let route = serde_json::json!({"upstream": "api", "access": {"allow_countries": ["JP"]}});
    let by_route = [geo(&path, &sha), f("routes", Value::Array(vec![route]))];
    assert!(
        loaded_from(&dir, &by_route)
            .unwrap()
            .policy
            .country
            .is_some()
    );

    // A file with another sha256, the same one in capitals not being the same string either.
    let other = hex(crate::rules::bundle::sha256(b"other"));
    let sha_sentence = "geo country_db does not have the sha256 that geo gives";
    for edits in [vec![lists.clone()], Vec::new()] {
        let mut all = vec![geo(&path, &other)];
        all.extend(edits);
        assert_eq!(
            loaded_from(&dir, &all).err().map(|e| e.0),
            Some(sha_sentence)
        );
    }
    // A file that is not there, a link to the file, a directory, and a file one byte over 256 MiB.
    let unreadable = "geo country_db cannot be read, or is a link";
    let not_regular = "geo country_db is not a regular file of at most 256 MiB";
    let refused = |path: &Path, sha: &str| {
        let edits = [geo(path.to_str().unwrap(), sha), lists.clone()];
        loaded_from(&dir, &edits).err().map(|e| e.0)
    };
    assert_eq!(
        refused(&dir.path().join("absent.mmdb"), &sha),
        Some(unreadable)
    );
    let link = dir.path().join("link.mmdb");
    std::os::unix::fs::symlink(&db, &link).unwrap();
    assert_eq!(refused(&link, &sha), Some(unreadable));
    assert_eq!(refused(dir.path(), &sha), Some(not_regular));
    let big = dir.path().join("big.mmdb");
    fs::File::create(&big)
        .unwrap()
        .set_len((256 << 20) + 1)
        .unwrap();
    assert_eq!(refused(&big, &sha), Some(not_regular));

    // A file whose sha256 is right but which is cut, and one that is not a database of countries.
    let cut = dir.path().join("cut.mmdb");
    fs::write(&cut, &file[..file.len() / 2]).unwrap();
    let sha_cut = hex(crate::rules::bundle::sha256(&file[..file.len() / 2]));
    assert_eq!(
        refused(&cut, &sha_cut),
        Some("the country database has no metadata section")
    );
    let isp = dir.path().join("isp.mmdb");
    let not_countries = database_of(
        "GeoIP2-ISP",
        true,
        24,
        &[("203.0.113.0/24", Record::Neither)],
    );
    fs::write(&isp, &not_countries).unwrap();
    assert_eq!(
        refused(&isp, &hex(crate::rules::bundle::sha256(&not_countries))),
        Some("the country database is not of countries: it has no country records")
    );
}

// ---- admin ----

fn admin_object() -> Value {
    serde_json::json!({
        "listen": "127.0.0.1:9190",
        "control": "/run/tukuyomi/control.sock",
        "store": {"kind": "file", "dir": "/var/lib/tukuyomi/admin"},
        "origin": "https://admin.example.test",
        "trusted_proxies": ["127.0.0.1/32"],
        "mfa": "optional",
        "session_idle_ms": 1_800_000,
        "session_total_ms": 43_200_000,
        "crs_dir": "/var/lib/tukuyomi/crs",
    })
}

fn admin(key: &str, value: impl Into<Value>) -> Edit {
    let mut object = admin_object();
    object[key] = value.into();
    ("", "admin", object)
}

fn admin_without(key: &str) -> Edit {
    let mut object = admin_object();
    object.as_object_mut().unwrap().remove(key);
    ("", "admin", object)
}

#[test]
fn the_admin_object_is_left_out_or_has_every_key_checked() {
    assert!(parse(BASE.as_bytes()).unwrap().admin.is_none());
    let loaded = parse(&doc(&[("", "admin", admin_object())])).unwrap();
    assert_eq!(
        loaded.admin,
        Some(AdminConfig {
            listen: "127.0.0.1:9190".parse().unwrap(),
            control: PathBuf::from("/run/tukuyomi/control.sock"),
            store: AdminStoreConfig::File {
                dir: PathBuf::from("/var/lib/tukuyomi/admin")
            },
            origin: "https://admin.example.test".to_string(),
            trusted_proxies: vec![Cidr::parse("127.0.0.1/32").unwrap()],
            mfa: Mfa::Optional,
            session_idle: Duration::from_millis(1_800_000),
            session_total: Duration::from_millis(43_200_000),
            crs_dir: Some(PathBuf::from("/var/lib/tukuyomi/crs")),
        })
    );
    // `crs_dir` may be left out, and the proxy does not look at the other values as the admin process does.
    assert_eq!(
        parse(&doc(&[admin_without("crs_dir")]))
            .unwrap()
            .admin
            .unwrap()
            .crs_dir,
        None
    );
    pass(&[admin("mfa", "required")]);

    // The object is whole, and an object, and not null.
    refuse(
        &[admin_without("control")],
        "configuration has a missing key",
    );
    refuse(&[admin("tls", true)], "configuration has an unknown key");
    refuse(
        &[admin("crs_dir", Value::Null)],
        "configuration has a value of the wrong type",
    );
    refuse(
        &[("", "admin", serde_json::json!(["127.0.0.1:9190"]))],
        "configuration has a value of the wrong type",
    );
    refuse(
        &[("", "admin", Value::Null)],
        "configuration has a value of the wrong type",
    );
}

#[test]
fn the_admin_listen_address_is_loopback_and_clashes_with_no_listener_and_not_with_the_status_listener()
 {
    let not_loopback = "admin listen is not a loopback address";
    for listen in [
        "0.0.0.0:9190",
        "[::]:9190",
        "192.0.2.1:9190",
        "[::ffff:127.0.0.1]:9190",
    ] {
        refuse(&[admin("listen", listen)], not_loopback);
    }
    pass(&[admin("listen", "[::1]:9190")]);
    refuse(
        &[admin("listen", "localhost:9190")],
        "admin listen is not an IP address and port",
    );
    refuse(&[admin("listen", "127.0.0.1:0")], "admin listen port is 0");

    let clash = "admin listen is the address of a listener or of the status listener, or one is an unspecified address at the port of the other";
    refuse(&[admin("listen", "127.0.0.1:8080")], clash);
    let (at_unspecified, listen) = (at("0.0.0.0:9190"), admin("listen", "127.0.0.1:9190"));
    refuse(&[at_unspecified, listen.clone()], clash);
    refuse(&[at("[::]:9190"), admin("listen", "[::1]:9190")], clash);
    pass(&[at("0.0.0.0:9191"), listen.clone()]);
    // The status listener and the admin listener cannot share an address either.
    refuse(&[status("127.0.0.1:9190"), listen.clone()], clash);
    pass(&[status("127.0.0.1:9191"), listen]);
}

#[test]
fn an_upstream_server_may_be_at_the_admin_listen_address() {
    // The route to the admin process is the way in from outside, unlike a route to a listener or the status listener.
    pass(&[
        admin("listen", "127.0.0.1:9190"),
        sv("address", "127.0.0.1:9190"),
    ]);
    refuse(
        &[
            admin("listen", "127.0.0.1:9190"),
            sv("address", "127.0.0.1:8080"),
        ],
        "a listener and a server are the same address",
    );
}

#[test]
fn the_admin_paths_and_the_origin_are_clean_and_within_their_limits() {
    let control = "admin control is not an absolute clean path of at most 107 bytes";
    pass(&[admin("control", format!("/run/{}", "c".repeat(102)))]);
    refuse(
        &[admin("control", format!("/run/{}", "c".repeat(103)))],
        control,
    );
    for bad in [
        "control.sock",
        "/run/../control.sock",
        "/run//control.sock",
        "/run/control.sock/",
    ] {
        refuse(&[admin("control", bad)], control);
    }

    let dir = "admin store dir is not an absolute clean path of at most 3840 bytes";
    let store =
        |kind: &str, dir: String| admin("store", serde_json::json!({"kind": kind, "dir": dir}));
    pass(&[store("file", format!("/{}", "d".repeat(3839)))]);
    refuse(&[store("file", format!("/{}", "d".repeat(3840)))], dir);
    refuse(&[store("file", "admin".to_string())], dir);
    refuse(
        &[store("db", "/var/lib/tukuyomi/admin".to_string())],
        "admin store kind is not supported",
    );
    let crs = "admin crs_dir is not an absolute clean path of at most 3840 bytes";
    pass(&[admin("crs_dir", format!("/{}", "d".repeat(3839)))]);
    refuse(&[admin("crs_dir", format!("/{}", "d".repeat(3840)))], crs);
    refuse(&[admin("crs_dir", "crs")], crs);

    let origin = "admin origin is not https:// and a host with an optional port";
    for good in [
        "https://admin.example.test",
        "https://admin.example.test:8443",
        "https://localhost",
    ] {
        pass(&[admin("origin", good)]);
    }
    for bad in [
        "http://admin.example.test",
        "admin.example.test",
        "https://",
        "https://admin.example.test/",
        "https://admin.example.test/x",
        "https://admin.example.test?x=1",
        "https://admin.example.test:0",
        "https://admin.example.test:65536",
        "https://*.example.test",
        "https://Admin.example.test",
        "https://admin.example.test.",
        "https://user@admin.example.test",
    ] {
        refuse(&[admin("origin", bad)], origin);
    }
}

#[test]
fn the_admin_trusted_networks_mfa_and_session_times_are_within_their_limits() {
    let many = "admin trusted_proxies has more than 256 entries";
    pass(&[admin("trusted_proxies", vec!["10.0.0.0/8"; 256])]);
    refuse(&[admin("trusted_proxies", vec!["10.0.0.0/8"; 257])], many);
    refuse(
        &[admin("trusted_proxies", vec!["10.0.0.1/8"])],
        "admin trusted_proxies has an entry that is not a network",
    );
    pass(&[admin("trusted_proxies", Vec::<String>::new())]);
    refuse(
        &[admin("mfa", "off")],
        "admin mfa is not optional or required",
    );

    // The two times together: the total may not be below the idle time.
    let sessions = |idle: u64, total: u64| {
        let mut object = admin_object();
        object["session_idle_ms"] = idle.into();
        object["session_total_ms"] = total.into();
        ("", "admin", object)
    };
    let idle = "admin session_idle_ms is not 1 minute to 24 hours";
    pass(&[sessions(60_000, 60_000)]);
    pass(&[sessions(86_400_000, 86_400_000)]);
    refuse(&[sessions(59_999, 1_800_000)], idle);
    refuse(&[sessions(86_400_001, 604_800_000)], idle);
    let total = "admin session_total_ms is not session_idle_ms to 7 days";
    pass(&[sessions(1_800_000, 604_800_000)]);
    refuse(&[sessions(1_800_000, 1_799_999)], total);
    refuse(&[sessions(1_800_000, 604_800_001)], total);
}

#[test]
fn the_rules_store_the_records_the_admin_store_and_the_control_socket_are_in_places_apart() {
    let inside =
        "admin control is inside the rules store dir, the records dir or the admin store dir";
    let apart = "the rules store dir, the records dir, the admin store dir and the directory of admin control are the same or inside one another";
    let with_records = records("dir", "/var/lib/tukuyomi/records");
    pass(&[with_records.clone(), admin("mfa", "optional")]);

    // The socket in the directory of the records, of the admin store or of the rules store.
    for dir in ["records", "admin", "rules"] {
        let control = admin("control", format!("/var/lib/tukuyomi/{dir}/control.sock"));
        refuse(&[with_records.clone(), control], inside);
    }
    // The directory of the socket has the other places inside it, or is one of them.
    refuse(&[admin("control", "/var/lib/tukuyomi/control.sock")], apart);
    refuse(
        &[admin(
            "store",
            serde_json::json!({"kind": "file", "dir": "/var/lib/tukuyomi/rules/admin"}),
        )],
        apart,
    );
    // Two places the same, or one inside another; a name that only starts with the other one is no place inside it.
    refuse(&[records("dir", "/var/lib/tukuyomi/rules")], apart);
    refuse(&[records("dir", "/var/lib/tukuyomi/rules/records")], apart);
    refuse(&[records("dir", "/var/lib/tukuyomi")], apart);
    refuse(
        &[
            with_records.clone(),
            admin(
                "store",
                serde_json::json!({"kind": "file", "dir": "/var/lib/tukuyomi/records"}),
            ),
        ],
        apart,
    );
    pass(&[records("dir", "/var/lib/tukuyomi/rules2")]);
}
