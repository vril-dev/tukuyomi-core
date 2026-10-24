use super::*;
use serde_json::Value;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::sync::atomic::{AtomicU32, Ordering};

const BASE: &str = r#"{"proxy":{"listeners":[{"address":"127.0.0.1:8080"}],"max_conns":1024,"max_head_bytes":8192,"max_body":1048576,"max_body_wire":2097152,"max_buffered_bytes":8388608,"upstream_max_headers":100,"upstream_max_head_bytes":16384,"upstream_head_wire":65536,"drive_slice_ms":50,"ready_wait_ms":10000,"head_read_ms":10000,"body_read_ms":30000,"inspect_wait_ms":30000,"upstream_connect_ms":5000,"upstream_header_ms":30000,"request_total_ms":60000,"response_idle_ms":60000,"conn_total_ms":120000,"stop_inspect_ms":5000,"stop_wait_ms":10000,"keepalive_timeout_ms":75000,"keepalive_requests":1000,"keepalive_time_ms":60000,"lingering_time_ms":30000,"lingering_timeout_ms":5000,"lingering_bytes":262144,"trusted_proxies":[],"upstream_keepalive":32,"upstream_keepalive_timeout_ms":60000,"upstream_keepalive_requests":1000},"forward":{"resolve_timeout_ms":30000,"upstreams":{"main":{"servers":[{"address":"127.0.0.1:9000","weight":1,"max_fails":1,"fail_timeout_ms":10000,"backup":false}]},"api":{"servers":[{"address":"127.0.0.1:9001","weight":3,"max_fails":2,"fail_timeout_ms":5000,"backup":false},{"address":"127.0.0.1:9002","weight":1,"max_fails":0,"fail_timeout_ms":5000,"backup":true}]}},"routes":[{"host":"api.example.test","path":"/v1/","upstream":"api"}],"default_upstream":"main"},"kernel":{"inspector":"/opt/tukuyomi/inspector","tmp_root":"/var/lib/tukuyomi/tmp","gomaxprocs":2,"gomemlimit":1073741824,"slots":4,"wait_queue":16,"records":20,"discard_limit":4,"tick_ms":100,"hello_wait_ms":5000,"frame_io_ms":1000,"verdict_wait_ms":2000,"wait_deadline_ms":3000,"closed_wait_ms":2000,"stop_after_ms":2000,"drain_wait_ms":1000,"exit_wait_ms":1000,"kill_grace_ms":1000,"restarts":3,"restart_window_ms":60000},"rules":{"store":{"kind":"file","dir":"/var/lib/tukuyomi/rules"}}}"#;

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

    refuse(
        &[p("max_body", (1u64 << 20) + 1)],
        "max_body is above the body limit",
    );
    pass(&[p("max_body", 1u64 << 20)]);

    // max_body_wire: from max_body (1 MiB here) to 4 MiB.
    let key = "max_body_wire";
    refuse(&[p(key, (1u64 << 20) - 1)], &out(key));
    pass(&[p(key, 1u64 << 20)]);
    pass(&[p(key, 4u64 << 20)]);
    refuse(&[p(key, (4u64 << 20) + 1)], &out(key));

    // max_buffered_bytes: from 2 * max_body + 24 KiB to 4 GiB.
    let key = "max_buffered_bytes";
    let least = 2 * (1u64 << 20) + 24 * 1024;
    refuse(&[p(key, least - 1)], &out(key));
    pass(&[p(key, least)]);
    pass(&[p(key, 4u64 << 30)]);
    refuse(&[p(key, (4u64 << 30) + 1)], &out(key));

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
    let permits = |text: &str| access.permits(text.parse().unwrap());
    // Deny first; then only the networks of allow.
    assert!(!permits("10.1.2.3"));
    assert!(permits("192.0.2.5"));
    assert!(!permits("198.51.100.1"));
    let empty = access_of(&route(serde_json::json!({})));
    assert!(empty.permits("203.0.113.1".parse().unwrap()));

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
