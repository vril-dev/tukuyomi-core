use std::fs;

use serde_json::json;

use super::*;
use crate::config::{Built, HostRateLimit, Routing};
use crate::forward::client_ip::Access;
use crate::managed::store::tests::Fixture;
use crate::managed::{Choice, LoadError};

const NAME: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// The sites of a version, as `sites` checks them.
fn checked(sites: Value) -> Result<Vec<Site>, ConfigError> {
    let raw: Vec<Object<RawSite<StoredCertificate>>> =
        serde_json::from_value(sites).map_err(|e| config::refusal(&e))?;
    super::sites(raw).map_err(|(e, _)| e)
}

fn site(name: &str, hosts: &[&str]) -> Value {
    json!({"name": name, "hosts": hosts, "certificate": {"chain": NAME, "key": NAME}})
}

fn refused(sites: Value) -> &'static str {
    checked(sites).expect_err("refused").0
}

#[test]
fn there_are_0_to_64_sites_with_a_name_each_and_a_host_in_one_site_only() {
    let many = |n: usize| {
        Value::Array(
            (0..n)
                .map(|i| site(&format!("s{i}"), &[&format!("h{i}.test")]))
                .collect(),
        )
    };
    assert_eq!(checked(many(64)).unwrap().len(), 64);
    assert_eq!(refused(many(65)), "sites has more than 64 sites");
    assert!(checked(many(0)).unwrap().is_empty());
    assert_eq!(
        refused(json!([site("a", &["a.test"]), site("a", &["b.test"])])),
        "a site name is written twice"
    );
    assert_eq!(
        refused(json!([
            site("a", &["*.example.test"]),
            site("b", &["*.example.test"])
        ])),
        "a site host is written twice in the sites"
    );
    // A wildcard and a name under it are two hosts.
    assert!(
        checked(json!([
            site("a", &["*.example.test"]),
            site("b", &["www.example.test"])
        ]))
        .is_ok()
    );
    assert_eq!(
        refused(json!([site("a", &["A.test"])])),
        "a site host is not a name, or * and a name"
    );
    let mut short = site("a", &["a.test"]);
    short["certificate"]["key"] = json!(&NAME[1..]);
    assert_eq!(
        refused(json!([short])),
        "a site chain or key is not 64 lower-case hexadecimal digits"
    );
}

#[test]
fn a_site_certificate_is_chain_and_key_or_acme_and_nothing_else() {
    let with = |hosts: &[&str], certificate: Value| json!([{"name": "a", "hosts": hosts, "certificate": certificate}]);
    let acme = |days: u64| json!({"acme": {"renew_before_days": days}});
    let sites = checked(with(&["a.test", "b.test"], acme(60))).unwrap();
    assert_eq!(
        sites[0].certificate,
        SiteCertificate::Acme(CertificateAcme {
            renew_before_days: 60
        })
    );
    assert_eq!(sites[0].certificate.files(), None);
    assert_eq!(
        refused(with(&["a.test"], acme(61))),
        "acme renew_before_days is not 1 to 60"
    );
    // HTTP-01 proves a name, not a wildcard.
    assert_eq!(
        refused(with(&["a.test", "*.a.test"], acme(30))),
        "a certificate with acme has a wildcard host"
    );
    let neither = "a site certificate is neither chain and key nor acme";
    for certificate in [
        json!({"chain": NAME, "key": NAME, "acme": {"renew_before_days": 30}}),
        json!({"chain": NAME, "acme": {"renew_before_days": 30}}),
        json!({"chain": NAME}),
        json!({}),
    ] {
        assert_eq!(refused(with(&["a.test"], certificate)), neither);
    }
    assert_eq!(
        refused(with(&["a.test"], json!({"chain": NAME, "key": null}))),
        "configuration has a value of the wrong type"
    );
}

#[test]
fn a_document_becomes_the_version_that_names_its_files_by_their_sha256() {
    let document = json!({
        "sites": [{"name": "a", "hosts": ["a.test"], "certificate": {"chain_file": "/d/a.pem", "key_file": "/d/a.key"}}],
        "upstreams": {"app": {
            "servers": [{"address": "127.0.0.1:9443", "weight": 1, "max_fails": 1, "fail_timeout_ms": 1000, "backup": false}],
            "tls": {"ca_file": "/d/ca.pem", "server_name": "app.test"},
        }},
        "routes": [],
        "default_upstream": "app",
    });
    // Any form: with white space.
    let bytes = serde_json::to_vec_pretty(&document).unwrap();
    assert!(parse_document(&bytes).is_ok());
    let names = BTreeMap::from([
        (PathBuf::from("/d/a.pem"), [1; 32]),
        (PathBuf::from("/d/a.key"), [2; 32]),
        (PathBuf::from("/d/ca.pem"), [3; 32]),
    ]);
    let version = version_of(&bytes, &names).unwrap();
    assert!(parse(&version).is_ok());
    let value: Value = serde_json::from_slice(&version).unwrap();
    assert_eq!(
        value["sites"][0]["certificate"],
        json!({"chain": hex(&[1; 32]), "key": hex(&[2; 32])})
    );
    assert_eq!(
        value["upstreams"]["app"]["tls"],
        json!({"ca": hex(&[3; 32]), "server_name": "app.test"})
    );
    // A document that names a file the store does not have makes no version.
    let fewer = BTreeMap::from([(PathBuf::from("/d/a.pem"), [1; 32])]);
    assert_eq!(
        version_of(&bytes, &fewer).err(),
        Some(ConfigError(
            "the managed document cannot be made into a version"
        ))
    );
    // A site with acme names no file, and is in the version as the document writes it.
    let mut issued = document.clone();
    issued["sites"][0]["certificate"] = json!({"acme": {"renew_before_days": 30}});
    let bytes = serde_json::to_vec(&issued).unwrap();
    assert!(parse_document(&bytes).is_ok());
    let version = version_of(&bytes, &names).unwrap();
    assert!(parse(&version).is_ok());
    let value: Value = serde_json::from_slice(&version).unwrap();
    assert_eq!(
        value["sites"][0]["certificate"],
        json!({"acme": {"renew_before_days": 30}})
    );
    // A document names its files by their paths only.
    let mut stored = document.clone();
    stored["sites"][0]["certificate"] = json!({"chain": NAME, "key": NAME});
    assert_eq!(
        parse_document(&serde_json::to_vec(&stored).unwrap()).err(),
        Some(ConfigError("configuration has an unknown key"))
    );
}

/// The main file of `fixture`, with the way to the admin process for `admin.test`, checked.
fn with_admin(fixture: &Fixture) -> Built {
    let path = fixture.main_file(|m| {
        m["admin"] = json!({
            "listen": "127.0.0.1:9180", "control": "/run/tukuyomi/admin.sock",
            "store": {"kind": "file", "dir": "/var/lib/tukuyomi/admin"}, "origin": "https://admin.test",
            "trusted_proxies": [], "mfa": "optional", "session_idle_ms": 600_000, "session_total_ms": 3_600_000,
            "route": {
                "host": "admin.test",
                "certificate": {"cert_file": "/etc/tukuyomi/admin.pem", "key_file": "/etc/tukuyomi/admin.key"},
                "access": {"allow_cidrs": ["192.0.2.0/24"]},
            },
        });
    });
    config::main_file(&fs::read(path).unwrap()).unwrap()
}

/// The refusal of `version` by the check of the admin process: its sentence and its place.
fn objection(built: &Built, version: &Value) -> (&'static str, Option<String>) {
    let Routing::Managed { resolve_timeout } = built.routing else {
        panic!("the main file has no managed object");
    };
    let bytes = serde_json::to_vec(version).unwrap();
    match check_sent(&bytes, &built.main, resolve_timeout, None) {
        Err(objection) => (objection.why, objection.at),
        Ok(_) => panic!("accepted"),
    }
}

/// The refusal of the body `body` by the reading of the admin process: its sentence and its place.
fn unread(body: &str) -> (&'static str, Option<String>) {
    match sent(body.as_bytes()) {
        Err(objection) => (objection.why, objection.at),
        Ok(_) => panic!("accepted"),
    }
}

fn server(address: &str) -> Value {
    json!({"address": address, "weight": 1, "max_fails": 1, "fail_timeout_ms": 1000, "backup": false})
}

fn at(path: &str) -> Option<String> {
    Some(path.to_owned())
}

#[test]
fn a_refusal_of_a_sent_version_is_about_the_item_and_the_key_it_is_about() {
    let fixture = Fixture::new();
    let built = with_admin(&fixture);
    let base = fixture.plain_version(b"chain", b"key");
    let refused = |edit: &dyn Fn(&mut Value)| {
        let mut version = base.clone();
        edit(&mut version);
        objection(&built, &version)
    };
    let push = |version: &mut Value, key: &str, item: Value| {
        version[key].as_array_mut().unwrap().push(item);
    };
    assert_eq!(
        refused(&|v| push(
            v,
            "sites",
            json!({"name": "b", "hosts": ["A.test"], "certificate": {"chain": NAME, "key": NAME}})
        )),
        (
            "a site host is not a name, or * and a name",
            at("sites[1].hosts[0]")
        )
    );
    // The groups are in the byte order of their names: `app`, then `g1`.
    assert_eq!(
        refused(&|v| v["upstreams"]["g1"] = json!({"servers": [
            server("127.0.0.1:9001"), server("127.0.0.1:9002"), server("0.0.0.0:9003"),
        ]})),
        (
            "a server address is unspecified or a multicast address",
            at("upstreams.g1.servers[2].address")
        )
    );
    assert_eq!(
        refused(&|v| {
            for path in ["/a", "/b", "/c", "d"] {
                push(v, "routes", json!({"path": path, "upstream": "app"}));
            }
        }),
        ("a route path does not start with /", at("routes[3].path"))
    );
    assert_eq!(
        refused(&|v| v["rate_limit"] = json!({"rate": 10, "burst": 0, "keys": 10})),
        (
            "rate_limit keys is not 1024 to 1048576",
            at("rate_limit.keys")
        )
    );
    // A rule that the version breaks with the main file.
    assert_eq!(
        refused(&|v| push(
            v,
            "routes",
            json!({"host": "admin.test:8443", "upstream": "app"})
        )),
        (
            "a route host is the host of the admin route",
            at("routes[0].host")
        )
    );
    // A group whose name is not a name is not named in the place.
    assert_eq!(
        refused(&|v| v["upstreams"]["bad name"] = json!({"servers": [server("127.0.0.1:9001")]})),
        (
            "an upstream name is not 1 to 64 letters, digits, - and _",
            at("upstreams")
        )
    );
}

#[test]
fn a_sent_version_that_cannot_be_read_is_refused_about_the_first_item_that_cannot() {
    let site = |name: Value| json!({"name": name, "hosts": ["a.test"], "certificate": {"chain": NAME, "key": NAME}});
    let body = |sites: Value, routes: Value, upstreams: Value| {
        json!({"version": {"sites": sites, "upstreams": upstreams, "routes": routes, "default_upstream": "app"}})
            .to_string()
    };
    let groups = || json!({"app": {"servers": [server("127.0.0.1:9000")]}});
    let wrong = "configuration has a value of the wrong type";
    assert_eq!(
        unread(&body(
            json!([site(json!("a")), site(json!(5))]),
            json!([]),
            groups()
        )),
        (wrong, at("sites[1]"))
    );
    // `routes` comes before `sites` in the text, and the first reading stops at its unknown key; the sentence and the
    // place are both those of the first item in the order of the check.
    let both = body(
        json!([site(json!("a")), site(json!(5))]),
        json!([{"upstream": "app", "colour": "red"}]),
        groups(),
    );
    assert!(both.find("\"routes\"") < both.find("\"sites\""));
    assert_eq!(unread(&both), (wrong, at("sites[1]")));
    let mut unnamed = groups();
    unnamed["bad name"] = json!({"servers": 5});
    assert_eq!(
        unread(&body(json!([]), json!([]), unnamed)),
        (wrong, at("upstreams"))
    );
    assert_eq!(
        unread(r#"{"version": {"sites": [], "upstreams": {}, "default_upstream": "app"}}"#),
        ("configuration has a missing key", at("routes"))
    );
    assert_eq!(
        unread(
            r#"{"version": {"sites": [], "upstreams": {}, "routes": [{"upstream": "a", "upstream": "b"}], "default_upstream": "app"}}"#
        ),
        ("configuration has a repeated key", None)
    );
}

#[test]
fn the_engine_of_a_group_is_checked_with_the_main_file_and_a_refusal_is_about_its_engine() {
    let fixture = Fixture::new();
    let plain = with_admin(&fixture);
    let named = {
        let path = fixture.main_file(|m| {
            m["kernel"]["engines"] =
                json!({"modsecurity": {"inspector": "/opt/tukuyomi/inspector-modsecurity"}});
        });
        config::main_file(&fs::read(path).unwrap()).unwrap()
    };
    let base = fixture.plain_version(b"chain", b"key");
    let with = |engine: Value| {
        let mut version = base.clone();
        version["upstreams"]["app"]["engine"] = engine;
        version
    };
    // The two names are taken, with an inspector in the main file for each.
    let Routing::Managed { resolve_timeout } = named.routing else {
        panic!("the main file has no managed object");
    };
    for name in ["coraza", "modsecurity"] {
        let bytes = serde_json::to_vec(&with(json!(name))).unwrap();
        let checked = check_sent(&bytes, &named.main, resolve_timeout, None).unwrap();
        assert_eq!(checked.forward.groups[0].engine.name(), name);
    }
    // The name is the lowercase one, exactly, and the engine has to be one the main file has an inspector for.
    let bad = "an upstream engine is not coraza or modsecurity";
    for name in ["Coraza", ""] {
        assert_eq!(
            objection(&plain, &with(json!(name))),
            (bad, at("upstreams.app.engine"))
        );
    }
    assert_eq!(
        objection(&plain, &with(json!("modsecurity"))),
        (
            "kernel.engines has no inspector for the engine of an upstream",
            at("upstreams.app.engine")
        )
    );
    // A group that has a server at the address of a group before it has the engine of that one: the later group is
    // the one that the refusal is about.
    let mut version = base.clone();
    version["upstreams"]["g1"] =
        json!({"servers": [server("127.0.0.1:9000")], "engine": "modsecurity"});
    assert_eq!(
        objection(&named, &version),
        (
            "two upstreams with a server at the same address have different engines",
            at("upstreams.g1.engine")
        )
    );
    version["upstreams"]["g1"]["servers"] = json!([server("127.0.0.1:9001")]);
    let bytes = serde_json::to_vec(&version).unwrap();
    assert!(check_sent(&bytes, &named.main, resolve_timeout, None).is_ok());
    // A value that is not text is refused about the group when the version is read item by item.
    let body = json!({"version": with(json!(5))}).to_string();
    assert_eq!(
        unread(&body),
        (
            "configuration has a value of the wrong type",
            at("upstreams.app")
        )
    );
}

/// A host policy named `name` for the hosts `hosts`, with an `access` that turns nobody away.
fn host_policy(name: &str, hosts: Value) -> Value {
    json!({"name": name, "hosts": hosts, "access": {}})
}

/// The policy of `version`, which the check of the admin process accepts.
fn accepted(built: &Built, version: &Value) -> PolicyConfig {
    let Routing::Managed { resolve_timeout } = built.routing else {
        panic!("the main file has no managed object");
    };
    let bytes = serde_json::to_vec(version).unwrap();
    match check_sent(&bytes, &built.main, resolve_timeout, None) {
        Ok(checked) => checked.policy,
        Err(objection) => panic!("refused: {} at {:?}", objection.why, objection.at),
    }
}

#[test]
fn the_host_policies_are_bounded_and_a_refusal_is_about_the_policy_the_host_or_the_key() {
    let fixture = Fixture::new();
    let built = with_admin(&fixture);
    let base = fixture.plain_version(b"chain", b"key");
    let with = |policies: Value| {
        let mut version = base.clone();
        version["host_policies"] = policies;
        version
    };
    let hosts = |from: usize, n: usize| {
        json!(
            (from..from + n)
                .map(|i| format!("h{i}.test"))
                .collect::<Vec<_>>()
        )
    };
    let many = |count: usize, each: usize| {
        Value::Array(
            (0..count)
                .map(|i| host_policy(&format!("p{i}"), hosts(i * each, each)))
                .collect(),
        )
    };
    // 64 policies, 64 hosts in one and 1024 in all pass, and one more of each is refused.
    accepted(&built, &with(many(64, 1)));
    assert_eq!(
        objection(&built, &with(many(65, 1))),
        (
            "host_policies has more than 64 entries",
            at("host_policies")
        )
    );
    accepted(&built, &with(many(1, 64)));
    assert_eq!(
        objection(&built, &with(many(1, 65))),
        (
            "a host policy has no host or more than 64",
            at("host_policies[0].hosts")
        )
    );
    let mut all = many(16, 64);
    accepted(&built, &with(all.clone()));
    all.as_array_mut()
        .unwrap()
        .push(host_policy("last", hosts(2000, 1)));
    assert_eq!(
        objection(&built, &with(all)),
        (
            "the host policies have more than 1024 hosts in all",
            at("host_policies[16].hosts[0]")
        )
    );

    // The keys of the configuration and of the policies with a table of their own are 1048576 at most together; a
    // policy whose rate limit is off counts none.
    let limited = |name: &str, host: &str, rate_limit: Value| json!({"name": name, "hosts": [host], "rate_limit": rate_limit});
    let keys = |keys: usize| json!({"rate": 10, "burst": 0, "keys": keys});
    let mut version = with(json!([
        limited("a", "a.test", keys(1024)),
        limited("b", "b.test", keys(1024)),
        limited("c", "c.test", json!({})),
    ]));
    version["rate_limit"] = keys((1 << 20) - 2048);
    accepted(&built, &version);
    version["host_policies"][1]["rate_limit"]["keys"] = json!(1025);
    assert_eq!(
        objection(&built, &version),
        (
            "the rate limits keep count of more than 1048576 clients in all",
            at("host_policies[1].rate_limit.keys")
        )
    );

    // A host is the host of a route without a port, and not the host of the way to the admin process, which a `*.`
    // host may cover, for the name comes first.
    let one = |policy: Value| objection(&built, &with(json!([policy])));
    assert_eq!(
        one(host_policy("a", json!(["a.test", "b.test", "c.test:8443"]))),
        (
            "a host policy host is malformed or has a port",
            at("host_policies[0].hosts[2]")
        )
    );
    assert_eq!(
        one(host_policy("a", json!(["admin.test"]))),
        (
            "a host policy host is the host of the admin route",
            at("host_policies[0].hosts[0]")
        )
    );
    accepted(&built, &with(json!([host_policy("a", json!(["*.test"]))])));
    let two = |a: Value, b: Value| objection(&built, &with(json!([a, b])));
    assert_eq!(
        two(
            host_policy("a", json!(["a.test"])),
            host_policy("a", json!(["b.test"]))
        ),
        (
            "a host policy name is written twice",
            at("host_policies[1].name")
        )
    );
    assert_eq!(
        two(
            host_policy("a", json!(["a.test"])),
            host_policy("b", json!(["a.test"]))
        ),
        (
            "a host policy host is written twice in the host policies",
            at("host_policies[1].hosts[0]")
        )
    );

    // `{}` turns each off; a rate limit is that or the whole one, and a policy has one of the two at least.
    let off = accepted(&built, &with(json!([limited("a", "a.test", json!({}))])));
    assert_eq!(off.host_policies[0].rate_limit, HostRateLimit::Off);
    let open = accepted(&built, &with(json!([host_policy("a", json!(["a.test"]))])));
    assert_eq!(open.host_policies[0].access, Some(Access::default()));
    assert_eq!(
        one(limited(
            "a",
            "a.test",
            json!({"exempt_cidrs": ["10.0.0.0/8"]})
        )),
        (
            "a host policy rate_limit is neither empty nor rate, burst and keys",
            at("host_policies[0].rate_limit")
        )
    );
    assert_eq!(
        one(json!({"name": "a", "hosts": ["a.test"]})),
        (
            "a host policy has neither access nor rate_limit",
            at("host_policies[0]")
        )
    );
    assert_eq!(
        one(limited(
            "a",
            "a.test",
            json!({"rate": 0, "burst": 0, "keys": 1024})
        )),
        (
            "rate_limit rate is not 1 to 100000",
            at("host_policies[0].rate_limit.rate")
        )
    );

    // A list of countries needs `geo`: the one of a host policy is found before the one of a route.
    let mut countries =
        with(json!([{"name": "a", "hosts": ["a.test"], "access": {"deny_countries": ["JP"]}}]));
    countries["routes"] =
        json!([{"path": "/", "upstream": "app", "access": {"deny_countries": ["JP"]}}]);
    assert_eq!(
        objection(&built, &countries),
        (
            "access has a list of countries while geo is left out",
            at("host_policies[0].access")
        )
    );

    // A policy that cannot be read in its form is the item that is refused.
    let unreadable = with(json!([
        host_policy("a", json!(["a.test"])),
        {"name": 5, "hosts": ["b.test"], "access": {}},
    ]));
    assert_eq!(
        unread(&json!({ "version": unreadable }).to_string()),
        (
            "configuration has a value of the wrong type",
            at("host_policies[1]")
        )
    );
}

#[test]
fn the_proxy_takes_the_sentence_of_a_refusal_without_its_place() {
    let fixture = Fixture::new();
    let path = fixture.main_file(|_| {});
    let built = config::main_file(&fs::read(&path).unwrap()).unwrap();
    let mut version = fixture.plain_version(b"chain", b"key");
    version["upstreams"]["app"]["servers"][0]["address"] = json!("0.0.0.0:9000");
    let (why, place) = objection(&built, &version);
    assert_eq!(place, at("upstreams.app.servers[0].address"));
    let bytes = serde_json::to_vec(&version).unwrap();
    assert_eq!(
        crate::managed::load(&path, &Choice::Given(bytes)).err(),
        Some(LoadError::Version(ConfigError(why)))
    );
}

#[test]
fn a_refusal_about_a_path_regex_or_a_priority_is_about_that_key_of_its_route() {
    let fixture = Fixture::new();
    let built = with_admin(&fixture);
    let base = fixture.plain_version(b"chain", b"key");
    let refused = |routes: Vec<Value>| {
        let mut version = base.clone();
        version["routes"].as_array_mut().unwrap().extend(routes);
        objection(&built, &version)
    };
    let route = |keys: Value| {
        let mut route = json!({"upstream": "app"});
        for (key, value) in keys.as_object().unwrap() {
            route[key] = value.clone();
        }
        route
    };
    let list = json!({"deny_cidrs": ["10.0.0.0/8"]});
    for (keys, sentence, place) in [
        (
            json!({"path": "/a", "path_regex": "a"}),
            "a route has both a path and a path regex",
            "routes[0].path_regex",
        ),
        (
            json!({"path_regex": ""}),
            "a route path regex is not 1 to 255 bytes",
            "routes[0].path_regex",
        ),
        (
            json!({"path_regex": "a b"}),
            "a route path regex has a character that is not allowed",
            "routes[0].path_regex",
        ),
        (
            json!({"path_regex": "("}),
            "a route path regex is not a valid regular expression",
            "routes[0].path_regex",
        ),
        (
            json!({"path_regex": "(a{100}){100}"}),
            "a route path regex is too large",
            "routes[0].path_regex",
        ),
        (
            json!({"priority": 1001}),
            "a route priority is not -1000 to 1000",
            "routes[0].priority",
        ),
        (
            json!({"path_regex": "a", "access": list}),
            "a route with a path regex has an access list",
            "routes[0].access",
        ),
        (
            json!({"path_regex": "a", "rewrite": {"path": "/v2/"}}),
            "a rewrite path is set on a route with a path regex",
            "routes[0].rewrite.path",
        ),
    ] {
        assert_eq!(
            refused(vec![route(keys)]),
            (sentence, at(place)),
            "{sentence}"
        );
    }
    // The 33rd route that has a path regex is the one that is refused.
    let many = (0..33)
        .map(|i| route(json!({"path_regex": format!("^/r{i}$")})))
        .collect();
    assert_eq!(
        refused(many),
        (
            "routes has more than 32 entries with a path regex",
            at("routes[32].path_regex")
        )
    );
}

#[test]
fn a_refusal_about_the_balance_of_a_group_is_about_that_key_of_its_group() {
    let fixture = Fixture::new();
    let built = with_admin(&fixture);
    let base = fixture.plain_version(b"chain", b"key");
    let refused = |keys: Value| {
        let mut version = base.clone();
        for (key, value) in keys.as_object().unwrap() {
            version["upstreams"]["app"][key] = value.clone();
        }
        objection(&built, &version)
    };
    for (keys, sentence, place) in [
        (
            json!({"balance": "random"}),
            "an upstream balance is not round_robin, least_conn or hash",
            "upstreams.app.balance",
        ),
        (
            json!({"balance": "hash"}),
            "an upstream with balance hash has no hash_policy",
            "upstreams.app.hash_policy",
        ),
        (
            json!({"balance": "hash", "hash_policy": "jwt_sub"}),
            "an upstream hash_policy is not client_ip, header or cookie",
            "upstreams.app.hash_policy",
        ),
        (
            json!({"hash_policy": "client_ip"}),
            "an upstream has a hash_policy without balance hash",
            "upstreams.app.hash_policy",
        ),
        (
            json!({"balance": "least_conn", "hash_key": "x"}),
            "an upstream has a hash_key without balance hash",
            "upstreams.app.hash_key",
        ),
        (
            json!({"balance": "hash", "hash_policy": "cookie"}),
            "an upstream hash_policy header or cookie has no hash_key",
            "upstreams.app.hash_key",
        ),
        (
            json!({"balance": "hash", "hash_policy": "client_ip", "hash_key": "x"}),
            "an upstream hash_policy client_ip has a hash_key",
            "upstreams.app.hash_key",
        ),
        (
            json!({"balance": "hash", "hash_policy": "header", "hash_key": "a b"}),
            "an upstream hash_key is not a name of 1 to 64 token characters",
            "upstreams.app.hash_key",
        ),
        (
            json!({"balance": "hash", "hash_policy": "header", "hash_key": "X_User"}),
            "an upstream hash_key header name has an underscore",
            "upstreams.app.hash_key",
        ),
    ] {
        assert_eq!(refused(keys), (sentence, at(place)), "{sentence}");
    }
}
