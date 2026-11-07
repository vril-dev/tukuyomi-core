use std::fs;

use serde_json::json;

use super::*;
use crate::config::{Built, Routing};
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
