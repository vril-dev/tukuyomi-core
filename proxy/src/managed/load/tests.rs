use super::*;
use crate::forward::tls::Authorities;
use crate::managed::SiteCertificate;
use crate::managed::store::tests::Fixture;
use crate::rules::bundle::hex;
use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::symlink;

fn refusal(result: Result<Loaded, LoadError>) -> LoadError {
    match result {
        Err(e) => e,
        Ok(_) => panic!("accepted"),
    }
}

/// The main file of `fixture` after `edit`, checked alone.
fn main_refusal(fixture: &Fixture, edit: impl FnOnce(&mut Value)) -> &'static str {
    match config::load_main(&fixture.main_file(edit)) {
        Err(e) => e.0,
        Ok(_) => panic!("accepted"),
    }
}

#[test]
fn a_main_file_with_managed_writes_none_of_what_a_version_holds() {
    let fixture = Fixture::new();
    let main = fixture.main_file(|_| {});
    // The main file alone does not look at the store.
    assert!(config::load_main(&main).is_ok());
    assert_eq!(
        main_refusal(&fixture, |m| m["forward"]["routes"] = json!([])),
        "forward has upstreams, routes or default_upstream while the configuration has managed"
    );
    assert_eq!(
        main_refusal(&fixture, |m| m["access"] =
            json!({"deny_cidrs": ["192.0.2.0/24"]})),
        "the configuration has access or rate_limit while it has managed"
    );
    assert_eq!(
        main_refusal(&fixture, |m| {
            m["proxy"]["listeners"] = json!([{"address": "127.0.0.1:8443", "tls": {
                "min_version": "1.2",
                "certificates": [{"cert_file": "/c.pem", "key_file": "/k.pem", "hosts": ["a.test"]}],
            }}]);
        }),
        "a tls listener has certificates while the configuration has managed"
    );
    assert_eq!(
        main_refusal(&fixture, |m| m["rules"]["store"]["dir"] =
            json!(fixture.dir().join("rules"))),
        "the managed dir is the same as, inside or around the rules store dir, the records dir, the admin store dir or the directory of admin control"
    );
}

#[test]
fn the_whole_reading_takes_the_routing_from_the_current_version() {
    let fixture = Fixture::new();
    let main = fixture.main_file(|m| m["forward"]["resolve_timeout_ms"] = json!(1234));
    assert_eq!(
        refusal(load(&main, &Choice::Current)),
        LoadError::Store(ManagedError("no managed version is chosen"))
    );
    let mut version = fixture.plain_version(b"chain", b"key");
    version["access"] = json!({"deny_cidrs": ["192.0.2.0/24"]});
    let name = fixture.current(&version);
    let loaded = load(&main, &Choice::Current).unwrap();
    assert_eq!(loaded.forward.resolve_timeout.as_millis(), 1234);
    assert_eq!(loaded.forward.groups[0].name, "app");
    assert_eq!(loaded.forward.default, Some(0));
    assert!(!loaded.policy.access.is_empty());
    let read = loaded.version.unwrap();
    assert_eq!(read.name, name);
    assert_eq!(read.sites[0].hosts, ["site.test"]);
    assert_eq!(
        read.sites[0].certificate.files().map(|(chain, _)| *chain),
        Some(sha256(b"chain"))
    );
    // The same file of the store, given as bytes, reads the same.
    let bytes = serde_json::to_vec(&version).unwrap();
    assert!(load(&main, &Choice::Given(bytes)).is_ok());
}

#[test]
fn a_version_that_names_a_path_is_refused() {
    let fixture = Fixture::new();
    let main = fixture.main_file(|_| {});
    let mut version = fixture.plain_version(b"chain", b"key");
    version["sites"][0]["certificate"]["cert_file"] = json!("/etc/tls/a.pem");
    let given = |version: &Value| Choice::Given(serde_json::to_vec(version).unwrap());
    assert_eq!(
        refusal(load(&main, &given(&version))),
        LoadError::Version(ConfigError("configuration has an unknown key"))
    );
    let mut version = fixture.plain_version(b"chain", b"key");
    version["upstreams"]["app"]["tls"] = json!({"ca_file": "/etc/tls/ca.pem"});
    assert_eq!(
        refusal(load(&main, &given(&version))),
        LoadError::Version(ConfigError("configuration has an unknown key"))
    );
}

#[test]
fn a_version_or_a_file_that_is_not_what_its_name_says_or_is_a_link_is_refused() {
    let fixture = Fixture::new();
    let main = fixture.main_file(|_| {});
    let version = fixture.plain_version(b"chain", b"key");
    let name = fixture.current(&version);
    let path = fixture
        .dir()
        .join("versions")
        .join(format!("{}.json", hex(&name)));
    let written = fs::read(&path).unwrap();
    fs::write(&path, b"{}").unwrap();
    assert_eq!(
        refusal(load(&main, &Choice::Current)),
        LoadError::Store(ManagedError("the managed version does not match its name"))
    );
    fs::write(&path, &written).unwrap();
    let key = fixture.store().file_path(sha256(b"key"));
    fs::write(&key, b"another key").unwrap();
    assert_eq!(
        refusal(load(&main, &Choice::Current)),
        LoadError::Store(ManagedError("a managed file does not match its name"))
    );
    let outside = fixture.root().join("key");
    fs::write(&outside, b"key").unwrap();
    fs::remove_file(&key).unwrap();
    symlink(&outside, &key).unwrap();
    assert_eq!(
        refusal(load(&main, &Choice::Current)),
        LoadError::Store(ManagedError("a managed file cannot be read, or is a link"))
    );
    fs::remove_file(&key).unwrap();
    assert_eq!(
        refusal(load(&main, &Choice::Current)),
        LoadError::Store(ManagedError("a managed file is not in the store"))
    );
}

#[test]
fn a_version_is_checked_against_the_values_of_its_main_file() {
    let fixture = Fixture::new();
    let main = fixture.main_file(|_| {});
    let refused = |edit: &dyn Fn(&mut Value)| {
        let mut version = fixture.plain_version(b"chain", b"key");
        edit(&mut version);
        match refusal(load(
            &main,
            &Choice::Given(serde_json::to_vec(&version).unwrap()),
        )) {
            LoadError::Version(e) => e.0,
            other => panic!("{other:?}"),
        }
    };
    assert_eq!(
        refused(&|v| v["routes"] = json!([{"path": "/", "upstream": "app", "max_body": 1048577}])),
        "a route max_body is above the max_body of the proxy"
    );
    assert_eq!(
        refused(&|v| v["upstreams"]["app"]["servers"][0]["address"] = json!("127.0.0.1:8080")),
        "a listener and a server are the same address"
    );
    assert_eq!(
        refused(&|v| v["access"] = json!({"allow_countries": ["JP"]})),
        "access has a list of countries while geo is left out"
    );
    assert_eq!(
        refused(&|v| v["routes"] = json!([{"path": "/", "upstream": "app", "records": "required"}])),
        "a route has records required while the file has no records object"
    );
    // Not in the one written form: the same content with a space, or with its keys in another order.
    let version = fixture.plain_version(b"chain", b"key");
    let mut spaced = serde_json::to_vec(&version).unwrap();
    spaced.push(b' ');
    let part = |key: &str| serde_json::to_string(&version[key]).unwrap();
    let reordered = format!(
        "{{\"upstreams\":{},\"sites\":{},\"routes\":{},\"default_upstream\":{}}}",
        part("upstreams"),
        part("sites"),
        part("routes"),
        part("default_upstream")
    );
    assert_eq!(
        serde_json::from_str::<Value>(&reordered).unwrap(),
        version,
        "the same content"
    );
    for bytes in [spaced, reordered.into_bytes()] {
        assert_eq!(
            refusal(load(&main, &Choice::Given(bytes))),
            LoadError::Version(ConfigError(
                "the managed version is not in its one written form"
            ))
        );
    }
}

/// The `admin` object, with this `route` if it is given.
fn admin(route: Option<Value>) -> Value {
    let mut admin = json!({
        "listen": "127.0.0.1:9180", "control": "/run/tukuyomi/admin.sock",
        "store": {"kind": "file", "dir": "/var/lib/tukuyomi/admin"}, "origin": "https://admin.test",
        "trusted_proxies": [], "mfa": "optional", "session_idle_ms": 600_000, "session_total_ms": 3_600_000,
    });
    if let Some(route) = route {
        admin["route"] = route;
    }
    admin
}

fn route(host: &str, access: Value) -> Value {
    json!({
        "host": host,
        "certificate": {"cert_file": "/etc/tukuyomi/admin.pem", "key_file": "/etc/tukuyomi/admin.key"},
        "access": access,
    })
}

#[test]
fn the_way_to_the_admin_process_is_in_admin_and_its_host_is_no_site_and_no_route() {
    let fixture = Fixture::new();
    let allowed = || json!({"allow_cidrs": ["192.0.2.0/24"]});
    assert_eq!(
        main_refusal(&fixture, |m| m["admin"] = admin(None)),
        "admin has no route while the configuration has managed"
    );
    assert_eq!(
        main_refusal(&fixture, |m| m["admin"] = admin(Some(route(
            "admin.test",
            json!({"deny_cidrs": ["192.0.2.0/24"]})
        )))),
        "admin route access has no allow_cidrs"
    );
    assert_eq!(
        main_refusal(&fixture, |m| m["admin"] =
            admin(Some(route("admin.test", json!({"allow_cidrs": []}))))),
        "admin route access has no allow_cidrs"
    );
    assert_eq!(
        main_refusal(&fixture, |m| m["admin"] =
            admin(Some(route("*.test", allowed())))),
        "admin route host is not a name"
    );
    // A file without `managed` writes its way to the admin process as a route of its own.
    assert_eq!(
        main_refusal(&fixture, |m| {
            m.as_object_mut().unwrap().remove("managed");
            m["forward"]["upstreams"] = json!({"app": {"servers": [{"address": "127.0.0.1:9000", "weight": 1, "max_fails": 1, "fail_timeout_ms": 1000, "backup": false}]}});
            m["forward"]["routes"] = json!([]);
            m["forward"]["default_upstream"] = json!("app");
            m["admin"] = admin(Some(route("admin.test", allowed())));
        }),
        "admin route is only for a configuration with managed"
    );

    let main = fixture.main_file(|m| m["admin"] = admin(Some(route("admin.test", allowed()))));
    let read = config::load_main(&main).unwrap().admin_route.unwrap();
    assert_eq!(
        (read.host.as_str(), read.certificate.hosts.as_slice()),
        ("admin.test", &["admin.test".to_owned()][..])
    );
    let refused = |edit: &dyn Fn(&mut Value)| {
        let mut version = fixture.plain_version(b"chain", b"key");
        edit(&mut version);
        match load(&main, &Choice::Given(serde_json::to_vec(&version).unwrap())) {
            Err(LoadError::Version(e)) => Some(e.0),
            Err(other) => panic!("{other:?}"),
            Ok(_) => None,
        }
    };
    assert_eq!(refused(&|_| {}), None);
    assert_eq!(
        refused(&|v| v["sites"][0]["hosts"] = json!(["site.test", "admin.test"])),
        Some("a site host is the host of the admin route")
    );
    assert_eq!(
        refused(&|v| v["routes"] = json!([{"host": "admin.test:8443", "upstream": "app"}])),
        Some("a route host is the host of the admin route")
    );
    // No group of the version reaches the admin process, by a route or as the default group.
    assert_eq!(
        refused(&|v| {
            v["upstreams"]["admin"] = json!({"servers": [{"address": "127.0.0.1:9180", "weight": 1, "max_fails": 1, "fail_timeout_ms": 1000, "backup": false}]});
            v["routes"] = json!([{"path": "/admin/", "upstream": "admin"}]);
            v["default_upstream"] = json!("admin");
        }),
        Some("a server is at the address of the admin process")
    );
    // A wildcard may cover the host: the name comes first, in the handshake and for the route.
    assert_eq!(
        refused(&|v| v["sites"][0]["hosts"] = json!(["*.test"])),
        None
    );
    assert_eq!(
        refused(&|v| v["routes"] = json!([{"host": "*.test", "upstream": "app"}])),
        None
    );
}

#[test]
fn a_tls_listener_needs_a_site_or_the_way_to_the_admin_process() {
    let fixture = Fixture::new();
    let tls = |m: &mut Value| {
        m["proxy"]["listeners"] =
            json!([{"address": "127.0.0.1:8443", "tls": {"min_version": "1.2"}}]);
    };
    let without = |version: &mut Value| version["sites"] = json!([]);
    let given = |edit: &dyn Fn(&mut Value)| {
        let mut version = fixture.plain_version(b"chain", b"key");
        edit(&mut version);
        Choice::Given(serde_json::to_vec(&version).unwrap())
    };
    let main = fixture.main_file(tls);
    assert_eq!(
        refusal(load(&main, &given(&without))),
        LoadError::Version(ConfigError(
            "a tls listener has no certificate, for the version has no site and admin has no route"
        ))
    );
    assert!(load(&main, &given(&|_| {})).is_ok());
    // Plain listeners need no site.
    let plain = fixture.main_file(|_| {});
    assert!(load(&plain, &given(&without)).is_ok());
}

#[test]
fn the_file_of_the_authorities_of_a_group_is_read_through_the_store_only() {
    let fixture = Fixture::new();
    let main = fixture.main_file(|_| {});
    let mut version = fixture.plain_version(b"chain", b"key");
    let ca = fixture.file(b"authorities");
    version["upstreams"]["app"]["tls"] = json!({"ca": hex(&ca), "server_name": "app.test"});
    fixture.current(&version);
    let loaded = load(&main, &Choice::Current).unwrap();
    // The group names the file by its SHA-256, not by a path: only the store reads it.
    assert_eq!(
        loaded.forward.groups[0].tls.as_ref().unwrap().authorities,
        Authorities::Stored(ca)
    );
    let path = fixture.store().file_path(ca);
    // A file of other content, or a link in its place, is refused.
    fs::write(&path, b"other authorities").unwrap();
    assert_eq!(
        refusal(load(&main, &Choice::Current)),
        LoadError::Store(ManagedError("a managed file does not match its name"))
    );
    let outside = fixture.root().join("authorities");
    fs::write(&outside, b"authorities").unwrap();
    fs::remove_file(&path).unwrap();
    symlink(&outside, &path).unwrap();
    assert_eq!(
        refusal(load(&main, &Choice::Current)),
        LoadError::Store(ManagedError("a managed file cannot be read, or is a link"))
    );
}

// ---- acme ----

fn acme_object() -> Value {
    json!({
        "directory_url": "https://ca.test/directory", "contact_email": "ops@example.test",
        "account_key_file": "/a/account.key", "challenge_dir": "/a/challenges", "ca_file": "/a/ca.pem",
        "timeout_ms": 1000,
    })
}

/// The version of the fixture whose site has `acme` in the place of its files.
fn acme_version(fixture: &Fixture) -> Value {
    let mut version = fixture.plain_version(b"chain", b"key");
    version["sites"][0]["certificate"] = json!({"acme": {"renew_before_days": 30}});
    version
}

#[test]
fn a_main_file_with_managed_may_have_acme_with_a_listener_for_the_challenge() {
    let fixture = Fixture::new();
    // No certificate of the main file has acme: those of the sites are in the version.
    let main = fixture.main_file(|m| m["acme"] = acme_object());
    assert!(config::load_main(&main).unwrap().acme.is_some());
    assert_eq!(
        main_refusal(&fixture, |m| {
            m["acme"] = acme_object();
            m["proxy"]["listeners"] =
                json!([{"address": "127.0.0.1:8443", "tls": {"min_version": "1.2"}}]);
        }),
        "a certificate with acme needs a plain or a redirect listener for the challenge"
    );
}

#[test]
fn a_site_with_acme_needs_the_acme_object_names_no_file_and_counts_as_a_certificate() {
    let fixture = Fixture::new();
    let given = |version: &Value| Choice::Given(serde_json::to_vec(version).unwrap());
    let without = fixture.main_file(|_| {});
    assert_eq!(
        refusal(load(&without, &given(&acme_version(&fixture)))),
        LoadError::Version(ConfigError(
            "a site has acme but the configuration has no acme object"
        ))
    );
    // With only that site, a TLS listener has its certificate, though it is not issued yet; the store has no `acme/`.
    let main = fixture.main_file(|m| {
        m["acme"] = acme_object();
        m["proxy"]["listeners"] = json!([
            {"address": "127.0.0.1:8080"},
            {"address": "127.0.0.1:8443", "tls": {"min_version": "1.2"}},
        ]);
    });
    let loaded = load(&main, &given(&acme_version(&fixture))).unwrap();
    assert_eq!(
        loaded.version.unwrap().sites[0].certificate,
        SiteCertificate::Acme(crate::config::CertificateAcme {
            renew_before_days: 30
        })
    );
    assert!(!fixture.dir().join("acme").exists());
}

/// The `admin` object whose route has a certificate with `acme`, its files `cert_file` and `key_file`.
fn admin_acme(cert_file: &str, key_file: &str) -> Value {
    let mut route = route("admin.test", json!({"allow_cidrs": ["192.0.2.0/24"]}));
    route["certificate"] = json!({
        "cert_file": cert_file, "key_file": key_file, "acme": {"renew_before_days": 30},
    });
    admin(Some(route))
}

#[test]
fn the_certificate_of_the_way_to_the_admin_process_may_have_acme_with_the_acme_object() {
    let fixture = Fixture::new();
    let (cert, key) = ("/etc/tukuyomi/admin.pem", "/etc/tukuyomi/admin.key");
    // The main file alone refuses it, as the proxy does.
    assert_eq!(
        main_refusal(&fixture, |m| m["admin"] = admin_acme(cert, key)),
        "a certificate has acme but the configuration has no acme object"
    );
    let main = fixture.main_file(|m| {
        m["admin"] = admin_acme(cert, key);
        m["acme"] = acme_object();
    });
    let route = config::load_main(&main).unwrap().admin_route.unwrap();
    assert_eq!(
        route.certificate.acme,
        Some(crate::config::CertificateAcme {
            renew_before_days: 30
        })
    );
    // Its files are files of the command: apart from the account key and outside challenge_dir.
    let with = |cert: &str, key: &str| {
        let (cert, key) = (cert.to_owned(), key.to_owned());
        main_refusal(&fixture, move |m| {
            m["admin"] = admin_acme(&cert, &key);
            m["acme"] = acme_object();
        })
    };
    assert_eq!(
        with(cert, "/a/account.key"),
        "the account key file, the ca_file and the cert and key files of the certificates with acme are not all different"
    );
    assert_eq!(
        with("/a/challenges/admin.pem", key),
        "the account key file, the ca_file or a cert or key file of a certificate is directly inside challenge_dir"
    );
}

#[test]
fn the_challenge_directory_and_the_files_of_acme_are_apart_from_the_managed_store() {
    let fixture = Fixture::new();
    let store = fixture.dir();
    let with_acme = |key: &str, path: PathBuf| {
        let mut object = acme_object();
        object[key] = json!(path);
        main_refusal(&fixture, |m| m["acme"] = object)
    };
    let challenge = "acme challenge_dir is the same as, inside or around the rules store dir, the records dir, the admin store dir, the directory of admin control or the managed dir";
    assert_eq!(with_acme("challenge_dir", store.clone()), challenge);
    assert_eq!(
        with_acme("challenge_dir", store.join("challenges")),
        challenge
    );
    assert_eq!(
        with_acme("challenge_dir", fixture.root().to_owned()),
        challenge
    );
    let inside = "the acme account_key_file or ca_file, or a cert or key file of admin route, is inside the managed dir";
    assert_eq!(
        with_acme("account_key_file", store.join("account.key")),
        inside
    );
    let in_store = store.join("admin.pem");
    assert_eq!(
        main_refusal(&fixture, |m| {
            m["admin"] = admin_acme(in_store.to_str().unwrap(), "/etc/tukuyomi/admin.key");
            m["acme"] = acme_object();
        }),
        inside
    );
    // A name that only starts with that of the store is no place inside it.
    let mut beside = store.into_os_string();
    beside.push("2");
    let beside = PathBuf::from(beside).join("account.key");
    let mut object = acme_object();
    object["account_key_file"] = json!(beside);
    assert!(config::load_main(&fixture.main_file(|m| m["acme"] = object)).is_ok());
}
