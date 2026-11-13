use std::fs;

use serde_json::json;

use super::*;
use crate::acme::tests::{Scratch, openssl};
use crate::admin::managed::Op;
use crate::admin::managed::routes::tests::{Rig, bare_version, rig, rig_with};
use crate::managed::certificates::tests::{FIRST_VERSION_END, first_version};

/// A self-signed certificate for `a.test`, good for 30 days, in PEM.
fn certificate(dir: &Scratch) -> Vec<u8> {
    openssl(
        dir.path(),
        &[
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-keyout",
            "c.key",
            "-out",
            "c.pem",
            "-subj",
            "/CN=x",
            "-days",
            "30",
            "-addext",
            "subjectAltName=DNS:a.test",
        ],
    );
    fs::read(dir.join("c.pem")).unwrap()
}

fn read(rig: &Rig, name: &str) -> Answer {
    rig.get(
        Op::Certificates,
        &format!("/api/managed/certificates/{name}"),
    )
}

#[test]
fn the_certificates_of_a_version_are_its_sites_in_order_and_no_key_is_in_the_answer() {
    let rig = rig(false);
    let dir = Scratch::new();
    let chain = rig.fixture.file(&certificate(&dir));
    let first = rig.fixture.file(&first_version());
    let key = rig
        .fixture
        .file(b"-----BEGIN PRIVATE KEY-----\nsecret of the site\n-----END PRIVATE KEY-----\n");
    let mut version = bare_version();
    version["sites"] = json!([
        {"name": "files", "hosts": ["a.test"], "certificate": {"chain": hex(&chain), "key": hex(&key)}},
        {"name": "acme", "hosts": ["b.test"], "certificate": {"acme": {"renew_before_days": 30}}},
        {"name": "key as chain", "hosts": ["c.test"], "certificate": {"chain": hex(&key), "key": hex(&key)}},
        {"name": "no names", "hosts": ["e.test"], "certificate": {"chain": hex(&first), "key": hex(&key)}},
        {"name": "neither", "hosts": ["d.test"], "certificate": {"key": hex(&key)}},
    ]);
    let name = rig.fixture.version(&version);
    let answer = read(&rig, &hex(&name));
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    let not_after = answer.body["sites"][0]["not_after"].clone();
    assert!(not_after.as_i64().is_some_and(|end| end > 0), "{not_after}");
    assert_eq!(
        answer.body,
        json!({
            "name": hex(&name),
            "sites": [
                {
                    "name": "files", "kind": "files", "chain": hex(&chain), "key": hex(&key), "state": "present",
                    "names": ["a.test"], "more": 0, "not_after": not_after, "expired": false,
                },
                {"name": "acme", "kind": "acme", "hosts": ["b.test"], "state": "waiting"},
                {"name": "key as chain", "kind": "files", "chain": hex(&key), "key": hex(&key), "state": "unreadable"},
                {
                    "name": "no names", "kind": "files", "chain": hex(&first), "key": hex(&key), "state": "unparsed",
                    "not_after": FIRST_VERSION_END, "expired": FIRST_VERSION_END <= now_ms() as i64 / 1000,
                },
                {"name": "neither", "kind": null, "state": "unreadable"},
            ],
        })
    );
    assert!(!answer.body.to_string().contains("secret"));
    for name in ["x".to_owned(), hex(&[9; 32])] {
        assert_eq!(read(&rig, &name).status, StatusCode::NOT_FOUND, "{name}");
    }
}

#[test]
fn a_main_file_without_managed_at_the_start_has_no_certificates_to_read() {
    let rig = rig_with(false, false);
    let answer = read(&rig, &hex(&rig.first));
    assert_eq!(
        (answer.status, &answer.body["error"]),
        (
            StatusCode::CONFLICT,
            &json!("the configuration has no managed object")
        )
    );
}
