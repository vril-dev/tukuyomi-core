use std::fs;

use serde_json::json;

use super::*;
use crate::config;
use crate::forward::tls::tests::Pki;
use crate::managed::store::tests::Fixture;
use crate::rules::bundle::hex;
use tukuyomi_kernel::Engine;

#[test]
fn a_file_that_a_request_cannot_use_is_about_the_key_of_the_version_that_names_it() {
    let (fixture, pki) = (Fixture::new(), Pki::new());
    let built = config::main_file(&fs::read(fixture.main_file(|_| {})).unwrap()).unwrap();
    let read = |path| Zeroizing::new(fs::read(path).unwrap());
    let chain = read(pki.issue("a", &["DNS:a.test"]).cert);
    let key = read(pki.issue("b", &["DNS:a.test"]).key);
    let version = serde_json::to_vec(&json!({
        "sites": [{"name": "a", "hosts": ["a.test"], "certificate": {"chain": hex(&sha256(&chain)), "key": hex(&sha256(&key))}}],
        "upstreams": {"app": {"servers": [{"address": "127.0.0.1:9000", "weight": 1, "max_fails": 1, "fail_timeout_ms": 1000, "backup": false}]}},
        "routes": [],
        "default_upstream": "app",
    }))
    .unwrap();
    let refused = |files: Vec<Zeroizing<Vec<u8>>>| match from_request(
        &built,
        &fixture.store(),
        version.clone(),
        files,
    ) {
        Err(Refused::Input(objection)) => (objection.why, objection.at),
        _ => panic!("accepted, or refused for the rules store"),
    };
    // The sentence names no site: the place does.
    assert_eq!(
        refused(vec![chain.clone(), key.clone()]),
        (
            "a certificate and a private key are not a pair",
            Some("sites[0].certificate.key".to_owned())
        )
    );
    // A file that neither the request nor the store has is about the first key that names it.
    assert_eq!(
        refused(vec![key.clone()]),
        (
            "a managed file is not in the store",
            Some("sites[0].certificate.chain".to_owned())
        )
    );
}

#[test]
fn a_version_whose_group_has_an_engine_with_no_generation_chosen_is_about_the_engine_of_the_group()
{
    let fixture = Fixture::new();
    let path = fixture.main_file(|m| {
        m["kernel"]["engines"] =
            json!({"modsecurity": {"inspector": "/opt/tukuyomi/inspector-modsecurity"}});
    });
    let built = config::main_file(&fs::read(path).unwrap()).unwrap();
    let group = |address: &str, engine: &str| {
        json!({"servers": [{
            "address": address, "weight": 1, "max_fails": 1, "fail_timeout_ms": 1000, "backup": false,
        }], "engine": engine})
    };
    // The groups are in the byte order of their names: `a` for Coraza, then `b` for ModSecurity.
    let version = serde_json::to_vec(&json!({
        "sites": [], "upstreams": {
            "a": group("127.0.0.1:9000", "coraza"), "b": group("127.0.0.1:9001", "modsecurity"),
        },
        "routes": [], "default_upstream": "a",
    }))
    .unwrap();
    let request = || from_request(&built, &fixture.store(), version.clone(), Vec::new());
    let Err(Refused::Input(refused)) = request() else {
        panic!("accepted, or refused for the rules store");
    };
    assert_eq!(
        (refused.why, refused.at),
        (
            "no generation is chosen for the engine of an upstream",
            Some("upstreams.b.engine".to_owned())
        )
    );
    // A rules store that cannot be read is not a refusal of the request.
    fs::write(fixture.rules().join("current.modsecurity"), "x").unwrap();
    assert!(matches!(
        request(),
        Err(Refused::Rules(StoreError(
            "the current generation record is broken"
        )))
    ));
    fs::remove_file(fixture.rules().join("current.modsecurity")).unwrap();
    fixture.choose_rules(Engine::ModSecurity);
    assert!(request().is_ok());
}
