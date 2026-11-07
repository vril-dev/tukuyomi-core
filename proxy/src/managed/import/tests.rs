use std::fs;

use serde_json::json;

use super::*;
use crate::config;
use crate::forward::tls::tests::Pki;
use crate::managed::store::tests::Fixture;
use crate::rules::bundle::hex;

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
        Err(objection) => (objection.why, objection.at),
        Ok(_) => panic!("accepted"),
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
