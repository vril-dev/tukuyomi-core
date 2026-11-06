use super::*;
use serde_json::json;

const NAME: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// The sites of a version, as `sites` checks them.
fn checked(sites: Value) -> Result<Vec<Site>, ConfigError> {
    let raw: Vec<Object<RawSite<StoredCertificate>>> =
        serde_json::from_value(sites).map_err(|e| config::refusal(&e))?;
    super::sites(raw)
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
