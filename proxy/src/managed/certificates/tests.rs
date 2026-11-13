use std::fs;
use std::os::unix::fs::symlink;

use serde_json::{Value, json};

use super::*;
use crate::acme::tests::{Scratch, openssl};
use crate::managed::store::tests::Fixture;
use crate::rules::bundle::{hex, sha256};

/// A self-signed certificate for the names `names` (as `openssl req -addext` takes them), good for 30 days, in PEM,
/// and the end of its time of validity.
fn certificate(dir: &Scratch, names: &str) -> (Vec<u8>, i64) {
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
            &format!("subjectAltName={names}"),
        ],
    );
    let pem = fs::read(dir.join("c.pem")).unwrap();
    let end = der::not_after(&chain_of(&pem).unwrap()[0]).unwrap();
    (pem, end)
}

/// A version with the sites `sites`, and the group `app` that every request goes to.
fn version(sites: Value) -> Value {
    json!({
        "sites": sites,
        "upstreams": {"app": {"servers": [{
            "address": "127.0.0.1:9000", "weight": 1, "max_fails": 1, "fail_timeout_ms": 10000, "backup": false,
        }]}},
        "routes": [],
        "default_upstream": "app",
    })
}

/// The end of the certificate of `first_version`: 2049-12-31 23:59:59 UTC.
pub(crate) const FIRST_VERSION_END: i64 = 2_524_607_999;

/// A certificate of the first version, in PEM, put together by hand: the reader takes its end (`FIRST_VERSION_END`)
/// and no names, for only the third version has extensions. Nothing of it but its form is sound, and nothing is signed.
pub(crate) fn first_version() -> Vec<u8> {
    let (integer, sequence, utc_time, bit_string) = (0x02, 0x30, 0x17, 0x03);
    let validity = [
        der::tlv(utc_time, b"260101000000Z"),
        der::tlv(utc_time, b"491231235959Z"),
    ];
    let tbs = [
        der::tlv(integer, &[1]),
        der::tlv(sequence, &[]),
        der::tlv(sequence, &[]),
        der::tlv(sequence, &validity.concat()),
        der::tlv(sequence, &[]),
        der::tlv(sequence, &[]),
    ];
    let certificate = der::tlv(
        sequence,
        &[
            der::tlv(sequence, &tbs.concat()),
            der::tlv(sequence, &[]),
            der::tlv(bit_string, &[0]),
        ]
        .concat(),
    );
    crate::acme::base64::pem("CERTIFICATE", &certificate)
        .as_bytes()
        .to_vec()
}

fn hosts(count: usize) -> Vec<String> {
    (0..count).map(|n| format!("h{n}.test")).collect()
}

#[test]
fn each_site_has_the_state_of_its_files_and_what_a_chain_that_is_read_tells() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let dir = Scratch::new();
    let (pem, end) = certificate(&dir, "DNS:a.test");
    let chain = fixture.file(&pem);
    let key = fixture.file(b"a key, which is not read");
    // A chain in PEM whose certificate the reader of DER cannot read.
    let odd = fixture.file(b"-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n");
    let first = fixture.file(&first_version());
    // A link in the place of a key whose chain is not there, for a site of the files and for one with acme.
    let linked = sha256(b"a link");
    symlink(fixture.root().join("elsewhere"), store.file_path(linked)).unwrap();
    let (_, linked_key) = store
        .issue_places(acme_name(&["j.test".to_owned()]))
        .unwrap();
    symlink(fixture.root().join("elsewhere"), linked_key).unwrap();
    let issued = ["b.test".to_owned()];
    // The chain of one site with acme is there with its key, and that of another without it.
    let waiting = ["c.test".to_owned()];
    for (written, with_key) in [(&issued, true), (&waiting, false)] {
        let (issued_chain, issued_key) = store.issue_places(acme_name(written)).unwrap();
        fs::write(issued_chain, &pem).unwrap();
        if with_key {
            fs::write(issued_key, b"a key, which is not read").unwrap();
        }
    }
    let files = |chain: [u8; 32], key: [u8; 32]| json!({"chain": hex(&chain), "key": hex(&key)});
    let acme = json!({"acme": {"renew_before_days": 30}});
    let no_key = sha256(b"no key");
    let name = fixture.version(&version(json!([
        {"name": "present", "hosts": ["a.test"], "certificate": files(chain, key)},
        {"name": "issued", "hosts": issued, "certificate": acme},
        {"name": "missing", "hosts": ["d.test"], "certificate": files(chain, no_key)},
        {"name": "waiting", "hosts": waiting, "certificate": acme},
        {"name": "not issued", "hosts": hosts(64), "certificate": acme},
        {"name": "unreadable", "hosts": ["e.test"], "certificate": files(sha256(b"no chain"), linked)},
        {"name": "unreadable key", "hosts": ["j.test"], "certificate": acme},
        {"name": "linked key", "hosts": ["k.test"], "certificate": files(chain, linked)},
        {"name": "unparsed", "hosts": ["f.test"], "certificate": files(odd, key)},
        {"name": "no names", "hosts": ["h.test"], "certificate": files(first, key)},
        {"name": "missing first", "hosts": ["g.test"], "certificate": files(odd, no_key)},
        {"name": "unknown", "hosts": ["i.test"], "certificate": {"chain": hex(&chain)}},
        {"name": "many hosts", "hosts": hosts(65), "certificate": acme},
        {"name": "files of many hosts", "hosts": hosts(65), "certificate": files(chain, key)},
    ])));
    let now = end - 1;
    let read = certificates(&store, name, now).unwrap();
    let states: Vec<_> = read
        .iter()
        .map(|site| (site.name.as_str(), site.state))
        .collect();
    assert_eq!(
        states,
        [
            ("present", State::Present),
            ("issued", State::Issued),
            ("missing", State::Missing),
            ("waiting", State::Waiting),
            ("not issued", State::Waiting),
            ("unreadable", State::Unreadable),
            ("unreadable key", State::Unreadable),
            ("linked key", State::Unreadable),
            ("unparsed", State::Unparsed),
            ("no names", State::Unparsed),
            ("missing first", State::Missing),
            ("unknown", State::Unreadable),
            ("many hosts", State::Unreadable),
            ("files of many hosts", State::Present),
        ]
    );
    // A chain that is read tells its names and its end, whatever the state; one that is not, or whose end the reader
    // cannot take, tells nothing, and one whose names the reader cannot take tells no names.
    let told = Some(Leaf {
        names: Some((vec!["a.test".to_owned()], 0)),
        expiry: Expiry {
            not_after: end,
            expired: false,
        },
    });
    let no_names = Some(Leaf {
        names: None,
        expiry: Expiry {
            not_after: FIRST_VERSION_END,
            expired: FIRST_VERSION_END <= now,
        },
    });
    let leaves: Vec<_> = read.iter().map(|site| site.leaf.clone()).collect();
    assert_eq!(
        leaves,
        [
            told.clone(),
            told.clone(),
            told.clone(),
            told.clone(),
            None,
            None,
            None,
            told.clone(),
            None,
            no_names,
            None,
            None,
            None,
            told
        ]
    );
    assert_eq!(read[0].kind, Some(Kind::Files { chain, key }));
    assert_eq!(
        read[1].kind,
        Some(Kind::Acme {
            hosts: Some(issued.to_vec())
        })
    );
    // A certificate in neither form has none, and the hosts of a site with acme that are too many are not given; those
    // of a site of the files are not looked at.
    assert_eq!(read[11].kind, None);
    assert_eq!(read[12].kind, Some(Kind::Acme { hosts: None }));
    assert_eq!(read[13].kind, Some(Kind::Files { chain, key }));
    // At its end, a certificate is expired.
    let read = certificates(&store, name, end).unwrap();
    let expiry = read[0].leaf.as_ref().map(|leaf| leaf.expiry);
    assert_eq!(
        expiry,
        Some(Expiry {
            not_after: end,
            expired: true
        })
    );
}

#[test]
fn a_version_of_64_sites_is_read_and_one_of_65_is_not() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let sites = |count: usize| -> Value {
        hosts(count)
            .into_iter()
            .enumerate()
            .map(|(n, host)| {
                json!({"name": format!("s{n}"), "hosts": [host], "certificate": {"acme": {"renew_before_days": 30}}})
            })
            .collect()
    };
    let read = certificates(&store, fixture.version(&version(sites(64))), 0).unwrap();
    assert_eq!(read.len(), 64);
    assert!(read.iter().all(|site| site.state == State::Waiting));
    assert_eq!(
        certificates(&store, fixture.version(&version(sites(65))), 0),
        Err(ManagedError("the managed version has more than 64 sites"))
    );
}
