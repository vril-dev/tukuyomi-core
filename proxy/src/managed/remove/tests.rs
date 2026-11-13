use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;

use serde_json::{Value, json};

use super::*;
use crate::managed::store::acme_name;
use crate::managed::store::tests::Fixture;
use crate::managed::{Choice, load};
use crate::rules::bundle::{hex, sha256};

/// A version whose site `a` has the files `chain` and `key` of the store, whose site `b` has `acme` for `hosts`, and
/// whose group `app` reaches its server over TLS with the file `ca` of the store as its authorities.
fn version(chain: [u8; 32], key: [u8; 32], hosts: &[&str], ca: [u8; 32]) -> Value {
    json!({
        "sites": [
            {"name": "a", "hosts": ["a.test"], "certificate": {"chain": hex(&chain), "key": hex(&key)}},
            {"name": "b", "hosts": hosts, "certificate": {"acme": {"renew_before_days": 30}}},
        ],
        "upstreams": {"app": {
            "servers": [{"address": "127.0.0.1:9443", "weight": 1, "max_fails": 1, "fail_timeout_ms": 1000, "backup": false}],
            "tls": {"ca": hex(&ca), "server_name": "app.test"},
        }},
        "routes": [],
        "default_upstream": "app",
    })
}

/// The directory of `acme/` of the store of `fixture` for these hosts, made with a chain and a key in it.
fn issued(fixture: &Fixture, hosts: &[&str]) -> PathBuf {
    let hosts: Vec<String> = hosts.iter().map(|host| (*host).to_owned()).collect();
    let (chain, key) = fixture.store().issue_places(acme_name(&hosts)).unwrap();
    fs::write(&chain, b"chain").unwrap();
    fs::write(&key, b"key").unwrap();
    chain.parent().unwrap().to_path_buf()
}

fn version_path(fixture: &Fixture, name: [u8; 32]) -> PathBuf {
    fixture
        .dir()
        .join("versions")
        .join(format!("{}.json", hex(&name)))
}

fn refusal(result: Result<Removed, ManagedError>) -> &'static str {
    match result {
        Err(e) => e.0,
        Ok(removed) => panic!("removed: {removed:?}"),
    }
}

#[test]
fn neither_the_current_version_nor_one_that_is_held_is_removed() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let current = fixture.current(&fixture.plain_version(b"chain 1", b"key 1"));
    let held = fixture.version(&fixture.plain_version(b"chain 2", b"key 2"));
    let unnamed = fixture.file(b"no version names this");
    assert_eq!(
        refusal(remove(&store, current)),
        "the managed version is the current one"
    );
    let (_, hold) = store.hold(held).unwrap();
    assert_eq!(
        refusal(remove(&store, held)),
        "the managed version is in use"
    );
    drop(hold);
    // Nothing changed: both versions are there, and so is the file that no version names.
    assert!(store.version(current).is_ok() && store.version(held).is_ok());
    assert!(store.file(unnamed).is_ok());
    assert_eq!(
        refusal(remove(&store, sha256(b"no version"))),
        "the managed version is not in the store"
    );
}

#[test]
fn a_removal_cleans_up_what_no_other_version_names() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let bytes: [&[u8]; 4] = [b"chain", b"key 1", b"key 2", b"ca"];
    let [chain, key, other_key, ca] = bytes.map(|bytes| fixture.file(bytes));
    // Both versions have the chain and the authorities; each has a key and a site with acme of its own.
    let kept = fixture.current(&version(chain, key, &["one.test"], ca));
    let gone = fixture.version(&version(chain, other_key, &["b.test", "two.test"], ca));
    let unnamed = fixture.file(b"no version names this");
    let files = fixture.dir().join("files");
    fs::write(files.join(format!("{}.new", hex(&unnamed))), b"half").unwrap();
    fs::write(
        fixture
            .dir()
            .join("versions")
            .join(format!("{}.json.new", hex(&kept))),
        b"half",
    )
    .unwrap();
    // A link under the name of a file goes, not what it points to; a directory under such a name stays.
    let target = fixture.root().join("target");
    fs::write(&target, b"target").unwrap();
    let linked = files.join(hex(&sha256(b"link")));
    symlink(&target, &linked).unwrap();
    let directory = files.join(hex(&sha256(b"directory")));
    fs::create_dir(&directory).unwrap();
    let one = issued(&fixture, &["one.test"]);
    let two = issued(&fixture, &["two.test", "b.test"]);
    fs::write(two.join(".acme-0123456789abcdef.tmp"), b"half").unwrap();
    // A link in `acme/` stays, and so does what it points to.
    let elsewhere = fixture.root().join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    fs::write(elsewhere.join("key"), b"key").unwrap();
    let acme_link = fixture.dir().join("acme").join(hex(&sha256(b"acme link")));
    symlink(&elsewhere, &acme_link).unwrap();

    assert_eq!(remove(&store, gone), Ok(Removed { cleaned: true }));
    assert!(!version_path(&fixture, gone).exists());
    for name in [chain, key, ca] {
        assert!(store.file(name).is_ok());
    }
    for name in [other_key, unnamed] {
        assert!(!store.file_path(name).exists());
    }
    let mut left: Vec<String> = fs::read_dir(&files)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    left.sort();
    let mut want = vec![hex(&chain), hex(&key), hex(&ca), hex(&sha256(b"directory"))];
    want.sort();
    assert_eq!(left, want);
    assert_eq!(fs::read(&target).unwrap(), b"target");
    let versions: Vec<_> = fs::read_dir(fixture.dir().join("versions"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(versions, [format!("{}.json", hex(&kept)).as_str()]);
    assert!(one.join("chain").exists() && !two.exists());
    assert!(fs::symlink_metadata(&acme_link).is_ok());
    assert_eq!(fs::read(elsewhere.join("key")).unwrap(), b"key");
}

#[test]
fn a_broken_version_is_removed_and_one_that_cannot_be_read_keeps_the_store_from_being_cleaned() {
    let fixture = Fixture::new();
    let store = fixture.store();
    fixture.current(&fixture.plain_version(b"chain 1", b"key 1"));
    let broken = fixture.version(&fixture.plain_version(b"chain 2", b"key 2"));
    fs::write(version_path(&fixture, broken), b"not a version").unwrap();
    let third = fixture.version(&fixture.plain_version(b"chain 3", b"key 3"));
    let left: [&[u8]; 4] = [b"chain 2", b"key 2", b"chain 3", b"key 3"];
    // What the broken version names cannot be known, so nothing is cleaned while it is there.
    assert_eq!(remove(&store, third), Ok(Removed { cleaned: false }));
    assert!(!version_path(&fixture, third).exists());
    for bytes in left {
        assert!(store.file(sha256(bytes)).is_ok());
    }
    // It is removed without being read, and then the files that no version names go.
    assert_eq!(remove(&store, broken), Ok(Removed { cleaned: true }));
    assert!(!version_path(&fixture, broken).exists());
    for bytes in left {
        assert!(!store.file_path(sha256(bytes)).exists());
    }
    assert!(store.file(sha256(b"chain 1")).is_ok());
}

#[test]
fn the_name_of_a_site_with_acme_is_the_one_that_the_reading_of_the_version_makes() {
    let fixture = Fixture::new();
    let main = fixture.main_file(|m| {
        m["acme"] = json!({
            "directory_url": "https://ca.test/directory", "contact_email": "ops@example.test",
            "account_key_file": "/a/account.key", "challenge_dir": "/a/challenges", "ca_file": "/a/ca.pem",
            "timeout_ms": 1000,
        });
    });
    let mut written = version(
        fixture.file(b"chain"),
        fixture.file(b"key"),
        &["z.test", "b.test"],
        [0; 32],
    );
    written["upstreams"]["app"]
        .as_object_mut()
        .unwrap()
        .remove("tls");
    let bytes = serde_json::to_vec(&written).unwrap();
    fixture.store().put_version(&bytes).unwrap();
    // The reading takes the version as it is given, and so holds no lock on its file.
    let loaded = load(&main, &Choice::Given(bytes)).unwrap();
    let hosts = &loaded.version.as_ref().unwrap().sites[1].hosts;
    let (_, issued) = named(&fixture.store(), [0; 32]).unwrap();
    assert_eq!(issued.into_iter().collect::<Vec<_>>(), [acme_name(hosts)]);
}

#[test]
fn a_directory_of_acme_that_cannot_be_emptied_loses_its_key_and_stays() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let bytes: [&[u8]; 4] = [b"chain", b"key 1", b"key 2", b"ca"];
    let [chain, key, other_key, ca] = bytes.map(|bytes| fixture.file(bytes));
    fixture.current(&version(chain, key, &["one.test"], ca));
    let gone = fixture.version(&version(chain, other_key, &["two.test"], ca));
    // A directory in the place of the chain cannot be removed as a name; the key goes all the same.
    let two = issued(&fixture, &["two.test"]);
    fs::remove_file(two.join("chain")).unwrap();
    fs::create_dir(two.join("chain")).unwrap();
    assert_eq!(remove(&store, gone), Ok(Removed { cleaned: false }));
    assert!(!version_path(&fixture, gone).exists());
    assert!(!two.join("key").exists() && two.join("chain").is_dir());
}
