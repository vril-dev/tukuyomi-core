use super::*;
use crate::forward::tls::tests::Pki;
use crate::log;
use crate::managed::store::tests::Fixture;
use crate::rules::bundle::sha256;
use serde_json::{Value, json};
use std::fs;

const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn args(text: &[&str]) -> Vec<OsString> {
    text.iter().map(OsString::from).collect()
}

#[test]
fn each_command_takes_the_configuration_and_its_own_argument() {
    assert_eq!(
        parse(&args(&["import", "/etc/t.json", "doc.json"])),
        Ok(Command::Import {
            config: PathBuf::from("/etc/t.json"),
            document: PathBuf::from("doc.json"),
        })
    );
    assert_eq!(
        parse(&args(&["activate", "/etc/t.json", HEX])),
        Ok(Command::Activate {
            config: PathBuf::from("/etc/t.json"),
            version: Fingerprint::from_hex(HEX.as_bytes()).unwrap().bytes(),
        })
    );
    assert_eq!(
        parse(&args(&["list", "/etc/t.json"])),
        Ok(Command::List {
            config: PathBuf::from("/etc/t.json"),
        })
    );
    for wrong in [
        &["import", "/etc/t.json"][..],
        &["import", "etc/t.json", "doc.json"],
        &["activate", "/etc/t.json", &HEX[1..]],
        &["activate", "/etc/t.json", &HEX.to_uppercase()],
        &["list", "/etc/t.json", "more"],
        &["remove", "/etc/t.json", HEX],
        &[],
    ] {
        assert!(parse(&args(wrong)).is_err(), "{wrong:?}");
    }
}

/// Runs the command `text` and gives how it ended, the standard output and the lines of the log.
fn command(text: &[&str]) -> (Exit, String, Vec<String>) {
    let (log, lines) = log::recording();
    let mut out = Vec::new();
    let exit = run(&args(text), &mut out, &log);
    (exit, String::from_utf8(out).unwrap(), lines.texts())
}

/// A document with one site whose certificate `pki` issues for `a.test`, and one group reached over TLS with the
/// authority of `pki`, written to the directory of `fixture`, with its path.
fn document(fixture: &Fixture, pki: &Pki) -> (Value, PathBuf) {
    let site = pki.issue("a", &["DNS:a.test"]);
    let document = json!({
        "sites": [{"name": "a", "hosts": ["a.test"], "certificate": {"chain_file": site.cert, "key_file": site.key}}],
        "upstreams": {"app": {
            "servers": [{"address": "127.0.0.1:9443", "weight": 1, "max_fails": 1, "fail_timeout_ms": 1000, "backup": false}],
            "tls": {"ca_file": pki.ca(), "server_name": "app.test"},
        }},
        "routes": [],
        "default_upstream": "app",
    });
    let path = fixture.root().join("document.json");
    fs::write(&path, serde_json::to_vec_pretty(&document).unwrap()).unwrap();
    (document, path)
}

#[test]
fn import_makes_a_version_activate_chooses_it_and_list_shows_it() {
    let (fixture, pki) = (Fixture::new(), Pki::new());
    let main = fixture.main_file(|_| {});
    let main = main.to_str().unwrap();
    let (written, path) = document(&fixture, &pki);
    let path = path.to_str().unwrap();
    let (exit, out, lines) = command(&["import", main, path]);
    assert_eq!(exit, Exit::Done, "{lines:?}");
    let name = out.split_whitespace().next().unwrap().to_owned();
    assert_eq!(out, format!("{name} created\n"));
    let (exit, out, _) = command(&["import", main, path]);
    assert_eq!((exit, out), (Exit::Done, format!("{name} existing\n")));
    // The files are in the store under their SHA-256, and the version names them so.
    let store = fixture.store();
    let key_file = written["sites"][0]["certificate"]["key_file"]
        .as_str()
        .unwrap();
    let key = sha256(&fs::read(key_file).unwrap());
    let version: Value =
        serde_json::from_slice(&store.version(digest(&name).unwrap()).unwrap()).unwrap();
    assert_eq!(version["sites"][0]["certificate"]["key"], json!(hex(&key)));
    assert!(store.file(key).is_ok());
    assert_eq!(store.current(), Ok(None));

    let (exit, out, lines) = command(&["activate", main, &name]);
    assert_eq!(exit, Exit::Done, "{lines:?}");
    assert_eq!(out, format!("{name} current\n"));
    assert_eq!(store.current(), Ok(Some(digest(&name).unwrap())));
    let (exit, out, _) = command(&["list", main]);
    assert_eq!(exit, Exit::Done);
    assert!(
        out.starts_with(&name) && out.ends_with(" current\n"),
        "{out}"
    );
}

#[test]
fn a_version_that_the_proxy_would_refuse_is_not_chosen() {
    let (fixture, pki) = (Fixture::new(), Pki::new());
    let main = fixture.main_file(|_| {});
    let main = main.to_str().unwrap();
    let (document, path) = document(&fixture, &pki);
    let (_, out, _) = command(&["import", main, path.to_str().unwrap()]);
    let good = out.split_whitespace().next().unwrap().to_owned();
    assert_eq!(command(&["activate", main, &good]).0, Exit::Done);

    // A document whose key is not the key of its certificate, or whose file of authorities holds no certificate, puts
    // nothing in the store.
    let other = pki.issue("b", &["DNS:a.test"]);
    let files = || fs::read_dir(fixture.dir().join("files")).unwrap().count();
    let before = files();
    for (pointer, why) in [
        (
            "/sites/0/certificate/key_file",
            "managed import: a certificate and a private key are not a pair (site a)",
        ),
        (
            "/upstreams/app/tls/ca_file",
            "managed import: an upstream ca_file does not hold 1 to 100 certificates in PEM (upstream app)",
        ),
    ] {
        let mut bad = document.clone();
        *bad.pointer_mut(pointer).unwrap() = json!(other.key);
        fs::write(&path, serde_json::to_vec(&bad).unwrap()).unwrap();
        let (exit, _, lines) = command(&["import", main, path.to_str().unwrap()]);
        assert_eq!(exit, Exit::Failed);
        assert_eq!(lines, [why]);
        assert_eq!(files(), before);
    }
    // A document that the main file refuses makes nothing.
    let mut bad = document.clone();
    bad["routes"] = json!([{"path": "/", "upstream": "app", "max_body": 1048577}]);
    fs::write(&path, serde_json::to_vec(&bad).unwrap()).unwrap();
    let (exit, out, lines) = command(&["import", main, path.to_str().unwrap()]);
    assert_eq!((exit, out.as_str()), (Exit::Failed, ""));
    assert!(lines.contains(
        &"managed import: document refused: a route max_body is above the max_body of the proxy".to_owned()
    ));
    // A version whose file of authorities holds no certificate passes the reading of the main file but not the
    // making of the TLS of its group, and is not chosen.
    let mut version: Value =
        serde_json::from_slice(&fixture.store().version(digest(&good).unwrap()).unwrap()).unwrap();
    version["upstreams"]["app"]["tls"]["ca"] = json!(hex(&fixture.file(b"no certificate")));
    let broken = fixture.version(&version);
    let (exit, _, lines) = command(&["activate", main, &hex(&broken)]);
    assert_eq!(exit, Exit::Failed);
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("managed activate: upstream refused: ")),
        "{lines:?}"
    );
    assert_eq!(fixture.store().current(), Ok(Some(digest(&good).unwrap())));
    // So is a version that the main file refuses, with the exit code of `import` for a refused document.
    let mut over: Value =
        serde_json::from_slice(&fixture.store().version(digest(&good).unwrap()).unwrap()).unwrap();
    over["routes"] = json!([{"path": "/", "upstream": "app", "max_body": 1048577}]);
    let over = fixture.version(&over);
    let (exit, _, lines) = command(&["activate", main, &hex(&over)]);
    assert_eq!(exit, Exit::Failed);
    assert!(lines.contains(
        &"managed activate: managed version refused: a route max_body is above the max_body of the proxy".to_owned()
    ));
    assert_eq!(fixture.store().current(), Ok(Some(digest(&good).unwrap())));
    // So is a version that is not in the store.
    assert_eq!(command(&["activate", main, HEX]).0, Exit::Failed);
    assert_eq!(fixture.store().current(), Ok(Some(digest(&good).unwrap())));
}

#[test]
fn a_main_file_without_managed_is_refused() {
    let fixture = Fixture::new();
    let main = fixture.main_file(|m| {
        m.as_object_mut().unwrap().remove("managed");
        m["forward"] = json!({
            "resolve_timeout_ms": 1000,
            "upstreams": {"app": {"servers": [{"address": "127.0.0.1:9000", "weight": 1, "max_fails": 1, "fail_timeout_ms": 1000, "backup": false}]}},
            "routes": [],
            "default_upstream": "app",
        });
    });
    let (exit, _, lines) = command(&["list", main.to_str().unwrap()]);
    assert_eq!(exit, Exit::Usage);
    assert_eq!(
        lines,
        ["managed list: configuration refused: there is no managed object"]
    );
}

fn digest(text: &str) -> Option<[u8; 32]> {
    Fingerprint::from_hex(text.as_bytes()).map(|name| name.bytes())
}
