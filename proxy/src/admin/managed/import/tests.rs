use std::fs;
use std::sync::atomic::Ordering;

use serde_json::Value;

use super::*;
use crate::admin::managed::Op;
use crate::admin::managed::routes::tests::{Rig, bare_version, rig};
use crate::forward::tls::tests::Pki;

/// The content of the files of the site `a` (for `a.test`) and of the authorities of the group `app`.
struct Files {
    chain: String,
    key: String,
    ca: String,
}

fn files(pki: &Pki) -> Files {
    let site = pki.issue("a", &["DNS:a.test"]);
    let read = |path| String::from_utf8(fs::read(path).unwrap()).unwrap();
    Files {
        chain: read(site.cert),
        key: read(site.key),
        ca: read(pki.ca()),
    }
}

/// A version with the site `a` whose chain and key are `chain` and `key`, and the group `app` reached over TLS with
/// the authorities `ca`.
fn version(chain: &str, key: &str, ca: &str) -> Value {
    let name = |text: &str| hex(&sha256(text.as_bytes()));
    json!({
        "sites": [{"name": "a", "hosts": ["a.test"], "certificate": {"chain": name(chain), "key": name(key)}}],
        "upstreams": {"app": {
            "servers": [{"address": "127.0.0.1:9443", "weight": 1, "max_fails": 1, "fail_timeout_ms": 1000, "backup": false}],
            "tls": {"ca": name(ca), "server_name": "app.test"},
        }},
        "routes": [],
        "default_upstream": "app",
    })
}

fn apply(rig: &Rig, body: &Value) -> Answer {
    apply_text(rig, &body.to_string())
}

fn apply_text(rig: &Rig, body: &str) -> Answer {
    rig.call(Op::Apply, "POST", "/api/managed/apply", body)
}

fn body(rig: &Rig, version: &Value, files: &[&str]) -> Value {
    body_from(rig.first, version, files)
}

fn body_from(expect: [u8; 32], version: &Value, files: &[&str]) -> Value {
    json!({"expect": hex(&expect), "version": version, "files": files})
}

/// The versions and the files of the store.
fn stored(rig: &Rig) -> (Vec<String>, Vec<String>) {
    (rig.entries("versions"), rig.entries("files"))
}

#[test]
fn a_version_and_its_files_are_saved_after_the_audit_and_the_job_puts_it_in_force() {
    let (rig, pki) = (rig(true), Pki::new());
    let f = files(&pki);
    let version = version(&f.chain, &f.key, &f.ca);
    // The version may come in any written form; it is saved in its one written form, whose SHA-256 is its name.
    let text = format!(
        "{{\"files\": {}, \"version\": {}, \"expect\": \"{}\"}}",
        json!([f.chain, f.key, f.ca]),
        serde_json::to_string_pretty(&version).unwrap(),
        hex(&rig.first)
    );
    let name = sha256(&serde_json::to_vec(&version).unwrap());
    let answer = apply_text(&rig, &text);
    assert_eq!(answer.status, StatusCode::ACCEPTED, "{}", answer.body);
    assert_eq!(
        (&answer.body["version"], &answer.body["placed"]),
        (&json!(hex(&name)), &json!("created"))
    );
    assert_eq!(
        (&answer.body["job"]["kind"], &answer.body["job"]["to"]),
        (&json!("apply"), &json!(hex(&name)))
    );
    let store = rig.fixture.store();
    assert_eq!(
        store.version(name).unwrap(),
        serde_json::to_vec(&version).unwrap()
    );
    for file in [&f.chain, &f.key, &f.ca] {
        assert_eq!(
            store.file(sha256(file.as_bytes())).unwrap().as_slice(),
            file.as_bytes()
        );
    }
    // The job puts it in force, and only then does the store choose it.
    assert_eq!(rig.ended_job()["result"], json!("applied"));
    assert_eq!(store.current(), Ok(Some(name)));
    let lines = rig.audit();
    let words: Vec<(&Value, &Value, &Value)> = lines
        .iter()
        .map(|line| (&line["action"], &line["result"], &line["target"]))
        .collect();
    let target = json!(hex(&name));
    assert_eq!(
        words,
        [
            (&json!("managed-import"), &json!("ok"), &target),
            (&json!("managed-apply"), &json!("ok"), &target),
        ]
    );
    // The same version again is the same version, and its putting in force passes.
    let again = apply(&rig, &body_from(name, &version, &[&f.chain, &f.key, &f.ca]));
    assert_eq!(again.body["placed"], json!("existing"));
    assert_eq!(rig.ended_job()["result"], json!("applied"));
    // A version may name files that the store has without bringing them.
    let mut routed = version.clone();
    routed["routes"] = json!([{"path": "/app", "upstream": "app"}]);
    let answer = apply(&rig, &body_from(name, &routed, &[]));
    assert_eq!(
        (answer.status, &answer.body["placed"]),
        (StatusCode::ACCEPTED, &json!("created"))
    );
    let job = rig.ended_job();
    // The key is in no answer, no job and no line of the audit log or of the history.
    let middle = f.key.lines().nth(1).unwrap();
    let history = rig.get(Op::History, "/api/managed/history").body;
    for text in [
        answer.body.to_string(),
        job.to_string(),
        history.to_string(),
    ] {
        assert!(!text.contains(middle));
    }
    assert!(
        rig.audit()
            .iter()
            .all(|line| !line.to_string().contains(middle))
    );
}

#[test]
fn a_request_brings_at_most_192_files_of_at_most_1_mib_each() {
    let rig = rig(true);
    let before = stored(&rig);
    let version = bare_version();
    // The sentence of the refusal, and whether the proxy was asked: whether the request got past its body.
    let refusal = |files: &[String]| {
        let files: Vec<&str> = files.iter().map(String::as_str).collect();
        let asked = rig.proxy().asked.load(Ordering::SeqCst);
        let answer = apply(&rig, &body(&rig, &version, &files));
        assert_eq!(answer.status, StatusCode::BAD_REQUEST);
        let past = rig.proxy().asked.load(Ordering::SeqCst) > asked;
        (answer.body["error"].as_str().unwrap().to_owned(), past)
    };
    // At the limit, the files are taken and refused by the next check, for the version does not name them; past it,
    // the reading of the body stops.
    let unnamed = "a file of the request is not named by the version".to_owned();
    let many: Vec<String> = (0..192).map(|n| format!("file {n}")).collect();
    assert_eq!(refusal(&many), (unnamed.clone(), true));
    let more: Vec<String> = (0..193).map(|n| format!("file {n}")).collect();
    assert_eq!(
        refusal(&more),
        ("the request has more than 192 files".to_owned(), false)
    );
    assert_eq!(refusal(&["x".repeat(1 << 20)]), (unnamed, true));
    assert_eq!(
        refusal(&["x".repeat((1 << 20) + 1)]),
        ("a file of the request is over 1 MiB".to_owned(), false)
    );
    assert_eq!(stored(&rig), before);
    assert!(rig.audit().is_empty());
}

#[test]
fn a_refused_body_saves_nothing_and_is_not_audited() {
    let (rig, pki) = (rig(true), Pki::new());
    let f = files(&pki);
    let before = stored(&rig);
    let good = version(&f.chain, &f.key, &f.ca);
    // A version with a path, or with a key twice, is refused before anything is asked or read.
    let mut chain_file = good.clone();
    chain_file["sites"][0]["certificate"] =
        json!({"chain_file": "/etc/a.pem", "key_file": "/etc/a.key"});
    let mut ca_file = good.clone();
    ca_file["upstreams"]["app"]["tls"] = json!({"ca_file": "/etc/ca.pem"});
    for (version, why) in [
        (&chain_file, "configuration has an unknown key"),
        (&ca_file, "configuration has an unknown key"),
    ] {
        let answer = apply(&rig, &body(&rig, version, &[]));
        assert_eq!(
            (answer.status, &answer.body["error"]),
            (StatusCode::BAD_REQUEST, &json!(why))
        );
    }
    let twice = format!(
        "{{\"expect\": \"{}\", \"files\": [], \"version\": {{\"sites\": [], \"sites\": [], \"upstreams\": {{}}, \"routes\": [], \"default_upstream\": \"app\"}}}}",
        hex(&rig.first)
    );
    let answer = apply_text(&rig, &twice);
    assert_eq!(
        answer.body["error"],
        json!("configuration has a repeated key")
    );
    assert_eq!(rig.proxy().asked.load(Ordering::SeqCst), 0);
    // The files must be those the version names, each once, and a file it names must come or be in the store.
    let other = files(&pki);
    for (files, why) in [
        (
            vec![&f.chain, &f.key, &f.ca, &other.key],
            "a file of the request is not named by the version",
        ),
        (
            vec![&f.chain, &f.key, &f.ca, &f.ca],
            "two files of the request have the same content",
        ),
        (vec![&f.chain, &f.key], "a managed file is not in the store"),
    ] {
        let files: Vec<&str> = files.iter().map(|file| file.as_str()).collect();
        let answer = apply(&rig, &body(&rig, &good, &files));
        assert_eq!(
            (answer.status, &answer.body["error"]),
            (StatusCode::BAD_REQUEST, &json!(why))
        );
    }
    assert_eq!(stored(&rig), before);
    assert!(rig.audit().is_empty());
    // A chain of the store with a new key that is not its key is not a pair.
    assert_eq!(
        apply(&rig, &body(&rig, &good, &[&f.chain, &f.key, &f.ca])).status,
        StatusCode::ACCEPTED
    );
    assert_eq!(rig.ended_job()["result"], json!("applied"));
    let before = stored(&rig);
    let lines = rig.audit().len();
    let unpaired = version(&f.chain, &other.key, &f.ca);
    let chosen = sha256(&serde_json::to_vec(&good).unwrap());
    let answer = apply(&rig, &body_from(chosen, &unpaired, &[&other.key]));
    assert_eq!(
        (answer.status, &answer.body["error"]),
        (
            StatusCode::BAD_REQUEST,
            &json!("a certificate and a private key are not a pair (site a)")
        )
    );
    assert!(
        !answer
            .body
            .to_string()
            .contains(other.key.lines().nth(1).unwrap())
    );
    assert_eq!((stored(&rig), rig.audit().len()), (before, lines));
}

#[test]
fn nothing_is_saved_before_expect_the_proxy_and_the_audit_log_let_it() {
    let mut version = bare_version();
    version["routes"] = json!([{"path": "/app", "upstream": "app"}]);
    // A proxy that cannot be reached.
    let unreachable = rig(false);
    let before = stored(&unreachable);
    let answer = apply(&unreachable, &body(&unreachable, &version, &[]));
    assert_eq!(
        (answer.status, &answer.body["error"]),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            &json!("the proxy cannot be reached")
        )
    );
    let line = unreachable.audit().pop().unwrap();
    assert_eq!(
        (&line["action"], &line["result"], &line["reason"]),
        (
            &json!("managed-apply"),
            &json!("denied"),
            &json!("unreachable")
        )
    );
    assert_eq!(stored(&unreachable), before);
    // The history has the line of the change that could not reach the proxy.
    let history = unreachable.get(Op::History, "/api/managed/history").body;
    let newest = &history["entries"][0];
    assert_eq!(
        (&newest["kind"], &newest["result"], &newest["from"]),
        (
            &json!("apply"),
            &json!("unreachable"),
            &json!(hex(&unreachable.first))
        )
    );

    let rig = rig(true);
    let before = stored(&rig);
    let send = |expect: [u8; 32]| {
        apply(
            &rig,
            &json!({"expect": hex(&expect), "version": version, "files": []}),
        )
    };
    let denied = |reason: &str| {
        let line = rig.audit().pop().unwrap();
        assert_eq!(
            (&line["action"], &line["result"], &line["reason"]),
            (&json!("managed-apply"), &json!("denied"), &json!(reason))
        );
    };
    let answer = send([7; 32]);
    assert_eq!(
        (answer.status, &answer.body["error"]),
        (
            StatusCode::CONFLICT,
            &json!("the chosen managed version is not the one that was expected")
        )
    );
    denied("expect");
    rig.proxy().closing.store(true, Ordering::SeqCst);
    assert_eq!(send(rig.first).status, StatusCode::SERVICE_UNAVAILABLE);
    denied("busy");
    rig.proxy().closing.store(false, Ordering::SeqCst);
    *rig.proxy().serving.lock().unwrap() = None;
    assert_eq!(send(rig.first).status, StatusCode::CONFLICT);
    denied("unmanaged");
    *rig.proxy().serving.lock().unwrap() = Some(rig.first);
    rig.audit_fails.store(true, Ordering::SeqCst);
    let answer = send(rig.first);
    assert_eq!(answer.status, StatusCode::SERVICE_UNAVAILABLE);
    rig.audit_fails.store(false, Ordering::SeqCst);
    // A change under way in this process holds the right to change.
    let Ok(seat) = rig.managed.seat() else {
        panic!("the right to change is free")
    };
    assert_eq!(
        send(rig.first).body["error"],
        json!("a change of the managed configuration is under way")
    );
    drop(seat);
    // A main file that names another store now.
    rig.fixture
        .main_file(|main| main["managed"] = json!({"dir": "/var/lib/elsewhere"}));
    assert_eq!(send(rig.first).status, StatusCode::CONFLICT);
    denied("managed");
    assert_eq!(stored(&rig), before);
}
