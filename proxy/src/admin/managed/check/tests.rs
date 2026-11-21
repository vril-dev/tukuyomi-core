use std::sync::atomic::Ordering;

use serde_json::Value;
use tukuyomi_kernel::Engine;

use super::*;
use crate::admin::managed::Op;
use crate::admin::managed::routes::tests::{Rig, bare_version, rig, rig_with};

fn check(rig: &Rig, body: &Value) -> Answer {
    rig.call(Op::Check, "POST", "/api/managed/check", &body.to_string())
}

#[test]
fn a_version_is_checked_without_a_change_and_a_refusal_is_about_its_place() {
    let rig = rig(true);
    let before = (rig.entries("versions"), rig.entries("files"));
    let version = bare_version();
    let name = hex(&sha256(&serde_json::to_vec(&version).unwrap()));
    // `expect` may be left out, or be anything: the body of the saving is checked as it is.
    for body in [
        json!({"version": version, "files": []}),
        json!({"expect": 5, "version": version, "files": []}),
    ] {
        let answer = check(&rig, &body);
        assert_eq!(
            (answer.status, answer.body),
            (StatusCode::OK, json!({ "version": name, "detect": [] }))
        );
    }
    let mut broken = bare_version();
    broken["upstreams"]["app"]["servers"][0]["address"] = json!("0.0.0.0:9000");
    let answer = check(&rig, &json!({"version": broken, "files": []}));
    assert_eq!(
        (answer.status, answer.body),
        (
            StatusCode::BAD_REQUEST,
            json!({
                "error": "a server address is unspecified or a multicast address",
                "at": "upstreams.app.servers[0].address",
            })
        )
    );
    // Nothing is put in the store or written to the audit log, and the proxy is not asked.
    assert_eq!((rig.entries("versions"), rig.entries("files")), before);
    assert!(rig.audit().is_empty());
    assert_eq!(rig.proxy().asked.load(Ordering::SeqCst), 0);
    // A main file that had no `managed` when the process started has nothing to check against.
    let unmanaged = rig_with(false, false);
    assert_eq!(
        check(&unmanaged, &json!({"version": bare_version(), "files": []})).status,
        StatusCode::CONFLICT
    );
}

#[test]
fn one_check_runs_at_a_time_for_the_saving_and_the_check() {
    let rig = rig(true);
    let body = json!({"expect": hex(&rig.first), "version": bare_version(), "files": []});
    let Ok(held) = rig.managed.check_seat() else {
        panic!("the seat of the check is free");
    };
    for (op, path) in [
        (Op::Check, "/api/managed/check"),
        (Op::Apply, "/api/managed/apply"),
    ] {
        let answer = rig.call(op, "POST", path, &body.to_string());
        assert_eq!(
            (answer.status, &answer.body["error"]),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                &json!("a check of a managed version is under way")
            ),
            "{path}"
        );
    }
    drop(held);
    assert_eq!(check(&rig, &body).status, StatusCode::OK);
}

#[test]
fn a_group_whose_engine_has_no_generation_chosen_is_refused_about_its_engine_and_an_unreadable_rules_store_is_500()
 {
    let rig = rig(true);
    // The main file names an inspector for ModSecurity, as a main file that can use that engine does; the rules store
    // has a generation chosen for Coraza only.
    rig.fixture.main_file(|m| {
        m["kernel"]["engines"] =
            json!({"modsecurity": {"inspector": "/opt/tukuyomi/inspector-modsecurity"}});
    });
    let mut version = bare_version();
    version["upstreams"]["app"]["engine"] = json!("modsecurity");
    let body = json!({"version": version, "files": []});
    let answer = check(&rig, &body);
    assert_eq!(
        (answer.status, answer.body),
        (
            StatusCode::BAD_REQUEST,
            json!({
                "error": "no generation is chosen for the engine of an upstream",
                "at": "upstreams.app.engine",
            })
        )
    );
    // A record that cannot be told is a fault of the process: 500, with the sentence of the rules store.
    let record = rig.fixture.rules().join("current.modsecurity");
    std::fs::write(&record, "x").unwrap();
    let answer = check(&rig, &body);
    assert_eq!(
        (answer.status, &answer.body["error"]),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!("the current generation record is broken")
        )
    );
    std::fs::remove_file(&record).unwrap();
    rig.fixture.choose_rules(Engine::ModSecurity);
    assert_eq!(check(&rig, &body).status, StatusCode::OK);
}
