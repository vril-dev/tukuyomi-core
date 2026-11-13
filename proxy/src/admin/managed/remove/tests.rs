use std::sync::atomic::Ordering;

use serde_json::{Value, json};

use super::*;
use crate::admin::managed::Op;
use crate::admin::managed::routes::tests::{Rig, bare_version, rig};

/// A version without a site whose route for `path` goes to `app`.
fn routed(path: &str) -> Value {
    let mut version = bare_version();
    version["routes"] = json!([{"path": path, "upstream": "app"}]);
    version
}

fn delete(rig: &Rig, name: &str) -> Answer {
    rig.call(
        Op::Remove,
        "DELETE",
        &format!("/api/managed/versions/{name}"),
        "",
    )
}

/// The result, the reason and the target of the newest line of the audit log.
fn audited(rig: &Rig) -> (Value, Value, Value) {
    let line = rig.audit().pop().unwrap();
    (
        line["result"].clone(),
        line["reason"].clone(),
        line["target"].clone(),
    )
}

#[test]
fn the_chosen_version_and_the_target_of_a_rollback_are_kept_and_a_refusal_removes_nothing() {
    let rig = rig(true);
    let (first, second, third) = (
        rig.first,
        rig.fixture.version(&routed("/a")),
        rig.fixture.version(&routed("/b")),
    );
    for name in ["x".to_owned(), hex(&[9; 32])] {
        assert_eq!(delete(&rig, &name).status, StatusCode::NOT_FOUND, "{name}");
    }
    let answer = delete(&rig, &hex(&first));
    assert_eq!(
        (answer.status, &answer.body["error"]),
        (
            StatusCode::CONFLICT,
            &json!("the version is the one the managed store chooses")
        )
    );
    assert_eq!(
        audited(&rig),
        (json!("denied"), json!("chosen"), json!(hex(&first)))
    );
    // Once the second version is put in force, the first one is the target of a rollback.
    let body = json!({"expect": hex(&first), "version": hex(&second)});
    let answer = rig.call(Op::Activate, "POST", "/x", &body.to_string());
    assert_eq!(answer.status, StatusCode::ACCEPTED, "{}", answer.body);
    assert_eq!(rig.ended_job()["result"], json!("applied"));
    let answer = delete(&rig, &hex(&first));
    assert_eq!(
        (answer.status, &answer.body["error"]),
        (
            StatusCode::CONFLICT,
            &json!("the version is the target of a rollback")
        )
    );
    assert_eq!(
        audited(&rig),
        (
            json!("denied"),
            json!("rollback target"),
            json!(hex(&first))
        )
    );
    // A change under way holds the right to change.
    let Ok(seat) = rig.managed.seat() else {
        panic!("the right to change is free")
    };
    let answer = delete(&rig, &hex(&third));
    assert_eq!(
        (answer.status, &answer.body["error"]),
        (
            StatusCode::CONFLICT,
            &json!("a change of the managed configuration is under way")
        )
    );
    drop(seat);
    // An audit log that does not take the line before the removal leaves the version where it is.
    rig.audit_fails.store(true, Ordering::SeqCst);
    assert_eq!(
        delete(&rig, &hex(&third)).status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    rig.audit_fails.store(false, Ordering::SeqCst);
    let store = rig.fixture.store();
    for name in [first, second, third] {
        assert!(store.version(name).is_ok());
    }
}

#[test]
fn a_version_is_removed_unless_the_store_finds_it_held() {
    let rig = rig(true);
    let (held, other) = (
        rig.fixture.version(&routed("/a")),
        rig.fixture.version(&routed("/b")),
    );
    // A version whose file is held, as by a proxy that serves with it, which the proxy of the test is not.
    let (_, hold) = rig.fixture.store().hold(held).unwrap();
    let answer = delete(&rig, &hex(&held));
    assert_eq!(
        (answer.status, &answer.body["error"]),
        (
            StatusCode::CONFLICT,
            &json!("the managed version is in use")
        )
    );
    assert_eq!(
        audited(&rig),
        (json!("failed"), json!("store"), json!(hex(&held)))
    );
    drop(hold);
    assert!(rig.fixture.store().version(held).is_ok());
    let answer = delete(&rig, &hex(&other));
    assert_eq!(
        (answer.status, answer.body),
        (
            StatusCode::OK,
            json!({"removed": hex(&other), "cleaned": true})
        )
    );
    assert_eq!(
        audited(&rig),
        (json!("ok"), Value::Null, json!(hex(&other)))
    );
    assert!(rig.fixture.store().version(other).is_err());
    assert!(rig.fixture.store().version(held).is_ok());
}
