use std::fs;
use std::sync::atomic::Ordering;

use serde_json::json;

use super::*;
use crate::admin::managed::Op;
use crate::admin::managed::routes::tests::{CONFIG, CX, Rig, bare_version, rig, rig_with, who};
use crate::admin::users::Role;

/// A version without a site whose route for `path` goes to `app`.
fn routed(path: &str) -> Value {
    let mut version = bare_version();
    version["routes"] = json!([{"path": path, "upstream": "app"}]);
    version
}

fn post(rig: &Rig, op: Op, body: Value) -> Answer {
    rig.call(op, "POST", "/x", &body.to_string())
}

fn activate(rig: &Rig, expect: [u8; 32], to: [u8; 32]) -> Answer {
    post(
        rig,
        Op::Activate,
        json!({"expect": hex(&expect), "version": hex(&to)}),
    )
}

fn rollback(rig: &Rig, expect: [u8; 32]) -> Answer {
    post(rig, Op::Rollback, json!({"expect": hex(&expect)}))
}

fn current(rig: &Rig) -> Option<[u8; 32]> {
    rig.fixture.store().current().unwrap()
}

/// The newest line of the history.
fn newest(rig: &Rig) -> Value {
    rig.get(Op::History, "/api/managed/history").body["entries"][0].clone()
}

#[test]
fn a_version_is_put_in_force_by_name_and_back_and_the_history_and_the_audit_log_follow() {
    let rig = rig(true);
    let (first, second) = (rig.first, rig.fixture.version(&routed("/a")));
    let answer = activate(&rig, first, second);
    assert_eq!(answer.status, StatusCode::ACCEPTED, "{}", answer.body);
    assert_eq!(
        (&answer.body["version"], &answer.body["job"]["kind"]),
        (&json!(hex(&second)), &json!("activate"))
    );
    let job = rig.ended_job();
    assert_eq!(
        (&job["result"], &job["from"], &job["to"], &job["history"]),
        (
            &json!("applied"),
            &json!(hex(&first)),
            &json!(hex(&second)),
            &json!(true)
        )
    );
    assert_eq!(
        (&job["config_before"], &job["config_after"], &job["actor"]),
        (&json!(hex(&CONFIG)), &json!(hex(&CONFIG)), &json!("ola"))
    );
    assert_eq!(current(&rig), Some(second));
    assert_eq!(*rig.proxy().orders.lock().unwrap(), [second]);
    let line = newest(&rig);
    assert_eq!(
        (&line["kind"], &line["result"], &line["from"], &line["to"]),
        (
            &json!("activate"),
            &json!("applied"),
            &json!(hex(&first)),
            &json!(hex(&second))
        )
    );
    // The line of the audit log came before the order, with both versions.
    let audit = rig.audit().pop().unwrap();
    assert_eq!(
        (&audit["action"], &audit["result"], &audit["target"]),
        (
            &json!("managed-activate"),
            &json!("ok"),
            &json!(hex(&second))
        )
    );
    let state = rig.get(Op::State, "/api/managed").body;
    assert_eq!(
        (
            &state["current"],
            &state["serving"],
            &state["rollback_to"],
            &state["job"]["state"]
        ),
        (
            &json!(hex(&second)),
            &json!(hex(&second)),
            &json!(hex(&first)),
            &json!("ended")
        )
    );
    // The way back goes to the version before the last change, and the right to change is free again at once.
    assert_eq!(rollback(&rig, second).status, StatusCode::ACCEPTED);
    let job = rig.ended_job();
    assert_eq!(
        (&job["kind"], &job["result"], &job["to"]),
        (&json!("rollback"), &json!("applied"), &json!(hex(&first)))
    );
    assert_eq!(current(&rig), Some(first));
    // A version that the store does not have, and a wrong `expect`.
    assert_eq!(activate(&rig, first, [9; 32]).status, StatusCode::NOT_FOUND);
    assert_eq!(activate(&rig, second, first).status, StatusCode::CONFLICT);
    assert_eq!(current(&rig), Some(first));
}

#[test]
fn a_refused_version_leaves_current_and_a_job_whose_audit_line_cannot_be_written_orders_nothing() {
    let rig = rig(true);
    let second = rig.fixture.version(&routed("/a"));
    rig.proxy().refusing.store(true, Ordering::SeqCst);
    assert_eq!(
        activate(&rig, rig.first, second).status,
        StatusCode::ACCEPTED
    );
    let job = rig.ended_job();
    assert_eq!(
        (&job["result"], &job["reason"], &job["detail"]),
        (
            &json!("refused"),
            &json!("upstream"),
            &json!("the name of a server cannot be looked up (upstream app)")
        )
    );
    assert_eq!(current(&rig), Some(rig.first));
    let line = newest(&rig);
    assert_eq!(
        (&line["result"], &line["reason"]),
        (&json!("refused"), &json!("upstream"))
    );
    let audit = rig.audit().pop().unwrap();
    assert_eq!(
        (&audit["action"], &audit["result"], &audit["reason"]),
        (
            &json!("managed-activate"),
            &json!("failed"),
            &json!("refused")
        )
    );
    // The line before the change cannot be written: the proxy is not ordered, and nothing changes.
    rig.proxy().refusing.store(false, Ordering::SeqCst);
    rig.audit_fails.store(true, Ordering::SeqCst);
    let orders = rig.proxy().orders.lock().unwrap().len();
    assert_eq!(
        activate(&rig, rig.first, second).status,
        StatusCode::ACCEPTED
    );
    let job = rig.ended_job();
    assert_eq!(
        (&job["result"], &job["history"]),
        (&json!("audit"), &Value::Null)
    );
    assert_eq!(rig.proxy().orders.lock().unwrap().len(), orders);
    assert_eq!(current(&rig), Some(rig.first));
}

#[test]
fn a_rollback_goes_back_only_from_an_applied_change_that_ends_at_the_chosen_version() {
    // The steps of a change come first: a configuration without `managed`, and a broken record of the choice.
    let unmanaged = rig_with(true, false);
    assert_eq!(
        rollback(&unmanaged, unmanaged.first).status,
        StatusCode::CONFLICT
    );
    let line = unmanaged.audit().pop().unwrap();
    assert_eq!(
        (
            &line["action"],
            &line["result"],
            &line["reason"],
            &line["target"]
        ),
        (
            &json!("managed-rollback"),
            &json!("denied"),
            &json!("managed"),
            &Value::Null
        )
    );
    let broken = rig(true);
    fs::write(broken.fixture.dir().join("current"), "broken\n").unwrap();
    assert_eq!(
        rollback(&broken, broken.first).status,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    let rig = rig(true);
    assert_eq!(
        rollback(&rig, rig.first).body["error"],
        json!("there is no change to go back from")
    );
    let second = rig.fixture.version(&routed("/a"));
    assert_eq!(
        activate(&rig, rig.first, second).status,
        StatusCode::ACCEPTED
    );
    assert_eq!(rig.ended_job()["result"], json!("applied"));
    // A command chose another version since: the history does not end at it.
    let third = rig.fixture.version(&routed("/b"));
    rig.fixture.store().choose(third).unwrap();
    assert_eq!(
        rollback(&rig, third).body["error"],
        json!("the history does not end at the chosen version")
    );
    assert_eq!(
        rig.get(Op::State, "/api/managed").body["rollback_to"],
        Value::Null
    );
}

#[test]
fn a_change_that_finds_the_process_stopping_after_it_took_the_right_starts_no_job() {
    let rig = rig(true);
    let Ok(seat) = rig.managed.seat() else {
        panic!("the right to change is free")
    };
    rig.managed.interrupt();
    let order = Order {
        kind: Kind::Activate,
        caller: Caller::of(&who(Role::Operator), &CX),
        from: rig.first,
        to: rig.first,
        resolve_timeout: Duration::from_secs(1),
        store: rig.fixture.store(),
    };
    let answer = rig.managed.start(seat, order, Instant::now(), json!({}));
    assert_eq!(answer.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        rig.get(Op::Job, "/api/managed/job").body,
        json!({"job": null})
    );
    let line = rig.audit().pop().unwrap();
    assert_eq!(
        (&line["action"], &line["result"], &line["reason"]),
        (
            &json!("managed-activate"),
            &json!("failed"),
            &json!("stopping")
        )
    );
    assert!(rig.proxy().orders.lock().unwrap().is_empty());
}
