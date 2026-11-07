use std::fs;

use serde_json::json;

use super::*;
use crate::admin::managed::Op;
use crate::admin::managed::routes::tests::rig;
use crate::rules::bundle::sha256;

/// The strings of `value` that are absolute paths.
fn paths(value: &Value, found: &mut Vec<String>) {
    match value {
        Value::String(text) if text.starts_with('/') => found.push(text.clone()),
        Value::Array(list) => list.iter().for_each(|entry| paths(entry, found)),
        Value::Object(object) => object.values().for_each(|entry| paths(entry, found)),
        _ => {}
    }
}

#[test]
fn the_values_of_the_main_file_are_shown_without_its_paths() {
    let rig = rig(false);
    let path = rig.fixture.root().join("config.json");
    // The answer has none of the paths of the file, and `true` for each.
    let values = |path: &std::path::Path| {
        let answer = rig.get(Op::Config, "/api/config");
        assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
        let file: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let mut written = Vec::new();
        paths(&file, &mut written);
        assert!(!written.is_empty());
        let text = answer.body.to_string();
        for written in written {
            assert!(!text.contains(&written), "{written}");
        }
        assert_eq!(
            answer.body["sha256"],
            json!(hex(&sha256(&fs::read(path).unwrap())))
        );
        answer.body
    };
    let managed = values(&path);
    assert_eq!(
        (
            &managed["managed"],
            &managed["kernel"]["inspector"],
            &managed["rules"]["store"]["dir"]
        ),
        (&json!(true), &json!(true), &json!(true))
    );
    assert_eq!(managed["forward"], json!({"resolve_timeout_ms": 30000}));
    // Without `managed` the file writes its routing, which is shown, the paths in it too.
    fixture_without_managed(&rig.fixture);
    let unmanaged = values(&path);
    assert_eq!(unmanaged["managed"], json!(false));
    assert_eq!(
        unmanaged["forward"]["upstreams"]["app"],
        json!({
            "servers": [{"address": "127.0.0.1:9000", "weight": 1, "max_fails": 1, "fail_timeout_ms": 1000, "backup": false}],
            "tls": {"ca_file": true, "server_name": "app.test"},
        })
    );
    assert_eq!(
        (
            &unmanaged["admin"]["control"],
            &unmanaged["admin"]["crs_dir"]
        ),
        (&json!(true), &Value::Null)
    );
    // A file that is refused is not shown.
    fs::write(&path, b"{}").unwrap();
    let refused = rig.get(Op::Config, "/api/config");
    assert_eq!(
        (refused.status, &refused.body["error"]),
        (
            StatusCode::CONFLICT,
            &json!("configuration has a missing key")
        )
    );
}

/// Writes the main file of `fixture` without `managed`, with its own routing and an `admin` without `crs_dir`.
fn fixture_without_managed(fixture: &crate::managed::store::tests::Fixture) {
    fixture.main_file(|m| {
        m.as_object_mut().unwrap().remove("managed");
        m["forward"]["upstreams"] = json!({"app": {
            "servers": [{"address": "127.0.0.1:9000", "weight": 1, "max_fails": 1, "fail_timeout_ms": 1000, "backup": false}],
            "tls": {"ca_file": "/etc/tukuyomi/ca.pem", "server_name": "app.test"},
        }});
        m["forward"]["routes"] = json!([]);
        m["forward"]["default_upstream"] = json!("app");
        m["admin"] = json!({
            "listen": "127.0.0.1:9180", "control": "/run/tukuyomi/admin.sock",
            "store": {"kind": "file", "dir": "/var/lib/tukuyomi/admin"}, "origin": "https://admin.test",
            "trusted_proxies": [], "mfa": "optional", "session_idle_ms": 600_000, "session_total_ms": 3_600_000,
        });
    });
}
