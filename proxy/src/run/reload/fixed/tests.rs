use super::*;
use crate::config;
use crate::managed::store::tests::Fixture;
use serde_json::{Value, json};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

const BASE: &str = r#"{"proxy":{"listeners":[{"address":"127.0.0.1:8080"}],"max_conns":1024,"max_head_bytes":8192,"max_body":1048576,"inspect_body":1048576,"max_body_wire":2097152,"max_buffered_bytes":8388608,"upstream_max_headers":100,"upstream_max_head_bytes":16384,"upstream_head_wire":65536,"drive_slice_ms":50,"ready_wait_ms":10000,"head_read_ms":10000,"body_read_ms":30000,"inspect_wait_ms":30000,"upstream_connect_ms":5000,"upstream_header_ms":30000,"request_total_ms":60000,"response_idle_ms":60000,"conn_total_ms":120000,"stop_inspect_ms":5000,"stop_wait_ms":10000,"keepalive_timeout_ms":75000,"keepalive_requests":1000,"keepalive_time_ms":60000,"lingering_time_ms":30000,"lingering_timeout_ms":5000,"lingering_bytes":262144,"trusted_proxies":[],"upstream_keepalive":32,"upstream_keepalive_timeout_ms":60000,"upstream_keepalive_requests":1000},"forward":{"resolve_timeout_ms":30000,"upstreams":{"main":{"servers":[{"address":"127.0.0.1:9000","weight":1,"max_fails":1,"fail_timeout_ms":10000,"backup":false}]}},"routes":[],"default_upstream":"main"},"kernel":{"inspector":"/opt/tukuyomi/inspector","tmp_root":"/var/lib/tukuyomi/tmp","gomaxprocs":2,"gomemlimit":1073741824,"slots":4,"wait_queue":16,"records":20,"discard_limit":4,"tick_ms":100,"hello_wait_ms":5000,"frame_io_ms":1000,"verdict_wait_ms":2000,"wait_deadline_ms":3000,"closed_wait_ms":2000,"stop_after_ms":2000,"drain_wait_ms":1000,"exit_wait_ms":1000,"kill_grace_ms":1000,"restarts":3,"restart_window_ms":60000},"rules":{"store":{"kind":"file","dir":"/var/lib/tukuyomi/rules"}},"records":{"dir":"/var/lib/tukuyomi/records","file_bytes":1048576,"files":4}}"#;

/// A change to the text of `BASE` that makes the file differ in one value.
type Edit = fn(&mut Value);

/// A fresh directory under the temp directory (`TMPDIR`), removed with everything in it when dropped.
struct TestDir(PathBuf);

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn scratch() -> TestDir {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "tukuyomi-proxy-fixed-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&dir).unwrap();
    TestDir(dir)
}

/// The fixed values of `BASE` after `edit` has changed it, read through `config::load` from a file of the directory.
fn fixed_after(dir: &TestDir, name: &str, edit: impl FnOnce(&mut Value)) -> Fixed {
    let mut config: Value = serde_json::from_str(BASE).unwrap();
    edit(&mut config);
    let file = dir.0.join(name);
    fs::write(&file, config.to_string()).unwrap();
    Fixed::of(&config::load(&file).unwrap())
}

#[test]
fn a_file_with_another_value_that_cannot_change_is_refused_by_the_first_such_key_and_one_without_passes()
 {
    let dir = scratch();
    let running = fixed_after(&dir, "running.json", |_| {});
    // The same file, and a file that differs only in `records.keep`, pass.
    assert_eq!(
        running.first_difference(&fixed_after(&dir, "same.json", |_| {})),
        None
    );
    let required = fixed_after(&dir, "keep.json", |c| {
        c["records"]["keep"] = json!("required");
    });
    assert_eq!(running.first_difference(&required), None);
    // So do a file with another address of the listener and a file with a listener more: the listeners may change.
    let moved = fixed_after(&dir, "moved.json", |c| {
        c["proxy"]["listeners"][0]["address"] = json!("127.0.0.1:8081");
    });
    assert_eq!(running.first_difference(&moved), None);
    let added = fixed_after(&dir, "added.json", |c| {
        c["proxy"]["listeners"]
            .as_array_mut()
            .unwrap()
            .push(json!({"address": "127.0.0.1:8082"}));
    });
    assert_eq!(running.first_difference(&added), None);

    let cases: [(&str, Edit); 5] = [
        ("proxy.max_conns", |c| c["proxy"]["max_conns"] = json!(2048)),
        ("records", |c| {
            c["records"]["dir"] = json!("/var/lib/tukuyomi/other-records");
        }),
        ("status", |c| {
            c["status"] = json!({"listen": "127.0.0.1:8090"})
        }),
        ("rules.store", |c| {
            c["rules"]["store"]["dir"] = json!("/var/lib/tukuyomi/other-rules");
        }),
        ("kernel", |c| c["kernel"]["restarts"] = json!(4)),
    ];
    for (n, (key, edit)) in cases.into_iter().enumerate() {
        let other = fixed_after(&dir, &format!("case{n}.json"), edit);
        assert_eq!(running.first_difference(&other), Some(key), "{key}");
    }
    // Two keys differ: the first one in the order of the list is named.
    let both = fixed_after(&dir, "both.json", |c| {
        c["kernel"]["restarts"] = json!(4);
        c["proxy"]["max_conns"] = json!(2048);
    });
    assert_eq!(running.first_difference(&both), Some("proxy.max_conns"));
}

#[test]
fn a_file_with_managed_keeps_its_dir_and_may_read_another_version() {
    let (one, two) = (Fixture::new(), Fixture::new());
    let fixed = |fixture: &Fixture| {
        fixture.current(&fixture.plain_version(b"chain", b"key"));
        Fixed::of(&config::load(&fixture.main_file(|_| {})).unwrap())
    };
    let running = fixed(&one);
    let mut other = one.plain_version(b"chain", b"key");
    other["default_upstream"] = json!("app");
    other["routes"] = json!([{"path": "/a/", "upstream": "app"}]);
    one.current(&other);
    let again = Fixed::of(&config::load(&one.main_file(|_| {})).unwrap());
    assert_eq!(running.first_difference(&again), None);
    assert_eq!(running.first_difference(&fixed(&two)), Some("managed"));
}

#[test]
fn the_host_of_the_way_to_the_admin_process_cannot_change_and_its_certificate_and_access_can() {
    let fixture = Fixture::new();
    fixture.current(&fixture.plain_version(b"chain", b"key"));
    let with_route = |host: &str, key_file: &str, allow: &str| {
        let main = fixture.main_file(|m| {
            m["admin"] = json!({
                "listen": "127.0.0.1:9180", "control": "/run/tukuyomi/admin.sock",
                "store": {"kind": "file", "dir": "/var/lib/tukuyomi/admin"}, "origin": "https://admin.test",
                "trusted_proxies": [], "mfa": "optional", "session_idle_ms": 600_000, "session_total_ms": 3_600_000,
                "route": {
                    "host": host,
                    "certificate": {"cert_file": "/etc/tukuyomi/admin.pem", "key_file": key_file},
                    "access": {"allow_cidrs": [allow]},
                },
            });
        });
        Fixed::of(&config::load(&main).unwrap())
    };
    let running = with_route("admin.test", "/etc/tukuyomi/admin.key", "192.0.2.0/24");
    let other = with_route("admin.test", "/etc/tukuyomi/new.key", "198.51.100.0/24");
    assert_eq!(running.first_difference(&other), None);
    let moved = with_route("panel.test", "/etc/tukuyomi/admin.key", "192.0.2.0/24");
    assert_eq!(running.first_difference(&moved), Some("admin.route.host"));
}
