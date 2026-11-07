//! The routes of the managed configuration in real processes: the proxy with a configuration with `managed` and a
//! control socket, and the admin process over the same configuration. An owner is made with `admin bootstrap` and logs
//! in, and reads the values of the main file. A version that sends every request to another group is checked and then
//! saved through the API; its job puts it in force, which the next request shows, and the way back puts the version
//! before it in force again.

use std::fs;
use std::net::SocketAddr;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;
use std::thread;
use std::time::Instant;

use serde_json::{Value, json};

use crate::admin::{Admin, OWNER, bootstrap, cookie_of, json_of};
use crate::support::*;
use crate::tls::Pki;

/// The groups of the test: `main` for every request, and `other`.
fn forward(addresses: &[SocketAddr]) -> Value {
    json!({
        "resolve_timeout_ms": RESOLVE_TIMEOUT_MS,
        "upstreams": {
            "main": {"servers": [server(addresses[0])]},
            "other": {"servers": [server(addresses[1])]},
        },
        "routes": [],
        "default_upstream": "main",
    })
}

/// A user who is logged in to the admin process.
struct Session<'a> {
    admin: &'a Admin,
    cookie: String,
    csrf: String,
}

impl Session<'_> {
    fn get(&self, path: &str) -> Value {
        let answer = self
            .admin
            .call("GET", path, &[("Cookie", &self.cookie)], "");
        assert_eq!(answer.status(), 200, "{path}: {:?}", json_of(&answer));
        json_of(&answer)
    }

    /// A change, with its status and the JSON of the answer.
    fn post(&self, path: &str, body: &Value) -> (u16, Value) {
        let fields = [
            ("Content-Type", "application/json"),
            ("Cookie", self.cookie.as_str()),
            ("X-CSRF-Token", self.csrf.as_str()),
        ];
        let answer = self.admin.call("POST", path, &fields, &body.to_string());
        (answer.status(), json_of(&answer))
    }

    /// The last job once it has ended.
    fn ended_job(&self) -> Value {
        let by = Instant::now() + 6 * MARGIN;
        loop {
            let job = self.get("/api/managed/job")["job"].clone();
            if job["state"] == "ended" {
                return job;
            }
            assert!(Instant::now() < by, "the job did not end: {job}");
            thread::sleep(50 * MS);
        }
    }
}

#[test]
#[ignore = "needs a built inspector"]
fn a_version_saved_through_the_api_is_put_in_force_by_its_job_and_then_rolled_back() {
    let mut pki = Pki::new("adm_mng");
    let route = pki.issue("admin", &["admin.a.example"]);
    let admin_port = free_port();
    let mut first = String::new();
    let knobs = Knobs {
        upstreams: 2,
        forward,
        ..Knobs::quick()
    };
    let proxy = Proxy::start_with("adm_mng", knobs, |root| {
        for name in ["ctl", "admin"] {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(root.join(name))
                .expect("make a directory of the test");
        }
        first = manage(root, |main, _| {
            main["admin"] = json!({
                "listen": format!("127.0.0.1:{admin_port}"),
                "control": root.join("ctl").join("c.sock"),
                "store": {"kind": "file", "dir": root.join("admin")},
                "origin": "https://admin.a.example",
                "trusted_proxies": [],
                "mfa": "optional",
                "session_idle_ms": 1_800_000,
                "session_total_ms": 43_200_000,
                "route": {
                    "host": "admin.a.example",
                    "certificate": {"cert_file": route.0, "key_file": route.1},
                    "access": {"allow_cidrs": ["127.0.0.1/32"]},
                },
            });
        });
    });
    let root: &Path = proxy.root();
    let made = bootstrap(root, "alice", &format!("{OWNER}\n"));
    assert_eq!(made.code, Some(0), "{}", made.err);
    let admin = Admin::start(root, admin_port);
    let login = admin.call(
        "POST",
        "/api/login",
        &[("Content-Type", "application/json")],
        &json!({"name": "alice", "password": OWNER}).to_string(),
    );
    assert_eq!(login.status(), 200);
    let session = Session {
        admin: &admin,
        cookie: cookie_of(&login),
        csrf: json_of(&login)["csrf"].as_str().unwrap().to_owned(),
    };

    // The store chooses the version of the start, and the proxy serves it.
    let state = session.get("/api/managed");
    assert_eq!(
        (&state["current"], &state["serving"]),
        (&json!(first), &json!(first))
    );
    assert_eq!(exchange(proxy.port, &get("/x")).status(), 200);
    assert_eq!(proxy.upstream.requests().len(), 1);

    // The values of the main file are those the proxy follows, without a path.
    let values = session.get("/api/config");
    assert_eq!(
        (&values["managed"], &values["admin"]["control"]),
        (&json!(true), &json!(true))
    );
    assert_eq!(
        values["sha256"],
        session.get("/api/status")["proxy"]["config"]
    );
    assert!(!values.to_string().contains(root.to_str().unwrap()));

    // A version that sends every request to `other` is checked, which changes nothing, then saved, and its job puts it
    // in force.
    let mut version = session.get(&format!("/api/managed/versions/{first}"))["version"].clone();
    version["default_upstream"] = json!("other");
    let listed = session.get("/api/managed/versions")["versions"].clone();
    let (status, checked) = session.post(
        "/api/managed/check",
        &json!({"version": version, "files": []}),
    );
    assert_eq!(status, 200, "{checked}");
    let mut broken = version.clone();
    broken["routes"] = json!([{"path": "x", "upstream": "main"}]);
    let (status, refused) = session.post(
        "/api/managed/check",
        &json!({"version": broken, "files": []}),
    );
    assert_eq!(
        (status, refused),
        (
            400,
            json!({"error": "a route path does not start with /", "at": "routes[0].path"})
        )
    );
    assert_eq!(session.get("/api/managed/versions")["versions"], listed);
    let (status, saved) = session.post(
        "/api/managed/apply",
        &json!({"expect": first, "version": version, "files": []}),
    );
    assert_eq!(status, 202, "{saved}");
    assert_eq!(saved["version"], checked["version"]);
    let second = saved["version"].as_str().unwrap().to_owned();
    let job = session.ended_job();
    assert_eq!(
        (&job["kind"], &job["result"], &job["to"], &job["history"]),
        (
            &json!("apply"),
            &json!("applied"),
            &json!(second),
            &json!(true)
        )
    );
    let state = session.get("/api/managed");
    assert_eq!(
        (&state["current"], &state["serving"], &state["rollback_to"]),
        (&json!(second), &json!(second), &json!(first))
    );
    assert_eq!(exchange(proxy.port, &get("/x")).status(), 200);
    assert_eq!(proxy.others[0].requests().len(), 1);

    // The way back puts the version before it in force again.
    let (status, back) = session.post("/api/managed/rollback", &json!({"expect": second}));
    assert_eq!(status, 202, "{back}");
    let job = session.ended_job();
    assert_eq!(
        (&job["kind"], &job["result"], &job["to"]),
        (&json!("rollback"), &json!("applied"), &json!(first))
    );
    assert_eq!(session.get("/api/managed")["current"], json!(first));
    assert_eq!(exchange(proxy.port, &get("/x")).status(), 200);
    assert_eq!(proxy.upstream.requests().len(), 2);
    let history = session.get("/api/managed/history");
    let kinds: Vec<(&Value, &Value)> = history["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|line| (&line["kind"], &line["result"]))
        .collect();
    assert_eq!(
        kinds,
        [
            (&json!("rollback"), &json!("applied")),
            (&json!("apply"), &json!("applied")),
        ]
    );
}
