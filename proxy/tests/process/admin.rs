//! The admin process in a real process, on the configuration of a test root that has the `admin` object (its store
//! is `admin/` in the root, and the control socket is never bound: no proxy runs). The first user is made with
//! `admin bootstrap` and the password on the standard input; the admin process is started, and a client logs in,
//! reads its session, changes its password, logs out and logs in again, over TCP. Then SIGTERM stops the process
//! with exit code 0. The audit log is read from the file and from the standard error of the process; the first user's
//! creation is in it as well. A configuration that asks for `mfa` `required` is refused by the process.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Instant;

use serde_json::{Value, json};

use crate::support::*;

pub(crate) const OWNER: &str = "first password 123";
const NEXT: &str = "second password 456";

/// Adds the `admin` object that listens on `port`, with this `mfa`, and the directory of its store, to the
/// configuration in `root`.
fn add_admin(root: &Path, port: u16, mfa: &str) {
    fs::DirBuilder::new()
        .mode(0o700)
        .create(root.join("admin"))
        .expect("make the directory of the admin store");
    add_object(
        root,
        "admin",
        json!({
            "listen": format!("127.0.0.1:{port}"),
            "control": root.join("ctl").join("c.sock").to_string_lossy(),
            "store": {"kind": "file", "dir": root.join("admin").to_string_lossy()},
            "origin": "https://admin.example.test",
            "trusted_proxies": [],
            "mfa": mfa,
            "session_idle_ms": 1_800_000,
            "session_total_ms": 43_200_000,
        }),
    );
}

/// How a command ended, and what it wrote.
pub(crate) struct Ran {
    pub(crate) code: Option<i32>,
    pub(crate) out: String,
    pub(crate) err: String,
}

/// Runs `tukuyomi-proxy admin <args>` with `input` on its standard input and waits for it.
fn command(args: &[&Path], input: &str) -> Ran {
    let mut child = Command::new(env!("CARGO_BIN_EXE_tukuyomi-proxy"))
        .arg("admin")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run the command");
    child
        .stdin
        .take()
        .expect("the standard input is piped")
        .write_all(input.as_bytes())
        .expect("send the password");
    let output = child.wait_with_output().expect("wait for the command");
    Ran {
        code: output.status.code(),
        out: String::from_utf8_lossy(&output.stdout).into_owned(),
        err: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

pub(crate) fn bootstrap(root: &Path, name: &str, input: &str) -> Ran {
    command(
        &[
            Path::new("bootstrap"),
            &root.join("config.json"),
            Path::new(name),
        ],
        input,
    )
}

/// The admin process, with its records as they arrive.
pub(crate) struct Admin {
    child: Child,
    records: Receiver<Value>,
    seen: Vec<Value>,
    port: u16,
    done: bool,
}

impl Admin {
    /// Starts the process on the configuration of `root` and waits until it listens.
    pub(crate) fn start(root: &Path, port: u16) -> Admin {
        let mut child = Command::new(env!("CARGO_BIN_EXE_tukuyomi-proxy"))
            .arg("admin")
            .arg(root.join("config.json"))
            .env_remove("NOTIFY_SOCKET")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start the admin process");
        let stderr = child.stderr.take().expect("the standard error is piped");
        let (send, records) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let record = serde_json::from_str(&line).unwrap_or(Value::String(line));
                if send.send(record).is_err() {
                    break;
                }
            }
        });
        let mut admin = Admin {
            child,
            records,
            seen: Vec::new(),
            port,
            done: false,
        };
        admin.wait_for("the process to listen", |r| r["line"] == "admin: listening");
        admin
    }

    /// Reads records until one satisfies `want`.
    fn wait_for(&mut self, what: &str, want: impl Fn(&Value) -> bool) {
        loop {
            match self.records.recv_timeout(MARGIN) {
                Ok(record) => {
                    let found = want(&record);
                    self.seen.push(record);
                    if found {
                        return;
                    }
                }
                Err(_) => panic!(
                    "timed out waiting for {what}; the records: {:#?}",
                    self.seen
                ),
            }
        }
    }

    /// One request on a new connection.
    pub(crate) fn call(
        &self,
        method: &str,
        path: &str,
        fields: &[(&str, &str)],
        body: &str,
    ) -> Message {
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nHost: admin.example.test\r\nContent-Length: {}\r\n",
            body.len()
        );
        for (name, value) in fields {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        request.push_str("\r\n");
        request.push_str(body);
        exchange(self.port, request.as_bytes()).message()
    }

    /// SIGTERM, and the exit status once the process is gone; the records that remain are read.
    pub(crate) fn stop(&mut self) -> ExitStatus {
        run_kill("TERM", self.child.id());
        let deadline = Instant::now() + MARGIN;
        let status = loop {
            if let Some(status) = self.child.try_wait().expect("wait for the process") {
                break status;
            }
            assert!(Instant::now() < deadline, "the process did not stop");
            thread::sleep(10 * MS);
        };
        self.done = true;
        while let Ok(record) = self.records.recv_timeout(MARGIN) {
            self.seen.push(record);
        }
        status
    }
}

impl Drop for Admin {
    fn drop(&mut self) {
        if !self.done {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

pub(crate) fn json_of(message: &Message) -> Value {
    serde_json::from_slice(&message.body).expect("the body is JSON")
}

/// The value of the cookie that the answer sets: `tukuyomi_admin=<id>` up to the first `;`.
pub(crate) fn cookie_of(message: &Message) -> String {
    let set = message.values("set-cookie");
    assert_eq!(set.len(), 1, "{:?}", message.fields);
    assert!(
        set[0].ends_with("; Secure; HttpOnly; SameSite=Strict; Path=/"),
        "{}",
        set[0]
    );
    set[0].split(';').next().expect("a pair").to_owned()
}

/// The fields that every answer has.
fn assert_fixed_fields(message: &Message) {
    for (name, value) in [
        ("content-type", "application/json"),
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
        (
            "content-security-policy",
            "default-src 'none'; frame-ancestors 'none'",
        ),
        ("referrer-policy", "no-referrer"),
    ] {
        assert_eq!(message.values(name), [value], "{name}");
    }
    assert_eq!(message.values("x-request-id").len(), 1);
}

#[test]
#[ignore = "needs a built inspector"]
fn the_first_owner_logs_in_changes_the_password_and_logs_out_and_sigterm_stops_the_process() {
    let port = free_port();
    let idle = Idle::new("admin_api", &Knobs::quick(), |root| {
        add_admin(root, port, "optional");
    });
    let root = idle.root();

    // The first user is made once.
    let made = bootstrap(root, "alice", &format!("{OWNER}\n"));
    assert_eq!(
        (made.code, made.out.as_str()),
        (Some(0), "created owner alice\n")
    );
    // The creation is audited: its line is on the standard error, and in the file (compared below).
    let created: Value = serde_json::from_str(made.err.trim_end()).expect("one line of JSON");
    for (key, value) in [
        ("type", "audit"),
        ("action", "create"),
        ("result", "ok"),
        ("target", "alice"),
        ("auth", "bootstrap"),
        ("after", "owner"),
    ] {
        assert_eq!(created[key], value, "{key}");
    }
    assert!(created.get("actor").is_none());
    // A second first user is refused by the store, after its line, and a line that says so follows.
    let again = bootstrap(root, "bob", &format!("{NEXT}\n"));
    assert_eq!((again.code, again.out.as_str()), (Some(1), ""));
    assert!(
        again
            .err
            .ends_with("admin bootstrap: the store has a user already\n"),
        "{}",
        again.err
    );
    assert_eq!(again.err.lines().count(), 3, "{}", again.err);

    let mut admin = Admin::start(root, port);
    let body = |name: &str, password: &str| json!({"name": name, "password": password}).to_string();
    let json_type = ("Content-Type", "application/json");

    // A login that fails, and one that passes.
    let refused = admin.call("POST", "/api/login", &[json_type], &body("alice", NEXT));
    assert_eq!(refused.status(), 401);
    assert_fixed_fields(&refused);
    assert!(refused.values("set-cookie").is_empty());
    let login = admin.call("POST", "/api/login", &[json_type], &body("alice", OWNER));
    assert_eq!(
        login.status(),
        200,
        "{}",
        String::from_utf8_lossy(&login.body)
    );
    assert_fixed_fields(&login);
    let session = json_of(&login);
    assert_eq!(
        (session["name"].as_str(), session["role"].as_str()),
        (Some("alice"), Some("owner"))
    );
    assert_eq!(session["mfa"], false);
    let cookie = cookie_of(&login);
    let csrf = session["csrf"].as_str().expect("a token").to_owned();

    // The session, a path that is not a route, and a body over the limit.
    let seen = admin.call("GET", "/api/session", &[("Cookie", &cookie)], "");
    assert_eq!(seen.status(), 200);
    assert_eq!(json_of(&seen)["csrf"], csrf.as_str());
    let missing = admin.call("GET", "/api/missing", &[], "");
    assert_eq!(missing.status(), 404);
    assert_fixed_fields(&missing);
    let large = exchange(
        port,
        b"POST /api/login HTTP/1.1\r\nHost: admin.example.test\r\nContent-Type: application/json\r\nContent-Length: 70000\r\n\r\n",
    )
    .message();
    assert_eq!(large.status(), 413);
    assert_fixed_fields(&large);
    // A chunked body has no length to go by: 64 KiB are taken (and are not JSON), and one byte more is refused
    // when it is seen, without waiting for the end of the body, which never comes.
    let chunk = [b'a'; 16 * 1024];
    let at_limit = exchange(
        port,
        &chunked_typed(
            "/api/login",
            JSON,
            &chunked_body(&[&chunk[..], &chunk[..], &chunk[..], &chunk[..]], b""),
        ),
    );
    assert_eq!(at_limit.status(), 400);
    let mut unended = chunked_body(&[&chunk[..], &chunk[..], &chunk[..], &chunk[..], b"a"], b"");
    unended.truncate(unended.len() - b"0\r\n\r\n".len());
    let mut sock = connect(port);
    // The process closes the connection while the client is still sending, so the write may fail.
    let _ = sock.write_all(&chunked_typed("/api/login", JSON, &unended));
    let over = collect(&mut sock, Instant::now());
    assert_eq!(over.status(), 413, "{}", over.text());
    assert!(over.took < MARGIN, "{:?}", over.took);
    assert_fixed_fields(&over.message());

    // The change of the password needs the token, closes the old session and gives a new cookie.
    let change = json!({"current": OWNER, "new": NEXT}).to_string();
    let without = admin.call(
        "PUT",
        "/api/account/password",
        &[json_type, ("Cookie", &cookie)],
        &change,
    );
    assert_eq!(without.status(), 403);
    let changed = admin.call(
        "PUT",
        "/api/account/password",
        &[json_type, ("Cookie", &cookie), ("X-CSRF-Token", &csrf)],
        &change,
    );
    assert_eq!(changed.status(), 200);
    let renewed = cookie_of(&changed);
    assert_ne!(renewed, cookie);
    let renewed_csrf = json_of(&changed)["csrf"]
        .as_str()
        .expect("a token")
        .to_owned();
    assert_eq!(
        admin
            .call("GET", "/api/session", &[("Cookie", &cookie)], "")
            .status(),
        401
    );
    assert_eq!(
        admin
            .call("GET", "/api/session", &[("Cookie", &renewed)], "")
            .status(),
        200
    );

    // The logout, and the passwords: the old one is refused and the new one is taken.
    let out = admin.call(
        "POST",
        "/api/logout",
        &[("Cookie", &renewed), ("X-CSRF-Token", &renewed_csrf)],
        "",
    );
    assert_eq!(out.status(), 200);
    assert_eq!(
        admin
            .call("GET", "/api/session", &[("Cookie", &renewed)], "")
            .status(),
        401
    );
    let old = admin.call("POST", "/api/login", &[json_type], &body("alice", OWNER));
    assert_eq!(old.status(), 401);
    let new = admin.call("POST", "/api/login", &[json_type], &body("alice", NEXT));
    assert_eq!(new.status(), 200);

    // The audit log, through the API, in the file and on the standard error.
    let cookie = cookie_of(&new);
    let log = admin.call("GET", "/api/audit", &[("Cookie", &cookie)], "");
    assert_eq!(log.status(), 200);
    let entries = json_of(&log)["entries"]
        .as_array()
        .expect("entries")
        .clone();
    let actions: Vec<(&str, &str)> = entries
        .iter()
        .map(|entry| {
            (
                entry["action"].as_str().unwrap(),
                entry["result"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        actions,
        [
            ("login", "ok"),
            ("login", "denied"),
            ("logout", "ok"),
            ("password", "ok"),
            ("password", "denied"),
            ("login", "ok"),
            ("login", "denied"),
            ("create", "failed"),
            ("create", "ok"),
            ("create", "ok"),
        ]
    );
    assert!(
        entries
            .iter()
            .filter(|entry| entry["action"] != "create")
            .all(|entry| entry["client"] == "127.0.0.1")
    );

    // SIGTERM stops the process with exit code 0.
    let status = admin.stop();
    assert_eq!(status.code(), Some(0), "{:#?}", admin.seen);
    let file = fs::read_to_string(root.join("admin").join("audit").join("audit.log"))
        .expect("the audit file");
    let in_file: Vec<Value> = file
        .lines()
        .map(|line| serde_json::from_str(line).expect("a line of JSON"))
        .collect();
    let on_stderr: Vec<&Value> = admin.seen.iter().filter(|r| r["type"] == "audit").collect();
    // The two tries of `admin bootstrap` come first; the process wrote the other seven.
    assert_eq!(in_file.len(), 10);
    assert_eq!(in_file[0], created);
    assert_eq!(in_file[2]["result"], "failed");
    assert_eq!(on_stderr, in_file[3..].iter().collect::<Vec<_>>());
    assert!(
        admin
            .seen
            .iter()
            .any(|r| r["line"] == "admin: stop: SIGTERM")
    );
    assert!(!admin.seen.iter().any(|r| r["type"] == "dropped"));
    assert_turned_away(port);
}

#[test]
#[ignore = "needs a built inspector"]
fn both_commands_refuse_a_configuration_without_the_admin_object() {
    let idle = Idle::new("admin_absent", &Knobs::quick(), |_| {});
    let config = idle.root().join("config.json");
    let run = command(&[config.as_path()], "");
    assert_eq!(run.code, Some(2), "{}", run.err);
    assert!(run.err.contains("there is no admin object"), "{}", run.err);
    let made = bootstrap(idle.root(), "alice", &format!("{OWNER}\n"));
    assert_eq!(made.code, Some(2), "{}", made.err);
    assert_eq!(made.out, "");
    assert_eq!(
        made.err,
        "admin bootstrap: configuration refused: there is no admin object\n"
    );
}

#[test]
#[ignore = "needs a built inspector"]
fn the_admin_process_does_not_start_when_mfa_is_required() {
    let port = free_port();
    let idle = Idle::new("admin_mfa", &Knobs::quick(), |root| {
        add_admin(root, port, "required");
    });
    let config = idle.root().join("config.json");
    let run = command(&[config.as_path()], "");
    assert_eq!(run.code, Some(1), "{}", run.err);
    assert!(
        run.err
            .contains("admin: start: mfa required is not available yet"),
        "{}",
        run.err
    );
    assert_turned_away(port);
}
