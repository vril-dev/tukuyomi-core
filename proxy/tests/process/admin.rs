//! The admin process in a real process, on the configuration of a test root that has the `admin` object (its store
//! is `admin/` in the root, and the control socket is never bound: no proxy runs). The first user is made with
//! `admin bootstrap` and the password on the standard input; the admin process is started, and a client logs in,
//! reads its session, changes its password, logs out and logs in again, over TCP. Then SIGTERM stops the process
//! with exit code 0. The audit log is read from the file and from the standard error of the process; the first user's
//! creation is in it as well. A second test goes through the accounts: an owner sets up a second factor (the test
//! makes the code from the seed with aws-lc-rs), logs in with it, makes an API token and uses it without a cookie
//! or a CSRF token, makes a user who has to change the password first, and disables that user, whose session is then
//! refused.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use aws_lc_rs::hmac;
use serde_json::{Value, json};

use crate::support::*;

pub(crate) const OWNER: &str = "first password 123";
const NEXT: &str = "second password 456";

/// Adds the `admin` object that listens on `port`, with `mfa` optional, and the directory of its store, to the
/// configuration in `root`.
pub(crate) fn add_admin(root: &Path, port: u16) {
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
            "mfa": "optional",
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
        add_admin(root, port);
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
    assert_eq!(session["mfa"], "off");
    assert_eq!(session["must_change"], false);
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
fn a_second_admin_process_on_the_same_store_does_not_start() {
    let port = free_port();
    let idle = Idle::new("admin_twice", &Knobs::quick(), |root| {
        add_admin(root, port);
    });
    let root = idle.root();
    let mut admin = Admin::start(root, port);
    let config = root.join("config.json");
    let second = command(&[config.as_path()], "");
    assert_eq!(second.code, Some(1), "{}", second.err);
    assert!(
        second
            .err
            .contains("admin: admin store refused: another admin process runs on this store"),
        "{}",
        second.err
    );
    // The first process is not disturbed, and after it ended the store is free for another one.
    assert_eq!(admin.call("GET", "/api/missing", &[], "").status(), 404);
    assert_eq!(admin.stop().code(), Some(0), "{:#?}", admin.seen);
    let mut again = Admin::start(root, port);
    assert_eq!(again.stop().code(), Some(0), "{:#?}", again.seen);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_reset_while_the_process_runs_ends_the_sessions_and_makes_the_user_change_the_password() {
    let port = free_port();
    let idle = Idle::new("admin_reset", &Knobs::quick(), |root| {
        add_admin(root, port);
    });
    let root = idle.root();
    let made = bootstrap(root, "alice", &format!("{OWNER}\n"));
    assert_eq!(made.code, Some(0), "{}", made.err);
    let mut admin = Admin::start(root, port);
    let alice = Login::of(&log_in(&admin, "alice", OWNER));
    let seen = |login: &Login| {
        login
            .call(&admin, "GET", "/api/session", &json!({}))
            .status()
    };
    assert_eq!(seen(&alice), 200);
    let config = root.join("config.json");
    let reset = |name: &str, input: &str| {
        command(
            &[Path::new("reset"), config.as_path(), Path::new(name)],
            input,
        )
    };
    // A user that the store does not have is refused, and nothing is changed.
    let none = reset("nobody", &format!("{NEXT}\n"));
    assert_eq!((none.code, none.out.as_str()), (Some(1), ""));
    assert!(
        none.err
            .ends_with("admin reset: the user is not in the store\n"),
        "{}",
        none.err
    );
    assert_eq!(seen(&alice), 200);
    // The reset is audited first, with the way it was done, and ends the session of the user.
    let done = reset("alice", &format!("{NEXT}\n"));
    assert_eq!(
        (done.code, done.out.as_str()),
        (Some(0), "reset password of alice\n"),
        "{}",
        done.err
    );
    let line: Value =
        serde_json::from_str(done.err.lines().next().unwrap()).expect("an audit line");
    for (key, value) in [
        ("action", "reset"),
        ("result", "ok"),
        ("target", "alice"),
        ("auth", "reset"),
    ] {
        assert_eq!(line[key], value, "{key}");
    }
    assert_eq!(seen(&alice), 401);
    assert_eq!(log_in(&admin, "alice", OWNER).status(), 401);
    let login = log_in(&admin, "alice", NEXT);
    assert_eq!(login.status(), 200);
    assert_eq!(json_of(&login)["must_change"], true);
    assert_eq!(admin.stop().code(), Some(0), "{:#?}", admin.seen);
}

/// The bytes that `text` stands for in base32 (RFC 4648, no padding).
fn unbase32(text: &str) -> Vec<u8> {
    const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let (mut out, mut buffer, mut held) = (Vec::new(), 0u32, 0u32);
    for c in text.chars() {
        buffer = (buffer << 5) | u32::try_from(ALPHABET.find(c).expect("a base32 letter")).unwrap();
        held += 5;
        if held >= 8 {
            held -= 8;
            out.push(u8::try_from((buffer >> held) & 0xff).unwrap());
        }
    }
    out
}

/// The one-time password (RFC 4226 with HMAC-SHA1 and 6 digits) of `seed` for the 30-second step `step`.
fn one_time_code(seed: &[u8], step: u64) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, seed);
    let tag = hmac::sign(&key, &step.to_be_bytes());
    let digest = tag.as_ref();
    let offset = usize::from(digest[19] & 0x0f);
    let number = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);
    format!("{:06}", number % 1_000_000)
}

/// The present 30-second step.
fn step_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is after the epoch")
        .as_secs()
        / 30
}

/// A session of the admin API: its cookie and CSRF token.
struct Login {
    cookie: String,
    csrf: String,
}

impl Login {
    /// The session that an answer to a login, a check of the second factor or a renewal opened.
    fn of(message: &Message) -> Login {
        assert_eq!(
            message.status(),
            200,
            "{}",
            String::from_utf8_lossy(&message.body)
        );
        Login {
            cookie: cookie_of(message),
            csrf: json_of(message)["csrf"]
                .as_str()
                .expect("a token")
                .to_owned(),
        }
    }

    /// A request of this session, with its CSRF token.
    fn call(&self, admin: &Admin, method: &str, path: &str, body: &Value) -> Message {
        let fields = [
            ("Content-Type", "application/json"),
            ("Cookie", self.cookie.as_str()),
            ("X-CSRF-Token", self.csrf.as_str()),
        ];
        admin.call(method, path, &fields, &body.to_string())
    }
}

fn log_in(admin: &Admin, name: &str, password: &str) -> Message {
    let body = json!({"name": name, "password": password}).to_string();
    admin.call(
        "POST",
        "/api/login",
        &[("Content-Type", "application/json")],
        &body,
    )
}

#[test]
#[ignore = "needs a built inspector"]
fn an_owner_sets_up_a_second_factor_makes_a_token_and_a_user_who_must_change_the_password_and_is_then_disabled()
 {
    const VERA: &str = "viewer password 123";
    const VERA_NEXT: &str = "viewer password 456";
    let port = free_port();
    let idle = Idle::new("admin_accounts", &Knobs::quick(), |root| {
        add_admin(root, port);
    });
    let root = idle.root();
    let made = bootstrap(root, "alice", &format!("{OWNER}\n"));
    assert_eq!(made.code, Some(0), "{}", made.err);
    let mut admin = Admin::start(root, port);

    // The owner logs in, and sets up the second factor with the password and a code of the seed.
    let alice = Login::of(&log_in(&admin, "alice", OWNER));
    let started = alice.call(
        &admin,
        "POST",
        "/api/account/mfa/setup",
        &json!({"password": OWNER}),
    );
    assert_eq!(started.status(), 200);
    let started = json_of(&started);
    assert!(
        started["uri"]
            .as_str()
            .expect("an address")
            .starts_with("otpauth://totp/tukuyomi-core:alice?secret=")
    );
    let seed = unbase32(started["secret"].as_str().expect("a seed"));
    assert_eq!(seed.len(), 20);
    // The step is read once: it may change during the test, and the same code must be sent twice.
    let step = step_now();
    let confirmed = alice.call(
        &admin,
        "POST",
        "/api/account/mfa/confirm",
        &json!({"code": one_time_code(&seed, step)}),
    );
    assert_eq!(confirmed.status(), 200);
    assert_eq!(
        json_of(&confirmed)["recovery"].as_array().map(Vec::len),
        Some(10)
    );
    let alice = Login::of(&confirmed);
    assert_eq!(
        alice
            .call(&admin, "POST", "/api/logout", &json!({}))
            .status(),
        200
    );

    // The next login asks for the code; until it is given the session can do nothing else. A code of the step that
    // confirmed is refused, the next step's is taken.
    let pending = log_in(&admin, "alice", OWNER);
    assert_eq!(json_of(&pending)["mfa"], "verify");
    let pending = Login::of(&pending);
    let blocked = admin.call("GET", "/api/session", &[("Cookie", &pending.cookie)], "");
    assert_eq!(blocked.status(), 403);
    assert_eq!(json_of(&blocked)["error"], "second factor required");
    let replay = pending.call(
        &admin,
        "POST",
        "/api/login/mfa",
        &json!({"code": one_time_code(&seed, step)}),
    );
    assert_eq!(replay.status(), 401);
    let verified = pending.call(
        &admin,
        "POST",
        "/api/login/mfa",
        &json!({"code": one_time_code(&seed, step + 1)}),
    );
    assert_eq!(json_of(&verified)["mfa"], "off");
    let alice = Login::of(&verified);
    assert_ne!(alice.cookie, pending.cookie);

    // A token of the role operator is used without a cookie or a CSRF token; the routes of the account are not for it.
    let made = alice.call(
        &admin,
        "POST",
        "/api/account/tokens",
        &json!({"name": "ci", "role": "operator", "days": 30, "password": OWNER}),
    );
    assert_eq!(made.status(), 200);
    let token = json_of(&made)["token"]
        .as_str()
        .expect("a token")
        .to_owned();
    let bearer = format!("Bearer {token}");
    let by_token = admin.call("GET", "/api/generations", &[("Authorization", &bearer)], "");
    assert_eq!(
        by_token.status(),
        200,
        "{}",
        String::from_utf8_lossy(&by_token.body)
    );
    assert_eq!(
        json_of(&by_token)["generations"].as_array().map(Vec::len),
        Some(1)
    );
    let account = admin.call(
        "GET",
        "/api/account/tokens",
        &[("Authorization", &bearer)],
        "",
    );
    assert_eq!(account.status(), 403);
    let both = admin.call(
        "GET",
        "/api/generations",
        &[("Authorization", &bearer), ("Cookie", &alice.cookie)],
        "",
    );
    assert_eq!(both.status(), 400);

    // A viewer has to change the password first: until then only the change works.
    let created = alice.call(
        &admin,
        "POST",
        "/api/users",
        &json!({"name": "vera", "role": "viewer", "password": VERA}),
    );
    assert_eq!(
        created.status(),
        200,
        "{}",
        String::from_utf8_lossy(&created.body)
    );
    let login = log_in(&admin, "vera", VERA);
    assert_eq!(json_of(&login)["must_change"], true);
    let vera = Login::of(&login);
    let limited = admin.call("GET", "/api/generations", &[("Cookie", &vera.cookie)], "");
    assert_eq!(limited.status(), 403);
    assert_eq!(json_of(&limited)["error"], "password change required");
    let changed = vera.call(
        &admin,
        "PUT",
        "/api/account/password",
        &json!({"current": VERA, "new": VERA_NEXT}),
    );
    let vera = Login::of(&changed);
    let allowed = admin.call("GET", "/api/generations", &[("Cookie", &vera.cookie)], "");
    assert_eq!(allowed.status(), 200);

    // The owner disables the viewer, and the session of the viewer is refused.
    let disabled = alice.call(&admin, "PUT", "/api/users/vera", &json!({"disabled": true}));
    assert_eq!(disabled.status(), 200);
    let after = admin.call("GET", "/api/generations", &[("Cookie", &vera.cookie)], "");
    assert_eq!(after.status(), 401);
    assert_eq!(log_in(&admin, "vera", VERA_NEXT).status(), 401);

    let status = admin.stop();
    assert_eq!(status.code(), Some(0), "{:#?}", admin.seen);
    let text = fs::read_to_string(root.join("admin").join("audit").join("audit.log"))
        .expect("the audit file");
    // No password, code, token or cookie is in the audit log or in the records of the process.
    let records = format!("{:?}", admin.seen);
    for secret in [OWNER, VERA, VERA_NEXT, token.as_str(), &token[21..]] {
        assert!(!text.contains(secret) && !records.contains(secret));
    }
    assert!(text.contains("\"action\":\"mfa_confirm\""));
    assert!(text.contains("\"action\":\"user_create\""));
}
