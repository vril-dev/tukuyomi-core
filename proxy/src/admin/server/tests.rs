use std::fs;
use std::path::Path;
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Context;

use http_body::{Body, Frame};

use super::*;
use crate::admin::audit::Append;
use crate::admin::file_store::FileAdminStore;
use crate::admin::file_store::tests::{TestDir, scratch};
use crate::admin::password::{Hash, hex};
use crate::admin::users::User;
use crate::config::Mfa;
use crate::log::{self, Lines, sink::RecordFile};
use crate::rules::bundle::sha256;

/// The iterations of the hashes of the tests.
pub(crate) const ITER: u32 = 1000;
pub(crate) const PASSWORD: &str = "correct horse battery";
pub(crate) const ORIGIN_OK: &str = "https://admin.example.test";
pub(crate) const JSON_TYPE: (&str, &str) = ("content-type", "application/json");

/// An audit sink that writes the file and keeps the lines in memory, and takes none while `fail` is set.
struct Memory {
    fail: Arc<AtomicBool>,
    written: Arc<Mutex<Vec<u8>>>,
    file: RecordFile,
}

impl Append for Memory {
    fn append(&mut self, line: &[u8]) -> bool {
        if self.fail.load(Ordering::SeqCst) || !self.file.append(line) {
            return false;
        }
        self.written.lock().unwrap().extend_from_slice(line);
        true
    }
}

pub(crate) struct Rig {
    pub(crate) app: App,
    pub(crate) fail: Arc<AtomicBool>,
    pub(crate) written: Arc<Mutex<Vec<u8>>>,
    /// What the logger got.
    pub(crate) lines: Lines,
    pub(crate) dir: TestDir,
}

/// A session: the value of its cookie and its CSRF token.
pub(crate) struct Session {
    pub(crate) id: String,
    pub(crate) csrf: String,
}

pub(crate) fn put_user(dir: &Path, name: &str, role: Role, password: &str, disabled: bool) {
    let mut user = User::new(name, role, Hash::new(password, ITER).unwrap(), 1000);
    user.disabled = disabled;
    fs::write(
        dir.join("users").join(format!("{name}.json")),
        user.encode().unwrap(),
    )
    .unwrap();
}

/// Rewrites the file of the user `name` with `change` applied, as another process would.
pub(crate) fn alter_user(rig: &Rig, name: &str, change: impl FnOnce(&mut User)) {
    let mut user = rig.user(name);
    change(&mut user);
    fs::write(
        rig.dir.path().join("users").join(format!("{name}.json")),
        user.encode().unwrap(),
    )
    .unwrap();
}

/// An app over a store with the owner `alice`, the operator `ola`, the viewer `vera` and the disabled viewer `dave`.
pub(crate) fn rig_trusting(trusted: &[&str]) -> Rig {
    rig_with(trusted, Mfa::Optional)
}

/// As `rig_trusting`, with this `admin.mfa`.
pub(crate) fn rig_with(trusted: &[&str], mfa: Mfa) -> Rig {
    let dir = scratch();
    let store = Arc::new(FileAdminStore::open(dir.path()).unwrap());
    put_user(dir.path(), "alice", Role::Owner, PASSWORD, false);
    put_user(dir.path(), "ola", Role::Operator, PASSWORD, false);
    put_user(dir.path(), "vera", Role::Viewer, PASSWORD, false);
    put_user(dir.path(), "dave", Role::Viewer, PASSWORD, true);
    let (log, lines) = log::recording();
    let fail = Arc::new(AtomicBool::new(false));
    let written = Arc::new(Mutex::new(Vec::new()));
    let audit_dir = dir.path().join("audit");
    let sink = Memory {
        fail: fail.clone(),
        written: written.clone(),
        file: RecordFile::open_in("audit", &audit_dir, 1 << 20, 2).unwrap(),
    };
    let audit = Arc::new(AuditLog::with_sink(Box::new(sink), &audit_dir, log));
    let config = AdminConfig {
        listen: SocketAddr::from(([127, 0, 0, 1], 9)),
        control: "/run/test/control.sock".into(),
        store: AdminStoreConfig::File {
            dir: dir.path().to_path_buf(),
        },
        origin: ORIGIN_OK.to_owned(),
        trusted_proxies: trusted
            .iter()
            .map(|net| Cidr::parse(net).unwrap())
            .collect(),
        mfa,
        session_idle: Duration::from_secs(1800),
        session_total: Duration::from_secs(43_200),
        crs_dir: None,
    };
    let app = App::new(
        &config,
        store,
        audit,
        RequestIds::new().unwrap(),
        ITER,
        None,
    )
    .unwrap();
    Rig {
        app,
        fail,
        written,
        lines,
        dir,
    }
}

pub(crate) fn rig() -> Rig {
    rig_trusting(&[])
}

pub(crate) fn request(method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> Req {
    let mut fields = HeaderMap::new();
    for (name, value) in headers {
        fields.append(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    Req {
        method: Method::from_bytes(method.as_bytes()).unwrap(),
        path: path.to_owned(),
        query: String::new(),
        headers: fields,
        peer: SocketAddr::from(([127, 0, 0, 1], 50_000)),
        body: Bytes::copy_from_slice(body.as_bytes()),
    }
}

impl Rig {
    pub(crate) fn send(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> Answer {
        self.app.handle(&request(method, path, headers, body))
    }

    pub(crate) fn try_login(&self, name: &str, password: &str) -> Answer {
        let body = json!({ "name": name, "password": password }).to_string();
        self.send("POST", "/api/login", &[JSON_TYPE], &body)
    }

    pub(crate) fn login(&self, name: &str) -> Session {
        let answer = self.try_login(name, PASSWORD);
        assert_eq!(answer.status, StatusCode::OK, "{:?}", answer.body);
        session_of(&answer)
    }

    /// A request with the cookie and the CSRF token of `session`, and `extra` fields.
    pub(crate) fn with(
        &self,
        session: &Session,
        method: &str,
        path: &str,
        extra: &[(&str, &str)],
        body: &str,
    ) -> Answer {
        let cookie = format!("{COOKIE_NAME}={}", session.id);
        let mut headers = vec![
            JSON_TYPE,
            ("cookie", cookie.as_str()),
            ("x-csrf-token", session.csrf.as_str()),
        ];
        headers.extend_from_slice(extra);
        self.send(method, path, &headers, body)
    }

    /// The lines of the audit log so far.
    pub(crate) fn audit(&self) -> Vec<Value> {
        let bytes = self.written.lock().unwrap().clone();
        String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    pub(crate) fn user(&self, name: &str) -> User {
        let store = FileAdminStore::open(self.dir.path()).unwrap();
        store.user(name).unwrap().unwrap()
    }
}

/// The session that a login answer opened.
pub(crate) fn session_of(answer: &Answer) -> Session {
    let cookie = answer.cookie.as_deref().expect("a cookie");
    let id = cookie
        .strip_prefix(&format!("{COOKIE_NAME}="))
        .and_then(|rest| rest.split(';').next())
        .expect("the cookie names the session");
    Session {
        id: id.to_owned(),
        csrf: answer.body["csrf"].as_str().expect("a token").to_owned(),
    }
}

#[test]
fn a_change_without_the_csrf_token_or_from_another_origin_is_refused_and_the_session_stays() {
    let rig = rig();
    let vera = rig.login("vera");
    let cookie = format!("{COOKIE_NAME}={}", vera.id);
    let logout = |token: Option<&str>, origin: Option<&str>| {
        let mut headers = vec![("cookie", cookie.as_str())];
        headers.extend(token.map(|token| ("x-csrf-token", token)));
        headers.extend(origin.map(|origin| ("origin", origin)));
        rig.send("POST", "/api/logout", &headers, "")
    };
    assert_eq!(logout(None, None).status, StatusCode::FORBIDDEN);
    assert_eq!(logout(Some("wrong"), None).status, StatusCode::FORBIDDEN);
    assert_eq!(
        logout(Some(&vera.csrf), Some("https://evil.example.test")).status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        logout(Some(&vera.csrf), Some("null")).status,
        StatusCode::FORBIDDEN
    );
    // None of them ended the session; each was written, with the user whose session it was.
    assert_eq!(
        rig.with(&vera, "GET", "/api/session", &[], "").status,
        StatusCode::OK
    );
    let refusals: Vec<(String, String)> = rig
        .audit()
        .iter()
        .filter(|line| line["result"] == "denied")
        .map(|line| {
            (
                line["actor"].as_str().unwrap().to_owned(),
                line["reason"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    let want = [
        ("vera", "csrf"),
        ("vera", "csrf"),
        ("vera", "origin"),
        ("vera", "origin"),
    ];
    assert_eq!(
        refusals,
        want.map(|(actor, reason)| (actor.to_owned(), reason.to_owned()))
    );
    // The token and the right origin together end it.
    assert_eq!(
        logout(Some(&vera.csrf), Some(ORIGIN_OK)).status,
        StatusCode::OK
    );
    assert_eq!(
        rig.with(&vera, "GET", "/api/session", &[], "").status,
        StatusCode::UNAUTHORIZED
    );
    // A login from another origin is refused as well, and opens no session.
    let body = json!({ "name": "vera", "password": PASSWORD }).to_string();
    let foreign = rig.send(
        "POST",
        "/api/login",
        &[JSON_TYPE, ("origin", "https://evil.example.test")],
        &body,
    );
    assert_eq!(foreign.status, StatusCode::FORBIDDEN);
    assert!(foreign.cookie.is_none());
}

#[test]
fn a_viewer_is_refused_a_route_of_an_operator_and_the_refusal_is_written() {
    let rig = rig();
    let vera = rig.login("vera");
    let refused = rig.with(&vera, "GET", "/api/audit", &[], "");
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    let last = rig.audit().pop().unwrap();
    assert_eq!(
        (
            last["action"].as_str(),
            last["reason"].as_str(),
            last["actor"].as_str()
        ),
        (Some("audit"), Some("role"), Some("vera"))
    );
    for name in ["ola", "alice"] {
        let session = rig.login(name);
        let answer = rig.with(&session, "GET", "/api/audit", &[], "");
        assert_eq!(answer.status, StatusCode::OK, "{name}");
        // The newest line first: the refusal of the viewer is the newest but one of these.
        let entries = answer.body["entries"].as_array().unwrap();
        assert_eq!(entries[0]["action"], "login");
        assert!(entries.iter().any(|entry| entry["reason"] == "role"));
    }
    // A route that needs a session is 401 without one, and nothing is written for it.
    let before = rig.audit().len();
    let none = rig.send("GET", "/api/audit", &[], "");
    assert_eq!(none.status, StatusCode::UNAUTHORIZED);
    assert_eq!(rig.audit().len(), before);
}

#[test]
fn a_path_that_is_not_in_the_table_is_404_and_another_method_is_405_with_the_methods_it_has() {
    let rig = rig();
    for path in [
        "/api",
        "/api/nothing",
        "/api/login/",
        "/api/%6cogin",
        "/API/login",
    ] {
        let answer = rig.send("GET", path, &[], "");
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{path}");
        assert!(answer.allow.is_none());
    }
    for (method, path, allow) in [
        ("GET", "/api/login", "POST"),
        ("DELETE", "/api/login", "POST"),
        ("PUT", "/api/session", "GET, HEAD"),
        ("POST", "/api/audit", "GET, HEAD"),
        ("GET", "/api/account/password", "PUT"),
    ] {
        let answer = rig.send(method, path, &[], "");
        assert_eq!(
            answer.status,
            StatusCode::METHOD_NOT_ALLOWED,
            "{method} {path}"
        );
        assert_eq!(answer.allow.as_deref(), Some(allow));
    }
    // HEAD is taken as GET.
    let vera = rig.login("vera");
    assert_eq!(
        rig.with(&vera, "HEAD", "/api/session", &[], "").status,
        StatusCode::OK
    );
}

#[test]
fn the_fifth_failure_locks_the_user_and_the_sixth_try_with_the_right_password_is_refused() {
    let rig = rig();
    let refused = rig.try_login("vera", "wrong password 1");
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
    for n in 2..=5 {
        let answer = rig.try_login("vera", &format!("wrong password {n}"));
        assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "failure {n}");
        assert_eq!(answer.body, refused.body);
    }
    let sixth = rig.try_login("vera", PASSWORD);
    assert_eq!(
        (sixth.status, &sixth.body),
        (StatusCode::UNAUTHORIZED, &refused.body)
    );
    assert!(sixth.cookie.is_none());
    // Another user is not locked by it.
    assert_eq!(rig.try_login("ola", PASSWORD).status, StatusCode::OK);
    let audit = rig.audit();
    let reasons: Vec<&str> = audit
        .iter()
        .filter(|line| line["action"] == "login" && line["target"] == "vera")
        .map(|line| line["reason"].as_str().unwrap())
        .collect();
    assert_eq!(
        reasons,
        [
            "wrong password",
            "wrong password",
            "wrong password",
            "wrong password",
            "wrong password",
            "locked"
        ]
    );
    assert_eq!(
        audit.iter().filter(|line| line["action"] == "lock").count(),
        1
    );
}

#[test]
fn a_reset_of_a_locked_user_by_another_process_ends_the_lock_and_the_new_password_logs_in() {
    let rig = rig();
    for n in 1..=5 {
        let answer = rig.try_login("vera", &format!("wrong password {n}"));
        assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "failure {n}");
    }
    assert_eq!(
        rig.try_login("vera", PASSWORD).status,
        StatusCode::UNAUTHORIZED
    );
    // `admin reset` runs in another process: it writes a new password and a later `changed`.
    alter_user(&rig, "vera", |user| {
        user.password = Hash::new("another password", ITER).unwrap();
        user.must_change = true;
        user.changed += 1;
        user.tokens_after = user.changed;
    });
    // The count starts again: four wrong tries do not lock, and the new password logs in.
    for n in 1..=4 {
        let answer = rig.try_login("vera", &format!("wrong password {n}"));
        assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "failure {n}");
    }
    let answer = rig.try_login("vera", "another password");
    assert_eq!(answer.status, StatusCode::OK, "{:?}", answer.body);
    assert_eq!(answer.body["must_change"], true);
}

#[test]
fn a_client_that_tries_too_often_is_turned_away_before_any_user_is_counted() {
    let rig = rig();
    for _ in 0..30 {
        assert_eq!(
            rig.try_login("nobody", "whatever it is").status,
            StatusCode::UNAUTHORIZED
        );
    }
    let answer = rig.try_login("vera", PASSWORD);
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(answer.cookie.is_none());
    // Nothing was written for the turned-away try, and nothing counted against the user.
    assert_eq!(rig.audit().len(), 30);
}

#[test]
fn an_unknown_name_a_wrong_password_and_a_disabled_user_get_the_same_answer() {
    let rig = rig();
    let unknown = rig.try_login("nobody", PASSWORD);
    let wrong = rig.try_login("vera", "wrong password 1");
    let disabled = rig.try_login("dave", PASSWORD);
    let malformed = rig.try_login("No Body/../", PASSWORD);
    let long = rig.try_login("vera", &"p".repeat(5000));
    for answer in [&unknown, &wrong, &disabled, &malformed, &long] {
        assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
        assert_eq!(answer.body, json!({ "error": "invalid credentials" }));
        assert!(answer.cookie.is_none() && answer.allow.is_none());
    }
    // The audit log has the reasons, and the name only when it is the name of a user.
    let audit = rig.audit();
    let seen: Vec<(Option<&str>, &str)> = audit
        .iter()
        .map(|line| (line["target"].as_str(), line["reason"].as_str().unwrap()))
        .collect();
    assert_eq!(
        seen,
        [
            (None, "unknown user"),
            (Some("vera"), "wrong password"),
            (Some("dave"), "disabled"),
            (None, "unknown user"),
            (Some("vera"), "wrong password"),
        ]
    );
}

#[test]
fn a_header_that_names_another_actor_does_not_change_the_actor_of_the_audit_log() {
    let rig = rig();
    let vera = rig.login("vera");
    let fields = [
        ("x-tukuyomi-actor", "alice"),
        ("x-forwarded-user", "alice"),
        ("x-actor", "alice"),
        ("x-remote-user", "alice"),
    ];
    let refused = rig.with(&vera, "GET", "/api/audit", &fields, "");
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    let changed = rig.with(
        &vera,
        "PUT",
        "/api/account/password",
        &fields,
        &json!({ "current": "wrong password 1", "new": "a new password!" }).to_string(),
    );
    assert_eq!(changed.status, StatusCode::FORBIDDEN);
    let audit = rig.audit();
    for line in &audit[audit.len() - 2..] {
        assert_eq!(line["actor"], "vera");
    }
    // Without a session the fields name nobody: the request is 401 and writes nothing.
    let before = rig.audit().len();
    let anonymous = rig.send("GET", "/api/audit", &fields, "");
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
    assert_eq!(rig.audit().len(), before);
}

#[test]
fn a_change_is_refused_and_nothing_changes_while_the_audit_log_cannot_be_written() {
    let rig = rig();
    let vera = rig.login("vera");
    rig.fail.store(true, Ordering::SeqCst);
    // No session is made.
    let login = rig.try_login("ola", PASSWORD);
    assert_eq!(login.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(login.cookie.is_none());
    // The password is not changed.
    let body = json!({ "current": PASSWORD, "new": "a new password!" }).to_string();
    let change = rig.with(&vera, "PUT", "/api/account/password", &[], &body);
    assert_eq!(change.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(change.cookie.is_none());
    // The session is not ended.
    rig.fail.store(false, Ordering::SeqCst);
    assert_eq!(
        rig.with(&vera, "GET", "/api/session", &[], "").status,
        StatusCode::OK
    );
    assert!(rig.user("vera").password.verify(PASSWORD));
    assert!(!rig.user("vera").password.verify("a new password!"));
    assert_eq!(rig.try_login("vera", PASSWORD).status, StatusCode::OK);
}

#[test]
fn a_password_change_closes_the_other_sessions_and_gives_this_one_a_new_id() {
    let rig = rig();
    let first = rig.login("vera");
    let second = rig.login("vera");
    let other = rig.login("ola");
    let body = |current: &str, new: &str| json!({ "current": current, "new": new }).to_string();
    // A wrong current password, a new one that is too short and a request that is not JSON change nothing.
    let path = "/api/account/password";
    assert_eq!(
        rig.with(
            &first,
            "PUT",
            path,
            &[],
            &body("wrong password 1", "a new password!")
        )
        .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        rig.with(&first, "PUT", path, &[], &body(PASSWORD, "short"))
            .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        rig.with(&first, "PUT", path, &[], "[1]").status,
        StatusCode::BAD_REQUEST
    );
    let before = rig.user("vera");
    assert!(before.password.verify(PASSWORD));
    // The change.
    let done = rig.with(&first, "PUT", path, &[], &body(PASSWORD, "a new password!"));
    assert_eq!(done.status, StatusCode::OK, "{:?}", done.body);
    let renewed = session_of(&done);
    assert_ne!(renewed.id, first.id);
    assert_ne!(renewed.csrf, first.csrf);
    assert_eq!(done.body["csrf"], renewed.csrf);
    for gone in [&first, &second] {
        assert_eq!(
            rig.with(gone, "GET", "/api/session", &[], "").status,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        rig.with(&renewed, "GET", "/api/session", &[], "").body["name"],
        "vera"
    );
    // The session of another user is not touched.
    assert_eq!(
        rig.with(&other, "GET", "/api/session", &[], "").status,
        StatusCode::OK
    );
    assert!(rig.user("vera").changed > before.changed);
    assert_eq!(
        rig.try_login("vera", PASSWORD).status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        rig.try_login("vera", "a new password!").status,
        StatusCode::OK
    );
    let ok = rig
        .audit()
        .into_iter()
        .find(|line| line["action"] == "password" && line["result"] == "ok")
        .unwrap();
    assert_eq!(
        (ok["actor"].as_str(), ok["target"].as_str()),
        (Some("vera"), Some("vera"))
    );
}

#[test]
fn the_cookie_has_its_attributes_and_the_answer_to_a_login_and_to_a_session_say_who_it_is() {
    let rig = rig();
    let answer = rig.try_login("ola", PASSWORD);
    let cookie = answer.cookie.as_deref().unwrap();
    let id = cookie
        .strip_prefix("tukuyomi_admin=")
        .and_then(|rest| rest.strip_suffix("; Secure; HttpOnly; SameSite=Strict; Path=/"))
        .unwrap_or_else(|| panic!("the cookie is {cookie:?}"));
    assert_eq!(id.len(), 43);
    assert!(
        id.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    );
    assert_eq!(answer.body["name"], "ola");
    assert_eq!(answer.body["role"], "operator");
    assert_eq!(answer.body["mfa"], "off");
    assert_eq!(answer.body["must_change"], false);
    assert_eq!(answer.body["csrf"].as_str().unwrap().len(), 43);
    let ola = session_of(&answer);
    let seen = rig.with(&ola, "GET", "/api/session", &[], "");
    assert_eq!(seen.body["csrf"], ola.csrf.as_str());
    assert_eq!(seen.body["role"], "operator");
    assert_eq!(seen.body["idle_expires_in_ms"], 1_800_000);
    assert_eq!(seen.body["state"], "active");
    // The cookie must be there once, and the logout takes it away.
    let twice = format!("{COOKIE_NAME}={id}; {COOKIE_NAME}={id}");
    assert_eq!(
        rig.send("GET", "/api/session", &[("cookie", &twice)], "")
            .status,
        StatusCode::UNAUTHORIZED
    );
    let out = rig.with(&ola, "POST", "/api/logout", &[], "");
    assert_eq!(out.status, StatusCode::OK);
    assert!(
        out.cookie
            .as_deref()
            .unwrap()
            .ends_with("Path=/; Max-Age=0")
    );
}

#[test]
fn a_body_must_be_json_with_the_keys_of_the_route_and_nothing_else() {
    let rig = rig();
    let body = json!({ "name": "vera", "password": PASSWORD }).to_string();
    let plain = rig.send(
        "POST",
        "/api/login",
        &[("content-type", "text/plain")],
        &body,
    );
    assert_eq!(plain.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let none = rig.send("POST", "/api/login", &[], &body);
    assert_eq!(none.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let typed = rig.send(
        "POST",
        "/api/login",
        &[("content-type", "Application/JSON; charset=utf-8")],
        &body,
    );
    assert_eq!(typed.status, StatusCode::OK);
    for bad in [
        "",
        "{}",
        r#"{"name":"vera"}"#,
        r#"{"name":"vera","password":"x","more":1}"#,
        r#"{"name":"vera","password":"x","password":"y"}"#,
        r#"{"name":1,"password":"x"}"#,
    ] {
        let answer = rig.send("POST", "/api/login", &[JSON_TYPE], bad);
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{bad}");
    }
}

#[test]
fn the_number_of_a_request_comes_from_a_trusted_peer_in_the_form_of_the_proxy_only() {
    let trusting = rig_trusting(&["127.0.0.0/8"]);
    let given = "0123456789abcdef-2a";
    let from = |rig: &Rig, id: &str| {
        rig.send("GET", "/api/nothing", &[("x-request-id", id)], "")
            .request
    };
    assert_eq!(from(&trusting, given), given);
    for bad in [
        "0123456789abcdef",
        "0123456789abcdef-",
        "0123456789ABCDEF-1",
        "0123456789abcdef-12345678901234567",
        "short-1",
        "0123456789abcdef-1 ",
    ] {
        let id = from(&trusting, bad);
        assert_ne!(id, bad, "{bad:?}");
        assert!(proxy_form(&id), "{id}");
    }
    // Two values of the field are not believed either.
    let two = trusting
        .send(
            "GET",
            "/api/nothing",
            &[("x-request-id", given), ("x-request-id", given)],
            "",
        )
        .request;
    assert_ne!(two, given);
    // A peer that is not trusted is not believed.
    let alone = rig();
    let id = from(&alone, given);
    assert_ne!(id, given);
    assert!(proxy_form(&id));
}

#[test]
fn every_answer_has_the_same_fields_and_the_body_is_json() {
    let mut answer = Answer::error(StatusCode::NOT_FOUND, "not found");
    answer.request = "0123456789abcdef-1".to_owned();
    answer.allow = Some("GET, HEAD".to_owned());
    answer.cookie = Some(cleared_cookie());
    let response = response(&answer);
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let fields = response.headers();
    for (name, value) in [
        ("content-type", "application/json"),
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
        (
            "content-security-policy",
            "default-src 'none'; frame-ancestors 'none'",
        ),
        ("referrer-policy", "no-referrer"),
        ("x-request-id", "0123456789abcdef-1"),
        ("allow", "GET, HEAD"),
    ] {
        assert_eq!(fields.get_all(name).iter().count(), 1, "{name}");
        assert_eq!(fields[name], value, "{name}");
    }
    assert_eq!(fields.get_all("set-cookie").iter().count(), 1);
}

#[test]
fn a_name_that_is_no_user_is_not_written_so_a_password_typed_in_its_place_stays_out_of_the_log() {
    let rig = rig();
    // It has the form of a name, as a lower-case password often has.
    let typed = "correct.horse-battery";
    let answer = rig.try_login(typed, PASSWORD);
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
    let audit = rig.audit();
    assert_eq!(audit.len(), 1);
    assert!(audit[0].get("target").is_none() && audit[0].get("actor").is_none());
    assert_eq!(audit[0]["reason"], "unknown user");
    // Neither the file nor the logger has it.
    let seen = format!("{audit:?} {:?}", rig.lines.take());
    assert!(!seen.contains(typed), "{seen}");
}

#[test]
fn a_session_ends_when_its_user_is_disabled_or_changed_by_another_process() {
    let rig = rig();
    let vera = rig.login("vera");
    let ola = rig.login("ola");
    let alice = rig.login("alice");
    let alive = |session: &Session| rig.with(session, "GET", "/api/session", &[], "").status;
    assert_eq!(alive(&vera), StatusCode::OK);
    // Disabled in the store: the next request is refused, and enabling the user again does not bring the session back.
    alter_user(&rig, "vera", |user| user.disabled = true);
    assert_eq!(alive(&vera), StatusCode::UNAUTHORIZED);
    alter_user(&rig, "vera", |user| user.disabled = false);
    assert_eq!(alive(&vera), StatusCode::UNAUTHORIZED);
    // A user that was changed since the login (a password or a role changed elsewhere) has the new `changed`.
    alter_user(&rig, "ola", |user| user.changed += 1);
    assert_eq!(alive(&ola), StatusCode::UNAUTHORIZED);
    // The session of a user that was not touched stays, and the users can log in again.
    assert_eq!(alive(&alice), StatusCode::OK);
    assert_eq!(rig.try_login("vera", PASSWORD).status, StatusCode::OK);
}

#[test]
fn the_csrf_token_of_another_session_is_refused() {
    let rig = rig();
    let first = rig.login("vera");
    let second = rig.login("vera");
    let other = rig.login("ola");
    for token in [&second.csrf, &other.csrf] {
        let mixed = Session {
            id: first.id.clone(),
            csrf: token.clone(),
        };
        let refused = rig.with(&mixed, "POST", "/api/logout", &[], "");
        assert_eq!(refused.status, StatusCode::FORBIDDEN);
    }
    // The session was not ended, and each refusal was written with the user whose cookie it was.
    assert_eq!(
        rig.with(&first, "GET", "/api/session", &[], "").status,
        StatusCode::OK
    );
    let refusals: Vec<Value> = rig
        .audit()
        .into_iter()
        .filter(|line| line["result"] == "denied")
        .collect();
    assert_eq!(refusals.len(), 2);
    for line in &refusals {
        assert_eq!(
            (line["actor"].as_str(), line["reason"].as_str()),
            (Some("vera"), Some("csrf"))
        );
    }
}

#[test]
fn the_seventeenth_session_of_a_user_closes_the_oldest_and_leaves_the_others() {
    let rig = rig();
    let ola = rig.login("ola");
    let sessions: Vec<Session> = (0..16).map(|_| rig.login("vera")).collect();
    let alive = |session: &Session| rig.with(session, "GET", "/api/session", &[], "").status;
    // Sixteen sessions are all alive, and using the first one does not make it newer.
    for session in &sessions {
        assert_eq!(alive(session), StatusCode::OK);
    }
    assert!(
        !rig.audit()
            .iter()
            .any(|line| line["reason"] == "too many sessions")
    );
    let newest = rig.login("vera");
    assert_eq!(alive(&sessions[0]), StatusCode::UNAUTHORIZED);
    for session in sessions[1..].iter().chain([&newest, &ola]) {
        assert_eq!(alive(session), StatusCode::OK);
    }
    // The session that was closed is in the audit log, as an end of a session of vera.
    let handle = hex(&sha256(sessions[0].id.as_bytes())[..4]);
    let ended = rig.audit().pop().unwrap();
    assert_eq!(
        (
            ended["action"].as_str(),
            ended["result"].as_str(),
            ended["reason"].as_str(),
            ended["actor"].as_str(),
            ended["target"].as_str(),
            ended["session"].as_str(),
        ),
        (
            Some("logout"),
            Some("ok"),
            Some("too many sessions"),
            Some("vera"),
            Some("vera"),
            Some(handle.as_str())
        )
    );
}

#[test]
fn a_logout_closes_the_session_also_when_the_audit_log_cannot_be_written() {
    let rig = rig();
    let vera = rig.login("vera");
    rig.fail.store(true, Ordering::SeqCst);
    let out = rig.with(&vera, "POST", "/api/logout", &[], "");
    assert_eq!(out.status, StatusCode::OK);
    assert!(
        out.cookie
            .as_deref()
            .unwrap()
            .ends_with("Path=/; Max-Age=0")
    );
    // The audit log told the logger that it could not write the line.
    assert!(
        rig.lines
            .texts()
            .contains(&"admin: the audit log cannot be written".to_owned())
    );
    rig.fail.store(false, Ordering::SeqCst);
    assert_eq!(
        rig.with(&vera, "GET", "/api/session", &[], "").status,
        StatusCode::UNAUTHORIZED
    );
}

#[test]
fn the_routes_of_the_rules_are_in_the_table_with_the_roles_it_gives_them() {
    let rig = rig();
    let one = format!("/api/generations/{}", "0123456789abcdef".repeat(4));
    let changes = [
        ("POST", "/api/generations", "import"),
        ("POST", "/api/activate", "activate"),
        ("POST", "/api/rollback", "rollback"),
        ("DELETE", one.as_str(), "remove"),
    ];
    let reads = [
        ("GET", "/api/status"),
        ("GET", "/api/generations"),
        ("GET", one.as_str()),
        ("GET", "/api/history"),
        ("GET", "/api/records"),
    ];
    let (vera, ola) = (rig.login("vera"), rig.login("ola"));
    let ola_cookie = format!("{COOKIE_NAME}={}", ola.id);
    for (method, path, action) in changes {
        let name = format!("{method} {path}");
        let none = rig.send(method, path, &[JSON_TYPE], "{}");
        assert_eq!(none.status, StatusCode::UNAUTHORIZED, "{name}");
        // A viewer is refused, and the refusal is written.
        let viewer = rig.with(&vera, method, path, &[], "{}");
        assert_eq!(viewer.status, StatusCode::FORBIDDEN, "{name}");
        let last = rig.audit().pop().unwrap();
        assert_eq!(
            (
                last["action"].as_str(),
                last["reason"].as_str(),
                last["actor"].as_str()
            ),
            (Some(action), Some("role"), Some("vera")),
            "{name}"
        );
        // An operator without the CSRF token is refused as well.
        let headers = [JSON_TYPE, ("cookie", ola_cookie.as_str())];
        let no_token = rig.send(method, path, &headers, "{}");
        assert_eq!(no_token.status, StatusCode::FORBIDDEN, "{name}");
        // An operator passes every check of the server; the rig has no routes of the rules, so the route is 404.
        let operator = rig.with(&ola, method, path, &[], "{}");
        assert_eq!(operator.status, StatusCode::NOT_FOUND, "{name}");
    }
    for (method, path) in reads {
        let name = format!("{method} {path}");
        let none = rig.send(method, path, &[], "");
        assert_eq!(none.status, StatusCode::UNAUTHORIZED, "{name}");
        let viewer = rig.with(&vera, method, path, &[], "");
        assert_eq!(viewer.status, StatusCode::NOT_FOUND, "{name}");
    }
    // A path below `/api/generations/` is the star of the table, and the table says which methods it has.
    for (method, path, allow) in [
        ("PUT", "/api/generations", "GET, HEAD, POST"),
        ("PUT", one.as_str(), "GET, HEAD, DELETE"),
        ("POST", "/api/status", "GET, HEAD"),
    ] {
        let answer = rig.send(method, path, &[], "");
        assert_eq!(
            answer.status,
            StatusCode::METHOD_NOT_ALLOWED,
            "{method} {path}"
        );
        assert_eq!(answer.allow.as_deref(), Some(allow));
    }
    assert_eq!(
        rig.send("GET", "/api/generation", &[], "").status,
        StatusCode::NOT_FOUND
    );
}

/// A body that tells whether anybody asked for its data.
struct Watched(Arc<AtomicBool>);

impl Body for Watched {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.0.store(true, Ordering::SeqCst);
        Poll::Ready(None)
    }
}

#[test]
fn a_body_over_the_usual_limit_is_read_only_for_a_live_session_of_an_operator() {
    let rig = rig();
    let (alice, ola, vera) = (rig.login("alice"), rig.login("ola"), rig.login("vera"));
    let big = waf::body_limit(&Method::POST, "/api/generations").unwrap();
    let dir = rig.dir.path().to_path_buf();
    let app = Arc::new(rig.app);
    let client = IpAddr::from([127, 0, 0, 1]);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    // Whether the body was asked for, and the request went on, for a client with this session.
    let read = |session: Option<&Session>, limit: usize| {
        let mut headers = HeaderMap::new();
        if let Some(session) = session {
            let cookie = format!("{COOKIE_NAME}={}", session.id);
            headers.insert(COOKIE, HeaderValue::from_str(&cookie).unwrap());
        }
        let asked = Arc::new(AtomicBool::new(false));
        let result = runtime.block_on(body::read(
            &app,
            &headers,
            client,
            Watched(asked.clone()),
            limit,
        ));
        (result.is_ok(), asked.load(Ordering::SeqCst))
    };
    // The usual limit is read for everybody; the limit of the import for an operator and an owner.
    assert_eq!(read(None, BODY_MAX), (true, true));
    assert_eq!(read(Some(&vera), BODY_MAX), (true, true));
    assert_eq!(read(Some(&ola), big), (true, true));
    assert_eq!(read(Some(&alice), big), (true, true));
    // No session, a cookie that names none, and a viewer get the request on without the body, to be refused.
    assert_eq!(read(None, big), (true, false));
    let unknown = Session {
        id: "a".repeat(43),
        csrf: String::new(),
    };
    assert_eq!(read(Some(&unknown), big), (true, false));
    assert_eq!(read(Some(&vera), big), (true, false));
    // The role is the one the store gives now: a user that was disabled is not read for either.
    put_user(&dir, "ola", Role::Operator, PASSWORD, true);
    assert_eq!(read(Some(&ola), big), (true, false));
    put_user(&dir, "alice", Role::Viewer, PASSWORD, false);
    assert_eq!(read(Some(&alice), big), (true, false));
}

#[test]
fn a_body_over_the_usual_limit_is_read_for_the_token_of_an_operator_and_for_nothing_else() {
    use crate::admin::auth::tokens::mint;
    let rig = rig();
    let store = FileAdminStore::open(rig.dir.path()).unwrap();
    let text = |owner: &str, role: Role| {
        let (text, token) = mint(owner, role, "test", crate::admin::users::now_ms(), 1).unwrap();
        store.create_token(&token).unwrap();
        text.as_str().to_owned()
    };
    let (operator, viewer, owner) = (
        text("ola", Role::Operator),
        text("vera", Role::Viewer),
        text("alice", Role::Owner),
    );
    let cookie = format!("{COOKIE_NAME}={}", rig.login("ola").id);
    let big = waf::body_limit(&Method::POST, "/api/generations").unwrap();
    let client = IpAddr::from([127, 0, 0, 1]);
    let app = Arc::new(rig.app);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let read = |fields: &[(&str, &str)]| {
        let mut headers = HeaderMap::new();
        for (name, value) in fields {
            headers.append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        let asked = Arc::new(AtomicBool::new(false));
        let result = runtime.block_on(body::read(
            &app,
            &headers,
            client,
            Watched(asked.clone()),
            big,
        ));
        (result.is_ok(), asked.load(Ordering::SeqCst))
    };
    let bearer = |text: &str| format!("Bearer {text}");
    assert_eq!(read(&[("authorization", &bearer(&operator))]), (true, true));
    assert_eq!(read(&[("authorization", &bearer(&owner))]), (true, true));
    // A viewer's token, a token that is not one, and a cookie together with a token are not read.
    assert_eq!(read(&[("authorization", &bearer(&viewer))]), (true, false));
    assert_eq!(
        read(&[("authorization", "Bearer tkc_nothing")]),
        (true, false)
    );
    assert_eq!(
        read(&[("authorization", &bearer(&operator)), ("cookie", &cookie)]),
        (true, false)
    );
    // A client that has used up its tries is not looked at, even with a token that is right.
    let bad = bearer(&format!("tkc_0123456789abcdef_{}", "a".repeat(43)));
    for _ in 0..30 {
        read(&[("authorization", &bad)]);
    }
    assert_eq!(
        read(&[("authorization", &bearer(&operator))]),
        (true, false)
    );
}
