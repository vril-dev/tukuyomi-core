//! The tests of the routes that read, and the rig of the tests of the routes of the managed configuration: a managed
//! store with its main file (`Fixture`), an audit log that can refuse, and a proxy that answers on a control socket.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::net::UnixListener;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;
use std::thread::{self, JoinHandle};

use bytes::Bytes;
use http::HeaderMap;
use http::header::{CONTENT_TYPE, HeaderValue};

use super::*;
use crate::admin::audit::Append;
use crate::admin::file_store::FileAdminStore;
use crate::admin::file_store::tests::{TestDir, scratch};
use crate::log;
use crate::log::sink::RecordFile;
use crate::managed::store::tests::Fixture;

pub(in crate::admin::managed) const CX: Cx<'static> = Cx {
    id: "0123456789abcdef-1",
    client: IpAddr::V4(Ipv4Addr::LOCALHOST),
};

pub(in crate::admin::managed) fn who(role: Role) -> Who {
    Who {
        name: "ola".to_owned(),
        role,
        auth: None,
        cookie: String::new(),
        csrf: String::new(),
        handle: "ab12cd34".to_owned(),
        changed: 1,
        idle_left: Duration::ZERO,
        total_left: Duration::ZERO,
        pending: false,
        must_change: false,
        setup_needed: false,
        mfa: false,
        recovery_left: 0,
    }
}

/// The SHA-256 of the main file that the proxy says it has in force.
pub(in crate::admin::managed) const CONFIG: [u8; 32] = [3; 32];

/// The proxy, as far as its control socket goes. It answers a question about its state with the managed version it
/// serves and its count of the readings that replaced its configuration, and a reload order by taking the version, or
/// by refusing it while `refusing` is set. It closes a connection without a word while `closing` is set. It counts the
/// questions and keeps the versions it was ordered to take.
pub(in crate::admin::managed) struct Proxy {
    pub(in crate::admin::managed) serving: Arc<Mutex<Option<[u8; 32]>>>,
    pub(in crate::admin::managed) reloading: Arc<AtomicBool>,
    pub(in crate::admin::managed) closing: Arc<AtomicBool>,
    pub(in crate::admin::managed) refusing: Arc<AtomicBool>,
    pub(in crate::admin::managed) asked: Arc<AtomicUsize>,
    pub(in crate::admin::managed) orders: Arc<Mutex<Vec<[u8; 32]>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

/// What the proxy answers to the line `line`.
fn answer_of(proxy: &Proxy, replaced: &AtomicUsize, line: &str) -> Value {
    let asked: Value = serde_json::from_str(line).unwrap();
    let serving = *proxy.serving.lock().unwrap();
    if asked["op"] == "reload" {
        let name = Fingerprint::from_hex(asked["managed"].as_str().unwrap().as_bytes())
            .unwrap()
            .bytes();
        proxy.orders.lock().unwrap().push(name);
        if proxy.refusing.load(Ordering::SeqCst) {
            return json!({
                "result": "refused", "reason": "upstream",
                "detail": "the name of a server cannot be looked up (upstream app)",
                "managed": serving.map(|name| hex(&name)),
            });
        }
        *proxy.serving.lock().unwrap() = Some(name);
        replaced.fetch_add(1, Ordering::SeqCst);
        return json!({"result": "replaced", "config": hex(&CONFIG), "managed": hex(&name)});
    }
    json!({
        "generation": "0".repeat(64), "mode": "block", "engine": "coraza", "phase": "ready",
        "switching": false, "ready": true, "reloading": proxy.reloading.load(Ordering::SeqCst),
        "managed": serving.map(|name| hex(&name)), "config": hex(&CONFIG), "resolve_timeout_ms": 1000,
        "config_reloads": {"replaced": replaced.load(Ordering::SeqCst), "refused": 0},
    })
}

impl Proxy {
    fn start(path: &Path, serving: Option<[u8; 32]>) -> Proxy {
        let listener = UnixListener::bind(path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut proxy = Proxy {
            serving: Arc::new(Mutex::new(serving)),
            reloading: Arc::new(AtomicBool::new(false)),
            closing: Arc::new(AtomicBool::new(false)),
            refusing: Arc::new(AtomicBool::new(false)),
            asked: Arc::new(AtomicUsize::new(0)),
            orders: Arc::new(Mutex::new(Vec::new())),
            stop: Arc::new(AtomicBool::new(false)),
            thread: None,
        };
        let seen = Proxy {
            serving: proxy.serving.clone(),
            reloading: proxy.reloading.clone(),
            closing: proxy.closing.clone(),
            refusing: proxy.refusing.clone(),
            asked: proxy.asked.clone(),
            orders: proxy.orders.clone(),
            stop: proxy.stop.clone(),
            thread: None,
        };
        proxy.thread = Some(thread::spawn(move || {
            let replaced = AtomicUsize::new(0);
            while !seen.stop.load(Ordering::SeqCst) {
                let Ok((mut sock, _)) = listener.accept() else {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                };
                seen.asked.fetch_add(1, Ordering::SeqCst);
                if seen.closing.load(Ordering::SeqCst) {
                    continue;
                }
                sock.set_nonblocking(false).unwrap();
                sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                let mut line = String::new();
                if BufReader::new(sock.try_clone().unwrap())
                    .read_line(&mut line)
                    .is_err()
                {
                    continue;
                }
                let answer = answer_of(&seen, &replaced, &line);
                let _ = sock.write_all(format!("{answer}\n").as_bytes());
            }
        }));
        proxy
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

/// An audit sink that writes the file and takes nothing while `fail` is set.
struct Sink {
    fail: Arc<AtomicBool>,
    file: RecordFile,
}

impl Append for Sink {
    fn append(&mut self, line: &[u8]) -> bool {
        !self.fail.load(Ordering::SeqCst) && Append::append(&mut self.file, line)
    }
}

pub(in crate::admin::managed) struct Rig {
    pub(in crate::admin::managed) managed: Managed,
    pub(in crate::admin::managed) fixture: Fixture,
    /// The version that the store chooses and the proxy serves when the rig is made.
    pub(in crate::admin::managed) first: [u8; 32],
    pub(in crate::admin::managed) audit_fails: Arc<AtomicBool>,
    pub(in crate::admin::managed) proxy: Option<Proxy>,
    audit: Arc<AuditLog>,
    _admin: TestDir,
    /// The directory of the control socket, apart from the fixture so that the path of the socket stays short.
    _ctl: TestDir,
}

/// A version without a site whose group `app` is at 127.0.0.1:9000, which serves every request.
pub(in crate::admin::managed) fn bare_version() -> Value {
    json!({
        "sites": [],
        "upstreams": {"app": {"servers": [{
            "address": "127.0.0.1:9000", "weight": 1, "max_fails": 1, "fail_timeout_ms": 10000, "backup": false,
        }]}},
        "routes": [],
        "default_upstream": "app",
    })
}

/// A rig whose store chooses a version without a site that the proxy serves, or no proxy at all.
pub(in crate::admin::managed) fn rig(with_proxy: bool) -> Rig {
    rig_with(with_proxy, true)
}

/// `rig`, for a main file that had `managed` when the process started, or not.
pub(in crate::admin::managed) fn rig_with(with_proxy: bool, managed: bool) -> Rig {
    let fixture = Fixture::new();
    let main = fixture.main_file(|_| {});
    let first = fixture.current(&bare_version());
    let admin = scratch();
    let store: Arc<dyn AdminStore> = Arc::new(FileAdminStore::open(admin.path()).unwrap());
    let audit_dir = admin.path().join("audit");
    let audit_fails = Arc::new(AtomicBool::new(false));
    let sink = Sink {
        fail: audit_fails.clone(),
        file: RecordFile::open_in("audit", &audit_dir, 1 << 20, 2).unwrap(),
    };
    let (logger, _) = log::recording();
    let audit = Arc::new(AuditLog::with_sink(
        Box::new(sink),
        &audit_dir,
        logger.clone(),
    ));
    let ctl = scratch();
    let socket = ctl.path().join("c.sock");
    let proxy = with_proxy.then(|| Proxy::start(&socket, Some(first)));
    let dir = fixture.dir();
    let managed = Managed::new(
        &main,
        managed.then_some(dir.as_path()),
        &socket,
        Duration::from_secs(1),
        store,
        audit.clone(),
        logger,
    );
    Rig {
        managed,
        fixture,
        first,
        audit_fails,
        proxy,
        audit,
        _admin: admin,
        _ctl: ctl,
    }
}

impl Rig {
    pub(in crate::admin::managed) fn call(
        &self,
        op: Op,
        method: &str,
        path: &str,
        body: &str,
    ) -> Answer {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let req = Req {
            method: Method::from_bytes(method.as_bytes()).unwrap(),
            path: path.to_owned(),
            query: String::new(),
            headers,
            peer: SocketAddr::from(([127, 0, 0, 1], 5)),
            body: Bytes::copy_from_slice(body.as_bytes()),
        };
        self.managed.handle(op, &req, &who(Role::Operator), &CX)
    }

    pub(in crate::admin::managed) fn get(&self, op: Op, path: &str) -> Answer {
        self.call(op, "GET", path, "")
    }

    /// The last job once it has ended, waited for at most 10 s.
    pub(in crate::admin::managed) fn ended_job(&self) -> Value {
        let by = Instant::now() + Duration::from_secs(10);
        loop {
            let job = self.get(Op::Job, "/api/managed/job").body["job"].clone();
            if job["state"] == "ended" {
                return job;
            }
            assert!(Instant::now() < by, "the job did not end: {job}");
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// The lines of the audit log, the oldest first.
    pub(in crate::admin::managed) fn audit(&self) -> Vec<Value> {
        let mut lines = self.audit.recent(100).unwrap();
        lines.reverse();
        lines
    }

    pub(in crate::admin::managed) fn proxy(&self) -> &Proxy {
        self.proxy.as_ref().unwrap()
    }

    /// The names of the entries of a directory of the store: `versions` or `files`.
    pub(in crate::admin::managed) fn entries(&self, kind: &str) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(self.fixture.dir().join(kind))
            .map(|dir| {
                dir.map(|entry| entry.unwrap().file_name().into_string().unwrap())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }
}

#[test]
fn the_state_shows_the_chosen_and_the_served_version() {
    let rig = rig(true);
    let state = rig.get(Op::State, "/api/managed");
    assert_eq!(state.status, StatusCode::OK);
    assert_eq!(
        state.body,
        json!({
            "managed": true, "current": hex(&rig.first), "serving": hex(&rig.first), "reachable": true,
            "reloading": false, "rollback_to": null, "job": null,
        })
    );
    // A proxy that serves another version, or none, or is reading its configuration again, says so.
    *rig.proxy().serving.lock().unwrap() = None;
    rig.proxy().reloading.store(true, Ordering::SeqCst);
    let state = rig.get(Op::State, "/api/managed");
    assert_eq!(
        (&state.body["serving"], &state.body["reloading"]),
        (&Value::Null, &json!(true))
    );
    // A proxy that cannot be reached, and a store that chooses nothing.
    let rig = rig_with(false, true);
    fs::remove_file(rig.fixture.dir().join("current")).unwrap();
    let state = rig.get(Op::State, "/api/managed");
    assert_eq!(
        state.body,
        json!({
            "managed": true, "current": null, "serving": null, "reachable": false, "reloading": null,
            "rollback_to": null, "job": null,
        })
    );
    // A record of the chosen version that cannot be read is 500.
    fs::write(rig.fixture.dir().join("current"), "broken\n").unwrap();
    let state = rig.get(Op::State, "/api/managed");
    assert_eq!(state.status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[test]
fn a_main_file_without_managed_at_the_start_has_no_managed_configuration() {
    let rig = rig_with(true, false);
    let state = rig.get(Op::State, "/api/managed");
    assert_eq!(
        (state.status, state.body),
        (StatusCode::OK, json!({"managed": false}))
    );
    let one = format!("/api/managed/versions/{}", hex(&rig.first));
    for (op, path) in [
        (Op::Versions, "/api/managed/versions"),
        (Op::Version, &one),
        (Op::Job, "/api/managed/job"),
        (Op::History, "/api/managed/history"),
    ] {
        let answer = rig.get(op, path);
        assert_eq!(answer.status, StatusCode::CONFLICT, "{path}");
        assert_eq!(
            answer.body["error"],
            json!("the configuration has no managed object")
        );
    }
    // Nothing was asked of the proxy.
    assert_eq!(rig.proxy().asked.load(Ordering::SeqCst), 0);
}

#[test]
fn the_versions_are_listed_newest_first_and_a_version_shows_its_json_but_no_file() {
    let rig = rig(true);
    let key = b"-----BEGIN PRIVATE KEY-----\nsecret of the site\n-----END PRIVATE KEY-----\n";
    let with_site = rig.fixture.plain_version(b"chain", key);
    let second = rig.fixture.version(&with_site);
    // The list is in the order of the times the versions were made.
    let older = fs::File::options()
        .write(true)
        .open(
            rig.fixture
                .dir()
                .join("versions")
                .join(format!("{}.json", hex(&rig.first))),
        )
        .unwrap();
    older
        .set_modified(std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1))
        .unwrap();
    let list = rig.get(Op::Versions, "/api/managed/versions");
    assert_eq!(list.status, StatusCode::OK);
    let items = list.body["versions"].as_array().unwrap();
    let names: Vec<&str> = items
        .iter()
        .map(|item| item["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, [hex(&second), hex(&rig.first)]);
    assert_eq!(
        (
            &items[1]["current"],
            &items[1]["serving"],
            &items[1]["made"]
        ),
        (&json!(true), &json!(true), &json!(1))
    );
    assert_eq!(
        (&items[0]["current"], &items[0]["serving"]),
        (&json!(false), &json!(false))
    );
    assert_eq!(list.body["reachable"], json!(true));

    let path = format!("/api/managed/versions/{}", hex(&second));
    let one = rig.get(Op::Version, &path);
    assert_eq!(one.status, StatusCode::OK);
    assert_eq!(one.body["version"], with_site);
    assert_eq!(one.body["name"], json!(hex(&second)));
    // The version names its key by its SHA-256; the key itself is in no answer.
    assert!(!one.body.to_string().contains("secret of the site"));
    // A version the store does not have, and a name that is not one, are 404.
    for path in [
        format!("/api/managed/versions/{}", "0".repeat(64)),
        "/api/managed/versions/xyz".to_owned(),
    ] {
        assert_eq!(
            rig.get(Op::Version, &path).status,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
    // A version whose bytes are not what its name says is listed, and its content is 500.
    let file = rig
        .fixture
        .dir()
        .join("versions")
        .join(format!("{}.json", hex(&second)));
    fs::write(&file, b"{}").unwrap();
    assert_eq!(
        rig.get(Op::Version, &path).status,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        rig.get(Op::Versions, "/api/managed/versions").body["versions"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}
