use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};

use bytes::Bytes;
use http::HeaderMap;
use http::header::{CONTENT_TYPE, HeaderValue};

use super::*;
use crate::acme::base64;
use crate::admin::audit::Append;
use crate::admin::file_store::FileAdminStore;
use crate::admin::file_store::tests::{TestDir, scratch};
use crate::admin::waf::history::Activation;
use crate::log;
use crate::log::sink::RecordFile;
use crate::rules::bundle::{Bundle, BundlePath, Mode};
use crate::rules::file_store::FileStore;
use crate::rules::routes::Routes;
use crate::rules::store::{NOT_EXPECTED, Staged};
use crate::rules::trial::{Failed, Finish};

const CX: Cx<'static> = Cx {
    id: "0123456789abcdef-1",
    client: IpAddr::V4(Ipv4Addr::LOCALHOST),
};
const WAITS: Waits = Waits {
    ready: Duration::from_secs(1),
    inspect: Duration::from_secs(1),
    stop: Duration::from_secs(1),
    slice: Duration::from_millis(20),
};

fn who() -> Who {
    Who {
        name: "ola".to_owned(),
        role: Role::Operator,
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

// ---- the proxy, as far as its control socket goes ----

#[derive(Clone, Copy, PartialEq, Eq)]
enum Behavior {
    /// Switches at once.
    Switch,
    Refuse,
    /// Says `busy` and switches 400 ms later.
    Busy,
    /// As `Busy`, and closes the next two connections without a word.
    BusyDeaf,
    /// Says `busy` and never switches.
    Lost,
    /// Says `busy` and goes away.
    Gone,
}

/// What to do when the proxy is asked for its state, once.
type Hook = Box<dyn FnOnce() + Send>;

struct Proxy {
    serving: Arc<Mutex<Fingerprint>>,
    behavior: Arc<Mutex<Behavior>>,
    orders: Arc<Mutex<Vec<Fingerprint>>>,
    /// The next connections, that many, are closed without a word, as the proxy does when its places are taken.
    closing: Arc<AtomicUsize>,
    /// Runs when the state is asked for the next time.
    hook: Arc<Mutex<Option<Hook>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Proxy {
    fn start(path: &Path) -> Proxy {
        let listener = UnixListener::bind(path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut proxy = Proxy {
            serving: Arc::new(Mutex::new(Fingerprint::of(b"none"))),
            behavior: Arc::new(Mutex::new(Behavior::Switch)),
            orders: Arc::new(Mutex::new(Vec::new())),
            closing: Arc::new(AtomicUsize::new(0)),
            hook: Arc::new(Mutex::new(None)),
            stop: Arc::new(AtomicBool::new(false)),
            thread: None,
        };
        let (serving, behavior, orders, stop) = (
            proxy.serving.clone(),
            proxy.behavior.clone(),
            proxy.orders.clone(),
            proxy.stop.clone(),
        );
        let (closing, hook) = (proxy.closing.clone(), proxy.hook.clone());
        let pending = Arc::new(AtomicBool::new(false));
        let thread = thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                let Ok((mut sock, _)) = listener.accept() else {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                };
                if closing.load(Ordering::SeqCst) > 0 {
                    closing.fetch_sub(1, Ordering::SeqCst);
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
                let ask: Value = serde_json::from_str(&line).unwrap();
                let current = *serving.lock().unwrap();
                let mut gone = false;
                let answer = if ask["op"] == "status" {
                    let hooked = hook.lock().unwrap().take();
                    if let Some(hooked) = hooked {
                        hooked();
                    }
                    format!(
                        r#"{{"generation":"{}","mode":"block","phase":"ready","switching":{},"ready":true}}"#,
                        current.hex(),
                        pending.load(Ordering::SeqCst)
                    )
                } else {
                    let expect =
                        Fingerprint::from_hex(ask["expect"].as_str().unwrap().as_bytes()).unwrap();
                    orders.lock().unwrap().push(expect);
                    let behavior = *behavior.lock().unwrap();
                    let (result, now) = if behavior == Behavior::Refuse {
                        ("refused", current)
                    } else if expect == current {
                        ("unchanged", current)
                    } else if behavior == Behavior::Switch {
                        *serving.lock().unwrap() = expect;
                        ("switched", expect)
                    } else {
                        gone = behavior == Behavior::Gone;
                        if matches!(behavior, Behavior::Busy | Behavior::BusyDeaf) {
                            if behavior == Behavior::BusyDeaf {
                                closing.store(2, Ordering::SeqCst);
                            }
                            pending.store(true, Ordering::SeqCst);
                            let (serving, pending) = (serving.clone(), pending.clone());
                            thread::spawn(move || {
                                thread::sleep(Duration::from_millis(400));
                                *serving.lock().unwrap() = expect;
                                pending.store(false, Ordering::SeqCst);
                            });
                        }
                        ("busy", current)
                    };
                    format!(r#"{{"result":"{result}","generation":"{}"}}"#, now.hex())
                };
                let _ = sock.write_all(format!("{answer}\n").as_bytes());
                if gone {
                    break;
                }
            }
        });
        proxy.thread = Some(thread);
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

// ---- the trial, the audit log and the rig ----

struct FakeTrial {
    fail: Arc<Mutex<Option<Failed>>>,
    runs: Arc<AtomicUsize>,
}

impl Trial for FakeTrial {
    fn run(&self, _: &Staged, _: bool, _: Mode, stop: &AtomicBool) -> Result<Finish, &'static str> {
        self.runs.fetch_add(1, Ordering::SeqCst);
        let result = match *self.fail.lock().unwrap() {
            _ if stop.load(Ordering::SeqCst) => Err(Failed::Interrupted),
            Some(failed) => Err(failed),
            None => Ok(Vec::new()),
        };
        Ok(Finish {
            result,
            detail: None,
            clean: true,
        })
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

struct Rig {
    waf: Waf,
    dir: TestDir,
    /// The directory of the control socket, apart from `dir` so that the path of the socket stays short.
    _ctl: TestDir,
    audit: Arc<AuditLog>,
    admin: Arc<FileAdminStore>,
    audit_fails: Arc<AtomicBool>,
    trial_fails: Arc<Mutex<Option<Failed>>>,
    runs: Arc<AtomicUsize>,
    proxy: Option<Proxy>,
}

fn rig(with_proxy: bool) -> Rig {
    rig_with(with_proxy, None)
}

fn rig_with(with_proxy: bool, records: Option<RecordsConfig>) -> Rig {
    let dir = scratch();
    fs::DirBuilder::new()
        .mode(0o700)
        .create(dir.path().join("rules"))
        .unwrap();
    let admin_dir = dir.path().join("admin");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&admin_dir)
        .unwrap();
    let admin = Arc::new(FileAdminStore::open(&admin_dir).unwrap());
    let audit_dir = admin_dir.join("audit");
    let audit_fails = Arc::new(AtomicBool::new(false));
    let sink = Sink {
        fail: audit_fails.clone(),
        file: RecordFile::open_in("audit", &audit_dir, 1 << 20, 2).unwrap(),
    };
    let (logger, _) = log::recording();
    let audit = Arc::new(AuditLog::with_sink(Box::new(sink), &audit_dir, logger));
    let (trial_fails, runs) = (Arc::new(Mutex::new(None)), Arc::new(AtomicUsize::new(0)));
    let ctl = scratch();
    let socket = ctl.path().join("c.sock");
    let proxy = with_proxy.then(|| Proxy::start(&socket));
    let rules = StoreConfig::File {
        dir: dir.path().join("rules"),
    };
    let config = Config {
        rules: &rules,
        control: &socket,
        crs_dir: None,
        records: records.as_ref(),
        waits: WAITS,
    };
    let trial = FakeTrial {
        fail: trial_fails.clone(),
        runs: runs.clone(),
    };
    let waf = Waf::new(config, admin.clone(), audit.clone(), Box::new(trial));
    Rig {
        waf,
        dir,
        _ctl: ctl,
        audit,
        admin,
        audit_fails,
        trial_fails,
        runs,
        proxy,
    }
}

fn bundle(n: u32, mode: Mode, routes: Routes) -> Bundle {
    let path = BundlePath::parse("rules/r.conf").unwrap();
    Bundle::new(
        mode,
        vec![(path.clone(), format!("SecDebugLogLevel {n}\n").into_bytes())],
        vec![path],
        routes,
    )
    .unwrap()
}

fn b64(data: &[u8]) -> String {
    let text = base64::url(data).replace('-', "+").replace('_', "/");
    format!("{text}{}", "=".repeat((4 - text.len() % 4) % 4))
}

impl Rig {
    fn store(&self) -> FileStore {
        FileStore::open(&self.dir.path().join("rules")).unwrap()
    }

    /// A generation whose rule file differs by `n`.
    fn make(&self, n: u32) -> Fingerprint {
        let bundle = bundle(n, Mode::Block, Routes::default());
        let mut store = self.store();
        store.stage(&bundle).unwrap();
        store.commit().unwrap();
        bundle.fingerprint()
    }

    /// The rules store chooses `generation` and the proxy serves it.
    fn start_on(&self, generation: Fingerprint) {
        self.store().activate(generation).unwrap();
        if let Some(proxy) = &self.proxy {
            *proxy.serving.lock().unwrap() = generation;
        }
    }

    fn current(&self) -> Option<Fingerprint> {
        self.store().current().unwrap()
    }

    fn serving(&self) -> Fingerprint {
        *self.proxy.as_ref().unwrap().serving.lock().unwrap()
    }

    fn behave(&self, behavior: Behavior) {
        *self.proxy.as_ref().unwrap().behavior.lock().unwrap() = behavior;
    }

    /// Runs `hook` when the proxy is asked for its state next, which is after the check of `expect` of a switch and
    /// before the choice.
    fn on_status(&self, hook: impl FnOnce() + Send + 'static) {
        *self.proxy.as_ref().unwrap().hook.lock().unwrap() = Some(Box::new(hook));
    }

    /// The proxy closes the next `times` connections without a word.
    fn close_next(&self, times: usize) {
        self.proxy
            .as_ref()
            .unwrap()
            .closing
            .store(times, Ordering::SeqCst);
    }

    fn orders(&self) -> Vec<Fingerprint> {
        self.proxy.as_ref().unwrap().orders.lock().unwrap().clone()
    }

    fn call(&self, op: Op, method: &str, path: &str, query: &str, body: &str) -> Answer {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let req = Req {
            method: Method::from_bytes(method.as_bytes()).unwrap(),
            path: path.to_owned(),
            query: query.to_owned(),
            headers,
            peer: SocketAddr::from(([127, 0, 0, 1], 5)),
            body: Bytes::copy_from_slice(body.as_bytes()),
        };
        self.waf.handle(op, &req, &who(), &CX)
    }

    fn post(&self, op: Op, body: Value) -> Answer {
        self.call(op, "POST", "/x", "", &body.to_string())
    }

    fn get(&self, op: Op, path: &str, query: &str) -> Answer {
        self.call(op, "GET", path, query, "")
    }

    fn activate(&self, to: Fingerprint, expect: Fingerprint) -> Answer {
        let body = json!({"generation": to.hex(), "expect": expect.hex()});
        self.post(Op::Activate, body)
    }

    fn rollback(&self, expect: Fingerprint) -> Answer {
        self.post(Op::Rollback, json!({"expect": expect.hex()}))
    }

    fn remove(&self, generation: Fingerprint) -> Answer {
        let path = format!("/api/generations/{}", generation.hex());
        self.call(Op::Remove, "DELETE", &path, "", "")
    }

    fn import(&self, body: &Value) -> Answer {
        self.call(
            Op::Import,
            "POST",
            "/api/generations",
            "",
            &body.to_string(),
        )
    }

    /// The lines of the audit log, the newest first.
    fn lines(&self) -> Vec<Value> {
        self.audit.recent(100).unwrap()
    }

    /// The history, the newest first, as (kind, from, to, result).
    fn history(&self) -> Vec<(Kind, Fingerprint, Fingerprint, Ended)> {
        self.admin
            .activations(100)
            .unwrap()
            .iter()
            .map(|a: &Activation| (a.kind, a.from, a.to, a.result))
            .collect()
    }
}

fn fields<'a>(line: &'a Value, keys: &[&str]) -> Vec<&'a str> {
    keys.iter()
        .map(|key| line[key].as_str().unwrap_or("-"))
        .collect()
}

// ---- switching ----

#[test]
fn an_activation_with_a_wrong_expect_is_409_and_changes_nothing() {
    let rig = rig(true);
    let (g1, g2, g3) = (rig.make(1), rig.make(2), rig.make(3));
    rig.start_on(g1);
    let answer = rig.activate(g3, g2);
    assert_eq!(answer.status, StatusCode::CONFLICT);
    assert_eq!(rig.current(), Some(g1));
    assert!(rig.orders().is_empty());
    assert!(rig.history().is_empty());
    let line = &rig.lines()[0];
    assert_eq!(
        fields(line, &["action", "result", "reason", "actor", "id"]),
        ["activate", "denied", "expect", "ola", "0123456789abcdef-1"]
    );
    // A generation that the store does not have, and digits that are not 64.
    assert_eq!(
        rig.activate(Fingerprint::of(b"x"), g1).status,
        StatusCode::NOT_FOUND
    );
    let bad = rig.post(
        Op::Activate,
        json!({"generation": "abc", "expect": g1.hex()}),
    );
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    let extra = rig.post(
        Op::Activate,
        json!({"generation": g2.hex(), "expect": g1.hex(), "force": true}),
    );
    assert_eq!(extra.status, StatusCode::BAD_REQUEST);
    assert_eq!(rig.current(), Some(g1));
    assert!(rig.history().is_empty());
}

#[test]
fn an_activation_with_the_proxy_unreachable_changes_nothing_and_is_written_to_the_history() {
    let rig = rig(false);
    let (g1, g2) = (rig.make(1), rig.make(2));
    rig.start_on(g1);
    // A request that has a wrong `expect` is refused first, and leaves no line: `from` is the generation the store has.
    assert_eq!(rig.activate(g2, g2).status, StatusCode::CONFLICT);
    assert!(rig.history().is_empty());
    let answer = rig.activate(g2, g1);
    assert_eq!(answer.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(answer.body["result"], "unreachable");
    assert_eq!(answer.body["chosen"], false);
    assert_eq!(rig.current(), Some(g1));
    assert_eq!(
        rig.history(),
        [(Kind::Activate, g1, g2, Ended::Unreachable)]
    );
    assert_eq!(
        fields(&rig.lines()[0], &["action", "result", "reason"]),
        ["activate", "denied", "unreachable"]
    );
    // The status says so as well, and a rollback has no switch to go back from.
    let status = rig.get(Op::Status, "/api/status", "");
    assert_eq!(status.body["reachable"], false);
    assert_eq!(status.body["proxy"], Value::Null);
    assert_eq!(status.body["current"], g1.hex());
    assert_eq!(rig.rollback(g1).status, StatusCode::CONFLICT);
}

#[test]
fn a_switch_is_written_to_the_history_and_a_rollback_goes_to_the_from_of_the_last_switch() {
    let rig = rig(true);
    let (g1, g2, g3) = (rig.make(1), rig.make(2), rig.make(3));
    rig.start_on(g1);
    let none = rig.rollback(g1);
    assert_eq!(none.status, StatusCode::CONFLICT);
    assert_eq!(none.body["error"], "there is no switch to go back from");

    let first = rig.activate(g2, g1);
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(first.body["result"], "switched");
    assert_eq!((rig.current(), rig.serving()), (Some(g2), g2));
    assert_eq!(rig.activate(g3, g2).body["result"], "switched");
    // The proxy refuses the next one: the store chooses it all the same, and the history says what happened.
    rig.behave(Behavior::Refuse);
    let refused = rig.activate(g1, g3);
    assert_eq!(refused.status, StatusCode::CONFLICT);
    assert_eq!(
        (
            refused.body["result"].as_str(),
            refused.body["chosen"].as_bool()
        ),
        (Some("refused"), Some(true))
    );
    assert_eq!((rig.current(), rig.serving()), (Some(g1), g3));
    rig.behave(Behavior::Switch);
    // The store is brought back to what runs; the proxy has it already.
    let same = rig.activate(g3, g1);
    assert_eq!(same.body["result"], "unchanged");
    assert_eq!(same.status, StatusCode::OK);

    // The last switch that changed the generation was g2 to g3: that is where a rollback goes back to.
    let back = rig.rollback(g3);
    assert_eq!(back.status, StatusCode::OK, "{:?}", back.body);
    assert_eq!(back.body["generation"], g2.hex());
    assert_eq!((rig.current(), rig.serving()), (Some(g2), g2));
    // And a rollback of the rollback goes forward again. A stale expect changes nothing.
    assert_eq!(rig.rollback(g3).status, StatusCode::CONFLICT);
    assert_eq!(rig.rollback(g2).body["generation"], g3.hex());
    assert_eq!(
        rig.history(),
        [
            (Kind::Rollback, g2, g3, Ended::Switched),
            (Kind::Rollback, g3, g2, Ended::Switched),
            (Kind::Activate, g1, g3, Ended::Unchanged),
            (Kind::Activate, g3, g1, Ended::Refused),
            (Kind::Activate, g2, g3, Ended::Switched),
            (Kind::Activate, g1, g2, Ended::Switched),
        ]
    );
    let history = rig.get(Op::History, "/api/history", "");
    assert_eq!(history.body["entries"].as_array().unwrap().len(), 6);
    assert_eq!(history.body["entries"][0]["actor"], "ola");
    // The audit log has the switches with the generation before and after, and the one that failed.
    let lines = rig.lines();
    let activate = lines
        .iter()
        .rev()
        .find(|l| l["action"] == "activate")
        .unwrap();
    assert_eq!(
        fields(activate, &["result", "before", "after", "target"]),
        ["ok".to_owned(), g1.hex(), g2.hex(), g2.hex()]
            .each_ref()
            .map(String::as_str)
    );
    assert!(
        lines.iter().any(|l| l["action"] == "activate"
            && l["result"] == "failed"
            && l["reason"] == "refused")
    );
}

#[test]
fn a_switch_that_is_under_way_is_waited_for_and_one_that_is_lost_is_failed() {
    let rig = rig(true);
    let (g1, g2, g3) = (rig.make(1), rig.make(2), rig.make(3));
    rig.start_on(g1);
    rig.behave(Behavior::Busy);
    let answer = rig.activate(g2, g1);
    assert_eq!(answer.status, StatusCode::OK, "{:?}", answer.body);
    assert_eq!(answer.body["result"], "switched");
    assert_eq!(rig.serving(), g2);
    assert_eq!(rig.history()[0].3, Ended::Switched);
    rig.behave(Behavior::Lost);
    let lost = rig.activate(g3, g2);
    assert_eq!(lost.status, StatusCode::BAD_GATEWAY);
    assert_eq!(lost.body["result"], "failed");
    assert_eq!(rig.history()[0], (Kind::Activate, g2, g3, Ended::Failed));
    assert_eq!(rig.serving(), g2);
}

#[test]
fn a_generation_that_another_process_chose_after_the_check_is_not_overwritten() {
    let rig = rig(true);
    let (g1, g2, g3) = (rig.make(1), rig.make(2), rig.make(3));
    rig.start_on(g1);
    // A command chooses g3 when the proxy is asked, which is after the check of `expect` and before the choice.
    let rules = rig.dir.path().join("rules");
    rig.on_status(move || FileStore::open(&rules).unwrap().activate(g3).unwrap());
    let answer = rig.activate(g2, g1);
    assert_eq!(answer.status, StatusCode::CONFLICT);
    assert_eq!(answer.body["error"], NOT_EXPECTED.0);
    assert_eq!(rig.current(), Some(g3));
    assert!(rig.orders().is_empty() && rig.history().is_empty());
    assert_eq!(
        fields(&rig.lines()[0], &["action", "result", "reason"]),
        ["activate", "failed", "expect"]
    );
}

#[test]
fn a_proxy_without_a_place_is_asked_again_and_is_busy_only_if_it_still_has_none() {
    let rig = rig(true);
    let (g1, g2, g3) = (rig.make(1), rig.make(2), rig.make(3));
    rig.start_on(g1);
    // Busy before the switch: nothing is changed, and it is not the proxy being gone.
    rig.close_next(2);
    let busy = rig.activate(g2, g1);
    assert_eq!(busy.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(busy.body["error"], "the proxy is busy");
    assert_eq!(rig.current(), Some(g1));
    assert!(rig.orders().is_empty() && rig.history().is_empty());
    assert_eq!(
        fields(&rig.lines()[0], &["action", "result", "reason"]),
        ["activate", "denied", "busy"]
    );
    // The status says the same: the proxy is there, and its state could not be read.
    rig.close_next(2);
    let status = rig.get(Op::Status, "/api/status", "");
    assert_eq!(status.body["reachable"], true);
    assert_eq!(status.body["proxy"], Value::Null);
    // Without a place once, the second look finds one.
    rig.close_next(1);
    assert_eq!(rig.activate(g2, g1).body["result"], "switched");
    // A switch that is under way is waited for although the proxy has no place for the looks at it.
    rig.behave(Behavior::BusyDeaf);
    let answer = rig.activate(g3, g2);
    assert_eq!(answer.status, StatusCode::OK, "{:?}", answer.body);
    assert_eq!(answer.body["result"], "switched");
    assert_eq!(rig.history()[0], (Kind::Activate, g2, g3, Ended::Switched));
}

#[test]
fn a_switch_whose_end_cannot_be_read_is_unconfirmed_and_a_line_that_cannot_be_written_is_told() {
    let gone_rig = rig(true);
    let (g1, g2) = (gone_rig.make(1), gone_rig.make(2));
    gone_rig.start_on(g1);
    // The store is changed, and the proxy goes away before it says how the switch ended.
    gone_rig.behave(Behavior::Gone);
    let gone = gone_rig.activate(g2, g1);
    assert_eq!(gone.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        (gone.body["result"].as_str(), gone.body["chosen"].as_bool()),
        (Some("unconfirmed"), Some(true))
    );
    assert_eq!(gone_rig.current(), Some(g2));
    assert_eq!(
        gone_rig.history(),
        [(Kind::Activate, g1, g2, Ended::Unconfirmed)]
    );
    assert_eq!(
        fields(&gone_rig.lines()[0], &["action", "result", "reason"]),
        ["activate", "failed", "unconfirmed"]
    );

    // With a directory in place of the history, no answer that has a line for it hides that it was not written: the
    // proxy that cannot be reached (nothing is changed), and the store that refuses.
    let none = rig(false);
    let (g1, g2) = (none.make(1), none.make(2));
    none.start_on(g1);
    fs::create_dir(none.dir.path().join("admin").join("activations.log")).unwrap();
    let unreachable = none.activate(g2, g1);
    assert_eq!(unreachable.body["result"], "unreachable");
    assert_eq!(unreachable.body["history"], "not written");
    let up = rig(true);
    let (g1, g2) = (up.make(1), up.make(2));
    up.start_on(g1);
    fs::create_dir(up.dir.path().join("admin").join("activations.log")).unwrap();
    let mut other = up.store();
    other
        .stage(&bundle(9, Mode::Block, Routes::default()))
        .unwrap();
    let refused = up.activate(g2, g1);
    assert_eq!(refused.status, StatusCode::CONFLICT);
    assert_eq!(refused.body["history"], "not written");
    other.discard().unwrap();
    let switched = up.activate(g2, g1);
    assert_eq!(switched.body["result"], "switched");
    assert_eq!(switched.body["history"], "not written");
}

#[test]
fn a_rollback_is_refused_when_the_history_does_not_end_at_the_chosen_generation() {
    let rig = rig(true);
    let (g1, g2, g3) = (rig.make(1), rig.make(2), rig.make(3));
    rig.start_on(g1);
    assert_eq!(rig.activate(g2, g1).body["result"], "switched");
    // The proxy never switches to g3, and the store chooses it. A rollback does not jump back over g2, which the
    // proxy still serves.
    rig.behave(Behavior::Lost);
    assert_eq!(rig.activate(g3, g2).status, StatusCode::BAD_GATEWAY);
    assert_eq!((rig.current(), rig.serving()), (Some(g3), g2));
    let refused = rig.rollback(g3);
    assert_eq!(refused.status, StatusCode::CONFLICT);
    assert_eq!(
        refused.body["error"],
        "the history does not end at the chosen generation"
    );
    assert_eq!((rig.current(), rig.serving()), (Some(g3), g2));
    // The operator chooses g2 again, which the proxy serves, and then switches to g3: now the history ends at the
    // chosen generation, and the rollback goes to g2.
    rig.behave(Behavior::Switch);
    assert_eq!(rig.activate(g2, g3).body["result"], "unchanged");
    assert_eq!(rig.activate(g3, g2).body["result"], "switched");
    let back = rig.rollback(g3);
    assert_eq!(back.status, StatusCode::OK, "{:?}", back.body);
    assert_eq!(back.body["generation"], g2.hex());
    // g1 was where the first rollback target was; it is not any more. g3 is, for the rollback of the rollback.
    assert_eq!(rig.remove(g3).status, StatusCode::CONFLICT);
    assert_eq!(rig.remove(g1).status, StatusCode::OK);
}

#[test]
fn nothing_is_changed_while_the_audit_log_cannot_take_the_line_or_another_change_is_under_way() {
    let rig = rig(true);
    let (g1, g2) = (rig.make(1), rig.make(2));
    rig.start_on(g1);
    rig.audit_fails.store(true, Ordering::SeqCst);
    assert_eq!(rig.activate(g2, g1).status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(rig.remove(g2).status, StatusCode::SERVICE_UNAVAILABLE);
    let body = json!({"rules": [{"name": "a.conf", "data": b64(b"a\n")}]});
    assert_eq!(rig.import(&body).status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(rig.current(), Some(g1));
    assert!(rig.orders().is_empty() && rig.history().is_empty());
    assert_eq!(rig.store().list().unwrap().len(), 2);
    assert_eq!(rig.runs.load(Ordering::SeqCst), 0);
    rig.audit_fails.store(false, Ordering::SeqCst);
    // A change of this process is under way: no change waits for it.
    let under_way = rig.waf.changing.lock().unwrap();
    for answer in [rig.activate(g2, g1), rig.remove(g2), rig.import(&body)] {
        assert_eq!(answer.status, StatusCode::CONFLICT);
        assert_eq!(answer.body["error"], "a change of the rules is under way");
    }
    drop(under_way);
    // The lock of the rules store is held by another process.
    let mut other = rig.store();
    other
        .stage(&bundle(9, Mode::Block, Routes::default()))
        .unwrap();
    let busy = rig.activate(g2, g1);
    assert_eq!(busy.status, StatusCode::CONFLICT);
    assert_eq!(
        busy.body["error"],
        "the rules store is in use by another command"
    );
    assert_eq!(rig.current(), Some(g1));
    other.discard().unwrap();
    assert_eq!(rig.activate(g2, g1).status, StatusCode::OK);
}

// ---- removing ----

#[test]
fn the_chosen_generation_the_target_of_a_rollback_and_one_in_use_are_not_removed() {
    let rig = rig(true);
    let (g1, g2, g3) = (rig.make(1), rig.make(2), rig.make(3));
    rig.start_on(g1);
    assert_eq!(rig.activate(g2, g1).status, StatusCode::OK);
    // g2 is chosen, g1 is where a rollback goes.
    for generation in [g2, g1] {
        let answer = rig.remove(generation);
        assert_eq!(answer.status, StatusCode::CONFLICT);
        assert_eq!(rig.store().list().unwrap().len(), 3);
    }
    let reasons: Vec<&str> = rig
        .lines()
        .iter()
        .filter(|l| l["action"] == "remove" && l["result"] == "denied")
        .map(|l| {
            if l["reason"] == "chosen" {
                "chosen"
            } else {
                "target"
            }
        })
        .collect();
    assert_eq!(reasons, ["target", "chosen"]);
    // A proxy holds g3.
    let store = rig.store();
    let hold = store.hold(g3).unwrap();
    let in_use = rig.remove(g3);
    assert_eq!(in_use.status, StatusCode::CONFLICT);
    assert_eq!(
        in_use.body["error"],
        "the generation is used by a running proxy"
    );
    drop(hold);
    let removed = rig.remove(g3);
    assert_eq!(
        (removed.status, removed.body["removed"].as_str()),
        (StatusCode::OK, Some(g3.hex().as_str()))
    );
    assert_eq!(rig.store().list().unwrap().len(), 2);
    assert!(
        rig.lines()
            .iter()
            .any(|l| l["action"] == "remove" && l["result"] == "ok" && l["target"] == g3.hex())
    );
    // One that the store does not have, and a path that is not a generation.
    assert_eq!(rig.remove(g3).status, StatusCode::NOT_FOUND);
    let path = rig.call(Op::Remove, "DELETE", "/api/generations/zz", "", "");
    assert_eq!(path.status, StatusCode::NOT_FOUND);
}

// ---- reading ----

#[test]
fn the_status_the_generations_and_one_generation_show_the_store_and_the_proxy() {
    let rig = rig(true);
    let g1 = rig.make(1);
    let routes = Routes::from_json(
        br#"[{"host":"admin.example.test","path":"/api/generations","action":"bypass"}]"#,
    )
    .unwrap();
    let detect = bundle(2, Mode::Detect, routes);
    let mut store = rig.store();
    store.stage(&detect).unwrap();
    store.commit().unwrap();
    let g2 = detect.fingerprint();
    rig.start_on(g1);

    let status = rig.get(Op::Status, "/api/status", "");
    assert_eq!(status.body["current"], g1.hex());
    assert_eq!(status.body["reachable"], true);
    assert_eq!(status.body["proxy"]["generation"], g1.hex());
    assert_eq!(status.body["proxy"]["phase"], "ready");

    let list = rig.get(Op::Generations, "/api/generations", "");
    assert_eq!(list.body["reachable"], true);
    let items = list.body["generations"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    for item in items {
        let first = item["fingerprint"] == g1.hex();
        assert_eq!(item["current"], first);
        assert_eq!(item["serving"], first);
        assert_eq!(item["mode"], if first { "block" } else { "detect" });
        assert_eq!(item["routes"], if first { 0 } else { 1 });
        assert!(item["made"].as_i64().unwrap() > 0);
    }

    let one = rig.get(
        Op::Generation,
        &format!("/api/generations/{}", g2.hex()),
        "",
    );
    assert_eq!(one.status, StatusCode::OK);
    assert_eq!(one.body["mode"], "detect");
    assert_eq!(one.body["current"], false);
    assert_eq!(one.body["load"], json!(["rules/r.conf"]));
    assert_eq!(one.body["files"][0]["path"], "rules/r.conf");
    assert_eq!(one.body["files"][0]["sha256"].as_str().unwrap().len(), 64);
    assert_eq!(
        one.body["routes"],
        json!([{"host": "admin.example.test", "path": "/api/generations", "action": "bypass"}])
    );
    for path in [
        format!("/api/generations/{}", Fingerprint::of(b"x").hex()),
        "/api/generations/zz".to_owned(),
    ] {
        assert_eq!(
            rig.get(Op::Generation, &path, "").status,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
}

#[test]
fn the_records_route_reads_the_record_files_or_says_that_there_are_none() {
    let none = rig(false);
    let answer = none.get(Op::Records, "/api/records", "");
    assert_eq!(answer.status, StatusCode::NOT_FOUND);
    assert_eq!(answer.body["error"], "records are not configured");

    let dir = scratch();
    let record = json!({"ts": "2026-10-25T08:00:00.000Z", "type": "request", "id": "0123456789abcdef-3", "path": "/a%20b"});
    fs::write(dir.path().join("records.log"), format!("{record}\n")).unwrap();
    let config = RecordsConfig {
        dir: dir.path().to_path_buf(),
        file_bytes: 1 << 20,
        files: 2,
    };
    let rig = rig_with(false, Some(config));
    let found = rig.get(Op::Records, "/api/records", "id=0123456789abcdef-3");
    assert_eq!(found.status, StatusCode::OK);
    assert_eq!(found.body["records"], json!([record]));
    assert_eq!(found.body["next"], Value::Null);
    assert!(
        rig.get(Op::Records, "/api/records", "id=00-0").body["records"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        rig.get(Op::Records, "/api/records", "color=red").status,
        StatusCode::BAD_REQUEST
    );
    let gone = rig.get(Op::Records, "/api/records", "file=0&offset=0&inode=1");
    assert_eq!(gone.status, StatusCode::CONFLICT);
    // A directory that others can reach is not read.
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o750)).unwrap();
    let open = rig.get(Op::Records, "/api/records", "");
    assert_eq!(open.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        open.body["error"],
        "the directory has group or other permission bits"
    );
}

// ---- importing ----

#[test]
fn an_import_makes_a_generation_that_is_not_chosen_and_says_what_it_made() {
    let rig = rig(true);
    let g1 = rig.make(1);
    rig.start_on(g1);
    let body = json!({
        "rules": [{"name": "a.conf", "data": b64(b"SecDebugLogLevel 7\n")}],
        "data": [{"name": "list.data", "data": b64(b"one\n")}],
        "detect_only": true,
        "routes": [{"path": "/api/generations", "action": "bypass"}],
    });
    let made = rig.import(&body);
    assert_eq!(made.status, StatusCode::OK, "{:?}", made.body);
    assert_eq!(made.body["result"], "created");
    assert_eq!(made.body["trial"]["passed"], true);
    let fingerprint = made.body["fingerprint"].as_str().unwrap().to_owned();
    assert_eq!(rig.import(&body).body["result"], "existing");
    assert_eq!(rig.runs.load(Ordering::SeqCst), 2);
    let one = rig.get(
        Op::Generation,
        &format!("/api/generations/{fingerprint}"),
        "",
    );
    assert_eq!(
        (
            one.body["mode"].as_str(),
            one.body["routes"].as_array().map(Vec::len)
        ),
        (Some("detect"), Some(1))
    );
    assert_eq!(one.body["load"], json!(["rules/a.conf"]));
    // It is not chosen, and nothing is left staged.
    assert_eq!(rig.current(), Some(g1));
    assert_eq!(
        fs::read_dir(rig.dir.path().join("rules").join("staging"))
            .unwrap()
            .count(),
        0
    );
    let line = rig
        .lines()
        .into_iter()
        .rev()
        .find(|l| l["action"] == "import")
        .unwrap();
    assert_eq!(
        fields(&line, &["result", "actor", "target"]),
        ["ok", "ola", fingerprint.as_str()]
    );
}

#[test]
fn an_import_that_fails_its_trial_leaves_no_generation_and_a_bad_input_is_refused_before_anything_is_staged()
 {
    let rig = rig(false);
    let body = json!({"rules": [{"name": "a.conf", "data": b64(b"a\n")}]});
    *rig.trial_fails.lock().unwrap() = Some(Failed::NotReady);
    let failed = rig.import(&body);
    assert_eq!(failed.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(failed.body["trial"]["passed"], false);
    assert!(rig.store().list().unwrap().is_empty());
    assert_eq!(
        fs::read_dir(rig.dir.path().join("rules").join("staging"))
            .unwrap()
            .count(),
        0
    );
    let lines = rig.lines();
    assert_eq!(
        fields(&lines[0], &["action", "result", "reason"]),
        ["import", "failed", "trial"]
    );
    assert_eq!(fields(&lines[1], &["action", "result"]), ["import", "ok"]);
    *rig.trial_fails.lock().unwrap() = None;
    let runs = rig.runs.load(Ordering::SeqCst);

    // A name that is a path, a name outside the rules, a CRS that the configuration does not have, a key that is not
    // known, a file that is not base64, and no rule file at all.
    let part = |name: &str| json!({"name": name, "data": b64(b"a\n")});
    let cases = [
        json!({"rules": [part("sub/a.conf")]}),
        json!({"rules": [part("../a.conf")]}),
        json!({"rules": [part("/etc/a.conf")]}),
        json!({"rules": [part("a.conf")], "crs": true}),
        json!({"rules": [part("a.conf")], "crs_dir": "/etc"}),
        json!({"rules": [{"name": "a.conf", "data": "!!!!"}]}),
        json!({"data": [part("l.data")]}),
        json!({"rules": [part("a.conf")], "routes": [{"path": "/", "action": "bypass"}]}),
    ];
    for case in cases {
        let answer = rig.import(&case);
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{case}");
        assert!(answer.body["error"].is_string(), "{case}");
    }
    let subject = rig
        .import(&json!({"rules": [part("sub/a\u{7f}.conf")]}))
        .body["subject"]
        .clone();
    assert_eq!(subject, "sub/a\\x7f.conf");
    assert_eq!(rig.runs.load(Ordering::SeqCst), runs);
    assert!(rig.store().list().unwrap().is_empty());
    // A process that is stopping ends the trial that it would run.
    rig.waf.interrupt();
    let stopped = rig.import(&body);
    assert_eq!(stopped.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(stopped.body["trial"]["failure"], "stopped by a signal");
    assert!(rig.store().list().unwrap().is_empty());
    // Not JSON, and not the JSON type.
    assert_eq!(
        rig.call(Op::Import, "POST", "/api/generations", "", "{")
            .status,
        StatusCode::BAD_REQUEST
    );
}

// ---- the table ----

#[test]
fn the_table_gives_each_route_its_role_and_a_generation_in_a_path_is_a_star() {
    assert_eq!(pattern("/api/generations/abc"), "/api/generations/*");
    assert_eq!(pattern("/api/generations"), "/api/generations");
    assert_eq!(pattern("/api/status"), "/api/status");
    assert_eq!(
        body_limit(&Method::POST, "/api/generations"),
        Some(12 << 20)
    );
    for path in ["/api/generations", "/api/activate", "/api/rollback"] {
        assert!(slow(&Method::POST, path), "{path}");
    }
    assert!(!slow(&Method::GET, "/api/generations"));
    assert!(!slow(&Method::POST, "/api/login"));
    assert!(!slow(&Method::DELETE, "/api/generations/x"));
    for (method, path) in [
        (Method::GET, "/api/generations"),
        (Method::POST, "/api/activate"),
        (Method::PUT, "/api/generations"),
        (Method::POST, "/api/generations/x"),
    ] {
        assert_eq!(body_limit(&method, path), None, "{method} {path}");
    }
    // A viewer reads; an operator changes.
    for route in &ROUTES {
        let least = if route.method == Method::GET {
            Role::Viewer
        } else {
            Role::Operator
        };
        assert_eq!(route.least, Some(least), "{} {}", route.method, route.path);
        assert!(route.path.starts_with("/api/"));
    }
    assert_eq!(ROUTES.len(), 9);
    // The server gives an answer the longer of an import with a trial that runs out all its times (5 s here) and two
    // waits for a switch (16 s), and a margin.
    let rig = rig(false);
    assert_eq!(rig.waf.longest(), Duration::from_secs(1 + 1 + 14 + 7));
}
