//! The table of the routes of the managed configuration, what they work with (`Managed`), and the routes that read: the
//! state of the managed store, of the proxy and of the last job, the versions of the store, and the job. `ROUTES` says
//! which role may use each route; `server` checks the origin, the session or the token, the CSRF token of a session,
//! the state of the session and the role before `Managed::handle` runs, and writes a refusal to the audit log. A
//! request with a token may use all of these routes.
//!
//! The routes work only for a main file that had `managed` when the process started: without it, `GET /api/managed` is
//! `{"managed": false}`, `GET /api/config` works as it does with it, and every other route is 409 (`the configuration
//! has no managed object`). The managed store is the directory that `managed.dir` named then; it is opened for each
//! request, and one that cannot be opened is 500 with the sentence of the store, as a record of the chosen version that
//! cannot be read is.
//!
//! The routes (a viewer may use the state, the list of the versions, the job and the history, an operator the content
//! of a version, its certificates, its check, the values of the main file, the changes and the removal of a version as
//! well; a body is JSON of at most 64 KiB, the ones of the saving and of the check 12 MiB; the answers are JSON, and
//! `error` is a fixed sentence, which a 400 of the saving and of the check has with `at`, the place it is about, see
//! `import`):
//! - `GET /api/managed`: `{"managed": true, "current", "serving", "reachable", "reloading", "rollback_to", "job"}`:
//!   the version the store chooses (`null` for none), the version the proxy serves by its control socket (`null` when
//!   its state cannot be read or it has none), whether the proxy can be reached (a proxy that has no place for the
//!   question can), whether it reads its configuration again just now (`null` when that is not known), the version a
//!   rollback would go to now (`null` for none; see `history`), and the last job (see `job`; `null` for none). The
//!   two versions may differ (a change whose job could not record its end, a choice that a command made): a change
//!   that puts either in force again makes them one. A history that cannot be read is 503.
//! - `GET /api/managed/versions`: `{"reachable", "versions"}`, the newest first, each with its `name`, `made` (seconds
//!   since the epoch), and whether it is `current` and `serving`.
//! - `GET /api/managed/versions/<name>`: that, and `version`, the JSON of the version as the store has it. A version
//!   names its files by their SHA-256 only, and no answer holds the content of a file. The content of a version is
//!   for an operator, for a route may write a secret for the upstream in its `rewrite`. 404 for a version the store
//!   does not have, 500 for one whose bytes are not what its name says.
//! - `DELETE /api/managed/versions/<name>`: the removal of a version that is neither chosen nor the target of a
//!   rollback, with the cleaning of what no version names any more; no body (see `remove`).
//! - `GET /api/managed/certificates/<name>`: the certificates of the sites of a version as the store has them (see
//!   `certificates`).
//! - `POST /api/managed/apply`: the saving of a version and its putting in force (see `import`); `POST
//!   /api/managed/activate` and `POST /api/managed/rollback`: the putting in force of a version of the store (see
//!   `job`). Each is answered 202 with its job.
//! - `POST /api/managed/check`: the check of a version as the saving checks it, which saves nothing (see `check`).
//! - `GET /api/config`: the values of the main file as it is now, without its paths (see `config`).
//! - `GET /api/managed/job`: `{"job"}`, the last job or `null`.
//! - `GET /api/managed/history`: `{"entries"}`, the newest 200 lines of the history (see `history`); 503 when it
//!   cannot be read.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use http::{Method, StatusCode};
use serde_json::{Value, json};

use super::history::rollback_target;
use super::job::Slot;
use crate::admin::audit::AuditLog;
use crate::admin::auth::{Cx, Who};
use crate::admin::server::{Answer, Gate, Handler, Req, Route};
use crate::admin::store::AdminStore;
use crate::admin::users::Role;
use crate::admin::waf::control::Control;
use crate::config::{self, AdminConfig, Built, MainFile};
use crate::log::Log;
use crate::managed::{ManagedError, Store};
use crate::rules::bundle::{Fingerprint, hex};

/// The most bytes of the body of the saving and of the check: the JSON of a version and its files.
const APPLY_BODY_MAX: usize = 12 << 20;
const APPLY: &str = "/api/managed/apply";
const CHECK: &str = "/api/managed/check";
/// The path of one version in a request; in the table it is `/api/managed/versions/*`.
pub(super) const VERSION: &str = "/api/managed/versions/";
/// The path of the certificates of one version in a request; in the table it is `/api/managed/certificates/*`.
pub(super) const CERTIFICATES: &str = "/api/managed/certificates/";

/// What a route of the managed configuration does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    State,
    Versions,
    Version,
    Apply,
    Activate,
    Rollback,
    Job,
    History,
    Check,
    Config,
    Remove,
    Certificates,
}

impl Op {
    /// The action that the audit log calls the operation.
    pub const fn action(self) -> &'static str {
        match self {
            Op::State => "managed",
            Op::Versions => "managed-versions",
            Op::Version => "managed-version",
            Op::Apply => "managed-apply",
            Op::Activate => "managed-activate",
            Op::Rollback => "managed-rollback",
            Op::Job => "managed-job",
            Op::History => "managed-history",
            Op::Check => "managed-check",
            Op::Config => "config",
            Op::Remove => "managed-remove",
            Op::Certificates => "managed-certificates",
        }
    }
}

const fn route(method: Method, path: &'static str, least: Role, op: Op) -> Route {
    Route {
        method,
        path,
        handler: Handler::Managed(op),
        least: Some(least),
        gate: Gate::Open,
        token: true,
        action: op.action(),
    }
}

/// The routes of the managed configuration. A `*` at the end of a path stands for the name of a version.
pub(in crate::admin) static ROUTES: [Route; 12] = [
    route(Method::GET, "/api/managed", Role::Viewer, Op::State),
    route(
        Method::GET,
        "/api/managed/versions",
        Role::Viewer,
        Op::Versions,
    ),
    route(
        Method::GET,
        "/api/managed/versions/*",
        Role::Operator,
        Op::Version,
    ),
    route(Method::POST, APPLY, Role::Operator, Op::Apply),
    route(
        Method::POST,
        "/api/managed/activate",
        Role::Operator,
        Op::Activate,
    ),
    route(
        Method::POST,
        "/api/managed/rollback",
        Role::Operator,
        Op::Rollback,
    ),
    route(Method::GET, "/api/managed/job", Role::Viewer, Op::Job),
    route(
        Method::GET,
        "/api/managed/history",
        Role::Viewer,
        Op::History,
    ),
    route(Method::POST, CHECK, Role::Operator, Op::Check),
    route(Method::GET, "/api/config", Role::Operator, Op::Config),
    route(
        Method::DELETE,
        "/api/managed/versions/*",
        Role::Operator,
        Op::Remove,
    ),
    route(
        Method::GET,
        "/api/managed/certificates/*",
        Role::Operator,
        Op::Certificates,
    ),
];

/// The most bytes of a body, for a request whose body may be longer than the usual limit.
pub(in crate::admin) fn body_limit(method: &Method, path: &str) -> Option<usize> {
    (*method == Method::POST && (path == APPLY || path == CHECK)).then_some(APPLY_BODY_MAX)
}

/// The version that `path`, a path below `prefix` (`VERSION` or `CERTIFICATES`), names.
pub(super) fn name_of(path: &str, prefix: &str) -> Option<[u8; 32]> {
    Fingerprint::from_hex(path.strip_prefix(prefix)?.as_bytes()).map(|name| name.bytes())
}

pub(super) fn not_found() -> Answer {
    Answer::error(StatusCode::NOT_FOUND, "not found")
}

pub(super) fn conflict(words: &'static str) -> Answer {
    Answer::error(StatusCode::CONFLICT, words)
}

/// The main file had no `managed` when the process started, or has none now.
const UNMANAGED: &str = "the configuration has no managed object";

pub(super) fn unmanaged() -> Answer {
    conflict(UNMANAGED)
}

/// The managed store cannot be opened or read.
pub(super) fn failed(e: ManagedError) -> Answer {
    Answer::error(StatusCode::INTERNAL_SERVER_ERROR, e.0)
}

/// A right that one holder at a time has in this process: to change the managed configuration (`Managed::seat`), or to
/// check a version (`Managed::check_seat`). It is given back when it is dropped: at the end of the change or of the
/// check, or when it ends in a panic.
pub(super) struct Seat(Arc<AtomicBool>);

impl Drop for Seat {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// The routes of the managed configuration.
pub struct Managed {
    /// The main file, which a change, a check and the route of its values read again.
    pub(super) config: PathBuf,
    /// The directory of the managed store that the main file named when the process started; none: it had no
    /// `managed`.
    pub(super) dir: Option<PathBuf>,
    pub(super) control: Arc<Control>,
    /// The admin store, which keeps the history.
    pub(super) admin: Arc<dyn AdminStore>,
    pub(super) audit: Arc<AuditLog>,
    /// The records of the process, for a job that panics.
    pub(super) log: Log,
    /// A change holds it (see `Seat`).
    seat: Arc<AtomicBool>,
    /// The check of a version holds it, for the saving and for the check (see `Seat`).
    checking: Arc<AtomicBool>,
    /// The last job.
    pub(super) job: Slot,
    /// The process is stopping: no change starts.
    stopping: AtomicBool,
}

impl Managed {
    /// The routes for the main file `config`, which named the managed store `dir` when the process started, with the
    /// control socket `control` of a proxy whose kernel may take `ready_wait` to be ready, the admin store `admin` (for
    /// the history), the audit log `audit` and the records `log`.
    pub fn new(
        config: &Path,
        dir: Option<&Path>,
        control: &Path,
        ready_wait: Duration,
        admin: Arc<dyn AdminStore>,
        audit: Arc<AuditLog>,
        log: Log,
    ) -> Managed {
        Managed {
            config: config.to_path_buf(),
            dir: dir.map(Path::to_path_buf),
            control: Arc::new(Control::new(control, ready_wait)),
            admin,
            audit,
            log,
            seat: Arc::new(AtomicBool::new(false)),
            checking: Arc::new(AtomicBool::new(false)),
            job: Arc::new(Mutex::new(None)),
            stopping: AtomicBool::new(false),
        }
    }

    /// The routes of the main file at `path`, read as `loaded` when the process started, whose `admin` object is
    /// `admin`.
    pub fn from_config(
        path: &Path,
        loaded: &MainFile,
        admin: &AdminConfig,
        store: Arc<dyn AdminStore>,
        audit: Arc<AuditLog>,
        log: Log,
    ) -> Managed {
        Managed::new(
            path,
            loaded.managed.as_ref().map(|managed| managed.dir.as_path()),
            &admin.control,
            loaded.proxy.ready_wait,
            store,
            audit,
            log,
        )
    }

    /// Tells that the process is stopping, so that no change starts.
    pub fn interrupt(&self) {
        self.stopping.store(true, Ordering::SeqCst);
    }

    /// Whether the process is stopping.
    pub(super) fn stopping(&self) -> bool {
        self.stopping.load(Ordering::SeqCst)
    }

    /// Answers a request of the route `op`, for the user `who`. It reads and writes files and asks the proxy.
    pub fn handle(&self, op: Op, req: &Req, who: &Who, cx: &Cx<'_>) -> Answer {
        // The time of the answer is counted from here, for a change that starts a job.
        let began = Instant::now();
        match op {
            Op::State => self.state(),
            Op::Versions => self.versions(),
            Op::Version => self.version(&req.path),
            Op::Apply => self.apply(req, who, cx, began),
            Op::Activate => self.activate(req, who, cx, began),
            Op::Rollback => self.rollback(req, who, cx, began),
            Op::Job => self.job(),
            Op::History => self.history(),
            Op::Check => self.check(req),
            Op::Config => self.values(),
            Op::Remove => self.remove(&req.path, who, cx),
            Op::Certificates => self.certificates(&req.path),
        }
    }

    /// The right to change: a process that stops gives none (503), and a change under way holds it (409).
    pub(super) fn seat(&self) -> Result<Seat, Answer> {
        if self.stopping() {
            return Err(Answer::unavailable());
        }
        match self
            .seat
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => Ok(Seat(self.seat.clone())),
            Err(_) => Err(conflict(
                "a change of the managed configuration is under way",
            )),
        }
    }

    /// The right to check a version, which the saving and the check take before they read their body: the reading
    /// again of a large body and of the files of the store holds much memory, so one check runs at a time (503 while
    /// another one does).
    pub(super) fn check_seat(&self) -> Result<Seat, Answer> {
        match self
            .checking
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => Ok(Seat(self.checking.clone())),
            Err(_) => Err(Answer::error(
                StatusCode::SERVICE_UNAVAILABLE,
                "a check of a managed version is under way",
            )),
        }
    }

    /// The main file, read again for a change or a check. It must have `managed`, with the directory `dir` that it
    /// named when the process started: another store is not opened. The refusal is the word of the audit log and the
    /// sentence of the answer, which is 409.
    pub(super) fn main_file(&self, dir: &Path) -> Result<Built, (&'static str, &'static str)> {
        let built = config::read(&self.config)
            .and_then(|bytes| config::main_file(&bytes))
            .map_err(|e| ("configuration", e.0))?;
        match &built.main.managed {
            Some(managed) if managed.dir == dir => Ok(built),
            Some(_) => Err((
                "managed",
                "the managed object of the configuration names another directory than at the start",
            )),
            None => Err(("managed", UNMANAGED)),
        }
    }

    /// The managed store of the start; 409 for a main file that had no `managed`, 500 for a store that cannot be
    /// opened.
    pub(super) fn store(&self) -> Result<Store, Answer> {
        let dir = self.dir.as_deref().ok_or_else(unmanaged)?;
        Store::open(dir).map_err(failed)
    }

    fn state(&self) -> Answer {
        if self.dir.is_none() {
            return Answer::json(StatusCode::OK, json!({"managed": false}));
        }
        let store = match self.store() {
            Ok(store) => store,
            Err(answer) => return answer,
        };
        let (current, list) = match (store.current(), store.versions()) {
            (Ok(current), Ok(list)) => (current, list),
            (Err(e), _) | (_, Err(e)) => return failed(e),
        };
        let lines = match self.lines() {
            Ok(lines) => lines,
            Err(answer) => return answer,
        };
        let rollback_to = current
            .and_then(|chosen| rollback_target(&lines, chosen).ok())
            .filter(|target| list.iter().any(|listed| listed.name == *target));
        let seen = self.control.status();
        let state = seen.state();
        Answer::json(
            StatusCode::OK,
            json!({
                "managed": true,
                "current": current.map(|name| hex(&name)),
                "serving": state.and_then(|status| status.managed).map(|name| hex(&name)),
                "reachable": seen.reachable(),
                "reloading": state.and_then(|status| status.reloading),
                "rollback_to": rollback_to.map(|name| hex(&name)),
                "job": self.last_job(),
            }),
        )
    }

    /// The last job as the API shows it, `null` for none.
    fn last_job(&self) -> Value {
        let place = self.job.lock().unwrap_or_else(PoisonError::into_inner);
        place.as_ref().map_or(Value::Null, |job| job.json())
    }

    fn job(&self) -> Answer {
        if self.dir.is_none() {
            return unmanaged();
        }
        Answer::json(StatusCode::OK, json!({"job": self.last_job()}))
    }

    fn versions(&self) -> Answer {
        let store = match self.store() {
            Ok(store) => store,
            Err(answer) => return answer,
        };
        let (list, current) = match (store.versions(), store.current()) {
            (Ok(list), Ok(current)) => (list, current),
            (Err(e), _) | (_, Err(e)) => return failed(e),
        };
        let seen = self.control.status();
        let serving = seen.state().and_then(|status| status.managed);
        let items: Vec<Value> = list
            .iter()
            .rev()
            .map(|listed| {
                json!({
                    "name": hex(&listed.name),
                    "made": listed.made,
                    "current": current == Some(listed.name),
                    "serving": serving == Some(listed.name),
                })
            })
            .collect();
        Answer::json(
            StatusCode::OK,
            json!({"reachable": seen.reachable(), "versions": items}),
        )
    }

    fn version(&self, path: &str) -> Answer {
        let store = match self.store() {
            Ok(store) => store,
            Err(answer) => return answer,
        };
        let Some(name) = name_of(path, VERSION) else {
            return not_found();
        };
        let (list, current) = match (store.versions(), store.current()) {
            (Ok(list), Ok(current)) => (list, current),
            (Err(e), _) | (_, Err(e)) => return failed(e),
        };
        let Some(listed) = list.iter().find(|listed| listed.name == name) else {
            return not_found();
        };
        let version: Value = match store.version(name) {
            Ok(bytes) => match serde_json::from_slice(&bytes) {
                Ok(version) => version,
                Err(_) => {
                    return Answer::error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "the managed version is not JSON",
                    );
                }
            },
            Err(e) => return failed(e),
        };
        let serving = self
            .control
            .status()
            .state()
            .and_then(|status| status.managed);
        Answer::json(
            StatusCode::OK,
            json!({
                "name": hex(&name),
                "made": listed.made,
                "current": current == Some(name),
                "serving": serving == Some(name),
                "version": version,
            }),
        )
    }
}

#[cfg(test)]
pub(super) mod tests;
