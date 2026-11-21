//! The routes of the rules: the generations of the rules store, the import of one with a trial, the switch of the
//! proxy to a generation and the way back, the history of the switches, and the records of the proxy. `ROUTES` says
//! which role may use each route; `server` checks the origin, the session or the token, the CSRF token of a session,
//! the state of the session and the role before `Waf::handle` runs, and writes a refusal to the audit log. A request
//! with a token may use all of these routes; the audit log shows the token (`auth`) where it shows the session.
//!
//! The parts, one file each: `control` (the control socket of the proxy), `history` (what is kept of each switch),
//! `import` (the body of an import and the trial), `records` (reading the record files), `status` (the status
//! route), `generations` (the list of the generations, one generation and the removal) and `activate` (the switch to
//! a generation and the way back).
//!
//! The routes (a viewer may use the status, the generations, the history and the records, an operator the import, the
//! switch, the rollback and the removal as well; a body is JSON of at most 64 KiB, the one of the import 12 MiB; the
//! answers are JSON, and `error` is a fixed sentence):
//! - `GET /api/status`: `{"current", "reachable", "proxy", "rollback_to", "crs"}`: the generation the rules store
//!   chooses, the state of the proxy from its control socket (`proxy` is `null` when the state could not be read, and
//!   `reachable` is false when the proxy cannot be reached; a proxy that has no place for the question is reachable;
//!   `proxy` has the `mode` and the `engine` of the generation it serves, and its figures: the time since it started,
//!   its counts and the SHA-256 of its configuration file, each `null` when an older proxy does not send it), the
//!   generation a rollback would go to now (`null` for none), and the CRS of the configuration (see `status`).
//! - `GET /api/generations`: `{"reachable", "generations"}`, the newest first, each with its `fingerprint`, `made`
//!   (seconds since the epoch), `mode`, `engine`, number of `routes`, and whether it is `current` and `serving`.
//! - `GET /api/generations/<fingerprint>`: that, and the `load` order, the `files` (path, size, SHA-256) and the
//!   `routes` of its manifest. 404 for a generation the store does not have.
//! - `POST /api/generations`: the import (see `import`): the same steps as `rules import`: the files are collected
//!   from the body, staged, tried with an inspector, and made a generation only if the trial passes. 200 with the
//!   `fingerprint`, `result` (`created`, `existing` or `repaired`) and the `trial`; 400 for input that is refused; 422
//!   when the trial fails; 409 when the rules store refuses or is in use. The generation is not chosen.
//! - `POST /api/activate` with `{"generation", "expect"}` and `POST /api/rollback` with `{"expect"}`: see below.
//! - `DELETE /api/generations/<fingerprint>`: 409 for the generation the store chooses, the target of a rollback,
//!   and one that a proxy uses (the store refuses it); else it is removed.
//! - `GET /api/history`: the newest 200 requests to switch (see `history`).
//! - `GET /api/records`: the lines of the record files (see `records`), 404 when the configuration has no `records`.
//!
//! The changes of the rules store (import, activate, rollback, remove) come one at a time in this process, and
//! never wait: another one in the same process, and a command or another process that holds the lock of the rules
//! store, are 409. A change is audited before it is made (the audit log that cannot take the line makes the answer 503
//! and the change none); the refusals that come before it are audited as denied, and a change that fails after it
//! as failed. The rules store is opened for each request.
//!
//! The text of a refusal is the fixed sentence of the part that refused (the rules store, the collecting of the
//! files, the query), and the name of an input only when the request gave it; the directory of the CRS is told by its
//! last name.
//!
//! A switch (activate, rollback): the generation the rules store chooses must be `expect`, the one the client saw
//! (else 409; the store checks it again when it chooses, under its lock, so that a generation another process chose
//! in between is not overwritten: also 409), the engine of the generation to switch to must be usable here (else 409
//! with the sentence of the check, audited as denied with the reason `engine`; the store is not touched, so it never
//! chooses a generation that the proxy would refuse; a manifest that cannot be read is left to the store, which
//! refuses it when it chooses), and the proxy must be reachable (else 503, nothing is changed,
//! the history has an `unreachable` line; a proxy that has no place for the question is 503 too, with no line). Then
//! the generation is chosen (`activate_if_current` of the store, which verifies it), and the proxy is ordered to
//! switch to it by its control socket. If the proxy says the switch is under way (`busy`) its state is looked at
//! every 250 ms until it serves the generation, or has been idle twice without it, or the time the old inspector may
//! take to stop and 7 s are over; a look that finds no place in the proxy is no end of the wait. The answer and the
//! line of the history say `switched` (200), `unchanged` (200), `refused` (409), `failed` (502), `unreachable` (503)
//! or `unconfirmed` (503: the rules store was changed, and the proxy went away or did not say how the switch ended).
//! `chosen` in the answer says whether the rules store chooses the generation now: it does not when nothing was
//! changed (the proxy could not be reached first), and it does when the switch then was refused, failed or
//! unconfirmed: the store is not put back. A history line that cannot be written is told by `history` in the answer.
//! A rollback goes to the target of the history: the generation before the last switch, if that switch ended at the
//! generation the rules store chooses now; there is none, or the history ends at another generation, or the target is
//! not in the store any more: 409.
//!
//! The longest time the import, the switch and the rollback may need is `Waf::longest`; the server gives the answer
//! that time, and every other route its usual 30 s.

pub mod control;
pub mod history;
pub mod import;
pub mod records;
pub mod status;

mod activate;
mod generations;

use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::Duration;

use http::{Method, StatusCode};
use serde_json::json;

use self::control::Control;
use self::import::{Inspector, Trial};
use super::audit::{AuditLog, Event, Outcome};
use super::auth::{Cx, Who};
use super::server::{Answer, Gate, Handler, Req, Route};
use super::store::AdminStore;
use super::users::Role;
use crate::config::{AdminConfig, MainFile, ProxyConfig, Records, StoreConfig};
use crate::log::escaped;
use crate::rules::collect::CollectError;
use crate::rules::store::{self, RuleStore, StoreError};

/// The most bytes of the body of an import: JSON with the files in base64.
const IMPORT_BODY_MAX: usize = 12 << 20;
const IMPORT: &str = "/api/generations";
/// The least role that may import a generation, and so the least role whose body over the usual limit is read.
const IMPORT_LEAST: Role = Role::Operator;
/// The path of one generation in a request; in the table it is `/api/generations/*`.
const GENERATION: &str = "/api/generations/";
/// A margin on the time that something is waited for.
const SLACK: Duration = Duration::from_secs(7);
/// The most bytes of the name of an input that an answer shows.
const SUBJECT_MAX: usize = 128;

/// What a route of the rules does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Status,
    Generations,
    Generation,
    Import,
    Activate,
    Rollback,
    Remove,
    History,
    Records,
}

impl Op {
    /// The action that the audit log calls the operation.
    pub const fn action(self) -> &'static str {
        match self {
            Op::Status => "status",
            Op::Generations => "generations",
            Op::Generation => "generation",
            Op::Import => "import",
            Op::Activate => "activate",
            Op::Rollback => "rollback",
            Op::Remove => "remove",
            Op::History => "history",
            Op::Records => "records",
        }
    }
}

const fn route(method: Method, path: &'static str, least: Role, op: Op) -> Route {
    Route {
        method,
        path,
        handler: Handler::Waf(op),
        least: Some(least),
        gate: Gate::Open,
        token: true,
        action: op.action(),
    }
}

/// The routes of the rules. A `*` at the end of a path stands for the rest of the path of a request.
pub(super) static ROUTES: [Route; 9] = [
    route(Method::GET, "/api/status", Role::Viewer, Op::Status),
    route(
        Method::GET,
        "/api/generations",
        Role::Viewer,
        Op::Generations,
    ),
    route(Method::POST, "/api/generations", IMPORT_LEAST, Op::Import),
    route(
        Method::GET,
        "/api/generations/*",
        Role::Viewer,
        Op::Generation,
    ),
    route(
        Method::DELETE,
        "/api/generations/*",
        Role::Operator,
        Op::Remove,
    ),
    route(Method::POST, "/api/activate", Role::Operator, Op::Activate),
    route(Method::POST, "/api/rollback", Role::Operator, Op::Rollback),
    route(Method::GET, "/api/history", Role::Viewer, Op::History),
    route(Method::GET, "/api/records", Role::Viewer, Op::Records),
];

/// The path as the table has it: a path below `/api/generations/` is `/api/generations/*`.
pub(super) fn pattern(path: &str) -> &str {
    if path.starts_with(GENERATION) {
        "/api/generations/*"
    } else {
        path
    }
}

/// The most bytes of a body, for a request whose body may be longer than the usual limit.
pub(super) fn body_limit(method: &Method, path: &str) -> Option<usize> {
    (*method == Method::POST && path == IMPORT).then_some(IMPORT_BODY_MAX)
}

/// Whether a request is for a route that may take long: the import with its trial, and the switch and the way back,
/// which wait for the proxy. The server gives these the time of `Waf::longest`, the others its usual time.
pub(super) fn slow(method: &Method, path: &str) -> bool {
    *method == Method::POST && matches!(path, IMPORT | "/api/activate" | "/api/rollback")
}

/// How long the routes wait, from the `proxy` object of the configuration.
#[derive(Clone, Copy, Debug)]
pub struct Waits {
    /// The time the kernel of the proxy may take to be ready.
    pub ready: Duration,
    /// The time for the verdict of one request of a trial.
    pub inspect: Duration,
    /// The time an inspector has to stop.
    pub stop: Duration,
    /// The length of one step of the kernel in a trial.
    pub slice: Duration,
}

impl Waits {
    pub fn of(proxy: &ProxyConfig) -> Waits {
        Waits {
            ready: proxy.ready_wait,
            inspect: proxy.inspect_wait,
            stop: proxy.stop_inspect,
            slice: proxy.drive_slice,
        }
    }
}

/// What the routes need of the configuration.
pub struct Config<'a> {
    pub rules: &'a StoreConfig,
    /// The control socket of the proxy.
    pub control: &'a Path,
    /// The directory of the CRS, if the configuration names one.
    pub crs_dir: Option<&'a Path>,
    pub records: Option<&'a Records>,
    pub waits: Waits,
}

/// Who asked, for the audit log.
#[derive(Clone, Copy)]
struct Caller<'a> {
    who: &'a Who,
    cx: &'a Cx<'a>,
}

impl<'a> Caller<'a> {
    /// An event of the request, with the user and the session it came from.
    fn event(&self, action: &'static str, outcome: Outcome) -> Event<'a> {
        let Caller { who, cx } = *self;
        who.event(cx, action, outcome)
    }
}

fn not_found() -> Answer {
    Answer::error(StatusCode::NOT_FOUND, "not found")
}

fn conflict(words: &'static str) -> Answer {
    Answer::error(StatusCode::CONFLICT, words)
}

/// The rules store cannot be read.
fn failed(e: StoreError) -> Answer {
    Answer::error(StatusCode::INTERNAL_SERVER_ERROR, e.0)
}

/// The rules store refuses a change: it is in use, or the generation is chosen or used, or it is not sound.
fn refused(e: StoreError) -> Answer {
    conflict(e.0)
}

/// Input that is refused: the sentence, and the name of the input if there is one, every byte outside 0x20 to 0x7e as
/// `\xNN` and at most `SUBJECT_MAX` of them.
fn invalid(e: CollectError) -> Answer {
    let mut body = json!({"error": e.reason});
    if let Some(subject) = e.subject {
        let bytes = subject.as_bytes();
        body["subject"] = escaped(&bytes[..bytes.len().min(SUBJECT_MAX)]).into();
    }
    Answer::json(StatusCode::BAD_REQUEST, body)
}

/// The routes of the rules.
pub struct Waf {
    rules: StoreConfig,
    control: Control,
    crs_dir: Option<PathBuf>,
    records: Option<Records>,
    waits: Waits,
    store: Arc<dyn AdminStore>,
    audit: Arc<AuditLog>,
    trial: Box<dyn Trial>,
    /// The changes of the rules store by this process come one at a time.
    changing: Mutex<()>,
    /// The process is stopping: a trial that runs ends, as a failure.
    stopping: AtomicBool,
}

impl Waf {
    /// The routes over `store` (for the history) and `audit`, with `trial` for the import.
    pub fn new(
        config: Config<'_>,
        store: Arc<dyn AdminStore>,
        audit: Arc<AuditLog>,
        trial: Box<dyn Trial>,
    ) -> Waf {
        Waf {
            rules: config.rules.clone(),
            control: Control::new(config.control, config.waits.ready),
            crs_dir: config.crs_dir.map(Path::to_path_buf),
            records: config.records.cloned(),
            waits: config.waits,
            store,
            audit,
            trial,
            changing: Mutex::new(()),
            stopping: AtomicBool::new(false),
        }
    }

    /// Tells that the process is stopping, so that a trial that runs ends and removes what it made.
    pub fn interrupt(&self) {
        self.stopping.store(true, Ordering::SeqCst);
    }

    /// The routes of the configuration `loaded`, whose `admin` object is `admin`, with the trial of an inspector.
    pub fn from_config(
        loaded: &MainFile,
        admin: &AdminConfig,
        store: Arc<dyn AdminStore>,
        audit: Arc<AuditLog>,
    ) -> Waf {
        let waits = Waits::of(&loaded.proxy);
        let config = Config {
            rules: &loaded.store,
            control: &admin.control,
            crs_dir: admin.crs_dir.as_deref(),
            records: loaded.records.as_ref(),
            waits,
        };
        let trial = Box::new(Inspector::new(loaded.kernel.clone(), waits));
        Waf::new(config, store, audit, trial)
    }

    /// The longest a request of these routes may take: an import with a trial that runs out all its times, or a
    /// switch that is waited for twice, and a margin. The server gives the answer this time.
    pub fn longest(&self) -> Duration {
        let w = &self.waits;
        let import = w
            .ready
            .saturating_add(w.inspect.saturating_mul(3))
            .saturating_add(w.stop);
        let switch = w
            .ready
            .saturating_add(w.stop)
            .saturating_add(SLACK.saturating_mul(2));
        import.max(switch).saturating_add(SLACK)
    }

    /// Answers a request of the route `op`, for the user `who`. It reads and writes files and waits for the proxy.
    pub fn handle(&self, op: Op, req: &Req, who: &Who, cx: &Cx<'_>) -> Answer {
        let caller = Caller { who, cx };
        match op {
            Op::Status => self.status(),
            Op::Generations => self.generations(),
            Op::Generation => self.generation(&req.path),
            Op::Import => self.import(req, &caller),
            Op::Activate => self.activate(req, &caller),
            Op::Rollback => self.rollback(req, &caller),
            Op::Remove => self.remove(&req.path, &caller),
            Op::History => self.history(),
            Op::Records => self.records(&req.query),
        }
    }

    fn rules(&self) -> Result<Box<dyn RuleStore>, Answer> {
        store::open(&self.rules).map_err(failed)
    }

    /// The right to change the rules store in this process.
    fn changing(&self) -> Result<MutexGuard<'_, ()>, Answer> {
        match self.changing.try_lock() {
            Ok(guard) => Ok(guard),
            Err(TryLockError::Poisoned(poisoned)) => Ok(poisoned.into_inner()),
            Err(TryLockError::WouldBlock) => Err(conflict("a change of the rules is under way")),
        }
    }

    /// Writes a line of the audit log that no answer depends on: a refusal before a change, or a failure after it.
    fn note(
        &self,
        caller: &Caller<'_>,
        action: &'static str,
        outcome: Outcome,
        reason: &'static str,
        target: &str,
    ) {
        let _ = self
            .audit
            .write(&caller.event(action, outcome).target(target).reason(reason));
    }
}

#[cfg(test)]
mod tests;
