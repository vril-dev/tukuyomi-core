//! A change of the managed configuration and its job. A change puts a version in force in the running proxy (see
//! `managed::apply`), which may take longer than an answer may: so a request that passes its checks is answered at
//! once (202), and the order runs on a thread of its own, the job, whose end the client reads later.
//!
//! The changes: `POST /api/managed/apply` saves a version and puts it in force (see `import`); `POST
//! /api/managed/activate` with `{"expect", "version"}` puts a version of the store in force by its name; `POST
//! /api/managed/rollback` with `{"expect"}` puts the target of a rollback in force (see `history`; none, or one that is
//! not in the store, is 409). `expect` is the version that the client saw chosen, and `version` a name, each 64
//! lowercase hexadecimal digits (else 400). The steps before the job, and the first that refuses answers:
//! 1. The right to change (`routes::Seat`): one change at a time in this process, its job included, so another one
//!    under way is 409, and a process that stops is 503. Not audited.
//! 2. The main file, read again: one without `managed` (or that had none when the process started), or whose
//!    `managed.dir` is not the directory of the start, is 409, and no other store is opened; so is one that is
//!    refused, with its sentence. Audited as denied (`managed`, `configuration`).
//! 3. The store: one that cannot be opened, or whose record of the chosen version cannot be read, is 500; a chosen
//!    version that is not `expect` (or none) is 409, audited as denied (`expect`). For `rollback`, its target is found
//!    now, from the history (none is 409, a history that cannot be read 503, neither audited); the lines of the audit
//!    log before have no target.
//! 4. The proxy, by its control socket: one that cannot be reached is 503 and has a line of the history
//!    (`unreachable`), one that has no place for the question is 503, one whose configuration in force has no
//!    `managed` 409; each audited as denied (`unreachable`, `busy`, `unmanaged`).
//! 5. For `activate` and `rollback`, the version is in the store (else 404 and 409); `apply` saves it here.
//! 6. The job starts, unless the time of the answer (30 s) is nearly over (5 s or less left), or the process began to
//!    stop since step 1: then 503, audited as failed (`time`, `stopping`), and what was saved stays. A thread that
//!    cannot be started is 503, audited as failed (`thread`).
//!
//! The answer is 202 with `version`, the name of the version to put in force, and `job`. A job is one thread, which is
//! not joined: it holds the right to change until it ends, and gives it back when it ends in a panic as well. It holds
//! copies of what it needs of the request (the name of the user, its session or its token, the number of the request
//! and the client), not the request. It runs the order with `from` the version of `expect`, `to` the version asked
//! for, and the time of the lookup of the names of the main file that was read for the request. Before anything is
//! changed, the order lets the job write the line of the audit log of the change (`managed-apply`, `managed-activate`
//! or `managed-rollback`, with `from` and `to`; the SHA-256 of the main file is in the history, not in the audit log);
//! a line that cannot be written ends the job as `audit`, with nothing changed. How a job ends, in the audit log and
//! the history:
//! - before that line (`busy`, `current changed`, `no version`, `unmanaged`, `store`, `unreachable`): denied, with the
//!   result as the reason; only `unreachable` has a line of the history;
//! - `applied`: the line written before is the one of the audit log; the history has a line;
//! - after that line (`refused`, `busy`, `error`, `failed`, `unconfirmed`, `not recorded`): failed, with the result as
//!   the reason; the history has a line with the result and its reason;
//! - a line of the history that cannot be written: failed, with the reason `history`.
//!
//! Only the last job is kept, and in memory only: it is gone when the process stops. A job that runs then ends with
//! it, and the lock of the store goes with the process. The job is `{"kind", "actor", "from", "to", "started", "ended",
//! "state", "result", "reason", "detail", "config_before", "config_after", "history"}`: `started` and `ended` are
//! seconds since the epoch, `state` is `running` or `ended`, and while it runs `ended`, `result` and `history` are
//! `null`. `result` is the end of the order (`applied`, `refused`, `busy`, `current changed`, `no version`, `unmanaged`,
//! `store`, `audit`, `error`, `unreachable`, `failed`, `unconfirmed`, `not recorded`); `reason` its fixed word (the
//! part of the proxy that refused, the reason of `busy` or `error`, `current changed` or `store` for `not recorded`);
//! `detail` the sentence of the proxy that refused, or of the store; `config_before` and `config_after` the SHA-256 of
//! the main file in force before and after the order, when they are known; and `history` whether the history took
//! its line (`null` when the end has none). A job that panics ends as `unconfirmed`, and the process writes a line to
//! its records. A job cannot be stopped, and a change of the role of its user does not stop it.

use std::cell::Cell;
use std::net::IpAddr;
use std::panic::{self, AssertUnwindSafe};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};

use super::history::{self, Kind, rollback_target};
use super::routes::{Managed, Seat, conflict, failed, not_found, unmanaged};
use crate::admin::audit::{AuditLog, Event, Outcome};
use crate::admin::auth::{Cx, Who};
use crate::admin::server::{ANSWER_WAIT, Answer, Req, json_body};
use crate::admin::store::AdminStore;
use crate::admin::users::now_ms;
use crate::admin::waf::control::{Control, Seen};
use crate::config::{Built, Routing};
use crate::log::Log;
use crate::managed::apply::{self, Unrecorded};
use crate::managed::store::NOT_CURRENT;
use crate::managed::{ManagedError, Store};
use crate::rules::bundle::{Fingerprint, hex};

/// What is left of the time of an answer when a job is no longer started.
const SPARE: Duration = Duration::from_secs(5);

/// Who asked for a change: the copies of what the audit log and the history need of the request.
#[derive(Clone)]
pub(super) struct Caller {
    name: String,
    /// How a request with a token got in, as the audit log shows it; none for a session.
    auth: Option<String>,
    handle: String,
    id: String,
    client: IpAddr,
}

impl Caller {
    pub(super) fn of(who: &Who, cx: &Cx<'_>) -> Caller {
        Caller {
            name: who.name.clone(),
            auth: who.auth.clone(),
            handle: who.handle.clone(),
            id: cx.id.to_owned(),
            client: cx.client,
        }
    }

    pub(super) fn name(&self) -> &str {
        &self.name
    }

    /// An event of the request, as `Who::event` makes it.
    pub(super) fn event(&self, action: &'static str, outcome: Outcome) -> Event<'_> {
        let event = Event::new(&self.id, self.client, action, outcome).actor(&self.name);
        match &self.auth {
            Some(auth) => event.auth(auth),
            None => event.session(&self.handle),
        }
    }
}

/// How a job ended.
#[derive(Clone, Debug)]
struct End {
    /// Seconds since the epoch.
    at: u64,
    result: &'static str,
    reason: Option<&'static str>,
    detail: Option<String>,
    config_before: Option<[u8; 32]>,
    config_after: Option<[u8; 32]>,
    /// Whether the history took the line; none for an end that has no line.
    history: Option<bool>,
}

/// The last job, as the API shows it.
#[derive(Clone, Debug)]
pub(super) struct Job {
    kind: Kind,
    actor: String,
    from: [u8; 32],
    to: [u8; 32],
    started: u64,
    end: Option<End>,
}

impl Job {
    pub(super) fn json(&self) -> Value {
        let end = self.end.as_ref();
        json!({
            "kind": self.kind.word(),
            "actor": self.actor,
            "from": hex(&self.from),
            "to": hex(&self.to),
            "started": self.started,
            "ended": end.map(|end| end.at),
            "state": if end.is_some() { "ended" } else { "running" },
            "result": end.map(|end| end.result),
            "reason": end.and_then(|end| end.reason),
            "detail": end.and_then(|end| end.detail.as_deref()),
            "config_before": end.and_then(|end| end.config_before).map(|name| hex(&name)),
            "config_after": end.and_then(|end| end.config_after).map(|name| hex(&name)),
            "history": end.and_then(|end| end.history),
        })
    }
}

/// The place of the last job, which a job that ends writes its end to.
pub(super) type Slot = Arc<Mutex<Option<Job>>>;

/// What a change has once the steps before its job passed: the right to change, the main file that was read for it,
/// the time of the lookup of its names, and the managed store.
pub(super) struct Ready {
    pub(super) seat: Seat,
    pub(super) built: Built,
    pub(super) resolve_timeout: Duration,
    pub(super) store: Store,
    /// The version to put in force.
    pub(super) to: [u8; 32],
}

/// The version a change puts in force.
#[derive(Clone, Copy)]
pub(super) enum Target {
    /// The version of this name.
    Named([u8; 32]),
    /// The target of a rollback, found once the store is known to choose `expect` (see `history`).
    Back,
}

/// A change that is to run as a job.
pub(super) struct Order {
    pub(super) kind: Kind,
    pub(super) caller: Caller,
    pub(super) from: [u8; 32],
    pub(super) to: [u8; 32],
    pub(super) resolve_timeout: Duration,
    pub(super) store: Store,
}

/// What the thread of a job works with, besides its order.
struct Parts {
    control: Arc<Control>,
    audit: Arc<AuditLog>,
    admin: Arc<dyn AdminStore>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivateBody {
    expect: String,
    version: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RollbackBody {
    expect: String,
}

/// A version of a request: 64 lowercase hexadecimal digits.
pub(super) fn version_of(text: &str) -> Result<[u8; 32], Answer> {
    Fingerprint::from_hex(text.as_bytes())
        .map(|name| name.bytes())
        .ok_or_else(|| {
            Answer::error(
                StatusCode::BAD_REQUEST,
                "a version is not 64 lowercase hexadecimal digits",
            )
        })
}

impl Managed {
    /// Steps 1 to 4 (see the module documentation) of a change of `kind` from `expect` to the version of `target`, for
    /// `caller`; a refusal is audited under the action of `kind`, with the version as the target once it is known. The
    /// target of a rollback is found after step 3: none is 409, a history that cannot be read 503, neither audited.
    pub(super) fn ready(
        &self,
        kind: Kind,
        caller: &Caller,
        expect: [u8; 32],
        target: Target,
    ) -> Result<Ready, Answer> {
        let known = match target {
            Target::Named(to) => Some(hex(&to)),
            Target::Back => None,
        };
        let deny_to = |to: Option<&str>, reason: &'static str| {
            let event = caller.event(kind.action(), Outcome::Denied);
            let event = match to {
                Some(to) => event.target(to),
                None => event,
            };
            let _ = self.audit.write(&event.reason(reason));
        };
        let deny = |reason: &'static str| deny_to(known.as_deref(), reason);
        let Some(dir) = self.dir.as_deref() else {
            deny("managed");
            return Err(unmanaged());
        };
        let seat = self.seat()?;
        let built = self.main_file(dir).map_err(|(reason, words)| {
            deny(reason);
            conflict(words)
        })?;
        let Routing::Managed { resolve_timeout } = built.routing else {
            // `main_file` gives only a file with `managed`, whose routing this is.
            return Err(unmanaged());
        };
        let store = Store::open(dir).map_err(failed)?;
        match store.current() {
            Ok(Some(current)) if current == expect => {}
            Ok(_) => {
                deny("expect");
                return Err(conflict(NOT_CURRENT.0));
            }
            Err(e) => return Err(failed(e)),
        }
        let to = match target {
            Target::Named(to) => to,
            Target::Back => {
                let lines = self.lines()?;
                rollback_target(&lines, expect).map_err(conflict)?
            }
        };
        let deny = |reason: &'static str| deny_to(Some(&hex(&to)), reason);
        match self.control.status() {
            Seen::State(status) if status.managed.is_some() => {}
            Seen::State(_) => {
                deny("unmanaged");
                return Err(conflict("the configuration in force has no managed object"));
            }
            Seen::Busy => {
                deny("busy");
                return Err(Answer::error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "the proxy is busy",
                ));
            }
            Seen::Unreachable => {
                deny("unreachable");
                let line = history::line(
                    caller,
                    kind,
                    (expect, to),
                    ("unreachable", None),
                    (None, None),
                );
                history::record(self.admin.as_ref(), &self.audit, caller, &line);
                return Err(Answer::error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "the proxy cannot be reached",
                ));
            }
        }
        Ok(Ready {
            seat,
            built,
            resolve_timeout,
            store,
            to,
        })
    }

    pub(super) fn activate(&self, req: &Req, who: &Who, cx: &Cx<'_>, began: Instant) -> Answer {
        let body: ActivateBody = match json_body(req) {
            Ok(body) => body,
            Err(answer) => return answer,
        };
        let (expect, to) = match (version_of(&body.expect), version_of(&body.version)) {
            (Ok(expect), Ok(to)) => (expect, to),
            (Err(answer), _) | (_, Err(answer)) => return answer,
        };
        let caller = Caller::of(who, cx);
        self.put_in_force(Kind::Activate, caller, expect, Target::Named(to), began)
    }

    pub(super) fn rollback(&self, req: &Req, who: &Who, cx: &Cx<'_>, began: Instant) -> Answer {
        let body: RollbackBody = match json_body(req) {
            Ok(body) => body,
            Err(answer) => return answer,
        };
        let expect = match version_of(&body.expect) {
            Ok(expect) => expect,
            Err(answer) => return answer,
        };
        let caller = Caller::of(who, cx);
        self.put_in_force(Kind::Rollback, caller, expect, Target::Back, began)
    }

    /// A change of `kind` that puts the version of `target`, a version of the store, in force.
    fn put_in_force(
        &self,
        kind: Kind,
        caller: Caller,
        expect: [u8; 32],
        target: Target,
        began: Instant,
    ) -> Answer {
        let ready = match self.ready(kind, &caller, expect, target) {
            Ok(ready) => ready,
            Err(answer) => return answer,
        };
        let to = ready.to;
        match ready.store.versions() {
            Ok(listed) if listed.iter().any(|version| version.name == to) => {}
            Ok(_) if kind == Kind::Rollback => {
                return conflict("the version to go back to is not in the store");
            }
            Ok(_) => return not_found(),
            Err(e) => return failed(e),
        }
        let order = Order {
            kind,
            caller,
            from: expect,
            to,
            resolve_timeout: ready.resolve_timeout,
            store: ready.store,
        };
        self.start(ready.seat, order, began, json!({"version": hex(&to)}))
    }

    /// Starts the job of `order`, which holds `seat` to its end (step 6 of the module documentation). `answer` is the
    /// body of the answer, which gets the job.
    pub(super) fn start(
        &self,
        seat: Seat,
        order: Order,
        began: Instant,
        mut answer: Value,
    ) -> Answer {
        let (target, action, caller) = (hex(&order.to), order.kind.action(), order.caller.clone());
        let fail = |reason: &'static str| {
            let event = caller.event(action, Outcome::Failed);
            let _ = self.audit.write(&event.target(&target).reason(reason));
        };
        if began.elapsed() >= ANSWER_WAIT.saturating_sub(SPARE) {
            fail("time");
            return Answer::error(
                StatusCode::SERVICE_UNAVAILABLE,
                "the change was not started, for the time of the answer is nearly over",
            );
        }
        // The process may have begun to stop since the right to change was taken.
        if self.stopping() {
            fail("stopping");
            return Answer::unavailable();
        }
        let job = Job {
            kind: order.kind,
            actor: order.caller.name.clone(),
            from: order.from,
            to: order.to,
            started: now_ms() / 1000,
            end: None,
        };
        let parts = Parts {
            control: self.control.clone(),
            audit: self.audit.clone(),
            admin: self.admin.clone(),
        };
        let (slot, log) = (self.job.clone(), self.log.clone());
        // The place is held until the job is in it, so that the thread cannot end before and find another.
        let mut place = slot.lock().unwrap_or_else(PoisonError::into_inner);
        let thread_slot = slot.clone();
        let spawned = thread::Builder::new()
            .name("managed-job".into())
            .spawn(move || run(seat, order, &parts, &thread_slot, &log));
        match spawned {
            Ok(_) => {
                answer["job"] = job.json();
                *place = Some(job);
                Answer::json(StatusCode::ACCEPTED, answer)
            }
            Err(_) => {
                drop(place);
                fail("thread");
                Answer::error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "the job of the change cannot be started",
                )
            }
        }
    }
}

/// The thread of a job: runs the order, writes how it ended, and gives back the right to change.
fn run(seat: Seat, order: Order, parts: &Parts, slot: &Slot, log: &Log) {
    let end = panic::catch_unwind(AssertUnwindSafe(|| ended(&order, parts))).unwrap_or_else(|_| {
        log.line("admin: a job of the managed configuration panicked");
        End {
            at: now_ms() / 1000,
            result: "unconfirmed",
            reason: None,
            detail: None,
            config_before: None,
            config_after: None,
            history: None,
        }
    });
    let mut place = slot.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(job) = place.as_mut() {
        job.end = Some(end);
    }
    // Given back while the end is written, so that a client that reads the end finds the right to change free.
    drop(seat);
    drop(place);
}

/// Runs the order and writes how it ended to the audit log and the history.
fn ended(order: &Order, parts: &Parts) -> End {
    let (from, to) = (hex(&order.from), hex(&order.to));
    let action = order.kind.action();
    // The SHA-256 of the main file in force when the order was checked: set once the line before the change is due.
    let checked: Cell<Option<Option<[u8; 32]>>> = Cell::new(None);
    let outcome = apply::apply(
        &order.store,
        parts.control.as_ref(),
        order.from,
        order.to,
        order.resolve_timeout,
        |state| {
            checked.set(Some(state.config));
            let event = order.caller.event(action, Outcome::Ok);
            parts
                .audit
                .write(&event.target(&to).change(&from, &to))
                .map_err(|_| ())
        },
    );
    let (result, reason, detail) = words(&outcome);
    let (config_before, config_after) = match &outcome {
        apply::Outcome::Applied { before, after }
        | apply::Outcome::NotRecorded { before, after, .. } => (*before, *after),
        _ => (checked.get().flatten(), None),
    };
    let note = |outcome: Outcome| {
        let event = order.caller.event(action, outcome);
        let _ = parts.audit.write(&event.target(&to).reason(result));
    };
    let lined = match (&outcome, checked.get()) {
        (apply::Outcome::Before(()), _) => false,
        (apply::Outcome::Applied { .. }, _) => true,
        (apply::Outcome::Unreachable, None) => {
            note(Outcome::Denied);
            true
        }
        (_, None) => {
            note(Outcome::Denied);
            false
        }
        (_, Some(_)) => {
            note(Outcome::Failed);
            true
        }
    };
    let history = lined.then(|| {
        let line = history::line(
            &order.caller,
            order.kind,
            (order.from, order.to),
            (result, reason),
            (config_before, config_after),
        );
        history::record(parts.admin.as_ref(), &parts.audit, &order.caller, &line)
    });
    End {
        at: now_ms() / 1000,
        result,
        reason,
        detail,
        config_before,
        config_after,
        history,
    }
}

/// The result, the reason and the sentence of an end of the order.
fn words(outcome: &apply::Outcome<()>) -> (&'static str, Option<&'static str>, Option<String>) {
    use apply::Outcome as O;
    let store = |e: &ManagedError| Some(e.0.to_owned());
    match outcome {
        O::Applied { .. } => ("applied", None, None),
        O::Refused { reason, detail } => ("refused", Some(*reason), Some(detail.clone())),
        O::Busy(reason) => ("busy", Some(*reason), None),
        O::CurrentChanged => ("current changed", None, None),
        O::NoVersion => ("no version", None, None),
        O::Unmanaged => ("unmanaged", None, None),
        O::Store(e) => ("store", None, store(e)),
        O::Before(()) => ("audit", None, None),
        O::Error(reason) => ("error", Some(*reason), None),
        O::Unreachable => ("unreachable", None, None),
        O::Failed => ("failed", None, None),
        O::Unconfirmed => ("unconfirmed", None, None),
        O::NotRecorded {
            why: Unrecorded::CurrentChanged,
            ..
        } => ("not recorded", Some("current changed"), None),
        O::NotRecorded {
            why: Unrecorded::Store(e),
            ..
        } => ("not recorded", Some("store"), store(e)),
    }
}

#[cfg(test)]
mod tests;
