//! The routes that switch the proxy: `POST /api/activate` and `POST /api/rollback`, with the wait for the end of the
//! switch.

use std::thread::sleep;
use std::time::{Duration, Instant};

use http::StatusCode;
use serde::Deserialize;
use serde_json::json;

use super::control::{Reply, Seen};
use super::history::{Ended, Kind, rollback_target};
use super::{Caller, SLACK, Waf, conflict, failed, refused};
use crate::admin::audit::Outcome;
use crate::admin::server::{Answer, Req, json_body};
use crate::rules::bundle::Fingerprint;
use crate::rules::store::{NOT_EXPECTED, RuleStore};

/// The time between two looks at the proxy while a switch is under way.
const POLL: Duration = Duration::from_millis(250);
/// The looks in a row at a proxy that is idle and does not serve the generation, after which the switch is lost.
const IDLE_LOOKS: u32 = 2;

fn digits(text: &str) -> Result<Fingerprint, Answer> {
    Fingerprint::from_hex(text.as_bytes()).ok_or_else(|| {
        Answer::error(
            StatusCode::BAD_REQUEST,
            "a generation is not 64 lowercase hexadecimal digits",
        )
    })
}

/// The answer to a request to switch. `ids` are the generation before and the one asked for; `chosen`: the rules
/// store chooses the latter now; `written`: the history has the line.
fn reply(ended: Ended, ids: (Fingerprint, Fingerprint), chosen: bool, written: bool) -> Answer {
    let (status, error) = match ended {
        Ended::Switched | Ended::Unchanged => (StatusCode::OK, None),
        Ended::Refused => (StatusCode::CONFLICT, Some("the proxy refused the switch")),
        Ended::Failed => (StatusCode::BAD_GATEWAY, Some("the proxy did not switch")),
        Ended::Unreachable => (
            StatusCode::SERVICE_UNAVAILABLE,
            Some("the proxy cannot be reached"),
        ),
        Ended::Unconfirmed => (
            StatusCode::SERVICE_UNAVAILABLE,
            Some("the proxy did not say how the switch ended"),
        ),
    };
    let mut body = json!({
        "result": ended.word(),
        "from": ids.0.hex(),
        "generation": ids.1.hex(),
        "chosen": chosen,
    });
    if let Some(error) = error {
        body["error"] = error.into();
    }
    unwritten(Answer::json(status, body), written)
}

/// The answer, with `history` saying so when the history does not have the line of the request.
fn unwritten(mut answer: Answer, written: bool) -> Answer {
    if !written {
        answer.body["history"] = "not written".into();
    }
    answer
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivateBody {
    generation: String,
    expect: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RollbackBody {
    expect: String,
}

impl Waf {
    pub(super) fn activate(&self, req: &Req, caller: &Caller<'_>) -> Answer {
        let body: ActivateBody = match json_body(req) {
            Ok(body) => body,
            Err(answer) => return answer,
        };
        match (digits(&body.generation), digits(&body.expect)) {
            (Ok(to), Ok(expect)) => self.switch_to(caller, Kind::Activate, Some(to), expect),
            (Err(answer), _) | (_, Err(answer)) => answer,
        }
    }

    pub(super) fn rollback(&self, req: &Req, caller: &Caller<'_>) -> Answer {
        let body: RollbackBody = match json_body(req) {
            Ok(body) => body,
            Err(answer) => return answer,
        };
        match digits(&body.expect) {
            Ok(expect) => self.switch_to(caller, Kind::Rollback, None, expect),
            Err(answer) => answer,
        }
    }

    /// The generation a request to switch is for, which the store must have: `asked`, or for a rollback the target
    /// of the history when the store chooses `chosen`.
    fn target(
        &self,
        store: &dyn RuleStore,
        kind: Kind,
        asked: Option<Fingerprint>,
        chosen: Fingerprint,
    ) -> Result<Fingerprint, Answer> {
        let to = match asked {
            Some(to) => to,
            None => rollback_target(&self.lines()?, chosen).map_err(conflict)?,
        };
        if store
            .list()
            .map_err(failed)?
            .iter()
            .any(|g| g.fingerprint == to)
        {
            return Ok(to);
        }
        Err(match kind {
            Kind::Activate => Answer::error(StatusCode::NOT_FOUND, "no such generation"),
            Kind::Rollback => conflict("the generation to go back to is not in the store"),
        })
    }

    /// A request to switch to `asked` (for a rollback: to the target of the history) when the rules store chooses
    /// `expect`. See the module documentation for the steps.
    fn switch_to(
        &self,
        caller: &Caller<'_>,
        kind: Kind,
        asked: Option<Fingerprint>,
        expect: Fingerprint,
    ) -> Answer {
        let action = kind.word();
        let _changing = match self.changing() {
            Ok(guard) => guard,
            Err(answer) => return answer,
        };
        let mut store = match self.rules() {
            Ok(store) => store,
            Err(answer) => return answer,
        };
        let to = match self.target(store.as_ref(), kind, asked, expect) {
            Ok(to) => to,
            Err(answer) => return answer,
        };
        let to_hex = to.hex();
        // Nothing is changed unless the rules store chooses what the client saw and the proxy can be asked. The
        // generation before is the one the store gave, which is `expect`.
        let from = match store.current() {
            Ok(Some(current)) if current == expect => current,
            Ok(_) => {
                self.note(caller, action, Outcome::Denied, "expect", &to_hex);
                return refused(NOT_EXPECTED);
            }
            Err(e) => return failed(e),
        };
        let (ids, from_hex) = ((from, to), from.hex());
        // Before the proxy is asked and before the store chooses: a generation whose engine cannot be used here
        // would be refused by the proxy, and left as the chosen one it would end the next start. A manifest that
        // cannot be read is not answered here: the store refuses it when it chooses, and that answer stands.
        if let Ok(engine) = store.engine(to)
            && let Err(text) = self.trial.usable(engine)
        {
            self.note(caller, action, Outcome::Denied, "engine", &to_hex);
            return conflict(text);
        }
        match self.control.status() {
            Seen::State(_) => {}
            Seen::Busy => {
                self.note(caller, action, Outcome::Denied, "busy", &to_hex);
                return Answer::error(StatusCode::SERVICE_UNAVAILABLE, "the proxy is busy");
            }
            Seen::Unreachable => {
                self.note(caller, action, Outcome::Denied, "unreachable", &to_hex);
                let written = self.record(caller, kind, ids, Ended::Unreachable);
                return reply(Ended::Unreachable, ids, false, written);
            }
        }
        let event = caller
            .event(action, Outcome::Ok)
            .target(&to_hex)
            .change(&from_hex, &to_hex);
        if self.audit.write(&event).is_err() {
            return Answer::unavailable();
        }
        if let Err(e) = store.activate_if_current(from, to) {
            // A generation that another process chose since the check above stays, and nothing is written to the
            // history, as for a wrong `expect`.
            if e == NOT_EXPECTED {
                self.note(caller, action, Outcome::Failed, "expect", &to_hex);
                return refused(e);
            }
            self.note(caller, action, Outcome::Failed, "store", &to_hex);
            let written = self.record(caller, kind, ids, Ended::Refused);
            return unwritten(refused(e), written);
        }
        let ended = self.switch(to);
        if !matches!(ended, Ended::Switched | Ended::Unchanged) {
            self.note(caller, action, Outcome::Failed, ended.word(), &to_hex);
        }
        let written = self.record(caller, kind, ids, ended);
        reply(ended, ids, true, written)
    }

    /// Orders the proxy to switch to `to`, and waits for the end of the switch.
    fn switch(&self, to: Fingerprint) -> Ended {
        match self.control.switch(to) {
            None => Ended::Unconfirmed,
            Some(Reply::Switched) => Ended::Switched,
            Some(Reply::Unchanged) => Ended::Unchanged,
            Some(Reply::Refused) => Ended::Refused,
            Some(Reply::Failed) => Ended::Failed,
            Some(Reply::Busy) => self.await_switch(to),
        }
    }

    /// The proxy did not finish the switch within the time it waits (or did not take the order): looks at its state
    /// until it serves `to`. A proxy that has no place for a look is looked at again; one that cannot be reached
    /// leaves the end of the switch unconfirmed.
    fn await_switch(&self, to: Fingerprint) -> Ended {
        let now = Instant::now();
        let by = now
            .checked_add(self.waits.stop.saturating_add(SLACK))
            .unwrap_or(now);
        let mut idle = 0;
        loop {
            sleep(POLL);
            match self.control.status() {
                Seen::Unreachable => return Ended::Unconfirmed,
                Seen::Busy => idle = 0,
                Seen::State(status) if status.generation == to => return Ended::Switched,
                Seen::State(status) if status.switching => idle = 0,
                Seen::State(_) => {
                    idle += 1;
                    if idle >= IDLE_LOOKS {
                        return Ended::Failed;
                    }
                }
            }
            if Instant::now() >= by {
                return Ended::Failed;
            }
        }
    }
}
