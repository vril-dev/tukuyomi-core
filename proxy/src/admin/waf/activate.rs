//! The routes that switch the proxy: `POST /api/activate` and `POST /api/rollback`, with the wait for the end of the
//! switch. A switch is for one engine: the engine of the generation that is activated, or the engine that a rollback
//! names (the default engine if it names none). The generation that the client expects (`expect`) is the one chosen for
//! that engine, `null` for an engine that has none chosen; the generation that is activated starts the engine if the
//! proxy does not run it, which is also what activating the generation that is chosen already does.
//!
//! A proxy of an older version, which runs one engine for everything and does not report its engines, is not switched:
//! the answer is 409, audited as denied (`version`), and the rules store is not touched.

use std::thread::sleep;
use std::time::{Duration, Instant};

use http::StatusCode;
use serde::Deserialize;
use serde_json::json;
use tukuyomi_kernel::Engine;

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
/// The sentence for a proxy that does not report its engines: a version that is not this one.
const OLD_PROXY: &str = "the proxy does not report its engines";

fn digits(text: &str) -> Result<Fingerprint, Answer> {
    Fingerprint::from_hex(text.as_bytes()).ok_or_else(|| {
        Answer::error(
            StatusCode::BAD_REQUEST,
            "a generation is not 64 lowercase hexadecimal digits",
        )
    })
}

/// The answer to a request to switch `engine`. `ids` are the generation before (the one asked for if there was none)
/// and the one asked for; `chosen`: the rules store chooses the latter now; `written`: the history has the line.
fn reply(
    ended: Ended,
    engine: Engine,
    ids: (Fingerprint, Fingerprint),
    chosen: bool,
    written: bool,
) -> Answer {
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
        "engine": engine.name(),
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
    /// The generation chosen for the engine of `generation`, or `null` for none. The key is there in every request:
    /// a request that leaves it out is not read as one that expects none.
    #[serde(deserialize_with = "Option::deserialize")]
    expect: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RollbackBody {
    /// The engine to roll back; the default engine if there is none.
    engine: Option<String>,
    expect: String,
}

/// What a request to switch is for.
#[derive(Clone, Copy)]
enum Which {
    /// This generation, whatever its engine is.
    Activate(Fingerprint),
    /// The target of the history for this engine, which ends at this generation (the one the client expects).
    Rollback(Engine, Fingerprint),
}

impl Waf {
    pub(super) fn activate(&self, req: &Req, caller: &Caller<'_>) -> Answer {
        let body: ActivateBody = match json_body(req) {
            Ok(body) => body,
            Err(answer) => return answer,
        };
        let expect = body.expect.as_deref().map(digits).transpose();
        match (digits(&body.generation), expect) {
            (Ok(to), Ok(expect)) => {
                self.switch_to(caller, Kind::Activate, Which::Activate(to), expect)
            }
            (Err(answer), _) | (_, Err(answer)) => answer,
        }
    }

    pub(super) fn rollback(&self, req: &Req, caller: &Caller<'_>) -> Answer {
        let body: RollbackBody = match json_body(req) {
            Ok(body) => body,
            Err(answer) => return answer,
        };
        let engine = match body.engine.as_deref() {
            None => self.default_engine,
            Some(name) => match Engine::parse(name) {
                Some(engine) => engine,
                None => {
                    return Answer::error(
                        StatusCode::BAD_REQUEST,
                        "engine is not the name of an engine (coraza or modsecurity)",
                    );
                }
            },
        };
        match digits(&body.expect) {
            Ok(expect) => self.switch_to(
                caller,
                Kind::Rollback,
                Which::Rollback(engine, expect),
                Some(expect),
            ),
            Err(answer) => answer,
        }
    }

    /// The generation a request to switch is for, which the store must have: the one asked for, or for a rollback the
    /// target of the history when the store chooses the generation that the client expects for the engine.
    fn target(&self, store: &dyn RuleStore, which: Which) -> Result<Fingerprint, Answer> {
        let to = match which {
            Which::Activate(to) => to,
            Which::Rollback(engine, chosen) => {
                let lines = self.lines()?;
                rollback_target(&lines, chosen, engine, |g| store.engine(g).ok())
                    .map_err(conflict)?
            }
        };
        if store
            .list()
            .map_err(failed)?
            .iter()
            .any(|g| g.fingerprint == to)
        {
            return Ok(to);
        }
        Err(match which {
            Which::Activate(_) => Answer::error(StatusCode::NOT_FOUND, "no such generation"),
            Which::Rollback(..) => conflict("the generation to go back to is not in the store"),
        })
    }

    /// A request to switch to the generation of `which` (for a rollback: the target of the history) when the rules
    /// store chooses `expect` for its engine (`None`: none). See the module documentation for the steps.
    fn switch_to(
        &self,
        caller: &Caller<'_>,
        kind: Kind,
        which: Which,
        expect: Option<Fingerprint>,
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
        let to = match self.target(store.as_ref(), which) {
            Ok(to) => to,
            Err(answer) => return answer,
        };
        let to_hex = to.hex();
        // The engine of the generation. A manifest that cannot be read is not answered here: the store refuses it when
        // it chooses, and that answer stands.
        let engine = store.engine(to).ok();
        // Nothing is changed unless the rules store chooses what the client saw for the engine and the proxy can be
        // asked. The generation before is the one the store gave, which is `expect`; where there is none it is `to`.
        let from = match engine.map(|engine| store.current(engine)) {
            None => expect.unwrap_or(to),
            Some(Ok(current)) if current == expect => expect.unwrap_or(to),
            Some(Ok(_)) => {
                self.note(caller, action, Outcome::Denied, "expect", &to_hex);
                return refused(NOT_EXPECTED);
            }
            Some(Err(e)) => return failed(e),
        };
        let (ids, from_hex) = ((from, to), from.hex());
        // Before the proxy is asked and before the store chooses: a generation whose engine cannot be used here
        // would be refused by the proxy, and left as the chosen one it would end the next start.
        if let Some(engine) = engine
            && let Err(text) = self.trial.usable(engine)
        {
            self.note(caller, action, Outcome::Denied, "engine", &to_hex);
            return conflict(text);
        }
        // The engine of a manifest that cannot be read is told as the default one: the store refuses the generation
        // before any of that matters.
        let engine = engine.unwrap_or(self.default_engine);
        match self.control.status() {
            Seen::State(status) if status.engines.is_some() => {}
            Seen::State(_) => {
                self.note(caller, action, Outcome::Denied, "version", &to_hex);
                return conflict(OLD_PROXY);
            }
            Seen::Busy => {
                self.note(caller, action, Outcome::Denied, "busy", &to_hex);
                return Answer::error(StatusCode::SERVICE_UNAVAILABLE, "the proxy is busy");
            }
            Seen::Unreachable => {
                self.note(caller, action, Outcome::Denied, "unreachable", &to_hex);
                let written = self.record(caller, kind, engine, ids, Ended::Unreachable);
                return reply(Ended::Unreachable, engine, ids, false, written);
            }
        }
        let event = caller
            .event(action, Outcome::Ok)
            .target(&to_hex)
            .change(&from_hex, &to_hex);
        if self.audit.write(&event).is_err() {
            return Answer::unavailable();
        }
        if let Err(e) = store.activate_if_current(expect, to) {
            // A generation that another process chose since the check above stays, and nothing is written to the
            // history, as for a wrong `expect`.
            if e == NOT_EXPECTED {
                self.note(caller, action, Outcome::Failed, "expect", &to_hex);
                return refused(e);
            }
            self.note(caller, action, Outcome::Failed, "store", &to_hex);
            let written = self.record(caller, kind, engine, ids, Ended::Refused);
            return unwritten(refused(e), written);
        }
        let ended = self.switch(engine, to);
        if !matches!(ended, Ended::Switched | Ended::Unchanged) {
            self.note(caller, action, Outcome::Failed, ended.word(), &to_hex);
        }
        let written = self.record(caller, kind, engine, ids, ended);
        reply(ended, engine, ids, true, written)
    }

    /// Orders the proxy to switch `engine` to `to`, and waits for the end of the switch.
    fn switch(&self, engine: Engine, to: Fingerprint) -> Ended {
        match self.control.switch(engine, to) {
            None => Ended::Unconfirmed,
            Some(Reply::Switched) => Ended::Switched,
            Some(Reply::Unchanged) => Ended::Unchanged,
            Some(Reply::Refused) => Ended::Refused,
            Some(Reply::Failed) => Ended::Failed,
            Some(Reply::Busy) => self.await_switch(engine, to),
        }
    }

    /// The proxy did not finish the switch within the time it waits (or did not take the order): looks at its state
    /// until it serves `to` for `engine`. A proxy that has no place for a look is looked at again; one that cannot be reached
    /// leaves the end of the switch unconfirmed.
    fn await_switch(&self, engine: Engine, to: Fingerprint) -> Ended {
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
                Seen::State(status)
                    if status
                        .engines
                        .and_then(|engines| engines.of(engine).map(|state| state.generation))
                        == Some(to) =>
                {
                    return Ended::Switched;
                }
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
