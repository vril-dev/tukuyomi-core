//! The history of the switches of the rules: `activations.log` of the admin store has one line of JSON for each
//! request to activate a generation or to roll back (an `Activation`), whatever came of it once the request was
//! checked: a wrong `expect`, and a proxy that has no place for the question, leave no line. The file is only
//! appended to and is never rotated; the store (see `AdminStore`) reads back the last 1 MiB of it (about 4000 lines)
//! and gives the newest lines of that, and a line that is not in the form below is left out. A rollback target or a
//! history older than that is not seen.
//!
//! A line has `ts` (the time, as a record has it), `actor` (the name of the user who asked), `from` (the generation
//! that the rules store chose before, 64 digits), `to` (the generation that was asked for), `kind` (`activate` or
//! `rollback`) and `result`: `switched` (the proxy serves `to` now), `unchanged` (it served `to` already), `refused`
//! (the rules store or the proxy refused), `failed` (the proxy did not switch in time, or at all), `unreachable` (the
//! proxy could not be asked, and the rules store was not changed) or `unconfirmed` (the rules store was changed, and
//! the answer of the proxy could not be read).
//!
//! The target of a rollback is `from` of the newest line whose result is `switched` and whose `from` is not `to` (a
//! switch from a generation to itself says nothing about the generation before it), but only if the `to` of that line
//! is the generation that the rules store chooses now. After a switch that failed, or a choice that a command made,
//! the history does not end at the chosen generation and there is no target.

use std::time::SystemTime;

use http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{Caller, Waf};
use crate::admin::audit::Outcome;
use crate::admin::password::valid_name;
use crate::admin::server::Answer;
use crate::log::record::RECORD_MAX;
use crate::log::time::rfc3339;
use crate::rules::bundle::Fingerprint;

/// The lines that `GET /api/history` gives.
const HISTORY_LINES: usize = 200;

/// What was asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Activate,
    Rollback,
}

impl Kind {
    /// The word in the history and in the audit log.
    pub fn word(self) -> &'static str {
        match self {
            Kind::Activate => "activate",
            Kind::Rollback => "rollback",
        }
    }

    fn parse(text: &str) -> Option<Kind> {
        [Kind::Activate, Kind::Rollback]
            .into_iter()
            .find(|kind| kind.word() == text)
    }
}

/// How a request to switch ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended {
    Switched,
    Unchanged,
    Refused,
    Failed,
    Unreachable,
    Unconfirmed,
}

impl Ended {
    pub fn word(self) -> &'static str {
        match self {
            Ended::Switched => "switched",
            Ended::Unchanged => "unchanged",
            Ended::Refused => "refused",
            Ended::Failed => "failed",
            Ended::Unreachable => "unreachable",
            Ended::Unconfirmed => "unconfirmed",
        }
    }

    fn parse(text: &str) -> Option<Ended> {
        [
            Ended::Switched,
            Ended::Unchanged,
            Ended::Refused,
            Ended::Failed,
            Ended::Unreachable,
            Ended::Unconfirmed,
        ]
        .into_iter()
        .find(|ended| ended.word() == text)
    }
}

/// One request to switch and how it ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Activation {
    pub ts: String,
    pub actor: String,
    pub from: Fingerprint,
    pub to: Fingerprint,
    pub kind: Kind,
    pub result: Ended,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    ts: String,
    actor: String,
    from: String,
    to: String,
    kind: String,
    result: String,
}

impl Activation {
    /// The request of `actor` at `at` to switch from `from` to `to`, which ended as `result` says.
    pub fn new(
        at: SystemTime,
        actor: &str,
        (from, to): (Fingerprint, Fingerprint),
        kind: Kind,
        result: Ended,
    ) -> Activation {
        Activation {
            ts: rfc3339(at),
            actor: actor.to_owned(),
            from,
            to,
            kind,
            result,
        }
    }

    /// The line of JSON, without its line feed. None: it would be longer than a record can be.
    pub fn encode(&self) -> Option<String> {
        let line = serde_json::to_string(&Stored {
            ts: self.ts.clone(),
            actor: self.actor.clone(),
            from: self.from.hex(),
            to: self.to.hex(),
            kind: self.kind.word().to_owned(),
            result: self.result.word().to_owned(),
        })
        .ok()?;
        (line.len() < RECORD_MAX).then_some(line)
    }

    /// The activation that `line` (without its line feed) holds. None: it is not a line of this form.
    pub fn decode(line: &[u8]) -> Option<Activation> {
        let stored: Stored = serde_json::from_slice(line).ok()?;
        if stored.ts.len() != 24 || !stored.ts.ends_with('Z') || !valid_name(&stored.actor) {
            return None;
        }
        Some(Activation {
            from: Fingerprint::from_hex(stored.from.as_bytes())?,
            to: Fingerprint::from_hex(stored.to.as_bytes())?,
            kind: Kind::parse(&stored.kind)?,
            result: Ended::parse(&stored.result)?,
            ts: stored.ts,
            actor: stored.actor,
        })
    }

    /// The activation as the API shows it.
    pub fn json(&self) -> Value {
        json!({
            "ts": self.ts,
            "actor": self.actor,
            "from": self.from.hex(),
            "to": self.to.hex(),
            "kind": self.kind.word(),
            "result": self.result.word(),
        })
    }
}

/// The generation a rollback goes to when the rules store chooses `chosen`, given the history with the newest line
/// first; else the fixed sentence of the refusal.
pub fn rollback_target(
    newest_first: &[Activation],
    chosen: Fingerprint,
) -> Result<Fingerprint, &'static str> {
    let line = newest_first
        .iter()
        .find(|line| line.result == Ended::Switched && line.from != line.to)
        .ok_or("there is no switch to go back from")?;
    if line.to != chosen {
        return Err("the history does not end at the chosen generation");
    }
    Ok(line.from)
}

impl Waf {
    /// All the lines of the history that can be read, the newest first.
    pub(super) fn lines(&self) -> Result<Vec<Activation>, Answer> {
        self.store
            .activations(usize::MAX)
            .map_err(|_| Answer::unavailable())
    }

    /// Writes the line of the history, and tells whether it was written; the audit log has a line when it was not.
    pub(super) fn record(
        &self,
        caller: &Caller<'_>,
        kind: Kind,
        ids: (Fingerprint, Fingerprint),
        ended: Ended,
    ) -> bool {
        let line = Activation::new(SystemTime::now(), &caller.who.name, ids, kind, ended);
        let written = self.store.record_activation(&line).is_ok();
        if !written {
            self.note(
                caller,
                kind.word(),
                Outcome::Failed,
                "history",
                &ids.1.hex(),
            );
        }
        written
    }

    pub(super) fn history(&self) -> Answer {
        match self.store.activations(HISTORY_LINES) {
            Ok(lines) => Answer::json(
                StatusCode::OK,
                json!({"entries": lines.iter().map(Activation::json).collect::<Vec<_>>()}),
            ),
            Err(_) => Answer::unavailable(),
        }
    }
}

#[cfg(test)]
mod tests;
