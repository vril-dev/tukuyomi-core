//! The history of the changes of the managed configuration: `managed.log` of the admin store has one line of JSON (a
//! `Change`) for each change whose job got past its checks and asked the proxy, and for each change that found the
//! proxy out of reach (see `job` for which ends have a line). Like the history of the rules (see `waf::history`), the
//! file is only appended to and is never rotated; the store (see `AdminStore`) reads back the last 1 MiB of it and
//! gives the newest lines of that, and a line that is not in the form below is left out.
//!
//! A line has `ts` (the time, as a record has it), `actor` (the name of the user who asked), `kind` (`apply`,
//! `activate` or `rollback`), `from` (the version that the store chose when the change was asked for, 64 digits), `to`
//! (the version asked for), `result` (`applied`, `refused`, `busy`, `error`, `failed`, `unconfirmed`, `not recorded`
//! or `unreachable`; see `job`), and when it has one, `reason` (a fixed word: the part of the proxy that refused, the
//! reason of `busy` or of `error`, or for `not recorded` `current changed` or `store`), `config_before` and
//! `config_after` (the SHA-256 of the main file in force before the order and after it). No sentence of the proxy or of
//! the store is written here; the job has them.
//!
//! The target of a rollback is `from` of the newest line whose result is `applied` and whose `from` is not its `to`
//! (a change from a version to itself says nothing about the version before it), but only if the `to` of that line is
//! the version that the store chooses now. After a change that did not apply, or a choice that a command made, the
//! history does not end at the chosen version and there is no target.

use std::time::SystemTime;

use http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::job::Caller;
use super::routes::Managed;
use crate::admin::audit::{AuditLog, Outcome};
use crate::admin::password::valid_name;
use crate::admin::server::Answer;
use crate::admin::store::AdminStore;
use crate::admin::waf::control::{BUSY, ERRORS, REFUSED};
use crate::log::record::RECORD_MAX;
use crate::log::time::rfc3339;
use crate::rules::bundle::{Fingerprint, hex};

/// The lines that `GET /api/managed/history` gives.
const HISTORY_LINES: usize = 200;
/// The results that a line may have.
const RESULTS: [&str; 8] = [
    "applied",
    "refused",
    "busy",
    "error",
    "failed",
    "unconfirmed",
    "not recorded",
    "unreachable",
];

/// What a change asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// The saving of a version and its putting in force.
    Apply,
    /// The putting in force of a version of the store by its name.
    Activate,
    /// The putting in force of the version before the last change.
    Rollback,
}

impl Kind {
    /// The word in the history and in the job.
    pub fn word(self) -> &'static str {
        match self {
            Kind::Apply => "apply",
            Kind::Activate => "activate",
            Kind::Rollback => "rollback",
        }
    }

    /// The action of the audit log for the change.
    pub fn action(self) -> &'static str {
        match self {
            Kind::Apply => "managed-apply",
            Kind::Activate => "managed-activate",
            Kind::Rollback => "managed-rollback",
        }
    }

    fn parse(text: &str) -> Option<Kind> {
        [Kind::Apply, Kind::Activate, Kind::Rollback]
            .into_iter()
            .find(|kind| kind.word() == text)
    }
}

/// The word of `words` that `text` is.
fn word(text: &str, words: impl IntoIterator<Item = &'static str>) -> Option<&'static str> {
    words.into_iter().find(|word| *word == text)
}

/// One change and how it ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    pub ts: String,
    pub actor: String,
    pub kind: Kind,
    pub from: [u8; 32],
    pub to: [u8; 32],
    pub result: &'static str,
    pub reason: Option<&'static str>,
    pub config_before: Option<[u8; 32]>,
    pub config_after: Option<[u8; 32]>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    ts: String,
    actor: String,
    kind: String,
    from: String,
    to: String,
    result: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    config_before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    config_after: Option<String>,
}

/// The 32 bytes of 64 lowercase digits; `Some(None)` for none, `None` for anything else.
fn digits(text: Option<&str>) -> Option<Option<[u8; 32]>> {
    match text {
        Some(text) => Some(Some(Fingerprint::from_hex(text.as_bytes())?.bytes())),
        None => Some(None),
    }
}

impl Change {
    /// The line of JSON, without its line feed. None: it would be longer than a record can be.
    pub fn encode(&self) -> Option<String> {
        let line = serde_json::to_string(&Stored {
            ts: self.ts.clone(),
            actor: self.actor.clone(),
            kind: self.kind.word().to_owned(),
            from: hex(&self.from),
            to: hex(&self.to),
            result: self.result.to_owned(),
            reason: self.reason.map(str::to_owned),
            config_before: self.config_before.map(|name| hex(&name)),
            config_after: self.config_after.map(|name| hex(&name)),
        })
        .ok()?;
        (line.len() < RECORD_MAX).then_some(line)
    }

    /// The change that `line` (without its line feed) holds. None: it is not a line of this form.
    pub fn decode(line: &[u8]) -> Option<Change> {
        let stored: Stored = serde_json::from_slice(line).ok()?;
        if stored.ts.len() != 24 || !stored.ts.ends_with('Z') || !valid_name(&stored.actor) {
            return None;
        }
        let reasons = REFUSED
            .into_iter()
            .chain(BUSY)
            .chain(ERRORS)
            .chain(["current changed"]);
        let reason = match stored.reason.as_deref() {
            Some(text) => Some(word(text, reasons)?),
            None => None,
        };
        Some(Change {
            kind: Kind::parse(&stored.kind)?,
            from: Fingerprint::from_hex(stored.from.as_bytes())?.bytes(),
            to: Fingerprint::from_hex(stored.to.as_bytes())?.bytes(),
            result: word(&stored.result, RESULTS)?,
            reason,
            config_before: digits(stored.config_before.as_deref())?,
            config_after: digits(stored.config_after.as_deref())?,
            ts: stored.ts,
            actor: stored.actor,
        })
    }

    /// The change as the API shows it.
    pub fn json(&self) -> Value {
        json!({
            "ts": self.ts,
            "actor": self.actor,
            "kind": self.kind.word(),
            "from": hex(&self.from),
            "to": hex(&self.to),
            "result": self.result,
            "reason": self.reason,
            "config_before": self.config_before.map(|name| hex(&name)),
            "config_after": self.config_after.map(|name| hex(&name)),
        })
    }
}

/// The version a rollback goes to when the store chooses `chosen`, given the history with the newest line first; else
/// the fixed sentence of the refusal.
pub(super) fn rollback_target(
    newest_first: &[Change],
    chosen: [u8; 32],
) -> Result<[u8; 32], &'static str> {
    let line = newest_first
        .iter()
        .find(|line| line.result == "applied" && line.from != line.to)
        .ok_or("there is no change to go back from")?;
    if line.to != chosen {
        return Err("the history does not end at the chosen version");
    }
    Ok(line.from)
}

/// Writes the line of the history of `change`, which `caller` asked for, and tells whether it was written; the audit
/// log has a line when it was not.
pub(super) fn record(
    store: &dyn AdminStore,
    audit: &AuditLog,
    caller: &Caller,
    change: &Change,
) -> bool {
    let written = store.record_change(change).is_ok();
    if !written {
        let _ = audit.write(
            &caller
                .event(change.kind.action(), Outcome::Failed)
                .target(&hex(&change.to))
                .reason("history"),
        );
    }
    written
}

/// The line of `caller` for a change of `kind` from `from` to `to` that ended now with `result` and `reason`.
pub(super) fn line(
    caller: &Caller,
    kind: Kind,
    (from, to): ([u8; 32], [u8; 32]),
    (result, reason): (&'static str, Option<&'static str>),
    (config_before, config_after): (Option<[u8; 32]>, Option<[u8; 32]>),
) -> Change {
    Change {
        ts: rfc3339(SystemTime::now()),
        actor: caller.name().to_owned(),
        kind,
        from,
        to,
        result,
        reason,
        config_before,
        config_after,
    }
}

impl Managed {
    /// All the lines of the history that can be read, the newest first.
    pub(super) fn lines(&self) -> Result<Vec<Change>, Answer> {
        self.admin
            .changes(usize::MAX)
            .map_err(|_| Answer::unavailable())
    }

    pub(super) fn history(&self) -> Answer {
        if self.dir.is_none() {
            return super::routes::unmanaged();
        }
        match self.admin.changes(HISTORY_LINES) {
            Ok(lines) => Answer::json(
                StatusCode::OK,
                json!({"entries": lines.iter().map(Change::json).collect::<Vec<_>>()}),
            ),
            Err(_) => Answer::unavailable(),
        }
    }
}

#[cfg(test)]
mod tests;
