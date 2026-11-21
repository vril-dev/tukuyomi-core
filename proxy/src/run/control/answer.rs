//! The answers of the control socket: how a switch order and a reload order ended, the figures of a status answer,
//! and the line of JSON and the record line that each answer makes.

use serde::Serialize;

use crate::inbound::conn::Setup;
use crate::rules::bundle::{Fingerprint, hex};
use crate::run::start::Refusal;

/// How a switch order ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::run) enum Outcome {
    Switched,
    Unchanged,
    Refused,
    Failed,
    Busy,
}

impl Outcome {
    fn word(self) -> &'static str {
        match self {
            Outcome::Switched => "switched",
            Outcome::Unchanged => "unchanged",
            Outcome::Refused => "refused",
            Outcome::Failed => "failed",
            Outcome::Busy => "busy",
        }
    }
}

/// How a reload order ended.
#[derive(Debug, PartialEq, Eq)]
pub(in crate::run) enum Reloaded {
    /// The configuration was replaced: the main file and the version that the order named serve now.
    Replaced,
    /// Nothing was replaced, for the reason that the refusal gives.
    Refused(Refusal),
    /// No reading was started for the order, or its end was not waited for; the word says why.
    Busy(&'static str),
}

impl Reloaded {
    fn word(&self) -> &'static str {
        match self {
            Reloaded::Replaced => "replaced",
            Reloaded::Refused(_) => "refused",
            Reloaded::Busy(_) => "busy",
        }
    }

    /// The reason of the answer and of its record line; `replaced` has none.
    fn reason(&self) -> Option<&'static str> {
        match self {
            Reloaded::Replaced => None,
            Reloaded::Refused(refusal) => Some(refusal.reason.word()),
            Reloaded::Busy(why) => Some(why),
        }
    }
}

/// The figures of the proxy that a status answer holds besides its state: what `/metrics` shows of the same, taken
/// when the answer is made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::run) struct Figures {
    /// The milliseconds since the proxy started.
    pub(in crate::run) uptime_ms: u64,
    /// The requests of every class of the records, `closed` (no answer) included, and those of a route that writes no
    /// record.
    pub(in crate::run) requests: u64,
    /// The requests that a rule blocked.
    pub(in crate::run) blocked: u64,
    /// The requests that the access list or the rate limit turned away.
    pub(in crate::run) policy_refused: u64,
    /// The failures of the servers of every upstream group of the configuration in force.
    pub(in crate::run) upstream_failures: u64,
    /// The SHA-256 of the configuration file in force.
    pub(in crate::run) config: [u8; 32],
    /// The name of the managed version in force, for a file with `managed`.
    pub(in crate::run) managed: Option<[u8; 32]>,
    /// The `forward.resolve_timeout_ms` of the configuration in force.
    pub(in crate::run) resolve_timeout_ms: u64,
    /// The readings of the configuration file again, by how they ended.
    pub(in crate::run) config_replaced: u64,
    pub(in crate::run) config_refused: u64,
}

/// The answer to a line, as the connection writes it.
#[derive(Debug, PartialEq, Eq)]
pub(in crate::run) enum Answer {
    Status {
        generation: Fingerprint,
        mode: &'static str,
        engine: &'static str,
        phase: &'static str,
        switching: bool,
        reloading: bool,
        ready: bool,
        figures: Figures,
    },
    Switch {
        outcome: Outcome,
        reason: Option<&'static str>,
        generation: Fingerprint,
    },
    /// The answer to a reload order, with the SHA-256 of the main file and the managed version in force when it is
    /// given.
    Reload {
        reloaded: Reloaded,
        config: [u8; 32],
        managed: Option<[u8; 32]>,
    },
    Error(&'static str),
}

/// The answer to a reload order, written by the JSON writer with its keys in this order: `config` only for `replaced`,
/// and `managed` always (`null` for none). The writer escapes the sentence of a refusal, which has names of the
/// configuration in it.
#[derive(Serialize)]
struct ReloadLine<'a> {
    result: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    config: Option<String>,
    managed: Option<String>,
}

impl Answer {
    /// The answer to a reload order that ended as `reloaded`, while `setup` is in force.
    pub(super) fn reload(reloaded: Reloaded, setup: &Setup) -> Answer {
        Answer::Reload {
            reloaded,
            config: setup.sha256,
            managed: setup.managed,
        }
    }

    /// The line of JSON with its line feed. Every value but the sentence of a refused reload order is a fixed word, a
    /// boolean, a number or hexadecimal digits, so those lines are written as they are, with nothing to escape; the
    /// answer to a reload order is written by the JSON writer.
    pub(super) fn line(&self) -> String {
        match self {
            Answer::Status {
                generation,
                mode,
                engine,
                phase,
                switching,
                reloading,
                ready,
                figures,
            } => format!(
                "{{\"generation\":\"{}\",\"mode\":\"{mode}\",\"engine\":\"{engine}\",\"phase\":\"{phase}\",\"switching\":{switching},\"reloading\":{reloading},\"ready\":{ready},\"uptime_ms\":{},\"requests\":{},\"blocked\":{},\"policy_refused\":{},\"upstream_failures\":{},\"config\":\"{}\",\"managed\":{},\"resolve_timeout_ms\":{},\"config_reloads\":{{\"replaced\":{},\"refused\":{}}}}}\n",
                generation.hex(),
                figures.uptime_ms,
                figures.requests,
                figures.blocked,
                figures.policy_refused,
                figures.upstream_failures,
                hex(&figures.config),
                figures
                    .managed
                    .map_or_else(|| "null".to_owned(), |name| format!("\"{}\"", hex(&name))),
                figures.resolve_timeout_ms,
                figures.config_replaced,
                figures.config_refused
            ),
            Answer::Switch {
                outcome,
                reason: Some(reason),
                generation,
            } => format!(
                "{{\"result\":\"{}\",\"reason\":\"{reason}\",\"generation\":\"{}\"}}\n",
                outcome.word(),
                generation.hex()
            ),
            Answer::Switch {
                outcome,
                reason: None,
                generation,
            } => format!(
                "{{\"result\":\"{}\",\"generation\":\"{}\"}}\n",
                outcome.word(),
                generation.hex()
            ),
            Answer::Reload {
                reloaded,
                config,
                managed,
            } => {
                let line = ReloadLine {
                    result: reloaded.word(),
                    reason: reloaded.reason(),
                    detail: match reloaded {
                        Reloaded::Refused(refusal) => Some(&refusal.detail),
                        Reloaded::Replaced | Reloaded::Busy(_) => None,
                    },
                    config: matches!(reloaded, Reloaded::Replaced).then(|| hex(config)),
                    managed: managed.map(|name| hex(&name)),
                };
                // The writer does not fail on these fields; an empty line would not be taken for an answer.
                let mut text = serde_json::to_string(&line).unwrap_or_default();
                text.push('\n');
                text
            }
            Answer::Error(reason) => format!("{{\"result\":\"error\",\"reason\":\"{reason}\"}}\n"),
        }
    }
}

/// The record line of an answer to a switch order. `serving` is the generation that serves then.
pub(super) fn switch_line(
    expect: Fingerprint,
    outcome: Outcome,
    reason: Option<&'static str>,
    serving: Fingerprint,
) -> String {
    let why = reason.map_or_else(String::new, |reason| format!(" ({reason})"));
    format!(
        "control: switch expect {}: {}{why}, serving {}",
        expect.hex(),
        outcome.word(),
        serving.hex()
    )
}

/// The record line of an answer to a reload order for the version `managed`.
pub(super) fn reload_line(managed: [u8; 32], reloaded: &Reloaded) -> String {
    let why = reloaded
        .reason()
        .map_or_else(String::new, |reason| format!(" ({reason})"));
    format!(
        "control: reload {}: {}{why}",
        hex(&managed),
        reloaded.word()
    )
}
