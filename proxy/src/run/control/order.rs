//! The orders that a connection hands to the main loop: the line that a client sends, what it asks for, and the
//! orders, each of which holds the channel that its answer is sent back on.

use serde::Deserialize;
use tokio::sync::oneshot;

use super::answer::{Answer, Outcome, Reloaded, reload_line, switch_line};
use crate::inbound::conn::Setup;
use crate::log::Log;
use crate::rules::bundle::Fingerprint;

/// A request to switch, and where its answer goes.
pub(in crate::run) struct SwitchOrder {
    pub(super) expect: Fingerprint,
    pub(super) reply: oneshot::Sender<Answer>,
}

impl SwitchOrder {
    /// The generation the client expects the store to choose.
    pub(in crate::run) fn expect(&self) -> Fingerprint {
        self.expect
    }

    /// Answers the client, and writes the record line of the order. `serving` is the generation that serves now.
    pub(in crate::run) fn finish(
        self,
        outcome: Outcome,
        reason: Option<&'static str>,
        serving: Fingerprint,
        log: &Log,
    ) {
        log.line(&switch_line(self.expect, outcome, reason, serving));
        let _ = self.reply.send(Answer::Switch {
            outcome,
            reason,
            generation: serving,
        });
    }
}

/// A request to read the configuration again with a managed version, and where its answer goes.
pub(in crate::run) struct ReloadOrder {
    pub(super) managed: [u8; 32],
    pub(super) reply: oneshot::Sender<Answer>,
}

impl ReloadOrder {
    /// The name of the version the configuration is to be read with.
    pub(in crate::run) fn managed(&self) -> [u8; 32] {
        self.managed
    }

    /// Answers the client, and writes the record line of the order. `setup` is the setup in force now.
    pub(in crate::run) fn finish(self, reloaded: Reloaded, setup: &Setup, log: &Log) {
        log.line(&reload_line(self.managed, &reloaded));
        let _ = self.reply.send(Answer::reload(reloaded, setup));
    }
}

/// What a connection asks of the main loop.
pub(in crate::run) enum Order {
    Status(oneshot::Sender<Answer>),
    Switch(SwitchOrder),
    Reload(ReloadOrder),
}

/// What a line asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Ask {
    Status,
    Switch(Fingerprint),
    /// A reading of the configuration with the managed version of this name.
    Reload([u8; 32]),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    op: String,
    expect: Option<String>,
    managed: Option<String>,
}

/// What the line asks for, or the word that says why it is not a request. A name is 64 lowercase hexadecimal digits.
pub(super) fn parse(line: &[u8]) -> Result<Ask, &'static str> {
    const MALFORMED: &str = "malformed request";
    let raw: Raw = serde_json::from_slice(line).map_err(|_| MALFORMED)?;
    match (raw.op.as_str(), raw.expect, raw.managed) {
        ("status", None, None) => Ok(Ask::Status),
        ("switch", Some(expect), None) => Fingerprint::from_hex(expect.as_bytes())
            .map(Ask::Switch)
            .ok_or("bad expect"),
        ("reload", None, Some(managed)) => Fingerprint::from_hex(managed.as_bytes())
            .map(|name| Ask::Reload(name.bytes()))
            .ok_or("bad managed"),
        ("status" | "switch" | "reload", _, _) => Err(MALFORMED),
        _ => Err("unknown op"),
    }
}
