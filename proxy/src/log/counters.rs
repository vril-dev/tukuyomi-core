//! The numbers that the status listener shows at `/metrics`: counters that only grow while the process runs and start
//! at 0, the number of connections that are open, and the time the process started.
//!
//! A counter is added where the event it counts is already handled, from the same value that the record of the event
//! shows, so a count and its records agree. Every label comes from a fixed list; a label that is not in its list is
//! not counted. The connections that are open are counted here as well (`Open`): a connection raises the number when
//! it starts and lowers it when it ends, however it ends. The other numbers that fall as well as rise (the bytes of
//! the byte budget in use, the inspections that wait) are not kept here: they are read from the permits and the
//! configuration when the page is asked for. The counts of the upstream groups are kept by the groups
//! (`forward::group`), and the numbers of the records that were dropped or not written by the logger (`Log`).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use tukuyomi_kernel::Reason;

/// The values of `class` in a record of the type `request`.
const CLASSES: [&str; 7] = [
    "forwarded",
    "blocked",
    "rejected",
    "redirected",
    "answered",
    "failed",
    "closed",
];

/// One word for each reason a request cannot be inspected (`Reason` of the kernel), in the order of `reason_label`.
const REASONS: [&str; 10] = [
    "invalid",
    "queue_full",
    "unavailable",
    "wait_deadline",
    "verdict_deadline",
    "inspector_lost",
    "protocol",
    "inspector_error",
    "not_created",
    "cancelled",
];

/// The word for `reason`; the codes that some reasons carry are left out.
fn reason_label(reason: Reason) -> &'static str {
    match reason {
        Reason::Invalid => "invalid",
        Reason::QueueFull => "queue_full",
        Reason::Unavailable => "unavailable",
        Reason::WaitDeadline => "wait_deadline",
        Reason::VerdictDeadline => "verdict_deadline",
        Reason::InspectorLost => "inspector_lost",
        Reason::Protocol => "protocol",
        Reason::InspectorError { .. } => "inspector_error",
        Reason::NotCreated { .. } => "not_created",
        Reason::Cancelled => "cancelled",
    }
}

/// What a rule did to a request it matched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleHit {
    /// The request was answered with the rule's status.
    Block,
    /// The rules only detect: the request went on.
    Detect,
}

impl RuleHit {
    fn label(self) -> &'static str {
        match self {
            RuleHit::Block => "block",
            RuleHit::Detect => "detect",
        }
    }
}

/// How the switch to another generation of the rules ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwitchResult {
    Switched,
    /// The rules store did not give a generation to switch to.
    Refused,
    /// The generation was chosen but did not start, or the driver did not take the order.
    Failed,
}

impl SwitchResult {
    fn label(self) -> &'static str {
        match self {
            SwitchResult::Switched => "switched",
            SwitchResult::Refused => "refused",
            SwitchResult::Failed => "failed",
        }
    }
}

/// How the reading of the certificate and key files again ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReloadResult {
    Replaced,
    Refused,
}

impl ReloadResult {
    fn label(self) -> &'static str {
        match self {
            ReloadResult::Replaced => "replaced",
            ReloadResult::Refused => "refused",
        }
    }
}

/// One number that only grows.
#[derive(Default)]
pub struct Counter(AtomicU64);

impl Counter {
    pub fn add(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// The number of connections that are open now. It rises with `count` and falls when the `Counted` that `count`
/// returned is dropped.
#[derive(Default)]
pub struct Open(AtomicUsize);

impl Open {
    /// One more connection is open until the returned value is dropped.
    pub fn count(self: &Arc<Open>) -> Counted {
        self.0.fetch_add(1, Ordering::Relaxed);
        Counted(self.clone())
    }

    pub fn get(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }
}

/// One connection that is counted in `Open`; it is taken off when this is dropped.
pub struct Counted(Arc<Open>);

impl Drop for Counted {
    fn drop(&mut self) {
        self.0.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Counters under a fixed list of labels.
pub struct Family<const N: usize> {
    labels: [&'static str; N],
    counts: [Counter; N],
}

impl<const N: usize> Family<N> {
    fn new(labels: [&'static str; N]) -> Family<N> {
        Family {
            labels,
            counts: std::array::from_fn(|_| Counter::default()),
        }
    }

    /// Counts one more under `label`; a label that is not in the list is not counted.
    pub fn add(&self, label: &str) {
        if let Some(at) = self.labels.iter().position(|&known| known == label) {
            self.counts[at].add();
        }
    }

    /// Every label of the list with its count, in the order of the list.
    pub fn samples(&self) -> [(&'static str, u64); N] {
        std::array::from_fn(|at| (self.labels[at], self.counts[at].get()))
    }
}

/// Everything the process counts for `/metrics`. Shared by the connections (through `Ctx`), the signal handlers and the
/// status listener; every number is read and written one at a time.
pub struct Counters {
    /// The requests that were answered, by `class` of their record.
    pub requests: Family<7>,
    /// The requests a rule decided, by what the rule did.
    pub rule_hits: Family<2>,
    /// The requests that could not be inspected, by the reason the kernel gave.
    pub uninspectable: Family<10>,
    /// The switches to another generation of the rules, by how they ended.
    pub switches: Family<3>,
    /// The readings of the certificate files again, by how they ended.
    pub reloads: Family<2>,
    /// The connections that were accepted.
    pub accepted: Counter,
    /// The connections that are open now.
    pub open: Arc<Open>,
    /// The TLS handshakes that failed or were not finished in time.
    pub tls_failures: Counter,
    /// When the process started, in seconds since the epoch of Unix time.
    started: u64,
}

impl Counters {
    /// All numbers at 0, and the time of the start taken now.
    pub fn start() -> Counters {
        Counters {
            requests: Family::new(CLASSES),
            rule_hits: Family::new([RuleHit::Block.label(), RuleHit::Detect.label()]),
            uninspectable: Family::new(REASONS),
            switches: Family::new([
                SwitchResult::Switched.label(),
                SwitchResult::Refused.label(),
                SwitchResult::Failed.label(),
            ]),
            reloads: Family::new([
                ReloadResult::Replaced.label(),
                ReloadResult::Refused.label(),
            ]),
            accepted: Counter::default(),
            open: Arc::new(Open::default()),
            tls_failures: Counter::default(),
            started: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |since| since.as_secs()),
        }
    }

    /// An answer of this `class` (the word of the record) was written.
    pub fn add_request(&self, class: &str) {
        self.requests.add(class);
    }

    pub fn add_rule_hit(&self, decision: RuleHit) {
        self.rule_hits.add(decision.label());
    }

    pub fn add_uninspectable(&self, reason: Reason) {
        self.uninspectable.add(reason_label(reason));
    }

    pub fn add_switch(&self, result: SwitchResult) {
        self.switches.add(result.label());
    }

    pub fn add_reload(&self, result: ReloadResult) {
        self.reloads.add(result.label());
    }

    /// The time the process started, in seconds since the epoch of Unix time.
    pub fn started(&self) -> u64 {
        self.started
    }
}

#[cfg(test)]
mod tests;
