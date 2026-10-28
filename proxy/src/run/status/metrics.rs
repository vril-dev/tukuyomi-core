//! The page of `/metrics`, in the Prometheus text format, version 0.0.4.
//!
//! A family is written once: its `# HELP` line, its `# TYPE` line and then all its samples, one after another. The
//! label values come from fixed lists or are the names of the upstream groups of the configuration, never a value of
//! a request, and they are written with `\`, `"` and the line feed escaped. The counters are those of `Counters`; the
//! numbers that fall as well as rise are given by the caller, who reads them from `Counters`, the permits, the rate
//! limit and the configuration when the page is asked for. Every counter starts at 0 when the process starts.

use std::fmt::{Display, Write as _};

use tukuyomi_kernel::Phase;

use crate::inspect::driver::State;
use crate::log::counters::Counters;

/// Everything the page is made of.
pub(super) struct Scrape<'a> {
    pub(super) counters: &'a Counters,
    /// The kernel that serves.
    pub(super) state: State,
    /// The connections that are open.
    pub(super) connections_open: usize,
    /// How many times a connection had to wait for a permit.
    pub(super) permit_waits: u64,
    /// The bytes of the byte budget in use.
    pub(super) body_buffer_bytes: usize,
    /// The inspections that hold a permit of the waiting queue.
    pub(super) inspections_waiting: usize,
    /// The name of each upstream group and its failures.
    pub(super) upstream_failures: Vec<(&'a str, u64)>,
    /// The clients that the rate limit counts, and those it dropped to make room; both 0 without a rate limit.
    pub(super) rate_limit_keys: usize,
    pub(super) rate_limit_evicted: u64,
    pub(super) records_dropped: u64,
    pub(super) record_write_errors: u64,
    pub(super) record_file_errors: u64,
}

/// A label value with `\`, `"` and the line feed escaped.
fn escaped(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

/// The text of a page that is being written.
struct Page(String);

impl Page {
    /// The `# HELP` and `# TYPE` lines of a family. `help` has no backslash and no line feed.
    fn family(&mut self, name: &str, kind: &str, help: &str) {
        let _ = writeln!(self.0, "# HELP {name} {help}");
        let _ = writeln!(self.0, "# TYPE {name} {kind}");
    }

    /// A sample of the family `name`, under the labels `labels` (name and value).
    fn sample(&mut self, name: &str, labels: &[(&str, &str)], value: impl Display) {
        self.0.push_str(name);
        if !labels.is_empty() {
            let list: Vec<String> = labels
                .iter()
                .map(|(key, text)| format!("{key}=\"{}\"", escaped(text)))
                .collect();
            let _ = write!(self.0, "{{{}}}", list.join(","));
        }
        let _ = writeln!(self.0, " {value}");
    }

    /// A family of one sample with no labels.
    fn single(&mut self, name: &str, kind: &str, help: &str, value: impl Display) {
        self.family(name, kind, help);
        self.sample(name, &[], value);
    }

    /// A family of one sample for each label in `samples`.
    fn labelled(&mut self, name: &str, help: &str, label: &str, samples: &[(&str, u64)]) {
        self.family(name, "counter", help);
        for &(text, count) in samples {
            self.sample(name, &[(label, text)], count);
        }
    }
}

/// The page for `scrape`.
pub(super) fn render(scrape: &Scrape<'_>) -> String {
    let counters = scrape.counters;
    let state = &scrape.state;
    let mut page = Page(String::new());
    page.labelled(
        "tukuyomi_requests_total",
        "Answers written to clients, by class.",
        "class",
        &counters.requests.samples(),
    );
    page.labelled(
        "tukuyomi_waf_rule_hits_total",
        "Requests that a rule decided, by what the rule did.",
        "decision",
        &counters.rule_hits.samples(),
    );
    page.labelled(
        "tukuyomi_uninspectable_total",
        "Requests that could not be inspected, by the reason the kernel gave.",
        "reason",
        &counters.uninspectable.samples(),
    );
    page.labelled(
        "tukuyomi_policy_refusals_total",
        "Requests turned away before their route was looked for, by what turned them away.",
        "policy",
        &counters.policy_refusals.samples(),
    );
    page.single(
        "tukuyomi_rate_limit_keys",
        "gauge",
        "Clients that the rate limit counts now.",
        scrape.rate_limit_keys,
    );
    page.single(
        "tukuyomi_rate_limit_evicted_total",
        "counter",
        "Clients dropped from the rate limit to make room while their count was still in force.",
        scrape.rate_limit_evicted,
    );
    page.single(
        "tukuyomi_connections_accepted_total",
        "counter",
        "Connections accepted.",
        counters.accepted.get(),
    );
    page.single(
        "tukuyomi_connections_open",
        "gauge",
        "Connections that are open.",
        scrape.connections_open,
    );
    page.single(
        "tukuyomi_connection_permit_waits_total",
        "counter",
        "Times a connection had to wait for a permit.",
        scrape.permit_waits,
    );
    page.single(
        "tukuyomi_tls_handshake_failures_total",
        "counter",
        "TLS handshakes that failed or were not finished in time.",
        counters.tls_failures.get(),
    );
    page.single(
        "tukuyomi_body_buffer_bytes",
        "gauge",
        "Bytes of the byte budget for request bodies in use.",
        scrape.body_buffer_bytes,
    );
    page.single(
        "tukuyomi_inspections_waiting",
        "gauge",
        "Inspections that hold a place in the waiting queue.",
        scrape.inspections_waiting,
    );
    page.single(
        "tukuyomi_inspector_up",
        "gauge",
        "1 if the kernel that serves is ready, otherwise 0.",
        u8::from(state.phase == Phase::Ready),
    );
    page.single(
        "tukuyomi_inspector_restarts_total",
        "counter",
        "Restarts of the inspector since the start.",
        state.restarts,
    );
    page.family(
        "tukuyomi_rules_generation_info",
        "gauge",
        "The generation of the rules that serves (first 16 digits) and what its rules do; always 1.",
    );
    let generation = state.generation.hex();
    page.sample(
        "tukuyomi_rules_generation_info",
        &[
            ("generation", generation.get(..16).unwrap_or(&generation)),
            ("mode", state.mode.name()),
        ],
        1,
    );
    page.labelled(
        "tukuyomi_rules_switches_total",
        "Switches to another generation of the rules, by how they ended.",
        "result",
        &counters.switches.samples(),
    );
    page.labelled(
        "tukuyomi_certificate_reloads_total",
        "Readings of the certificate files again, by how they ended.",
        "result",
        &counters.reloads.samples(),
    );
    page.labelled(
        "tukuyomi_upstream_failures_total",
        "Failures of the servers of an upstream group.",
        "group",
        &scrape.upstream_failures,
    );
    page.single(
        "tukuyomi_records_dropped_total",
        "counter",
        "Records dropped because the queue was full, there was no logger, or the line was too long.",
        scrape.records_dropped,
    );
    page.single(
        "tukuyomi_record_write_errors_total",
        "counter",
        "Records that could not be written.",
        scrape.record_write_errors,
    );
    page.single(
        "tukuyomi_record_file_errors_total",
        "counter",
        "Records that could not be written to the record file.",
        scrape.record_file_errors,
    );
    page.single(
        "tukuyomi_start_time_seconds",
        "gauge",
        "When the process started, in seconds since the epoch of Unix time.",
        counters.started(),
    );
    page.0
}

#[cfg(test)]
mod tests;
