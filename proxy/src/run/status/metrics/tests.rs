use std::collections::HashSet;

use tukuyomi_kernel::Reason;

use super::*;
use crate::log::counters::RuleHit;
use crate::rules::bundle::{Fingerprint, Mode};

fn scrape<'a>(counters: &'a Counters, groups: Vec<(&'a str, u64)>) -> Scrape<'a> {
    Scrape {
        counters,
        state: State {
            phase: Phase::Ready,
            restarts: 3,
            generation: Fingerprint::from_hex(&[b'a'; 64]).unwrap(),
            mode: Mode::Detect,
        },
        connections_open: 2,
        permit_waits: 5,
        body_buffer_bytes: 4096,
        inspections_waiting: 1,
        upstream_failures: groups,
        records_dropped: 7,
        record_write_errors: 8,
        record_file_errors: 9,
    }
}

#[test]
fn a_label_value_has_the_backslash_the_quote_and_the_line_feed_escaped() {
    assert_eq!(escaped("a\\b\"c\nd"), "a\\\\b\\\"c\\nd");
    assert_eq!(escaped("plain-name_1"), "plain-name_1");

    let counters = Counters::start();
    let text = render(&scrape(&counters, vec![("a\"b\\c\nd", 3)]));
    assert!(
        text.contains("tukuyomi_upstream_failures_total{group=\"a\\\"b\\\\c\\nd\"} 3\n"),
        "{text}"
    );
    // The escaped value is one line.
    assert!(text.lines().all(|line| !line.is_empty()));
}

#[test]
fn every_family_has_its_help_and_type_once_and_its_samples_follow_them() {
    let counters = Counters::start();
    counters.add_request("forwarded");
    counters.add_request("blocked");
    counters.add_rule_hit(RuleHit::Block);
    counters.add_uninspectable(Reason::InspectorLost);
    counters.accepted.add();
    let text = render(&scrape(&counters, vec![("main", 0), ("api", 2)]));

    let mut families = HashSet::new();
    let mut current = "";
    let mut samples = 0;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("# HELP ") {
            let name = rest.split(' ').next().unwrap();
            assert!(families.insert(name.to_string()), "{name} twice");
            current = name;
        } else if let Some(rest) = line.strip_prefix("# TYPE ") {
            let (name, kind) = rest.split_once(' ').unwrap();
            assert_eq!(name, current, "TYPE does not follow its HELP");
            assert!(kind == "counter" || kind == "gauge", "{line}");
        } else {
            // A sample belongs to the family whose lines came last.
            let name = line.split(['{', ' ']).next().unwrap();
            assert_eq!(name, current, "{line}");
            samples += 1;
        }
    }
    assert_eq!(families.len(), 19);
    assert!(samples >= 19, "{samples}");

    for line in [
        "tukuyomi_requests_total{class=\"forwarded\"} 1",
        "tukuyomi_requests_total{class=\"blocked\"} 1",
        "tukuyomi_requests_total{class=\"closed\"} 0",
        "tukuyomi_waf_rule_hits_total{decision=\"block\"} 1",
        "tukuyomi_uninspectable_total{reason=\"inspector_lost\"} 1",
        "tukuyomi_connections_accepted_total 1",
        "tukuyomi_connections_open 2",
        "tukuyomi_connection_permit_waits_total 5",
        "tukuyomi_body_buffer_bytes 4096",
        "tukuyomi_inspections_waiting 1",
        "tukuyomi_inspector_up 1",
        "tukuyomi_inspector_restarts_total 3",
        "tukuyomi_rules_generation_info{generation=\"aaaaaaaaaaaaaaaa\",mode=\"detect\"} 1",
        "tukuyomi_upstream_failures_total{group=\"api\"} 2",
        "tukuyomi_records_dropped_total 7",
        "tukuyomi_record_write_errors_total 8",
        "tukuyomi_record_file_errors_total 9",
    ] {
        assert!(text.lines().any(|have| have == line), "{line} in {text}");
    }
}

#[test]
fn the_inspector_is_up_only_in_the_phase_ready() {
    let counters = Counters::start();
    let mut seen = scrape(&counters, Vec::new());
    seen.state.phase = Phase::Starting;
    assert!(render(&seen).contains("\ntukuyomi_inspector_up 0\n"));
}
