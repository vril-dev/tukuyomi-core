use super::*;

#[test]
fn every_reason_of_the_kernel_is_counted_under_a_word_of_its_own() {
    let counters = Counters::start();
    for reason in [
        Reason::Invalid,
        Reason::QueueFull,
        Reason::Unavailable,
        Reason::WaitDeadline,
        Reason::VerdictDeadline,
        Reason::InspectorLost,
        Reason::Protocol,
        Reason::InspectorError { code: 7 },
        Reason::NotCreated { code: 9 },
        Reason::Cancelled,
    ] {
        counters.add_uninspectable(reason);
    }
    // Ten reasons, ten words, each counted once, whatever code a reason carried.
    let samples = counters.uninspectable.samples();
    assert!(samples.iter().all(|&(_, count)| count == 1), "{samples:?}");
}

#[test]
fn a_label_outside_its_list_is_not_counted() {
    let counters = Counters::start();
    counters.add_request("forwarded");
    counters.add_request("forwarded");
    counters.add_request("not a class");
    counters.add_rule_hit(RuleHit::Detect);
    counters.add_switch(SwitchResult::Refused);
    counters.add_reload(ReloadResult::Replaced);
    counters.add_config_reload(ReloadResult::Refused);
    let requests = counters.requests.samples();
    assert_eq!(requests[0], ("forwarded", 2));
    assert_eq!(counters.requests.total(), 2);
    assert_eq!(counters.rule_hits.samples(), [("block", 0), ("detect", 1)]);
    assert_eq!(
        counters.switches.samples(),
        [("switched", 0), ("refused", 1), ("failed", 0)]
    );
    assert_eq!(
        counters.reloads.samples(),
        [("replaced", 1), ("refused", 0)]
    );
    assert_eq!(
        counters.config_reloads.samples(),
        [("replaced", 0), ("refused", 1)]
    );
    assert_eq!(
        (counters.accepted.get(), counters.tls_failures.get()),
        (0, 0)
    );
    assert!(counters.started() > 0);
}

#[test]
fn the_sums_and_the_counts_that_the_control_socket_gives_are_read_from_the_families() {
    let counters = Counters::start();
    for class in ["forwarded", "forwarded", "blocked", "failed"] {
        counters.add_request(class);
    }
    counters.add_rule_hit(RuleHit::Block);
    counters.add_rule_hit(RuleHit::Detect);
    counters.add_rule_hit(RuleHit::Detect);
    counters.add_policy_refusal(Policy::Access);
    counters.add_policy_refusal(Policy::RateLimit);
    counters.add_policy_refusal(Policy::RateLimit);
    counters.add_config_reload(ReloadResult::Replaced);
    counters.add_config_reload(ReloadResult::Refused);
    counters.add_config_reload(ReloadResult::Refused);
    assert_eq!(counters.requests.total(), 4);
    assert_eq!(counters.requests.get("forwarded"), 2);
    assert_eq!(counters.requests.get("not a class"), 0);
    // Only the requests that a rule blocked, not those it let through.
    assert_eq!(counters.blocked(), 1);
    assert_eq!(counters.policy_refusals.total(), 3);
    assert_eq!(counters.config_reloaded(ReloadResult::Replaced), 1);
    assert_eq!(counters.config_reloaded(ReloadResult::Refused), 2);
    assert!(counters.uptime() < Duration::from_secs(60));
}

#[test]
fn the_open_connections_rise_with_each_one_counted_and_fall_when_it_is_dropped() {
    let counters = Counters::start();
    assert_eq!(counters.open.get(), 0);
    let first = counters.open.count();
    assert_eq!(counters.open.get(), 1);
    let second = counters.open.count();
    assert_eq!(counters.open.get(), 2);
    drop(first);
    assert_eq!(counters.open.get(), 1);
    drop(second);
    assert_eq!(counters.open.get(), 0);

    // A task that panics gives its count back as well.
    let open = counters.open.clone();
    let panicked = std::thread::spawn(move || {
        let _counted = open.count();
        panic!("the connection fails");
    })
    .join();
    assert!(panicked.is_err());
    assert_eq!(counters.open.get(), 0);
}
