use std::time::Instant;

use crate::support::*;

#[test]
#[ignore = "needs a built inspector"]
fn killing_the_inspector_during_an_inspection_gives_503_and_no_upstream_connection() {
    // One restart in the budget: without it the kernel would give up, and the proxy would stop on that failure.
    let knobs = Knobs {
        restarts: 1,
        ..Knobs::slow()
    };
    let mut proxy = Proxy::start("kill_inspector", knobs);
    let victim = proxy.inspector();
    let mut sock = proxy.start_slow(&post_form("/submit", &padded_form("ok", MAX_BODY)));
    run_kill("KILL", victim);
    let answer = collect(&mut sock, Instant::now());
    assert_empty_answer(&answer, 503);
    proxy
        .records
        .conn("the 503 record", |l| l.contains(": failed 503 inspector "));
    assert_eq!(proxy.upstream.connections(), 0);

    // The kernel started a new inspector, and a normal request passes through it.
    let after = exchange(proxy.port, &get("/after"));
    assert_eq!(after.status(), 200, "answer: {:?}", after.text());
    let replacement = proxy.wait_inspector(Some(victim));
    assert_ne!(replacement, victim);
    proxy.finish(1);
}
