use crate::support::*;

#[test]
#[ignore = "needs a built inspector"]
fn sigterm_lets_an_in_flight_request_finish_and_the_proxy_exits_within_stop_wait() {
    let proxy = Proxy::start("sigterm_in_flight", Knobs::slow());
    let mut sock = proxy.start_slow(&post_form("/submit", &padded_form("ok", MAX_BODY)));
    let since = proxy.term();

    // The inspection goes on after the signal, the request is forwarded, and its answer comes back whole.
    let answer = collect(&mut sock, since);
    assert_eq!(answer.status(), 200, "answer: {:?}", answer.text());
    assert_eq!(answer.message().body, UPSTREAM_BODY.as_bytes());
    let requests = proxy.upstream.requests();
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0].len() > MAX_BODY,
        "the upstream got {} bytes",
        requests[0].len()
    );

    let counts = proxy.finish_after_term(since, 1);
    assert!(
        counts[0] >= 1,
        "the request was in flight when the stop began: {counts:?}"
    );
}
