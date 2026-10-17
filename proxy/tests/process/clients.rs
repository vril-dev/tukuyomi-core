use std::net::TcpStream;
use std::time::{Duration, Instant};

use crate::support::*;

#[test]
#[ignore = "needs a built inspector"]
fn a_client_that_goes_away_during_the_inspection_causes_no_upstream_connection() {
    // One slot: the next request can only be inspected when the slot of the abandoned one is free again.
    let knobs = Knobs {
        slots: 1,
        wait_deadline_ms: 20_000,
        ..Knobs::slow()
    };
    let proxy = Proxy::start("client_gone", knobs);
    // Exactly the declared bytes and nothing after them, so the proxy sees the close.
    let sock = proxy.start_slow(&post_form("/submit", &padded_form("ok", MAX_BODY)));
    let gone = Instant::now();
    drop(sock);
    proxy
        .records
        .conn("the record of the abandoned connection", |l| {
            l.contains(": closed 0 ")
        });
    // The connection ended long before the inspection could have (it needs several seconds).
    assert!(gone.elapsed() < 3 * SEC, "took {:?}", gone.elapsed());
    assert_eq!(proxy.upstream.connections(), 0);

    let after = exchange(proxy.port, &get("/after"));
    assert_eq!(after.status(), 200, "answer: {:?}", after.text());
    assert_eq!(proxy.finish(1), StopCounts::NONE);
}

// ---------------------------------------------------------------------------------------------------------
// A client that resets
// ---------------------------------------------------------------------------------------------------------

/// Closes the socket with an RST, not a FIN: `SO_LINGER` with a time of zero. The standard library cannot set
/// it, so tokio does that for the one call. The socket is dropped while the runtime is still there.
fn reset(sock: TcpStream) {
    sock.set_nonblocking(true)
        .expect("make the client socket non-blocking");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .expect("build a runtime for the client socket");
    let _entered = runtime.enter();
    let sock = tokio::net::TcpStream::from_std(sock).expect("hand the client socket to tokio");
    sock.set_zero_linger().expect("set SO_LINGER to zero");
    assert_eq!(
        sock.linger().expect("read SO_LINGER back"),
        Some(Duration::ZERO)
    );
    drop(sock);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_client_that_resets_during_the_inspection_causes_no_upstream_connection() {
    // One slot: the next request can only be inspected when the slot of the abandoned one is free again.
    let knobs = Knobs {
        slots: 1,
        wait_deadline_ms: 20_000,
        ..Knobs::slow()
    };
    let proxy = Proxy::start("client_reset", knobs);
    let sock = proxy.start_slow(&post_form("/submit", &padded_form("ok", MAX_BODY)));
    let gone = Instant::now();
    reset(sock);
    proxy
        .records
        .conn("the record of the reset connection", |l| {
            l.contains(": closed 0 ")
        });
    // The connection ended long before the inspection could have (it needs several seconds).
    assert!(gone.elapsed() < 3 * SEC, "took {:?}", gone.elapsed());
    assert_eq!(proxy.upstream.connections(), 0);

    let after = exchange(proxy.port, &get("/after"));
    assert_eq!(after.status(), 200, "answer: {:?}", after.text());
    assert_eq!(proxy.finish(1), StopCounts::NONE);
}
