use std::io::Write;
use std::time::Instant;

use crate::support::*;

#[test]
#[ignore = "needs a built inspector"]
fn the_head_deadline_gives_408_and_the_connection_permits_come_back() {
    let knobs = Knobs {
        max_conns: 2,
        head_read_ms: 1_500,
        ..Knobs::quick()
    };
    let proxy = Proxy::start("head_deadline", knobs);
    // Two connections that never finish their head hold both permits.
    let partial = b"GET /slow HTTP/1.1\r\nHost: example.test\r\n";
    let started = Instant::now();
    let mut a = connect(proxy.port);
    a.write_all(partial).expect("send half a head");
    let mut b = connect(proxy.port);
    b.write_all(partial).expect("send half a head");

    // A third request is not accepted before a permit is back, so it is answered only after the deadline.
    let third = exchange(proxy.port, &get("/third"));
    assert_eq!(third.status(), 200, "answer: {:?}", third.text());
    assert!(
        third.took >= SEC,
        "the third request was answered after {:?}; it should have waited for a permit",
        third.took
    );
    for sock in [&mut a, &mut b] {
        let late = collect(sock, started);
        assert_empty_answer(&late, 408);
        assert!(late.took >= SEC, "408 after {:?}", late.took);
    }
    proxy.records.conns("two head-deadline records", 2, |l| {
        is_answer(l, "rejected", 408, "head not received in time")
    });
    proxy.finish(1);
}
