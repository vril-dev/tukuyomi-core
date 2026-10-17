use crate::support::*;

#[test]
#[ignore = "needs a built inspector"]
fn transfer_encoding_with_content_length_gives_400_and_no_upstream_connection() {
    let proxy = Proxy::start("te_and_cl", Knobs::quick());
    // Both orders: the second is the one that a parser which drops the length after the coding would hide.
    for fields in [
        "Transfer-Encoding: chunked\r\nContent-Length: 11\r\n",
        "Content-Length: 11\r\nTransfer-Encoding: chunked\r\n",
    ] {
        let request = format!(
            "POST /x HTTP/1.1\r\nHost: example.test\r\nContent-Type: {URLENCODED}\r\n{fields}\r\nb\r\nprobe=block\r\n0\r\n\r\n"
        );
        let reply = exchange(proxy.port, request.as_bytes());
        assert_empty_answer(&reply, 400);
    }
    proxy.records.conns("two malformed-head records", 2, |l| {
        l.contains(": rejected 400 malformed request head ")
    });
    assert_eq!(proxy.upstream.connections(), 0);
    proxy.finish(0);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_content_length_over_the_limit_gives_413_and_no_100_continue() {
    let proxy = Proxy::start("too_large", Knobs::quick());
    // Over the limit by one byte: the answer is 413 at once, and no 100 Continue is sent for a body that
    // cannot be taken.
    let head = format!(
        "POST /big HTTP/1.1\r\nHost: example.test\r\nContent-Type: {URLENCODED}\r\nContent-Length: {}\r\nExpect: 100-continue\r\n\r\n",
        MAX_BODY + 1
    );
    let refused = exchange(proxy.port, head.as_bytes());
    assert!(
        !refused.text().contains("100 Continue"),
        "answer: {:?}",
        refused.text()
    );
    assert_empty_answer(&refused, 413);
    proxy.records.conn("the 413 record", |l| {
        l.contains(": rejected 413 body over the limit ")
    });
    assert_eq!(proxy.upstream.connections(), 0);
    proxy.finish(0);
}
