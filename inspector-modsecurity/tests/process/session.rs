//! The end of a session when the connection is lost.

use crate::support::{KIND_TX_BEGIN, Options, frame, start, tx_begin_payload};

// A connection that is lost before anything else ends the session with 12.
#[test]
fn a_lost_connection_ends_the_session_with_12() {
    let mut p = start(Options::default());
    p.hello();
    p.conn = None;
    assert_eq!(p.code(), 12);
    let text = p.stderr_text();
    assert!(text.contains("exit=12 started=0 closed=0"), "{text}");
}

// A transaction that is open when the connection is lost is closed, and the session still ends with 12.
#[test]
fn a_lost_connection_closes_an_open_transaction_and_ends_with_12() {
    let mut p = start(Options::default());
    p.hello();
    p.send(&frame(KIND_TX_BEGIN, 1, 1, &tx_begin_payload()));
    // The process has taken the transaction when it answers the frame; the answer is not looked at.
    let answer = p.recv().expect("an answer to TX_BEGIN");
    assert_eq!(answer.tx(), 1);
    p.conn = None;
    assert_eq!(p.code(), 12);
    let text = p.stderr_text();
    assert!(text.contains("exit=12 started=1 closed=1"), "{text}");
}
