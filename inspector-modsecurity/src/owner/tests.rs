use super::*;
use crate::codec::{
    CLASS_NOT_CREATED, CLASS_TX_FAILED, CODE_BAD_BEGIN, CODE_BAD_VERDICT, CODE_DRAINING,
    CODE_INCOMPLETE, CODE_LIMIT, CODE_ORDER, CODE_REQ_OVER, CODE_REQ_TRUNCATED, CODE_REQ_WRITE,
    CODE_UNSTARTED, KIND_BODY, KIND_BODY_END, KIND_TX_BEGIN, KIND_TX_END,
};
use crate::testkit::{
    Fake, INC, Log, RUN, Script, begin_payload, expect_closed, expect_error, expect_verdict, header,
};
use std::sync::{Arc, Mutex};

fn table(script: Script) -> (Table<Fake>, Arc<Mutex<Log>>) {
    let (fake, log) = Fake::new(script);
    (Table::new(fake, RUN, INC), log)
}

fn begin(t: &mut Table<Fake>, tx: u64, declared: u64) -> Option<Vec<u8>> {
    t.dispatch(&header(KIND_TX_BEGIN, tx, 1), &begin_payload(declared))
}

fn frame(t: &mut Table<Fake>, kind: u8, tx: u64, msg: u32, payload: &[u8]) -> Option<Vec<u8>> {
    t.dispatch(&header(kind, tx, msg), payload)
}

fn end(t: &mut Table<Fake>, tx: u64, msg: u32) -> Option<Vec<u8>> {
    frame(t, KIND_TX_END, tx, msg, &[1])
}

#[test]
fn a_request_goes_through_and_tx_end_is_answered_with_closed() {
    let (mut t, log) = table(Script::default());
    expect_verdict(begin(&mut t, 1, 5), 1, 1, 1, false);
    assert!(frame(&mut t, KIND_BODY, 1, 2, b"a=b").is_none());
    assert!(frame(&mut t, KIND_BODY, 1, 3, b"&c").is_none()); // 3 + 2: exactly the declared 5
    expect_verdict(frame(&mut t, KIND_BODY_END, 1, 4, b""), 1, 4, 2, false);
    expect_closed(end(&mut t, 1, 5), 1, 5, false);
    {
        let l = log.lock().unwrap();
        assert_eq!(l.begins, [b"/a?q=1".to_vec()]);
        assert_eq!(l.bodies, [b"a=b".to_vec(), b"&c".to_vec()]);
        assert_eq!((l.ends, l.closes), (1, 1));
    }
    let counts = Counts {
        started: 1,
        closed: 1,
        ..Counts::default()
    };
    assert_eq!(t.counts(), counts);
    // The id is used: what comes for it later is discarded.
    assert!(frame(&mut t, KIND_BODY, 1, 6, b"x").is_none());
    assert_eq!(t.counts().discarded, 1);
}

#[test]
fn the_fifth_transaction_is_refused_and_a_place_comes_back_with_closed() {
    let (mut t, _) = table(Script::default());
    for id in 1..=4 {
        expect_verdict(begin(&mut t, id, 0), id, 1, 1, false);
    }
    expect_error(begin(&mut t, 5, 0), 5, 1, CLASS_NOT_CREATED, CODE_LIMIT);
    // The id was used by the ERROR.
    assert!(frame(&mut t, KIND_BODY_END, 5, 2, b"").is_none());
    assert_eq!((t.counts().started, t.counts().discarded), (4, 1));
    expect_closed(end(&mut t, 2, 2), 2, 2, false);
    expect_verdict(begin(&mut t, 6, 0), 6, 1, 1, false);
}

#[test]
fn after_drain_no_transaction_is_taken_and_the_open_ones_finish() {
    let (mut t, _) = table(Script::default());
    expect_verdict(begin(&mut t, 1, 0), 1, 1, 1, false);
    assert!(t.start_drain());
    assert!(!t.start_drain());
    expect_error(begin(&mut t, 2, 0), 2, 1, CLASS_NOT_CREATED, CODE_DRAINING);
    assert!(!t.is_drained());
    expect_verdict(frame(&mut t, KIND_BODY_END, 1, 2, b""), 1, 2, 2, false);
    expect_closed(end(&mut t, 1, 3), 1, 3, false);
    assert!(t.is_drained());
    assert_eq!(
        (
            t.counts().started,
            t.counts().closed,
            t.counts().close_errors
        ),
        (1, 1, 0)
    );
}

#[test]
fn a_message_number_gap_fails_the_transaction_once() {
    let (mut t, log) = table(Script::default());
    expect_verdict(begin(&mut t, 1, 5), 1, 1, 1, false);
    expect_error(
        frame(&mut t, KIND_BODY, 1, 3, b"abcde"),
        1,
        3,
        CLASS_TX_FAILED,
        CODE_ORDER,
    );
    // The frame with the wrong number did not reach the inspection, and what follows is discarded.
    assert!(log.lock().unwrap().bodies.is_empty());
    assert!(frame(&mut t, KIND_BODY, 1, 4, b"abcde").is_none());
    assert!(frame(&mut t, KIND_BODY_END, 1, 5, b"").is_none());
    assert_eq!(t.counts().discarded, 2);
    expect_closed(end(&mut t, 1, 6), 1, 6, false);
    // A repeated number is a gap too.
    expect_verdict(begin(&mut t, 2, 5), 2, 1, 1, false);
    expect_error(
        frame(&mut t, KIND_BODY, 2, 1, b"a"),
        2,
        1,
        CLASS_TX_FAILED,
        CODE_ORDER,
    );
}

#[test]
fn the_declared_length_is_the_limit_of_the_body() {
    let (mut t, log) = table(Script::default());
    // Exactly the declared bytes, in one part.
    expect_verdict(begin(&mut t, 1, 5), 1, 1, 1, false);
    assert!(frame(&mut t, KIND_BODY, 1, 2, b"abcde").is_none());
    expect_verdict(frame(&mut t, KIND_BODY_END, 1, 3, b""), 1, 3, 2, false);
    // One byte past it: refused before the inspection sees the part.
    expect_verdict(begin(&mut t, 2, 5), 2, 1, 1, false);
    expect_error(
        frame(&mut t, KIND_BODY, 2, 2, b"abcdef"),
        2,
        2,
        CLASS_TX_FAILED,
        CODE_REQ_OVER,
    );
    assert_eq!(log.lock().unwrap().bodies.len(), 1);
    // One byte short at BODY_END.
    expect_verdict(begin(&mut t, 3, 5), 3, 1, 1, false);
    assert!(frame(&mut t, KIND_BODY, 3, 2, b"abcd").is_none());
    expect_error(
        frame(&mut t, KIND_BODY_END, 3, 3, b""),
        3,
        3,
        CLASS_TX_FAILED,
        CODE_REQ_TRUNCATED,
    );
    assert_eq!(log.lock().unwrap().ends, 1);
}

#[test]
fn a_block_in_the_body_discards_what_follows() {
    let script = Script {
        block_at_body: Some(1),
        ..Script::default()
    };
    let (mut t, log) = table(script);
    expect_verdict(begin(&mut t, 1, 10), 1, 1, 1, false);
    expect_verdict(frame(&mut t, KIND_BODY, 1, 2, b"abcde"), 1, 2, 2, true);
    assert!(frame(&mut t, KIND_BODY, 1, 3, b"fghij").is_none());
    assert!(frame(&mut t, KIND_BODY_END, 1, 4, b"").is_none());
    assert_eq!(t.counts().discarded, 2);
    expect_closed(end(&mut t, 1, 5), 1, 5, false);
    let l = log.lock().unwrap();
    assert_eq!((l.bodies.len(), l.ends, l.closes), (1, 0, 1));
}

#[test]
fn a_fault_of_the_inspection_or_a_verdict_that_cannot_be_written_is_an_error() {
    // The status 70000 does not fit a VERDICT.
    let script = Script {
        end_status: Some(70_000),
        ..Script::default()
    };
    let (mut t, _) = table(script);
    expect_verdict(begin(&mut t, 1, 0), 1, 1, 1, false);
    expect_error(
        frame(&mut t, KIND_BODY_END, 1, 2, b""),
        1,
        2,
        CLASS_TX_FAILED,
        CODE_BAD_VERDICT,
    );
    // A fault of the inspection reports its own code, once.
    let script = Script {
        body_fault: true,
        ..Script::default()
    };
    let (mut t, _) = table(script);
    expect_verdict(begin(&mut t, 1, 5), 1, 1, 1, false);
    expect_error(
        frame(&mut t, KIND_BODY, 1, 2, b"abc"),
        1,
        2,
        CLASS_TX_FAILED,
        CODE_REQ_WRITE,
    );
    assert!(frame(&mut t, KIND_BODY, 1, 3, b"de").is_none());
    // An inspection that cannot be made fails at TX_BEGIN, and TX_END still frees the place.
    let script = Script {
        start_fault: true,
        ..Script::default()
    };
    let (mut t, log) = table(script);
    expect_error(begin(&mut t, 1, 0), 1, 1, CLASS_TX_FAILED, CODE_INCOMPLETE);
    expect_closed(end(&mut t, 1, 2), 1, 2, false);
    assert_eq!(log.lock().unwrap().closes, 0);
    assert_eq!((t.counts().started, t.counts().closed), (1, 1));
}

#[test]
fn a_frame_for_an_id_that_was_never_started_is_not_created() {
    let (mut t, _) = table(Script::default());
    expect_error(
        frame(&mut t, KIND_BODY, 7, 2, b"x"),
        7,
        2,
        CLASS_NOT_CREATED,
        CODE_UNSTARTED,
    );
    // Ids go up: a lower id is never new, not even for a TX_BEGIN.
    assert!(begin(&mut t, 3, 0).is_none());
    assert_eq!((t.counts().started, t.counts().discarded), (0, 1));
    expect_verdict(begin(&mut t, 8, 0), 8, 1, 1, false);
}

#[test]
fn a_tx_begin_must_be_message_1_with_a_payload_that_decodes() {
    let (mut t, _) = table(Script::default());
    expect_error(
        t.dispatch(&header(KIND_TX_BEGIN, 1, 2), &begin_payload(0)),
        1,
        2,
        CLASS_NOT_CREATED,
        CODE_BAD_BEGIN,
    );
    expect_error(
        t.dispatch(&header(KIND_TX_BEGIN, 2, 1), b"garbage"),
        2,
        1,
        CLASS_NOT_CREATED,
        CODE_BAD_BEGIN,
    );
    // A cut body has declared bytes.
    let mut cut = header(KIND_TX_BEGIN, 3, 1);
    cut.cut = true;
    expect_error(
        t.dispatch(&cut, &begin_payload(0)),
        3,
        1,
        CLASS_NOT_CREATED,
        CODE_BAD_BEGIN,
    );
    cut.tx = 4;
    expect_verdict(t.dispatch(&cut, &begin_payload(5)), 4, 1, 1, false);
}

#[test]
fn a_second_tx_begin_for_an_active_id_is_an_order_error() {
    let (mut t, _) = table(Script::default());
    expect_verdict(begin(&mut t, 1, 0), 1, 1, 1, false);
    expect_error(
        frame(&mut t, KIND_TX_BEGIN, 1, 2, &begin_payload(0)),
        1,
        2,
        CLASS_TX_FAILED,
        CODE_ORDER,
    );
}

#[test]
fn a_close_error_is_reported_and_counted_and_a_bad_reason_still_closes() {
    let script = Script {
        close_error: true,
        ..Script::default()
    };
    let (mut t, _) = table(script);
    expect_verdict(begin(&mut t, 1, 0), 1, 1, 1, false);
    expect_closed(frame(&mut t, KIND_TX_END, 1, 2, &[9]), 1, 2, true);
    let c = t.counts();
    assert_eq!((c.closed, c.close_errors, c.bad_tx_end), (1, 1, 1));
}

#[test]
fn a_lost_connection_closes_every_transaction_without_closed() {
    let (mut t, log) = table(Script::default());
    expect_verdict(begin(&mut t, 1, 0), 1, 1, 1, false);
    expect_verdict(begin(&mut t, 2, 0), 2, 1, 1, false);
    t.connection_lost();
    assert_eq!(log.lock().unwrap().closes, 2);
    assert_eq!((t.counts().started, t.counts().closed), (2, 2));
}

#[test]
fn a_blocked_or_a_failed_transaction_is_closed_once() {
    let script = Script {
        end_status: Some(403),
        body_fault: true,
        ..Script::default()
    };
    // Transaction 1 is blocked at the end of the request, 2 fails on its body.
    let open = |t: &mut Table<Fake>| {
        expect_verdict(begin(t, 1, 0), 1, 1, 1, false);
        expect_verdict(frame(t, KIND_BODY_END, 1, 2, b""), 1, 2, 2, true);
        expect_verdict(begin(t, 2, 5), 2, 1, 1, false);
        expect_error(
            frame(t, KIND_BODY, 2, 2, b"abc"),
            2,
            2,
            CLASS_TX_FAILED,
            CODE_REQ_WRITE,
        );
    };
    // TX_END closes each of them once.
    let (mut t, log) = table(script);
    open(&mut t);
    expect_closed(end(&mut t, 1, 3), 1, 3, false);
    assert_eq!(log.lock().unwrap().closes, 1);
    expect_closed(end(&mut t, 2, 3), 2, 3, false);
    assert_eq!(log.lock().unwrap().closes, 2);
    assert_eq!((t.counts().started, t.counts().closed), (2, 2));
    // So does the loss of the connection.
    let (mut t, log) = table(script);
    open(&mut t);
    t.connection_lost();
    assert_eq!(log.lock().unwrap().closes, 2);
    assert_eq!((t.counts().started, t.counts().closed), (2, 2));
}
