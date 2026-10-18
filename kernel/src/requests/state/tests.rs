use super::*;

fn limits() -> Limits {
    Limits {
        slots: 4,
        wait_queue: 8,
        records: 64,
        discard_limit: 64,
        verdict_wait: Duration::from_secs(2),
        wait_deadline: Duration::from_secs(3),
        closed_wait: Duration::from_secs(2),
        stop_after: Duration::from_secs(6),
    }
}

fn request() -> Request {
    Request {
        begin: vec![1, 2, 3],
        body: vec![vec![b'a'; 4], vec![b'b'; 5]],
    }
}

fn at(t0: Instant, ms: u64) -> Instant {
    t0 + Duration::from_millis(ms)
}

/// An engine after HELLO (inc 1, first transaction 100) and the base time.
fn start() -> (Engine, Instant) {
    let t0 = Instant::now();
    let mut e = Engine::new(limits(), 1, 100);
    e.ready(t0, 1);
    (e, t0)
}

fn take(e: &mut Engine, now: Instant) -> Outgoing {
    e.next_frame(now).expect("a frame")
}

fn drain(e: &mut Engine, now: Instant) -> Vec<(u64, u32, OutKind)> {
    let mut v = Vec::new();
    while let Some(f) = e.next_frame(now) {
        v.push((f.tx, f.msg, f.kind));
    }
    v
}

/// The writer queue holds exactly TX_END: its message number and reason.
fn only_end(e: &mut Engine, now: Instant) -> (u32, u8) {
    let v = drain(e, now);
    match v.as_slice() {
        [(_, msg, OutKind::TxEnd(reason))] => (*msg, *reason),
        other => panic!("expected only TX_END, got {other:?}"),
    }
}

fn cont(e: &mut Engine, now: Instant, tx: u64, msg: u32, phase: u8) -> Result<(), ConnFault> {
    e.on_verdict(
        now,
        tx,
        msg,
        phase,
        false,
        false,
        0,
        0,
        &[phase, 0, msg as u8],
    )
}

fn blk(e: &mut Engine, now: Instant, tx: u64, msg: u32, phase: u8) -> Result<(), ConnFault> {
    e.on_verdict(
        now,
        tx,
        msg,
        phase,
        true,
        false,
        949110,
        403,
        &[phase, 1, msg as u8],
    )
}

/// A continue of phase 2 that carries a match the rules only detected.
fn det(e: &mut Engine, now: Instant, tx: u64, msg: u32) -> Result<(), ConnFault> {
    e.on_verdict(
        now,
        tx,
        msg,
        2,
        false,
        true,
        949110,
        403,
        &[2, 0, msg as u8, 4],
    )
}

fn blocked(phase: u8) -> Decision {
    Decision::Block {
        phase,
        rule_id: 949110,
        status: 403,
    }
}

fn detected() -> Decision {
    Decision::Detected {
        rule_id: 949110,
        status: 403,
    }
}

/// "Not created" (class 1).
fn nc(e: &mut Engine, now: Instant, tx: u64, msg: u32) -> Result<(), ConnFault> {
    e.on_error(now, tx, msg, 1, 1, &[1, 1, msg as u8])
}

/// Failure of a created transaction (class 2).
fn txerr(e: &mut Engine, now: Instant, tx: u64, msg: u32) -> Result<(), ConnFault> {
    e.on_error(now, tx, msg, 2, 19, &[2, 19, msg as u8])
}

fn closed(e: &mut Engine, now: Instant, tx: u64, msg: u32) -> Result<(), ConnFault> {
    e.on_closed(now, tx, msg, false, &[0, msg as u8])
}

fn out(e: &Engine, id: ReqId) -> &Outcome {
    e.outcome(id).unwrap()
}

/// The request decision is uninspectable, for this reason.
fn assert_unins(e: &Engine, id: ReqId, why: Why) {
    assert_eq!(out(e, id).decision, Some(Decision::Uninspectable(why)));
}

/// A transaction driven to one state of a held transaction with the real engine (one `row_*` fixture per
/// state). The messages taken so far are named in each fixture function.
struct Fx {
    e: Engine,
    t0: Instant,
    id: ReqId,
    tx: u64,
}

/// Row "writer queue": TX_BEGIN is in the writer queue, not taken.
fn row_queued() -> Fx {
    let (mut e, t0) = start();
    let id = e.submit(t0, request()).unwrap();
    Fx { e, t0, id, tx: 100 }
}

/// Row "phase 1 wait": TX_BEGIN taken (msg 1) at t0.
fn row_p1() -> Fx {
    let mut f = row_queued();
    let b = take(&mut f.e, f.t0);
    assert_eq!(
        (b.tx, b.msg, b.kind, b.payload),
        (100, 1, OutKind::TxBegin, vec![1, 2, 3])
    );
    f
}

/// Row "body being sent": phase 1 continued; BODY (msg 2) taken, BODY (3) and BODY_END (4) not.
fn row_body() -> Fx {
    let mut f = row_p1();
    cont(&mut f.e, f.t0, 100, 1, 1).unwrap();
    let b = take(&mut f.e, f.t0);
    assert_eq!(
        (b.msg, b.kind, b.payload),
        (2, OutKind::Body, vec![b'a'; 4])
    );
    f
}

/// Row "phase 2 wait": BODY 2, 3 and BODY_END 4 taken at t0.
fn row_p2() -> Fx {
    let mut f = row_body();
    assert_eq!(take(&mut f.e, f.t0).msg, 3);
    let be = take(&mut f.e, f.t0);
    assert_eq!((be.msg, be.kind, be.payload), (4, OutKind::BodyEnd, vec![]));
    f
}

/// Row "decided": forwarded; TX_END (msg 5, reason 1) taken and written at t0.
fn row_ended() -> Fx {
    let mut f = row_p2();
    cont(&mut f.e, f.t0, 100, 4, 2).unwrap();
    let end = take(&mut f.e, f.t0);
    assert_eq!(
        (end.msg, end.kind, end.payload),
        (5, OutKind::TxEnd(1), vec![1])
    );
    f.e.frame_written(f.t0, 100, 5);
    f
}

/// The checks that are the same shape in the states with a request verdict wait or a
/// body being sent: a verdict of another phase, CLOSED before TX_END, "not created" after creation was
/// shown, a failure of a created transaction, disconnect, deadline, connection fault. `next_msg` is
/// the number TX_END gets (frames dropped from the queue use none).
fn check_failure_columns(make: fn() -> Fx, next_msg: u32, deadline: bool, nc_is_order: bool) {
    // a verdict of another phase
    let Fx { mut e, t0, id, tx } = make();
    cont(&mut e, t0, tx, 1, 4).unwrap();
    assert_unins(&e, id, Why::Order);
    assert_eq!(only_end(&mut e, t0), (next_msg, 3));
    assert_eq!(e.held_slots(), 1);
    // CLOSED before TX_END is not a return
    let Fx { mut e, t0, id, tx } = make();
    closed(&mut e, t0, tx, 1).unwrap();
    assert_unins(&e, id, Why::Order);
    assert_eq!(only_end(&mut e, t0), (next_msg, 3));
    assert_eq!(e.held_slots(), 1);
    assert!(out(&e, id).returns.is_empty());
    // "not created" where (3) does not apply: the transaction was created
    if nc_is_order {
        let Fx { mut e, t0, id, tx } = make();
        nc(&mut e, t0, tx, 1).unwrap();
        assert_unins(&e, id, Why::Order);
        assert_eq!(only_end(&mut e, t0), (next_msg, 3));
        assert_eq!(e.held_slots(), 1);
    }
    // a failure of a created transaction
    let Fx { mut e, t0, id, tx } = make();
    txerr(&mut e, t0, tx, 1).unwrap();
    assert_unins(&e, id, Why::TxError { code: 19 });
    assert_eq!(only_end(&mut e, t0), (next_msg, 3));
    assert_eq!(e.held_slots(), 1);
    // disconnect: the taken frames count, TX_END(4), the slot is kept, stop time (b)
    let Fx { mut e, t0, id, tx } = make();
    e.cancel(at(t0, 100), id);
    let o = out(&e, id);
    assert_eq!(o.decision, Some(Decision::ClientDisconnect));
    assert_eq!(
        o.stop,
        Some(StopPlan {
            at: at(t0, 6100),
            origin: StopOrigin::Sent,
            cleared: false
        })
    );
    assert_eq!(only_end(&mut e, t0), (next_msg, 4));
    assert_eq!(e.held_slots(), 1);
    assert!(out(&e, id).returns.is_empty());
    closed(&mut e, t0, tx, next_msg).unwrap();
    assert_eq!(out(&e, id).returns, vec![(tx, ReturnReason::Closed)]);
    // deadline
    let Fx { mut e, t0, id, .. } = make();
    if deadline {
        assert!(e.tick(at(t0, 2000)).is_none());
        assert!(out(&e, id).decision.is_none());
        assert!(e.tick(at(t0, 2000) + Duration::from_nanos(1)).is_none());
        assert_unins(&e, id, Why::VerdictDeadline);
        let plan = out(&e, id).stop.unwrap();
        assert_eq!(
            (plan.at, plan.origin),
            (at(t0, 8000), StopOrigin::Abandoned)
        );
        assert_eq!(only_end(&mut e, t0), (next_msg, 5));
        assert_eq!(e.held_slots(), 1);
    } else {
        // no verdict wait is running: the writer, not a verdict, is awaited (the I/O layer bounds the write)
        assert!(e.tick(at(t0, 60_000)).is_none());
        assert_eq!(e.held_slots(), 1);
        assert!(out(&e, id).stop.is_none() && out(&e, id).decision.is_none());
    }
    // connection fault: undecided becomes uninspectable, the slot stays until the exit is confirmed
    let Fx { mut e, t0, id, tx } = make();
    e.conn_fault(t0);
    assert_unins(&e, id, Why::ConnFault);
    assert!(e.next_frame(t0).is_none());
    assert_eq!(e.held_slots(), 1);
    assert!(out(&e, id).incomplete && !out(&e, id).close_unconfirmed);
    e.exit_confirmed(t0, 1);
    assert_eq!(e.held_slots(), 0);
    assert!(out(&e, id).incomplete && !out(&e, id).close_unconfirmed);
    assert_eq!(out(&e, id).returns, vec![(tx, ReturnReason::ExitConfirmed)]);
}

// ---- one test per state of a held transaction (the `row_*` fixtures) ----

#[test]
fn row_writer_queue() {
    // every answer for a TX_BEGIN the writer has not taken is a connection fault: the engine applies it,
    // the number is dropped and the request is back in the waiting queue
    for n in 0..6 {
        let Fx { mut e, t0, id, tx } = row_queued();
        let r = match n {
            0 => cont(&mut e, t0, tx, 1, 1),
            1 => blk(&mut e, t0, tx, 1, 1),
            2 => cont(&mut e, t0, tx, 1, 2),
            3 => nc(&mut e, t0, tx, 1),
            4 => txerr(&mut e, t0, tx, 1),
            _ => closed(&mut e, t0, tx, 1),
        };
        assert_eq!(r, Err(ConnFault::NotSent { tx }), "column {n}");
        assert_eq!((e.held_slots(), e.waiting()), (0, 1));
        assert_eq!(out(&e, id).decision, None);
        assert!(e.next_frame(t0).is_none());
    }
    // disconnect: the slot goes back by (4) and nothing is sent
    let Fx { mut e, t0, id, tx } = row_queued();
    e.cancel(t0, id);
    assert_eq!(out(&e, id).decision, Some(Decision::ClientDisconnect));
    assert_eq!(out(&e, id).returns, vec![(tx, ReturnReason::BeforeBegin)]);
    assert_eq!((e.held_slots(), drain(&mut e, t0)), (0, vec![]));
    // deadline: the wait (from submit) also covers the writer; (4), nothing is sent
    let Fx { mut e, t0, id, tx } = row_queued();
    assert!(e.tick(at(t0, 3000)).is_none());
    assert_eq!((e.held_slots(), out(&e, id).decision), (1, None));
    assert!(e.tick(at(t0, 3000) + Duration::from_nanos(1)).is_none());
    assert_eq!(
        out(&e, id).decision,
        Some(Decision::Uninspectable(Why::WaitDeadline))
    );
    assert_eq!(out(&e, id).returns, vec![(tx, ReturnReason::BeforeBegin)]);
    assert_eq!((e.held_slots(), drain(&mut e, t0)), (0, vec![]));
    // connection fault: the number is dropped, the request goes back to waiting and gets a new number
    let Fx { mut e, t0, id, tx } = row_queued();
    e.conn_fault(t0);
    assert_eq!(
        (e.held_slots(), e.waiting(), out(&e, id).decision),
        (0, 1, None)
    );
    assert_eq!(out(&e, id).returns, vec![(tx, ReturnReason::BeforeBegin)]);
    assert!(!out(&e, id).incomplete && !out(&e, id).close_unconfirmed);
    assert!(e.next_frame(t0).is_none());
    e.exit_confirmed(t0, 1);
    assert!(!out(&e, id).incomplete && !out(&e, id).close_unconfirmed);
    e.ready(t0, 2);
    assert_eq!(drain(&mut e, t0), vec![(101, 1, OutKind::TxBegin)]);
    assert_eq!(out(&e, id).txs, vec![100, 101]);
}

#[test]
fn row_phase1_wait() {
    // continue: the body goes out
    let Fx { mut e, t0, id, tx } = row_p1();
    cont(&mut e, t0, tx, 1, 1).unwrap();
    assert_eq!(out(&e, id).decision, None);
    assert_eq!(
        drain(&mut e, t0),
        vec![
            (100, 2, OutKind::Body),
            (100, 3, OutKind::Body),
            (100, 4, OutKind::BodyEnd)
        ]
    );
    // block
    let Fx { mut e, t0, id, tx } = row_p1();
    blk(&mut e, t0, tx, 1, 1).unwrap();
    assert_eq!(out(&e, id).decision, Some(blocked(1)));
    assert_eq!(only_end(&mut e, t0), (2, 2));
    assert_eq!(
        out(&e, id).stop.map(|p| (p.at, p.origin)),
        Some((at(t0, 6000), StopOrigin::Sent))
    );
    // "not created" that satisfies (3): uninspectable, no TX_END, the slot is returned
    let Fx { mut e, t0, id, tx } = row_p1();
    nc(&mut e, t0, tx, 1).unwrap();
    assert_eq!(
        out(&e, id).decision,
        Some(Decision::Uninspectable(Why::NotCreated { code: 1 }))
    );
    assert_eq!((e.held_slots(), drain(&mut e, t0)), (0, vec![]));
    assert_eq!(out(&e, id).returns, vec![(tx, ReturnReason::NotCreated)]);
    assert!(out(&e, id).stop.is_none());
    // "not created" for another message number does not satisfy (3)
    let Fx { mut e, t0, id, tx } = row_p1();
    nc(&mut e, t0, tx, 2).unwrap();
    assert_eq!(
        out(&e, id).decision,
        Some(Decision::Uninspectable(Why::Order))
    );
    assert_eq!((e.held_slots(), only_end(&mut e, t0)), (1, (2, 3)));
    // abandon by deadline: TX_END(5), stop time (a); the disconnect case is in the common columns
    check_failure_columns(row_p1, 2, true, false);
}

#[test]
fn row_body_being_sent() {
    // a repeat of the phase 1 continue is dropped and counted
    let Fx { mut e, t0, id, tx } = row_body();
    cont(&mut e, t0, tx, 1, 1).unwrap();
    assert_eq!(
        (e.discarded(), out(&e, id).late, out(&e, id).decision),
        (1, 1, None)
    );
    // the same message with other content is an order violation, not a repeat
    let Fx { mut e, t0, id, tx } = row_body();
    blk(&mut e, t0, tx, 1, 1).unwrap();
    assert_eq!(
        out(&e, id).decision,
        Some(Decision::Uninspectable(Why::Order))
    );
    // block on the BODY that was taken: the rest of the body is not sent and uses no number
    let Fx { mut e, t0, id, tx } = row_body();
    blk(&mut e, t0, tx, 2, 2).unwrap();
    assert_eq!(out(&e, id).decision, Some(blocked(2)));
    assert_eq!(only_end(&mut e, t0), (3, 2));
    // a block that names a BODY not taken yet is out of order
    let Fx { mut e, t0, id, tx } = row_body();
    blk(&mut e, t0, tx, 3, 2).unwrap();
    assert_eq!(
        out(&e, id).decision,
        Some(Decision::Uninspectable(Why::Order))
    );
    // a phase 2 continue for a frame that was not taken is out of order
    let Fx { mut e, t0, id, tx } = row_body();
    cont(&mut e, t0, tx, 4, 2).unwrap();
    assert_eq!(
        out(&e, id).decision,
        Some(Decision::Uninspectable(Why::Order))
    );
    // no verdict is awaited here, so no deadline: the disconnect and the rest are in the common columns
    check_failure_columns(row_body, 3, false, true);
}

#[test]
fn row_phase2_wait() {
    // continue: forwarded (both continues), TX_END(done)
    let Fx { mut e, t0, id, tx } = row_p2();
    cont(&mut e, t0, tx, 4, 2).unwrap();
    assert_eq!(out(&e, id).decision, Some(Decision::Forward));
    assert_eq!(only_end(&mut e, t0), (5, 1));
    // a continue with a detection on BODY_END is forwarded and kept as detected, TX_END(done), and CLOSED returns
    // the slot; on a BODY it is not the continue of phase 2
    let Fx { mut e, t0, id, tx } = row_p2();
    det(&mut e, t0, tx, 4).unwrap();
    assert_eq!(out(&e, id).decision, Some(detected()));
    assert_eq!(only_end(&mut e, t0), (5, 1));
    closed(&mut e, t0, tx, 5).unwrap();
    assert_eq!(e.held_slots(), 0);
    let Fx { mut e, t0, id, tx } = row_p2();
    det(&mut e, t0, tx, 3).unwrap();
    assert_eq!(
        out(&e, id).decision,
        Some(Decision::Uninspectable(Why::Order))
    );
    // block on BODY_END, and on a BODY
    for msg in [4, 2] {
        let Fx { mut e, t0, id, tx } = row_p2();
        blk(&mut e, t0, tx, msg, 2).unwrap();
        assert_eq!(out(&e, id).decision, Some(blocked(2)));
        assert_eq!(only_end(&mut e, t0), (5, 2));
    }
    // a continue for a BODY is not the continue of phase 2
    let Fx { mut e, t0, id, tx } = row_p2();
    cont(&mut e, t0, tx, 3, 2).unwrap();
    assert_eq!(
        out(&e, id).decision,
        Some(Decision::Uninspectable(Why::Order))
    );
    check_failure_columns(row_p2, 5, true, true);
}

#[test]
fn row_decided() {
    // continue, block, other phase, failure, "not created": dropped and counted, nothing changes
    let Fx { mut e, t0, id, tx } = row_ended();
    cont(&mut e, t0, tx, 4, 2).unwrap();
    blk(&mut e, t0, tx, 4, 2).unwrap();
    cont(&mut e, t0, tx, 1, 4).unwrap();
    txerr(&mut e, t0, tx, 1).unwrap();
    nc(&mut e, t0, tx, 1).unwrap();
    assert_eq!((e.discarded(), out(&e, id).late), (5, 5));
    assert_eq!(out(&e, id).decision, Some(Decision::Forward));
    assert!(out(&e, id).returns.is_empty());
    // CLOSED with another number is dropped; CLOSED that answers TX_END returns the slot (1)
    closed(&mut e, t0, tx, 4).unwrap();
    assert_eq!((e.discarded(), e.held_slots()), (6, 1));
    closed(&mut e, t0, tx, 5).unwrap();
    assert_eq!(
        (e.held_slots(), out(&e, id).returns.clone()),
        (0, vec![(tx, ReturnReason::Closed)])
    );
    assert_eq!(out(&e, id).close_error, Some(false));
    // CLOSED wait passed: Close unconfirmed, slot kept, the stop time is not moved
    let Fx { mut e, t0, id, tx } = row_ended();
    assert!(e.tick(at(t0, 2000)).is_none());
    assert!(!out(&e, id).close_unconfirmed);
    assert!(e.tick(at(t0, 2000) + Duration::from_nanos(1)).is_none());
    assert!(out(&e, id).close_unconfirmed);
    assert_eq!(e.held_slots(), 1);
    e.cancel(at(t0, 2500), id);
    assert_eq!(out(&e, id).decision, Some(Decision::Forward));
    assert!(drain(&mut e, t0).is_empty());
    let plan = out(&e, id).stop.unwrap();
    assert_eq!((plan.at, plan.origin), (at(t0, 6000), StopOrigin::Sent));
    // CLOSED before the stop time: returned, plan taken off, confirmation kept apart from the observation
    closed(&mut e, at(t0, 3000), tx, 5).unwrap();
    let o = out(&e, id);
    assert!(o.close_unconfirmed && o.close_confirmed_late);
    assert_eq!(o.stop.map(|p| p.cleared), Some(true));
    assert_eq!(e.held_slots(), 0);
    assert!(e.tick(at(t0, 60_000)).is_none());
    // no CLOSED: the stop time (b) passes
    let Fx { mut e, t0, id, tx } = row_ended();
    assert!(e.tick(at(t0, 6000)).is_none());
    let s = e.tick(at(t0, 6000) + Duration::from_nanos(1)).unwrap();
    assert_eq!(
        (s.req, s.tx, s.at, s.origin),
        (id, tx, at(t0, 6000), StopOrigin::Sent)
    );
    // connection fault: the decision stays, Close is unconfirmed, the slot is returned by (2)
    let Fx { mut e, t0, id, tx } = row_ended();
    e.conn_fault(t0);
    assert_eq!(out(&e, id).decision, Some(Decision::Forward));
    assert!(out(&e, id).close_unconfirmed && !out(&e, id).incomplete);
    e.exit_confirmed(t0, 1);
    assert!(out(&e, id).close_unconfirmed && !out(&e, id).incomplete);
    assert_eq!(out(&e, id).returns, vec![(tx, ReturnReason::ExitConfirmed)]);
}

// ---- 1. one final decision ----

#[test]
fn nothing_else_forwards() {
    // (msg, phase) at the phase 2 wait of a transaction whose frames are 1 TX_BEGIN, 2 3 BODY, 4 BODY_END
    let cases: [(u32, u8); 6] = [(4, 3), (4, 1), (4, 4), (3, 2), (5, 2), (0, 2)];
    for (msg, phase) in cases {
        let Fx { mut e, t0, id, tx } = row_p2();
        cont(&mut e, t0, tx, msg, phase).unwrap();
        assert_eq!(
            out(&e, id).decision,
            Some(Decision::Uninspectable(Why::Order)),
            "msg {msg} phase {phase}"
        );
        assert_eq!(only_end(&mut e, t0), (5, 3));
    }
    // an unknown transaction number
    let Fx { mut e, t0, .. } = row_p2();
    assert_eq!(
        cont(&mut e, t0, 101, 4, 2),
        Err(ConnFault::Unissued { tx: 101 })
    );
    // a returned transaction: the answers are dropped and the earlier decision stays
    let Fx { mut e, t0, id, tx } = row_p1();
    blk(&mut e, t0, tx, 1, 1).unwrap();
    assert_eq!(take(&mut e, t0).msg, 2);
    closed(&mut e, t0, tx, 2).unwrap();
    assert_eq!(e.held_slots(), 0);
    cont(&mut e, t0, tx, 1, 1).unwrap();
    cont(&mut e, t0, tx, 4, 2).unwrap();
    assert_eq!((out(&e, id).decision, e.discarded()), (Some(blocked(1)), 2));
}

#[test]
fn the_decision_is_made_once() {
    // block first, then both continues: stays blocked
    let Fx { mut e, t0, id, tx } = row_p1();
    blk(&mut e, t0, tx, 1, 1).unwrap();
    cont(&mut e, t0, tx, 1, 1).unwrap();
    cont(&mut e, t0, tx, 4, 2).unwrap();
    assert_eq!(out(&e, id).decision, Some(blocked(1)));
    // forward first, then a block, a deadline and a disconnect: stays forwarded
    let Fx { mut e, t0, id, tx } = row_ended();
    blk(&mut e, t0, tx, 4, 2).unwrap();
    e.cancel(t0, id);
    e.tick(at(t0, 10_000));
    assert_eq!(out(&e, id).decision, Some(Decision::Forward));
    assert_eq!(out(&e, id).late, 1);
    // the deadline first, then a late continue: stays uninspectable
    let Fx { mut e, t0, id, tx } = row_p1();
    e.tick(at(t0, 2001));
    cont(&mut e, t0, tx, 1, 1).unwrap();
    assert_eq!(
        out(&e, id).decision,
        Some(Decision::Uninspectable(Why::VerdictDeadline))
    );
    // a repeat of the same answer is dropped, a different answer for the same message is out of order
    let Fx { mut e, t0, id, tx } = row_body();
    cont(&mut e, t0, tx, 1, 1).unwrap();
    assert_eq!((out(&e, id).decision, e.discarded()), (None, 1));
    e.on_verdict(t0, tx, 1, 1, false, false, 0, 0, &[0xff])
        .unwrap();
    assert_eq!(
        out(&e, id).decision,
        Some(Decision::Uninspectable(Why::Order))
    );
}

#[test]
fn unknown_error_class_is_out_of_order() {
    let Fx { mut e, t0, id, tx } = row_p1();
    e.on_error(t0, tx, 1, 7, 1, &[7]).unwrap();
    assert_eq!(
        out(&e, id).decision,
        Some(Decision::Uninspectable(Why::Order))
    );
    assert_eq!(e.held_slots(), 1);
}

// ---- 3. limits ----

#[test]
fn requests_that_fail_the_checks_are_not_sent() {
    let (mut e, t0) = start();
    let frag = |n: usize| vec![0u8; n];
    let bad = [
        Request {
            begin: vec![],
            ..request()
        },
        Request {
            begin: frag(MAX_BEGIN + 1),
            ..request()
        },
        Request {
            body: vec![frag(1); MAX_FRAGS + 1],
            ..request()
        },
        Request {
            body: vec![frag(0)],
            ..request()
        },
        Request {
            body: vec![frag(MAX_FRAG + 1)],
            ..request()
        },
    ];
    for r in bad {
        let id = e.submit(t0, r).unwrap();
        let invalid = Some(Decision::Uninspectable(Why::Invalid));
        assert_eq!(out(&e, id).decision, invalid);
        assert!(out(&e, id).txs.is_empty());
    }
    // the limits themselves are accepted
    let edge = Request {
        begin: frag(MAX_BEGIN),
        body: vec![frag(MAX_FRAG); MAX_FRAGS],
    };
    let id = e.submit(t0, edge).unwrap();
    assert_eq!(out(&e, id).decision, None);
}

#[test]
fn the_discard_limit_is_per_incarnation_and_the_discard_above_it_is_a_fault() {
    // a returned transaction
    let Fx { mut e, t0, tx, .. } = row_ended();
    closed(&mut e, t0, tx, 5).unwrap();
    for i in 1..=64 {
        cont(&mut e, t0, tx, 4, 2).unwrap();
        assert_eq!(e.discarded(), i);
    }
    assert_eq!(cont(&mut e, t0, tx, 4, 2), Err(ConnFault::DiscardLimit));
    assert_eq!(e.discarded(), 65);
    e.conn_fault(t0);
    e.exit_confirmed(t0, 1);
    assert_eq!(e.discarded(), 0);
    e.ready(t0, 2);
    for _ in 0..64 {
        cont(&mut e, t0, tx, 4, 2).unwrap();
    }
    assert_eq!(cont(&mut e, t0, tx, 4, 2), Err(ConnFault::DiscardLimit));
    // exact repeats for a held transaction count the same way
    let Fx { mut e, t0, tx, .. } = row_ended();
    for _ in 0..64 {
        cont(&mut e, t0, tx, 4, 2).unwrap();
    }
    assert_eq!(blk(&mut e, t0, tx, 4, 2), Err(ConnFault::DiscardLimit));
}

// ---- 4. transaction numbers ----

#[test]
fn unissued_returned_and_unsent_numbers() {
    // a number that was never assigned (the next one is 101) is a connection fault, every kind of answer
    for tx in [101, u64::MAX] {
        for n in 0..5 {
            let Fx { mut e, t0, .. } = row_p1();
            let r = match n {
                0 => cont(&mut e, t0, tx, 1, 1),
                1 => blk(&mut e, t0, tx, 1, 1),
                2 => nc(&mut e, t0, tx, 1),
                3 => txerr(&mut e, t0, tx, 1),
                _ => closed(&mut e, t0, tx, 1),
            };
            assert_eq!(r, Err(ConnFault::Unissued { tx }), "tx {tx} column {n}");
        }
    }
    // a number below the next one that is not held is a returned one: dropped and counted
    let Fx { mut e, t0, .. } = row_p1();
    cont(&mut e, t0, 99, 1, 1).unwrap();
    assert_eq!(e.discarded(), 1);
}

// ---- 5. overflow ----

#[test]
fn transaction_number_overflow_stops_assigning() {
    let t0 = Instant::now();
    let mut e = Engine::new(limits(), 1, u64::MAX);
    e.ready(t0, 1);
    let a = e.submit(t0, request()).unwrap();
    assert_eq!((out(&e, a).txs.clone(), e.halted()), (vec![u64::MAX], None));
    let b = e.submit(t0, request()).unwrap();
    assert_eq!(
        out(&e, b).decision,
        Some(Decision::Uninspectable(Why::Halted(Halt::TxExhausted)))
    );
    assert!(out(&e, b).txs.is_empty());
    assert_eq!(
        (e.halted(), e.waiting(), e.held_slots()),
        (Some(Halt::TxExhausted), 0, 1)
    );
    let c = e.submit(t0, request()).unwrap();
    assert_eq!(
        out(&e, c).decision,
        Some(Decision::Uninspectable(Why::Halted(Halt::TxExhausted)))
    );
    // the transaction that holds the last number runs normally; no number is "unissued" any more
    let f = take(&mut e, t0);
    assert_eq!((f.tx, f.msg), (u64::MAX, 1));
    cont(&mut e, t0, u64::MAX, 1, 1).unwrap();
    cont(&mut e, t0, 0, 1, 1).unwrap();
    assert_eq!(e.discarded(), 1);
    assert_eq!(drain(&mut e, t0).len(), 3);
    cont(&mut e, t0, u64::MAX, 4, 2).unwrap();
    assert_eq!(out(&e, a).decision, Some(Decision::Forward));
}

#[test]
fn incarnation_overflow_stops_the_restart() {
    let t0 = Instant::now();
    let mut e = Engine::new(limits(), u32::MAX, 100);
    e.ready(t0, u32::MAX);
    let a = e.submit(t0, request()).unwrap();
    take(&mut e, t0);
    e.conn_fault(t0);
    let w = e.submit(t0, request()).unwrap();
    e.exit_confirmed(t0, u32::MAX);
    assert_eq!(e.halted(), Some(Halt::IncExhausted));
    assert_eq!(e.incarnation(), u32::MAX);
    assert_eq!(out(&e, a).returns, vec![(100, ReturnReason::ExitConfirmed)]);
    assert_eq!(
        out(&e, w).decision,
        Some(Decision::Uninspectable(Why::Halted(Halt::IncExhausted)))
    );
    e.ready(t0, u32::MAX);
    let x = e.submit(t0, request()).unwrap();
    assert_eq!(
        out(&e, x).decision,
        Some(Decision::Uninspectable(Why::Halted(Halt::IncExhausted)))
    );
    assert_eq!((e.held_slots(), e.waiting()), (0, 0));
}

#[test]
fn the_session_halt_decides_the_waiting_requests_at_once() {
    // DRAIN: the taken transaction goes on; the waiting and the new requests are decided
    let t0 = Instant::now();
    let mut e = Engine::new(
        Limits {
            slots: 1,
            ..limits()
        },
        1,
        100,
    );
    e.ready(t0, 1);
    let a = e.submit(t0, request()).unwrap();
    let b = e.submit(t0, request()).unwrap();
    assert_eq!(e.waiting(), 1);
    e.halt(t0, Halt::Drain);
    assert_eq!(
        out(&e, b).decision,
        Some(Decision::Uninspectable(Why::Halted(Halt::Drain)))
    );
    assert_eq!(take(&mut e, t0).kind, OutKind::TxBegin);
    assert_eq!(out(&e, a).decision, None);
    let c = e.submit(t0, request()).unwrap();
    assert_eq!(
        out(&e, c).decision,
        Some(Decision::Uninspectable(Why::Halted(Halt::Drain)))
    );
    // the first reason stays
    e.halt(t0, Halt::NoRestart);
    assert_eq!((e.halted(), e.held_slots()), (Some(Halt::Drain), 1));
}

// ---- 6. the four reasons are one path ----

#[test]
fn early_closed_and_false_not_created_do_not_return() {
    // CLOSED before TX_END, with the number TX_END will get
    let Fx { mut e, t0, id, tx } = row_p2();
    closed(&mut e, t0, tx, 5).unwrap();
    assert_eq!(
        out(&e, id).decision,
        Some(Decision::Uninspectable(Why::Order))
    );
    assert_eq!((e.held_slots(), out(&e, id).returns.clone()), (1, vec![]));
    let end = take(&mut e, t0);
    assert_eq!((end.msg, end.kind), (5, OutKind::TxEnd(3)));
    // the CLOSED that really answers TX_END is not swallowed as a repeat of the early one
    closed(&mut e, t0, tx, 5).unwrap();
    assert_eq!(out(&e, id).returns, vec![(tx, ReturnReason::Closed)]);
    // "not created" after the creation was shown
    for evidence in 0..2 {
        let Fx { mut e, t0, id, tx } = row_p1();
        if evidence == 0 {
            cont(&mut e, t0, tx, 1, 1).unwrap();
        } else {
            blk(&mut e, t0, tx, 1, 1).unwrap();
        }
        let before = out(&e, id).decision;
        nc(&mut e, t0, tx, 1).unwrap();
        assert_eq!(e.held_slots(), 1);
        assert!(out(&e, id).returns.is_empty());
        if evidence == 1 {
            assert_eq!(
                (before, out(&e, id).decision, e.discarded()),
                (Some(blocked(1)), Some(blocked(1)), 1)
            );
        }
    }
}

#[test]
fn conn_fault_counts_incomplete_and_close_unconfirmed_apart() {
    /// (incomplete, close_unconfirmed) of the request.
    fn flags(e: &Engine, id: ReqId) -> (bool, bool) {
        (out(e, id).incomplete, out(e, id).close_unconfirmed)
    }
    let (mut e, t0) = start();
    let decided = e.submit(t0, request()).unwrap(); // 100: decided, TX_END handed over, no CLOSED
    let closed_ok = e.submit(t0, request()).unwrap(); // 101: decided, CLOSED received, slot returned
    let undecided = e.submit(t0, request()).unwrap(); // 102: TX_BEGIN taken, phase 1 verdict awaited
    assert_eq!(drain(&mut e, t0).len(), 3);
    blk(&mut e, t0, 100, 1, 1).unwrap();
    blk(&mut e, t0, 101, 1, 1).unwrap();
    assert_eq!(
        drain(&mut e, t0),
        vec![(100, 2, OutKind::TxEnd(2)), (101, 2, OutKind::TxEnd(2))]
    );
    closed(&mut e, t0, 101, 2).unwrap();
    let queued = e.submit(t0, request()).unwrap(); // 103: TX_BEGIN still in the writer queue
    assert_eq!((e.held_slots(), e.waiting()), (3, 0));
    e.conn_fault(t0);
    assert_eq!((e.held_slots(), e.waiting()), (2, 1));
    // the observations stay through the exit confirmation
    for confirmed in [false, true] {
        if confirmed {
            e.exit_confirmed(t0, 1);
            assert_eq!((e.held_slots(), e.waiting()), (0, 1));
        }
        assert_eq!(flags(&e, decided), (false, true));
        assert_eq!(flags(&e, closed_ok), (false, false));
        assert_eq!(flags(&e, undecided), (true, false));
        assert_eq!(flags(&e, queued), (false, false));
    }
}

#[test]
fn a_connection_fault_puts_unsent_requests_back_in_order() {
    let t0 = Instant::now();
    let mut e = Engine::new(limits(), 1, 100);
    e.ready(t0, 1);
    let ids: Vec<ReqId> = (0..12)
        .map(|_| e.submit(at(t0, 100), request()).unwrap())
        .collect();
    assert_eq!((e.held_slots(), e.waiting()), (4, 8));
    e.conn_fault(at(t0, 200));
    // 4 + 8 are waiting: none is lost, and a new one is refused
    assert_eq!((e.held_slots(), e.waiting()), (0, 12));
    let thirteen = e.submit(at(t0, 200), request()).unwrap();
    assert_eq!(
        out(&e, thirteen).decision,
        Some(Decision::Uninspectable(Why::QueueFull))
    );
    for id in &ids[..4] {
        assert_eq!(out(&e, *id).returns.len(), 1);
        assert_eq!(out(&e, *id).returns[0].1, ReturnReason::BeforeBegin);
        assert_eq!(out(&e, *id).decision, None);
    }
    e.exit_confirmed(at(t0, 300), 1);
    assert_eq!(e.incarnation(), 2);
    assert!(e.next_frame(t0).is_none());
    e.ready(at(t0, 400), 2);
    // the restored requests are first, with new numbers
    for (i, id) in ids[..4].iter().enumerate() {
        assert_eq!(out(&e, *id).txs, vec![100 + i as u64, 104 + i as u64]);
    }
    assert_eq!((e.held_slots(), e.waiting()), (4, 8));
    assert_eq!(drain(&mut e, at(t0, 400)).len(), 4);
    // the original wait deadline (submit time + 3 s) still applies to what waits
    assert!(e.tick(at(t0, 3100)).is_none());
    assert_eq!(e.waiting(), 8);
    e.tick(at(t0, 3101));
    assert_eq!(e.waiting(), 0);
    assert_eq!(
        out(&e, ids[8]).decision,
        Some(Decision::Uninspectable(Why::WaitDeadline))
    );
}

// ---- deadlines that do not fit in an Instant: over at once (fail closed) ----

#[test]
fn an_overflowing_deadline_is_already_expired() {
    // before HELLO: the request is decided at the submit, at the same time, and gets nothing later
    let t0 = Instant::now();
    let mut lim = limits();
    lim.wait_deadline = Duration::MAX;
    let mut e = Engine::new(lim, 1, 100);
    let a = e.submit(t0, request()).unwrap();
    assert_eq!(
        (out(&e, a).decision, out(&e, a).decided_at),
        (Some(Decision::Uninspectable(Why::WaitDeadline)), Some(t0))
    );
    assert_eq!(e.waiting(), 0);
    assert!(e.tick(t0).is_none());
    e.ready(at(t0, 1), 1);
    assert!(out(&e, a).txs.is_empty());
    assert_eq!((e.held_slots(), e.waiting()), (0, 0));
    assert!(e.next_frame(at(t0, 1)).is_none());
}

/// An engine after HELLO with these limits (inc 1, first transaction 100) and the base time.
fn start_with(lim: Limits) -> (Engine, Instant) {
    let t0 = Instant::now();
    let mut e = Engine::new(lim, 1, 100);
    e.ready(t0, 1);
    (e, t0)
}

#[test]
fn a_deadline_that_does_not_fit_in_an_instant_is_already_over() {
    // verdict_wait: TX_BEGIN is not handed out (nothing was sent), the slot goes back at once, and the answers
    // that come afterwards do not bring the wait back.
    let (mut e, t0) = start_with(Limits {
        verdict_wait: Duration::MAX,
        ..limits()
    });
    let id = e.submit(t0, request()).unwrap();
    assert!(e.next_frame(t0).is_none());
    let o = out(&e, id);
    assert_eq!(
        o.decision,
        Some(Decision::Uninspectable(Why::VerdictDeadline))
    );
    assert_eq!(o.returns, vec![(100, ReturnReason::BeforeBegin)]);
    assert!(o.stop.is_none());
    cont(&mut e, t0, 100, 1, 1).unwrap();
    assert_eq!((e.discarded(), e.held_slots()), (1, 0));
    // closed_wait: Close is unconfirmed as soon as TX_END is written; the slot waits for a CLOSED, which is late.
    // stop_after: the stop time is due at once.
    let forwarded = |lim: Limits| {
        let (mut e, t0) = start_with(lim);
        let id = e.submit(t0, request()).unwrap();
        take(&mut e, t0);
        cont(&mut e, t0, 100, 1, 1).unwrap();
        assert_eq!(drain(&mut e, t0).len(), 3);
        cont(&mut e, t0, 100, 4, 2).unwrap();
        assert_eq!(take(&mut e, t0).msg, 5);
        e.frame_written(t0, 100, 5);
        (e, t0, id)
    };
    let (mut e, t0, id) = forwarded(Limits {
        closed_wait: Duration::MAX,
        ..limits()
    });
    assert!(out(&e, id).close_unconfirmed);
    assert_eq!(e.held_slots(), 1);
    closed(&mut e, t0, 100, 5).unwrap();
    assert!(out(&e, id).close_confirmed_late);
    assert_eq!(e.held_slots(), 0);
    let (mut e, t0, id) = forwarded(Limits {
        stop_after: Duration::MAX,
        ..limits()
    });
    let s = e.tick(t0).unwrap();
    assert_eq!((s.req, s.at, s.origin), (id, t0, StopOrigin::Sent));
}

// ---- a fault found by the engine ----

#[test]
fn a_fault_found_by_the_engine_stops_the_writer() {
    // tx 100 is taken, tx 101 is in the writer queue
    let setup = || {
        let Fx { mut e, t0, id, tx } = row_p1();
        let queued = e.submit(t0, request()).unwrap();
        (e, t0, id, tx, queued)
    };
    for kind in 0..3 {
        let (mut e, t0, id, tx, queued) = setup();
        let expect = match kind {
            0 => {
                let r = cont(&mut e, t0, 999, 1, 1);
                (r, ConnFault::Unissued { tx: 999 })
            }
            1 => {
                let r = cont(&mut e, t0, 101, 1, 1);
                (r, ConnFault::NotSent { tx: 101 })
            }
            _ => {
                cont(&mut e, t0, tx, 1, 1).unwrap();
                let mut r = Ok(());
                for _ in 0..65 {
                    r = cont(&mut e, t0, tx, 1, 1);
                }
                (r, ConnFault::DiscardLimit)
            }
        };
        assert_eq!(expect.0, Err(expect.1), "kind {kind}");
        // nothing more goes to the writer; what was undecided is uninspectable; the frame never taken
        // goes back to the waiting queue; the taken one keeps its slot until the exit is confirmed
        assert!(e.next_frame(t0).is_none());
        assert_eq!(
            out(&e, id).decision,
            Some(Decision::Uninspectable(Why::ConnFault))
        );
        assert_eq!((e.held_slots(), e.waiting()), (1, 1));
        assert_eq!(out(&e, queued).returns[0].1, ReturnReason::BeforeBegin);
        e.exit_confirmed(t0, 1);
        e.ready(t0, 2);
        assert_eq!(out(&e, queued).txs, vec![101, 102]);
        assert_eq!(drain(&mut e, t0), vec![(102, 1, OutKind::TxBegin)]);
    }
}

// ---- deadlines found by the events alone (no tick is called) ----

#[test]
fn a_late_answer_without_a_tick_finds_the_verdict_deadline() {
    // TX_BEGIN taken at t0: the verdict wait ends at 2000; the answer comes at 2500 and no tick ran
    for kind in 0..4 {
        let Fx { mut e, t0, id, tx } = row_p1();
        let now = at(t0, 2500);
        match kind {
            0 => cont(&mut e, now, tx, 1, 1).unwrap(),
            1 => blk(&mut e, now, tx, 1, 1).unwrap(),
            2 => txerr(&mut e, now, tx, 1).unwrap(),
            _ => e.cancel(now, id),
        }
        let o = out(&e, id);
        assert_eq!(
            o.decision,
            Some(Decision::Uninspectable(Why::VerdictDeadline)),
            "kind {kind}"
        );
        assert_eq!(o.created, kind != 3, "kind {kind}");
        assert_eq!(
            o.stop.map(|p| (p.at, p.origin)),
            Some((at(t0, 8000), StopOrigin::Abandoned)),
            "kind {kind}"
        );
        // the body is not sent: only TX_END (reason 5) is in the writer queue
        assert_eq!(only_end(&mut e, now), (2, 5), "kind {kind}");
    }
    // at the deadline itself nothing has expired yet
    let Fx { mut e, t0, id, tx } = row_p1();
    cont(&mut e, at(t0, 2000), tx, 1, 1).unwrap();
    assert_eq!(out(&e, id).decision, None);
    assert_eq!(drain(&mut e, t0).len(), 3);
}

#[test]
fn a_late_closed_without_a_tick_is_close_unconfirmed() {
    // TX_END written at t0: the CLOSED wait ends at 2000; the CLOSED comes at 2500 and no tick ran
    let Fx { mut e, t0, id, tx } = row_ended();
    closed(&mut e, at(t0, 2500), tx, 5).unwrap();
    let o = out(&e, id);
    assert_eq!(o.returns, vec![(tx, ReturnReason::Closed)]);
    assert!(o.close_unconfirmed && o.close_confirmed_late);
    assert_eq!(o.close_error, Some(false));
    // at the deadline itself it is still in time
    let Fx { mut e, t0, id, tx } = row_ended();
    closed(&mut e, at(t0, 2000), tx, 5).unwrap();
    let o = out(&e, id);
    assert_eq!(o.returns, vec![(tx, ReturnReason::Closed)]);
    assert!(!o.close_unconfirmed && !o.close_confirmed_late);
}

// ---- message numbers ----

#[test]
fn the_message_number_overflow_is_a_checked_stop() {
    let Fx { mut e, t0, id, tx } = row_p1();
    cont(&mut e, t0, tx, 1, 1).unwrap();
    // the last valid number goes to the next frame (BODY); the one after it has none
    e.held[0].next_msg = Some(u32::MAX);
    let f = take(&mut e, t0);
    assert_eq!((f.tx, f.msg, f.kind), (100, u32::MAX, OutKind::Body));
    assert_eq!(e.halted(), None);
    assert!(e.next_frame(t0).is_none());
    assert_eq!(e.halted(), Some(Halt::MsgOverflow));
    // nothing is handed out any more, no number wraps round to 0, whatever the time
    for ms in [0, 1, 2500, 60_000] {
        assert!(e.next_frame(at(t0, ms)).is_none());
        assert!(e.tick(at(t0, ms)).is_none());
    }
    assert!(drain(&mut e, t0).is_empty());
    // the stop alone does not return the slot
    assert_eq!(e.held_slots(), 1);
    assert!(out(&e, id).returns.is_empty());
    assert_eq!(out(&e, id).decision, None);
    // (2) returns it once
    e.exit_confirmed(at(t0, 100), 1);
    assert_eq!(out(&e, id).returns, vec![(tx, ReturnReason::ExitConfirmed)]);
    assert_eq!(e.held_slots(), 0);
    assert_eq!(e.halted(), Some(Halt::MsgOverflow));
    assert!(e.next_frame(at(t0, 200)).is_none());
    assert_eq!(out(&e, id).returns.len(), 1);
    // the restart does not start the sending again: a normal request gets no slot and no frame
    e.ready(at(t0, 300), 2);
    let x = e.submit(at(t0, 300), request()).unwrap();
    assert_eq!(
        out(&e, x).decision,
        Some(Decision::Uninspectable(Why::Halted(Halt::MsgOverflow)))
    );
    assert!(out(&e, x).txs.is_empty());
    assert_eq!((e.held_slots(), e.waiting()), (0, 0));
    assert!(e.next_frame(at(t0, 300)).is_none());
}

// ---- the incarnation of HELLO and of the exit ----

#[test]
fn hello_and_exit_of_another_incarnation_do_nothing() {
    let t0 = Instant::now();
    let mut e = Engine::new(limits(), 1, 100);
    let id = e.submit(t0, request()).unwrap();
    // a HELLO of an incarnation that is not the current one makes nothing ready
    e.ready(t0, 0);
    e.ready(t0, 2);
    assert_eq!((e.held_slots(), e.waiting()), (0, 1));
    e.ready(t0, 1);
    assert_eq!((e.held_slots(), e.waiting()), (1, 0));
    assert_eq!(take(&mut e, t0).kind, OutKind::TxBegin);
    // the exit of another incarnation: no fault, no return, no new incarnation
    e.exit_confirmed(t0, 2);
    e.exit_confirmed(t0, 0);
    assert_eq!((e.incarnation(), e.held_slots()), (1, 1));
    assert_eq!(out(&e, id).decision, None);
    assert!(out(&e, id).returns.is_empty() && !out(&e, id).incomplete);
    cont(&mut e, t0, 100, 1, 1).unwrap();
    assert_eq!(drain(&mut e, t0).len(), 3);
    // the exit of the current one counts once
    e.exit_confirmed(t0, 1);
    assert_eq!((e.incarnation(), e.held_slots()), (2, 0));
    assert_eq!(
        out(&e, id).returns,
        vec![(100, ReturnReason::ExitConfirmed)]
    );
    e.exit_confirmed(t0, 1);
    assert_eq!((e.incarnation(), out(&e, id).returns.len()), (2, 1));
}

// ---- request records ----

#[test]
fn a_full_record_table_refuses_without_a_record() {
    let t0 = Instant::now();
    let limits = Limits {
        records: 1,
        ..limits()
    };
    let mut e = Engine::new(limits, 1, 100);
    // an immediate decision is a record too
    let invalid = Request {
        begin: vec![],
        ..request()
    };
    let bad = e.submit(t0, invalid).unwrap();
    let invalid = Decision::Uninspectable(Why::Invalid);
    assert_eq!(out(&e, bad).decision, Some(invalid));
    assert_eq!(e.submit(t0, request()), Err(SubmitError::Full));
    assert_eq!((e.records(), e.waiting(), e.held_slots()), (1, 0, 0));
    // a record ends when its decision was handed over and no slot is held: room again
    assert_eq!(e.next_done(), Some((bad, invalid)));
    assert_eq!(e.records(), 0);
    assert_eq!(e.submit(t0, request()), Ok(1));
}

#[test]
fn request_numbers_run_out_without_a_record() {
    let t0 = Instant::now();
    let mut e = Engine::new(limits(), 1, 100);
    e.next_req = Some(u64::MAX);
    let last = e.submit(t0, request()).unwrap();
    assert_eq!(last, u64::MAX);
    assert_eq!(e.submit(t0, request()), Err(SubmitError::IdsExhausted));
    assert_eq!(e.records(), 1);
    // no number is used twice, also after the record ended
    assert_eq!(
        e.next_done(),
        None,
        "an undecided request is not handed over"
    );
    e.cancel(t0, last);
    assert_eq!(e.next_done(), Some((last, Decision::ClientDisconnect)));
    assert_eq!(e.records(), 0);
    assert_eq!(e.submit(t0, request()), Err(SubmitError::IdsExhausted));
}

#[test]
fn a_decision_is_handed_over_once() {
    // decided without a slot: once, in the order they were decided; the record ends with the hand-over
    let (mut e, t0) = start();
    let a = e.submit(t0, request()).unwrap();
    let b = e.submit(t0, request()).unwrap();
    let c = e.submit(t0, request()).unwrap();
    assert_eq!(drain(&mut e, t0).len(), 3);
    assert_eq!(e.next_done(), None);
    blk(&mut e, t0, 101, 1, 1).unwrap();
    blk(&mut e, t0, 100, 1, 1).unwrap();
    assert_eq!(e.next_done(), Some((b, blocked(1))));
    assert_eq!(e.next_done(), Some((a, blocked(1))));
    assert_eq!(e.next_done(), None);
    // more events do not hand over a request again
    blk(&mut e, t0, 100, 1, 1).unwrap();
    e.cancel(t0, a);
    e.cancel(t0, c);
    e.tick(at(t0, 60_000));
    assert_eq!(e.next_done(), Some((c, Decision::ClientDisconnect)));
    assert_eq!(e.next_done(), None);
}

#[test]
fn the_record_of_a_decision_handed_over_ends_with_the_slot() {
    // decided, slot held: handed over once, the record stays, CLOSED returns the slot and ends it
    let Fx { mut e, t0, id, tx } = row_p1();
    blk(&mut e, t0, tx, 1, 1).unwrap();
    assert_eq!(e.next_done(), Some((id, blocked(1))));
    assert_eq!(e.next_done(), None);
    assert_eq!(out(&e, id).decision, Some(blocked(1)));
    assert_eq!(e.records(), 1);
    let end = take(&mut e, t0);
    e.frame_written(t0, tx, end.msg);
    closed(&mut e, t0, tx, end.msg).unwrap();
    assert!(e.outcome(id).is_none());
    assert_eq!((e.records(), e.held_slots()), (0, 0));
    assert_eq!(e.next_done(), None);
    // undecided, then the connection fault: handed over with the fault, the exit ends the record
    let Fx { mut e, t0, id, .. } = row_p1();
    e.conn_fault(t0);
    assert_eq!(
        e.next_done(),
        Some((id, Decision::Uninspectable(Why::ConnFault)))
    );
    assert_eq!(e.outcome(id).map(|o| o.returns.len()), Some(0));
    e.exit_confirmed(t0, 1);
    assert!(e.outcome(id).is_none());
    assert_eq!((e.records(), e.held_slots()), (0, 0));
    assert_eq!(e.next_done(), None);
}

// ---- the halt and a connection fault ----

#[test]
fn a_fault_after_the_halt_decides_the_unsent_requests() {
    let (mut e, t0) = start();
    let a = e.submit(t0, request()).unwrap();
    let b = e.submit(t0, request()).unwrap();
    let c = e.submit(t0, request()).unwrap();
    // a is taken; b and c wait in the writer queue
    let f = take(&mut e, t0);
    assert_eq!((f.tx, f.kind), (100, OutKind::TxBegin));
    e.halt(t0, Halt::Drain);
    e.conn_fault(at(t0, 5));
    // not queued again: decided at once, in order, with the first reason
    assert_eq!((e.held_slots(), e.waiting()), (1, 0));
    for (id, tx) in [(b, 101), (c, 102)] {
        let o = out(&e, id);
        assert_eq!(
            o.decision,
            Some(Decision::Uninspectable(Why::Halted(Halt::Drain)))
        );
        assert_eq!(o.decided_at, Some(at(t0, 5)));
        assert_eq!(o.returns, vec![(tx, ReturnReason::BeforeBegin)]);
        assert!(!o.incomplete && !o.close_unconfirmed);
    }
    assert_eq!(
        out(&e, a).decision,
        Some(Decision::Uninspectable(Why::ConnFault))
    );
    let order: Vec<ReqId> = std::iter::from_fn(|| e.next_done().map(|(id, _)| id)).collect();
    assert_eq!(order, vec![b, c, a]);
    // the exit: the taken one returns; nothing waits, nothing is assigned after the restart
    e.exit_confirmed(at(t0, 6), 1);
    e.ready(at(t0, 7), 2);
    assert_eq!((e.held_slots(), e.waiting(), e.records()), (0, 0, 0));
    assert!(e.next_frame(at(t0, 7)).is_none());
}
