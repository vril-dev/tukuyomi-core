//! Transaction slots, waiting requests, numbering, the single writer queue and the deadline rules of
//! held transactions and waiting requests, driven by events and the caller's clock. No I/O, no threads,
//! no `Instant::now()`.
//!
//! After a connection fault no further frames are handed to the writer and responses are ignored for
//! that connection. New requests may still wait for restart. The writer takes the next frame just
//! before writing it. On a non-faulted connection, answers for issued transaction numbers no longer
//! held are discarded and counted; exceeding the discard limit or receiving an unissued number
//! faults the connection. Each request receives at most one final decision.
//!
//! Deadlines are absolute `Instant`s and expire when `now` is strictly after them. An `Instant` that
//! would overflow becomes an already expired deadline (fail closed). A deadline is never extended or
//! replaced by a later event. `tick` and every event entry apply the deadlines that have passed by their
//! own `now` first (`expire`; not after a connection fault), so an answer is never judged by a state that
//! its own time has already left.
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, VecDeque};
use std::mem;
use std::time::{Duration, Instant};

/// Upper bounds checked before anything is sent: a TX_BEGIN payload 32 KiB, a body fragment 64 KiB, 16 fragments.
const MAX_BEGIN: usize = 32 * 1024;
const MAX_FRAG: usize = 64 * 1024;
const MAX_FRAGS: usize = 16;

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Concurrent transactions.
    pub slots: usize,
    /// Requests waiting for a slot.
    pub wait_queue: usize,
    /// Request records alive at once: undecided, decided but not handed over by `next_done`, and handed over
    /// while their slot is still held.
    pub records: usize,
    /// Responses that may be discarded and counted per incarnation: the discard that takes the count above
    /// this limit is a connection fault.
    pub discard_limit: u32,
    /// Wait for a verdict, from the moment the writer took the request frame.
    pub verdict_wait: Duration,
    /// Wait for a slot and for the writer to take TX_BEGIN, from `submit`.
    pub wait_deadline: Duration,
    /// Wait for CLOSED, from `frame_written` of TX_END.
    pub closed_wait: Duration,
    /// Stop threshold: how long after the abandon or the hand-over of TX_END a slot that has not been returned
    /// is a reason to stop the inspector; see `StopOrigin`.
    pub stop_after: Duration,
}

pub type ReqId = u64;

#[derive(Clone, Debug)]
pub struct Request {
    /// Encoded TX_BEGIN payload (1..=32 KiB).
    pub begin: Vec<u8>,
    /// Body fragments, each 1..=65536 bytes, at most 16.
    pub body: Vec<Vec<u8>>,
}

/// Why `submit` made no record and sent nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SubmitError {
    /// `Limits::records` records are alive.
    Full,
    /// The request numbers are used up.
    IdsExhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutKind {
    TxBegin,
    Body,
    BodyEnd,
    /// The reason is 1 done, 2 blocked, 3 uninspectable, 4 client disconnect, 5 deadline.
    TxEnd(u8),
}

/// One frame for the writer. `payload` is the frame's payload bytes as they go on the wire: the encoded
/// TX_BEGIN, a body fragment, empty for BODY_END, and `[reason]` for TX_END.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outgoing {
    pub tx: u64,
    pub msg: u32,
    pub kind: OutKind,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Halt {
    /// The transaction numbers are used up: nothing is assigned any more.
    TxExhausted,
    /// The incarnation numbers are used up: no restart.
    IncExhausted,
    /// A message number would overflow (cannot happen with the sending rule; kept checked). It takes the
    /// place of an earlier reason: nothing is sent any more.
    MsgOverflow,
    /// The session sent DRAIN (set via `halt`): nothing new is taken; the taken transactions end.
    Drain,
    /// The inspector exited and is not restarted (set via `halt`).
    NoRestart,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// The request failed the checks made before sending.
    Invalid,
    /// The waiting queue was full.
    QueueFull,
    Halted(Halt),
    /// Waited longer than `wait_deadline`, for a slot or for the writer to take TX_BEGIN.
    WaitDeadline,
    /// Abandoned: no verdict within `verdict_wait`.
    VerdictDeadline,
    /// Connection-wide fault or inspector exit while undecided.
    ConnFault,
    /// Wrong phase / message number / content, CLOSED before TX_END, "not created" that is not legitimate.
    Order,
    /// ERROR of a created transaction.
    TxError {
        code: u16,
    },
    /// A legitimate "not created" ERROR (return reason (3)).
    NotCreated {
        code: u16,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Forward,
    Block {
        phase: u8,
        rule_id: i64,
        status: u16,
    },
    Uninspectable(Why),
    ClientDisconnect,
}

/// The four reasons a slot is returned; they all go through `Engine::release`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReturnReason {
    /// (1) CLOSED that answers TX_END.
    Closed,
    /// (2) The inspector's exit was confirmed.
    ExitConfirmed,
    /// (3) A legitimate "not created" ERROR.
    NotCreated,
    /// (4) Cancelled or expired before the writer took TX_BEGIN; nothing was sent.
    BeforeBegin,
}

/// Where a stop time comes from: (a) the abandon (verdict deadline) or (b) the hand-over of TX_END.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopOrigin {
    Abandoned,
    Sent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StopPlan {
    /// The stop time. Where it does not fit in an `Instant` this is the base time it was counted from (the
    /// deadline, the hand-over or the time the wait was found over) as the record; the stop is due at once.
    pub at: Instant,
    pub origin: StopOrigin,
    /// The plan was taken off by (1) or (3). The `at` and `origin` stay as the record.
    pub cleared: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StopReason {
    pub req: ReqId,
    pub tx: u64,
    /// The `at` of the plan.
    pub at: Instant,
    pub origin: StopOrigin,
}

/// A connection-wide fault found in an answer. The engine has already applied `conn_fault` when it returns
/// one (nothing more is handed to the writer); the caller kills the inspector and calls `exit_confirmed`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnFault {
    /// A response for a transaction number that was never assigned.
    Unissued { tx: u64 },
    /// A response for a transaction whose TX_BEGIN the writer has not taken (never sent).
    NotSent { tx: u64 },
    /// More than `discard_limit` responses discarded in this incarnation.
    DiscardLimit,
}

/// What happened to a request. Only the engine writes it.
#[derive(Clone, Debug, Default)]
pub struct Outcome {
    /// The final decision, once.
    pub decision: Option<Decision>,
    pub decided_at: Option<Instant>,
    /// Transaction numbers assigned, in order (a request restored to the waiting queue gets another).
    pub txs: Vec<u64>,
    /// Slot returns: the transaction and the reason.
    pub returns: Vec<(u64, ReturnReason)>,
    /// Evidence that the inspector created the current transaction (a legitimate VERDICT or an ERROR of
    /// class 2), also recorded after the decision.
    pub created: bool,
    /// The decision was final but Close was not confirmed (CLOSED wait passed, or the connection fault /
    /// exit came first for a transaction whose TX_END was already handed over).
    pub close_unconfirmed: bool,
    /// The connection fault / exit came while the decision was still open for a transaction whose
    /// TX_BEGIN the writer had taken: it became uninspectable. Kept apart from `close_unconfirmed`.
    pub incomplete: bool,
    /// A legitimate CLOSED arrived after `close_unconfirmed` was recorded (a separate item).
    pub close_confirmed_late: bool,
    /// Close error flag of the legitimate CLOSED.
    pub close_error: Option<bool>,
    pub stop: Option<StopPlan>,
    /// Responses discarded and counted (duplicates and records after the decision) for this request.
    pub late: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// TX_BEGIN is in the writer queue, not taken.
    BeginQueued,
    /// TX_BEGIN taken; phase 1 verdict awaited.
    P1,
    /// Phase 1 continued; BODY / BODY_END are queued or being taken.
    Body,
    /// BODY_END taken; phase 2 verdict awaited.
    P2,
    /// TX_END was handed to the writer queue (or the connection failed).
    Ended,
}

/// A VERDICT or ERROR already received for a transaction; only an exact repeat is a "duplicate". CLOSED
/// is not kept: whether it answers TX_END is decided by the state, and a repeat of one that did not is
/// dropped as a decided transaction's answer anyway.
#[derive(PartialEq)]
enum Seen {
    Verdict {
        msg: u32,
        phase: u8,
        block: bool,
        rule_id: i64,
        status: u16,
        payload: Vec<u8>,
    },
    Error {
        msg: u32,
        class: u8,
        code: u16,
        payload: Vec<u8>,
    },
}

/// A held slot.
struct Live {
    tx: u64,
    req: ReqId,
    stage: Stage,
    /// The message number the next taken frame gets; `None` after u32::MAX was used.
    next_msg: Option<u32>,
    begin_msg: Option<u32>,
    body_msgs: Vec<u32>,
    body_end_msg: Option<u32>,
    /// The message number of TX_END, recorded by the first take and never overwritten.
    end_msg: Option<u32>,
    /// The phase 1 wait ended by deadline or disconnect with no answer.
    p1_unanswered: bool,
    verdict_due: Option<Instant>,
    closed_due: Option<Instant>,
    /// The CLOSED wait started where its end overflows: it is over at once (`close_unconfirmed` was set
    /// then) and is not started again.
    closed_overflow: bool,
    /// The stop time overflowed: it is due at once. `Outcome::stop.at` keeps the base time as the record.
    stop_overflow: bool,
    seen: Vec<Seen>,
}

impl Live {
    fn new(tx: u64, req: ReqId) -> Live {
        Live {
            tx,
            req,
            stage: Stage::BeginQueued,
            next_msg: Some(1),
            begin_msg: None,
            body_msgs: Vec::new(),
            body_end_msg: None,
            end_msg: None,
            p1_unanswered: false,
            verdict_due: None,
            closed_due: None,
            closed_overflow: false,
            stop_overflow: false,
            seen: Vec::new(),
        }
    }

    /// The message number was handed out by `next_frame`.
    fn taken(&self, msg: u32) -> bool {
        msg >= 1 && self.next_msg.is_none_or(|n| msg < n)
    }

    /// The VERDICT's phase answers a frame that was taken: 1 TX_BEGIN, 2 BODY / BODY_END. Phases 3 and 4 answer
    /// nothing this side sends.
    fn correlated(&self, phase: u8, msg: u32) -> bool {
        match phase {
            1 => self.begin_msg == Some(msg),
            2 => self.body_msgs.contains(&msg) || self.body_end_msg == Some(msg),
            _ => false,
        }
    }
}

enum QKind {
    Begin,
    Body(usize),
    BodyEnd,
    End(u8),
}

struct QFrame {
    tx: u64,
    kind: QKind,
}

struct Req {
    out: Outcome,
    req: Request,
    /// `submit` time + `wait_deadline`; kept when the request goes back to the waiting queue. `None`: the
    /// time overflows, the wait is over at once.
    wait_until: Option<Instant>,
    /// `next_done` handed the decision over. The record goes with the last slot the request holds.
    delivered: bool,
}

/// How a stage ends. `Done` is the continue of the last phase (Forward).
#[derive(Clone, Copy)]
enum Ending {
    Block {
        phase: u8,
        rule_id: i64,
        status: u16,
    },
    Uninspectable(Why),
    Disconnect,
    Done,
}

pub struct Engine {
    limits: Limits,
    inc: u32,
    /// The next transaction number; `None` when the numbers are used up.
    next_tx: Option<u64>,
    ready: bool,
    faulted: bool,
    halt: Option<Halt>,
    /// The request numbers start at 0 and are never used twice; `None` when they are used up.
    next_req: Option<ReqId>,
    reqs: BTreeMap<ReqId, Req>,
    waiting: VecDeque<ReqId>,
    /// The requests whose decision `next_done` has not handed over, in the order they were decided.
    done: VecDeque<ReqId>,
    held: Vec<Live>,
    out: VecDeque<QFrame>,
    discarded: u32,
}

/// `t + d`, or `None` where it does not fit: such a deadline is already over (fail closed), so every caller
/// decides at once instead of keeping a time.
fn after(t: Instant, d: Duration) -> Option<Instant> {
    t.checked_add(d)
}

fn frags_ok(f: &[Vec<u8>]) -> bool {
    f.len() <= MAX_FRAGS && f.iter().all(|b| (1..=MAX_FRAG).contains(&b.len()))
}

fn valid(r: &Request) -> bool {
    (1..=MAX_BEGIN).contains(&r.begin.len()) && frags_ok(&r.body)
}

/// The payloads are no longer needed once the request is decided.
fn free(r: &mut Req) {
    r.req = Request {
        begin: Vec::new(),
        body: Vec::new(),
    };
}

/// The record of a request that waits or holds a slot. It lives until its decision was handed over and its last
/// slot returned, so it is there whenever a queue or a held slot names it.
fn rec(reqs: &mut BTreeMap<ReqId, Req>, id: ReqId) -> &mut Req {
    reqs.get_mut(&id)
        .expect("a request named by a queue or a held slot has its record")
}

impl Engine {
    /// A new engine in the starting state (before HELLO): nothing is assigned until `ready`.
    pub fn new(limits: Limits, first_inc: u32, first_tx: u64) -> Engine {
        Engine {
            limits,
            inc: first_inc,
            next_tx: Some(first_tx),
            ready: false,
            faulted: false,
            halt: None,
            next_req: Some(0),
            reqs: BTreeMap::new(),
            waiting: VecDeque::new(),
            done: VecDeque::new(),
            held: Vec::new(),
            out: VecDeque::new(),
            discarded: 0,
        }
    }

    /// HELLO of incarnation `inc` was checked: waiting requests get slots. Ignored between a connection fault
    /// and `exit_confirmed`, and for an incarnation other than the current one.
    pub(crate) fn ready(&mut self, now: Instant, inc: u32) {
        if inc != self.inc || self.faulted {
            return;
        }
        self.expire(now);
        self.ready = true;
        self.assign(now);
    }

    /// A new request. Full queue, halt, failed checks and a wait deadline that overflows decide it at once
    /// as uninspectable (the record is made). No record is made, and no request number is used, when `records`
    /// records are alive or the request numbers are used up.
    pub(crate) fn submit(&mut self, now: Instant, req: Request) -> Result<ReqId, SubmitError> {
        if !self.faulted {
            self.expire(now);
        }
        if self.reqs.len() >= self.limits.records {
            return Err(SubmitError::Full);
        }
        let Some(id) = self.next_req else {
            return Err(SubmitError::IdsExhausted);
        };
        self.next_req = id.checked_add(1);
        let wait_until = after(now, self.limits.wait_deadline);
        let why = if !valid(&req) {
            Some(Why::Invalid)
        } else if let Some(h) = self.halt {
            Some(Why::Halted(h))
        } else if self.waiting.len() >= self.limits.wait_queue {
            Some(Why::QueueFull)
        } else if wait_until.is_none() {
            Some(Why::WaitDeadline)
        } else {
            None
        };
        let mut r = Req {
            out: Outcome::default(),
            req,
            wait_until,
            delivered: false,
        };
        match why {
            Some(w) => {
                r.out.decision = Some(Decision::Uninspectable(w));
                r.out.decided_at = Some(now);
                free(&mut r);
                self.reqs.insert(id, r);
                self.done.push_back(id);
            }
            None => {
                self.reqs.insert(id, r);
                self.waiting.push_back(id);
                self.assign(now);
            }
        }
        Ok(id)
    }

    /// The client went away.
    pub fn cancel(&mut self, now: Instant, id: ReqId) {
        if !self.faulted {
            self.expire(now);
        }
        if !self.reqs.contains_key(&id) {
            return;
        }
        let ri = id;
        if let Some(wp) = self.waiting.iter().position(|&r| r == ri) {
            self.waiting.remove(wp);
            self.settle(ri, now, Decision::ClientDisconnect);
            return;
        }
        let Some(ti) = self.held.iter().position(|l| l.req == ri) else {
            return;
        };
        match self.held[ti].stage {
            Stage::BeginQueued => {
                // (4): the writer has not taken TX_BEGIN; nothing was sent.
                self.settle(ri, now, Decision::ClientDisconnect);
                self.release(ti, ReturnReason::BeforeBegin);
                self.assign(now);
            }
            Stage::P1 => {
                self.held[ti].p1_unanswered = true;
                self.end_tx(now, ti, Ending::Disconnect);
            }
            Stage::Ended => {}
            _ => self.end_tx(now, ti, Ending::Disconnect),
        }
    }

    /// The writer's take. The message number is assigned here and the correlation and the state become
    /// valid at the same moment, before the frame is written. `None` after a connection fault and after
    /// `Halt::MsgOverflow`, which this call itself can raise: that `None` looks like an empty queue, so the
    /// caller checks `halted()` and `tick` after the call too, before writing anything.
    pub fn next_frame(&mut self, now: Instant) -> Option<Outgoing> {
        if self.faulted || self.halt == Some(Halt::MsgOverflow) {
            return None;
        }
        self.expire(now);
        let verdict_wait = self.limits.verdict_wait;
        loop {
            let q = self.out.pop_front()?;
            // release() takes the frames of a returned transaction out of the queue; this is a guard.
            let Some(ti) = self.held.iter().position(|l| l.tx == q.tx) else {
                continue;
            };
            // A frame that starts a verdict wait is handed out only if the end of the wait fits; if it does
            // not, the wait is over already. This is decided before the frame gets a number and before the
            // stage changes: the frame is never handed out.
            let starts_wait = matches!(q.kind, QKind::Begin | QKind::BodyEnd);
            let due = after(now, verdict_wait);
            if starts_wait && due.is_none() {
                let ri = self.held[ti].req;
                if matches!(q.kind, QKind::Begin) {
                    // (4): nothing was sent
                    self.settle(ri, now, Decision::Uninspectable(Why::VerdictDeadline));
                    self.release(ti, ReturnReason::BeforeBegin);
                    self.assign(now);
                } else {
                    // The abandon of `expire`; its stop time (a) is due at once, `at` is the record.
                    let o = &mut rec(&mut self.reqs, ri).out;
                    if o.stop.is_none() {
                        o.stop = Some(StopPlan {
                            at: now,
                            origin: StopOrigin::Abandoned,
                            cleared: false,
                        });
                        self.held[ti].stop_overflow = true;
                    }
                    self.end_tx(now, ti, Ending::Uninspectable(Why::VerdictDeadline));
                }
                continue;
            }
            let l = &mut self.held[ti];
            let Some(msg) = l.next_msg else {
                self.set_halt(now, Halt::MsgOverflow);
                return None;
            };
            l.next_msg = msg.checked_add(1);
            let r = rec(&mut self.reqs, l.req);
            let (kind, payload) = match q.kind {
                QKind::Begin => {
                    l.stage = Stage::P1;
                    l.begin_msg = Some(msg);
                    l.verdict_due = due;
                    (OutKind::TxBegin, mem::take(&mut r.req.begin))
                }
                QKind::Body(i) => {
                    l.body_msgs.push(msg);
                    (
                        OutKind::Body,
                        r.req.body.get_mut(i).map(mem::take).unwrap_or_default(),
                    )
                }
                QKind::BodyEnd => {
                    l.stage = Stage::P2;
                    l.body_end_msg = Some(msg);
                    l.verdict_due = due;
                    (OutKind::BodyEnd, Vec::new())
                }
                QKind::End(reason) => {
                    l.end_msg.get_or_insert(msg);
                    (OutKind::TxEnd(reason), vec![reason])
                }
            };
            return Some(Outgoing {
                tx: q.tx,
                msg,
                kind,
                payload,
            });
        }
    }

    /// The writer finished one whole frame. For TX_END this starts the CLOSED wait.
    pub fn frame_written(&mut self, now: Instant, tx: u64, msg: u32) {
        if self.faulted {
            return;
        }
        self.expire(now);
        let closed_wait = self.limits.closed_wait;
        if let Some(l) = self.held.iter_mut().find(|l| l.tx == tx)
            && l.end_msg == Some(msg)
            && l.closed_due.is_none()
            && !l.closed_overflow
        {
            l.closed_due = after(now, closed_wait);
            if l.closed_due.is_none() {
                // The wait is over at once: Close is unconfirmed, and the wait is not started again.
                l.closed_overflow = true;
                rec(&mut self.reqs, l.req).out.close_unconfirmed = true;
            }
        }
    }

    /// A VERDICT. `payload` is only compared bytewise to tell an exact repeat from a different answer.
    #[allow(clippy::too_many_arguments)]
    pub fn on_verdict(
        &mut self,
        now: Instant,
        tx: u64,
        msg: u32,
        phase: u8,
        block: bool,
        rule_id: i64,
        status: u16,
        payload: &[u8],
    ) -> Result<(), ConnFault> {
        if !self.faulted {
            self.expire(now);
        }
        let seen = Seen::Verdict {
            msg,
            phase,
            block,
            rule_id,
            status,
            payload: payload.to_vec(),
        };
        if let Some(ti) = self.incoming(now, tx, Some(seen))? {
            self.verdict(now, ti, msg, phase, block, rule_id, status)?;
        }
        self.assign(now);
        Ok(())
    }

    /// An ERROR: class 1 "not created", class 2 "failure of a created transaction"; anything else is
    /// treated as out of order.
    pub fn on_error(
        &mut self,
        now: Instant,
        tx: u64,
        msg: u32,
        class: u8,
        code: u16,
        payload: &[u8],
    ) -> Result<(), ConnFault> {
        if !self.faulted {
            self.expire(now);
        }
        let seen = Seen::Error {
            msg,
            class,
            code,
            payload: payload.to_vec(),
        };
        if let Some(ti) = self.incoming(now, tx, Some(seen))? {
            self.error(now, ti, msg, class, code)?;
        }
        self.assign(now);
        Ok(())
    }

    /// A CLOSED. Only the one that carries TX_END's message number returns the slot, (1).
    /// The payload is not needed: only the state decides.
    pub fn on_closed(
        &mut self,
        now: Instant,
        tx: u64,
        msg: u32,
        close_error: bool,
        _payload: &[u8],
    ) -> Result<(), ConnFault> {
        if !self.faulted {
            self.expire(now);
        }
        if let Some(ti) = self.incoming(now, tx, None)? {
            if self.held[ti].end_msg == Some(msg) {
                let o = &mut rec(&mut self.reqs, self.held[ti].req).out;
                o.close_error = Some(close_error);
                if o.close_unconfirmed {
                    o.close_confirmed_late = true;
                }
                self.release(ti, ReturnReason::Closed);
            } else {
                self.order(now, ti)?;
            }
        }
        self.assign(now);
        Ok(())
    }

    /// The stop times: the first one that has passed, after `expire` (also called by every event entry); a
    /// stop time that does not fit has passed at once.
    /// Returns nothing after a connection fault.
    pub fn tick(&mut self, now: Instant) -> Option<StopReason> {
        self.expire(now);
        if self.faulted {
            return None;
        }
        let mut stop: Option<StopReason> = None;
        for l in &self.held {
            let o = &self.reqs[&l.req].out;
            if let Some(p) = o.stop.filter(|p| l.stop_overflow || now > p.at)
                && stop.is_none_or(|s| p.at < s.at)
            {
                stop = Some(StopReason {
                    req: l.req,
                    tx: l.tx,
                    at: p.at,
                    origin: p.origin,
                });
            }
        }
        stop
    }

    /// The connection failed or the inspector was stopped (before the kill). Undecided transactions
    /// become uninspectable and are recorded as incomplete; Close is unconfirmed for the decided ones
    /// (TX_END already handed over); transactions whose TX_BEGIN the writer never took are returned by (4)
    /// and their requests go back to the front of the waiting queue, with neither record. Where the intake
    /// has been ended (`halt`), they are decided at once as `Halted` with the first reason instead.
    /// The taken transactions keep their slots until `exit_confirmed`.
    pub fn conn_fault(&mut self, now: Instant) {
        if self.faulted {
            return;
        }
        self.faulted = true;
        self.ready = false;
        self.out.clear();
        let mut unsent: Vec<u64> = self
            .held
            .iter()
            .filter(|l| l.stage == Stage::BeginQueued)
            .map(|l| l.tx)
            .collect();
        if self.halt.is_none() {
            // Back to the front of the queue one by one: the last one first keeps the order.
            unsent.reverse();
        }
        for tx in unsent {
            if let Some(ti) = self.held.iter().position(|l| l.tx == tx) {
                let ri = self.held[ti].req;
                self.release(ti, ReturnReason::BeforeBegin);
                match self.halt {
                    Some(h) => self.settle(ri, now, Decision::Uninspectable(Why::Halted(h))),
                    None => self.waiting.push_front(ri),
                }
            }
        }
        for ti in 0..self.held.len() {
            let undecided = self.held[ti].stage != Stage::Ended;
            self.set_result(now, ti, Ending::Uninspectable(Why::ConnFault));
            let l = &mut self.held[ti];
            l.stage = Stage::Ended;
            l.verdict_due = None;
            l.closed_due = None;
            let o = &mut rec(&mut self.reqs, l.req).out;
            if undecided {
                o.incomplete = true;
            } else {
                o.close_unconfirmed = true;
            }
        }
    }

    /// The exit of incarnation `inc` was confirmed: every held slot is returned by (2), the queue and the
    /// discard count start empty for the next incarnation, which is numbered one higher (overflow halts). It
    /// counts once: a call for another incarnation than the current one does nothing.
    pub(crate) fn exit_confirmed(&mut self, now: Instant, inc: u32) {
        if inc != self.inc {
            return;
        }
        self.conn_fault(now);
        while !self.held.is_empty() {
            self.release(0, ReturnReason::ExitConfirmed);
        }
        self.out.clear();
        self.discarded = 0;
        self.faulted = false;
        self.ready = false;
        match self.inc.checked_add(1) {
            Some(n) => self.inc = n,
            None => self.set_halt(now, Halt::IncExhausted),
        }
    }

    /// The next decision that was not handed over, in the order they were decided, and the end of its record
    /// if no slot is held for it: the record of a decision handed over while its slot is held goes when the
    /// slot returns. A request is handed over once.
    pub(crate) fn next_done(&mut self) -> Option<(ReqId, Decision)> {
        loop {
            let id = self.done.pop_front()?;
            let Some(r) = self.reqs.get_mut(&id) else {
                continue;
            };
            let Some(d) = r.out.decision else {
                continue;
            };
            r.delivered = true;
            if !self.held.iter().any(|l| l.req == id) {
                self.reqs.remove(&id);
            }
            return Some((id, d));
        }
    }

    #[cfg(test)]
    pub fn outcome(&self, id: ReqId) -> Option<&Outcome> {
        self.reqs.get(&id).map(|r| &r.out)
    }

    pub fn held_slots(&self) -> usize {
        self.held.len()
    }

    pub fn waiting(&self) -> usize {
        self.waiting.len()
    }

    /// The frames in the writer queue that no `next_frame` has taken yet.
    pub fn queued(&self) -> usize {
        self.out.len()
    }

    /// The request records alive.
    pub fn records(&self) -> usize {
        self.reqs.len()
    }

    #[cfg(test)]
    pub fn discarded(&self) -> u32 {
        self.discarded
    }

    /// The incarnation number the frames of the current inspector carry.
    pub fn incarnation(&self) -> u32 {
        self.inc
    }

    /// Why the engine assigns nothing any more, if it does not. It can change inside `next_frame`; it is
    /// never lifted (not by `exit_confirmed` either) and keeps the first reason, except `MsgOverflow`, after
    /// which nothing is sent any more.
    pub fn halted(&self) -> Option<Halt> {
        self.halt
    }

    /// The session ends the intake for good (DRAIN, or no restart after the exit): every waiting request,
    /// also one that `conn_fault` put back, is decided at once as `Halted` with the first reason. Taken
    /// transactions go on to their end (only `MsgOverflow` stops `next_frame`).
    pub fn halt(&mut self, now: Instant, h: Halt) {
        self.set_halt(now, h);
    }

    fn set_halt(&mut self, now: Instant, h: Halt) {
        // The first reason stays, except that a message number overflow takes its place: `next_frame` stops
        // at that one alone, so nothing may be handed out after it, whatever the reason was before.
        if h == Halt::MsgOverflow {
            self.halt = Some(h);
        }
        let h = *self.halt.get_or_insert(h);
        while let Some(ri) = self.waiting.pop_front() {
            self.settle(ri, now, Decision::Uninspectable(Why::Halted(h)));
        }
    }

    /// Deadlines: waiting requests (also during a restart), TX_BEGIN not taken, verdict waits and CLOSED
    /// waits. `tick` and the event entries call it first with their own `now`.
    fn expire(&mut self, now: Instant) {
        let expired: Vec<ReqId> = self
            .waiting
            .iter()
            .copied()
            .filter(|r| self.reqs[r].wait_until.is_none_or(|w| now > w))
            .collect();
        for ri in expired {
            self.waiting.retain(|&r| r != ri);
            self.settle(ri, now, Decision::Uninspectable(Why::WaitDeadline));
        }
        // The same wait covers the time until the writer takes TX_BEGIN: (4), nothing was sent.
        let unsent: Vec<u64> = self
            .held
            .iter()
            .filter(|l| {
                l.stage == Stage::BeginQueued
                    && self.reqs[&l.req].wait_until.is_none_or(|w| now > w)
            })
            .map(|l| l.tx)
            .collect();
        for tx in unsent {
            if let Some(ti) = self.held.iter().position(|l| l.tx == tx) {
                let ri = self.held[ti].req;
                self.settle(ri, now, Decision::Uninspectable(Why::WaitDeadline));
                self.release(ti, ReturnReason::BeforeBegin);
            }
        }
        self.assign(now);
        if self.faulted {
            return;
        }
        let stop_after = self.limits.stop_after;
        for ti in 0..self.held.len() {
            let l = &mut self.held[ti];
            let Some(due) = l.verdict_due.filter(|&d| now > d) else {
                continue;
            };
            if l.stage == Stage::P1 {
                l.p1_unanswered = true;
            }
            let o = &mut rec(&mut self.reqs, l.req).out;
            if o.stop.is_none() {
                // A stop time that overflows is due at once; `at` keeps the base time as the record.
                let (at, overflow) = match after(due, stop_after) {
                    Some(t) => (t, false),
                    None => (due, true),
                };
                o.stop = Some(StopPlan {
                    at,
                    origin: StopOrigin::Abandoned,
                    cleared: false,
                });
                l.stop_overflow = overflow;
            }
            self.end_tx(now, ti, Ending::Uninspectable(Why::VerdictDeadline));
        }
        for l in &self.held {
            if l.closed_due.is_some_and(|c| now > c) {
                rec(&mut self.reqs, l.req).out.close_unconfirmed = true;
            }
        }
    }

    /// Slots for waiting requests, in order. The numbers are checked before anything else.
    fn assign(&mut self, now: Instant) {
        while !self.waiting.is_empty() && self.halt.is_none() {
            let Some(tx) = self.next_tx else {
                self.set_halt(now, Halt::TxExhausted);
                return;
            };
            if !self.ready || self.faulted || self.held.len() >= self.limits.slots {
                return;
            }
            let Some(ri) = self.waiting.pop_front() else {
                return;
            };
            self.next_tx = tx.checked_add(1);
            let o = &mut rec(&mut self.reqs, ri).out;
            o.txs.push(tx);
            o.created = false;
            self.held.push(Live::new(tx, ri));
            self.out.push_back(QFrame {
                tx,
                kind: QKind::Begin,
            });
        }
    }

    /// The only place a slot goes from held to returned. The frames of the transaction that are still
    /// in the writer queue are taken out with it (they never get a message number). The record of a request whose
    /// decision was handed over ends with its slot.
    fn release(&mut self, ti: usize, reason: ReturnReason) {
        let l = self.held.remove(ti);
        self.out.retain(|q| q.tx != l.tx);
        let r = rec(&mut self.reqs, l.req);
        r.out.returns.push((l.tx, reason));
        if matches!(reason, ReturnReason::Closed | ReturnReason::NotCreated)
            && let Some(p) = r.out.stop.as_mut()
        {
            p.cleared = true;
        }
        if r.delivered {
            self.reqs.remove(&l.req);
        }
    }

    /// The common front of every response: unissued number, returned transaction, TX_BEGIN not taken,
    /// exact repeat. `Ok(Some(i))` is a response to handle for the held transaction `i`.
    fn incoming(
        &mut self,
        now: Instant,
        tx: u64,
        seen: Option<Seen>,
    ) -> Result<Option<usize>, ConnFault> {
        if self.faulted {
            return Ok(None);
        }
        if self.next_tx.is_some_and(|n| tx >= n) {
            self.conn_fault(now);
            return Err(ConnFault::Unissued { tx });
        }
        let Some(ti) = self.held.iter().position(|l| l.tx == tx) else {
            self.discard(now, None)?;
            return Ok(None);
        };
        let l = &mut self.held[ti];
        if l.stage == Stage::BeginQueued {
            self.conn_fault(now);
            return Err(ConnFault::NotSent { tx });
        }
        if let Some(seen) = seen {
            if l.seen.contains(&seen) {
                let ri = l.req;
                self.discard(now, Some(ri))?;
                return Ok(None);
            }
            l.seen.push(seen);
        }
        Ok(Some(ti))
    }

    /// A response is dropped and counted; the limit is per incarnation. Past it the connection is faulted.
    fn discard(&mut self, now: Instant, ri: Option<ReqId>) -> Result<(), ConnFault> {
        self.discarded = self.discarded.saturating_add(1);
        if let Some(r) = ri.and_then(|i| self.reqs.get_mut(&i)) {
            r.out.late = r.out.late.saturating_add(1);
        }
        if self.discarded > self.limits.discard_limit {
            self.conn_fault(now);
            Err(ConnFault::DiscardLimit)
        } else {
            Ok(())
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn verdict(
        &mut self,
        now: Instant,
        ti: usize,
        msg: u32,
        phase: u8,
        block: bool,
        rule_id: i64,
        status: u16,
    ) -> Result<(), ConnFault> {
        let l = &self.held[ti];
        let (stage, ri, correlated) = (l.stage, l.req, l.correlated(phase, msg));
        if stage == Stage::Ended {
            // After the decision: not used, but a legitimate answer is the evidence that it was created.
            if correlated {
                rec(&mut self.reqs, ri).out.created = true;
            }
            return self.discard(now, Some(ri));
        }
        // The phase the stage is in, and the frame whose continue completes it.
        let (in_phase, last) = match stage {
            Stage::P1 => (1, l.begin_msg),
            Stage::Body => (2, None),
            Stage::P2 => (2, l.body_end_msg),
            Stage::BeginQueued | Stage::Ended => (0, None),
        };
        if in_phase == 0 || phase != in_phase || !correlated {
            self.end_tx(now, ti, Ending::Uninspectable(Why::Order));
            return Ok(());
        }
        rec(&mut self.reqs, ri).out.created = true;
        if block {
            self.end_tx(
                now,
                ti,
                Ending::Block {
                    phase,
                    rule_id,
                    status,
                },
            );
        } else if last == Some(msg) {
            self.advance(now, ti);
        } else {
            self.end_tx(now, ti, Ending::Uninspectable(Why::Order));
        }
        Ok(())
    }

    fn error(
        &mut self,
        now: Instant,
        ti: usize,
        msg: u32,
        class: u8,
        code: u16,
    ) -> Result<(), ConnFault> {
        let l = &self.held[ti];
        let (stage, ri, taken, begin_msg, unanswered) =
            (l.stage, l.req, l.taken(msg), l.begin_msg, l.p1_unanswered);
        match class {
            1 => {
                // (3): answers the TX_BEGIN the writer took, creation not shown, still in the phase 1 wait or
                // left it by deadline or disconnect.
                let phase1 = stage == Stage::P1 || (stage == Stage::Ended && unanswered);
                if phase1 && begin_msg == Some(msg) && !self.reqs[&ri].out.created {
                    if stage == Stage::P1 {
                        self.settle(ri, now, Decision::Uninspectable(Why::NotCreated { code }));
                    }
                    self.release(ti, ReturnReason::NotCreated);
                    return Ok(());
                }
                self.order(now, ti)
            }
            2 => {
                if taken {
                    rec(&mut self.reqs, ri).out.created = true;
                }
                if stage == Stage::Ended {
                    return self.discard(now, Some(ri));
                }
                self.end_tx(now, ti, Ending::Uninspectable(Why::TxError { code }));
                Ok(())
            }
            _ => self.order(now, ti),
        }
    }

    /// An answer that does not fit: undecided becomes uninspectable, decided is recorded and counted.
    fn order(&mut self, now: Instant, ti: usize) -> Result<(), ConnFault> {
        if self.held[ti].stage == Stage::Ended {
            let ri = self.held[ti].req;
            return self.discard(now, Some(ri));
        }
        self.end_tx(now, ti, Ending::Uninspectable(Why::Order));
        Ok(())
    }

    /// The continue of the phase the stage waits for.
    fn advance(&mut self, now: Instant, ti: usize) {
        let l = &mut self.held[ti];
        let ri = l.req;
        match l.stage {
            Stage::P1 => {
                l.stage = Stage::Body;
                l.verdict_due = None;
                let tx = l.tx;
                for i in 0..self.reqs[&ri].req.body.len() {
                    self.out.push_back(QFrame {
                        tx,
                        kind: QKind::Body(i),
                    });
                }
                self.out.push_back(QFrame {
                    tx,
                    kind: QKind::BodyEnd,
                });
            }
            Stage::P2 => {
                // Phase 1 and phase 2 both continued: forward.
                self.set_result(now, ti, Ending::Done);
                self.close_tx(now, ti, 1);
            }
            _ => {}
        }
    }

    /// Record the result of the current stage once: the request decision. A decision other than Forward frees
    /// the payloads. The request is queued for `next_done` where the decision is first made.
    fn set_result(&mut self, now: Instant, ti: usize, e: Ending) {
        let l = &self.held[ti];
        if l.stage == Stage::Ended {
            return;
        }
        let id = l.req;
        let r = rec(&mut self.reqs, id);
        if r.out.decision.is_none() {
            r.out.decision = Some(match e {
                Ending::Block {
                    phase,
                    rule_id,
                    status,
                } => Decision::Block {
                    phase,
                    rule_id,
                    status,
                },
                Ending::Uninspectable(w) => Decision::Uninspectable(w),
                Ending::Disconnect => Decision::ClientDisconnect,
                Ending::Done => Decision::Forward,
            });
            r.out.decided_at = Some(now);
            self.done.push_back(id);
        }
        if !matches!(e, Ending::Done) {
            free(r);
        }
    }

    /// A decision on a request that has no transaction (waiting, or returned by (4)).
    fn settle(&mut self, ri: ReqId, now: Instant, d: Decision) {
        let r = rec(&mut self.reqs, ri);
        if r.out.decision.is_none() {
            r.out.decision = Some(d);
            r.out.decided_at = Some(now);
            self.done.push_back(ri);
        }
        free(r);
    }

    /// Settle the stage and hand TX_END to the writer queue.
    fn end_tx(&mut self, now: Instant, ti: usize, e: Ending) {
        let reason = match e {
            Ending::Done => 1,
            Ending::Block { .. } => 2,
            Ending::Uninspectable(Why::VerdictDeadline) => 5,
            Ending::Uninspectable(_) => 3,
            Ending::Disconnect => 4,
        };
        self.set_result(now, ti, e);
        self.close_tx(now, ti, reason);
    }

    /// TX_END goes to the writer queue, once. The frames not yet taken are dropped (they get no number).
    /// The stop time (b) starts here unless (a) already did; it is never moved.
    fn close_tx(&mut self, now: Instant, ti: usize, reason: u8) {
        if self.held[ti].stage == Stage::Ended {
            return;
        }
        let stop_after = self.limits.stop_after;
        let l = &mut self.held[ti];
        l.stage = Stage::Ended;
        l.verdict_due = None;
        let tx = l.tx;
        let o = &mut rec(&mut self.reqs, l.req).out;
        if o.stop.is_none() {
            // A stop time that overflows is due at once; `at` keeps the base time as the record.
            let (at, overflow) = match after(now, stop_after) {
                Some(t) => (t, false),
                None => (now, true),
            };
            o.stop = Some(StopPlan {
                at,
                origin: StopOrigin::Sent,
                cleared: false,
            });
            l.stop_overflow = overflow;
        }
        self.out.retain(|q| q.tx != tx);
        self.out.push_back(QFrame {
            tx,
            kind: QKind::End(reason),
        });
    }
}

#[cfg(test)]
mod tests;
