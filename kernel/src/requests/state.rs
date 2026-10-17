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
mod tests {
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
        e.on_verdict(now, tx, msg, phase, false, 0, 0, &[phase, 0, msg as u8])
    }

    fn blk(e: &mut Engine, now: Instant, tx: u64, msg: u32, phase: u8) -> Result<(), ConnFault> {
        e.on_verdict(
            now,
            tx,
            msg,
            phase,
            true,
            949110,
            403,
            &[phase, 1, msg as u8],
        )
    }

    fn blocked(phase: u8) -> Decision {
        Decision::Block {
            phase,
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

    #[test]
    fn row_returned() {
        let Fx { mut e, t0, id, tx } = row_ended();
        closed(&mut e, t0, tx, 5).unwrap();
        assert_eq!(e.held_slots(), 0);
        cont(&mut e, t0, tx, 4, 2).unwrap();
        blk(&mut e, t0, tx, 1, 1).unwrap();
        cont(&mut e, t0, tx, 1, 4).unwrap();
        nc(&mut e, t0, tx, 1).unwrap();
        txerr(&mut e, t0, tx, 1).unwrap();
        closed(&mut e, t0, tx, 5).unwrap();
        closed(&mut e, t0, tx, 9).unwrap();
        assert_eq!(e.discarded(), 7);
        e.cancel(t0, id);
        assert!(e.tick(at(t0, 60_000)).is_none());
        e.conn_fault(t0);
        e.exit_confirmed(t0, 1);
        assert_eq!(out(&e, id).returns, vec![(tx, ReturnReason::Closed)]);
        assert_eq!(out(&e, id).decision, Some(Decision::Forward));
    }

    // ---- 1. one final decision ----

    #[test]
    fn forward_needs_the_phase1_and_phase2_continues() {
        let Fx { mut e, t0, id, tx } = row_p1();
        cont(&mut e, t0, tx, 1, 1).unwrap();
        assert_eq!(out(&e, id).decision, None);
        assert_eq!(drain(&mut e, t0).len(), 3);
        assert_eq!(out(&e, id).decision, None);
        cont(&mut e, t0, tx, 4, 2).unwrap();
        assert_eq!(out(&e, id).decision, Some(Decision::Forward));
        // phase 2 without the phase 1 continue: the BODY_END was never taken, so it cannot be answered
        let Fx { mut e, t0, id, tx } = row_p1();
        cont(&mut e, t0, tx, 1, 2).unwrap();
        assert_eq!(
            out(&e, id).decision,
            Some(Decision::Uninspectable(Why::Order))
        );
    }

    #[test]
    fn nothing_else_forwards() {
        // (msg, phase) at the phase 2 wait of a transaction whose frames are 1 TX_BEGIN, 2 3 BODY, 4 BODY_END
        let cases: [(u32, u8); 9] = [
            (4, 3),
            (4, 1),
            (4, 4),
            (3, 2),
            (1, 2),
            (2, 2),
            (5, 2),
            (0, 2),
            (4, 0),
        ];
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
        e.on_verdict(t0, tx, 1, 1, false, 0, 0, &[0xff]).unwrap();
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
    fn eight_waiting_four_slots() {
        let t0 = Instant::now();
        let mut e = Engine::new(limits(), 1, 100);
        let ids: Vec<ReqId> = (0..9).map(|_| e.submit(t0, request()).unwrap()).collect();
        assert_eq!((e.waiting(), e.held_slots()), (8, 0));
        assert_eq!(
            out(&e, ids[8]).decision,
            Some(Decision::Uninspectable(Why::QueueFull))
        );
        assert!(e.next_frame(t0).is_none());
        e.ready(t0, 1);
        assert_eq!((e.held_slots(), e.waiting()), (4, 4));
        assert_eq!(out(&e, ids[3]).txs, vec![103]);
        assert!(out(&e, ids[4]).txs.is_empty());
        for _ in 0..4 {
            e.submit(t0, request()).unwrap();
        }
        assert_eq!(e.waiting(), 8);
        let nine = e.submit(t0, request()).unwrap();
        assert_eq!(
            out(&e, nine).decision,
            Some(Decision::Uninspectable(Why::QueueFull))
        );
        assert_eq!(e.waiting(), 8);
        // a freed slot goes to the first waiting request
        e.cancel(t0, ids[0]);
        assert_eq!((e.held_slots(), e.waiting()), (4, 7));
        assert_eq!(out(&e, ids[4]).txs, vec![104]);
    }

    #[test]
    fn requests_that_fail_the_checks_are_not_sent() {
        let (mut e, t0) = start();
        let frag = |n: usize| vec![0u8; n];
        let mut bad = vec![
            Request {
                begin: vec![],
                ..request()
            },
            Request {
                begin: frag(MAX_BEGIN + 1),
                ..request()
            },
        ];
        bad.push(Request {
            body: vec![frag(1); 17],
            ..request()
        });
        bad.push(Request {
            body: vec![frag(0)],
            ..request()
        });
        bad.push(Request {
            body: vec![frag(MAX_FRAG + 1)],
            ..request()
        });
        for r in bad {
            let id = e.submit(t0, r).unwrap();
            assert_eq!(
                out(&e, id).decision,
                Some(Decision::Uninspectable(Why::Invalid))
            );
            assert!(out(&e, id).txs.is_empty());
        }
        assert_eq!((e.held_slots(), e.waiting()), (0, 0));
        // the limits themselves are accepted
        let edge = Request {
            begin: frag(MAX_BEGIN),
            body: vec![frag(MAX_FRAG); MAX_FRAGS],
        };
        let id = e.submit(t0, edge).unwrap();
        assert_eq!(out(&e, id).decision, None);
        let none = Request {
            begin: vec![1],
            body: vec![],
        };
        let id = e.submit(t0, none).unwrap();
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
        for tx in [101, 102, u64::MAX] {
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
        // a number whose TX_BEGIN the writer has not taken
        for n in 0..3 {
            let Fx { mut e, t0, .. } = row_p1();
            e.submit(t0, request()).unwrap();
            let r = match n {
                0 => cont(&mut e, t0, 101, 1, 1),
                1 => nc(&mut e, t0, 101, 1),
                _ => closed(&mut e, t0, 101, 1),
            };
            assert_eq!(r, Err(ConnFault::NotSent { tx: 101 }), "column {n}");
        }
        // after the take the same answer is accepted
        let Fx { mut e, t0, .. } = row_p1();
        e.submit(t0, request()).unwrap();
        let b = take(&mut e, t0);
        assert_eq!((b.tx, b.msg), (101, 1));
        cont(&mut e, t0, 101, 1, 1).unwrap();
        // a number given up by (4) was never on the wire; an answer for it is dropped like a returned one
        let Fx { mut e, t0, id, tx } = row_queued();
        e.cancel(t0, id);
        cont(&mut e, t0, tx, 1, 1).unwrap();
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
        // a request that waits when the numbers run out is decided too
        let mut lim = limits();
        lim.slots = 1;
        let mut e = Engine::new(lim, 1, u64::MAX);
        e.ready(t0, 1);
        e.submit(t0, request()).unwrap();
        let w = e.submit(t0, request()).unwrap();
        assert_eq!(
            out(&e, w).decision,
            Some(Decision::Uninspectable(Why::Halted(Halt::TxExhausted)))
        );
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
        // the normal case: one higher
        let (mut e, t0) = start();
        e.exit_confirmed(t0, 1);
        assert_eq!((e.incarnation(), e.halted()), (2, None));
    }

    #[test]
    fn the_session_halt_decides_the_waiting_requests_at_once() {
        // no restart: the request that conn_fault put back does not wait for its deadline
        let (mut e, t0) = start();
        let a = e.submit(t0, request()).unwrap();
        let b = e.submit(t0, request()).unwrap();
        let f = take(&mut e, t0);
        assert_eq!((f.tx, f.kind), (100, OutKind::TxBegin));
        e.conn_fault(at(t0, 10));
        e.exit_confirmed(at(t0, 20), 1);
        assert_eq!(e.waiting(), 1);
        e.halt(at(t0, 30), Halt::NoRestart);
        assert_eq!((e.held_slots(), e.waiting()), (0, 0));
        assert_eq!(
            out(&e, a).decision,
            Some(Decision::Uninspectable(Why::ConnFault))
        );
        assert_eq!(
            out(&e, b).decision,
            Some(Decision::Uninspectable(Why::Halted(Halt::NoRestart)))
        );
        assert_eq!(out(&e, b).decided_at, Some(at(t0, 30)));
        assert_eq!(out(&e, b).returns, vec![(101, ReturnReason::BeforeBegin)]);
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
    fn return_4_before_the_take_sends_nothing_and_assigns_the_next() {
        let t0 = Instant::now();
        let mut lim = limits();
        lim.slots = 1;
        let mut e = Engine::new(lim, 1, 100);
        e.ready(t0, 1);
        let a = e.submit(t0, request()).unwrap();
        let b = e.submit(t0, request()).unwrap();
        assert_eq!((e.held_slots(), e.waiting()), (1, 1));
        e.cancel(t0, a);
        assert_eq!(out(&e, a).decision, Some(Decision::ClientDisconnect));
        assert_eq!(out(&e, a).returns, vec![(100, ReturnReason::BeforeBegin)]);
        assert_eq!(
            (out(&e, b).txs.clone(), e.held_slots(), e.waiting()),
            (vec![101], 1, 0)
        );
        // nothing was sent for 100, and the numbers of 101 start at 1
        assert_eq!(drain(&mut e, t0), vec![(101, 1, OutKind::TxBegin)]);
        // a request cancelled while waiting is never assigned
        let c = e.submit(t0, request()).unwrap();
        e.cancel(t0, c);
        assert_eq!(
            (out(&e, c).decision, out(&e, c).txs.clone()),
            (Some(Decision::ClientDisconnect), vec![])
        );
        assert_eq!(e.waiting(), 0);
    }

    #[test]
    fn cancel_after_the_take_is_not_a_return() {
        let Fx { mut e, t0, id, tx } = row_p1();
        e.cancel(t0, id);
        assert_eq!((e.held_slots(), out(&e, id).returns.clone()), (1, vec![]));
        assert_eq!(out(&e, id).decision, Some(Decision::ClientDisconnect));
        let end = take(&mut e, t0);
        assert_eq!((end.msg, end.kind), (2, OutKind::TxEnd(4)));
        e.frame_written(t0, tx, 2);
        closed(&mut e, t0, tx, 2).unwrap();
        assert_eq!(out(&e, id).returns, vec![(tx, ReturnReason::Closed)]);
        // a partly sent body counts as sent
        let Fx { mut e, t0, id, .. } = row_body();
        e.cancel(t0, id);
        assert_eq!((e.held_slots(), only_end(&mut e, t0)), (1, (3, 4)));
    }

    #[test]
    fn the_message_number_of_tx_end_is_the_first_take() {
        let Fx { mut e, t0, id, tx } = row_p2();
        blk(&mut e, t0, tx, 4, 2).unwrap();
        let end = take(&mut e, t0);
        assert_eq!((end.msg, end.kind), (5, OutKind::TxEnd(2)));
        // later events do not queue another TX_END nor change the number
        e.cancel(at(t0, 10), id);
        e.tick(at(t0, 30_000));
        blk(&mut e, t0, tx, 2, 2).unwrap();
        assert!(drain(&mut e, t0).is_empty());
        closed(&mut e, t0, tx, 6).unwrap();
        assert_eq!(e.held_slots(), 1);
        closed(&mut e, t0, tx, 5).unwrap();
        assert_eq!(out(&e, id).returns, vec![(tx, ReturnReason::Closed)]);
    }

    #[test]
    fn the_stop_time_is_never_moved() {
        // (a): the abandon, then the TX_END hand-over, the write, the CLOSED wait and a late answer
        let Fx { mut e, t0, id, tx } = row_p1();
        assert!(e.tick(at(t0, 2500)).is_none());
        let plan = out(&e, id).stop.unwrap();
        assert_eq!(
            (plan.at, plan.origin),
            (at(t0, 8000), StopOrigin::Abandoned)
        );
        let end = take(&mut e, at(t0, 2600));
        assert_eq!((end.msg, end.kind), (2, OutKind::TxEnd(5)));
        e.frame_written(at(t0, 3000), tx, 2);
        assert!(e.tick(at(t0, 5000)).is_none());
        assert!(!out(&e, id).close_unconfirmed);
        assert!(e.tick(at(t0, 5001)).is_none());
        assert!(out(&e, id).close_unconfirmed);
        cont(&mut e, at(t0, 6500), tx, 1, 1).unwrap();
        assert_eq!(
            out(&e, id).stop.map(|p| (p.at, p.origin)),
            Some((at(t0, 8000), StopOrigin::Abandoned))
        );
        assert!(e.tick(at(t0, 8000)).is_none());
        let s = e.tick(at(t0, 8000) + Duration::from_nanos(1)).unwrap();
        assert_eq!(
            (s.req, s.tx, s.at, s.origin),
            (id, tx, at(t0, 8000), StopOrigin::Abandoned)
        );
        // (b): decided without an abandon; the hand-over time plus the threshold, whatever the write time
        let Fx { mut e, t0, id, tx } = row_p2();
        cont(&mut e, at(t0, 1000), tx, 4, 2).unwrap();
        assert_eq!(
            out(&e, id).stop.map(|p| (p.at, p.origin)),
            Some((at(t0, 7000), StopOrigin::Sent))
        );
        let end = take(&mut e, at(t0, 1500));
        e.frame_written(at(t0, 4000), tx, end.msg);
        assert!(e.tick(at(t0, 6001)).is_none());
        assert!(out(&e, id).close_unconfirmed);
        assert_eq!(out(&e, id).stop.map(|p| p.at), Some(at(t0, 7000)));
        assert!(e.tick(at(t0, 7000)).is_none());
        let s = e.tick(at(t0, 7000) + Duration::from_nanos(1)).unwrap();
        assert_eq!((s.at, s.origin), (at(t0, 7000), StopOrigin::Sent));
        // the connection fault stops the clock: the process is being killed
        e.conn_fault(at(t0, 8000));
        assert!(e.tick(at(t0, 60_000)).is_none());
    }

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
        assert_eq!(out(&e, decided).decision, Some(blocked(1)));
        assert_eq!(out(&e, closed_ok).decision, Some(blocked(1)));
        assert_eq!(
            out(&e, undecided).decision,
            Some(Decision::Uninspectable(Why::ConnFault))
        );
        assert_eq!(out(&e, queued).decision, None);
        assert_eq!(
            out(&e, decided).returns,
            vec![(100, ReturnReason::ExitConfirmed)]
        );
        assert_eq!(
            out(&e, closed_ok).returns,
            vec![(101, ReturnReason::Closed)]
        );
        assert_eq!(
            out(&e, undecided).returns,
            vec![(102, ReturnReason::ExitConfirmed)]
        );
        assert_eq!(
            out(&e, queued).returns,
            vec![(103, ReturnReason::BeforeBegin)]
        );
    }

    #[test]
    fn exit_confirmed_returns_every_slot_once() {
        let (mut e, t0) = start();
        let ids: Vec<ReqId> = (0..4).map(|_| e.submit(t0, request()).unwrap()).collect();
        assert_eq!(drain(&mut e, t0).len(), 4); // TX_BEGIN of 100..=103: all taken
        let late = e.submit(t0, request()).unwrap(); // waits: no slot
        blk(&mut e, t0, 100, 1, 1).unwrap();
        assert_eq!(take(&mut e, t0).kind, OutKind::TxEnd(2));
        e.conn_fault(t0);
        assert_eq!((e.held_slots(), e.waiting()), (4, 1));
        assert!(e.next_frame(t0).is_none());
        e.exit_confirmed(t0, 1);
        assert_eq!((e.held_slots(), e.waiting()), (0, 1));
        for (i, id) in ids.iter().enumerate() {
            assert_eq!(
                out(&e, *id).returns,
                vec![(100 + i as u64, ReturnReason::ExitConfirmed)]
            );
            let o = out(&e, *id);
            assert_eq!((o.incomplete, o.close_unconfirmed), (i != 0, i == 0));
        }
        assert_eq!(out(&e, ids[0]).decision, Some(blocked(1)));
        assert_eq!(
            out(&e, ids[1]).decision,
            Some(Decision::Uninspectable(Why::ConnFault))
        );
        // nothing is returned twice, whatever arrives afterwards
        closed(&mut e, t0, 100, 2).unwrap();
        e.frame_written(t0, 100, 2);
        e.ready(t0, 2);
        assert_eq!(
            (
                e.held_slots(),
                out(&e, ids[0]).returns.len(),
                out(&e, late).txs.clone()
            ),
            (1, 1, vec![104])
        );
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
        // and during the restart
        let (mut e, t0) = start();
        let a = e.submit(t0, request()).unwrap();
        let b = e.submit(t0, request()).unwrap();
        e.conn_fault(t0);
        e.tick(at(t0, 3001));
        assert_eq!(
            out(&e, a).decision,
            Some(Decision::Uninspectable(Why::WaitDeadline))
        );
        assert_eq!(
            out(&e, b).decision,
            Some(Decision::Uninspectable(Why::WaitDeadline))
        );
        assert_eq!(e.waiting(), 0);
    }

    // ---- 7. crossings of "not created" with the disconnect, the deadline and the creation evidence ----

    #[test]
    fn cross_a_disconnect_then_not_created_with_tx_end_still_queued() {
        let Fx { mut e, t0, id, tx } = row_p1();
        e.cancel(at(t0, 10), id);
        assert_eq!(out(&e, id).decision, Some(Decision::ClientDisconnect));
        nc(&mut e, at(t0, 20), tx, 1).unwrap();
        let o = out(&e, id);
        assert_eq!(o.decision, Some(Decision::ClientDisconnect));
        assert_eq!(o.returns, vec![(tx, ReturnReason::NotCreated)]);
        assert_eq!(
            o.stop.map(|p| (p.at, p.cleared)),
            Some((at(t0, 6010), true))
        );
        assert!(!o.close_unconfirmed);
        assert_eq!(e.held_slots(), 0);
        // TX_END left the queue without a number: nothing at all goes out for 100
        assert!(drain(&mut e, t0).is_empty());
        assert!(e.tick(at(t0, 60_000)).is_none());
        let next = e.submit(t0, request()).unwrap();
        assert_eq!(drain(&mut e, t0), vec![(101, 1, OutKind::TxBegin)]);
        assert_eq!(out(&e, next).txs, vec![101]);
    }

    #[test]
    fn cross_b_tx_end_taken_then_not_created() {
        let Fx { mut e, t0, id, tx } = row_p1();
        e.cancel(at(t0, 10), id);
        let end = take(&mut e, at(t0, 11));
        assert_eq!((end.msg, end.kind), (2, OutKind::TxEnd(4)));
        nc(&mut e, at(t0, 20), tx, 1).unwrap();
        assert_eq!(out(&e, id).returns, vec![(tx, ReturnReason::NotCreated)]);
        // the write that finishes after the return neither starts the CLOSED wait nor the stop time
        e.frame_written(at(t0, 30), tx, 2);
        assert!(e.tick(at(t0, 60_000)).is_none());
        let o = out(&e, id);
        assert!(!o.close_unconfirmed);
        assert_eq!(o.stop.map(|p| p.cleared), Some(true));
        assert_eq!((e.held_slots(), o.returns.len()), (0, 1));
    }

    #[test]
    fn cross_c_abandon_then_not_created() {
        let Fx { mut e, t0, id, tx } = row_p1();
        assert!(e.tick(at(t0, 2001)).is_none());
        assert_eq!(
            out(&e, id).decision,
            Some(Decision::Uninspectable(Why::VerdictDeadline))
        );
        let end = take(&mut e, at(t0, 2002));
        assert_eq!(end.kind, OutKind::TxEnd(5));
        e.frame_written(at(t0, 2100), tx, end.msg);
        // the CLOSED wait ran out first: that observation stays
        assert!(e.tick(at(t0, 4101)).is_none());
        assert!(out(&e, id).close_unconfirmed);
        nc(&mut e, at(t0, 4200), tx, 1).unwrap();
        let o = out(&e, id);
        assert_eq!(
            o.decision,
            Some(Decision::Uninspectable(Why::VerdictDeadline))
        );
        assert_eq!(o.returns, vec![(tx, ReturnReason::NotCreated)]);
        assert!(o.close_unconfirmed && !o.close_confirmed_late);
        assert_eq!(
            o.stop.map(|p| (p.at, p.origin, p.cleared)),
            Some((at(t0, 8000), StopOrigin::Abandoned, true))
        );
        assert!(e.tick(at(t0, 60_000)).is_none());
        // the same, with TX_END still in the queue
        let Fx { mut e, t0, id, tx } = row_p1();
        e.tick(at(t0, 2001));
        nc(&mut e, at(t0, 2002), tx, 1).unwrap();
        assert_eq!(out(&e, id).returns, vec![(tx, ReturnReason::NotCreated)]);
        assert!(drain(&mut e, t0).is_empty());
    }

    #[test]
    fn cross_d_creation_evidence_and_disconnect_in_both_orders() {
        // evidence, disconnect, false "not created"
        let Fx { mut e, t0, id, tx } = row_p1();
        cont(&mut e, t0, tx, 1, 1).unwrap();
        e.cancel(t0, id);
        nc(&mut e, t0, tx, 1).unwrap();
        assert_eq!((e.held_slots(), out(&e, id).returns.clone()), (1, vec![]));
        assert_eq!(out(&e, id).decision, Some(Decision::ClientDisconnect));
        // disconnect, evidence, false "not created"
        let Fx { mut e, t0, id, tx } = row_p1();
        e.cancel(t0, id);
        cont(&mut e, t0, tx, 1, 1).unwrap();
        assert!(out(&e, id).created);
        nc(&mut e, t0, tx, 1).unwrap();
        assert_eq!((e.held_slots(), out(&e, id).returns.clone()), (1, vec![]));
        assert_eq!(
            (out(&e, id).decision, e.discarded()),
            (Some(Decision::ClientDisconnect), 2)
        );
        // the same with an ERROR of class 2 as the evidence
        let Fx { mut e, t0, id, tx } = row_p1();
        e.cancel(t0, id);
        txerr(&mut e, t0, tx, 1).unwrap();
        assert!(out(&e, id).created);
        nc(&mut e, t0, tx, 1).unwrap();
        assert_eq!((e.held_slots(), out(&e, id).returns.clone()), (1, vec![]));
        // evidence by an ERROR, then disconnect
        let Fx { mut e, t0, id, tx } = row_p1();
        txerr(&mut e, t0, tx, 1).unwrap();
        e.cancel(t0, id);
        nc(&mut e, t0, tx, 1).unwrap();
        assert_eq!(
            (e.held_slots(), out(&e, id).decision),
            (1, Some(Decision::Uninspectable(Why::TxError { code: 19 })))
        );
        // still returned by (1)
        let end = drain(&mut e, t0);
        assert_eq!(end.len(), 1);
        closed(&mut e, t0, tx, end[0].1).unwrap();
        assert_eq!(out(&e, id).returns, vec![(tx, ReturnReason::Closed)]);
    }

    #[test]
    fn cross_e_late_creation_then_false_not_created() {
        for how in 0..2 {
            let Fx { mut e, t0, id, tx } = row_p1();
            e.tick(at(t0, 2001));
            assert!(!out(&e, id).created);
            if how == 0 {
                cont(&mut e, at(t0, 2100), tx, 1, 1).unwrap();
            } else {
                txerr(&mut e, at(t0, 2100), tx, 1).unwrap();
            }
            let o = out(&e, id);
            assert!(o.created);
            assert_eq!(
                o.decision,
                Some(Decision::Uninspectable(Why::VerdictDeadline))
            );
            assert_eq!((o.late, e.discarded()), (1, 1));
            nc(&mut e, at(t0, 2200), tx, 1).unwrap();
            assert_eq!((e.held_slots(), out(&e, id).returns.clone()), (1, vec![]));
            assert_eq!(e.discarded(), 2);
        }
        // a late answer that does not answer a taken frame is no evidence
        let Fx { mut e, t0, id, tx } = row_p1();
        e.tick(at(t0, 2001));
        cont(&mut e, at(t0, 2100), tx, 9, 1).unwrap();
        assert!(!out(&e, id).created);
        nc(&mut e, at(t0, 2200), tx, 1).unwrap();
        assert_eq!(out(&e, id).returns, vec![(tx, ReturnReason::NotCreated)]);
    }

    #[test]
    fn cross_f_no_second_return_and_no_revived_deadline() {
        // returned by (3)
        let Fx { mut e, t0, id, tx } = row_p1();
        e.cancel(t0, id);
        nc(&mut e, t0, tx, 1).unwrap();
        assert_eq!(out(&e, id).returns, vec![(tx, ReturnReason::NotCreated)]);
        nc(&mut e, t0, tx, 1).unwrap(); // the same bytes again
        e.on_error(t0, tx, 1, 1, 2, &[0]).unwrap(); // another code
        closed(&mut e, t0, tx, 2).unwrap();
        e.frame_written(t0, tx, 2);
        assert_eq!(e.discarded(), 3);
        assert!(e.tick(at(t0, 60_000)).is_none());
        e.conn_fault(t0);
        e.exit_confirmed(t0, 1);
        assert_eq!(out(&e, id).returns, vec![(tx, ReturnReason::NotCreated)]);
        // returned by (1)
        let Fx { mut e, t0, id, tx } = row_ended();
        closed(&mut e, t0, tx, 5).unwrap();
        nc(&mut e, t0, tx, 1).unwrap();
        closed(&mut e, t0, tx, 5).unwrap();
        e.frame_written(t0, tx, 5);
        assert!(e.tick(at(t0, 60_000)).is_none());
        e.conn_fault(t0);
        e.exit_confirmed(t0, 1);
        assert_eq!(out(&e, id).returns, vec![(tx, ReturnReason::Closed)]);
        assert_eq!(e.discarded(), 0); // a new incarnation
    }

    // ---- 8. message numbers are given at the take only ----

    #[test]
    fn dropped_unsent_frames_use_no_numbers() {
        // block on the first BODY: the second BODY and BODY_END are dropped, TX_END follows 1, 2
        let Fx { mut e, t0, tx, .. } = row_body();
        blk(&mut e, t0, tx, 2, 2).unwrap();
        assert_eq!(drain(&mut e, t0), vec![(100, 3, OutKind::TxEnd(2))]);
        // the numbers are per transaction, the writer queue is in order
        let (mut e, t0) = start();
        e.submit(t0, request()).unwrap();
        e.submit(t0, request()).unwrap();
        assert_eq!(
            drain(&mut e, t0),
            vec![(100, 1, OutKind::TxBegin), (101, 1, OutKind::TxBegin)]
        );
        cont(&mut e, t0, 101, 1, 1).unwrap();
        cont(&mut e, t0, 100, 1, 1).unwrap();
        let v: Vec<(u64, u32)> = drain(&mut e, t0)
            .into_iter()
            .map(|(tx, msg, _)| (tx, msg))
            .collect();
        assert_eq!(
            v,
            vec![(101, 2), (101, 3), (101, 4), (100, 2), (100, 3), (100, 4)]
        );
    }

    #[test]
    fn nothing_is_taken_after_a_fault() {
        let (mut e, t0) = start();
        e.submit(t0, request()).unwrap();
        e.submit(t0, request()).unwrap();
        assert_eq!(take(&mut e, t0).tx, 100);
        e.conn_fault(t0);
        assert!(e.next_frame(t0).is_none());
        e.exit_confirmed(t0, 1);
        assert!(e.next_frame(t0).is_none());
        e.ready(t0, 2);
        // the request whose TX_BEGIN was never taken is assigned again with a new number
        assert_eq!(drain(&mut e, t0), vec![(102, 1, OutKind::TxBegin)]);
    }

    #[test]
    fn answers_and_writes_after_a_fault_are_ignored() {
        let Fx { mut e, t0, id, tx } = row_p2();
        e.conn_fault(t0);
        cont(&mut e, t0, tx, 4, 2).unwrap();
        closed(&mut e, t0, tx, 5).unwrap();
        cont(&mut e, t0, tx + 50, 1, 1).unwrap(); // not counted, not a fault
        e.frame_written(t0, tx, 5);
        e.ready(t0, 1); // there is no connection to assign on
        assert_eq!(
            (e.discarded(), e.held_slots(), out(&e, id).returns.len()),
            (0, 1, 0)
        );
        assert_eq!(
            out(&e, id).decision,
            Some(Decision::Uninspectable(Why::ConnFault))
        );
        e.cancel(t0, id);
        assert_eq!(
            out(&e, id).decision,
            Some(Decision::Uninspectable(Why::ConnFault))
        );
        e.exit_confirmed(t0, 1);
        assert_eq!(out(&e, id).returns, vec![(tx, ReturnReason::ExitConfirmed)]);
    }

    // ---- waiting requests ----

    #[test]
    fn waiting_requests_expire_and_cancel_before_hello() {
        let t0 = Instant::now();
        let mut e = Engine::new(limits(), 1, 100);
        let a = e.submit(t0, request()).unwrap();
        let b = e.submit(at(t0, 1000), request()).unwrap();
        let c = e.submit(at(t0, 1000), request()).unwrap();
        e.cancel(at(t0, 1500), c);
        assert_eq!(out(&e, c).decision, Some(Decision::ClientDisconnect));
        assert!(e.tick(at(t0, 3000)).is_none());
        assert_eq!(e.waiting(), 2);
        e.tick(at(t0, 3001));
        assert_eq!(
            out(&e, a).decision,
            Some(Decision::Uninspectable(Why::WaitDeadline))
        );
        assert_eq!((out(&e, b).decision, e.waiting()), (None, 1));
        e.ready(at(t0, 3500), 1);
        assert_eq!(out(&e, b).txs, vec![100]);
        assert!(out(&e, a).txs.is_empty() && out(&e, c).txs.is_empty());
        assert!(e.outcome(99).is_none());
        e.cancel(t0, 99);
        e.cancel(t0, u64::MAX);
        assert!(e.outcome(u64::MAX).is_none());
    }

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

    #[test]
    fn a_late_tick_keeps_the_absolute_stop_time() {
        let Fx { mut e, t0, id, tx } = row_p1();
        let s = e.tick(at(t0, 20_000)).unwrap();
        assert_eq!(
            (s.req, s.tx, s.at, s.origin),
            (id, tx, at(t0, 8000), StopOrigin::Abandoned)
        );
        assert_eq!(
            out(&e, id).decision,
            Some(Decision::Uninspectable(Why::VerdictDeadline))
        );
    }

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

    #[test]
    fn a_request_past_its_wait_deadline_gets_no_slot_without_a_tick() {
        // waiting before HELLO: the wait ends at 3000; HELLO comes at 3500 and no tick ran
        let t0 = Instant::now();
        let mut e = Engine::new(limits(), 1, 100);
        let a = e.submit(t0, request()).unwrap();
        e.ready(at(t0, 3500), 1);
        assert_eq!(
            out(&e, a).decision,
            Some(Decision::Uninspectable(Why::WaitDeadline))
        );
        assert!(out(&e, a).txs.is_empty());
        assert_eq!((e.held_slots(), e.waiting()), (0, 0));
        assert!(e.next_frame(at(t0, 3500)).is_none());
        // at the deadline itself it still gets its slot
        let mut e = Engine::new(limits(), 1, 100);
        let a = e.submit(t0, request()).unwrap();
        e.ready(at(t0, 3000), 1);
        assert_eq!(out(&e, a).txs, vec![100]);
        assert_eq!(
            drain(&mut e, at(t0, 3000)),
            vec![(100, 1, OutKind::TxBegin)]
        );
    }

    #[test]
    fn next_frame_without_a_tick_does_not_take_an_expired_request() {
        // four hold slots (TX_BEGIN not taken) and one waits; the wait ends at 3000
        let (mut e, t0) = start();
        let ids: Vec<ReqId> = (0..5).map(|_| e.submit(t0, request()).unwrap()).collect();
        assert_eq!((e.held_slots(), e.waiting()), (4, 1));
        assert!(e.next_frame(at(t0, 3001)).is_none());
        for id in ids {
            assert_eq!(
                out(&e, id).decision,
                Some(Decision::Uninspectable(Why::WaitDeadline))
            );
        }
        assert_eq!((e.held_slots(), e.waiting()), (0, 0));
        for tx in 100..104 {
            assert_eq!(
                e.outcome(tx - 100).unwrap().returns,
                vec![(tx, ReturnReason::BeforeBegin)]
            );
        }
        // at the deadline itself the first one is taken
        let (mut e, t0) = start();
        e.submit(t0, request()).unwrap();
        assert_eq!(take(&mut e, at(t0, 3000)).kind, OutKind::TxBegin);
    }

    #[test]
    fn not_created_after_an_early_closed_decided_by_order_returns_nothing() {
        // phase 1 wait; CLOSED with the number TX_END will get decides by Order
        let Fx { mut e, t0, id, tx } = row_p1();
        closed(&mut e, t0, tx, 2).unwrap();
        assert_eq!(
            out(&e, id).decision,
            Some(Decision::Uninspectable(Why::Order))
        );
        // "not created" for the TX_BEGIN message: the phase 1 wait did not end by deadline or disconnect
        nc(&mut e, t0, tx, 1).unwrap();
        let o = out(&e, id);
        assert!(o.returns.is_empty());
        assert_eq!((e.held_slots(), o.late, e.discarded()), (1, 1, 1));
        // the slot is still returned only by the CLOSED that answers TX_END
        assert_eq!(only_end(&mut e, t0), (2, 3));
        closed(&mut e, t0, tx, 2).unwrap();
        assert_eq!(out(&e, id).returns, vec![(tx, ReturnReason::Closed)]);
    }

    #[test]
    fn tx_end_is_handed_over_once() {
        let Fx { mut e, t0, id, tx } = row_p1();
        e.cancel(t0, id);
        // a second close of the ended transaction changes nothing
        e.end_tx(t0, 0, Ending::Done);
        e.close_tx(t0, 0, 1);
        assert_eq!(out(&e, id).decision, Some(Decision::ClientDisconnect));
        assert_eq!(only_end(&mut e, t0), (2, 4));
        assert_eq!(e.held[0].tx, tx);
    }

    // ---- deadlines that do not fit in an Instant: over at once (fail closed) ----

    const NS: Duration = Duration::from_nanos(1);

    fn plus(t: Instant, d: Duration) -> Instant {
        t.checked_add(d).expect("the time fits")
    }

    /// The largest `d` with `base + d` an `Instant`, found by search: no value of the platform is assumed.
    fn dmax(base: Instant) -> Duration {
        fn ns(n: u128) -> Duration {
            Duration::new((n / 1_000_000_000) as u64, (n % 1_000_000_000) as u32)
        }
        assert!(base.checked_add(Duration::MAX).is_none());
        // `base + lo` fits, `base + hi` does not
        let (mut lo, mut hi) = (0u128, Duration::MAX.as_nanos());
        while hi - lo > 1 {
            let mid = lo + (hi - lo) / 2;
            if base.checked_add(ns(mid)).is_some() {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        ns(lo)
    }

    /// An engine after HELLO with these limits (inc 1, first transaction 100) and the base time.
    fn start_with(lim: Limits) -> (Engine, Instant) {
        let t0 = Instant::now();
        let mut e = Engine::new(lim, 1, 100);
        e.ready(t0, 1);
        (e, t0)
    }

    /// `limits()` where the limit `set` picks is `dmax(t0)` plus `delta` nanoseconds (-1, 0 or 1): `t0 + limit`
    /// is the Instant before the last one, the last one, or does not fit. `dmax(t0)` is returned too.
    fn limits_near_max(
        t0: Instant,
        set: fn(&mut Limits) -> &mut Duration,
        delta: i8,
    ) -> (Limits, Duration) {
        let dm = dmax(t0);
        let mut lim = limits();
        *set(&mut lim) = match delta {
            -1 => dm - NS,
            0 => dm,
            _ => dm + NS,
        };
        (lim, dm)
    }

    fn start_near_max(
        set: fn(&mut Limits) -> &mut Duration,
        delta: i8,
    ) -> (Engine, Instant, Duration) {
        let t0 = Instant::now();
        let (lim, dm) = limits_near_max(t0, set, delta);
        let mut e = Engine::new(lim, 1, 100);
        e.ready(t0, 1);
        (e, t0, dm)
    }

    /// Forwarded at `t0` with the limit `set` picks near the largest; TX_END (msg 5, reason 1) is taken at `t0`
    /// and not yet written.
    fn forwarded_near_max(set: fn(&mut Limits) -> &mut Duration, delta: i8) -> (Fx, Duration) {
        let (mut e, t0, dm) = start_near_max(set, delta);
        let id = e.submit(t0, request()).unwrap();
        assert_eq!(drain(&mut e, t0).len(), 1);
        cont(&mut e, t0, 100, 1, 1).unwrap();
        assert_eq!(drain(&mut e, t0).len(), 3);
        cont(&mut e, t0, 100, 4, 2).unwrap();
        assert_eq!(out(&e, id).decision, Some(Decision::Forward));
        let end = take(&mut e, t0);
        assert_eq!((end.msg, end.kind), (5, OutKind::TxEnd(1)));
        (Fx { e, t0, id, tx: 100 }, dm)
    }

    /// The verdict wait is the largest `t0` allows. TX_BEGIN and both BODY frames are taken at `t0` (their waits
    /// fit); BODY_END is taken one nanosecond later, where the end of its wait does not fit. Returns the
    /// transaction (100), that time and the frame that comes instead: TX_END (reason 5).
    fn abandoned_at_the_take() -> (Fx, Instant, Outgoing) {
        let (mut e, t0, _) = start_near_max(|l| &mut l.verdict_wait, 0);
        let id = e.submit(t0, request()).unwrap();
        // TX_BEGIN 1
        assert_eq!(take(&mut e, t0).kind, OutKind::TxBegin);
        cont(&mut e, t0, 100, 1, 1).unwrap();
        // BODY 2 and 3
        assert_eq!(take(&mut e, t0).msg, 2);
        assert_eq!(take(&mut e, t0).msg, 3);
        let t1 = plus(t0, NS);
        let end = take(&mut e, t1);
        assert_eq!((end.tx, end.kind), (100, OutKind::TxEnd(5)));
        assert_eq!(end.payload, vec![5]);
        (Fx { e, t0, id, tx: 100 }, t1, end)
    }

    /// What holds after `abandoned_at_the_take`. BODY_END (message 4, answered by a phase 2 verdict) was not
    /// handed out; TX_END took its number.
    fn check_abandoned_at_the_take() {
        let (never, phase) = (4, 2);
        let check = |e: &Engine, id: ReqId, t1: Instant| {
            let o = out(e, id);
            assert_eq!(
                (o.decision, o.decided_at),
                (
                    Some(Decision::Uninspectable(Why::VerdictDeadline)),
                    Some(t1)
                )
            );
        };
        let (Fx { mut e, id, tx, .. }, t1, end) = abandoned_at_the_take();
        assert_eq!(end.msg, never);
        check(&e, id, t1);
        // the stop time (a) is due at once: the tick at the same time returns it
        assert_eq!(
            out(&e, id).stop,
            Some(StopPlan {
                at: t1,
                origin: StopOrigin::Abandoned,
                cleared: false
            })
        );
        let s = e.tick(t1).unwrap();
        assert_eq!(
            (s.req, s.tx, s.at, s.origin),
            (id, tx, t1, StopOrigin::Abandoned)
        );
        // the slot is kept, nothing is returned without evidence, nothing more is handed out, and the
        // late answers do not bring the wait back
        assert_eq!((e.held_slots(), out(&e, id).returns.len()), (1, 0));
        assert!(e.next_frame(t1).is_none());
        cont(&mut e, t1, tx, never, phase).unwrap();
        nc(&mut e, t1, tx, 1).unwrap();
        e.tick(at(t1, 60_000));
        check(&e, id, t1);
        assert_eq!(
            (e.held_slots(), out(&e, id).returns.len(), e.discarded()),
            (1, 0, 2)
        );
        // (1): the CLOSED that answers TX_END returns it once
        e.frame_written(t1, tx, end.msg);
        closed(&mut e, at(t1, 10), tx, end.msg).unwrap();
        let o = out(&e, id);
        assert_eq!(o.returns, vec![(tx, ReturnReason::Closed)]);
        assert!(!o.close_unconfirmed);
        assert_eq!(o.stop.map(|p| p.cleared), Some(true));
        assert_eq!(e.held_slots(), 0);
        closed(&mut e, at(t1, 20), tx, end.msg).unwrap();
        assert_eq!(out(&e, id).returns.len(), 1);
        assert!(e.tick(at(t1, 60_000)).is_none());
        // (2): the exit returns it once
        let (Fx { mut e, id, tx, .. }, t1, _) = abandoned_at_the_take();
        e.conn_fault(t1);
        assert_eq!((e.held_slots(), out(&e, id).returns.len()), (1, 0));
        e.exit_confirmed(t1, 1);
        assert_eq!(out(&e, id).returns, vec![(tx, ReturnReason::ExitConfirmed)]);
        assert_eq!(e.held_slots(), 0);
        check(&e, id, t1);
        assert!(out(&e, id).close_unconfirmed && !out(&e, id).incomplete);
    }

    #[test]
    fn dmax_is_the_last_instant() {
        let t0 = Instant::now();
        let dm = dmax(t0);
        let last = plus(t0, dm);
        assert!(last.checked_add(NS).is_none());
        assert!(t0.checked_add(dm + NS).is_none());
        assert!(plus(t0, dm - NS) < last);
    }

    #[test]
    fn an_overflowing_wait_deadline_gives_no_slot_and_no_begin() {
        let mut lim = limits();
        lim.wait_deadline = Duration::MAX;
        let (mut e, t0) = start_with(lim);
        let a = e.submit(t0, request()).unwrap();
        let o = out(&e, a);
        assert_eq!(
            (o.decision, o.decided_at),
            (Some(Decision::Uninspectable(Why::WaitDeadline)), Some(t0))
        );
        assert!(o.txs.is_empty() && o.returns.is_empty() && o.stop.is_none());
        assert_eq!((e.waiting(), e.held_slots()), (0, 0));
        // no tick came: nothing is handed out
        assert!(e.next_frame(t0).is_none());
        assert!(e.tick(t0).is_none());
        // the reasons that are checked before keep their place
        let bad = Request {
            begin: vec![],
            ..request()
        };
        let b = e.submit(t0, bad).unwrap();
        assert_eq!(
            out(&e, b).decision,
            Some(Decision::Uninspectable(Why::Invalid))
        );
        let mut lim = limits();
        lim.wait_deadline = Duration::MAX;
        lim.wait_queue = 0;
        let (mut e, t0) = start_with(lim);
        let c = e.submit(t0, request()).unwrap();
        assert_eq!(
            out(&e, c).decision,
            Some(Decision::Uninspectable(Why::QueueFull))
        );
    }

    #[test]
    fn the_wait_for_a_slot_at_the_last_instants() {
        // waiting before HELLO; the wait ends at t0 + limit
        for delta in [-1, 0, 1] {
            let t0 = Instant::now();
            let (lim, dm) = limits_near_max(t0, |l| &mut l.wait_deadline, delta);
            let (before, last) = (plus(t0, dm - NS), plus(t0, dm));
            let mut e = Engine::new(lim, 1, 100);
            let a = e.submit(t0, request()).unwrap();
            match delta {
                1 => {
                    // does not fit: decided at the submit
                    let o = out(&e, a);
                    assert_eq!(
                        (o.decision, o.decided_at),
                        (Some(Decision::Uninspectable(Why::WaitDeadline)), Some(t0))
                    );
                    assert_eq!(e.waiting(), 0);
                }
                0 => {
                    // the last Instant is the deadline itself: in time, and nothing is later
                    assert!(e.tick(last).is_none());
                    assert_eq!((out(&e, a).decision, e.waiting()), (None, 1));
                    e.ready(last, 1);
                    assert_eq!(out(&e, a).txs, vec![100]);
                }
                _ => {
                    assert!(e.tick(before).is_none());
                    assert_eq!((out(&e, a).decision, e.waiting()), (None, 1));
                    assert!(e.tick(last).is_none());
                    assert_eq!(
                        out(&e, a).decision,
                        Some(Decision::Uninspectable(Why::WaitDeadline))
                    );
                    assert_eq!(e.waiting(), 0);
                }
            }
        }
    }

    #[test]
    fn the_wait_for_the_writer_at_the_last_instants() {
        // the slot is held and TX_BEGIN waits in the writer queue; the wait ends at t0 + limit
        for delta in [-1, 0, 1] {
            let (mut e, t0, dm) = start_near_max(|l| &mut l.wait_deadline, delta);
            let (before, last) = (plus(t0, dm - NS), plus(t0, dm));
            let a = e.submit(t0, request()).unwrap();
            match delta {
                1 => {
                    // does not fit: decided at the submit, no slot, nothing to take
                    let o = out(&e, a);
                    assert_eq!(
                        (o.decision, o.decided_at),
                        (Some(Decision::Uninspectable(Why::WaitDeadline)), Some(t0))
                    );
                    assert!(o.txs.is_empty() && o.returns.is_empty());
                    assert_eq!(e.held_slots(), 0);
                    assert!(e.next_frame(t0).is_none());
                }
                0 => {
                    assert!(e.tick(last).is_none());
                    assert_eq!((e.held_slots(), out(&e, a).decision), (1, None));
                }
                _ => {
                    assert!(e.tick(before).is_none());
                    assert_eq!((e.held_slots(), out(&e, a).decision), (1, None));
                    assert!(e.tick(last).is_none());
                    assert_eq!(
                        out(&e, a).decision,
                        Some(Decision::Uninspectable(Why::WaitDeadline))
                    );
                    assert_eq!(out(&e, a).returns, vec![(100, ReturnReason::BeforeBegin)]);
                    assert_eq!(e.held_slots(), 0);
                    assert!(drain(&mut e, last).is_empty());
                }
            }
        }
    }

    #[test]
    fn an_overflowing_verdict_wait_hands_out_no_begin_and_never_forwards() {
        let mut lim = limits();
        lim.verdict_wait = Duration::MAX;
        let (mut e, t0) = start_with(lim);
        let id = e.submit(t0, request()).unwrap();
        // the slot is held and TX_BEGIN waits in the writer queue until the writer asks
        assert_eq!((e.held_slots(), e.waiting()), (1, 0));
        assert!(e.next_frame(t0).is_none());
        let o = out(&e, id);
        assert_eq!(
            (o.decision, o.decided_at),
            (
                Some(Decision::Uninspectable(Why::VerdictDeadline)),
                Some(t0)
            )
        );
        // nothing was sent: (4), no TX_END, no stop time
        assert_eq!(
            (o.txs.clone(), o.returns.clone()),
            (vec![100], vec![(100, ReturnReason::BeforeBegin)])
        );
        assert!(o.stop.is_none() && !o.created);
        assert_eq!((e.held_slots(), e.waiting()), (0, 0));
        // CONTINUE answers for phase 1, the body and phase 2 arriving at the same time are discarded and
        // do not change the expired decision
        for (msg, phase) in [(1, 1), (2, 2), (3, 2), (4, 2)] {
            cont(&mut e, t0, 100, msg, phase).unwrap();
        }
        assert_eq!(
            out(&e, id).decision,
            Some(Decision::Uninspectable(Why::VerdictDeadline))
        );
        assert_eq!(e.discarded(), 4);
        assert!(drain(&mut e, t0).is_empty());
        assert_eq!(out(&e, id).returns.len(), 1);
        // the freed slot goes to the next waiting request, which ends the same way in the same call
        let mut lim = limits();
        lim.verdict_wait = Duration::MAX;
        lim.slots = 1;
        let (mut e, t0) = start_with(lim);
        let a = e.submit(t0, request()).unwrap();
        let b = e.submit(t0, request()).unwrap();
        assert_eq!((e.held_slots(), e.waiting()), (1, 1));
        assert!(e.next_frame(t0).is_none());
        for (id, tx) in [(a, 100), (b, 101)] {
            assert_eq!(
                out(&e, id).decision,
                Some(Decision::Uninspectable(Why::VerdictDeadline))
            );
            assert_eq!(out(&e, id).returns, vec![(tx, ReturnReason::BeforeBegin)]);
        }
        assert_eq!((e.held_slots(), e.waiting()), (0, 0));
    }

    #[test]
    fn begin_is_handed_out_only_while_its_verdict_wait_fits() {
        // the end of the wait is the last Instant: handed out
        let (mut e, t0, _) = start_near_max(|l| &mut l.verdict_wait, 0);
        let id = e.submit(t0, request()).unwrap();
        let f = take(&mut e, t0);
        assert_eq!((f.tx, f.msg, f.kind), (100, 1, OutKind::TxBegin));
        assert_eq!(out(&e, id).decision, None);
        // it does not fit: not handed out, nothing sent
        let (mut e, t0, _) = start_near_max(|l| &mut l.verdict_wait, 1);
        let id = e.submit(t0, request()).unwrap();
        assert!(e.next_frame(t0).is_none());
        let o = out(&e, id);
        assert_eq!(
            (o.decision, o.returns.clone()),
            (
                Some(Decision::Uninspectable(Why::VerdictDeadline)),
                vec![(100, ReturnReason::BeforeBegin)]
            )
        );
    }

    #[test]
    fn the_verdict_wait_at_the_last_instants() {
        // the deadline is the Instant before the last one: in time at it, over at the last one; the stop
        // time (a) does not fit and is due at once, its `at` is the deadline
        let (mut e, t0, dm) = start_near_max(|l| &mut l.verdict_wait, -1);
        let id = e.submit(t0, request()).unwrap();
        assert_eq!(take(&mut e, t0).kind, OutKind::TxBegin);
        let (due, last) = (plus(t0, dm - NS), plus(t0, dm));
        assert!(e.tick(due).is_none());
        assert_eq!(out(&e, id).decision, None);
        let s = e.tick(last).unwrap();
        assert_eq!(
            (s.req, s.tx, s.at, s.origin),
            (id, 100, due, StopOrigin::Abandoned)
        );
        assert_eq!(
            out(&e, id).decision,
            Some(Decision::Uninspectable(Why::VerdictDeadline))
        );
        // the deadline is the last Instant: an answer at it is in time
        let (mut e, t0, dm) = start_near_max(|l| &mut l.verdict_wait, 0);
        let id = e.submit(t0, request()).unwrap();
        assert_eq!(take(&mut e, t0).kind, OutKind::TxBegin);
        let last = plus(t0, dm);
        cont(&mut e, last, 100, 1, 1).unwrap();
        assert_eq!(out(&e, id).decision, None);
        assert_eq!(take(&mut e, last).msg, 2);
    }

    #[test]
    fn an_overflowing_wait_at_the_take_of_body_end_abandons() {
        check_abandoned_at_the_take();
    }

    #[test]
    fn the_closed_wait_at_the_last_instants() {
        // the wait ends at the last Instant: the CLOSED at that time is in time
        let (Fx { mut e, t0, id, tx }, dm) = forwarded_near_max(|l| &mut l.closed_wait, 0);
        e.frame_written(t0, tx, 5);
        assert!(!out(&e, id).close_unconfirmed);
        closed(&mut e, plus(t0, dm), tx, 5).unwrap();
        let o = out(&e, id);
        assert_eq!(o.returns, vec![(tx, ReturnReason::Closed)]);
        assert!(!o.close_unconfirmed && !o.close_confirmed_late);
        // the wait ends at the Instant before the last one: in time at it, late at the last one
        for late in [false, true] {
            let (Fx { mut e, t0, id, tx }, dm) = forwarded_near_max(|l| &mut l.closed_wait, -1);
            e.frame_written(t0, tx, 5);
            assert!(!out(&e, id).close_unconfirmed);
            closed(&mut e, plus(t0, if late { dm } else { dm - NS }), tx, 5).unwrap();
            let o = out(&e, id);
            assert_eq!(o.returns, vec![(tx, ReturnReason::Closed)]);
            assert_eq!((o.close_unconfirmed, o.close_confirmed_late), (late, late));
        }
        // the end does not fit: the wait is over when it starts, and it does not start again; the slot
        // is kept until a CLOSED, which is late
        let (Fx { mut e, t0, id, tx }, _) = forwarded_near_max(|l| &mut l.closed_wait, 1);
        e.frame_written(t0, tx, 5);
        assert!(out(&e, id).close_unconfirmed);
        e.frame_written(t0, tx, 5);
        assert_eq!((e.held_slots(), out(&e, id).returns.len()), (1, 0));
        assert!(!out(&e, id).close_confirmed_late);
        closed(&mut e, t0, tx, 5).unwrap();
        let o = out(&e, id);
        assert_eq!(o.returns, vec![(tx, ReturnReason::Closed)]);
        assert!(o.close_unconfirmed && o.close_confirmed_late);
        // ... or until the exit
        let (Fx { mut e, t0, id, tx }, _) = forwarded_near_max(|l| &mut l.closed_wait, 1);
        e.frame_written(t0, tx, 5);
        e.conn_fault(t0);
        assert_eq!(e.held_slots(), 1);
        e.exit_confirmed(t0, 1);
        assert_eq!(out(&e, id).returns, vec![(tx, ReturnReason::ExitConfirmed)]);
        assert!(out(&e, id).close_unconfirmed);
    }

    #[test]
    fn a_closed_wait_that_did_not_fit_is_not_started_again() {
        // the write finishes where the end of the wait does not fit; a repeat of the write at a time where
        // it would fit (the clock is not trusted to go forward) does not start a wait
        let (Fx { mut e, t0, id, tx }, _) = forwarded_near_max(|l| &mut l.closed_wait, 0);
        e.frame_written(plus(t0, NS), tx, 5);
        assert!(out(&e, id).close_unconfirmed);
        assert!(e.held[0].closed_due.is_none());
        e.frame_written(t0, tx, 5);
        assert!(e.held[0].closed_due.is_none());
        assert_eq!((e.held_slots(), out(&e, id).returns.len()), (1, 0));
    }

    #[test]
    fn the_stop_time_from_the_hand_over_at_the_last_instants() {
        // the stop time is the Instant before the last one
        let (Fx { mut e, t0, id, tx }, dm) = forwarded_near_max(|l| &mut l.stop_after, -1);
        let (before, last) = (plus(t0, dm - NS), plus(t0, dm));
        assert_eq!(
            out(&e, id).stop,
            Some(StopPlan {
                at: before,
                origin: StopOrigin::Sent,
                cleared: false
            })
        );
        assert!(e.tick(before).is_none());
        let s = e.tick(last).unwrap();
        assert_eq!(
            (s.req, s.tx, s.at, s.origin),
            (id, tx, before, StopOrigin::Sent)
        );
        // the stop time is the last Instant: nothing is later
        let (Fx { mut e, t0, id, .. }, dm) = forwarded_near_max(|l| &mut l.stop_after, 0);
        let last = plus(t0, dm);
        assert_eq!(out(&e, id).stop.map(|p| p.at), Some(last));
        assert!(e.tick(last).is_none());
        // the end does not fit: due at once, `at` is the hand-over time
        let (Fx { mut e, t0, id, tx }, _) = forwarded_near_max(|l| &mut l.stop_after, 1);
        assert_eq!(
            out(&e, id).stop,
            Some(StopPlan {
                at: t0,
                origin: StopOrigin::Sent,
                cleared: false
            })
        );
        let s = e.tick(t0).unwrap();
        assert_eq!(
            (s.req, s.tx, s.at, s.origin),
            (id, tx, t0, StopOrigin::Sent)
        );
        // the legitimate CLOSED takes the plan off
        e.frame_written(t0, tx, 5);
        closed(&mut e, t0, tx, 5).unwrap();
        assert_eq!(out(&e, id).stop.map(|p| p.cleared), Some(true));
        assert!(e.tick(at(t0, 60_000)).is_none());
    }

    #[test]
    fn the_stop_time_from_the_abandon_at_the_last_instants() {
        // TX_BEGIN taken at t0, the verdict wait ends at `due`; the stop time counts from `due`
        for delta in [-1, 0, 1] {
            let t0 = Instant::now();
            let due = at(t0, 2000);
            let (lim, dm) = limits_near_max(due, |l| &mut l.stop_after, delta);
            let (just_over, before, last) = (plus(due, NS), plus(due, dm - NS), plus(due, dm));
            let mut e = Engine::new(lim, 1, 100);
            e.ready(t0, 1);
            let id = e.submit(t0, request()).unwrap();
            assert_eq!(take(&mut e, t0).kind, OutKind::TxBegin);
            match delta {
                1 => {
                    // does not fit: due at once, `at` is the deadline
                    let s = e.tick(just_over).unwrap();
                    assert_eq!(
                        (s.req, s.tx, s.at, s.origin),
                        (id, 100, due, StopOrigin::Abandoned)
                    );
                }
                0 => {
                    // the last Instant: nothing is later
                    assert!(e.tick(just_over).is_none());
                    assert_eq!(out(&e, id).stop.map(|p| p.at), Some(last));
                    assert!(e.tick(last).is_none());
                }
                _ => {
                    assert!(e.tick(just_over).is_none());
                    assert!(e.tick(before).is_none());
                    let s = e.tick(last).unwrap();
                    assert_eq!(
                        (s.req, s.tx, s.at, s.origin),
                        (id, 100, before, StopOrigin::Abandoned)
                    );
                }
            }
            assert_eq!(
                out(&e, id).decision,
                Some(Decision::Uninspectable(Why::VerdictDeadline))
            );
        }
    }

    #[test]
    fn the_earliest_of_the_stop_times_due_at_once_is_returned() {
        let mut lim = limits();
        lim.stop_after = Duration::MAX;
        let (mut e, t0) = start_with(lim);
        let a = e.submit(t0, request()).unwrap();
        let b = e.submit(t0, request()).unwrap();
        assert_eq!(drain(&mut e, t0).len(), 2);
        // 101 is handed over first and 100 later: the held order is not the order of the times
        blk(&mut e, at(t0, 10), 101, 1, 1).unwrap();
        blk(&mut e, at(t0, 20), 100, 1, 1).unwrap();
        let s = e.tick(at(t0, 20)).unwrap();
        assert_eq!(
            (s.req, s.tx, s.at, s.origin),
            (b, 101, at(t0, 10), StopOrigin::Sent)
        );
        // its CLOSED takes its plan off; the other one is next, also at once
        assert_eq!(
            drain(&mut e, at(t0, 20)),
            vec![(101, 2, OutKind::TxEnd(2)), (100, 2, OutKind::TxEnd(2))]
        );
        closed(&mut e, at(t0, 20), 101, 2).unwrap();
        let s = e.tick(at(t0, 20)).unwrap();
        assert_eq!(
            (s.req, s.tx, s.at, s.origin),
            (a, 100, at(t0, 20), StopOrigin::Sent)
        );
    }

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

    /// TX_BEGIN of the held transaction `tx` is taken (message 1): phase 1 continues and the first BODY is
    /// taken with the last valid message number. The next frame of the transaction has none.
    fn at_the_last_message_number(e: &mut Engine, t0: Instant, tx: u64) {
        cont(e, t0, tx, 1, 1).unwrap();
        let ti = e.held.iter().position(|l| l.tx == tx).unwrap();
        e.held[ti].next_msg = Some(u32::MAX);
        let f = take(e, t0);
        assert_eq!((f.tx, f.msg, f.kind), (tx, u32::MAX, OutKind::Body));
    }

    /// Two transactions hold the last two numbers and a third request found them used up (`TxExhausted`).
    /// The first transaction is at its last valid message number and the second has continued phase 1: the
    /// writer queue holds BODY and BODY_END of the first, then BODY, BODY and BODY_END of the second.
    fn exhausted_and_at_the_last_message_number() -> (Engine, Instant, [ReqId; 3]) {
        let t0 = Instant::now();
        let mut e = Engine::new(limits(), 1, u64::MAX - 1);
        e.ready(t0, 1);
        let a = e.submit(t0, request()).unwrap();
        let b = e.submit(t0, request()).unwrap();
        let c = e.submit(t0, request()).unwrap();
        assert_eq!(
            (
                out(&e, a).txs.clone(),
                out(&e, b).txs.clone(),
                out(&e, c).txs.clone()
            ),
            (vec![u64::MAX - 1], vec![u64::MAX], vec![])
        );
        assert_eq!(
            out(&e, c).decision,
            Some(Decision::Uninspectable(Why::Halted(Halt::TxExhausted)))
        );
        assert_eq!(
            (e.halted(), e.waiting(), e.held_slots()),
            (Some(Halt::TxExhausted), 0, 2)
        );
        assert_eq!(
            drain(&mut e, t0),
            vec![
                (u64::MAX - 1, 1, OutKind::TxBegin),
                (u64::MAX, 1, OutKind::TxBegin)
            ]
        );
        at_the_last_message_number(&mut e, t0, u64::MAX - 1);
        cont(&mut e, t0, u64::MAX, 1, 1).unwrap();
        assert_eq!(e.out.len(), 5);
        assert_eq!(e.out.iter().filter(|q| q.tx == u64::MAX).count(), 3);
        (e, t0, [a, b, c])
    }

    #[test]
    fn the_message_overflow_replaces_the_exhausted_numbers_as_the_reason() {
        let t0 = Instant::now();
        let mut e = Engine::new(limits(), 1, u64::MAX);
        e.ready(t0, 1);
        let a = e.submit(t0, request()).unwrap();
        let b = e.submit(t0, request()).unwrap();
        assert_eq!(
            out(&e, b).decision,
            Some(Decision::Uninspectable(Why::Halted(Halt::TxExhausted)))
        );
        assert_eq!(
            (e.halted(), e.waiting(), e.held_slots()),
            (Some(Halt::TxExhausted), 0, 1)
        );
        // the exhausted numbers stop the new transactions only: the last one sends TX_BEGIN and a BODY
        let f = take(&mut e, t0);
        assert_eq!((f.tx, f.msg, f.kind), (u64::MAX, 1, OutKind::TxBegin));
        at_the_last_message_number(&mut e, t0, u64::MAX);
        assert_eq!(e.halted(), Some(Halt::TxExhausted));
        // the second BODY has no number: the stop is the message overflow, in place of the earlier reason
        assert_eq!(e.next_frame(t0), None);
        assert_eq!(e.halted(), Some(Halt::MsgOverflow));
        // BODY_END is still queued: nothing is handed out any more, no number wraps round to 0, whatever
        // the time, and the queue is left as it is
        assert_eq!(e.out.len(), 1);
        for ms in [0, 1, 2500, 60_000] {
            for _ in 0..3 {
                assert_eq!(e.next_frame(at(t0, ms)), None);
            }
        }
        assert_eq!(e.out.len(), 1);
        // the stop alone returns no slot and decides nothing; the earlier result stays
        assert_eq!(e.held_slots(), 1);
        assert!(out(&e, a).returns.is_empty());
        assert_eq!(out(&e, a).decision, None);
        assert_eq!(
            out(&e, b).decision,
            Some(Decision::Uninspectable(Why::Halted(Halt::TxExhausted)))
        );
        // a new request is refused with the new reason
        let c = e.submit(t0, request()).unwrap();
        assert_eq!(
            out(&e, c).decision,
            Some(Decision::Uninspectable(Why::Halted(Halt::MsgOverflow)))
        );
    }

    #[test]
    fn nothing_of_another_transaction_goes_out_after_the_message_overflow() {
        let (mut e, t0, [a, b, c]) = exhausted_and_at_the_last_message_number();
        assert_eq!(e.halted(), Some(Halt::TxExhausted));
        // the second BODY of the first transaction has no number
        assert_eq!(e.next_frame(t0), None);
        // the frames of the second transaction are queued, and its numbers would be valid: none goes out
        let queued = e.out.len();
        assert_eq!(queued, 4);
        assert_eq!(e.out.iter().filter(|q| q.tx == u64::MAX).count(), 3);
        for ms in [0, 1, 2500, 60_000] {
            for _ in 0..queued + 2 {
                assert_eq!(e.next_frame(at(t0, ms)), None);
            }
        }
        assert_eq!(e.out.len(), queued);
        assert_eq!(e.halted(), Some(Halt::MsgOverflow));
        // no slot is returned and nothing is decided; the result settled before stays
        assert_eq!(e.held_slots(), 2);
        assert!(out(&e, a).returns.is_empty() && out(&e, b).returns.is_empty());
        assert_eq!((out(&e, a).decision, out(&e, b).decision), (None, None));
        assert_eq!(
            out(&e, c).decision,
            Some(Decision::Uninspectable(Why::Halted(Halt::TxExhausted)))
        );
    }

    #[test]
    fn the_message_overflow_stop_is_not_lifted_by_the_exit_and_the_restart() {
        let (mut e, t0, [a, b, c]) = exhausted_and_at_the_last_message_number();
        let (tx_a, tx_b) = (u64::MAX - 1, u64::MAX);
        assert_eq!(e.next_frame(t0), None);
        // nothing is returned before the exit is confirmed
        assert_eq!(e.held_slots(), 2);
        assert!(out(&e, a).returns.is_empty() && out(&e, b).returns.is_empty());
        // (2) returns each slot once and the stop stays
        e.exit_confirmed(at(t0, 100), 1);
        assert_eq!(
            out(&e, a).returns,
            vec![(tx_a, ReturnReason::ExitConfirmed)]
        );
        assert_eq!(
            out(&e, b).returns,
            vec![(tx_b, ReturnReason::ExitConfirmed)]
        );
        assert_eq!(e.held_slots(), 0);
        assert_eq!(e.halted(), Some(Halt::MsgOverflow));
        // HELLO and a normal request: no number, no slot, no frame
        e.ready(at(t0, 200), 2);
        let d = e.submit(at(t0, 200), request()).unwrap();
        assert_eq!(
            out(&e, d).decision,
            Some(Decision::Uninspectable(Why::Halted(Halt::MsgOverflow)))
        );
        assert!(out(&e, d).txs.is_empty());
        assert_eq!((e.held_slots(), e.waiting()), (0, 0));
        assert_eq!(e.next_frame(at(t0, 200)), None);
        // the old CLOSED and write reports return nothing again
        closed(&mut e, at(t0, 300), tx_a, 1).unwrap();
        closed(&mut e, at(t0, 300), tx_b, 1).unwrap();
        e.frame_written(at(t0, 300), tx_a, u32::MAX);
        e.frame_written(at(t0, 300), tx_b, 2);
        assert_eq!(e.discarded(), 2);
        assert_eq!(
            out(&e, a).returns,
            vec![(tx_a, ReturnReason::ExitConfirmed)]
        );
        assert_eq!(
            out(&e, b).returns,
            vec![(tx_b, ReturnReason::ExitConfirmed)]
        );
        assert_eq!(e.held_slots(), 0);
        assert_eq!(e.next_frame(at(t0, 300)), None);
        // the result settled before the stop stays, and the stop stays
        assert_eq!(
            out(&e, c).decision,
            Some(Decision::Uninspectable(Why::Halted(Halt::TxExhausted)))
        );
        assert_eq!(e.halted(), Some(Halt::MsgOverflow));
    }

    #[test]
    fn a_request_waiting_at_the_message_overflow_is_decided_as_halted() {
        let mut lim = limits();
        lim.slots = 1;
        let (mut e, t0) = start_with(lim);
        let a = e.submit(t0, request()).unwrap();
        let w = e.submit(t0, request()).unwrap();
        assert_eq!((e.held_slots(), e.waiting()), (1, 1));
        let f = take(&mut e, t0);
        assert_eq!((f.tx, f.msg, f.kind), (100, 1, OutKind::TxBegin));
        at_the_last_message_number(&mut e, t0, 100);
        assert_eq!(e.next_frame(t0), None);
        assert_eq!(e.halted(), Some(Halt::MsgOverflow));
        assert_eq!(
            out(&e, w).decision,
            Some(Decision::Uninspectable(Why::Halted(Halt::MsgOverflow)))
        );
        assert!(out(&e, w).txs.is_empty());
        assert_eq!((e.waiting(), e.held_slots()), (0, 1));
        assert_eq!(out(&e, a).decision, None);
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
        // the HELLO of the old incarnation does not make the new one ready
        e.ready(t0, 1);
        let b = e.submit(t0, request()).unwrap();
        assert_eq!((e.held_slots(), e.waiting()), (0, 1));
        e.ready(t0, 2);
        assert_eq!(out(&e, b).txs, vec![101]);
    }

    // ---- request records ----

    #[test]
    fn a_full_record_table_refuses_without_a_record() {
        let t0 = Instant::now();
        let mut e = Engine::new(
            Limits {
                records: 3,
                ..limits()
            },
            1,
            100,
        );
        let ids: Vec<ReqId> = (0..3).map(|_| e.submit(t0, request()).unwrap()).collect();
        assert_eq!(ids, vec![0, 1, 2]);
        assert_eq!(e.submit(t0, request()), Err(SubmitError::Full));
        assert_eq!((e.records(), e.waiting(), e.held_slots()), (3, 3, 0));
        // an immediate decision is a record too
        let mut e = Engine::new(
            Limits {
                records: 1,
                ..limits()
            },
            1,
            100,
        );
        let bad = e
            .submit(
                t0,
                Request {
                    begin: vec![],
                    ..request()
                },
            )
            .unwrap();
        assert_eq!(
            out(&e, bad).decision,
            Some(Decision::Uninspectable(Why::Invalid))
        );
        assert_eq!(e.submit(t0, request()), Err(SubmitError::Full));
        // a record ends when its decision was handed over and no slot is held: room again
        assert_eq!(
            e.next_done(),
            Some((bad, Decision::Uninspectable(Why::Invalid)))
        );
        assert_eq!(e.records(), 0);
        assert_eq!(e.submit(t0, request()), Ok(1));
        // a held slot keeps its record: room only after the slot is returned
        let mut e = Engine::new(
            Limits {
                records: 1,
                ..limits()
            },
            1,
            100,
        );
        e.ready(t0, 1);
        let a = e.submit(t0, request()).unwrap();
        assert_eq!(take(&mut e, t0).kind, OutKind::TxBegin);
        blk(&mut e, t0, 100, 1, 1).unwrap();
        assert_eq!(e.next_done(), Some((a, blocked(1))));
        assert_eq!(e.submit(t0, request()), Err(SubmitError::Full));
        let end = take(&mut e, t0);
        e.frame_written(t0, 100, end.msg);
        closed(&mut e, t0, 100, end.msg).unwrap();
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
        // Full is looked at first
        let mut e = Engine::new(
            Limits {
                records: 1,
                ..limits()
            },
            1,
            100,
        );
        e.next_req = Some(u64::MAX);
        e.submit(t0, request()).unwrap();
        assert_eq!(e.submit(t0, request()), Err(SubmitError::Full));
        // the numbers start at 0 and follow each other
        let mut e = Engine::new(limits(), 1, 100);
        let ids: Vec<ReqId> = (0..3).map(|_| e.submit(t0, request()).unwrap()).collect();
        assert_eq!(ids, vec![0, 1, 2]);
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
        // decided while waiting (cancel, deadline) and in the writer queue (deadline), then by the halt: each
        // once, in the order of the decisions
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
        let queued = e.submit(t0, request()).unwrap();
        let w1 = e.submit(t0, request()).unwrap();
        let w2 = e.submit(at(t0, 1000), request()).unwrap();
        let w3 = e.submit(at(t0, 1000), request()).unwrap();
        e.cancel(at(t0, 1500), w3);
        e.tick(at(t0, 3001));
        assert_eq!(e.next_done(), Some((w3, Decision::ClientDisconnect)));
        assert_eq!(
            e.next_done(),
            Some((w1, Decision::Uninspectable(Why::WaitDeadline)))
        );
        assert_eq!(
            e.next_done(),
            Some((queued, Decision::Uninspectable(Why::WaitDeadline)))
        );
        assert_eq!(e.next_done(), None);
        // w2 got the freed slot at the tick and is undecided
        assert_eq!(out(&e, w2).decision, None);
        let w4 = e.submit(at(t0, 3001), request()).unwrap();
        e.halt(at(t0, 3002), Halt::Drain);
        assert_eq!(
            e.next_done(),
            Some((w4, Decision::Uninspectable(Why::Halted(Halt::Drain))))
        );
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
        // the slot returned first: the hand-over ends the record
        let Fx { mut e, t0, id, tx } = row_p1();
        blk(&mut e, t0, tx, 1, 1).unwrap();
        let end = take(&mut e, t0);
        e.frame_written(t0, tx, end.msg);
        closed(&mut e, t0, tx, end.msg).unwrap();
        assert!(e.outcome(id).is_some());
        assert_eq!(e.next_done(), Some((id, blocked(1))));
        assert!(e.outcome(id).is_none());
        // undecided, then the connection fault: handed over with the fault, the exit ends the record
        let Fx { mut e, t0, id, tx } = row_p1();
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
        // an id that is gone is ignored, and a late answer for its returned transaction is only counted
        e.cancel(t0, id);
        cont(&mut e, t0, tx, 1, 1).unwrap();
        assert_eq!(e.discarded(), 1);
        // (4): the request goes on after the return; its record is not touched by the one that ended
        let Fx { mut e, t0, id, tx } = row_queued();
        e.cancel(t0, id);
        assert_eq!(e.next_done(), Some((id, Decision::ClientDisconnect)));
        assert!(e.outcome(id).is_none());
        cont(&mut e, t0, tx, 1, 1).unwrap();
        assert_eq!(e.discarded(), 1);
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
        // the first reason stays when a later one comes
        let (mut e, t0) = start();
        let a = e.submit(t0, request()).unwrap();
        e.halt(t0, Halt::NoRestart);
        e.halt(t0, Halt::Drain);
        e.conn_fault(t0);
        assert_eq!(
            e.next_done(),
            Some((a, Decision::Uninspectable(Why::Halted(Halt::NoRestart))))
        );
    }

    // ---- phases 3 and 4 answer nothing this side sends ----

    #[test]
    fn verdicts_of_phase_3_and_4_are_out_of_order() {
        for phase in [3, 4] {
            let Fx { mut e, t0, id, tx } = row_p1();
            cont(&mut e, t0, tx, 1, phase).unwrap();
            assert_eq!(
                out(&e, id).decision,
                Some(Decision::Uninspectable(Why::Order))
            );
            assert!(!out(&e, id).created);
            assert_eq!(only_end(&mut e, t0), (2, 3));
            let Fx { mut e, t0, id, tx } = row_p2();
            blk(&mut e, t0, tx, 4, phase).unwrap();
            assert_eq!(
                out(&e, id).decision,
                Some(Decision::Uninspectable(Why::Order))
            );
            assert_eq!(only_end(&mut e, t0), (5, 3));
        }
        // the forward asks for nothing more: TX_END only, and a phase 3 answer afterwards is dropped
        let Fx { mut e, t0, id, tx } = row_p2();
        cont(&mut e, t0, tx, 4, 2).unwrap();
        assert_eq!(out(&e, id).decision, Some(Decision::Forward));
        assert_eq!(only_end(&mut e, t0), (5, 1));
        cont(&mut e, t0, tx, 5, 3).unwrap();
        assert_eq!((e.discarded(), out(&e, id).late), (1, 1));
        assert_eq!(out(&e, id).decision, Some(Decision::Forward));
    }
}
