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
use std::time::{Duration, Instant};

use crate::protocol::codec::Matched;

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
    /// The fragments are only the first bytes of the request body: the TX_BEGIN frame carries the cut flag.
    pub cut: bool,
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
/// TX_BEGIN, a body fragment, empty for BODY_END, and `[reason]` for TX_END. `cut` is true for the TX_BEGIN of a
/// request whose body is cut, and for no other frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outgoing {
    pub tx: u64,
    pub msg: u32,
    pub kind: OutKind,
    pub payload: Vec<u8>,
    pub cut: bool,
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
    /// Forwarded like `Forward`; a rule matched while the rules only detect. The values are the inspector's own.
    Detected {
        rule_id: i64,
        status: u16,
    },
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
    /// The rules that matched, as the VERDICT that made the decision says. Nothing for a decision that no VERDICT
    /// made, and for the continue of phase 1, whose rules the continue of phase 2 repeats and adds to.
    pub matched: Matched,
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

/// How a stage ends. `Done` is the continue of the last phase (Forward); `Detected` is that continue with a
/// match that did not stop the request. The ones that a VERDICT makes carry the rules it says matched.
#[derive(Clone, Copy)]
enum Ending {
    Block {
        phase: u8,
        rule_id: i64,
        status: u16,
        matched: Matched,
    },
    Uninspectable(Why),
    Disconnect,
    Done {
        matched: Matched,
    },
    Detected {
        rule_id: i64,
        status: u16,
        matched: Matched,
    },
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
        cut: false,
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
}

mod answers;
mod intake;
mod settle;
mod stopping;
mod writer;

#[cfg(test)]
mod tests;
