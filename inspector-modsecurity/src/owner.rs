//! The transactions of one session: the table that the frames of the kernel go through.
//!
//! The kernel starts a transaction with TX_BEGIN, sends its body in BODY frames and BODY_END, and ends it with TX_END.
//! The table keeps at most `MAX_CONCUR_TX` transactions at once and answers each frame with at most one frame: a
//! VERDICT for TX_BEGIN and BODY_END (and for a BODY that the inspection blocks), CLOSED for TX_END, or an ERROR. The
//! inspection itself is behind the traits `Inspection` and `Transaction`: the table checks the protocol (the ids, the
//! message numbers, the order of the frames, the declared body length) and calls the inspection only for what is left.
//!
//! A frame of a transaction that is blocked or has failed is discarded and counted, not inspected. TX_END always
//! closes the transaction. An id is used once: a frame for an id that was closed, or that was answered with an ERROR of
//! class 1, is discarded. The table runs on one thread; see `link` for how that relates to the queue depth.
#![forbid(unsafe_code)]

use crate::codec::{
    CLASS_NOT_CREATED, CLASS_TX_FAILED, CODE_BAD_BEGIN, CODE_BAD_CONTENT, CODE_BAD_VERDICT,
    CODE_DRAINING, CODE_INCOMPLETE, CODE_LIMIT, CODE_ORDER, CODE_REQ_OVER, CODE_REQ_TRUNCATED,
    CODE_UNSTARTED, Decision, FaultCode, Header, KIND_BODY, KIND_BODY_END, KIND_TX_BEGIN,
    KIND_TX_END, MAX_CONCUR_TX, RuleDetail, TxBegin, Verdict, decode_tx_begin, decode_tx_end,
    encode_closed, encode_error, encode_verdict,
};

/// A failure of the inspection of a transaction, which the table reports as an ERROR of class 2. The code is one that
/// the kernel accepts for the class. The text is a fixed one: it never holds a value of the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault {
    pub code: FaultCode,
    pub text: &'static str,
}

/// What stops a request: the rule that did it, the HTTP status to answer with, the action and its data, and the rules
/// that matched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stop {
    pub rule_id: i64,
    pub status: i32,
    pub action: Vec<u8>,
    pub data: Vec<u8>,
    pub rules: RuleDetail,
}

/// What the inspection decided at the end of a phase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The request goes on; the rules that matched so far.
    Continue(RuleDetail),
    /// The request is stopped.
    Block(Stop),
    /// Phase 2 only: the rules only detect, and a rule matched that would have stopped the request.
    Detected(Stop),
}

impl Stop {
    fn verdict(&self, decision: Decision) -> Verdict<'_> {
        Verdict {
            decision,
            rule_id: self.rule_id,
            status: self.status,
            action: &self.action,
            data: &self.data,
            rules: &self.rules,
        }
    }
}

impl Outcome {
    fn verdict(&self) -> Verdict<'_> {
        match self {
            Outcome::Continue(rules) => Verdict {
                decision: Decision::Continue,
                rule_id: 0,
                status: 0,
                action: &[],
                data: &[],
                rules,
            },
            Outcome::Block(stop) => stop.verdict(Decision::Block),
            Outcome::Detected(stop) => stop.verdict(Decision::Detected),
        }
    }
}

/// The inspection of the requests of one session: it makes the inspection of one transaction.
pub trait Inspection {
    type Tx: Transaction;

    /// Makes the inspection of a transaction, before TX_BEGIN is handed to it.
    fn start(&mut self) -> Result<Self::Tx, Fault>;
}

/// The inspection of one transaction, called in the order of the frames and never again after a block or a fault.
pub trait Transaction {
    /// The request line and the headers have arrived (phase 1).
    fn begin(&mut self, t: &TxBegin<'_>) -> Result<Outcome, Fault>;

    /// A part of the request body, at least one byte and within the declared length. `Some` stops the request in phase
    /// 2 before the end of the body (the body went over the limit).
    fn body(&mut self, bytes: &[u8]) -> Result<Option<Stop>, Fault>;

    /// The whole declared body has arrived, or there is none (phase 2).
    fn end(&mut self) -> Result<Outcome, Fault>;

    /// Ends the transaction, whatever state it is in. `true` when closing it failed.
    fn close(self) -> bool;
}

/// How many frames the table has dealt with so far.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// Transactions started.
    pub started: u64,
    /// Transactions closed.
    pub closed: u64,
    /// Transactions whose close failed.
    pub close_errors: u64,
    /// Frames discarded: after a block or an ERROR, and for an id that is closed.
    pub discarded: u64,
    /// TX_END frames with a reason that the protocol does not have (the transaction is closed all the same).
    pub bad_tx_end: u64,
}

fn bump(c: &mut u64) {
    *c = c.saturating_add(1);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    /// Phase 1 continued; no BODY yet.
    Headers,
    /// BODY received.
    Body,
    /// Phase 2 continued.
    ReqDone,
    /// Blocked in phase 1 or 2.
    Blocked,
    /// An ERROR was sent.
    Failed,
}

struct Active<T> {
    id: u64,
    /// `None` only when the inspection could not be made; the state is then `Failed`.
    tx: Option<T>,
    state: State,
    last_msg: u32,
    declared: u64,
    recv: u64,
}

/// The transactions of a session.
pub struct Table<I: Inspection> {
    inspection: I,
    run: u64,
    inc: u32,
    active: Vec<Active<I::Tx>>,
    /// The highest id that was started or answered as not created. Ids go up: a lower id is never new.
    max_id: u64,
    draining: bool,
    counts: Counts,
}

impl<I: Inspection> Table<I> {
    pub fn new(inspection: I, run: u64, inc: u32) -> Table<I> {
        Table {
            inspection,
            run,
            inc,
            active: Vec::with_capacity(MAX_CONCUR_TX),
            max_id: 0,
            draining: false,
            counts: Counts::default(),
        }
    }

    pub fn counts(&self) -> Counts {
        self.counts
    }

    /// DRAIN: no transaction is taken from now on. `false` for a second DRAIN.
    pub fn start_drain(&mut self) -> bool {
        !std::mem::replace(&mut self.draining, true)
    }

    /// DRAIN came and every transaction is closed: BYE is next.
    pub fn is_drained(&self) -> bool {
        self.draining && self.active.is_empty()
    }

    /// The connection is gone: every transaction is closed, and nothing is sent.
    pub fn connection_lost(&mut self) {
        for a in std::mem::take(&mut self.active) {
            self.finish(a);
        }
    }

    /// Deals with one frame that `check_header` accepted (not DRAIN, which `link` takes) and returns the frame to send
    /// in answer, if there is one.
    pub fn dispatch(&mut self, h: &Header, p: &[u8]) -> Option<Vec<u8>> {
        let Some(i) = self.active.iter().position(|a| a.id == h.tx) else {
            return self.unstarted(h, p);
        };
        if h.kind == KIND_TX_END {
            return Some(self.close(i, h, p));
        }
        self.handle(i, h, p)
    }

    fn not_created(&self, h: &Header, code: u16, text: &'static str) -> Vec<u8> {
        encode_error(
            self.run,
            self.inc,
            h.tx,
            h.msg,
            CLASS_NOT_CREATED,
            code,
            text,
        )
    }

    /// A frame for an id that has no transaction. The max id advances on the first frame of an id, TX_BEGIN or not.
    fn unstarted(&mut self, h: &Header, p: &[u8]) -> Option<Vec<u8>> {
        if h.tx <= self.max_id {
            bump(&mut self.counts.discarded);
            return None;
        }
        self.max_id = h.tx;
        if h.kind != KIND_TX_BEGIN {
            return Some(self.not_created(h, CODE_UNSTARTED, "frame for an unstarted transaction"));
        }
        let begin = match self.admit(h, p) {
            Ok(begin) => begin,
            Err((code, text)) => return Some(self.not_created(h, code, text)),
        };
        bump(&mut self.counts.started);
        let mut a = Active {
            id: h.tx,
            tx: None,
            state: State::Headers,
            last_msg: h.msg,
            declared: begin.declared,
            recv: 0,
        };
        match self.inspection.start() {
            Err(fault) => {
                a.state = State::Failed;
                self.active.push(a);
                Some(self.error(h.tx, h.msg, u16::from(fault.code), fault.text))
            }
            Ok(mut tx) => {
                let result = tx.begin(&begin);
                a.tx = Some(tx);
                self.active.push(a);
                self.answer(self.active.len() - 1, h.msg, 1, result)
            }
        }
    }

    /// Whether a new transaction is taken, in this order: not draining, a free place, message number 1, a TX_BEGIN
    /// that decodes.
    fn admit<'p>(&self, h: &Header, p: &'p [u8]) -> Result<TxBegin<'p>, (u16, &'static str)> {
        if self.draining {
            return Err((CODE_DRAINING, "draining"));
        }
        if self.active.len() >= MAX_CONCUR_TX {
            return Err((CODE_LIMIT, "concurrency limit"));
        }
        if h.msg != 1 {
            return Err((CODE_BAD_BEGIN, "TX_BEGIN message number is not 1"));
        }
        decode_tx_begin(p, h.cut).map_err(|_| (CODE_BAD_BEGIN, "invalid TX_BEGIN payload"))
    }

    fn error(&self, id: u64, msg: u32, code: u16, text: &'static str) -> Vec<u8> {
        encode_error(self.run, self.inc, id, msg, CLASS_TX_FAILED, code, text)
    }

    /// The single ERROR of a transaction. Once it has failed, anything more is only counted.
    fn fail(&mut self, i: usize, msg: u32, code: u16, text: &'static str) -> Option<Vec<u8>> {
        let a = &mut self.active[i];
        if a.state == State::Failed {
            bump(&mut self.counts.discarded);
            return None;
        }
        a.state = State::Failed;
        let id = a.id;
        Some(self.error(id, msg, code, text))
    }

    /// The answer to what the inspection said in a phase: its VERDICT, or an ERROR for a fault and for a VERDICT that
    /// cannot be written.
    fn answer(
        &mut self,
        i: usize,
        msg: u32,
        phase: u8,
        result: Result<Outcome, Fault>,
    ) -> Option<Vec<u8>> {
        match result {
            Err(fault) => self.fail(i, msg, u16::from(fault.code), fault.text),
            Ok(outcome) => self.verdict(i, msg, phase, &outcome),
        }
    }

    fn verdict(&mut self, i: usize, msg: u32, phase: u8, outcome: &Outcome) -> Option<Vec<u8>> {
        let id = self.active[i].id;
        match encode_verdict(self.run, self.inc, id, msg, phase, &outcome.verdict()) {
            Err(_) => self.fail(i, msg, CODE_BAD_VERDICT, "verdict fields out of range"),
            Ok(frame) => {
                self.active[i].state = match outcome {
                    Outcome::Block(_) => State::Blocked,
                    _ if phase == 2 => State::ReqDone,
                    _ => State::Headers,
                };
                Some(frame)
            }
        }
    }

    /// Applies the frame and state rules to a BODY, BODY_END or second TX_BEGIN of a transaction.
    fn handle(&mut self, i: usize, h: &Header, p: &[u8]) -> Option<Vec<u8>> {
        let a = &mut self.active[i];
        if a.state == State::Failed {
            bump(&mut self.counts.discarded);
            return None;
        }
        let expected = a.last_msg.checked_add(1);
        a.last_msg = h.msg;
        if expected != Some(h.msg) {
            return self.fail(i, h.msg, CODE_ORDER, "message number gap or duplicate");
        }
        match (h.kind, a.state) {
            (KIND_BODY, State::Headers | State::Body) => self.body(i, h.msg, p),
            (KIND_BODY_END, State::Headers | State::Body) => self.body_end(i, h.msg),
            // A request body that was in flight when the request was blocked.
            (KIND_BODY | KIND_BODY_END, State::Blocked) => {
                bump(&mut self.counts.discarded);
                None
            }
            (KIND_BODY, _) => self.fail(i, h.msg, CODE_ORDER, "BODY not allowed in this state"),
            (KIND_BODY_END, _) => {
                self.fail(i, h.msg, CODE_ORDER, "BODY_END not allowed in this state")
            }
            // The one kind left: a second TX_BEGIN for an id that is active.
            _ => self.fail(i, h.msg, CODE_ORDER, "duplicate TX_BEGIN"),
        }
    }

    fn body(&mut self, i: usize, msg: u32, bytes: &[u8]) -> Option<Vec<u8>> {
        let a = &mut self.active[i];
        if bytes.is_empty() {
            return self.fail(i, msg, CODE_BAD_CONTENT, "empty BODY");
        }
        let n = bytes.len() as u64;
        if n > a.declared.saturating_sub(a.recv) {
            return self.fail(i, msg, CODE_REQ_OVER, "request body longer than declared");
        }
        let Some(tx) = a.tx.as_mut() else {
            return self.fail(i, msg, CODE_INCOMPLETE, "request inspection incomplete");
        };
        match tx.body(bytes) {
            Err(fault) => self.fail(i, msg, u16::from(fault.code), fault.text),
            Ok(Some(stop)) => self.verdict(i, msg, 2, &Outcome::Block(stop)),
            Ok(None) => {
                a.recv = a.recv.saturating_add(n);
                a.state = State::Body;
                None
            }
        }
    }

    fn body_end(&mut self, i: usize, msg: u32) -> Option<Vec<u8>> {
        let a = &mut self.active[i];
        if a.recv != a.declared {
            return self.fail(
                i,
                msg,
                CODE_REQ_TRUNCATED,
                "request body shorter than declared",
            );
        }
        let Some(tx) = a.tx.as_mut() else {
            return self.fail(i, msg, CODE_INCOMPLETE, "request inspection incomplete");
        };
        let result = tx.end();
        self.answer(i, msg, 2, result)
    }

    /// TX_END: the transaction leaves the table, is closed, and CLOSED is the answer. A TX_END with a reason that the
    /// protocol does not have closes it all the same.
    fn close(&mut self, i: usize, h: &Header, p: &[u8]) -> Vec<u8> {
        if decode_tx_end(p).is_err() {
            bump(&mut self.counts.bad_tx_end);
        }
        let a = self.active.remove(i);
        let id = a.id;
        let close_error = self.finish(a);
        encode_closed(self.run, self.inc, id, h.msg, close_error)
    }

    /// Ends the inspection of a transaction that has left the table and counts it.
    fn finish(&mut self, a: Active<I::Tx>) -> bool {
        let close_error = a.tx.is_some_and(Transaction::close);
        bump(&mut self.counts.closed);
        if close_error {
            bump(&mut self.counts.close_errors);
        }
        close_error
    }
}

#[cfg(test)]
mod tests;
