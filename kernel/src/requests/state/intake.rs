//! Taking requests in and handing decisions out: HELLO, `submit`, `cancel`, the slots given to waiting
//! requests and the hand-over of decisions.
#![forbid(unsafe_code)]

use std::time::Instant;

use super::{
    Decision, Ending, Engine, Halt, Live, Outcome, QFrame, QKind, Req, ReqId, Request,
    ReturnReason, Stage, SubmitError, Why, after, free, rec, valid,
};

impl Engine {
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

    /// Slots for waiting requests, in order. The numbers are checked before anything else.
    pub(super) fn assign(&mut self, now: Instant) {
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
}
