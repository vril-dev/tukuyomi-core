//! Answers of the inspector: VERDICT, ERROR and CLOSED, checked against the state of the held transaction.
#![forbid(unsafe_code)]

use std::time::Instant;

use super::{
    ConnFault, Decision, Ending, Engine, QFrame, QKind, ReqId, ReturnReason, Seen, Stage, Why, rec,
};

impl Engine {
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
}
