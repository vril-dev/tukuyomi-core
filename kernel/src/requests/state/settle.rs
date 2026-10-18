//! The places where a decision is recorded and a slot is returned.
#![forbid(unsafe_code)]

use std::time::Instant;

use super::{
    Decision, Ending, Engine, QFrame, QKind, ReqId, ReturnReason, Stage, StopOrigin, StopPlan, Why,
    after, free, rec,
};

impl Engine {
    /// The only place a slot goes from held to returned. The frames of the transaction that are still
    /// in the writer queue are taken out with it (they never get a message number). The record of a request whose
    /// decision was handed over ends with its slot.
    pub(super) fn release(&mut self, ti: usize, reason: ReturnReason) {
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

    /// Record the result of the current stage once: the request decision. A decision other than Forward frees
    /// the payloads. The request is queued for `next_done` where the decision is first made.
    pub(super) fn set_result(&mut self, now: Instant, ti: usize, e: Ending) {
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
    pub(super) fn settle(&mut self, ri: ReqId, now: Instant, d: Decision) {
        let r = rec(&mut self.reqs, ri);
        if r.out.decision.is_none() {
            r.out.decision = Some(d);
            r.out.decided_at = Some(now);
            self.done.push_back(ri);
        }
        free(r);
    }

    /// Settle the stage and hand TX_END to the writer queue.
    pub(super) fn end_tx(&mut self, now: Instant, ti: usize, e: Ending) {
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
    pub(super) fn close_tx(&mut self, now: Instant, ti: usize, reason: u8) {
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
