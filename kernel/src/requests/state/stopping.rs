//! Deadlines, the end of the intake and connection faults: `expire`, `tick`, `halt`, `conn_fault` and
//! `exit_confirmed`.
#![forbid(unsafe_code)]

use std::time::Instant;

use super::{
    Decision, Ending, Engine, Halt, ReqId, ReturnReason, Stage, StopOrigin, StopPlan, StopReason,
    Why, after, rec,
};

impl Engine {
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

    /// The session ends the intake for good (DRAIN, or no restart after the exit): every waiting request,
    /// also one that `conn_fault` put back, is decided at once as `Halted` with the first reason. Taken
    /// transactions go on to their end (only `MsgOverflow` stops `next_frame`).
    pub fn halt(&mut self, now: Instant, h: Halt) {
        self.set_halt(now, h);
    }

    pub(super) fn set_halt(&mut self, now: Instant, h: Halt) {
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
    pub(super) fn expire(&mut self, now: Instant) {
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
}
