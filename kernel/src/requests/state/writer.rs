//! The writer's side: the next frame is taken, and numbered, just before it is written; a written frame
//! starts the CLOSED wait.
#![forbid(unsafe_code)]

use std::mem;
use std::time::Instant;

use super::{
    Decision, Ending, Engine, Halt, OutKind, Outgoing, QKind, ReturnReason, Stage, StopOrigin,
    StopPlan, Why, after, rec,
};

impl Engine {
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
}
