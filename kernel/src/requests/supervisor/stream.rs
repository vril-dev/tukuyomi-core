//! One turn while a start owns the stream: the engine's clock and halt, the writes of the queued frames
//! and the read of at most one frame.
#![forbid(unsafe_code)]

use std::io::ErrorKind;
use std::mem;
use std::ops::ControlFlow::{self, Break, Continue};
use std::thread;
use std::time::{Duration, Instant};

use crate::process::start::Start;
use crate::protocol::codec::{self, ConnError, Header, HelloExpect};
use crate::protocol::io;
use crate::requests::state::Halt;

use super::{End, Failure, Run, Supervisor, bounded, wire_kind};

impl Supervisor {
    /// The start that owns the stream, with the run number.
    fn conn(&self) -> Option<(&Start, u64)> {
        let run = self.run_id?;
        match &self.run {
            Run::Hello { start, .. } | Run::Ready { start } | Run::Draining { start, .. } => {
                Some((start, run))
            }
            _ => None,
        }
    }

    /// One turn. Down: wait while the restart window is full, else one try to start. Stopping: one try to see the
    /// exit. Stopped and Failed: wait. With a stream: the shutdown deadline, the engine's clock and halt, DRAIN
    /// once the intake has ended and nothing is held, every frame the engine has queued at that point, at most one
    /// frame read (a tick long when nothing arrives). `until` cuts the wait for the first byte; the frame that has
    /// begun is read to its end.
    pub(super) fn step(&mut self, until: Instant) {
        let now = Instant::now();
        match self.run {
            Run::Down => return self.down(now, until),
            Run::Stopping { .. } => return self.reap(now, until),
            Run::Stopped | Run::Failed { .. } => return self.nap(now, until, None),
            Run::Hello { .. } | Run::Ready { .. } | Run::Draining { .. } => {}
        }
        if self.expired(now).is_break()
            || self.check(now).is_break()
            || self.drain_if_done(now).is_break()
            || self.write_queued().is_break()
        {
            return;
        }
        // Frames are left only when the engine's own deadlines queued them during the writes. A read waits for its
        // first byte (it reads nothing when `until` has passed), and no answer may come until those frames have
        // gone out, so the step ends here and the next one goes on writing.
        if self.engine.queued() == 0 {
            let _ = self.read_step(until);
        }
    }

    /// Sleeps until the next tick, `until` or `next`, whichever is first.
    pub(super) fn nap(&self, now: Instant, until: Instant, next: Option<Instant>) {
        let mut wake = bounded(now, self.cfg.tick, None).min(until);
        if let Some(n) = next {
            wake = wake.min(n);
        }
        thread::sleep(wake.saturating_duration_since(now));
    }

    /// The deadlines of the stream states that no frame can move: the shutdown deadline, the wait for BYE (a
    /// moment after the due time, as in the engine) and the HELLO wait (nothing left is over, as in `io`).
    fn expired(&mut self, now: Instant) -> ControlFlow<()> {
        if self.shutdown_by.is_some_and(|d| now > d) {
            return self.stopped(now, End::Restart("shutdown deadline"));
        }
        match self.run {
            Run::Draining { until, .. } if now > until => self.stopped(now, End::Restart("no bye")),
            Run::Hello { until, .. } if now >= until => {
                self.stopped(now, End::Restart("hello wait"))
            }
            _ => Continue(()),
        }
    }

    /// The engine's clock and halt. A stop time that has passed ends the start with the kill at once; so does a
    /// halt that is not the intake ended by `shutdown`: nothing is written after it.
    pub(super) fn check(&mut self, now: Instant) -> ControlFlow<()> {
        if self.engine.tick(now).is_some() {
            return self.stopped(now, End::Restart("stop time"));
        }
        match self.engine.halted() {
            None | Some(Halt::Drain) => Continue(()),
            Some(Halt::TxExhausted | Halt::IncExhausted | Halt::MsgOverflow) => {
                self.stopped(now, End::Fail(Failure::Exhausted))
            }
            // The intake is ended for good only after the stop of a start, never while one runs.
            Some(Halt::NoRestart) => {
                self.stopped(now, End::Fail(Failure::Internal("halted while running")))
            }
        }
    }

    /// The intake has ended and no slot is held: DRAIN goes out through the one writer, and BYE is due within
    /// `drain_wait` of it.
    fn drain_if_done(&mut self, now: Instant) -> ControlFlow<()> {
        if !matches!(self.run, Run::Ready { .. })
            || self.engine.halted() != Some(Halt::Drain)
            || self.engine.held_slots() != 0
            || self.engine.waiting() != 0
        {
            return Continue(());
        }
        let Some((start, run)) = self.conn() else {
            return Continue(());
        };
        let frame = match codec::encode_frame(codec::KIND_DRAIN, run, start.inc, 0, 0, &[]) {
            Ok(f) => f,
            Err(_) => return self.stopped(now, End::Fail(Failure::Internal("encode"))),
        };
        self.put(&frame)?;
        let until = bounded(Instant::now(), self.cfg.drain_wait, self.shutdown_by);
        match mem::replace(&mut self.run, Run::Down) {
            Run::Ready { start } => self.run = Run::Draining { start, until },
            other => self.run = other,
        }
        self.check(Instant::now())
    }

    /// The frames the engine has queued when the call begins, written one after the other by `write_step`, so each
    /// has its own checks and deadline. That count is the bound of the step: nothing is read meanwhile, so no
    /// answer can queue more, and what the engine's own deadlines queue during the writes (an end of a transaction,
    /// a frame for a request that waited) goes out in the next step.
    fn write_queued(&mut self) -> ControlFlow<()> {
        for _ in 0..self.engine.queued() {
            self.write_step()?;
        }
        Continue(())
    }

    /// The engine's next frame, if any, written. `next_frame` is the writer's take: the message number and the
    /// state change are valid from there, so the clock and the halt are looked at again right after it (a halt can
    /// rise inside it, and its `None` looks like an empty queue), and once more in `put` right before the bytes go.
    /// A frame taken and not written is not sent again: the connection fault makes its request uninspectable.
    pub(super) fn write_step(&mut self) -> ControlFlow<()> {
        if self.conn().is_none() {
            return Continue(());
        }
        let taken = self.engine.next_frame(Instant::now());
        self.check(Instant::now())?;
        let Some(out) = taken else {
            return Continue(());
        };
        let Some((start, run)) = self.conn() else {
            return Continue(());
        };
        let frame = match codec::encode_frame(
            wire_kind(out.kind),
            run,
            start.inc,
            out.tx,
            out.msg,
            &out.payload,
        ) {
            Ok(f) => f,
            Err(_) => {
                return self.stopped(Instant::now(), End::Fail(Failure::Internal("encode")));
            }
        };
        self.put(&frame)?;
        self.engine.frame_written(Instant::now(), out.tx, out.msg);
        self.check(Instant::now())
    }

    /// The only place bytes are written: the last look at the clock and the halt, then `io::send` before an
    /// absolute deadline (cut at the shutdown deadline).
    fn put(&mut self, frame: &[u8]) -> ControlFlow<()> {
        let t = Instant::now();
        self.check(t)?;
        let Some((start, _)) = self.conn() else {
            return Continue(());
        };
        let sent = io::send(
            &start.stream,
            frame,
            bounded(t, self.cfg.frame_io, self.shutdown_by),
        );
        match sent {
            Ok(()) => Continue(()),
            Err(_) => self.lost(Instant::now(), "send"),
        }
    }

    /// One frame, waiting at most a tick (and not past `until`) for its first byte. `Io(WouldBlock)` is that wait
    /// running out and is not an error; every other error is a fault of the whole connection. Before HELLO the
    /// whole frame is due by the HELLO wait; after DRAIN, by the wait for BYE; otherwise a frame that has begun
    /// is due within `frame_io`. All are cut at the shutdown deadline.
    pub(super) fn read_step(&mut self, until: Instant) -> ControlFlow<()> {
        let t = Instant::now();
        let Some((start, run)) = self.conn() else {
            return Continue(());
        };
        let idle = bounded(t, self.cfg.tick, self.shutdown_by).min(until);
        let hard = match &self.run {
            Run::Hello { until: u, .. } => bounded(*u, Duration::ZERO, self.shutdown_by),
            Run::Draining { until: u, .. } => *u,
            _ => bounded(idle, self.cfg.frame_io, self.shutdown_by),
        };
        let received = io::recv(&start.stream, run, start.inc, idle, self.cfg.frame_io, hard);
        let now = Instant::now();
        match received {
            Ok((h, p)) => self.dispatch(now, &h, &p),
            Err(ConnError::Io(ErrorKind::WouldBlock)) => Continue(()),
            // The frame had begun and the wait ran out inside it: the same stop as no HELLO within the wait.
            Err(ConnError::Io(ErrorKind::TimedOut)) if matches!(self.run, Run::Hello { until: u, .. } if now >= u) => {
                self.stopped(now, End::Restart("hello wait"))
            }
            Err(_) => self.lost(now, "recv"),
        }
    }

    /// A received frame. The deadlines and the engine's clock are looked at again with the same `now` the engine
    /// gets: a frame that comes back after a deadline is late, and a late CLOSED must not take back a stop that is
    /// already due.
    fn dispatch(&mut self, now: Instant, h: &Header, p: &[u8]) -> ControlFlow<()> {
        self.expired(now)?;
        self.check(now)?;
        let Some((start, run)) = self.conn() else {
            return Continue(());
        };
        if h.run != run || h.inc != start.inc {
            return if matches!(self.run, Run::Hello { .. }) {
                self.stopped(
                    now,
                    End::Fail(Failure::Hello("hello of another run or incarnation")),
                )
            } else {
                self.lost(now, "frame of another run or incarnation")
            };
        }
        if matches!(self.run, Run::Hello { .. }) {
            return self.hello(now, h, p);
        }
        match h.kind {
            codec::KIND_VERDICT => {
                let Ok(v) = codec::decode_verdict(p) else {
                    return self.lost(now, "verdict content");
                };
                let detected = v.flags & codec::FLAG_DETECTED != 0;
                let r = self.engine.on_verdict(
                    now, h.tx, h.msg, v.phase, v.block, detected, v.rule_id, v.status, p,
                );
                if r.is_err() {
                    return self.lost(now, "engine fault");
                }
            }
            codec::KIND_ERROR => {
                let Ok(e) = codec::decode_error(p) else {
                    return self.lost(now, "error content");
                };
                if self
                    .engine
                    .on_error(now, h.tx, h.msg, e.class, e.code, p)
                    .is_err()
                {
                    return self.lost(now, "engine fault");
                }
            }
            codec::KIND_CLOSED => {
                let Ok(close_error) = codec::decode_closed(p) else {
                    return self.lost(now, "closed content");
                };
                if self
                    .engine
                    .on_closed(now, h.tx, h.msg, close_error, p)
                    .is_err()
                {
                    return self.lost(now, "engine fault");
                }
            }
            // BYE is the inspector's last frame and only answers our DRAIN.
            codec::KIND_BYE => {
                if !matches!(self.run, Run::Draining { .. }) {
                    return self.lost(now, "bye before drain");
                }
                if codec::decode_bye(p).is_err() {
                    return self.lost(now, "bye content");
                }
                let kill_at = bounded(now, self.cfg.exit_wait, self.shutdown_by);
                self.end(now, End::Bye, kill_at);
                return Break(());
            }
            codec::KIND_HELLO => return self.lost(now, "second hello"),
            _ => return self.lost(now, "unexpected frame kind"),
        }
        self.check(Instant::now())
    }

    /// HELLO: the first frame of a start, checked against the start and the configuration. Then the engine is
    /// ready. A HELLO that does not match is a deterministic refusal: the start is killed at once and the failure
    /// is final.
    fn hello(&mut self, now: Instant, h: &Header, p: &[u8]) -> ControlFlow<()> {
        if h.kind != codec::KIND_HELLO {
            return self.stopped(now, End::Fail(Failure::Hello("first frame is not hello")));
        }
        let hello = match codec::decode_hello(p) {
            Ok(x) => x,
            Err(e) => return self.stopped(now, End::Fail(Failure::Hello(e.0))),
        };
        let Some((start, run)) = self.conn() else {
            return Continue(());
        };
        let inc = start.inc;
        let expect = HelloExpect {
            rules_sha256: &self.cfg.rules_sha256,
            mem_limit: self.cfg.gomemlimit,
            gomaxprocs: self.cfg.gomaxprocs,
        };
        if let Err(m) = codec::check_hello(&hello, &expect, run, inc, start.pid, &start.nonce) {
            return self.stopped(now, End::Fail(Failure::Hello(m)));
        }
        self.engine.ready(now, inc);
        match mem::replace(&mut self.run, Run::Down) {
            Run::Hello { start, .. } => self.run = Run::Ready { start },
            other => self.run = other,
        }
        self.check(now)
    }

    /// A fault of the connection: our end is closed and the inspector, which sees the loss, is given `exit_wait`
    /// to end by itself before it is killed.
    fn lost(&mut self, now: Instant, why: &'static str) -> ControlFlow<()> {
        let kill_at = bounded(now, self.cfg.exit_wait, self.shutdown_by);
        self.end(now, End::Restart(why), kill_at);
        Break(())
    }

    /// The inspector must be stopped at once.
    fn stopped(&mut self, now: Instant, end: End) -> ControlFlow<()> {
        self.end(now, end, now);
        Break(())
    }

    /// The one end of a start, whichever way it ends: the engine gets the connection fault, our end is closed and
    /// dropped (`Start::stop`), and the stop runs, at once or from `kill_at`.
    pub(super) fn end(&mut self, now: Instant, end: End, kill_at: Instant) {
        match mem::replace(&mut self.run, Run::Down) {
            Run::Hello { start, .. } | Run::Ready { start } | Run::Draining { start, .. } => {
                self.engine.conn_fault(now);
                self.run = Run::Stopping {
                    stop: start.stop(kill_at),
                    end,
                };
            }
            other => self.run = other,
        }
    }
}
