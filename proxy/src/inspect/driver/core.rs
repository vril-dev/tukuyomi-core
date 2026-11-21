//! The driver thread repeats one round. It takes in new tickets (at most one more than all the waiting queues hold,
//! so a round always goes on to the next steps), calls `cancel` once for every ticket whose connection went away,
//! steps the kernel of each engine for one slice, delivers the results, tells the main thread when the kernels
//! became ready or one failed, publishes the state of the kernel of each engine (`States`), and records one line when
//! the incarnation of an inspector changed, which is how a restart shows from outside. After a stop message it goes
//! on serving the tickets of the connections that exist, calls `shutdown` once nothing can arrive any more (or when
//! the stop deadline is reached), and from then on answers every ticket with `Outcome::Unavailable` until the last
//! sender is gone.
//!
//! A ticket goes to the lane of its engine (see `engines`), and to no other. The driver has one lane for each engine,
//! with a kernel for each engine that was started, and steps them one after the other.
//!
//! A switch message makes the driver serve two generations of an engine for a while. It makes a second kernel on the
//! rules of the new generation and steps it in every round for the shortest step that can read a frame, while new
//! tickets of the engine still go to the kernel that serves. When the new kernel is ready, new tickets go to it, and
//! the other kernel finishes the requests it holds, for `stop_inspect` at the most, and is stopped on a thread of its
//! own. A new kernel that fails to start, or that is not ready within `ready_wait`, is stopped the same way and the
//! old one serves on. For an engine that has no kernel the switch starts the kernel, and its end is told when the
//! kernel is ready. Each kernel has a table of its own for its requests (`slot`). A failure of a kernel that serves
//! stops the proxy as ever, also in the middle of a switch, but the failure of a kernel before it is ready is the
//! failure of its switch. The main thread is told how a switch ended when the kernel that was stopped is gone.

use std::mem;
use std::sync::mpsc::{Receiver, RecvTimeoutError, TryRecvError};
use std::time::{Duration, Instant};

use tokio::sync::oneshot;
use tukuyomi_kernel::{Engine, Shutdown, Status};

use super::{End, Kernel, Limits, Msg, Outcome, Switched, Ticket};
use crate::inspect::engines::{Lane, MIN_SLICE, Publisher, Switching, Told, index};
use crate::log::Log;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Mode {
    Run,
    /// A stop was asked for: the tickets of existing connections are still served until `shutdown` is due.
    Stopping {
        inspect_by: Instant,
    },
    /// `shutdown` was called: no ticket is submitted any more.
    Down,
}

/// Whether `shutdown` is due: nothing can arrive any more and nothing waits for a result, or the stop deadline
/// is reached.
fn shutdown_due(closed: bool, nothing_pending: bool, inspect_by: Instant, now: Instant) -> bool {
    (closed && nothing_pending) || now >= inspect_by
}

/// The record line for the start of a stop: what the kernel of an engine still holds. Fixed text and numbers only.
fn stop_line(engine: Engine, status: &Status) -> String {
    format!(
        "driver: stop, engine {}, records {}, held {}, waiting {}",
        engine.name(),
        status.records,
        status.held,
        status.waiting
    )
}

/// Everything the driver thread owns.
pub(super) struct Core<K> {
    pub(super) rx: Receiver<Msg>,
    /// One lane for each engine, in the order of `ENGINES`.
    pub(super) lanes: Vec<Lane<K>>,
    pub(super) mode: Mode,
    /// Every sender is gone: nothing can arrive any more.
    closed: bool,
    pub(super) told: Told,
    log: Log,
    /// The longest wait for a message while there is nothing to do.
    tick: Duration,
    /// The times of the proxy; the slice is cut to the tick, and is at least `MIN_SLICE`.
    pub(super) limits: Limits,
    /// The most messages one intake takes: one more than the waiting queues hold.
    take: usize,
    /// Where the states of the kernels that serve are published after every round.
    publisher: Publisher,
}

impl<K: Kernel> Core<K> {
    // One argument for each part of the state of the driver; a struct of them would only repeat the fields of `Core`.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        lanes: Vec<Lane<K>>,
        rx: Receiver<Msg>,
        told: Told,
        log: Log,
        limits: Limits,
        tick: Duration,
        take: usize,
        publisher: Publisher,
    ) -> Core<K> {
        Core {
            rx,
            lanes,
            mode: Mode::Run,
            closed: false,
            told,
            log,
            tick,
            limits: Limits {
                slice: limits.slice.min(tick).max(MIN_SLICE),
                ..limits
            },
            take: take.max(1),
            publisher,
        }
    }

    /// Runs to the end and tells the main thread how it ended. The kernels and the tables go when this returns, so
    /// the end is told first.
    pub(super) fn drive(mut self, end: oneshot::Sender<End>) {
        let ended = self.run();
        let _ = end.send(ended);
    }

    pub(super) fn run(&mut self) -> End {
        let done = loop {
            match self.round() {
                Ok(None) => {}
                Ok(Some(done)) => break done,
                Err(why) => return End::Fatal(why),
            }
        };
        match self.quiesce() {
            Ok(()) => End::Done {
                kernel: done,
                retired_clean: self.lanes.iter().all(|lane| lane.retired_clean),
            },
            Err(why) => End::Fatal(why),
        }
    }

    /// One round. `Some` is the end of the `shutdown` that was called in this round (the other kernels are stopped on
    /// threads of their own). `Err` is a fault that stops the driver.
    pub(super) fn round(&mut self) -> Result<Option<Shutdown>, &'static str> {
        self.intake(None)?;
        for lane in &mut self.lanes {
            lane.scan();
        }
        self.wait()?;
        let slice = self.limits.slice;
        // A lane with nothing to do is stepped for the shortest step, unless no lane has anything to do.
        let alone = !self.lanes.iter().any(Lane::working);
        for lane in &mut self.lanes {
            lane.step(slice, alone, &self.log)?;
        }
        // The state is published before the main thread is told that a kernel is ready, so that a main thread that
        // has been told never finds the older state.
        self.publisher.publish(&self.lanes);
        for lane in &mut self.lanes {
            if let Some(phase) = lane.active.as_ref().map(|active| active.status().phase)
                && let Some(said) = lane.signals.note(phase)
            {
                self.told.said(said);
            }
            lane.note(&self.log);
        }
        for lane in &mut self.lanes {
            lane.advance(&self.limits, &self.log)?;
        }
        let done = self.finish_if_due()?;
        // Again, for what the switch and the shutdown of this round changed.
        self.publisher.publish(&self.lanes);
        Ok(done)
    }

    /// Takes in at most `take` messages, `first` (one that was waited for) included.
    pub(super) fn intake(&mut self, first: Option<Msg>) -> Result<(), &'static str> {
        let mut left = self.take;
        if let Some(msg) = first {
            left -= 1;
            self.accept(msg)?;
        }
        while left > 0 && !self.closed {
            match self.rx.try_recv() {
                Ok(msg) => {
                    left -= 1;
                    self.accept(msg)?;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => self.close(),
            }
        }
        Ok(())
    }

    fn accept(&mut self, msg: Msg) -> Result<(), &'static str> {
        match msg {
            Msg::Ticket(ticket) => self.admit(ticket),
            Msg::Switch(switch) => {
                let lane = &mut self.lanes[index(switch.kernel.engine)];
                let run = self.mode == Mode::Run;
                lane.begin_switch(switch, run, self.limits.ready_wait, &self.log);
                Ok(())
            }
            Msg::Stop { inspect_by } => {
                self.stop(inspect_by);
                Ok(())
            }
        }
    }

    /// After `shutdown` nothing is submitted. A ticket goes to the lane of its engine, which answers it at once if
    /// the engine has no kernel.
    fn admit(&mut self, ticket: Ticket) -> Result<(), &'static str> {
        if self.mode == Mode::Down {
            let _ = ticket.reply.send(Outcome::Unavailable.into());
            return Ok(());
        }
        self.lanes[index(ticket.engine)].admit(ticket)
    }

    /// The first stop message records one line for each kernel and sets the deadline; a later one can only bring it
    /// forward. A kernel that is starting holds no request: it is stopped at once.
    fn stop(&mut self, inspect_by: Instant) {
        self.mode = match self.mode {
            Mode::Run => {
                for lane in &mut self.lanes {
                    if let Some(active) = &lane.active {
                        self.log.line(&stop_line(lane.engine, &active.status()));
                    }
                    match mem::replace(&mut lane.switching, Switching::Idle) {
                        Switching::Starting { next, .. } => {
                            lane.retire(next, inspect_by, Switched::No);
                        }
                        other => lane.switching = other,
                    }
                }
                Mode::Stopping { inspect_by }
            }
            Mode::Stopping { inspect_by: first } => Mode::Stopping {
                inspect_by: first.min(inspect_by),
            },
            Mode::Down => Mode::Down,
        };
    }

    /// The last sender is gone. Without a stop message that is a stop whose deadline has passed: nothing can
    /// arrive any more, and whatever is in flight is decided at once.
    fn close(&mut self) {
        self.closed = true;
        if self.mode == Mode::Run {
            self.stop(Instant::now());
        }
    }

    /// Whether every lane waits for nothing.
    fn idle(&self) -> bool {
        self.lanes
            .iter()
            .all(|lane| lane.idle(self.mode == Mode::Run))
    }

    /// Whether no request waits for a result, in any lane.
    fn nothing_pending(&self) -> bool {
        self.lanes.iter().all(Lane::nothing_pending)
    }

    /// Waits for a message, but only when idle. Anything else must go on stepping the kernels.
    fn wait(&mut self) -> Result<(), &'static str> {
        if !self.idle() {
            return Ok(());
        }
        match self.rx.recv_timeout(self.tick) {
            Ok(msg) => self.intake(Some(msg)),
            Err(RecvTimeoutError::Timeout) => Ok(()),
            Err(RecvTimeoutError::Disconnected) => {
                self.close();
                Ok(())
            }
        }
    }

    /// Calls `shutdown` when it is due and delivers its results. Every kernel but one goes on a thread of its own,
    /// all at the same time, the one that is left here: the end of that `shutdown` is the end of the driver. Every
    /// request is decided by then, so a ticket that is left in a table breaks the promise that every result comes out
    /// once.
    fn finish_if_due(&mut self) -> Result<Option<Shutdown>, &'static str> {
        let Mode::Stopping { inspect_by } = self.mode else {
            return Ok(None);
        };
        if !shutdown_due(
            self.closed,
            self.nothing_pending(),
            inspect_by,
            Instant::now(),
        ) {
            return Ok(None);
        }
        let mut here = None;
        for (at, lane) in self.lanes.iter_mut().enumerate() {
            match mem::replace(&mut lane.switching, Switching::Idle) {
                Switching::Draining { old, .. } => lane.retire(old, inspect_by, Switched::Yes),
                other => lane.switching = other,
            }
            if lane.active.is_none() {
                continue;
            }
            if here.is_none() {
                here = Some(at);
            } else if let Some(active) = lane.active.take() {
                // The retirement that the lane has is over first: a lane has one at a time.
                lane.collect(&self.log)?;
                lane.retire(active, inspect_by, Switched::Yes);
            }
        }
        let Some(active) = here.and_then(|at| self.lanes[at].active.as_mut()) else {
            return Err("no kernel to stop");
        };
        let done = active.shutdown(inspect_by)?;
        self.mode = Mode::Down;
        for lane in &mut self.lanes {
            lane.collect(&self.log)?;
        }
        Ok(Some(done))
    }

    /// After `shutdown`: answers every ticket with `Outcome::Unavailable` until the last sender is gone. The
    /// kernels are not stepped any more.
    pub(super) fn quiesce(&mut self) -> Result<(), &'static str> {
        while !self.closed {
            match self.rx.recv() {
                Ok(msg) => self.intake(Some(msg))?,
                Err(_) => self.close(),
            }
        }
        Ok(())
    }
}
