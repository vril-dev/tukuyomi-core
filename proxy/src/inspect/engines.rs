//! The engines of the driver: what the connections share of each engine (`Gates`), what the driver tells the main side
//! of each (`States`), and the share of the driver that one engine has (`Lane`).
//!
//! The driver serves one kernel for each engine that was started, and two for a while when it switches to another
//! generation of an engine. A lane is the part of the driver that belongs to one engine: the slot that serves, the
//! switch of the engine that is under way, the table of the requests of its generation that skip the inspection, and
//! the part of the signals that the engine has. The lanes are stepped one after the other in a round of the driver,
//! on its one thread; a lane whose slot holds nothing is stepped for the shortest step that can read a frame, so that
//! an engine that has nothing to do does not delay the one that has. When no lane holds anything, the first lane that
//! has a slot is stepped for the whole slice and the others for the shortest step: the round waits for a frame for one
//! slice, as it does with one lane.
//!
//! A connection takes the gate of the engine of the upstream group its request goes to: the routes of that engine's
//! generation and the inspection permits of that engine, as many as the kernel's waiting queue. So an engine whose
//! inspections wait does not use up the permits of the other, and a request is never inspected by another engine than
//! the one of its group, nor skips the inspection by a route of another engine's generation. An engine that was not
//! started has a gate whose table is empty, and a lane without a slot: its tickets are answered
//! `Outcome::Unavailable` at once.

use std::mem;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{oneshot, watch};
use tukuyomi_kernel::{Engine, Failure, Phase};

use super::driver::{Kernel, Limits, Outcome, State, Switch, Switched, Ticket};
use super::slot::{Retired, Retirement, Slot};
use crate::log::{Log, escaped};
use crate::rules::routes::{Routes, SharedRoutes};
use crate::rules::store::{ENGINES, index};

/// The shortest slice of one kernel step. A shorter one would end a step before it could read anything.
pub(super) const MIN_SLICE: Duration = Duration::from_millis(1);

/// What the connections share of one engine.
#[derive(Clone)]
pub struct Gate {
    /// The routes of the generation of the engine that serves: the requests that skip the inspection. A connection
    /// reads them once for each request, and the driver replaces them when it makes another generation of the engine
    /// the one that serves, so the routes and the generation that inspects change together.
    pub routes: SharedRoutes,
    /// The inspection permits, as many as the waiting queue of the kernel.
    pub inspect: Arc<tokio::sync::Semaphore>,
}

/// The gate of each engine.
#[derive(Clone)]
pub struct Gates([Gate; ENGINES.len()]);

impl Gates {
    /// A gate for each engine, with no route and `wait_queue` permits.
    pub fn new(wait_queue: usize) -> Gates {
        Gates(ENGINES.map(|_| Gate {
            routes: SharedRoutes::new(Routes::default()),
            inspect: Arc::new(tokio::sync::Semaphore::new(wait_queue)),
        }))
    }

    pub fn of(&self, engine: Engine) -> &Gate {
        &self.0[index(engine)]
    }

    /// The inspections that hold a permit of the waiting queue, of every engine.
    pub fn waiting(&self, wait_queue: usize) -> usize {
        self.0.iter().fold(0usize, |sum, gate| {
            sum.saturating_add(wait_queue.saturating_sub(gate.inspect.available_permits()))
        })
    }
}

/// What the driver tells the main side of each engine that serves: `None` for an engine that was not started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct States([Option<State>; ENGINES.len()]);

impl States {
    /// No engine is started.
    pub fn none() -> States {
        States([None; ENGINES.len()])
    }

    pub fn of(&self, engine: Engine) -> Option<&State> {
        self.0[index(engine)].as_ref()
    }

    /// The states of the engines that were started, in the order of their names.
    pub fn started(&self) -> impl Iterator<Item = &State> {
        self.0.iter().flatten()
    }

    /// Every engine that was started serves: its kernel is in the phase `Ready`.
    pub fn all_ready(&self) -> bool {
        self.started().all(|state| state.phase == Phase::Ready)
    }

    /// The restarts of the inspectors of every engine.
    pub fn restarts(&self) -> u64 {
        self.started().fold(0u64, |sum, state| {
            sum.saturating_add(u64::from(state.restarts))
        })
    }

    /// Puts the state of `engine`.
    pub fn set(&mut self, engine: Engine, state: Option<State>) {
        self.0[index(engine)] = state;
    }
}

/// What the main thread was told about the kernel of one engine. Each answer is given once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Signals {
    /// Nothing was said yet: the main thread waits for the kernel to be ready.
    Waiting,
    /// Ready was said; a failure is still to be said.
    Running,
    /// Everything that can be said was said.
    Told,
}

/// What a phase of the kernel makes the main thread be told.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Said {
    /// The kernel became ready.
    Ready,
    /// The kernel failed before it was ready.
    Failed(Failure),
    /// The kernel failed after it was ready: the proxy stops.
    Lost(Failure),
}

impl Signals {
    /// Takes in the phase the kernel is in after a step.
    pub(super) fn note(&mut self, phase: Phase) -> Option<Said> {
        match (*self, phase) {
            (Signals::Waiting, Phase::Ready) => {
                *self = Signals::Running;
                Some(Said::Ready)
            }
            (Signals::Waiting, Phase::Failed(why)) => {
                *self = Signals::Told;
                Some(Said::Failed(why))
            }
            (Signals::Running, Phase::Failed(why)) => {
                *self = Signals::Told;
                Some(Said::Lost(why))
            }
            _ => None,
        }
    }
}

/// What a switch of generation is doing. There is one at a time in a lane.
pub(super) enum Switching<K> {
    Idle,
    /// The new kernel starts. New tickets still go to the kernel that serves, if there is one.
    Starting {
        next: Slot<K>,
        ready_by: Instant,
        /// The routes of `next`: they become the table of the gate when it serves.
        routes: Routes,
    },
    /// The new kernel serves. The old one finishes the requests it holds, until `drain_by`.
    Draining {
        old: Slot<K>,
        drain_by: Instant,
    },
    /// A kernel is being stopped on a thread of its own. `switched` is how the switch ends.
    Retiring {
        retirement: Retirement,
        switched: Switched,
    },
}

/// `t + d`; a sum that does not fit is `t`: due at once.
pub(super) fn after(t: Instant, d: Duration) -> Instant {
    t.checked_add(d).unwrap_or(t)
}

/// The share of the driver that one engine has.
pub(super) struct Lane<K> {
    pub(super) engine: Engine,
    /// The kernel that new tickets of the engine go to: none while the engine was not started.
    pub(super) active: Option<Slot<K>>,
    /// The routes of the generation of `active`, which the connections read.
    pub(super) routes: SharedRoutes,
    pub(super) switching: Switching<K>,
    /// Where to tell the main thread how the switch ended.
    reply: Option<oneshot::Sender<Switched>>,
    /// The answer to the switch that started the kernel of an engine that had none, kept until the state of the lanes
    /// is published (`tell`), so that the main thread that is told finds the engine in it.
    started: Option<oneshot::Sender<Switched>>,
    pub(super) signals: Signals,
    /// The restarts that the kernels made which served before the one that serves now.
    restarts_before: u32,
    /// Every kernel of the lane that was stopped so far stopped cleanly.
    pub(super) retired_clean: bool,
}

impl<K: Kernel> Lane<K> {
    /// The lane of `engine` with the table `routes` of its gate, the slot that serves from the start if there is one
    /// (then the main thread waits for it, as `signals` says).
    pub(super) fn new(engine: Engine, routes: SharedRoutes, active: Option<Slot<K>>) -> Lane<K> {
        let signals = if active.is_some() {
            Signals::Waiting
        } else {
            Signals::Told
        };
        Lane {
            engine,
            active,
            routes,
            switching: Switching::Idle,
            reply: None,
            started: None,
            signals,
            restarts_before: 0,
            retired_clean: true,
        }
    }

    /// Hands the ticket to the slot that serves. A lane without one answers at once that the inspection is not
    /// available; a ticket is never handed to another engine.
    pub(super) fn admit(&mut self, ticket: Ticket) -> Result<(), &'static str> {
        match self.active.as_mut() {
            Some(active) => active.admit(ticket),
            None => {
                let _ = ticket.reply.send(Outcome::Unavailable.into());
                Ok(())
            }
        }
    }

    /// Makes the kernel of the new generation, when a switch can begin: the proxy runs (`run`) and no other switch
    /// of the engine is under way. The main thread sends one switch at a time, so the second condition is a guard.
    pub(super) fn begin_switch(
        &mut self,
        switch: Switch,
        run: bool,
        ready_wait: Duration,
        log: &Log,
    ) {
        let Switch {
            generation,
            mode,
            routes,
            kernel,
            reply,
        } = switch;
        if !run || !matches!(self.switching, Switching::Idle) {
            let _ = reply.send(Switched::No);
            return;
        }
        match K::create(kernel) {
            Ok(kernel) => {
                self.switching = Switching::Starting {
                    next: Slot::new(generation, self.engine, mode, kernel),
                    ready_by: after(Instant::now(), ready_wait),
                    routes,
                };
                self.reply = Some(reply);
            }
            Err(why) => {
                log.line(&format!(
                    "reload: generation {} failed to start: {why}",
                    generation.hex()
                ));
                let _ = reply.send(Switched::No);
            }
        }
    }

    /// The kernel that does not get new tickets: the new one while it starts, the old one while it finishes.
    pub(super) fn other(&mut self) -> Option<&mut Slot<K>> {
        match &mut self.switching {
            Switching::Starting { next, .. } => Some(next),
            Switching::Draining { old, .. } => Some(old),
            Switching::Idle | Switching::Retiring { .. } => None,
        }
    }

    /// Calls `cancel` for the tickets whose connection went away, in both kernels.
    pub(super) fn scan(&mut self) {
        if let Some(active) = self.active.as_mut() {
            active.scan();
        }
        if let Some(other) = self.other() {
            other.scan();
        }
    }

    /// Whether the lane holds a request or a record that waits for a result.
    pub(super) fn working(&self) -> bool {
        self.active
            .as_ref()
            .is_some_and(|active| !active.pending.is_empty() || active.status().records != 0)
    }

    /// Steps the kernel that serves: for `slice` if the lane is working or `leads` (no lane is working, and this is
    /// the first lane that has a kernel), else for the shortest step that can read a frame, so that a lane with nothing
    /// to do does not hold up one that has, and the lanes that have nothing to do do not wait one slice each. Then
    /// the kernel that does not get new tickets, for the shortest step as well. A step whose end has passed writes
    /// but reads nothing (`Supervisor::poll`), and a kernel that is not the one that serves has a frame to read: the
    /// HELLO of a new inspector, the verdicts of an old one.
    pub(super) fn step(
        &mut self,
        slice: Duration,
        leads: bool,
        log: &Log,
    ) -> Result<(), &'static str> {
        let working = self.working();
        if let Some(active) = self.active.as_mut() {
            let slice = if working || leads { slice } else { MIN_SLICE };
            active.step(after(Instant::now(), slice))?;
        }
        let until = after(Instant::now(), MIN_SLICE);
        let lines = match self.other() {
            Some(other) => {
                other.step(until)?;
                [other.note_incarnation(), other.note_turned()]
            }
            None => [None, None],
        };
        for line in lines.into_iter().flatten() {
            log.line(&line);
        }
        Ok(())
    }

    /// The record lines for what the kernel that serves did in this round.
    pub(super) fn note(&mut self, log: &Log) {
        if let Some(active) = self.active.as_mut() {
            for line in [active.note_incarnation(), active.note_turned()]
                .into_iter()
                .flatten()
            {
                log.line(&line);
            }
        }
    }

    /// What the main thread is told of the lane: the state of the kernel that serves.
    pub(super) fn state(&self) -> Option<State> {
        let active = self.active.as_ref()?;
        let status = active.status();
        Some(State {
            phase: status.phase,
            restarts: self.restarts_before.saturating_add(status.restarts),
            generation: active.generation,
            engine: active.engine,
            mode: active.mode,
        })
    }

    /// Whether the lane waits for nothing: the proxy runs (`run`), no switch is under way, and the kernel that serves
    /// is ready and holds no request and no record.
    pub(super) fn idle(&self, run: bool) -> bool {
        if !run || !matches!(self.switching, Switching::Idle) {
            return false;
        }
        match &self.active {
            None => true,
            Some(active) => {
                if !active.pending.is_empty() {
                    return false;
                }
                let status = active.status();
                status.records == 0 && status.phase == Phase::Ready
            }
        }
    }

    /// Whether no request waits for a result, in the kernel that serves and in the one that finishes.
    pub(super) fn nothing_pending(&self) -> bool {
        let old = match &self.switching {
            Switching::Draining { old, .. } => old.pending.is_empty(),
            _ => true,
        };
        old && self
            .active
            .as_ref()
            .is_none_or(|active| active.pending.is_empty())
    }

    /// Moves the switch on by what the round found out.
    pub(super) fn advance(&mut self, limits: &Limits, log: &Log) -> Result<(), &'static str> {
        let now = Instant::now();
        match mem::replace(&mut self.switching, Switching::Idle) {
            Switching::Idle => {}
            Switching::Starting {
                next,
                ready_by,
                routes,
            } => self.advance_starting(next, ready_by, routes, now, limits, log),
            Switching::Draining { old, drain_by } => {
                if old.pending.is_empty() || now >= drain_by {
                    // A kernel that still holds requests is out of time: it is stopped at once, and `shutdown`
                    // decides them. One that holds nothing is given the time to end by itself.
                    let by = if old.pending.is_empty() {
                        after(now, limits.stop_inspect)
                    } else {
                        now
                    };
                    self.retire(old, by, Switched::Yes);
                } else {
                    self.switching = Switching::Draining { old, drain_by };
                }
            }
            Switching::Retiring {
                mut retirement,
                switched,
            } => match retirement.poll()? {
                Some(retired) => self.retired(&retired, switched, log),
                None => {
                    self.switching = Switching::Retiring {
                        retirement,
                        switched,
                    };
                }
            },
        }
        Ok(())
    }

    /// The new kernel that was stepped in this round: serving from now on if it is ready, with its `routes` as the
    /// table of the gate, stopped if it failed or is late, and then the table stays as it is. A failure before it is
    /// ready is the failure of the switch, also for an engine that had no kernel: the lane goes on as it was.
    fn advance_starting(
        &mut self,
        next: Slot<K>,
        ready_by: Instant,
        routes: Routes,
        now: Instant,
        limits: &Limits,
        log: &Log,
    ) {
        // The kernel that serves failed in this round: the proxy stops, and does not hurry to the new one.
        let serving_failed = self
            .active
            .as_ref()
            .is_some_and(|active| matches!(active.status().phase, Phase::Failed(_)));
        match next.status().phase {
            Phase::Ready if !serving_failed => {
                log.line(&format!(
                    "reload: generation {} is ready, switched",
                    next.generation.hex()
                ));
                self.routes.replace(routes);
                match self.active.replace(next) {
                    Some(old) => {
                        self.restarts_before =
                            self.restarts_before.saturating_add(old.status().restarts);
                        self.switching = Switching::Draining {
                            old,
                            drain_by: after(now, limits.stop_inspect),
                        };
                    }
                    None => {
                        // An engine that had no kernel: nothing is left to finish, and the proxy is told if this
                        // kernel fails from now on. The main thread is told that the switch ended in `tell`.
                        self.signals = Signals::Running;
                        self.started = self.reply.take();
                    }
                }
            }
            // Ready, but the kernel that serves failed: the stop that follows retires it.
            Phase::Ready => {
                self.switching = Switching::Starting {
                    next,
                    ready_by,
                    routes,
                }
            }
            Phase::Failed(why) => {
                self.failed_to_start(&next, &format!("{why:?}"), log);
                self.retire(next, after(now, limits.stop_inspect), Switched::No);
            }
            _ if now >= ready_by => {
                self.failed_to_start(&next, "not ready in time", log);
                self.retire(next, after(now, limits.stop_inspect), Switched::No);
            }
            _ => {
                self.switching = Switching::Starting {
                    next,
                    ready_by,
                    routes,
                }
            }
        }
    }

    /// Two record lines: what failed (fixed text), and the line that the inspector left, if there is one, with
    /// every byte outside 0x20 to 0x7e escaped.
    fn failed_to_start(&self, slot: &Slot<K>, kind: &str, log: &Log) {
        log.line(&format!(
            "reload: generation {} failed to start: {kind}",
            slot.generation.hex()
        ));
        if let Some(detail) = slot.kernel.start_detail() {
            let line = detail.strip_suffix(b"\n").unwrap_or(&detail);
            log.line(&format!(
                "reload: the inspector said: \"{}\"",
                escaped(line)
            ));
        }
    }

    /// Gives the slot to a thread that stops it.
    pub(super) fn retire(&mut self, slot: Slot<K>, deadline: Instant, switched: Switched) {
        self.switching = Switching::Retiring {
            retirement: slot.retire(deadline),
            switched,
        };
    }

    /// Tells the main thread that the switch which started the kernel of an engine that had none has ended. It is
    /// called after the state of the lanes is published.
    pub(super) fn tell(&mut self) {
        if let Some(reply) = self.started.take() {
            let _ = reply.send(Switched::Yes);
        }
    }

    /// A retirement is over: one record line, and the main thread is told how the switch ended (when there is a
    /// switch to tell).
    pub(super) fn retired(&mut self, retired: &Retired, switched: Switched, log: &Log) {
        log.line(&format!(
            "reload: generation {} retired, clean {}",
            retired.generation.hex(),
            retired.clean
        ));
        self.retired_clean &= retired.clean;
        if let Some(reply) = self.reply.take() {
            let _ = reply.send(switched);
        }
    }

    /// Waits for the retirement that is going on, if there is one.
    pub(super) fn collect(&mut self, log: &Log) -> Result<(), &'static str> {
        if let Switching::Retiring {
            retirement,
            switched,
        } = mem::replace(&mut self.switching, Switching::Idle)
        {
            let retired = retirement.wait()?;
            self.retired(&retired, switched, log);
        }
        Ok(())
    }
}

/// How the main thread is told what the lanes say: that every kernel that was started at the start is ready, the
/// first failure of one that is not, and the failure of a kernel that served.
pub(super) struct Told {
    /// The answer to the start: ready when `waiting` kernels have said so, or the failure of the first that fails.
    ready: Option<oneshot::Sender<Result<(), Failure>>>,
    waiting: usize,
    /// A kernel that served and failed. At most one for each engine says so; the sender is kept for as long as the
    /// driver runs, so that the main thread never sees the channel close without an answer.
    failed: tokio::sync::mpsc::Sender<Failure>,
}

impl Told {
    /// The start is ready when each of `waiting` kernels has said so; with none, it is ready as it is.
    pub(super) fn new(
        ready: oneshot::Sender<Result<(), Failure>>,
        waiting: usize,
        failed: tokio::sync::mpsc::Sender<Failure>,
    ) -> Told {
        let mut told = Told {
            ready: Some(ready),
            waiting,
            failed,
        };
        told.complete();
        told
    }

    fn complete(&mut self) {
        if self.waiting == 0
            && let Some(ready) = self.ready.take()
        {
            let _ = ready.send(Ok(()));
        }
    }

    /// Takes in what a lane said.
    pub(super) fn said(&mut self, said: Said) {
        match said {
            Said::Ready => {
                self.waiting = self.waiting.saturating_sub(1);
                self.complete();
            }
            Said::Failed(why) => {
                if let Some(ready) = self.ready.take() {
                    let _ = ready.send(Err(why));
                }
            }
            Said::Lost(why) => {
                let _ = self.failed.try_send(why);
            }
        }
    }
}

/// The sender of the state of the engines, and what was last sent.
pub(super) struct Publisher {
    sender: watch::Sender<States>,
}

impl Publisher {
    pub(super) fn new(sender: watch::Sender<States>) -> Publisher {
        Publisher { sender }
    }

    /// Tells the main side the states of the lanes, if they changed.
    pub(super) fn publish<K: Kernel>(&self, lanes: &[Lane<K>]) {
        let mut states = States::none();
        for lane in lanes {
            states.set(lane.engine, lane.state());
        }
        self.sender.send_if_modified(|seen| {
            let changed = *seen != states;
            *seen = states;
            changed
        });
    }
}
