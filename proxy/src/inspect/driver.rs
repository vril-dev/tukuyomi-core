//! The inspection driver: the owner of the kernel's `Supervisor`s, on its own thread.
//!
//! A connection hands a `Ticket` over one bounded channel and waits on the reply slot of the ticket. The driver
//! submits the ticket to the kernel, keeps it until the kernel's result for it comes out, and then answers on the
//! reply slot. Besides the channels, the driver shares one thing with the connections: the table of the routes
//! (`SharedRoutes`), which the connections read and the driver replaces.
//!
//! The driver thread repeats one round. It takes in new tickets (at most one more than the waiting queue holds,
//! so a round always goes on to the next steps), calls `cancel` once for every ticket whose connection went away,
//! steps the kernel for one slice, delivers the results, tells the main thread when the kernel became ready or
//! failed, and records one line when the incarnation of the inspector changed, which is how a restart shows from
//! outside. After a stop message it goes on serving the tickets of the connections that exist, calls `shutdown`
//! once nothing can arrive any more (or when the stop deadline is reached), and from then on answers every ticket
//! with `Outcome::Unavailable` until the last sender is gone.
//!
//! What a ticket holds (the inspection permit, the byte budget of the kernel's copy, its share of the body) goes
//! back only when the result of its request has been taken, or when the ticket is dropped before it was
//! submitted. A connection that gave up does not give it back: the kernel keeps the record until its result
//! comes out.
//!
//! A switch message makes the driver serve two generations for a while. It makes a second kernel on the rules of
//! the new generation and steps it in every round for the shortest step that can read a frame, while new tickets
//! still go to the kernel that serves. When the new kernel is ready, new tickets go to it, and the other kernel
//! finishes the requests it holds, for `stop_inspect` at the most, and is stopped on a thread of its own. A new
//! kernel that fails to start, or that is not ready within `ready_wait`, is stopped the same way and the old one
//! serves on. Each kernel has a table of its own for its requests (`slot`). A failure of the kernel that serves
//! stops the proxy as ever, also in the middle of a switch. The main thread is told how a switch ended when the
//! kernel that was stopped is gone.
//!
//! Each slot keeps the mode of its generation. A generation that blocks never has a request that is only detected,
//! so a `Detected` that its kernel gives is not believed: the ticket is answered with `Uninspectable`, and the
//! first time it happens in a slot the driver records one line.
//!
//! The routes of the generation that serves are not kept by the slots. A connection matches its request against the
//! shared table before it makes a ticket, so a request that a route matches never reaches the driver, and nothing
//! the kernel does or fails to do has a part in it. The driver replaces the table at the moment it makes a new
//! generation the one that serves (the routes come with the switch message), so the table and the generation that
//! inspects change together. A switch that fails leaves the table as it is.

use std::mem;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TryRecvError, sync_channel};
use std::thread;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::{OwnedSemaphorePermit, oneshot};
use tukuyomi_kernel::{
    Failure, Phase, Refused, ReqId, Request, Shutdown, Status, Supervisor, Verdict,
};

use crate::inspect::slot::{Retired, Retirement, Slot};
use crate::log::{Log, escaped};
use crate::rules::bundle::{self, Fingerprint};
use crate::rules::routes::{Routes, SharedRoutes};

/// The shortest slice of one kernel step. A shorter one would end a step before it could read anything.
const MIN_SLICE: Duration = Duration::from_millis(1);

/// One request for inspection, as a connection hands it over. The protocol version is always HTTP/1.1.
pub struct InspectReq {
    pub client: SocketAddr,
    pub server: SocketAddr,
    pub method: Bytes,
    pub uri: Bytes,
    pub headers: Vec<(Bytes, Bytes)>,
    pub body: Arc<BodyHold>,
}

/// The decoded body, shared by the connection and the ticket. Its share of the byte budget returns when the last
/// holder drops it.
pub struct BodyHold {
    pub bytes: Bytes,
    _budget: OwnedSemaphorePermit,
}

impl BodyHold {
    pub fn new(bytes: Bytes, budget: OwnedSemaphorePermit) -> BodyHold {
        BodyHold {
            bytes,
            _budget: budget,
        }
    }
}

/// What a ticket holds until the driver consumes its result or drops it before submitting: an inspection permit
/// and the byte budget of the kernel's copy.
pub struct Hold {
    _inspect: OwnedSemaphorePermit,
    _copy: OwnedSemaphorePermit,
}

impl Hold {
    pub fn new(inspect: OwnedSemaphorePermit, copy: OwnedSemaphorePermit) -> Hold {
        Hold {
            _inspect: inspect,
            _copy: copy,
        }
    }
}

pub struct Ticket {
    pub req: InspectReq,
    pub reply: oneshot::Sender<Outcome>,
    pub hold: Hold,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Verdict(Verdict),
    Refused(Refused),
    Unavailable,
}

pub enum Msg {
    Ticket(Ticket),
    /// Serve another generation from now on.
    Switch(Switch),
    Stop {
        inspect_by: Instant,
    },
}

/// The order to switch to another generation.
pub struct Switch {
    pub generation: Fingerprint,
    /// What the rules of the generation do to a request they match.
    pub mode: bundle::Mode,
    /// The requests of the generation that skip the inspection. They are the shared table from the moment the
    /// generation serves.
    pub routes: Routes,
    pub kernel: tukuyomi_kernel::Config,
    /// How the switch ended. It is given once, when the kernel that was stopped is gone.
    pub reply: oneshot::Sender<Switched>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Switched {
    /// The new generation serves.
    Yes,
    /// The generation that served goes on.
    No,
}

#[derive(Debug)]
pub enum End {
    Done {
        /// The end of the kernel that served last.
        kernel: tukuyomi_kernel::Shutdown,
        /// Every kernel that was stopped before it stopped with its process gone and its directory removed.
        retired_clean: bool,
    },
    Fatal(&'static str),
}

/// The main thread's side of the driver.
pub struct Driver {
    pub ingress: SyncSender<Msg>,
    pub ready: oneshot::Receiver<Result<(), Failure>>,
    pub failed: oneshot::Receiver<Failure>,
    pub end: oneshot::Receiver<End>,
}

/// The times of the proxy that the driver keeps.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// The length of one step of the kernel that serves.
    pub slice: Duration,
    /// The longest a new generation has to be ready.
    pub ready_wait: Duration,
    /// The longest a kernel that is replaced finishes its requests, and the deadline of the `shutdown` of a kernel
    /// that is stopped while the proxy goes on.
    pub stop_inspect: Duration,
}

/// Starts the driver thread and returns at once, without waiting for the kernel to be ready. `Err` means only
/// that the thread could not be created. The kernel is created on the thread; a configuration it refuses ends
/// the driver with `End::Fatal`. `generation` names the rules that `cfg` is for, `mode` is what they do to a
/// request they match, and `routes` is the shared table of the requests that skip the inspection, which holds the
/// routes of `generation` already and which the driver replaces when another generation serves.
pub fn start(
    cfg: tukuyomi_kernel::Config,
    generation: Fingerprint,
    mode: bundle::Mode,
    routes: SharedRoutes,
    limits: Limits,
    log: Log,
) -> Result<Driver, &'static str> {
    let tick = cfg.tick;
    // One intake takes at most every waiting ticket and the stop message. The channel has room for one more, a
    // switch (the main thread has one under way at a time). A count that cannot be added to cannot pass the
    // kernel's configuration check either, so any capacity will do for it.
    let take = cfg.wait_queue.checked_add(1).unwrap_or(1);
    let (ingress, rx) = sync_channel(take.saturating_add(1));
    let (ready_tx, ready) = oneshot::channel();
    let (failed_tx, failed) = oneshot::channel();
    let (end_tx, end) = oneshot::channel();
    thread::Builder::new()
        .name("driver".into())
        .spawn(move || match Supervisor::new(cfg) {
            Ok(kernel) => {
                let signals = Signals::Waiting {
                    ready: ready_tx,
                    failed: failed_tx,
                };
                let slot = Slot::new(generation, mode, kernel);
                Core::new(slot, routes, rx, signals, log, limits, tick, take).drive(end_tx);
            }
            Err(refused) => {
                let _ = end_tx.send(End::Fatal(refused.0));
            }
        })
        .map_err(|_| "cannot start the driver thread")?;
    Ok(Driver {
        ingress,
        ready,
        failed,
        end,
    })
}

/// The part of the supervisor that the driver uses. The driver runs on `Supervisor`; its tests run it on a
/// stand-in that records the calls. A kernel that is stopped goes to a thread of its own.
pub(super) trait Kernel: Send + 'static {
    /// A kernel for `cfg`. Nothing is started yet.
    fn create(cfg: tukuyomi_kernel::Config) -> Result<Self, &'static str>
    where
        Self: Sized;
    fn submit(&mut self, req: &Request<'_>) -> Result<ReqId, Refused>;
    fn cancel(&mut self, id: ReqId);
    fn poll(&mut self, until: Instant) -> Vec<(ReqId, Verdict)>;
    fn status(&self) -> Status;
    fn start_detail(&self) -> Option<Vec<u8>>;
    fn shutdown(&mut self, deadline: Instant) -> Shutdown;
}

impl Kernel for Supervisor {
    fn create(cfg: tukuyomi_kernel::Config) -> Result<Supervisor, &'static str> {
        Supervisor::new(cfg).map_err(|e| e.0)
    }

    fn submit(&mut self, req: &Request<'_>) -> Result<ReqId, Refused> {
        Supervisor::submit(self, req)
    }

    fn cancel(&mut self, id: ReqId) {
        Supervisor::cancel(self, id);
    }

    fn poll(&mut self, until: Instant) -> Vec<(ReqId, Verdict)> {
        Supervisor::poll(self, until)
    }

    fn status(&self) -> Status {
        Supervisor::status(self)
    }

    fn start_detail(&self) -> Option<Vec<u8>> {
        Supervisor::start_detail(self)
    }

    fn shutdown(&mut self, deadline: Instant) -> Shutdown {
        Supervisor::shutdown(self, deadline)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Run,
    /// A stop was asked for: the tickets of existing connections are still served until `shutdown` is due.
    Stopping {
        inspect_by: Instant,
    },
    /// `shutdown` was called: no ticket is submitted any more.
    Down,
}

/// What the main thread was told about the kernel. Each answer is given once.
enum Signals {
    /// Nothing was said yet.
    Waiting {
        ready: oneshot::Sender<Result<(), Failure>>,
        failed: oneshot::Sender<Failure>,
    },
    /// Ready was said; a failure is still to be said on `failed`.
    Running { failed: oneshot::Sender<Failure> },
    /// Everything that can be said was said. A sender that is left is kept, so that the main thread never sees
    /// `failed` close without an answer while the driver runs.
    Told {
        _failed: Option<oneshot::Sender<Failure>>,
    },
}

impl Signals {
    /// Takes in the phase the kernel is in after a step.
    fn note(&mut self, phase: Phase) {
        let before = mem::replace(self, Signals::Told { _failed: None });
        *self = match (before, phase) {
            (Signals::Waiting { ready, failed }, Phase::Ready) => {
                let _ = ready.send(Ok(()));
                Signals::Running { failed }
            }
            (Signals::Waiting { ready, failed }, Phase::Failed(why)) => {
                let _ = ready.send(Err(why));
                Signals::Told {
                    _failed: Some(failed),
                }
            }
            (Signals::Running { failed }, Phase::Failed(why)) => {
                let _ = failed.send(why);
                Signals::Told { _failed: None }
            }
            (other, _) => other,
        };
    }
}

/// Whether `shutdown` is due: nothing can arrive any more and nothing waits for a result, or the stop deadline
/// is reached.
fn shutdown_due(closed: bool, nothing_pending: bool, inspect_by: Instant, now: Instant) -> bool {
    (closed && nothing_pending) || now >= inspect_by
}

/// The record line for the start of a stop: what the kernel still holds. Fixed text and numbers only.
fn stop_line(status: &Status) -> String {
    format!(
        "driver: stop, records {}, held {}, waiting {}",
        status.records, status.held, status.waiting
    )
}

/// `t + d`; a sum that does not fit is `t`: due at once.
fn after(t: Instant, d: Duration) -> Instant {
    t.checked_add(d).unwrap_or(t)
}

/// What a switch of generation is doing. There is one at a time.
enum Switching<K> {
    Idle,
    /// The new kernel starts. New tickets still go to the kernel that serves.
    Starting {
        next: Slot<K>,
        ready_by: Instant,
        /// The routes of `next`: they become the shared table when it serves.
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

/// Everything the driver thread owns.
struct Core<K> {
    rx: Receiver<Msg>,
    /// The kernel that new tickets go to.
    active: Slot<K>,
    /// The routes of the generation of `active`, which the connections read.
    routes: SharedRoutes,
    switching: Switching<K>,
    /// Where to tell the main thread how the switch ended.
    reply: Option<oneshot::Sender<Switched>>,
    mode: Mode,
    /// Every sender is gone: nothing can arrive any more.
    closed: bool,
    signals: Signals,
    log: Log,
    /// The longest wait for a message while there is nothing to do.
    tick: Duration,
    /// The times of the proxy; the slice is cut to the tick, and is at least `MIN_SLICE`.
    limits: Limits,
    /// The most messages one intake takes: one more than the waiting queue holds.
    take: usize,
    /// Every kernel that was stopped so far stopped cleanly.
    retired_clean: bool,
}

impl<K: Kernel> Core<K> {
    // One argument for each part of the state of the driver; a struct of them would only repeat the fields of `Core`.
    #[allow(clippy::too_many_arguments)]
    fn new(
        active: Slot<K>,
        routes: SharedRoutes,
        rx: Receiver<Msg>,
        signals: Signals,
        log: Log,
        limits: Limits,
        tick: Duration,
        take: usize,
    ) -> Core<K> {
        Core {
            rx,
            active,
            routes,
            switching: Switching::Idle,
            reply: None,
            mode: Mode::Run,
            closed: false,
            signals,
            log,
            tick,
            limits: Limits {
                slice: limits.slice.min(tick).max(MIN_SLICE),
                ..limits
            },
            take: take.max(1),
            retired_clean: true,
        }
    }

    /// Runs to the end and tells the main thread how it ended. The kernel and the table go when this returns, so
    /// the end is told first.
    fn drive(mut self, end: oneshot::Sender<End>) {
        let ended = self.run();
        let _ = end.send(ended);
    }

    fn run(&mut self) -> End {
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
                retired_clean: self.retired_clean,
            },
            Err(why) => End::Fatal(why),
        }
    }

    /// One round. `Some` is the end of `shutdown`, which was called in this round. `Err` is a fault that stops
    /// the driver.
    fn round(&mut self) -> Result<Option<Shutdown>, &'static str> {
        self.intake(None)?;
        self.scan();
        self.wait()?;
        let now = Instant::now();
        let until = after(now, self.limits.slice);
        self.active.step(until)?;
        self.step_other()?;
        self.signals.note(self.active.status().phase);
        if let Some(line) = self.active.note_incarnation() {
            self.log.line(&line);
        }
        if let Some(line) = self.active.note_turned() {
            self.log.line(&line);
        }
        self.advance()?;
        self.finish_if_due()
    }

    /// Takes in at most `take` messages, `first` (one that was waited for) included.
    fn intake(&mut self, first: Option<Msg>) -> Result<(), &'static str> {
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
                self.begin_switch(switch);
                Ok(())
            }
            Msg::Stop { inspect_by } => {
                self.stop(inspect_by);
                Ok(())
            }
        }
    }

    /// After `shutdown` nothing is submitted.
    fn admit(&mut self, ticket: Ticket) -> Result<(), &'static str> {
        if self.mode == Mode::Down {
            let _ = ticket.reply.send(Outcome::Unavailable);
            return Ok(());
        }
        self.active.admit(ticket)
    }

    /// Makes the kernel of the new generation, when a switch can begin: the proxy runs and no other switch is
    /// under way. The main thread sends one switch at a time, so the second condition is a guard.
    fn begin_switch(&mut self, switch: Switch) {
        let Switch {
            generation,
            mode,
            routes,
            kernel,
            reply,
        } = switch;
        if self.mode != Mode::Run || !matches!(self.switching, Switching::Idle) {
            let _ = reply.send(Switched::No);
            return;
        }
        match K::create(kernel) {
            Ok(kernel) => {
                self.switching = Switching::Starting {
                    next: Slot::new(generation, mode, kernel),
                    ready_by: after(Instant::now(), self.limits.ready_wait),
                    routes,
                };
                self.reply = Some(reply);
            }
            Err(why) => {
                self.log.line(&format!(
                    "reload: generation {} failed to start: {why}",
                    generation.hex()
                ));
                let _ = reply.send(Switched::No);
            }
        }
    }

    /// The first stop message records one line and sets the deadline; a later one can only bring it forward. A
    /// kernel that is starting holds no request: it is stopped at once.
    fn stop(&mut self, inspect_by: Instant) {
        self.mode = match self.mode {
            Mode::Run => {
                self.log.line(&stop_line(&self.active.status()));
                match mem::replace(&mut self.switching, Switching::Idle) {
                    Switching::Starting { next, .. } => self.retire(next, inspect_by, Switched::No),
                    other => self.switching = other,
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

    /// The kernel that does not get new tickets: the new one while it starts, the old one while it finishes.
    fn other(&mut self) -> Option<&mut Slot<K>> {
        match &mut self.switching {
            Switching::Starting { next, .. } => Some(next),
            Switching::Draining { old, .. } => Some(old),
            Switching::Idle | Switching::Retiring { .. } => None,
        }
    }

    /// Calls `cancel` for the tickets whose connection went away, in both kernels.
    fn scan(&mut self) {
        self.active.scan();
        if let Some(other) = self.other() {
            other.scan();
        }
    }

    /// Steps the kernel that does not get new tickets, for the shortest step that can read a frame. A step whose
    /// end has passed writes but reads nothing (`Supervisor::poll`), and this kernel has a frame to read: the
    /// HELLO of a new inspector, the verdicts of an old one.
    fn step_other(&mut self) -> Result<(), &'static str> {
        let until = after(Instant::now(), MIN_SLICE);
        let lines = match self.other() {
            Some(other) => {
                other.step(until)?;
                [other.note_incarnation(), other.note_turned()]
            }
            None => [None, None],
        };
        for line in lines.into_iter().flatten() {
            self.log.line(&line);
        }
        Ok(())
    }

    /// Whether the kernel that serves is ready and holds no record, and nothing else is going on: nothing is in
    /// flight and nothing is to be closed.
    fn idle(&self) -> bool {
        if self.mode != Mode::Run
            || !matches!(self.switching, Switching::Idle)
            || !self.active.pending.is_empty()
        {
            return false;
        }
        let status = self.active.status();
        status.records == 0 && status.phase == Phase::Ready
    }

    /// Whether no request waits for a result, in the kernel that serves and in the one that finishes.
    fn nothing_pending(&self) -> bool {
        let old = match &self.switching {
            Switching::Draining { old, .. } => old.pending.is_empty(),
            _ => true,
        };
        self.active.pending.is_empty() && old
    }

    /// Waits for a message, but only when idle. Anything else must go on stepping the kernel.
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

    /// Moves the switch on by what the round found out.
    fn advance(&mut self) -> Result<(), &'static str> {
        let now = Instant::now();
        match mem::replace(&mut self.switching, Switching::Idle) {
            Switching::Idle => {}
            Switching::Starting {
                next,
                ready_by,
                routes,
            } => self.advance_starting(next, ready_by, routes, now),
            Switching::Draining { old, drain_by } => {
                if old.pending.is_empty() || now >= drain_by {
                    // A kernel that still holds requests is out of time: it is stopped at once, and `shutdown`
                    // decides them. One that holds nothing is given the time to end by itself.
                    let by = if old.pending.is_empty() {
                        after(now, self.limits.stop_inspect)
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
                Some(retired) => self.retired(&retired, switched),
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
    /// shared table, stopped if it failed or is late, and then the table stays as it is.
    fn advance_starting(&mut self, next: Slot<K>, ready_by: Instant, routes: Routes, now: Instant) {
        let serving_failed = matches!(self.active.status().phase, Phase::Failed(_));
        match next.status().phase {
            // The kernel that serves failed in this round: the proxy stops, and does not hurry to the new one.
            Phase::Ready if !serving_failed => {
                self.log.line(&format!(
                    "reload: generation {} is ready, switched",
                    next.generation.hex()
                ));
                let old = mem::replace(&mut self.active, next);
                self.routes.replace(routes);
                self.switching = Switching::Draining {
                    old,
                    drain_by: after(now, self.limits.stop_inspect),
                };
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
                self.failed_to_start(&next, &format!("{why:?}"));
                self.retire(next, after(now, self.limits.stop_inspect), Switched::No);
            }
            _ if now >= ready_by => {
                self.failed_to_start(&next, "not ready in time");
                self.retire(next, after(now, self.limits.stop_inspect), Switched::No);
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
    fn failed_to_start(&self, slot: &Slot<K>, kind: &str) {
        self.log.line(&format!(
            "reload: generation {} failed to start: {kind}",
            slot.generation.hex()
        ));
        if let Some(detail) = slot.kernel.start_detail() {
            let line = detail.strip_suffix(b"\n").unwrap_or(&detail);
            self.log.line(&format!(
                "reload: the inspector said: \"{}\"",
                escaped(line)
            ));
        }
    }

    /// Gives the slot to a thread that stops it.
    fn retire(&mut self, slot: Slot<K>, deadline: Instant, switched: Switched) {
        self.switching = Switching::Retiring {
            retirement: slot.retire(deadline),
            switched,
        };
    }

    /// A retirement is over: one record line, and the main thread is told how the switch ended.
    fn retired(&mut self, retired: &Retired, switched: Switched) {
        self.log.line(&format!(
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
    fn collect(&mut self) -> Result<(), &'static str> {
        if let Switching::Retiring {
            retirement,
            switched,
        } = mem::replace(&mut self.switching, Switching::Idle)
        {
            let retired = retirement.wait()?;
            self.retired(&retired, switched);
        }
        Ok(())
    }

    /// Calls `shutdown` when it is due and delivers its results. The old kernel of a switch goes on its own
    /// thread, at the same time. Every request is decided by then, so a ticket that is left in a table breaks the
    /// promise that every result comes out once.
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
        match mem::replace(&mut self.switching, Switching::Idle) {
            Switching::Draining { old, .. } => self.retire(old, inspect_by, Switched::Yes),
            other => self.switching = other,
        }
        let done = self.active.shutdown(inspect_by)?;
        self.mode = Mode::Down;
        self.collect()?;
        Ok(Some(done))
    }

    /// After `shutdown`: answers every ticket with `Outcome::Unavailable` until the last sender is gone. The
    /// kernel is not stepped any more.
    fn quiesce(&mut self) -> Result<(), &'static str> {
        while !self.closed {
            match self.rx.recv() {
                Ok(msg) => self.intake(Some(msg))?,
                Err(_) => self.close(),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
