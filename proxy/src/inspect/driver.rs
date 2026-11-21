//! The inspection driver: the owner of the kernel's `Supervisor`s, on its own thread.
//!
//! A connection hands a `Ticket` over one bounded channel and waits on the reply slot of the ticket. The ticket names
//! the engine that is to inspect the request. The driver submits the ticket to the kernel of that engine, keeps it
//! until the kernel's result for it comes out, and then answers on the reply slot. Besides the channels, the driver
//! shares with the connections the gate of each engine (`Gates`): the table of the routes (`SharedRoutes`) and the
//! inspection permits, the table of which the connections read and the driver replaces.
//!
//! What a ticket holds (the inspection permit, the byte budget of the kernel's copy, its share of the body) goes
//! back only when the result of its request has been taken, or when the ticket is dropped before it was
//! submitted. A connection that gave up does not give it back: the kernel keeps the record until its result
//! comes out.
//!
//! The answer on the reply slot is the outcome and, when the outcome is a verdict of a kernel, the generation of that
//! kernel, the engine and the mode of its rules, the verdict as it is delivered and the rules that matched the
//! request as the verdict says them, so that the record of the request can say which rules judged it and what they
//! matched, and the counters can tell why a request could not be inspected.
//!
//! Each slot keeps the mode of its generation. A generation that blocks never has a request that is only detected,
//! so a `Detected` that its kernel gives is not believed: the ticket is answered with `Uninspectable`, and the
//! first time it happens in a slot the driver records one line.
//!
//! After every round the driver publishes the `State` of the kernel that serves each engine (its phase, the restarts
//! of the inspector made so far, and the generation with the engine and the mode of its rules) on a `watch` that the
//! main side reads when it is asked whether the inspectors are up; nothing waits for it.
//!
//! The routes of the generations that serve are not kept by the slots. A connection matches its request against the
//! table of the engine of its upstream group before it makes a ticket, so a request that a route matches never reaches
//! the driver, and nothing the kernel does or fails to do has a part in it. The driver replaces the table of an
//! engine at the moment it makes a new generation of that engine the one that serves (the routes come with the switch
//! message), so the table and the generation that inspects change together. A switch that fails leaves the table as it
//! is.

use std::mem;
use std::net::SocketAddr;
use std::sync::mpsc::{SyncSender, sync_channel};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::{OwnedSemaphorePermit, mpsc, oneshot, watch};
use tukuyomi_kernel::{
    Engine, Failure, Matched, Phase, Refused, ReqId, Request, Shutdown, Status, Supervisor, Verdict,
};

use self::core::Core;
use crate::inspect::engines::{Gates, Lane, Publisher, States, Told, index};
use crate::inspect::slot::Slot;
use crate::log::Log;
use crate::rules::bundle::{self, Fingerprint};
use crate::rules::routes::Routes;
use crate::rules::store::ENGINES;

mod core;

/// One request for inspection, as a connection hands it over.
pub struct InspectReq {
    pub client: SocketAddr,
    pub server: SocketAddr,
    pub method: Bytes,
    pub uri: Bytes,
    pub headers: Vec<(Bytes, Bytes)>,
    pub body: Arc<BodyHold>,
    /// The body goes on after the bytes in `body`, which are only inspected.
    pub cut: bool,
    /// The protocol of the request: `HTTP/1.0` or `HTTP/1.1`.
    pub proto: &'static [u8],
}

/// The decoded body, or its first bytes if it is cut, shared by the connection and the ticket. Its share of the byte budget returns when the last
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
    /// The engine that is to inspect the request: the one of the upstream group it goes to.
    pub engine: Engine,
    pub req: InspectReq,
    pub reply: oneshot::Sender<Answer>,
    pub hold: Hold,
}

/// The generation whose kernel gave a verdict, the engine of its rules, what they do to a request they match, the
/// verdict as it is delivered and the rules that matched the request, as the verdict says them (none for a verdict
/// that is not an inspection). The verdict is the one of the outcome in the same answer, so a `Detected` of a
/// generation that blocks is `Uninspectable` here too. It is kept here because the connection keeps the `Judge` and
/// not the outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Judge {
    pub generation: Fingerprint,
    pub engine: Engine,
    pub mode: bundle::Mode,
    pub verdict: Verdict,
    pub matched: Matched,
}

/// What the driver answers for a ticket: the outcome, and the generation that gave it if it is a verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Answer {
    pub outcome: Outcome,
    pub by: Option<Judge>,
}

/// An outcome that no kernel gave a verdict for.
impl From<Outcome> for Answer {
    fn from(outcome: Outcome) -> Answer {
        Answer { outcome, by: None }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Verdict(Verdict),
    Refused(Refused),
    Unavailable,
}

pub enum Msg {
    Ticket(Ticket),
    /// Serve another generation of an engine from now on, or start the engine.
    Switch(Switch),
    Stop {
        inspect_by: Instant,
    },
}

/// The order to switch to another generation of the engine `kernel.engine`, which is started if it is not running.
pub struct Switch {
    pub generation: Fingerprint,
    /// What the rules of the generation do to a request they match.
    pub mode: bundle::Mode,
    /// The requests of the generation that skip the inspection. They are the table of the gate of its engine from
    /// the moment the generation serves.
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

/// The way from the connections to the driver. A connection takes a sender when a request starts and drops it as
/// soon as the ticket is sent (or when the request needs none), so a connection that waits for its next request
/// holds none, and the driver sees the last sender go when the last request that was under way is done. The main
/// thread closes the handle when the stop begins: a request that starts after that gets no sender, and the
/// connections that wait for a request are told. The accept side tells them too (`drain`) when a connection has
/// to wait for a permit, so that the permits of connections that do nothing come back.
pub struct Ingress {
    sender: Mutex<Option<SyncSender<Msg>>>,
    closed: watch::Sender<bool>,
    /// Counts the calls of `drain`.
    drained: watch::Sender<u64>,
}

impl Ingress {
    pub fn new(sender: SyncSender<Msg>) -> Ingress {
        Ingress {
            sender: Mutex::new(Some(sender)),
            closed: watch::channel(false).0,
            drained: watch::channel(0).0,
        }
    }

    /// A sender for one request; `None` once the handle is closed.
    pub fn sender(&self) -> Option<SyncSender<Msg>> {
        self.sender
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Closes the handle: no request gets a sender any more, and the receivers of `watch` see `true`. Closing it
    /// again does nothing more.
    pub fn close(&self) {
        drop(
            self.sender
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take(),
        );
        self.closed.send_replace(true);
    }

    /// The handle is closed.
    pub fn is_closed(&self) -> bool {
        *self.closed.borrow()
    }

    /// A receiver that is told when the handle is closed. One that is made after the close sees no change; it
    /// asks `is_closed` first.
    pub fn watch(&self) -> watch::Receiver<bool> {
        self.closed.subscribe()
    }

    /// Tells the connections that wait for a request to close. A connection that is serving a request is not
    /// touched: each connection looks at its own state when it is told.
    pub fn drain(&self) {
        self.drained
            .send_modify(|calls| *calls = calls.wrapping_add(1));
    }

    /// A receiver that sees a change at every `drain` after it was made.
    pub fn drained(&self) -> watch::Receiver<u64> {
        self.drained.subscribe()
    }

    /// How many times `drain` was called.
    pub fn drains(&self) -> u64 {
        *self.drained.borrow()
    }
}

/// What the driver tells the main side of the kernel that serves an engine: its phase, the restarts of the inspector
/// made so far (counting the kernels that served before it, so the number does not fall when another generation takes
/// over), and the generation with the engine and the mode of its rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct State {
    pub phase: Phase,
    pub restarts: u32,
    pub generation: Fingerprint,
    pub engine: Engine,
    pub mode: bundle::Mode,
}

/// The main thread's side of the driver.
pub struct Driver {
    pub ingress: SyncSender<Msg>,
    /// Every kernel that was started at the start is ready, or the failure of the first that failed before it was.
    pub ready: oneshot::Receiver<Result<(), Failure>>,
    /// A kernel that served failed; the receiver closes only when the driver is gone.
    pub failed: mpsc::Receiver<Failure>,
    pub end: oneshot::Receiver<End>,
    pub state: watch::Receiver<States>,
}

/// The times of the proxy that the driver keeps.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// The length of one step of a kernel that serves.
    pub slice: Duration,
    /// The longest a new generation has to be ready.
    pub ready_wait: Duration,
    /// The longest a kernel that is replaced finishes its requests, and the deadline of the `shutdown` of a kernel
    /// that is stopped while the proxy goes on.
    pub stop_inspect: Duration,
}

/// A kernel that the driver starts with: the generation, what its rules do, its routes and its kernel configuration
/// (`kernel.engine` is the engine of the rules).
pub struct Start {
    pub generation: Fingerprint,
    pub mode: bundle::Mode,
    pub routes: Routes,
    pub kernel: tukuyomi_kernel::Config,
}

/// How many messages one intake of the driver takes, and the room of the channel of the connections, for kernels whose
/// waiting queue holds `wait_queue`. An intake takes at most every waiting ticket of every engine and the stop message.
/// The channel has room for one more, a switch (the main thread has one under way at a time, of any engine). So the
/// channel has room for every message that can be waiting, by construction: the tickets are held back by the permits
/// of their engine, as many as the waiting queue. A count that cannot be added to cannot pass the kernel's
/// configuration check either, so any capacity will do for it.
pub(super) fn intake_sizes(wait_queue: usize) -> (usize, usize) {
    let take = wait_queue
        .checked_mul(ENGINES.len())
        .and_then(|n| n.checked_add(1))
        .unwrap_or(1);
    (take, take.saturating_add(1))
}

/// Starts the driver thread and returns at once, without waiting for the kernels to be ready. `Err` means only that
/// the thread could not be created, or that there is nothing to start, or two kernels are for one engine. The kernels
/// are created on the thread; a configuration one of them refuses ends the driver with `End::Fatal`. Each of `starts`
/// is the kernel of one engine that serves from the start, and its routes are put in the table of the gate of the
/// engine, which `gates` holds and the driver replaces when another generation of the engine serves. The channel of
/// the connections has room for the waiting queue of every engine, the stop message and one switch.
pub fn start(
    starts: Vec<Start>,
    gates: Gates,
    limits: Limits,
    log: Log,
) -> Result<Driver, &'static str> {
    let Some(first) = starts.first() else {
        return Err("no engine to start");
    };
    let tick = first.kernel.tick;
    let (take, room) = intake_sizes(first.kernel.wait_queue);
    let mut seen = [false; ENGINES.len()];
    for start in &starts {
        let place = &mut seen[index(start.kernel.engine)];
        if mem::replace(place, true) {
            return Err("two kernels for one engine");
        }
        gates
            .of(start.kernel.engine)
            .routes
            .replace(start.routes.clone());
    }
    let (ingress, rx) = sync_channel(room);
    let (ready_tx, ready) = oneshot::channel();
    let (failed_tx, failed) = mpsc::channel(ENGINES.len());
    let (end_tx, end) = oneshot::channel();
    let mut states = States::none();
    for start in &starts {
        states.set(
            start.kernel.engine,
            Some(State {
                phase: Phase::Starting,
                restarts: 0,
                generation: start.generation,
                engine: start.kernel.engine,
                mode: start.mode,
            }),
        );
    }
    let (state_tx, state) = watch::channel(states);
    thread::Builder::new()
        .name("driver".into())
        .spawn(move || {
            let waiting = starts.len();
            let mut kernels = Vec::with_capacity(waiting);
            for start in starts {
                let engine = start.kernel.engine;
                match Supervisor::new(start.kernel) {
                    Ok(kernel) => kernels.push((engine, start.generation, start.mode, kernel)),
                    Err(refused) => {
                        let _ = end_tx.send(End::Fatal(refused.0));
                        return;
                    }
                }
            }
            let mut lanes = Vec::with_capacity(ENGINES.len());
            for engine in ENGINES {
                let slot = kernels
                    .iter()
                    .position(|(kernel_engine, ..)| *kernel_engine == engine)
                    .map(|at| kernels.remove(at))
                    .map(|(_, generation, mode, kernel)| {
                        Slot::new(generation, engine, mode, kernel)
                    });
                lanes.push(Lane::new(engine, gates.of(engine).routes.clone(), slot));
            }
            let told = Told::new(ready_tx, waiting, failed_tx);
            Core::new(
                lanes,
                rx,
                told,
                log,
                limits,
                tick,
                take,
                Publisher::new(state_tx),
            )
            .drive(end_tx);
        })
        .map_err(|_| "cannot start the driver thread")?;
    Ok(Driver {
        ingress,
        ready,
        failed,
        end,
        state,
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
    fn poll(&mut self, until: Instant) -> Vec<(ReqId, Verdict, Matched)>;
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

    fn poll(&mut self, until: Instant) -> Vec<(ReqId, Verdict, Matched)> {
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

#[cfg(test)]
mod tests;
