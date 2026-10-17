//! The inspection driver: the only owner of the kernel's `Supervisor`, on its own thread.
//!
//! A connection hands a `Ticket` over one bounded channel and waits on the reply slot of the ticket. The driver
//! submits the ticket to the kernel, keeps it until the kernel's result for it comes out, and then answers on the
//! reply slot. Nothing is shared with the connections besides the channels: no lock, no shared state.
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

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
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

use crate::log::Log;

/// The protocol of every request that is inspected.
const PROTO: &[u8] = b"HTTP/1.1";

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
    Stop { inspect_by: Instant },
}

#[derive(Debug)]
pub enum End {
    Done(tukuyomi_kernel::Shutdown),
    Fatal(&'static str),
}

/// The main thread's side of the driver.
pub struct Driver {
    pub ingress: SyncSender<Msg>,
    pub ready: oneshot::Receiver<Result<(), Failure>>,
    pub failed: oneshot::Receiver<Failure>,
    pub end: oneshot::Receiver<End>,
}

/// Starts the driver thread and returns at once, without waiting for the kernel to be ready. `Err` means only
/// that the thread could not be created. The kernel is created on the thread; a configuration it refuses ends
/// the driver with `End::Fatal`.
pub fn start(
    cfg: tukuyomi_kernel::Config,
    slice: Duration,
    log: Log,
) -> Result<Driver, &'static str> {
    let tick = cfg.tick;
    // Room for every waiting ticket and for the stop message. A count that cannot be added to cannot pass the
    // kernel's configuration check either, so any capacity will do for it.
    let take = cfg.wait_queue.checked_add(1).unwrap_or(1);
    let (ingress, rx) = sync_channel(take);
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
                Core::new(kernel, rx, signals, log, tick, slice, take).drive(end_tx);
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
/// stand-in that records the calls.
trait Kernel {
    fn submit(&mut self, req: &Request<'_>) -> Result<ReqId, Refused>;
    fn cancel(&mut self, id: ReqId);
    fn poll(&mut self, until: Instant) -> Vec<(ReqId, Verdict)>;
    fn status(&self) -> Status;
    fn shutdown(&mut self, deadline: Instant) -> Shutdown;
}

impl Kernel for Supervisor {
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

    fn shutdown(&mut self, deadline: Instant) -> Shutdown {
        Supervisor::shutdown(self, deadline)
    }
}

/// A submitted ticket that waits for its result.
struct Pending {
    ticket: Ticket,
    /// `cancel` was called for it: its result is taken and not sent.
    cancelled: bool,
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

/// The record line for a new incarnation of the inspector, or `None` while it is the one seen last. The kernel
/// numbers the next incarnation when the one before it has ended, so the number can change before the next
/// process has started, or with none to follow; the line says only that the number changed and how many
/// restarts the kernel has made in all. The first incarnation is the number the kernel starts with and gets no
/// line. Fixed text and numbers only.
fn restart_line(seen: u32, status: &Status) -> Option<String> {
    (status.inc != seen).then(|| {
        format!(
            "driver: inspector incarnation changed, inc {}, restarts {}",
            status.inc, status.restarts
        )
    })
}

/// Takes the result of every `(id, verdict)` out of the table: sends it to the connection unless `cancel` was
/// called, and drops the ticket, which gives its permits back. A result for a request that is not in the table
/// breaks the promise that every result comes out once.
fn deliver(
    pending: &mut BTreeMap<ReqId, Pending>,
    results: &[(ReqId, Verdict)],
) -> Result<(), &'static str> {
    for &(id, verdict) in results {
        let Some(Pending { ticket, cancelled }) = pending.remove(&id) else {
            return Err("result for an unknown request");
        };
        // The request and the hold live to the end of this turn, after the send.
        let Ticket {
            req: _req,
            reply,
            hold: _hold,
        } = ticket;
        if !cancelled {
            // Err only says that the connection is gone already.
            let _ = reply.send(Outcome::Verdict(verdict));
        }
    }
    Ok(())
}

/// Hands the request of a ticket to the kernel. The bytes are the ones the connection will forward.
fn submit(kernel: &mut impl Kernel, req: &InspectReq) -> Result<ReqId, Refused> {
    let client = req.client.ip().to_canonical().to_string();
    let server = req.server.ip().to_canonical().to_string();
    let headers: Vec<(&[u8], &[u8])> = req
        .headers
        .iter()
        .map(|(name, value)| (&name[..], &value[..]))
        .collect();
    kernel.submit(&Request {
        client_addr: client.as_bytes(),
        client_port: req.client.port(),
        server_addr: server.as_bytes(),
        server_port: req.server.port(),
        method: &req.method,
        uri: &req.uri,
        proto: PROTO,
        headers: &headers,
        body: &req.body.bytes,
    })
}

/// Everything the driver thread owns.
struct Core<K> {
    kernel: K,
    rx: Receiver<Msg>,
    pending: BTreeMap<ReqId, Pending>,
    mode: Mode,
    /// Every sender is gone: nothing can arrive any more.
    closed: bool,
    signals: Signals,
    log: Log,
    /// The incarnation number of the inspector that the last round saw.
    inc: u32,
    /// The longest wait for a message while there is nothing to do.
    tick: Duration,
    /// The length of one kernel step.
    slice: Duration,
    /// The most messages one intake takes: one more than the waiting queue holds.
    take: usize,
}

impl<K: Kernel> Core<K> {
    fn new(
        kernel: K,
        rx: Receiver<Msg>,
        signals: Signals,
        log: Log,
        tick: Duration,
        slice: Duration,
        take: usize,
    ) -> Core<K> {
        let inc = kernel.status().inc;
        Core {
            kernel,
            rx,
            pending: BTreeMap::new(),
            mode: Mode::Run,
            closed: false,
            signals,
            log,
            inc,
            tick,
            slice: slice.min(tick).max(MIN_SLICE),
            take: take.max(1),
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
            Ok(()) => End::Done(done),
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
        // A sum that does not fit is due at once; the slice is cut to the kernel's tick, so that does not happen.
        let until = now.checked_add(self.slice).unwrap_or(now);
        let results = self.kernel.poll(until);
        deliver(&mut self.pending, &results)?;
        let status = self.kernel.status();
        self.signals.note(status.phase);
        self.note_incarnation(&status);
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
            Msg::Stop { inspect_by } => {
                self.stop(inspect_by);
                Ok(())
            }
        }
    }

    /// A ticket that is closed (its connection is gone) is dropped without a submit. After `shutdown`
    /// nothing is submitted.
    fn admit(&mut self, ticket: Ticket) -> Result<(), &'static str> {
        if self.mode == Mode::Down {
            let _ = ticket.reply.send(Outcome::Unavailable);
            return Ok(());
        }
        if ticket.reply.is_closed() {
            return Ok(());
        }
        match submit(&mut self.kernel, &ticket.req) {
            Ok(id) => match self.pending.entry(id) {
                Entry::Occupied(_) => Err("duplicate request id"),
                Entry::Vacant(slot) => {
                    slot.insert(Pending {
                        ticket,
                        cancelled: false,
                    });
                    Ok(())
                }
            },
            Err(refused) => {
                let _ = ticket.reply.send(Outcome::Refused(refused));
                Ok(())
            }
        }
    }

    /// The first stop message records one line and sets the deadline; a later one can only bring it forward.
    fn stop(&mut self, inspect_by: Instant) {
        self.mode = match self.mode {
            Mode::Run => {
                self.log.line(&stop_line(&self.kernel.status()));
                Mode::Stopping { inspect_by }
            }
            Mode::Stopping { inspect_by: first } => Mode::Stopping {
                inspect_by: first.min(inspect_by),
            },
            Mode::Down => Mode::Down,
        };
    }

    /// Records one line when the incarnation of the inspector is not the one seen last, and takes it in. It is
    /// called with the status after a step and before `shutdown`, so the exit that `shutdown` confirms gives no
    /// line.
    fn note_incarnation(&mut self, status: &Status) {
        if let Some(line) = restart_line(self.inc, status) {
            self.log.line(&line);
            self.inc = status.inc;
        }
    }

    /// The last sender is gone. Without a stop message that is a stop whose deadline has passed: nothing can
    /// arrive any more, and whatever is in flight is decided at once.
    fn close(&mut self) {
        self.closed = true;
        if self.mode == Mode::Run {
            self.stop(Instant::now());
        }
    }

    /// Calls `cancel` once for every submitted ticket whose connection went away. The mark is kept in the table,
    /// not in a message, so a full channel cannot lose it.
    fn scan(&mut self) {
        for (&id, entry) in &mut self.pending {
            if !entry.cancelled && entry.ticket.reply.is_closed() {
                self.kernel.cancel(id);
                entry.cancelled = true;
            }
        }
    }

    /// Whether nothing is in flight and nothing is to be closed: the kernel is ready and holds no record.
    fn idle(&self) -> bool {
        if self.mode != Mode::Run || !self.pending.is_empty() {
            return false;
        }
        let status = self.kernel.status();
        status.records == 0 && status.phase == Phase::Ready
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

    /// Calls `shutdown` when it is due and delivers its results. Every request is decided by then, so a ticket
    /// that is left in the table breaks the promise that every result comes out once.
    fn finish_if_due(&mut self) -> Result<Option<Shutdown>, &'static str> {
        let Mode::Stopping { inspect_by } = self.mode else {
            return Ok(None);
        };
        let nothing_pending = self.pending.is_empty();
        if !shutdown_due(self.closed, nothing_pending, inspect_by, Instant::now()) {
            return Ok(None);
        }
        let done = self.kernel.shutdown(inspect_by);
        self.mode = Mode::Down;
        deliver(&mut self.pending, &done.results)?;
        if !self.pending.is_empty() {
            return Err("request left after shutdown");
        }
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
