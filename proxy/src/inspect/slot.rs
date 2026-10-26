//! One generation's share of the driver: the kernel of the generation, the requests that were submitted to it and
//! its retirement.
//!
//! The driver serves at most two slots. Every slot has a table of its own for the requests it holds: the kernels
//! number their requests on their own, so the ids of two slots can be equal, and a result is looked up only in the
//! table of the slot whose kernel gave it.
//!
//! A slot also knows the mode of its generation, and a result is checked against it before it is delivered: a
//! generation that blocks has no request that is only detected, so a `Detected` from its kernel cannot be what the
//! rules said. The inspector is a separate process that is not trusted, so such a result is delivered as
//! `Uninspectable` and never as a request that may go on.
//!
//! A slot that is retired gives its kernel to a thread of its own, which calls `shutdown`: `shutdown` waits for the
//! inspector to end, and the requests of the slot that stays must not wait for that. The table stays with the
//! driver, and when the thread reports, the results of `shutdown` are delivered to it like any other.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::sync::mpsc::{Receiver, SendError, Sender, TryRecvError, channel};
use std::thread;
use std::time::Instant;

use tukuyomi_kernel::{Reason, Refused, ReqId, Request, Shutdown, Status, Verdict};

use crate::inspect::driver::{Answer, InspectReq, Judge, Kernel, Outcome, Ticket};
use crate::rules::bundle::{Fingerprint, Mode};

/// A submitted ticket that waits for its result.
pub(super) struct Pending {
    pub(super) ticket: Ticket,
    /// `cancel` was called for it: its result is taken and not sent.
    pub(super) cancelled: bool,
}

/// The record line for a new incarnation of the inspector, or `None` while it is the one seen last. The kernel
/// numbers the next incarnation when the one before it has ended, so the number can change before the next
/// process has started, or with none to follow; the line says only that the number changed and how many
/// restarts the kernel has made in all. The first incarnation is the number the kernel starts with and gets no
/// line. Fixed text and numbers only.
pub(super) fn restart_line(seen: u32, status: &Status) -> Option<String> {
    (status.inc != seen).then(|| {
        format!(
            "driver: inspector incarnation changed, inc {}, restarts {}",
            status.inc, status.restarts
        )
    })
}

/// The record line for the first `Detected` that a kernel gave for a generation that blocks, which is delivered
/// as not inspectable. Fixed text and the name of the generation only.
fn turned_line(generation: Fingerprint) -> String {
    format!(
        "driver: generation {} blocks, and its inspector sent a detection, which is not accepted",
        generation.hex()
    )
}

/// Takes the result of every `(id, verdict)` out of the table: sends it to the connection unless `cancel` was
/// called, and drops the ticket, which gives its permits back. A `Detected` for a generation that blocks is sent
/// as `Uninspectable(Protocol)`: the request is not let through. The answer is true if there was one, for the
/// record line of a slot that serves; a slot that is stopped makes none. A result for a request that is not in
/// the table breaks the promise that every result comes out once.
pub(super) fn deliver(
    pending: &mut BTreeMap<ReqId, Pending>,
    results: &[(ReqId, Verdict)],
    judge: Judge,
) -> Result<bool, &'static str> {
    let mut turned = false;
    for &(id, verdict) in results {
        let Some(Pending { ticket, cancelled }) = pending.remove(&id) else {
            return Err("result for an unknown request");
        };
        let verdict = match verdict {
            Verdict::Detected { .. } if judge.mode == Mode::Block => {
                turned = true;
                Verdict::Uninspectable(Reason::Protocol)
            }
            other => other,
        };
        // The request and the hold live to the end of this turn, after the send.
        let Ticket {
            req: _req,
            reply,
            hold: _hold,
        } = ticket;
        if !cancelled {
            // Err only says that the connection is gone already.
            let _ = reply.send(Answer {
                outcome: Outcome::Verdict(verdict),
                by: Some(judge),
            });
        }
    }
    Ok(turned)
}

/// Hands the request of a ticket to the kernel. The bytes are the ones the connection will forward.
pub(super) fn submit(kernel: &mut impl Kernel, req: &InspectReq) -> Result<ReqId, Refused> {
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
        proto: req.proto,
        headers: &headers,
        body: &req.body.bytes,
        body_cut: req.cut,
    })
}

/// The kernel of one generation and the requests it holds.
pub(super) struct Slot<K> {
    pub(super) generation: Fingerprint,
    /// What the rules of the generation do to a request they match.
    pub(super) mode: Mode,
    pub(super) kernel: K,
    pub(super) pending: BTreeMap<ReqId, Pending>,
    /// The incarnation number of the inspector that the last round saw.
    inc: u32,
    /// A `Detected` was delivered as not inspectable, and the record line for it is not yet taken.
    turned: bool,
    /// The record line for it was taken: a slot makes it once.
    told: bool,
}

impl<K: Kernel> Slot<K> {
    pub(super) fn new(generation: Fingerprint, mode: Mode, kernel: K) -> Slot<K> {
        let inc = kernel.status().inc;
        Slot {
            generation,
            mode,
            kernel,
            pending: BTreeMap::new(),
            inc,
            turned: false,
            told: false,
        }
    }

    /// Submits the request of the ticket and keeps the ticket until the result comes out. A ticket that is closed
    /// (its connection is gone) is dropped without a submit; one that the kernel refuses is answered at once.
    pub(super) fn admit(&mut self, ticket: Ticket) -> Result<(), &'static str> {
        if ticket.reply.is_closed() {
            return Ok(());
        }
        match submit(&mut self.kernel, &ticket.req) {
            Ok(id) => match self.pending.entry(id) {
                Entry::Occupied(_) => Err("duplicate request id"),
                Entry::Vacant(entry) => {
                    entry.insert(Pending {
                        ticket,
                        cancelled: false,
                    });
                    Ok(())
                }
            },
            Err(refused) => {
                let _ = ticket.reply.send(Outcome::Refused(refused).into());
                Ok(())
            }
        }
    }

    /// Calls `cancel` once for every submitted ticket whose connection went away. The mark is kept in the table,
    /// not in a message, so a full channel cannot lose it.
    pub(super) fn scan(&mut self) {
        for (&id, entry) in &mut self.pending {
            if !entry.cancelled && entry.ticket.reply.is_closed() {
                self.kernel.cancel(id);
                entry.cancelled = true;
            }
        }
    }

    /// Steps the kernel until a result is ready or `until`, and delivers the results.
    pub(super) fn step(&mut self, until: Instant) -> Result<(), &'static str> {
        let results = self.kernel.poll(until);
        let judge = self.judge();
        self.turned |= deliver(&mut self.pending, &results, judge)?;
        Ok(())
    }

    /// The generation of the slot and the mode of its rules, as a verdict of its kernel names them.
    fn judge(&self) -> Judge {
        Judge {
            generation: self.generation,
            mode: self.mode,
        }
    }

    pub(super) fn status(&self) -> Status {
        self.kernel.status()
    }

    /// The record line for the incarnation of the inspector, when it is not the one seen last, and takes it in.
    /// It is called with the status after a step and before `shutdown`, so the exit that `shutdown` confirms
    /// gives no line.
    pub(super) fn note_incarnation(&mut self) -> Option<String> {
        let status = self.kernel.status();
        let line = restart_line(self.inc, &status)?;
        self.inc = status.inc;
        Some(line)
    }

    /// The record line for a `Detected` that was delivered as not inspectable, the first time and not again. It
    /// is called after a step, like `note_incarnation`.
    pub(super) fn note_turned(&mut self) -> Option<String> {
        if !self.turned || self.told {
            return None;
        }
        self.told = true;
        Some(turned_line(self.generation))
    }

    /// Calls `shutdown` here and delivers its results. Every request is decided by then, so a ticket that is
    /// left in the table breaks the promise that every result comes out once.
    pub(super) fn shutdown(&mut self, deadline: Instant) -> Result<Shutdown, &'static str> {
        let done = self.kernel.shutdown(deadline);
        let judge = self.judge();
        deliver(&mut self.pending, &done.results, judge)?;
        if !self.pending.is_empty() {
            return Err("request left after shutdown");
        }
        Ok(done)
    }

    /// Gives the kernel to a thread of its own, which calls `shutdown`. What the slot still owes goes with the
    /// returned `Retirement`. A thread that cannot be made leaves the stop to this thread: the inspector has to be
    /// stopped in any case.
    pub(super) fn retire(self, deadline: Instant) -> Retirement {
        let Slot {
            generation,
            mode,
            kernel,
            pending,
            ..
        } = self;
        let (report, reported) = channel();
        let (give, take) = channel();
        let thread_report = report.clone();
        let spawned = thread::Builder::new().name("retire".into()).spawn(move || {
            if let Ok(kernel) = take.recv() {
                stop(kernel, deadline, &thread_report);
            }
        });
        let left = match spawned {
            Ok(_) => give.send(kernel).err().map(|SendError(kernel)| kernel),
            Err(_) => Some(kernel),
        };
        if let Some(kernel) = left {
            stop(kernel, deadline, &report);
        }
        Retirement {
            generation,
            mode,
            pending,
            reported,
        }
    }
}

/// Stops the kernel and reports. The kernel is dropped before the report, so what its drop does is done when the
/// retirement is told to be over.
fn stop<K: Kernel>(mut kernel: K, deadline: Instant, report: &Sender<Shutdown>) {
    let done = kernel.shutdown(deadline);
    drop(kernel);
    let _ = report.send(done);
}

/// A slot whose kernel is being stopped on another thread.
pub(super) struct Retirement {
    generation: Fingerprint,
    mode: Mode,
    pending: BTreeMap<ReqId, Pending>,
    reported: Receiver<Shutdown>,
}

/// How a retirement ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Retired {
    pub(super) generation: Fingerprint,
    /// The process of the inspector is gone and its directory is removed.
    pub(super) clean: bool,
}

impl Retirement {
    /// The end of the retirement if the thread reported, and `None` while it goes on.
    pub(super) fn poll(&mut self) -> Result<Option<Retired>, &'static str> {
        match self.reported.try_recv() {
            Ok(done) => self.end(Some(done)).map(Some),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => self.end(None).map(Some),
        }
    }

    /// Waits for the report.
    pub(super) fn wait(mut self) -> Result<Retired, &'static str> {
        let done = self.reported.recv().ok();
        self.end(done)
    }

    /// `done` is `None` when the thread ended without a report: nothing is known of the inspector then, and the
    /// tickets are dropped, which the connections see as a reply slot that closed.
    fn end(&mut self, done: Option<Shutdown>) -> Result<Retired, &'static str> {
        let Some(done) = done else {
            self.pending.clear();
            return Ok(Retired {
                generation: self.generation,
                clean: false,
            });
        };
        let judge = Judge {
            generation: self.generation,
            mode: self.mode,
        };
        deliver(&mut self.pending, &done.results, judge)?;
        if !self.pending.is_empty() {
            return Err("request left after shutdown");
        }
        Ok(Retired {
            generation: self.generation,
            clean: done.exit_confirmed && done.dir_removed,
        })
    }
}

#[cfg(test)]
mod tests;
