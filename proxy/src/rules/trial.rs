//! The trial of a staged bundle: one inspector is started on it and three fixed requests are inspected.
//!
//! The trial shows that the bundle starts and that requests of a normal shape are inspected and let through. It does
//! not show that the rules are right. The three requests have a `Host` (a name, not an address), a `User-Agent` and an
//! `Accept`, and the two with a body a `Content-Type` and a `Content-Length`, so that the default rules of the CRS
//! (paranoia level 1) give them no score: `GET /`, `POST /` with the urlencoded body `a=b`, and `POST /` with the JSON
//! body `{"a":"b"}`. The trial passes when the inspector is ready within `ready_wait` and each request gets `Allow`
//! within `inspect_wait`. A `Block` fails it too, unless the operator accepts blocks; then the rule is reported and
//! the trial goes on. A `Detected` (a rule matched while the rules only detect) is not a failure when the bundle only
//! detects: it is reported and the trial goes on. From a bundle that blocks, a `Detected` cannot be what its rules
//! said, so it fails the trial as a request that cannot be inspected. A request that cannot be inspected fails the
//! trial, and so does a start that ends in a failure.
//!
//! The trial runs on the part of the kernel that it needs (`TrialKernel`), which the supervisor is and which a test
//! replaces. The supervisor of a trial never restarts the inspector (`restarts` 0): the first end of a start is the
//! end of the trial. `shutdown` is always called before the kernel is dropped.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use tukuyomi_kernel::{
    Config, Failure, Phase, Reason, Refused, ReqId, Request, Shutdown, Status, Supervisor, Verdict,
};

use crate::rules::bundle::Mode;

/// The addresses and the protocol of the requests. They are documentation addresses (RFC 5737).
const CLIENT: &[u8] = b"192.0.2.10";
const CLIENT_PORT: u16 = 49152;
const SERVER: &[u8] = b"192.0.2.1";
const SERVER_PORT: u16 = 80;
const PROTO: &[u8] = b"HTTP/1.1";

/// The part of the supervisor that a trial uses. The trial runs on `Supervisor`; its tests run it on a stand-in.
pub trait TrialKernel {
    fn submit(&mut self, req: &Request<'_>) -> Result<ReqId, Refused>;
    fn cancel(&mut self, id: ReqId);
    fn poll(&mut self, until: Instant) -> Vec<(ReqId, Verdict)>;
    fn status(&self) -> Status;
    fn shutdown(&mut self, deadline: Instant) -> Shutdown;
    fn start_detail(&self) -> Option<Vec<u8>>;
}

impl TrialKernel for Supervisor {
    fn submit(&mut self, req: &Request<'_>) -> Result<ReqId, Refused> {
        Supervisor::submit(self, req)
    }

    fn cancel(&mut self, id: ReqId) {
        Supervisor::cancel(self, id);
    }

    fn poll(&mut self, until: Instant) -> Vec<(ReqId, Verdict)> {
        Supervisor::poll(self, until)
            .into_iter()
            .map(|(id, verdict, _)| (id, verdict))
            .collect()
    }

    fn status(&self) -> Status {
        Supervisor::status(self)
    }

    fn shutdown(&mut self, deadline: Instant) -> Shutdown {
        Supervisor::shutdown(self, deadline)
    }

    fn start_detail(&self) -> Option<Vec<u8>> {
        Supervisor::start_detail(self)
    }
}

/// How long a trial waits, and what it accepts.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// The most time for the inspector to be ready.
    pub ready_wait: Duration,
    /// The most time for the verdict of one request.
    pub inspect_wait: Duration,
    /// The deadline given to `shutdown` at the end.
    pub stop_inspect: Duration,
    /// The length of one step of the kernel.
    pub slice: Duration,
    /// A `Block` is not a failure.
    pub accept_block: bool,
    /// What the rules of the bundle do to a request they match. A `Detected` is accepted only for `Detect`.
    pub mode: Mode,
}

/// A request of the trial.
struct Probe {
    name: &'static str,
    method: &'static [u8],
    /// The content type and the body, if there is a body.
    body: Option<(&'static [u8], &'static [u8])>,
}

const PROBES: [Probe; 3] = [
    Probe {
        name: "GET /",
        method: b"GET",
        body: None,
    },
    Probe {
        name: "POST / with a urlencoded body",
        method: b"POST",
        body: Some((b"application/x-www-form-urlencoded", b"a=b")),
    },
    Probe {
        name: "POST / with a JSON body",
        method: b"POST",
        body: Some((b"application/json", br#"{"a":"b"}"#)),
    },
];

/// Why a trial failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failed {
    /// SIGINT or SIGTERM.
    Interrupted,
    /// The kernel failed before the inspector was ready.
    Start(Failure),
    /// The inspector was not ready in time.
    NotReady,
    Refused {
        probe: &'static str,
        refused: Refused,
    },
    /// No verdict in time.
    NoVerdict {
        probe: &'static str,
    },
    Blocked {
        probe: &'static str,
        phase: u8,
        rule_id: i64,
        status: u16,
    },
    Uninspectable {
        probe: &'static str,
        reason: Reason,
    },
    /// Every request was as wanted, but the kernel did not end as stopped.
    NotStopped,
}

/// A request that did not fail the trial and is reported: a `Block` that was accepted, or a `Detected`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Accepted {
    Block {
        probe: &'static str,
        phase: u8,
        rule_id: i64,
        status: u16,
    },
    Detected {
        probe: &'static str,
        rule_id: i64,
        status: u16,
    },
}

/// The end of a trial.
#[derive(Debug)]
pub struct Finish {
    /// The accepted blocks and the detections of a trial that passed, or why it failed.
    pub result: Result<Vec<Accepted>, Failed>,
    /// What the inspector left in `start-failure`, if it refused to start. The bytes are the inspector's own.
    pub detail: Option<Vec<u8>>,
    /// The process is gone and its directory is removed: nothing is left behind. A trial passes only if so.
    pub clean: bool,
}

impl Finish {
    pub fn passed(&self) -> bool {
        self.result.is_ok() && self.clean
    }
}

/// Runs the trial on the kernel, whatever happens ends with `shutdown`. The kernel is checked at every step for
/// `interrupt`, which a signal handler sets.
pub fn run(kernel: &mut impl TrialKernel, limits: &Limits, interrupt: &AtomicBool) -> Finish {
    let result = judge(kernel, limits, interrupt);
    let now = Instant::now();
    let done = kernel.shutdown(now.checked_add(limits.stop_inspect).unwrap_or(now));
    let result = match result {
        Ok(_) if done.phase != Phase::Stopped => Err(Failed::NotStopped),
        other => other,
    };
    Finish {
        result,
        detail: kernel.start_detail(),
        clean: done.exit_confirmed && done.dir_removed,
    }
}

/// The trial on a supervisor whose configuration is the one of the proxy except `restarts`, which is 0. The caller
/// has called `host::check`, which the supervisor requires.
pub fn run_supervised(
    mut kernel: Config,
    limits: &Limits,
    interrupt: &AtomicBool,
) -> Result<Finish, &'static str> {
    kernel.restarts = 0;
    let mut supervisor = Supervisor::new(kernel).map_err(|e| e.0)?;
    Ok(run(&mut supervisor, limits, interrupt))
}

fn judge(
    kernel: &mut impl TrialKernel,
    limits: &Limits,
    interrupt: &AtomicBool,
) -> Result<Vec<Accepted>, Failed> {
    ready(kernel, limits, interrupt)?;
    let mut accepted = Vec::new();
    for probe in &PROBES {
        match inspect(kernel, limits, interrupt, probe)? {
            Verdict::Allow => {}
            Verdict::Detected { rule_id, status } if limits.mode == Mode::Detect => {
                accepted.push(Accepted::Detected {
                    probe: probe.name,
                    rule_id,
                    status,
                });
            }
            // A bundle that blocks has no request that is only detected: the inspector is not believed.
            Verdict::Detected { .. } => {
                return Err(Failed::Uninspectable {
                    probe: probe.name,
                    reason: Reason::Protocol,
                });
            }
            Verdict::Block {
                phase,
                rule_id,
                status,
            } => {
                if !limits.accept_block {
                    return Err(Failed::Blocked {
                        probe: probe.name,
                        phase,
                        rule_id,
                        status,
                    });
                }
                accepted.push(Accepted::Block {
                    probe: probe.name,
                    phase,
                    rule_id,
                    status,
                });
            }
            Verdict::Uninspectable(reason) => {
                return Err(Failed::Uninspectable {
                    probe: probe.name,
                    reason,
                });
            }
        }
    }
    Ok(accepted)
}

/// `at + d`, or `at` itself when the sum does not fit in an `Instant` (a deadline that has passed).
fn after(at: Instant, d: Duration) -> Instant {
    at.checked_add(d).unwrap_or(at)
}

/// Steps the kernel until it is ready.
fn ready(
    kernel: &mut impl TrialKernel,
    limits: &Limits,
    interrupt: &AtomicBool,
) -> Result<(), Failed> {
    let deadline = after(Instant::now(), limits.ready_wait);
    loop {
        if interrupt.load(Ordering::SeqCst) {
            return Err(Failed::Interrupted);
        }
        match kernel.status().phase {
            Phase::Ready => return Ok(()),
            Phase::Failed(why) => return Err(Failed::Start(why)),
            Phase::Starting => {}
            Phase::Stopping | Phase::Stopped => return Err(Failed::NotReady),
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(Failed::NotReady);
        }
        // No request is waiting, so nothing comes out; the step is what moves the start on.
        kernel.poll(after(now, limits.slice).min(deadline));
    }
}

/// Submits one request and steps the kernel until its verdict.
fn inspect(
    kernel: &mut impl TrialKernel,
    limits: &Limits,
    interrupt: &AtomicBool,
    probe: &Probe,
) -> Result<Verdict, Failed> {
    let length = probe.body.map(|(_, body)| body.len().to_string());
    let mut headers: Vec<(&[u8], &[u8])> = vec![
        (b"Host", b"example.test"),
        (b"User-Agent", b"Mozilla/5.0 (X11; Linux x86_64)"),
        (b"Accept", b"*/*"),
    ];
    if let (Some((kind, _)), Some(length)) = (probe.body, &length) {
        headers.push((b"Content-Type", kind));
        headers.push((b"Content-Length", length.as_bytes()));
    }
    let id = kernel
        .submit(&Request {
            client_addr: CLIENT,
            client_port: CLIENT_PORT,
            server_addr: SERVER,
            server_port: SERVER_PORT,
            method: probe.method,
            uri: b"/",
            proto: PROTO,
            headers: &headers,
            body: probe.body.map_or(&[][..], |(_, body)| body),
            body_cut: false,
        })
        .map_err(|refused| Failed::Refused {
            probe: probe.name,
            refused,
        })?;
    let deadline = after(Instant::now(), limits.inspect_wait);
    loop {
        if interrupt.load(Ordering::SeqCst) {
            kernel.cancel(id);
            return Err(Failed::Interrupted);
        }
        let now = Instant::now();
        if now >= deadline {
            kernel.cancel(id);
            return Err(Failed::NoVerdict { probe: probe.name });
        }
        let results = kernel.poll(after(now, limits.slice).min(deadline));
        if let Some((_, verdict)) = results.into_iter().find(|&(got, _)| got == id) {
            return Ok(verdict);
        }
    }
}

#[cfg(test)]
mod tests;
