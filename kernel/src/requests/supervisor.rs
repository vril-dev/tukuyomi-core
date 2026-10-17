//! The single owner of the engine, of the current start and of the times of the restarts.
//!
//! One thread drives everything. `poll` and `shutdown` repeat `step`: the engine's clock and halt are looked at
//! first, then at most one frame is written (the engine's frames, and DRAIN through the same writer), then at most
//! one frame is read. There is no reader thread.
//!
//! Deadlines are absolute `Instant`s and are never extended: the HELLO wait counts from just before the spawn,
//! the wait of a request from its `submit` (also across a restart), the wait for BYE from DRAIN. A sum that does
//! not fit in an `Instant` is a deadline that has passed. Once `shutdown` was called, every wait a step creates
//! (a send, a read, the wait for the exit) is cut at its deadline.
//!
//! Restarts are counted in a sliding window (`Config::restarts` within `Config::restart_window`). When the window
//! is full the next start waits, without a process and without failing, until the oldest restart is a whole window
//! old; the requests meanwhile wait for their own deadlines. With `restarts` 0 nothing is restarted: the first
//! start that ends, unless `shutdown` ended it, fails the supervisor.
//!
//! Trusted connection generation: the run number and the incarnation of the `Start` that owns the stream. A frame
//! with another run or incarnation is a fault of the whole connection and never reaches the engine; the old
//! stream is gone before the next start exists.
//!
//! Ownership: whatever an unknown reap or an unknown clean-up still owns stays in `Run::Failed` (`Leftover`) and
//! is retried by a later `shutdown`; nothing is started after it. A request whose TX_BEGIN the writer has taken is
//! never sent again: only the requests whose TX_BEGIN was not taken, and the waiting ones, go to the next start
//! (state.rs).
#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::io::ErrorKind;
use std::mem;
use std::ops::ControlFlow::{self, Break, Continue};
use std::thread;
use std::time::{Duration, Instant};

use crate::config::{Config, ConfigError};
use crate::process::child::{self, Exit};
use crate::process::start::{self, LaunchError, Start, StartDir, Step, Stopped, Stopping};
use crate::protocol::codec::{self, ConnError, Header, HelloExpect};
use crate::protocol::io;
use crate::requests::state::{self, Decision, Engine, Halt, Limits, OutKind, SubmitError, Why};

/// The wait between two tries to reap a child when the supervisor is dropped.
const POLL: Duration = Duration::from_millis(5);

/// A request number: from 0, one at a time, never used again by the same `Supervisor`.
pub type ReqId = u64;

/// One request to inspect. Allow is a verdict on these bytes only; the host forwards these bytes and nothing
/// else, except the changes its own contract lists (removed hop-by-hop fields, added forwarding fields, the framing
/// it writes).
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    pub client_addr: &'a [u8],
    pub client_port: u16,
    pub server_addr: &'a [u8],
    pub server_port: u16,
    pub method: &'a [u8],
    pub uri: &'a [u8],
    pub proto: &'a [u8],
    pub headers: &'a [(&'a [u8], &'a [u8])],
    /// The whole decoded body (no transfer coding).
    pub body: &'a [u8],
}

/// The answer for one request. `Allow` is a verdict on the bytes that were given to `submit`, inspected by the
/// rules and the fixed trailing directives in the phases 1 and 2, and on nothing else: whatever was not inspected,
/// or inspected in part, is `Uninspectable`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Block {
        phase: u8,
        rule_id: i64,
        /// The value the inspector sent, as it is. The host checks it as an HTTP status.
        status: u16,
    },
    Uninspectable(Reason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    Invalid,
    QueueFull,
    Unavailable,
    WaitDeadline,
    VerdictDeadline,
    InspectorLost,
    Protocol,
    InspectorError { code: u16 },
    NotCreated { code: u16 },
    Cancelled,
}

/// Refused at `submit`: no record is made, nothing is sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    Invalid(&'static str),
    Unsupported(&'static str),
    Full,
    IdsExhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    TmpDir(&'static str),
    Hello(&'static str),
    Exit(i32),
    /// A start ended or could not be made, and `restarts` is 0: no restart is allowed.
    BudgetExhausted,
    ReapUnknown,
    CleanupUnknown,
    Exhausted,
    Internal(&'static str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Starting,
    Ready,
    Stopping,
    Stopped,
    Failed(Failure),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub phase: Phase,
    pub inc: u32,
    /// The restarts made in all (saturating): the first start is not counted, a try to start that failed is. Not
    /// the number within the window, and not one that is still waiting for the window.
    pub restarts: u32,
    pub waiting: usize,
    pub held: usize,
    pub records: usize,
}

/// The state at the end of one `shutdown` call.
#[derive(Debug)]
pub struct Shutdown {
    /// Every result not delivered before, each once.
    pub results: Vec<(ReqId, Verdict)>,
    /// Stopped or Failed(..); a Failed reason stays after a later retry.
    pub phase: Phase,
    /// This call received the BYE that answered its DRAIN.
    pub bye: bool,
    /// No started process is left unreaped (true when none existed).
    pub exit_confirmed: bool,
    /// No per-start directory or unidentified entry is left (true when none existed).
    pub dir_removed: bool,
    /// `engine.held_slots()` at the end (0 unless an exit is unknown).
    pub held_left: usize,
    /// `engine.waiting()` at the end (always 0: halt decides them).
    pub waiting_left: usize,
}

enum Run {
    /// No process; the next step launches.
    Down,
    /// `until` = `start.started` + `hello_wait` (no extension).
    Hello {
        start: Start,
        until: Instant,
    },
    Ready {
        start: Start,
    },
    /// Shutdown only: DRAIN is written, the whole BYE is due by `until`.
    Draining {
        start: Start,
        until: Instant,
    },
    Stopping {
        stop: Stopping,
        end: End,
    },
    Stopped,
    Failed {
        why: Failure,
        left: Option<Leftover>,
    },
}

/// What an unknown reap or clean-up still owns. Kept in `Run::Failed` (never dropped by `shutdown`) for a later
/// retry.
enum Leftover {
    Running(Stopping),
    Dir(StartDir),
    Unidentified,
}

/// How a start ends.
enum End {
    /// BYE came after DRAIN: the inspector ends by itself.
    Bye,
    Restart(
        #[cfg_attr(
            not(test),
            expect(dead_code, reason = "the reason is read by the unit tests")
        )]
        &'static str,
    ),
    Fail(Failure),
}

/// What follows a stop whose exit was seen.
#[derive(Debug, PartialEq, Eq)]
enum Next {
    Restart,
    Stopped,
    Fail(Failure),
}

/// What the restart window says to a restart that is wanted.
#[derive(Debug, PartialEq, Eq)]
enum Slot {
    /// There is room: the time was recorded and the start may go ahead.
    Now,
    /// The window is full: no start before this time.
    Wait(Instant),
}

/// The three ways a stop can end, for `apply_stop`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StopTag {
    Done,
    DirLeft,
    Unreaped,
}

/// Starts, feeds and stops one inspector process, and owns what that takes: the engine, the current start and
/// the times of the restarts.
///
/// What the caller must hold to: one thread uses it; it moves only while `poll` or `shutdown` runs, so a deadline
/// that passes between two calls is found, as expired and never as a permission, by the next call; call
/// `shutdown` before the value is dropped (`Drop` is a separate bounded best effort, and the results the engine
/// still holds are lost); the host process holds no file descriptor that is not close-on-exec, does not run
/// with `SIGCHLD` ignored (`SIG_IGN`, whether it set that itself or inherited it from its parent across `execve`)
/// or with `SA_NOCLDWAIT` set (Linux then reaps children by itself, the exit of the inspector can no longer be
/// confirmed and the supervisor stops as failed), and does not reap the child of this supervisor by a signal handler,
/// `wait`, `waitpid`, `waitid` (a wait for any child, such as `waitpid(-1)`, can reap it) or any other mechanism
/// of its own; waiting by pid for its own unrelated children is fine.
///
/// What the caller can rely on, and what it cannot: `poll(until)` with an `until` that has already passed writes
/// at most one frame but reads none (the wait for the first byte is over before it begins), so a caller must not
/// repeat only `poll` calls whose `until` is not after the current time: nothing is read from the inspector that way;
/// `cancel` does not change a result that is already decided and not yet delivered (`Allow` included), which comes
/// out once as it is; `shutdown` returns every result not delivered before in its `Shutdown.results`;
/// `Phase::Stopping` does not tell a stop for a restart from the stop of a `shutdown`; the stage of a request from
/// the continue of phase 1 until the writer takes BODY_END has no verdict deadline (`verdict_wait` counts from the
/// take of TX_BEGIN and from the take of BODY_END, and every frame write is cut at `frame_io`, but the stage as a
/// whole has no deadline), so the host keeps the limit for the whole stage and calls `cancel` when it has passed.
pub struct Supervisor {
    cfg: Config,
    engine: Engine,
    /// The run number, chosen once before the first start.
    run_id: Option<u64>,
    run: Run,
    /// Restarts made in all (what `Status` reports); the first start is not counted, a failed retry is.
    restarts: u32,
    /// The times of the restarts that can still be inside the window, oldest first: at most `cfg.restarts`.
    restart_times: VecDeque<Instant>,
    /// Set while the window is full: `Down` starts nothing before this time.
    not_before: Option<Instant>,
    /// `None` until the first `shutdown`; then that call's deadline.
    shutdown_by: Option<Instant>,
}

/// `t + d` (a sum that overflows is `t`: due at once), cut at `cap` when it is `Some`.
fn bounded(t: Instant, d: Duration, cap: Option<Instant>) -> Instant {
    let x = t.checked_add(d).unwrap_or(t);
    cap.map_or(x, |c| x.min(c))
}

/// The restart window for a restart wanted at `now`. A record that is a whole `window` old is dropped (a sum that
/// does not fit in an `Instant` has passed, as in `bounded`). With fewer than `limit` records left, `now` is
/// recorded and the restart may go ahead. Otherwise it must wait until the oldest record is a whole `window` old;
/// that time is after `now`, because a record that is that old has been dropped. `times` is oldest first because
/// `now` never goes back. With a `limit` of 0 nothing is ever recorded and the wait is a whole window from `now`,
/// again and again: `next` never asks for a restart then.
fn restart_slot(times: &mut VecDeque<Instant>, now: Instant, limit: u32, window: Duration) -> Slot {
    while times
        .front()
        .is_some_and(|&t| bounded(t, window, None) <= now)
    {
        times.pop_front();
    }
    if u32::try_from(times.len()).is_ok_and(|n| n < limit) {
        times.push_back(now);
        return Slot::Now;
    }
    Slot::Wait(bounded(times.front().copied().unwrap_or(now), window, None))
}

fn wire_kind(k: OutKind) -> u8 {
    match k {
        OutKind::TxBegin => codec::KIND_TX_BEGIN,
        OutKind::Body => codec::KIND_BODY,
        OutKind::BodyEnd => codec::KIND_BODY_END,
        OutKind::TxEnd(_) => codec::KIND_TX_END,
    }
}

/// The engine's decision as the answer of the public API: every row of both enums, none dropped by a wildcard.
fn verdict_of(d: Decision) -> Verdict {
    match d {
        Decision::Forward => Verdict::Allow,
        Decision::Block {
            phase,
            rule_id,
            status,
        } => Verdict::Block {
            phase,
            rule_id,
            status,
        },
        Decision::ClientDisconnect => Verdict::Uninspectable(Reason::Cancelled),
        Decision::Uninspectable(why) => Verdict::Uninspectable(match why {
            Why::Invalid => Reason::Invalid,
            Why::QueueFull => Reason::QueueFull,
            Why::Halted(_) => Reason::Unavailable,
            Why::WaitDeadline => Reason::WaitDeadline,
            Why::VerdictDeadline => Reason::VerdictDeadline,
            Why::ConnFault => Reason::InspectorLost,
            Why::Order => Reason::Protocol,
            Why::TxError { code } => Reason::InspectorError { code },
            Why::NotCreated { code } => Reason::NotCreated { code },
        }),
    }
}

/// The engine's part of a stop: `Done` confirms the exit; `DirLeft` confirms it too but the directory is not
/// removed; `Unreaped` confirms nothing, the slots stay held. Where a failure is returned the supervisor does not
/// go on (no `next`), and the waiting requests are decided: nothing starts again.
fn apply_stop(engine: &mut Engine, now: Instant, inc: u32, tag: StopTag) -> Option<Failure> {
    match tag {
        StopTag::Done => {
            engine.exit_confirmed(now, inc);
            None
        }
        StopTag::DirLeft => {
            engine.exit_confirmed(now, inc);
            engine.halt(now, Halt::NoRestart);
            Some(Failure::CleanupUnknown)
        }
        StopTag::Unreaped => {
            engine.halt(now, Halt::NoRestart);
            Some(Failure::ReapUnknown)
        }
    }
}

/// What follows a stop whose exit was seen (rows in order, the first that applies; `exit` is `None` when no process
/// was started). `_used`, the restarts made in all, decides nothing: only `budget == 0` ends the supervisor, and a
/// full restart window makes the next start wait.
fn next(end: End, exit: Option<Exit>, halted: Option<Halt>, _used: u32, budget: u32) -> Next {
    // A status with a code (not killed by a signal) of 10, 11 or 14 is a deterministic refusal of the inspector.
    if let Some(code @ (10 | 11 | 14)) = exit.and_then(|x| x.status.code()) {
        return Next::Fail(Failure::Exit(code));
    }
    if let End::Fail(f) = end {
        return Next::Fail(f);
    }
    if matches!(end, End::Bye) && exit.is_some_and(|x| !x.killed && x.status.code() == Some(0)) {
        return Next::Stopped;
    }
    match halted {
        Some(Halt::Drain) => return Next::Stopped,
        Some(Halt::TxExhausted | Halt::IncExhausted | Halt::MsgOverflow) => {
            return Next::Fail(Failure::Exhausted);
        }
        Some(Halt::NoRestart) | None => {}
    }
    if budget == 0 {
        return Next::Fail(Failure::BudgetExhausted);
    }
    Next::Restart
}

/// Whether `essence` (a Content-Type before its first `;`, without the blanks around it) is
/// `application/<name>+json`, ASCII case ignored. The name is 1 to 122 characters: the first an ASCII letter or
/// digit, the rest ASCII letters, digits, `.` or `-`. A name that starts with `x-www-form-urlencoded` does not
/// count: Coraza selects its urlencoded processor for every value with that prefix, so such a body would not be
/// parsed as JSON.
fn is_json_suffix_type(essence: &[u8]) -> bool {
    const HEAD: &[u8] = b"application/";
    const TAIL: &[u8] = b"+json";
    const URLENCODED: &[u8] = b"x-www-form-urlencoded";
    const MAX_NAME: usize = 122;
    let end = essence.len().saturating_sub(TAIL.len());
    let (Some(head), Some(name), Some(tail)) = (
        essence.get(..HEAD.len()),
        essence.get(HEAD.len()..end),
        essence.get(end..),
    ) else {
        return false;
    };
    head.eq_ignore_ascii_case(HEAD)
        && tail.eq_ignore_ascii_case(TAIL)
        && (1..=MAX_NAME).contains(&name.len())
        && name.first().is_some_and(u8::is_ascii_alphanumeric)
        && name
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
        && !name
            .get(..URLENCODED.len())
            .is_some_and(|start| start.eq_ignore_ascii_case(URLENCODED))
}

impl Supervisor {
    /// Checks the configuration and nothing else: no process is started and the file system is not touched.
    pub fn new(cfg: Config) -> Result<Supervisor, ConfigError> {
        cfg.check()?;
        let engine = Engine::new(
            Limits {
                slots: cfg.slots,
                wait_queue: cfg.wait_queue,
                records: cfg.records,
                discard_limit: cfg.discard_limit,
                verdict_wait: cfg.verdict_wait,
                wait_deadline: cfg.wait_deadline,
                closed_wait: cfg.closed_wait,
                stop_after: cfg.stop_after,
            },
            1,
            1,
        );
        // At most `restarts` entries (`check` caps it), so the queue never grows.
        let restart_times =
            VecDeque::with_capacity(usize::try_from(cfg.restarts).unwrap_or_default());
        Ok(Supervisor {
            cfg,
            engine,
            run_id: None,
            run: Run::Down,
            restarts: 0,
            restart_times,
            not_before: None,
            shutdown_by: None,
        })
    }

    /// Takes one request. What cannot be inspected faithfully is refused here (`Refused::Unsupported`) and never
    /// becomes `Allow`. A decision the engine takes at once (queue full, intake ended, wait deadline that does
    /// not fit) makes a record like any other and comes out of the next `poll` or `shutdown`.
    pub fn submit(&mut self, req: &Request<'_>) -> Result<ReqId, Refused> {
        let Some(declared) = u64::try_from(req.body.len())
            .ok()
            .filter(|&n| n <= codec::MAX_DECLARED)
        else {
            return Err(Refused::Unsupported("body over the protocol limit"));
        };
        // Every field of TX_BEGIN is bounded first; for the headers that is their number, the length of each name
        // and value, and their total. What passes is small, so the header rules below read no more than that.
        let begin = codec::encode_tx_begin(&codec::TxBegin {
            client_addr: req.client_addr,
            client_port: req.client_port,
            server_addr: req.server_addr,
            server_port: req.server_port,
            method: req.method,
            uri: req.uri,
            proto: req.proto,
            declared,
            headers: req.headers,
        })
        .map_err(|e| Refused::Invalid(e.0))?;
        let header = |name: &'static [u8]| {
            req.headers
                .iter()
                .filter(move |h| h.0.eq_ignore_ascii_case(name))
        };
        if header(b"transfer-encoding").next().is_some() {
            return Err(Refused::Unsupported("transfer-encoding"));
        }
        // The body is not decompressed, so a body that is coded cannot be inspected.
        if header(b"content-encoding").next().is_some() {
            return Err(Refused::Unsupported("content-encoding"));
        }
        let mut lengths = header(b"content-length");
        if let Some(first) = lengths.next() {
            let value = first.1;
            let same = !value.is_empty()
                && value.iter().all(u8::is_ascii_digit)
                && std::str::from_utf8(value)
                    .ok()
                    .and_then(|s| s.parse::<u64>().ok())
                    == Some(declared);
            if lengths.next().is_some() || !same {
                return Err(Refused::Unsupported("content-length"));
            }
        }
        if !req.body.is_empty() {
            // Only these types get a body processor: Coraza selects it for the first two, and the inspector sets the
            // JSON processor for `application/json` and for `application/<name>+json`. Any other body is not parsed.
            let mut types = header(b"content-type");
            let known = match (types.next(), types.next()) {
                (Some(t), None) => {
                    let essence =
                        t.1.split(|&b| b == b';')
                            .next()
                            .unwrap_or_default()
                            .trim_ascii();
                    essence.eq_ignore_ascii_case(b"application/x-www-form-urlencoded")
                        || essence.eq_ignore_ascii_case(b"multipart/form-data")
                        || essence.eq_ignore_ascii_case(b"application/json")
                        || is_json_suffix_type(essence)
                }
                _ => false,
            };
            if !known {
                return Err(Refused::Unsupported("content-type"));
            }
        }
        let body: Vec<Vec<u8>> = req
            .body
            .chunks(codec::MAX_BODY)
            .map(<[u8]>::to_vec)
            .collect();
        match self
            .engine
            .submit(Instant::now(), state::Request { begin, body })
        {
            Ok(id) => Ok(id),
            Err(SubmitError::Full) => Err(Refused::Full),
            Err(SubmitError::IdsExhausted) => Err(Refused::IdsExhausted),
        }
    }

    /// The client went away. An id that is unknown, or already delivered, is ignored.
    pub fn cancel(&mut self, id: ReqId) {
        self.engine.cancel(Instant::now(), id);
    }

    /// Steps until a result is ready or `until`, and returns the results (each once). `until` is looked at between
    /// steps: one step writes one frame and reads one frame, so the return can be later than `until` by what one
    /// frame takes. A step whose `until` has passed writes but does not read. At least one step is made.
    /// The return can also be later by a start made in that call (creating the start directory, spawning the
    /// inspector, reading `/dev/urandom`), by the removal of a start directory after an exit, and by the operating
    /// system's scheduling delay. A read in progress is not cut.
    pub fn poll(&mut self, until: Instant) -> Vec<(ReqId, Verdict)> {
        loop {
            self.step(until);
            let results = self.results();
            if !results.is_empty() || Instant::now() >= until {
                return results;
            }
        }
    }

    pub fn status(&self) -> Status {
        Status {
            phase: self.phase(),
            inc: self.engine.incarnation(),
            restarts: self.restarts,
            waiting: self.engine.waiting(),
            held: self.engine.held_slots(),
            records: self.engine.records(),
        }
    }

    /// Ends the intake for good. Callable again: a reap or clean-up left unknown stays owned and is retried.
    ///
    /// Every request accepted and not decided is decided in this call, whatever the state, and comes out in
    /// `results` (or came out of an earlier `poll`) once. Nothing is started. Every wait a step creates is cut at
    /// `deadline`; the return is no later than `max(call time, deadline)` plus `kill_grace`, plus what the
    /// following take, which the bound leaves out: the operating system's scheduling delay, the granularity of
    /// socket timeouts, the `kill`, `waitpid` and `lstat` system calls, and the removal of the directory after the
    /// exit is confirmed (how long it takes depends on what the directory holds).
    pub fn shutdown(&mut self, deadline: Instant) -> Shutdown {
        // Only a supervisor that was already failed when this call began retries what the failure left. One that
        // fails inside this call keeps its leftover: a second kill here would double the wait.
        let was_failed = matches!(self.run, Run::Failed { .. });
        self.shutdown_by = Some(deadline);
        let now = Instant::now();
        // Deadlines that have passed are decided first, with their own reasons; then the intake ends.
        let _ = self.engine.tick(now);
        self.engine.halt(now, Halt::Drain);
        let mut bye = false;
        if was_failed {
            if let Run::Failed { why, left } = mem::replace(&mut self.run, Run::Down) {
                let left = match left {
                    Some(Leftover::Running(s)) => {
                        let mut s = s.again(now);
                        loop {
                            let t = Instant::now();
                            match s.step(t) {
                                Stopped::Waiting(w) => {
                                    let wake = bounded(t, self.cfg.tick, None).min(w.next_at());
                                    thread::sleep(wake.saturating_duration_since(t));
                                    s = w;
                                }
                                Stopped::Done { inc, .. } => {
                                    self.engine.exit_confirmed(t, inc);
                                    break None;
                                }
                                Stopped::DirLeft { inc, dir, .. } => {
                                    self.engine.exit_confirmed(t, inc);
                                    break Some(Leftover::Dir(dir));
                                }
                                Stopped::Unreaped { left: s2, .. } => {
                                    break Some(Leftover::Running(s2));
                                }
                            }
                        }
                    }
                    Some(Leftover::Dir(dir)) => match dir.remove() {
                        Ok(()) => None,
                        Err((dir, _)) => Some(Leftover::Dir(dir)),
                    },
                    other @ (Some(Leftover::Unidentified) | None) => other,
                };
                self.run = Run::Failed { why, left };
            }
        } else {
            match &mut self.run {
                Run::Down => self.run = Run::Stopped,
                Run::Hello { .. } => self.end(now, End::Restart("shutdown"), now),
                Run::Stopping { stop, .. } => stop.kill_by(deadline),
                Run::Ready { .. } | Run::Draining { .. } | Run::Stopped | Run::Failed { .. } => {}
            }
            while !matches!(self.run, Run::Stopped | Run::Failed { .. }) {
                let until = match &self.run {
                    Run::Stopping { stop, .. } => stop.next_at(),
                    _ => deadline,
                };
                self.step(until);
                bye |= matches!(self.run, Run::Stopping { end: End::Bye, .. });
            }
        }
        Shutdown {
            results: self.results(),
            phase: self.phase(),
            bye,
            exit_confirmed: !matches!(
                self.run,
                Run::Failed {
                    left: Some(Leftover::Running(_)),
                    ..
                }
            ),
            dir_removed: !matches!(self.run, Run::Failed { left: Some(_), .. }),
            held_left: self.engine.held_slots(),
            waiting_left: self.engine.waiting(),
        }
    }

    fn phase(&self) -> Phase {
        match &self.run {
            Run::Down | Run::Hello { .. } => Phase::Starting,
            Run::Ready { .. } => Phase::Ready,
            Run::Draining { .. } | Run::Stopping { .. } => Phase::Stopping,
            Run::Stopped => Phase::Stopped,
            Run::Failed { why, .. } => Phase::Failed(*why),
        }
    }

    /// Every decision not delivered yet, each once, in the order they were made.
    fn results(&mut self) -> Vec<(ReqId, Verdict)> {
        let mut results = Vec::new();
        while let Some((id, decision)) = self.engine.next_done() {
            results.push((id, verdict_of(decision)));
        }
        results
    }

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
    /// once the intake has ended and nothing is held, at most one frame written, at most one frame read (a tick
    /// long when nothing arrives). `until` cuts the wait for the first byte; the frame that has begun is read to
    /// its end.
    fn step(&mut self, until: Instant) {
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
            || self.write_step().is_break()
        {
            return;
        }
        let _ = self.read_step(until);
    }

    /// Sleeps until the next tick, `until` or `next`, whichever is first.
    fn nap(&self, now: Instant, until: Instant, next: Option<Instant>) {
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
    fn check(&mut self, now: Instant) -> ControlFlow<()> {
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

    /// The engine's next frame, if any, written. `next_frame` is the writer's take: the message number and the
    /// state change are valid from there, so the clock and the halt are looked at again right after it (a halt can
    /// rise inside it, and its `None` looks like an empty queue), and once more in `put` right before the bytes go.
    /// A frame taken and not written is not sent again: the connection fault makes its request uninspectable.
    fn write_step(&mut self) -> ControlFlow<()> {
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
    fn read_step(&mut self, until: Instant) -> ControlFlow<()> {
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
                let r = self
                    .engine
                    .on_verdict(now, h.tx, h.msg, v.phase, v.block, v.rule_id, v.status, p);
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
    fn end(&mut self, now: Instant, end: End, kill_at: Instant) {
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

    /// Down: while the restart window is full, nothing is started; the engine's clock still runs, so the waiting
    /// requests keep their deadlines. When the time has come the window decides again and, with room, the start is
    /// made.
    fn down(&mut self, now: Instant, until: Instant) {
        if let Some(due) = self.not_before {
            let _ = self.engine.tick(now);
            if now < due {
                return self.nap(now, until, Some(due));
            }
            self.not_before = self.restart_wait(now);
            // Still full: wait for the time it names.
            if self.not_before.is_some() {
                return;
            }
        }
        self.launch(now);
    }

    /// A restart is wanted at `now`: `None` when the window has room (the time is recorded and counted), else the
    /// time before which it must not start.
    fn restart_wait(&mut self, now: Instant) -> Option<Instant> {
        match restart_slot(
            &mut self.restart_times,
            now,
            self.cfg.restarts,
            self.cfg.restart_window,
        ) {
            Slot::Now => {
                self.restarts = self.restarts.saturating_add(1);
                None
            }
            Slot::Wait(t) => Some(t),
        }
    }

    /// One try to start. Nothing is started after the intake ended or the numbers ran out. A try that fails has
    /// no process, so the incarnation is used up and never used again.
    fn launch(&mut self, now: Instant) {
        match self.engine.halted() {
            None => {}
            Some(Halt::Drain) => {
                self.run = Run::Stopped;
                return;
            }
            Some(_) => return self.fail(now, Failure::Exhausted, None),
        }
        let inc = self.engine.incarnation();
        let launched = match self.run_id.map_or_else(child::fresh_run, Ok) {
            Ok(run) => {
                self.run_id = Some(run);
                start::launch(&self.cfg, run, inc)
            }
            Err(_) => Err(LaunchError::Clean {
                step: Step::Random,
                why: "run id not available",
            }),
        };
        let now = Instant::now().max(now);
        let error = match launched {
            Ok(start) => {
                let until = bounded(start.started, self.cfg.hello_wait, None);
                self.run = Run::Hello { start, until };
                return;
            }
            Err(e) => e,
        };
        self.engine.exit_confirmed(now, inc);
        match error {
            LaunchError::Clean {
                step: Step::TmpDir,
                why,
            } => self.fail(now, Failure::TmpDir(why), None),
            LaunchError::Clean { why, .. } => {
                let n = next(
                    End::Restart(why),
                    None,
                    self.engine.halted(),
                    self.restarts,
                    self.cfg.restarts,
                );
                self.proceed(now, n);
            }
            LaunchError::DirLeft { dir, .. } => {
                self.fail(now, Failure::CleanupUnknown, Some(Leftover::Dir(dir)));
            }
            LaunchError::Unidentified { .. } => {
                self.fail(now, Failure::CleanupUnknown, Some(Leftover::Unidentified));
            }
        }
    }

    /// Stopping: one try to see the exit, with the engine's clock first (the waiting requests keep their
    /// deadlines meanwhile).
    fn reap(&mut self, now: Instant, until: Instant) {
        let (stop, end) = match mem::replace(&mut self.run, Run::Down) {
            Run::Stopping { stop, end } => (stop, end),
            other => {
                self.run = other;
                return;
            }
        };
        let _ = self.engine.tick(now);
        let (inc, tag, exit, left) = match stop.step(now) {
            Stopped::Waiting(stop) => {
                let wake = stop.next_at();
                self.run = Run::Stopping { stop, end };
                return self.nap(now, until, Some(wake));
            }
            Stopped::Done { inc, exit } => (inc, StopTag::Done, Some(exit), None),
            Stopped::DirLeft { inc, exit, dir, .. } => {
                (inc, StopTag::DirLeft, Some(exit), Some(Leftover::Dir(dir)))
            }
            Stopped::Unreaped { left: rest, .. } => (
                rest.inc(),
                StopTag::Unreaped,
                None,
                Some(Leftover::Running(rest)),
            ),
        };
        match apply_stop(&mut self.engine, now, inc, tag) {
            Some(why) => self.fail(now, why, left),
            None => {
                let n = next(
                    end,
                    exit,
                    self.engine.halted(),
                    self.restarts,
                    self.cfg.restarts,
                );
                self.proceed(now, n);
            }
        }
    }

    /// The step after a stop whose exit was seen (or a try to start that failed without a process).
    fn proceed(&mut self, now: Instant, n: Next) {
        match n {
            Next::Restart => {
                // `next` chose this only with `restarts` above 0. A full window keeps `Down` waiting.
                self.not_before = self.restart_wait(now);
                self.run = Run::Down;
            }
            Next::Stopped => self.run = Run::Stopped,
            Next::Fail(why) => self.fail(now, why, None),
        }
    }

    /// The end of the road: what is still owned stays in `left`, the waiting requests are decided, and nothing is
    /// started again.
    fn fail(&mut self, now: Instant, why: Failure, left: Option<Leftover>) {
        self.engine.halt(now, Halt::NoRestart);
        self.run = Run::Failed { why, left };
    }
}

impl Drop for Supervisor {
    /// A separate, bounded best effort (the results the engine still holds are lost): a start that runs is
    /// stopped at once, a stop in progress is killed now, a leftover reap gets one more kill, a leftover directory
    /// one try. It waits for the exit for at most about two `kill_grace` (this loop and the `Drop` of the
    /// inspector that still owns an unreaped child), plus what the operating system takes.
    fn drop(&mut self) {
        let now = Instant::now();
        let mut stop = match mem::replace(&mut self.run, Run::Down) {
            Run::Hello { start, .. } | Run::Ready { start } | Run::Draining { start, .. } => {
                start.stop(now)
            }
            Run::Stopping { mut stop, .. } => {
                stop.kill_by(now);
                stop
            }
            Run::Failed {
                left: Some(Leftover::Running(s)),
                ..
            } => s.again(now),
            Run::Failed {
                left: Some(Leftover::Dir(dir)),
                ..
            } => {
                let _ = dir.remove();
                return;
            }
            Run::Down | Run::Stopped | Run::Failed { .. } => return,
        };
        loop {
            let t = Instant::now();
            match stop.step(t) {
                Stopped::Waiting(s) => {
                    thread::sleep(POLL.min(s.next_at().saturating_duration_since(t)));
                    stop = s;
                }
                // Done, or the directory kept, or not reaped (the `Inspector` kills and waits once more).
                Stopped::Done { .. } | Stopped::DirLeft { .. } | Stopped::Unreaped { .. } => return,
            }
        }
    }
}

#[cfg(test)]
mod tests;
