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

use crate::child::{self, Exit};
use crate::codec::{self, ConnError, Header, HelloExpect};
use crate::config::{Config, ConfigError};
use crate::io;
use crate::start::{self, LaunchError, Start, StartDir, Step, Stopped, Stopping};
use crate::state::{self, Decision, Engine, Halt, Limits, OutKind, SubmitError, Why};

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
mod tests {
    use super::*;
    use crate::state::ReturnReason;
    use std::fs;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
    use std::os::unix::process::ExitStatusExt;
    use std::path::{Path, PathBuf};
    use std::process::ExitStatus;
    use std::sync::atomic::{AtomicU32, Ordering};

    const MS: Duration = Duration::from_millis(1);

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    /// A configuration that passes `Config::check` and is never used to start anything.
    fn cfg() -> Config {
        Config {
            inspector: PathBuf::from("/test-only/inspector"),
            rules: PathBuf::from("/test-only/rules.conf"),
            rules_sha256: [0; 32],
            tmp_root: PathBuf::from("/test-only/tmp"),
            gomaxprocs: 1,
            gomemlimit: 256 << 20,
            slots: 4,
            wait_queue: 8,
            records: 16,
            discard_limit: 64,
            tick: 20 * MS,
            hello_wait: secs(5),
            frame_io: secs(2),
            verdict_wait: secs(2),
            wait_deadline: secs(3),
            closed_wait: secs(2),
            stop_after: secs(6),
            drain_wait: secs(3),
            exit_wait: secs(3),
            kill_grace: secs(1),
            restarts: 1,
            restart_window: secs(60),
        }
    }

    const HOST: [(&[u8], &[u8]); 1] = [(b"Host", b"example.test")];

    fn with<'a>(uri: &'a [u8], headers: &'a [(&'a [u8], &'a [u8])], body: &'a [u8]) -> Request<'a> {
        Request {
            client_addr: b"192.0.2.10",
            client_port: 49152,
            server_addr: b"192.0.2.1",
            server_port: 8080,
            method: b"GET",
            uri,
            proto: b"HTTP/1.1",
            headers,
            body,
        }
    }

    fn get(uri: &'static [u8]) -> Request<'static> {
        with(uri, &HOST, b"")
    }

    fn unavailable() -> Verdict {
        Verdict::Uninspectable(Reason::Unavailable)
    }

    fn code(c: i32) -> Exit {
        Exit {
            status: ExitStatus::from_raw(c << 8),
            killed: false,
        }
    }

    fn signal(sig: i32, killed: bool) -> Exit {
        Exit {
            status: ExitStatus::from_raw(sig),
            killed,
        }
    }

    // ---- pure rules ----

    #[test]
    fn bounded_is_due_at_once_on_overflow_and_cut_at_the_cap() {
        let t = Instant::now();
        let cap = t + secs(1);
        // no cap
        assert_eq!(bounded(t, 20 * MS, None), t + 20 * MS);
        assert_eq!(bounded(t, Duration::MAX, None), t);
        // a cap
        assert_eq!(bounded(t, 20 * MS, Some(cap)), t + 20 * MS);
        assert_eq!(bounded(t, secs(5), Some(cap)), cap);
        assert_eq!(bounded(t, cap - t, Some(cap)), cap);
        // a sum that does not fit is due at once, also under a later cap
        assert_eq!(bounded(t, Duration::MAX, Some(cap)), t);
        // a cap that has passed wins
        if let Some(past) = t.checked_sub(secs(1)) {
            assert_eq!(bounded(t, 20 * MS, Some(past)), past);
            assert_eq!(bounded(t, Duration::MAX, Some(past)), past);
        }
    }

    #[test]
    fn every_decision_has_its_verdict() {
        let halts = [
            Halt::TxExhausted,
            Halt::IncExhausted,
            Halt::MsgOverflow,
            Halt::Drain,
            Halt::NoRestart,
        ];
        assert_eq!(verdict_of(Decision::Forward), Verdict::Allow);
        assert_eq!(
            verdict_of(Decision::Block {
                phase: 2,
                rule_id: 9202,
                status: 403
            }),
            Verdict::Block {
                phase: 2,
                rule_id: 9202,
                status: 403
            }
        );
        // the status is passed on as it is, a value that is no HTTP status too
        assert_eq!(
            verdict_of(Decision::Block {
                phase: 1,
                rule_id: -1,
                status: 0
            }),
            Verdict::Block {
                phase: 1,
                rule_id: -1,
                status: 0
            }
        );
        assert_eq!(
            verdict_of(Decision::ClientDisconnect),
            Verdict::Uninspectable(Reason::Cancelled)
        );
        let rows = [
            (Why::Invalid, Reason::Invalid),
            (Why::QueueFull, Reason::QueueFull),
            (Why::WaitDeadline, Reason::WaitDeadline),
            (Why::VerdictDeadline, Reason::VerdictDeadline),
            (Why::ConnFault, Reason::InspectorLost),
            (Why::Order, Reason::Protocol),
            (
                Why::TxError { code: 19 },
                Reason::InspectorError { code: 19 },
            ),
            (Why::NotCreated { code: 3 }, Reason::NotCreated { code: 3 }),
        ];
        for (why, reason) in rows {
            assert_eq!(
                verdict_of(Decision::Uninspectable(why)),
                Verdict::Uninspectable(reason),
                "{why:?}"
            );
        }
        for h in halts {
            assert_eq!(
                verdict_of(Decision::Uninspectable(Why::Halted(h))),
                unavailable(),
                "{h:?}"
            );
        }
    }

    #[test]
    fn every_out_kind_has_the_kind_codec_sends() {
        let all = [
            (OutKind::TxBegin, codec::KIND_TX_BEGIN),
            (OutKind::Body, codec::KIND_BODY),
            (OutKind::BodyEnd, codec::KIND_BODY_END),
            (OutKind::TxEnd(3), codec::KIND_TX_END),
        ];
        for (k, w) in all {
            assert_eq!(wire_kind(k), w);
        }
    }

    #[test]
    fn next_follows_the_table_in_order() {
        let restart = || End::Restart("x");
        let halts = [
            None,
            Some(Halt::Drain),
            Some(Halt::TxExhausted),
            Some(Halt::NoRestart),
        ];
        // 1. a code of 10, 11 or 14 wins over everything below, also over a kill and an unspent budget
        for c in [10, 11, 14] {
            for halted in halts {
                let fail = Next::Fail(Failure::Exit(c));
                assert_eq!(next(restart(), Some(code(c)), halted, 0, 9), fail);
                assert_eq!(
                    next(End::Fail(Failure::Hello("h")), Some(code(c)), halted, 9, 0),
                    fail
                );
                assert_eq!(next(End::Bye, Some(code(c)), halted, 0, 0), fail);
            }
        }
        let killed_10 = Exit {
            status: ExitStatus::from_raw(10 << 8),
            killed: true,
        };
        assert_eq!(
            next(restart(), Some(killed_10), None, 0, 1),
            Next::Fail(Failure::Exit(10))
        );
        // a signal is not a code, and neither is no process
        assert_eq!(
            next(restart(), Some(signal(10, false)), None, 0, 1),
            Next::Restart
        );
        // 2. the end's own failure
        for exit in [None, Some(code(0)), Some(code(12)), Some(signal(9, true))] {
            for halted in halts {
                assert_eq!(
                    next(End::Fail(Failure::Hello("h")), exit, halted, 5, 0),
                    Next::Fail(Failure::Hello("h"))
                );
            }
        }
        // 3. BYE and a clean exit that was not killed
        assert_eq!(next(End::Bye, Some(code(0)), None, 9, 0), Next::Stopped);
        assert_eq!(
            next(End::Bye, Some(code(0)), Some(Halt::TxExhausted), 9, 0),
            Next::Stopped
        );
        // BYE with a kill or another code is no clean stop: the rows below decide
        let killed_0 = Exit {
            status: ExitStatus::from_raw(0),
            killed: true,
        };
        assert_eq!(next(End::Bye, Some(killed_0), None, 0, 1), Next::Restart);
        assert_eq!(next(End::Bye, Some(code(1)), None, 0, 1), Next::Restart);
        assert_eq!(
            next(End::Bye, Some(code(1)), None, 0, 0),
            Next::Fail(Failure::BudgetExhausted)
        );
        assert_eq!(
            next(End::Bye, Some(code(1)), Some(Halt::Drain), 0, 0),
            Next::Stopped
        );
        // 4. the intake ended by shutdown: stopped, whatever the exit, also with no budget
        for exit in [
            None,
            Some(code(0)),
            Some(code(1)),
            Some(code(2)),
            Some(code(12)),
            Some(code(13)),
            Some(signal(9, true)),
            Some(signal(11, false)),
        ] {
            assert_eq!(
                next(restart(), exit, Some(Halt::Drain), 9, 0),
                Next::Stopped
            );
            assert_eq!(
                next(restart(), exit, Some(Halt::Drain), 0, 9),
                Next::Stopped
            );
        }
        // 5. numbers used up: exhausted, before the budget
        for h in [Halt::TxExhausted, Halt::IncExhausted, Halt::MsgOverflow] {
            for (used, budget) in [(0, 9), (9, 0)] {
                assert_eq!(
                    next(restart(), Some(code(12)), Some(h), used, budget),
                    Next::Fail(Failure::Exhausted),
                    "{h:?}"
                );
                assert_eq!(
                    next(End::Bye, Some(code(1)), Some(h), used, budget),
                    Next::Fail(Failure::Exhausted),
                    "{h:?}"
                );
            }
        }
        // 6. no restart at all (`budget == 0`): the end of the supervisor, whatever was made so far
        for used in [0, 1, 9, u32::MAX] {
            for exit in [None, Some(code(0)), Some(code(12)), Some(signal(9, true))] {
                for halted in [None, Some(Halt::NoRestart)] {
                    assert_eq!(
                        next(restart(), exit, halted, used, 0),
                        Next::Fail(Failure::BudgetExhausted),
                        "{used}"
                    );
                }
            }
        }
        // 7. otherwise a restart, whatever was made so far: a full window waits, it does not fail
        for (used, budget) in [
            (0, 1),
            (1, 1),
            (2, 1),
            (u32::MAX, 1),
            (0, 2),
            (999, 1000),
            (1000, 1000),
            (u32::MAX - 1, u32::MAX),
            (u32::MAX, u32::MAX),
        ] {
            assert_eq!(
                next(restart(), Some(code(12)), None, used, budget),
                Next::Restart,
                "{used} {budget}"
            );
        }
        // any exit, also none (a try to start that failed)
        for exit in [
            None,
            Some(code(0)),
            Some(code(2)),
            Some(code(12)),
            Some(code(13)),
            Some(code(99)),
            Some(signal(9, true)),
            Some(signal(11, false)),
        ] {
            assert_eq!(next(restart(), exit, None, 0, 1), Next::Restart);
            assert_eq!(
                next(restart(), exit, Some(Halt::NoRestart), 0, 1),
                Next::Restart
            );
        }
        assert_eq!(
            next(restart(), None, None, u32::MAX - 1, u32::MAX),
            Next::Restart
        );
    }

    // ---- the restart window ----

    #[test]
    fn the_restart_window_has_room_until_the_limit_and_then_names_the_time() {
        let (t0, w) = (Instant::now(), secs(10));
        let mut times = VecDeque::new();
        // empty and below the limit: recorded
        assert_eq!(restart_slot(&mut times, t0, 3, w), Slot::Now);
        assert_eq!(restart_slot(&mut times, t0 + secs(1), 3, w), Slot::Now);
        assert_eq!(restart_slot(&mut times, t0 + secs(2), 3, w), Slot::Now);
        assert_eq!(times, [t0, t0 + secs(1), t0 + secs(2)]);
        // full: the oldest plus a window, nothing recorded, the same answer however often it is asked
        for ask in [3, 4, 9] {
            assert_eq!(
                restart_slot(&mut times, t0 + secs(ask), 3, w),
                Slot::Wait(t0 + w)
            );
        }
        assert_eq!(times, [t0, t0 + secs(1), t0 + secs(2)]);
        // a limit of 1 is full after one
        let mut one = VecDeque::new();
        assert_eq!(restart_slot(&mut one, t0, 1, w), Slot::Now);
        assert_eq!(restart_slot(&mut one, t0, 1, w), Slot::Wait(t0 + w));
        // a limit of 0 has no oldest record: nothing is recorded, and the wait is a whole window from now
        let mut none = VecDeque::new();
        assert_eq!(restart_slot(&mut none, t0, 0, w), Slot::Wait(t0 + w));
        assert_eq!(
            restart_slot(&mut none, t0 + w, 0, w),
            Slot::Wait(t0 + w + w)
        );
        assert!(none.is_empty());
    }

    #[test]
    fn the_restart_window_drops_a_record_that_is_a_whole_window_old() {
        let (t0, w, ns) = (Instant::now(), secs(10), Duration::from_nanos(1));
        // one nanosecond short of a whole window: the record stays, so the window is full
        let mut times = VecDeque::from([t0]);
        assert_eq!(
            restart_slot(&mut times, t0 + w - ns, 1, w),
            Slot::Wait(t0 + w)
        );
        assert_eq!(times, [t0]);
        // a whole window: it is dropped and the new time is recorded (the time that was named is a time that works)
        assert_eq!(restart_slot(&mut times, t0 + w, 1, w), Slot::Now);
        assert_eq!(times, [t0 + w]);
        // only the records that are old go, all of them if all are
        let all = [t0, t0 + secs(1), t0 + secs(2)];
        let mut times = VecDeque::from(all);
        assert_eq!(restart_slot(&mut times, t0 + secs(10), 3, w), Slot::Now);
        assert_eq!(times, [t0 + secs(1), t0 + secs(2), t0 + secs(10)]);
        let mut times = VecDeque::from(all);
        assert_eq!(
            restart_slot(&mut times, t0 + secs(10), 2, w),
            Slot::Wait(t0 + secs(11))
        );
        assert_eq!(times, [t0 + secs(1), t0 + secs(2)]);
        let mut times = VecDeque::from(all);
        assert_eq!(restart_slot(&mut times, t0 + secs(12), 3, w), Slot::Now);
        assert_eq!(times, [t0 + secs(12)]);
    }

    #[test]
    fn the_restart_window_treats_a_sum_that_does_not_fit_as_passed() {
        let t0 = Instant::now();
        // a window so long that its end does not fit in an `Instant`: the record has passed, so it is dropped and
        // the window has room, however full it was
        let mut times = VecDeque::from([t0]);
        assert_eq!(restart_slot(&mut times, t0, 1, Duration::MAX), Slot::Now);
        assert_eq!(times, [t0]);
        // a window whose end fits still keeps the record
        let mut times = VecDeque::from([t0]);
        assert_eq!(
            restart_slot(&mut times, t0, 1, secs(1)),
            Slot::Wait(t0 + secs(1))
        );
    }

    #[test]
    fn the_restart_window_allows_no_more_than_its_limit_in_any_window() {
        let (t0, w, limit) = (Instant::now(), secs(10), 3);
        let mut times = VecDeque::new();
        let mut made = Vec::new();
        for i in 0..100 {
            let now = t0 + secs(i);
            if restart_slot(&mut times, now, limit, w) == Slot::Now {
                made.push(now);
            }
            assert!(times.len() <= 3);
        }
        // three at once and three more as soon as the oldest leaves the window, ten times
        assert_eq!(made.len(), 30);
        for &m in &made {
            let inside = made.iter().filter(|&&x| x <= m && m < x + w).count();
            assert!(
                inside <= 3,
                "{inside} restarts in the window that ends at {m:?}"
            );
        }
        assert_eq!(made[3], t0 + w);
    }

    /// A supervisor whose window is full: the restart wanted at `t0` found room, the second one did not.
    fn window_full(window: Duration) -> (Supervisor, Instant) {
        let mut c = cfg();
        (c.tick, c.wait_deadline, c.restarts, c.restart_window) = (MS, 50 * MS, 1, window);
        let mut s = Supervisor::new(c).unwrap();
        let t0 = Instant::now();
        s.proceed(t0, Next::Restart);
        assert!(matches!(s.run, Run::Down));
        assert_eq!((s.status().restarts, s.not_before), (1, None));
        s.proceed(t0, Next::Restart);
        (s, t0)
    }

    #[test]
    fn a_full_window_keeps_down_and_the_requests_keep_their_deadlines() {
        let (mut s, t0) = window_full(secs(30));
        let a = s.submit(&get(b"/a")).unwrap();
        // the second restart is not made: not counted, and the time before which nothing starts is held
        assert!(matches!(s.run, Run::Down));
        assert_eq!(
            (s.status().restarts, s.not_before),
            (1, Some(t0 + secs(30)))
        );
        assert_eq!(s.status().phase, Phase::Starting);
        // a step starts nothing; the clock runs, so the request ends at its own deadline, not at the window
        thread::sleep(60 * MS);
        s.step(Instant::now());
        assert!(matches!(s.run, Run::Down) && s.run_id.is_none());
        assert_eq!(
            s.poll(Instant::now()),
            vec![(a, Verdict::Uninspectable(Reason::WaitDeadline))]
        );
        assert_eq!(
            (s.status().restarts, s.not_before),
            (1, Some(t0 + secs(30)))
        );
        // a request that comes now waits as well, and a shutdown stops the wait at once: it starts nothing and
        // the restart that was waiting is not counted
        let b = s.submit(&get(b"/b")).unwrap();
        let sd = s.shutdown(Instant::now());
        assert_eq!(sd.results, vec![(b, unavailable())]);
        assert_eq!(sd.phase, Phase::Stopped);
        assert!(!sd.bye && sd.exit_confirmed && sd.dir_removed);
        assert_eq!((sd.held_left, sd.waiting_left), (0, 0));
        assert!(s.run_id.is_none());
        let st = s.status();
        assert_eq!((st.phase, st.inc, st.restarts), (Phase::Stopped, 1, 1));
    }

    #[test]
    fn a_restart_that_is_due_is_recorded_counted_and_started() {
        let (mut s, t0) = window_full(40 * MS);
        let due = s.not_before.unwrap();
        assert_eq!(due, t0 + 40 * MS);
        assert_eq!((s.status().restarts, s.not_before), (1, Some(due)));
        // from the time: the oldest record is a whole window old, so the window has room again; the try is
        // made (`cfg()` names a tmp root that is not there, so it ends at once, before anything is made)
        thread::sleep(50 * MS);
        assert!(Instant::now() >= due);
        s.step(Instant::now());
        let st = s.status();
        assert!(
            matches!(st.phase, Phase::Failed(Failure::TmpDir(_))),
            "{st:?}"
        );
        assert_eq!((st.restarts, st.inc), (2, 2));
        assert_eq!(s.not_before, None);
        assert_eq!(s.restart_times.len(), 1);
        assert!(s.restart_times[0] >= due);
        let sd = s.shutdown(Instant::now());
        assert!(sd.exit_confirmed && sd.dir_removed);
    }

    /// An engine after HELLO with one slot and room for one waiting request.
    fn engine() -> (Engine, Instant) {
        let t0 = Instant::now();
        let mut e = Engine::new(
            Limits {
                slots: 1,
                wait_queue: 2,
                records: 8,
                discard_limit: 8,
                verdict_wait: secs(2),
                wait_deadline: secs(30),
                closed_wait: secs(2),
                stop_after: secs(6),
            },
            1,
            1,
        );
        e.ready(t0, 1);
        (e, t0)
    }

    /// One request holds the slot (TX_BEGIN taken), one waits, and the connection has faulted: the state in which
    /// a stop ends.
    fn faulted() -> (Engine, Instant, ReqId, ReqId) {
        let (mut e, t0) = engine();
        let request = || state::Request {
            begin: vec![1, 2, 3],
            body: Vec::new(),
        };
        let held = e.submit(t0, request()).unwrap();
        let waiting = e.submit(t0, request()).unwrap();
        assert_eq!(e.next_frame(t0).map(|f| f.kind), Some(OutKind::TxBegin));
        e.conn_fault(t0);
        (e, t0, held, waiting)
    }

    #[test]
    fn an_unreaped_stop_keeps_the_slot_and_ends_the_intake() {
        let (mut e, t0, held, waiting) = faulted();
        assert_eq!(
            apply_stop(&mut e, t0, 1, StopTag::Unreaped),
            Some(Failure::ReapUnknown)
        );
        // the exit is not confirmed: the incarnation is the same, the slot is held, nothing is returned
        assert_eq!((e.incarnation(), e.held_slots(), e.waiting()), (1, 1, 0));
        let o = e.outcome(held).unwrap();
        assert_eq!(o.decision, Some(Decision::Uninspectable(Why::ConnFault)));
        assert!(o.returns.is_empty());
        // the waiting request does not wait for a start that will not come
        assert_eq!(
            e.outcome(waiting).unwrap().decision,
            Some(Decision::Uninspectable(Why::Halted(Halt::NoRestart)))
        );
        assert_eq!(
            e.next_done().map(|(i, d)| (i, verdict_of(d))),
            Some((held, Verdict::Uninspectable(Reason::InspectorLost)))
        );
        assert_eq!(
            e.next_done().map(|(i, d)| (i, verdict_of(d))),
            Some((waiting, unavailable()))
        );
        // a later confirmed reap of the same incarnation returns the slot once
        assert_eq!(apply_stop(&mut e, t0, 1, StopTag::Done), None);
        assert_eq!((e.incarnation(), e.held_slots()), (2, 0));
        assert!(
            e.outcome(held).is_none(),
            "delivered, so it goes with the slot"
        );
    }

    #[test]
    fn a_stop_that_left_the_directory_counts_the_exit_once() {
        let (mut e, t0, held, waiting) = faulted();
        assert_eq!(
            apply_stop(&mut e, t0, 1, StopTag::DirLeft),
            Some(Failure::CleanupUnknown)
        );
        // the exit is confirmed: the incarnation is used up, the slot is back, the intake is ended
        assert_eq!((e.incarnation(), e.held_slots(), e.waiting()), (2, 0, 0));
        assert_eq!(
            e.outcome(held).unwrap().returns,
            vec![(1, ReturnReason::ExitConfirmed)]
        );
        assert_eq!(
            e.outcome(waiting).unwrap().decision,
            Some(Decision::Uninspectable(Why::Halted(Halt::NoRestart)))
        );
        // the same incarnation again does nothing, however it comes
        e.exit_confirmed(t0, 1);
        assert_eq!(apply_stop(&mut e, t0, 1, StopTag::Done), None);
        assert!(apply_stop(&mut e, t0, 1, StopTag::DirLeft).is_some());
        assert_eq!((e.incarnation(), e.held_slots()), (2, 0));
        assert_eq!(e.outcome(held).unwrap().returns.len(), 1);
    }

    #[test]
    fn a_confirmed_stop_returns_the_slot_and_numbers_the_next_start() {
        let (mut e, t0, held, waiting) = faulted();
        assert_eq!(apply_stop(&mut e, t0, 1, StopTag::Done), None);
        assert_eq!((e.incarnation(), e.held_slots(), e.waiting()), (2, 0, 1));
        assert_eq!(
            e.outcome(held).unwrap().returns,
            vec![(1, ReturnReason::ExitConfirmed)]
        );
        // the request that waited goes on to the next start with its own deadline
        assert_eq!(e.outcome(waiting).unwrap().decision, None);
        e.ready(t0, 2);
        assert_eq!(e.outcome(waiting).unwrap().txs, vec![2]);
        assert_eq!(apply_stop(&mut e, t0, 1, StopTag::Done), None);
        assert_eq!(e.incarnation(), 2);
    }

    // ---- the public API without a process ----

    #[test]
    fn a_supervisor_starts_nothing_and_refuses_a_bad_configuration() {
        let s = Supervisor::new(cfg()).unwrap();
        assert_eq!(
            s.status(),
            Status {
                phase: Phase::Starting,
                inc: 1,
                restarts: 0,
                waiting: 0,
                held: 0,
                records: 0
            }
        );
        let mut bad = cfg();
        bad.discard_limit = u32::MAX;
        assert_eq!(
            Supervisor::new(bad).err(),
            Some(ConfigError("discard_limit must be below u32::MAX"))
        );
    }

    #[test]
    fn shutdown_before_any_start_decides_the_request_and_starts_nothing() {
        let mut s = Supervisor::new(cfg()).unwrap();
        let a = s.submit(&get(b"/a")).unwrap();
        assert_eq!(a, 0);
        let sd = s.shutdown(Instant::now());
        assert_eq!(sd.results, vec![(a, unavailable())]);
        assert_eq!(sd.phase, Phase::Stopped);
        assert!(!sd.bye && sd.exit_confirmed && sd.dir_removed);
        assert_eq!((sd.held_left, sd.waiting_left), (0, 0));
        let st = s.status();
        assert_eq!((st.phase, st.inc, st.restarts), (Phase::Stopped, 1, 0));
        // again: nothing is delivered twice
        let sd = s.shutdown(Instant::now());
        assert_eq!(sd.results, vec![]);
        assert_eq!(sd.phase, Phase::Stopped);
        // after it: a record at once, delivered once, nothing started
        let b = s.submit(&get(b"/b")).unwrap();
        assert_eq!(b, 1);
        assert_eq!(s.poll(Instant::now()), vec![(b, unavailable())]);
        assert_eq!(s.poll(Instant::now()), vec![]);
        assert_eq!(s.status().inc, 1);
        assert!(matches!(s.run, Run::Stopped));
    }

    #[test]
    fn a_request_past_its_wait_deadline_is_decided_with_that_reason_at_shutdown() {
        let mut c = cfg();
        (c.tick, c.wait_deadline) = (MS, MS);
        let mut s = Supervisor::new(c).unwrap();
        let a = s.submit(&get(b"/a")).unwrap();
        thread::sleep(20 * MS);
        let sd = s.shutdown(Instant::now());
        assert_eq!(
            sd.results,
            vec![(a, Verdict::Uninspectable(Reason::WaitDeadline))]
        );
        // a cancel decides at once, an unknown or delivered id is ignored
        let mut s = Supervisor::new(cfg()).unwrap();
        let a = s.submit(&get(b"/a")).unwrap();
        let b = s.submit(&get(b"/b")).unwrap();
        s.cancel(a);
        s.cancel(99);
        let sd = s.shutdown(Instant::now());
        assert_eq!(
            sd.results,
            vec![
                (a, Verdict::Uninspectable(Reason::Cancelled)),
                (b, unavailable())
            ]
        );
        s.cancel(a);
        s.cancel(b);
        assert_eq!(s.shutdown(Instant::now()).results, vec![]);
    }

    #[test]
    fn requests_that_cannot_be_inspected_faithfully_are_refused_in_order() {
        let refused = |r: Request<'_>| {
            let mut s = Supervisor::new(cfg()).unwrap();
            let e = s.submit(&r).unwrap_err();
            assert_eq!(s.status().records, 0, "no record for {e:?}");
            e
        };
        let unsupported = |why| Refused::Unsupported(why);
        let big = vec![b'a'; (codec::MAX_DECLARED as usize) + 1];
        // 1. the protocol's limit comes first, whatever else is wrong
        let te: [(&[u8], &[u8]); 1] = [(b"Transfer-Encoding", b"chunked")];
        assert_eq!(
            refused(with(b"/", &te, &big)),
            unsupported("body over the protocol limit")
        );
        // 2. coded bodies, whatever the case of the name
        for name in [
            &b"Transfer-Encoding"[..],
            b"transfer-encoding",
            b"TRANSFER-ENCODING",
        ] {
            let h: [(&[u8], &[u8]); 1] = [(name, b"chunked")];
            assert_eq!(
                refused(with(b"/", &h, b"")),
                unsupported("transfer-encoding")
            );
        }
        let ce: [(&[u8], &[u8]); 1] = [(b"content-ENCODING", b"gzip")];
        assert_eq!(
            refused(with(b"/", &ce, b"")),
            unsupported("content-encoding")
        );
        let both: [(&[u8], &[u8]); 2] =
            [(b"Content-Encoding", b"gzip"), (b"Transfer-Encoding", b"x")];
        assert_eq!(
            refused(with(b"/", &both, b"")),
            unsupported("transfer-encoding")
        );
        // 3. Content-Length: one, digits only, and the length of the body
        let cl =
            |v: &'static [u8]| -> [(&'static [u8], &'static [u8]); 1] { [(b"Content-Length", v)] };
        for bad in [
            &b""[..],
            b"1",
            b"+0",
            b"0 ",
            b" 0",
            b"0x0",
            b"-0",
            b"99999999999999999999999",
        ] {
            assert_eq!(
                refused(with(b"/", &cl(bad), b"")),
                unsupported("content-length"),
                "{bad:?}"
            );
        }
        let two: [(&[u8], &[u8]); 2] = [(b"Content-Length", b"0"), (b"content-length", b"0")];
        assert_eq!(
            refused(with(b"/", &two, b"")),
            unsupported("content-length")
        );
        // 4. a body needs exactly one Content-Type of the kinds the inspector parses
        let none: [(&[u8], &[u8]); 1] = [(b"Content-Length", b"3")];
        assert_eq!(
            refused(with(b"/", &none, b"a=b")),
            unsupported("content-type")
        );
        // application/ + a name of `len` characters + +json
        let json_named = |len: usize| [&b"application/"[..], &vec![b'a'; len], b"+json"].concat();
        let too_long = json_named(123);
        for bad in [
            &b"application/xml"[..],
            b"text/plain",
            b"",
            b"application/x-www-form-urlencoded2",
            b"multipart/mixed",
            b"application/json2",
            b"application/jsonp",
            b"text/json",
            // application/<name>+json: no name, a first character that is not a letter or digit, a character
            // outside the set, the name Coraza reads as urlencoded (also in any case), another type, another end,
            // a name one character too long
            b"application/+json",
            b"application/.x+json",
            b"application/-x+json",
            b"application/a+b+json",
            b"application/x/y+json",
            b"application/\xc3\xa9+json",
            b"application/x-www-form-urlencoded+json",
            b"Application/X-WWW-Form-Urlencoded+JSON",
            b"application/x-www-form-urlencoded-x+json",
            b"text/x+json",
            b"application/x+json2",
            b"application/x+jsonp",
            &too_long[..],
        ] {
            let h: [(&[u8], &[u8]); 2] = [(b"Content-Length", b"3"), (b"Content-Type", bad)];
            assert_eq!(
                refused(with(b"/", &h, b"a=b")),
                unsupported("content-type"),
                "{bad:?}"
            );
        }
        let twice: [(&[u8], &[u8]); 3] = [
            (b"Content-Length", b"3"),
            (b"Content-Type", b"application/x-www-form-urlencoded"),
            (b"content-type", b"application/x-www-form-urlencoded"),
        ];
        assert_eq!(
            refused(with(b"/", &twice, b"a=b")),
            unsupported("content-type")
        );
        let mixed: [(&[u8], &[u8]); 3] = [
            (b"Content-Length", b"3"),
            (b"Content-Type", b"application/json"),
            (b"content-type", b"application/x-www-form-urlencoded"),
        ];
        assert_eq!(
            refused(with(b"/", &mixed, b"a=b")),
            unsupported("content-type")
        );
        // what TX_BEGIN cannot carry is refused right after the protocol's limit (1), before the header rules (2 to 4)
        let long_uri = vec![b'a'; 5000];
        assert_eq!(
            refused(with(&long_uri, &HOST, b"")),
            Refused::Invalid("uri length out of range")
        );
        assert_eq!(
            refused(with(&long_uri, &te, b"")),
            Refused::Invalid("uri length out of range")
        );
        assert_eq!(
            refused(Request {
                method: b"",
                ..get(b"/")
            }),
            Refused::Invalid("method length out of range")
        );
        // accepted: the two form types, in any case, with parameters and spaces; an empty body needs no type
        let mut s = Supervisor::new(cfg()).unwrap();
        let ok = |ct: &'static [u8]| -> [(&'static [u8], &'static [u8]); 2] {
            [(b"Content-Length", b"3"), (b"Content-Type", ct)]
        };
        for ct in [
            &b"application/x-www-form-urlencoded"[..],
            b"Application/X-WWW-Form-Urlencoded; charset=UTF-8",
            b"  multipart/form-data ; boundary=x",
        ] {
            s.submit(&with(b"/", &ok(ct), b"a=b")).unwrap();
        }
        let zero: [(&[u8], &[u8]); 1] = [(b"Content-Length", b"0")];
        s.submit(&with(b"/", &zero, b"")).unwrap();
        assert_eq!(s.status().records, 4);
        // accepted: application/json, in any case, with parameters, spaces and tabs
        let mut j = Supervisor::new(cfg()).unwrap();
        for ct in [
            &b"application/json"[..],
            b"Application/JSON; charset=UTF-8",
            b"application/json;charset=utf-8",
            b"  application/json  ",
            b"\tapplication/json\t ; x=y",
        ] {
            j.submit(&with(b"/", &ok(ct), b"[1]")).unwrap();
        }
        assert_eq!(j.status().records, 5);
        // accepted: application/<name>+json, in any case, with parameters; a name of 1 character, one that starts
        // with a digit, one short of the urlencoded name by a character, and the longest name
        let mut n = Supervisor::new(cfg()).unwrap();
        let longest = json_named(122);
        for ct in [
            &b"application/vnd.api+json"[..],
            b"application/problem+json",
            b"application/merge-patch+json",
            b"Application/VND.API+JSON; charset=utf-8",
            b"application/a+json",
            b"application/1x+json",
            b"application/x-www-form-urlencode+json",
            &longest[..],
        ] {
            let h: [(&[u8], &[u8]); 2] = [(b"Content-Length", b"3"), (b"Content-Type", ct)];
            n.submit(&with(b"/", &h, b"[1]")).unwrap();
        }
        assert_eq!(n.status().records, 8);
        // the limit itself, in the largest number of fragments
        let max = vec![b'a'; codec::MAX_DECLARED as usize];
        let h: [(&[u8], &[u8]); 2] = [
            (b"Content-Length", b"1048576"),
            (b"Content-Type", b"application/x-www-form-urlencoded"),
        ];
        s.submit(&with(b"/", &h, &max)).unwrap();
    }

    #[test]
    fn a_full_record_table_refuses_without_a_record() {
        let mut c = cfg();
        (c.slots, c.wait_queue, c.records) = (1, 1, 2);
        let mut s = Supervisor::new(c).unwrap();
        s.submit(&get(b"/a")).unwrap();
        // the queue is full: a record, decided at once
        let b = s.submit(&get(b"/b")).unwrap();
        assert_eq!(s.submit(&get(b"/c")), Err(Refused::Full));
        assert_eq!(s.status().records, 2);
        let sd = s.shutdown(Instant::now());
        assert_eq!(
            sd.results,
            vec![
                (b, Verdict::Uninspectable(Reason::QueueFull)),
                (0, unavailable())
            ]
        );
        // delivered and nothing held: room again, and the numbers go on
        assert_eq!(s.submit(&get(b"/d")), Ok(2));
    }

    #[test]
    fn a_failed_supervisor_keeps_what_it_owns_and_starts_nothing() {
        let mut s = Supervisor::new(cfg()).unwrap();
        s.fail(
            Instant::now(),
            Failure::CleanupUnknown,
            Some(Leftover::Unidentified),
        );
        let a = s.submit(&get(b"/a")).unwrap();
        assert_eq!(s.status().phase, Phase::Failed(Failure::CleanupUnknown));
        // poll starts nothing and only hands the result over
        assert_eq!(s.poll(Instant::now()), vec![(a, unavailable())]);
        assert!(matches!(s.run, Run::Failed { .. }));
        // an entry that cannot be identified stays, for every later shutdown
        for _ in 0..2 {
            let sd = s.shutdown(Instant::now());
            assert_eq!(sd.phase, Phase::Failed(Failure::CleanupUnknown));
            assert!(sd.exit_confirmed && !sd.dir_removed && !sd.bye);
            assert_eq!(sd.results, vec![]);
        }
        assert!(matches!(
            s.run,
            Run::Failed {
                left: Some(Leftover::Unidentified),
                ..
            }
        ));
    }

    /// A 0700 directory of its own under the given parent; only an empty one is removed at the end.
    struct TempRoot(PathBuf);

    impl TempRoot {
        fn under(parent: &Path) -> TempRoot {
            static N: AtomicU32 = AtomicU32::new(0);
            let path = parent.join(format!(
                "sup-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            TempRoot(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn entries(&self) -> usize {
            fs::read_dir(&self.0).unwrap().count()
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir(&self.0);
        }
    }

    #[test]
    fn shutdown_retries_the_removal_of_a_directory_left_behind() {
        let root = TempRoot::under(&std::env::temp_dir());
        let dir = StartDir::create(root.path(), 7, 1).ok().expect("created");
        let path = dir.path().to_path_buf();
        let mut s = Supervisor::new(cfg()).unwrap();
        s.fail(
            Instant::now(),
            Failure::CleanupUnknown,
            Some(Leftover::Dir(dir)),
        );
        assert!(path.is_dir());
        let sd = s.shutdown(Instant::now());
        assert_eq!(sd.phase, Phase::Failed(Failure::CleanupUnknown));
        assert!(sd.exit_confirmed && sd.dir_removed);
        assert!(!path.exists());
        assert_eq!(root.entries(), 0);
        // a directory that is no longer the one that was made is not removed, and stays owned
        let dir = StartDir::create(root.path(), 7, 2).ok().expect("created");
        let path = dir.path().to_path_buf();
        fs::remove_dir(&path).unwrap();
        symlink("/test-only/elsewhere", &path).unwrap();
        s.fail(
            Instant::now(),
            Failure::CleanupUnknown,
            Some(Leftover::Dir(dir)),
        );
        for _ in 0..2 {
            let sd = s.shutdown(Instant::now());
            assert_eq!(sd.phase, Phase::Failed(Failure::CleanupUnknown));
            assert!(sd.exit_confirmed && !sd.dir_removed);
        }
        assert!(fs::symlink_metadata(&path).is_ok());
        fs::remove_file(&path).unwrap();
        assert_eq!(root.entries(), 0);
    }

    // ---- with a built inspector ----

    fn env(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
    }

    fn sha256_from_hex(s: &str) -> [u8; 32] {
        assert!(s.len() == 64 && s.is_ascii(), "64 hex digits are required");
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex digit");
        }
        out
    }

    /// The configuration of the real inspector from the environment of the test run.
    fn real(root: &Path, restarts: u32) -> Config {
        let mut c = cfg();
        c.inspector = PathBuf::from(env("TUKUYOMI_TEST_INSPECTOR"));
        c.rules = PathBuf::from(env("TUKUYOMI_TEST_RULES"));
        c.rules_sha256 = sha256_from_hex(&env("TUKUYOMI_TEST_RULES_SHA256"));
        c.tmp_root = root.to_path_buf();
        c.restarts = restarts;
        c.wait_deadline = secs(20);
        c
    }

    fn real_root() -> TempRoot {
        TempRoot::under(Path::new(&env("TUKUYOMI_TEST_TMP")))
    }

    fn soon() -> Instant {
        Instant::now() + 100 * MS
    }

    fn within(n: u64) -> Instant {
        Instant::now() + secs(n)
    }

    fn until_ready(s: &mut Supervisor) {
        let guard = within(30);
        while !matches!(s.run, Run::Ready { .. }) {
            assert!(Instant::now() < guard, "no HELLO: {:?}", s.status());
            assert!(!matches!(s.run, Run::Failed { .. }), "{:?}", s.status());
            s.step(soon());
        }
    }

    /// The end of every test: the shutdown leaves nothing owned and nothing in the root.
    fn finish(mut s: Supervisor, root: &TempRoot) -> Shutdown {
        let sd = s.shutdown(within(10));
        assert!(sd.exit_confirmed && sd.dir_removed, "{sd:?}");
        assert_eq!((sd.held_left, sd.waiting_left), (0, 0));
        assert_eq!(root.entries(), 0);
        sd
    }

    #[test]
    #[ignore = "needs a built inspector"]
    fn a_request_is_allowed_and_a_shutdown_ends_with_bye() {
        let root = real_root();
        let mut s = Supervisor::new(real(root.path(), 0)).unwrap();
        let a = s.submit(&get(b"/")).unwrap();
        let guard = within(30);
        let mut got = Vec::new();
        while got.is_empty() {
            assert!(Instant::now() < guard, "no result: {:?}", s.status());
            got = s.poll(soon());
        }
        assert_eq!(got, vec![(a, Verdict::Allow)]);
        assert_eq!(s.status().phase, Phase::Ready);
        assert!(root.entries() == 1);
        let sd = finish(s, &root);
        assert!(sd.bye);
        assert_eq!(sd.phase, Phase::Stopped);
        assert_eq!(sd.results, vec![]);
    }

    #[test]
    #[ignore = "needs a built inspector"]
    fn a_request_in_flight_at_shutdown_gets_its_verdict() {
        let root = real_root();
        let mut s = Supervisor::new(real(root.path(), 0)).unwrap();
        until_ready(&mut s);
        let a = s.submit(&get(b"/")).unwrap();
        let sd = s.shutdown(within(10));
        assert_eq!(sd.results, vec![(a, Verdict::Allow)]);
        assert!(sd.bye && sd.exit_confirmed && sd.dir_removed);
        assert_eq!(sd.phase, Phase::Stopped);
        assert_eq!(s.status().inc, 2);
        assert_eq!(root.entries(), 0);
        // nothing starts afterwards, and a new request is decided at once
        let b = s.submit(&get(b"/")).unwrap();
        assert_eq!(s.poll(Instant::now()), vec![(b, unavailable())]);
        assert_eq!(s.status().inc, 2);
    }

    #[test]
    #[ignore = "needs a built inspector"]
    fn a_hello_past_its_deadline_is_a_restart_without_luck() {
        let root = real_root();
        let mut s = Supervisor::new(real(root.path(), 0)).unwrap();
        let a = s.submit(&get(b"/")).unwrap();
        // Down -> launch -> Hello
        s.step(soon());
        let Run::Hello { start, until } = &mut s.run else {
            panic!("not waiting for HELLO");
        };
        // a time that has passed whatever the scheduler did
        *until = start.started.checked_sub(Duration::from_nanos(1)).unwrap();
        s.step(soon());
        assert!(
            matches!(&s.run, Run::Stopping { end: End::Restart(why), .. } if *why == "hello wait")
        );
        let guard = within(30);
        while !matches!(s.run, Run::Failed { .. }) {
            assert!(Instant::now() < guard, "{:?}", s.status());
            s.step(soon());
        }
        let st = s.status();
        assert_eq!(st.phase, Phase::Failed(Failure::BudgetExhausted));
        assert_eq!((st.restarts, st.waiting, st.held), (0, 0, 0));
        assert_eq!(s.poll(Instant::now()), vec![(a, unavailable())]);
        // the directory of the start is gone with the process
        assert_eq!(root.entries(), 0);
        let sd = finish(s, &root);
        assert_eq!(sd.phase, Phase::Failed(Failure::BudgetExhausted));
        // With a restart in the window the same stop is only a restart: the next start is made and inspects.
        let mut s = Supervisor::new(real(root.path(), 1)).unwrap();
        let a = s.submit(&get(b"/")).unwrap();
        s.step(soon());
        let Run::Hello { start, until } = &mut s.run else {
            panic!("not waiting for HELLO");
        };
        *until = start.started.checked_sub(Duration::from_nanos(1)).unwrap();
        s.step(soon());
        assert!(
            matches!(&s.run, Run::Stopping { end: End::Restart(why), .. } if *why == "hello wait")
        );
        until_ready(&mut s);
        let st = s.status();
        assert_eq!((st.phase, st.inc, st.restarts), (Phase::Ready, 2, 1));
        let guard = within(30);
        let mut got = Vec::new();
        while got.is_empty() {
            assert!(Instant::now() < guard, "no result: {:?}", s.status());
            got = s.poll(soon());
        }
        assert_eq!(got, vec![(a, Verdict::Allow)]);
        let sd = finish(s, &root);
        assert!(sd.bye);
        assert_eq!(sd.phase, Phase::Stopped);
    }

    #[test]
    #[ignore = "needs a built inspector"]
    fn a_loss_moves_only_the_request_whose_begin_was_not_taken_to_the_next_start() {
        let root = real_root();
        let mut c = real(root.path(), 1);
        (c.slots, c.wait_deadline) = (4, secs(20));
        let mut s = Supervisor::new(c).unwrap();
        let (a, b) = (
            s.submit(&get(b"/a")).unwrap(),
            s.submit(&get(b"/b")).unwrap(),
        );
        until_ready(&mut s);
        let run_id = s.run_id.unwrap();
        // The first TX_BEGIN (request a) is written. Then no frame is written until a's phase 1 VERDICT is in.
        assert!(s.write_step().is_continue());
        assert_eq!(s.engine.outcome(a).unwrap().txs, vec![1]);
        assert_eq!(s.engine.outcome(b).unwrap().txs, vec![2]);
        let guard = within(30);
        while !s.engine.outcome(a).unwrap().created {
            assert!(Instant::now() < guard, "no verdict: {:?}", s.status());
            assert!(s.check(Instant::now()).is_continue());
            assert!(s.read_step(soon()).is_continue());
        }
        // The inspector is lost with b's TX_BEGIN still in the writer queue; nothing is written any more.
        let Run::Ready { start } = &mut s.run else {
            panic!("not ready");
        };
        start.kill_now().unwrap();
        while !matches!(s.run, Run::Stopping { .. }) {
            assert!(Instant::now() < guard, "loss not seen: {:?}", s.status());
            let _ = s.check(Instant::now());
            let _ = s.read_step(soon());
        }
        // The reap and the restart, with neither `poll` nor `next_done`: the records are read as they are.
        loop {
            assert!(Instant::now() < guard, "{:?}", s.status());
            s.step(soon());
            if s.engine.outcome(b).unwrap().decision.is_some() && s.engine.held_slots() == 0 {
                break;
            }
        }
        let (oa, ob) = (s.engine.outcome(a).unwrap(), s.engine.outcome(b).unwrap());
        // a: taken, so lost, never sent again
        assert_eq!(oa.decision, Some(Decision::Uninspectable(Why::ConnFault)));
        assert_eq!(oa.txs, vec![1]);
        assert_eq!(oa.returns, vec![(1, ReturnReason::ExitConfirmed)]);
        // b: not taken, so it waited for the next start and was inspected there
        assert_eq!(ob.decision, Some(Decision::Forward));
        assert_eq!(ob.txs, vec![2, 3]);
        assert_eq!(
            ob.returns,
            vec![(2, ReturnReason::BeforeBegin), (3, ReturnReason::Closed)]
        );
        assert_eq!(s.status().restarts, 1);
        assert!(
            !root
                .path()
                .join(format!("insp-{run_id:016x}-{:08x}", 1))
                .exists()
        );
        assert_eq!(root.entries(), 1);
        // Delivered once each, in the order they were decided; a delivered record with no slot is gone.
        assert_eq!(
            s.engine.next_done().map(|(i, d)| (i, verdict_of(d))),
            Some((a, Verdict::Uninspectable(Reason::InspectorLost)))
        );
        assert_eq!(
            s.engine.next_done().map(|(i, d)| (i, verdict_of(d))),
            Some((b, Verdict::Allow))
        );
        assert!(s.engine.next_done().is_none());
        assert!(s.engine.outcome(a).is_none() && s.engine.outcome(b).is_none());
        let sd = finish(s, &root);
        assert_eq!(sd.results, vec![]);
        assert_eq!(sd.phase, Phase::Stopped);
    }

    #[test]
    fn a_tmp_root_that_does_not_exist_ends_the_supervisor_at_the_first_start() {
        // `cfg()` names a root that is not there: the start is refused before anything is made
        let mut s = Supervisor::new(cfg()).unwrap();
        let a = s.submit(&get(b"/")).unwrap();
        assert_eq!(s.poll(Instant::now()), vec![(a, unavailable())]);
        let st = s.status();
        assert!(
            matches!(st.phase, Phase::Failed(Failure::TmpDir(_))),
            "{st:?}"
        );
        // the incarnation of the try is used up, and the try is not a restart
        assert_eq!((st.inc, st.restarts, st.waiting, st.held), (2, 0, 0, 0));
        let sd = s.shutdown(Instant::now());
        assert!(sd.exit_confirmed && sd.dir_removed);
        assert_eq!(sd.phase, st.phase);
    }

    fn past() -> Instant {
        Instant::now().checked_sub(MS).unwrap()
    }

    #[test]
    #[ignore = "needs a built inspector"]
    fn a_shutdown_past_its_deadline_kills_at_once_and_decides_everything() {
        let root = real_root();
        // TX_BEGIN still in the writer queue: nothing was sent, so the request is only unavailable
        let mut s = Supervisor::new(real(root.path(), 0)).unwrap();
        until_ready(&mut s);
        let a = s.submit(&get(b"/")).unwrap();
        let sd = s.shutdown(past());
        assert_eq!(sd.results, vec![(a, unavailable())]);
        assert_eq!(sd.phase, Phase::Stopped);
        assert!(!sd.bye && sd.exit_confirmed && sd.dir_removed);
        assert_eq!(root.entries(), 0);
        // TX_BEGIN taken and written: the verdict is not read any more, so it is lost, and not sent again
        let mut s = Supervisor::new(real(root.path(), 0)).unwrap();
        until_ready(&mut s);
        let b = s.submit(&get(b"/")).unwrap();
        assert!(s.write_step().is_continue());
        let sd = s.shutdown(past());
        assert_eq!(
            sd.results,
            vec![(b, Verdict::Uninspectable(Reason::InspectorLost))]
        );
        assert_eq!(sd.phase, Phase::Stopped);
        assert!(!sd.bye && sd.exit_confirmed && sd.dir_removed);
        assert_eq!(root.entries(), 0);
        assert_eq!(s.status().restarts, 0);
    }

    #[test]
    #[ignore = "needs a built inspector"]
    fn a_shutdown_while_hello_is_awaited_stops_the_start() {
        let root = real_root();
        let mut s = Supervisor::new(real(root.path(), 3)).unwrap();
        let a = s.submit(&get(b"/")).unwrap();
        s.step(soon());
        assert!(matches!(s.run, Run::Hello { .. }));
        let sd = s.shutdown(within(10));
        assert_eq!(sd.results, vec![(a, unavailable())]);
        assert_eq!(sd.phase, Phase::Stopped);
        assert!(!sd.bye && sd.exit_confirmed && sd.dir_removed);
        let st = s.status();
        assert_eq!(
            (st.inc, st.restarts),
            (2, 0),
            "no restart after the intake ended"
        );
        assert_eq!(root.entries(), 0);
    }

    #[test]
    #[ignore = "needs a built inspector"]
    fn a_shutdown_in_a_stop_in_progress_does_not_start_again() {
        let root = real_root();
        let mut s = Supervisor::new(real(root.path(), 3)).unwrap();
        let (a, b) = (
            s.submit(&get(b"/a")).unwrap(),
            s.submit(&get(b"/b")).unwrap(),
        );
        until_ready(&mut s);
        assert!(s.write_step().is_continue());
        let Run::Ready { start } = &mut s.run else {
            panic!("not ready");
        };
        start.kill_now().unwrap();
        let guard = within(30);
        while !matches!(s.run, Run::Stopping { .. }) {
            assert!(Instant::now() < guard, "loss not seen: {:?}", s.status());
            let _ = s.check(Instant::now());
            let _ = s.read_step(soon());
        }
        // a was taken: lost with the connection. b waits for the next start, which the shutdown forbids.
        let sd = s.shutdown(past());
        assert_eq!(
            sd.results,
            vec![
                (a, Verdict::Uninspectable(Reason::InspectorLost)),
                (b, unavailable())
            ]
        );
        assert_eq!(sd.phase, Phase::Stopped);
        assert!(!sd.bye && sd.exit_confirmed && sd.dir_removed);
        let st = s.status();
        assert_eq!((st.inc, st.restarts), (2, 0));
        assert_eq!(root.entries(), 0);
    }

    #[test]
    #[ignore = "needs a built inspector"]
    fn a_hello_that_does_not_match_ends_the_supervisor_for_good() {
        let root = real_root();
        let mut c = real(root.path(), 3);
        c.rules_sha256[0] ^= 1;
        let mut s = Supervisor::new(c).unwrap();
        let a = s.submit(&get(b"/")).unwrap();
        let guard = within(30);
        while !matches!(s.run, Run::Failed { .. }) {
            assert!(Instant::now() < guard, "{:?}", s.status());
            s.step(soon());
        }
        let st = s.status();
        assert_eq!(
            st.phase,
            Phase::Failed(Failure::Hello("hello rules sha256 differs"))
        );
        assert_eq!((st.inc, st.restarts), (2, 0));
        assert_eq!(s.poll(Instant::now()), vec![(a, unavailable())]);
        assert_eq!(root.entries(), 0);
        finish(s, &root);
    }

    #[test]
    #[ignore = "needs a built inspector"]
    fn a_start_that_cannot_run_ends_the_supervisor_when_it_may_not_restart() {
        let root = real_root();
        let mut c = real(root.path(), 0);
        c.inspector = root.path().join("missing");
        let mut s = Supervisor::new(c).unwrap();
        let a = s.submit(&get(b"/")).unwrap();
        let guard = within(30);
        while !matches!(s.run, Run::Failed { .. }) {
            assert!(Instant::now() < guard, "{:?}", s.status());
            s.step(soon());
        }
        let st = s.status();
        assert_eq!(st.phase, Phase::Failed(Failure::BudgetExhausted));
        // the one try used up its incarnation, and it was not a restart
        assert_eq!((st.inc, st.restarts), (2, 0));
        assert_eq!(s.poll(Instant::now()), vec![(a, unavailable())]);
        assert_eq!(root.entries(), 0);
        finish(s, &root);
    }

    /// Every start of this supervisor fails (`inspector`). One restart is allowed in a window of 300 ms. It runs
    /// through two whole windows and must never fail, never restart faster than once a window (the number of
    /// restarts is at most one more than the windows that have passed), keep its incarnations in step with the
    /// restarts, and leave a request that waits to its own deadline. A shutdown ends the wait and decides the
    /// request that waits then.
    fn fails_every_start_but_waits_for_the_window(root: &TempRoot, inspector: PathBuf) {
        let mut c = real(root.path(), 1);
        c.inspector = inspector;
        (c.restart_window, c.wait_deadline) = (300 * MS, 400 * MS);
        let window = c.restart_window;
        let mut s = Supervisor::new(c).unwrap();
        let started = Instant::now();
        let a = s.submit(&get(b"/")).unwrap();
        let guard = within(30);
        let mut got = Vec::new();
        while s.status().restarts < 3 {
            assert!(Instant::now() < guard, "{:?}", s.status());
            got.extend(s.poll(soon()));
            let st = s.status();
            assert!(
                matches!(st.phase, Phase::Starting | Phase::Stopping),
                "{st:?}"
            );
            assert!(
                u128::from(st.restarts) <= 1 + started.elapsed().as_nanos() / window.as_nanos(),
                "{st:?}"
            );
            assert!(
                (st.restarts + 1..=st.restarts + 2).contains(&st.inc),
                "{st:?}"
            );
        }
        assert!(started.elapsed() >= 2 * window);
        assert_eq!(got, vec![(a, Verdict::Uninspectable(Reason::WaitDeadline))]);
        let b = s.submit(&get(b"/")).unwrap();
        let sd = finish(s, root);
        assert_eq!(sd.results, vec![(b, unavailable())]);
        assert_eq!(sd.phase, Phase::Stopped);
        assert!(!sd.bye);
    }

    #[test]
    #[ignore = "needs a built inspector"]
    fn a_start_that_cannot_run_is_tried_again_once_a_window_and_never_fails() {
        let root = real_root();
        fails_every_start_but_waits_for_the_window(&root, root.path().join("missing"));
    }

    #[test]
    #[ignore = "needs a built inspector"]
    fn a_start_that_ends_before_hello_is_tried_again_once_a_window_and_never_fails() {
        let root = real_root();
        // exits at once, whatever it is given: the connection ends before any HELLO
        fails_every_start_but_waits_for_the_window(&root, PathBuf::from("/bin/true"));
    }

    #[test]
    #[ignore = "needs a built inspector"]
    fn dropping_a_running_supervisor_stops_it_and_removes_its_directory() {
        let root = real_root();
        let mut s = Supervisor::new(real(root.path(), 0)).unwrap();
        until_ready(&mut s);
        assert_eq!(root.entries(), 1);
        drop(s);
        assert_eq!(root.entries(), 0);
    }

    #[test]
    #[ignore = "needs a built inspector"]
    fn a_start_that_ends_before_hello_ends_the_supervisor_when_it_may_not_restart() {
        let root = real_root();
        let mut c = real(root.path(), 0);
        // exits at once, whatever it is given: the connection ends before any HELLO
        c.inspector = PathBuf::from("/bin/true");
        let mut s = Supervisor::new(c).unwrap();
        let a = s.submit(&get(b"/")).unwrap();
        let guard = within(30);
        while !matches!(s.run, Run::Failed { .. }) {
            assert!(Instant::now() < guard, "{:?}", s.status());
            s.step(soon());
        }
        let st = s.status();
        assert_eq!(st.phase, Phase::Failed(Failure::BudgetExhausted));
        assert_eq!((st.inc, st.restarts), (2, 0));
        assert_eq!(s.poll(Instant::now()), vec![(a, unavailable())]);
        assert_eq!(root.entries(), 0);
        finish(s, &root);
    }
}
