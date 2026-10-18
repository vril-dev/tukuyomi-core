//! The single owner of the engine, of the current start and of the times of the restarts.
//!
//! One thread drives everything. `poll` and `shutdown` repeat `step`: the engine's clock and halt are looked at
//! first, then the frames the engine has queued at that moment are written (and DRAIN, through the same writer),
//! then at most one frame is read. There is no reader thread.
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
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::process::child::Exit;
use crate::process::start::{self, Start, StartDir, Stopping};
use crate::protocol::codec;
use crate::requests::state::{Decision, Engine, Halt, OutKind, Why};

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
/// or inspected in part, is `Uninspectable`. `Detected` is an `Allow` in which a rule matched while the rules only
/// detect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Detected {
        rule_id: i64,
        /// The value the inspector sent, as it is: what the rule would have blocked with.
        status: u16,
    },
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
/// the queued frames but reads none (the wait for the first byte is over before it begins), so a caller must not
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
    /// The line an inspector left in `start-failure` when its start ended in a refusal (`start_detail`).
    detail: Option<Vec<u8>>,
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
        Decision::Detected { rule_id, status } => Verdict::Detected { rule_id, status },
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
    if let Some(code) = exit.as_ref().and_then(start::refusal) {
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

mod intake;
mod lifecycle;
mod stream;

#[cfg(test)]
mod tests;
