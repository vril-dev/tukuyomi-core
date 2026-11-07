//! The client of the control socket of the proxy (`admin.control`; `run::control` has the socket and its lines). A
//! question is a connection of its own: one line of JSON out, one line of JSON back, and the close. The line the proxy
//! sends is read for at most 4 KiB. The connect has 2 s. A status question has 2 s, like the proxy gives itself to
//! read the line of the question; a switch has the time the proxy waits for a switch (the time its kernel may take to
//! be ready, and 5 s) and 2 s more, so that the proxy's own `busy` for a switch that takes longer arrives before this
//! client gives up. A reload order has the time its caller gives (see `managed::apply`, for which this client is the
//! proxy: the time the lookup of the names of the proxy may take, and 7 s, for the same reason).
//!
//! The connect of std has no time limit: on a socket whose queue of connections is full it waits until the proxy has
//! taken the others. So the connect is made by tokio, which never waits there (the queue being full is an error at
//! once) and is given the time of a question in any case; the socket then goes on as a blocking std socket. A runtime
//! of its own is made for each connect and ends with it: the handlers run on the threads of the blocking pool of the
//! runtime of the admin process, where a runtime can be driven and dropped, and a runtime that lived longer could be
//! dropped on the thread of the other one, which tokio refuses.
//!
//! No socket, a socket that nobody answers at, a line that is not one of the proxy's, and no line in time are all
//! the same to the caller: the proxy cannot be reached. For a reload order they are `None` instead, an end that is
//! not known, for the order may have come to the proxy and its reading may go on. A connection that the proxy takes
//! and closes before it says
//! anything is another case: the proxy has no place for it (it serves 4 connections at once). A status question that
//! meets it is asked once more after 250 ms, and then the answer is `Seen::Busy`; a switch order that meets it is
//! `Reply::Busy`, which is also what the order of a switch that goes on is. A reload order that meets it has no answer
//! (`None`), as when no line came in time: the reading may or may not go on. A line is taken only if it has the fields
//! of an answer, 64 digits for the generation and one of the words of the proxy for the rest. The figures of a status
//! (`reloading`, `uptime_ms`, `requests`, `blocked`, `policy_refused`, `upstream_failures`, `config`, `managed`,
//! `resolve_timeout_ms` and `config_reloads`) are not needed for that: a proxy of an older version does not send them,
//! and each one that is missing is `None`, as `managed` is when it is `null`. One that is there and is not what it
//! should be (a boolean or a number; for `config` and `managed`, 64 lowercase digits; for `resolve_timeout_ms`, 1 ms
//! to 3600 s, the range that the configuration allows) makes the line one that is not
//! the proxy's. The answer to a reload order is taken only if its `result` is one of `replaced`, `refused`, `busy` and
//! `error`, its `reason` one of the words of that result (none for `replaced`), `config` 64 lowercase digits for
//! `replaced` and nothing else, `managed` 64 lowercase digits or `null` (none for `error`), and `detail`, for `refused`
//! only, 1 to 512 bytes from 0x20 to 0x7e. The answer of a proxy that does not know the order (`error`, `unknown op`)
//! is such a line.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{Value, json};
use tokio::runtime::Builder;
use tokio::time::timeout;
use tukuyomi_kernel::Engine;

use crate::managed::apply::{self, Answered, Look};
use crate::rules::bundle::{Fingerprint, hex};

/// The longest line of an answer in bytes, its line feed included.
const LINE_MAX: usize = 4096;
const ASK_WAIT: Duration = Duration::from_secs(2);
/// The time before a status question that found the proxy without a place is asked again.
const ASK_AGAIN: Duration = Duration::from_millis(250);
const STATUS: &str = "{\"op\":\"status\"}\n";
/// What a switch is waited for besides the time the kernel may take to be ready: the proxy's 5 s and 2 s more.
const SWITCH_EXTRA: Duration = Duration::from_secs(7);
const MODES: [&str; 2] = ["block", "detect"];
const PHASES: [&str; 5] = ["starting", "ready", "stopping", "stopped", "failed"];
/// The words of the reason of an answer to a reload order, by its result.
pub(crate) const REFUSED: [&str; 9] = [
    "configuration",
    "version",
    "store",
    "upstream",
    "tls",
    "fixed",
    "listener",
    "thread",
    "unmanaged",
];
pub(crate) const BUSY: [&str; 4] = [
    "starting",
    "reload under way",
    "too many orders",
    "stopping",
];
pub(crate) const ERRORS: [&str; 5] = [
    "line too long",
    "malformed request",
    "unknown op",
    "bad expect",
    "bad managed",
];
/// The longest sentence of a refused reload order, in bytes.
const DETAIL_MAX: usize = 512;

/// The state of the proxy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    /// The generation that serves.
    pub generation: Fingerprint,
    pub mode: &'static str,
    /// The engine that applies the rules of the generation.
    pub engine: &'static str,
    pub phase: &'static str,
    /// A switch is under way.
    pub switching: bool,
    pub ready: bool,
    // The figures that a proxy adds to its state; a figure that the proxy does not send is `None`.
    /// A reading of the configuration file again is under way.
    pub reloading: Option<bool>,
    /// The milliseconds since the proxy started.
    pub uptime_ms: Option<u64>,
    /// The answers written to clients, of every class.
    pub requests: Option<u64>,
    /// The requests that a rule blocked.
    pub blocked: Option<u64>,
    /// The requests that the access list or the rate limit turned away.
    pub policy_refused: Option<u64>,
    /// The failures of the servers of the upstream groups of the configuration in force.
    pub upstream_failures: Option<u64>,
    /// The SHA-256 of the configuration file in force.
    pub config: Option<[u8; 32]>,
    /// The name of the managed version in force.
    pub managed: Option<[u8; 32]>,
    /// The `forward.resolve_timeout_ms` of the configuration in force.
    pub resolve_timeout_ms: Option<u64>,
    /// The readings of the configuration file again, by how they ended.
    pub config_reloads: Option<Reloads>,
}

/// The readings of the configuration file again, by how they ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
pub struct Reloads {
    pub replaced: u64,
    pub refused: u64,
}

impl Status {
    pub fn json(&self) -> Value {
        json!({
            "generation": self.generation.hex(),
            "mode": self.mode,
            "engine": self.engine,
            "phase": self.phase,
            "switching": self.switching,
            "reloading": self.reloading,
            "ready": self.ready,
            "uptime_ms": self.uptime_ms,
            "requests": self.requests,
            "blocked": self.blocked,
            "policy_refused": self.policy_refused,
            "upstream_failures": self.upstream_failures,
            "config": self.config.map(|sha256| hex(&sha256)),
            "managed": self.managed.map(|name| hex(&name)),
            "resolve_timeout_ms": self.resolve_timeout_ms,
            "config_reloads": self.config_reloads.map(|reloads| json!({
                "replaced": reloads.replaced,
                "refused": reloads.refused,
            })),
        })
    }
}

/// What a question about the state of the proxy found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Seen {
    /// The state of the proxy. It is boxed: with its figures it is much larger than the other two.
    State(Box<Status>),
    /// The proxy takes the connection and closes it without an answer: it has no place for it just now.
    Busy,
    /// The proxy cannot be reached.
    Unreachable,
}

impl Seen {
    /// The state, if it was read.
    pub fn state(&self) -> Option<Status> {
        match self {
            Seen::State(status) => Some(**status),
            Seen::Busy | Seen::Unreachable => None,
        }
    }

    /// Whether there is a proxy that takes connections: a busy one is not unreachable.
    pub fn reachable(&self) -> bool {
        *self != Seen::Unreachable
    }
}

/// How the proxy answered a switch order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reply {
    Switched,
    Unchanged,
    Refused,
    Failed,
    /// The switch is not finished, or the order was not taken.
    Busy,
}

/// How the proxy answered a reload order, with the managed version in force that it named (`None` for `null`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reloaded {
    /// The configuration was replaced: the SHA-256 of the main file in force.
    Replaced {
        config: [u8; 32],
        managed: Option<[u8; 32]>,
    },
    /// Nothing was replaced: the part that refused, and the sentence of the record line of the proxy.
    Refused {
        reason: &'static str,
        detail: String,
        managed: Option<[u8; 32]>,
    },
    Busy {
        reason: &'static str,
        managed: Option<[u8; 32]>,
    },
    /// The proxy did not take the line for an order: for a proxy that does not know it, `unknown op`.
    Error(&'static str),
}

/// What a question got back.
enum Heard {
    /// The one line, without its line feed.
    Line(Vec<u8>),
    /// The proxy took the connection and closed it before it said anything.
    Closed,
    /// Anything else: no connection, no line in time, a line that is too long or is not one line.
    Nothing,
}

#[derive(Deserialize)]
struct StatusLine {
    generation: String,
    mode: String,
    engine: String,
    phase: String,
    switching: bool,
    ready: bool,
    // The figures: a field that is missing is `None`.
    reloading: Option<bool>,
    uptime_ms: Option<u64>,
    requests: Option<u64>,
    blocked: Option<u64>,
    policy_refused: Option<u64>,
    upstream_failures: Option<u64>,
    config: Option<String>,
    managed: Option<String>,
    resolve_timeout_ms: Option<u64>,
    config_reloads: Option<Reloads>,
}

#[derive(Deserialize)]
struct SwitchLine {
    result: String,
    generation: String,
}

#[derive(Deserialize)]
struct ReloadLine {
    result: String,
    reason: Option<String>,
    detail: Option<String>,
    config: Option<String>,
    managed: Option<String>,
}

/// The socket of a proxy.
pub struct Control {
    path: PathBuf,
    ask_wait: Duration,
    switch_wait: Duration,
}

/// The word of `words` that `text` is.
fn word(text: &str, words: &[&'static str]) -> Option<&'static str> {
    words.iter().copied().find(|word| *word == text)
}

/// Whether the error says that the other end of the connection is gone: it closed the connection before the question
/// was written, or with the question unread.
fn hung_up(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
    )
}

/// The state that `line` holds.
fn status_of(line: &[u8]) -> Option<Status> {
    let line: StatusLine = serde_json::from_slice(line).ok()?;
    Some(Status {
        generation: Fingerprint::from_hex(line.generation.as_bytes())?,
        mode: word(&line.mode, &MODES)?,
        engine: Engine::parse(&line.engine)?.name(),
        phase: word(&line.phase, &PHASES)?,
        switching: line.switching,
        ready: line.ready,
        reloading: line.reloading,
        uptime_ms: line.uptime_ms,
        requests: line.requests,
        blocked: line.blocked,
        policy_refused: line.policy_refused,
        upstream_failures: line.upstream_failures,
        config: match line.config {
            Some(text) => Some(Fingerprint::from_hex(text.as_bytes())?.bytes()),
            None => None,
        },
        managed: match line.managed {
            Some(text) => Some(Fingerprint::from_hex(text.as_bytes())?.bytes()),
            None => None,
        },
        resolve_timeout_ms: match line.resolve_timeout_ms {
            // The range of `forward.resolve_timeout_ms` that the configuration takes (`config::MAX_MS`).
            Some(ms) if !(1..=crate::config::MAX_MS).contains(&ms) => return None,
            ms => ms,
        },
        config_reloads: line.config_reloads,
    })
}

/// The 32 bytes of `text`, 64 lowercase digits; `Some(None)` for none.
fn digits(text: Option<&str>) -> Option<Option<[u8; 32]>> {
    match text {
        Some(text) => Some(Some(Fingerprint::from_hex(text.as_bytes())?.bytes())),
        None => Some(None),
    }
}

/// The answer to a reload order that `line` holds, by the rules of the module documentation.
fn reloaded_of(line: &[u8]) -> Option<Reloaded> {
    let line: ReloadLine = serde_json::from_slice(line).ok()?;
    let reason = |words: &[&'static str]| word(line.reason.as_deref()?, words);
    let managed = digits(line.managed.as_deref())?;
    let (config, detail) = (line.config.as_deref(), line.detail.as_deref());
    match (line.result.as_str(), config, detail) {
        ("replaced", Some(config), None) if line.reason.is_none() => Some(Reloaded::Replaced {
            config: digits(Some(config))??,
            managed,
        }),
        ("refused", None, Some(detail))
            if (1..=DETAIL_MAX).contains(&detail.len())
                && detail.bytes().all(|b| (0x20..=0x7e).contains(&b)) =>
        {
            Some(Reloaded::Refused {
                reason: reason(&REFUSED)?,
                detail: detail.to_owned(),
                managed,
            })
        }
        ("busy", None, None) => Some(Reloaded::Busy {
            reason: reason(&BUSY)?,
            managed,
        }),
        ("error", None, None) if managed.is_none() => Some(Reloaded::Error(reason(&ERRORS)?)),
        _ => None,
    }
}

/// The answer to a switch order that `line` holds.
fn reply_of(line: &[u8]) -> Option<Reply> {
    let line: SwitchLine = serde_json::from_slice(line).ok()?;
    Fingerprint::from_hex(line.generation.as_bytes())?;
    match line.result.as_str() {
        "switched" => Some(Reply::Switched),
        "unchanged" => Some(Reply::Unchanged),
        "refused" => Some(Reply::Refused),
        "failed" => Some(Reply::Failed),
        "busy" => Some(Reply::Busy),
        _ => None,
    }
}

impl Control {
    /// The socket at `path` of a proxy whose kernel may take `ready_wait` to be ready.
    pub fn new(path: &Path, ready_wait: Duration) -> Control {
        Control {
            path: path.to_path_buf(),
            ask_wait: ASK_WAIT,
            switch_wait: ready_wait.saturating_add(SWITCH_EXTRA),
        }
    }

    /// The state of the proxy. A proxy that has no place for the question is asked again once, after `ASK_AGAIN`.
    pub fn status(&self) -> Seen {
        let mut heard = self.ask(STATUS, self.ask_wait);
        if matches!(heard, Heard::Closed) {
            sleep(ASK_AGAIN);
            heard = self.ask(STATUS, self.ask_wait);
        }
        match heard {
            Heard::Line(line) => {
                status_of(&line).map_or(Seen::Unreachable, |status| Seen::State(Box::new(status)))
            }
            Heard::Closed => Seen::Busy,
            Heard::Nothing => Seen::Unreachable,
        }
    }

    /// Orders the proxy to switch to the generation the rules store chooses, if that is `expect`. None: the proxy
    /// cannot be reached.
    pub fn switch(&self, expect: Fingerprint) -> Option<Reply> {
        let request = format!("{{\"op\":\"switch\",\"expect\":\"{}\"}}\n", expect.hex());
        match self.ask(&request, self.switch_wait) {
            Heard::Line(line) => reply_of(&line),
            // The proxy has no place for the order, which it did not read.
            Heard::Closed => Some(Reply::Busy),
            Heard::Nothing => None,
        }
    }

    /// Orders the proxy to read the configuration again with the managed version `managed`, and waits `wait` for the
    /// answer. None: no answer of the proxy (it cannot be reached, it closed the connection without a line, no line
    /// came in time, or the line is not one of the proxy's).
    pub fn reload(&self, managed: [u8; 32], wait: Duration) -> Option<Reloaded> {
        let request = format!("{{\"op\":\"reload\",\"managed\":\"{}\"}}\n", hex(&managed));
        match self.ask(&request, wait) {
            Heard::Line(line) => reloaded_of(&line),
            Heard::Closed | Heard::Nothing => None,
        }
    }

    /// The connection to the socket, made within the time of a question. None: it was not made.
    fn connect(&self) -> Option<UnixStream> {
        let runtime = Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .ok()?;
        runtime.block_on(async {
            let sock = timeout(self.ask_wait, tokio::net::UnixStream::connect(&self.path))
                .await
                .ok()?
                .ok()?;
            let sock = sock.into_std().ok()?;
            sock.set_nonblocking(false).ok()?;
            Some(sock)
        })
    }

    /// Sends `request` and reads the one line that comes back, within `wait`. The line is returned without its line
    /// feed.
    fn ask(&self, request: &str, wait: Duration) -> Heard {
        let Some(mut sock) = self.connect() else {
            return Heard::Nothing;
        };
        if sock.set_write_timeout(Some(self.ask_wait)).is_err() {
            return Heard::Nothing;
        }
        match sock.write_all(request.as_bytes()) {
            Ok(()) => {}
            Err(e) if hung_up(&e) => return Heard::Closed,
            Err(_) => return Heard::Nothing,
        }
        let Some(by) = Instant::now().checked_add(wait) else {
            return Heard::Nothing;
        };
        let mut line = Vec::new();
        let mut chunk = [0u8; 512];
        loop {
            let left = by.saturating_duration_since(Instant::now());
            if left.is_zero() || sock.set_read_timeout(Some(left)).is_err() {
                return Heard::Nothing;
            }
            match sock.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => line.extend_from_slice(&chunk[..n]),
                Err(e) if line.is_empty() && hung_up(&e) => return Heard::Closed,
                Err(_) => return Heard::Nothing,
            }
            if line.len() > LINE_MAX {
                return Heard::Nothing;
            }
        }
        if line.is_empty() {
            return Heard::Closed;
        }
        // One line, ended by its line feed.
        match line.strip_suffix(b"\n") {
            Some(text) if !text.contains(&b'\n') => Heard::Line(text.to_vec()),
            _ => Heard::Nothing,
        }
    }
}

/// The proxy of the order that puts a managed version in force (`managed::apply`), in its words.
impl apply::Proxy for Control {
    fn status(&self) -> Look {
        match Control::status(self) {
            Seen::State(status) => Look::State(apply::State {
                config: status.config,
                managed: status.managed,
                reloading: status.reloading,
                resolve_timeout: status.resolve_timeout_ms.map(Duration::from_millis),
                replaced: status.config_reloads.map(|reloads| reloads.replaced),
            }),
            Seen::Busy => Look::Busy,
            Seen::Unreachable => Look::Unreachable,
        }
    }

    fn reload(&self, to: [u8; 32], wait: Duration) -> Answered {
        match Control::reload(self, to, wait) {
            Some(Reloaded::Replaced { config, managed }) => Answered::Replaced { config, managed },
            Some(Reloaded::Refused { reason, detail, .. }) => Answered::Refused { reason, detail },
            Some(Reloaded::Busy { reason, .. }) => Answered::Busy(reason),
            Some(Reloaded::Error(reason)) => Answered::Error(reason),
            None => Answered::Nothing,
        }
    }
}

#[cfg(test)]
mod tests;
