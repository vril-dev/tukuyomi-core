//! The client of the control socket of the proxy (`admin.control`; `run::control` has the socket and its lines). A
//! question is a connection of its own: one line of JSON out, one line of JSON back, and the close. The line the proxy
//! sends is read for at most 4 KiB. The connect has 2 s. A status question has 2 s, like the proxy gives itself to
//! read the line of the question; a switch has the time the proxy waits for a switch (the time its kernel may take to
//! be ready, and 5 s) and 2 s more, so that the proxy's own `busy` for a switch that takes longer arrives before this
//! client gives up.
//!
//! The connect of std has no time limit: on a socket whose queue of connections is full it waits until the proxy has
//! taken the others. So the connect is made by tokio, which never waits there (the queue being full is an error at
//! once) and is given the time of a question in any case; the socket then goes on as a blocking std socket. A runtime
//! of its own is made for each connect and ends with it: the handlers run on the threads of the blocking pool of the
//! runtime of the admin process, where a runtime can be driven and dropped, and a runtime that lived longer could be
//! dropped on the thread of the other one, which tokio refuses.
//!
//! No socket, a socket that nobody answers at, a line that is not one of the proxy's, and no line in time are all
//! the same to the caller: the proxy cannot be reached. A connection that the proxy takes and closes before it says
//! anything is another case: the proxy has no place for it (it serves 4 connections at once). A status question that
//! meets it is asked once more after 250 ms, and then the answer is `Seen::Busy`; a switch order that meets it is
//! `Reply::Busy`, which is also what the order of a switch that goes on is. A line is taken only if it has the fields
//! of an answer, 64 digits for the generation and one of the words of the proxy for the rest.

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

use crate::rules::bundle::Fingerprint;

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
}

impl Status {
    pub fn json(&self) -> Value {
        json!({
            "generation": self.generation.hex(),
            "mode": self.mode,
            "engine": self.engine,
            "phase": self.phase,
            "switching": self.switching,
            "ready": self.ready,
        })
    }
}

/// What a question about the state of the proxy found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Seen {
    /// The state of the proxy.
    State(Status),
    /// The proxy takes the connection and closes it without an answer: it has no place for it just now.
    Busy,
    /// The proxy cannot be reached.
    Unreachable,
}

impl Seen {
    /// The state, if it was read.
    pub fn state(self) -> Option<Status> {
        match self {
            Seen::State(status) => Some(status),
            Seen::Busy | Seen::Unreachable => None,
        }
    }

    /// Whether there is a proxy that takes connections: a busy one is not unreachable.
    pub fn reachable(self) -> bool {
        self != Seen::Unreachable
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
}

#[derive(Deserialize)]
struct SwitchLine {
    result: String,
    generation: String,
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
    })
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
            Heard::Line(line) => status_of(&line).map_or(Seen::Unreachable, Seen::State),
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

#[cfg(test)]
mod tests;
