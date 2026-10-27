//! The control socket: how another process of this user (the admin process) asks the proxy for its state and to
//! switch to the generation of rules that the rules store chooses. The path is `admin.control` of the configuration.
//!
//! The socket is bound after `prepare` and before the driver starts, so a path that cannot be used ends the start
//! before the inspector runs. Its directory must be a real directory owned by this user without group or other bits:
//! that keeps others away from the socket also in the moment between its making and the setting of its mode to
//! 0600. A file at the path is removed only if it is a socket of this user that nobody listens at (what a process
//! that was killed leaves: a connection to it is refused); a socket that takes a connection has a process behind
//! it, and that ends the start, as anything else does. The socket is served from when the driver has started until
//! the first cause of a stop; then it is closed and its file removed, but only if the file is still the one that was
//! made. Nothing but the mode of the file tells clients apart: every process of this user can use it.
//!
//! At most 4 connections are served at once; one that finds no place is accepted and closed. A client sends one line
//! of JSON of at most 4 KiB within 2 s, gets one line of JSON (2 s to write it) and is closed. A client that sends no
//! line in time, or goes away, gets no answer. Both ops are carried out by the main loop (`Order`), which owns the
//! switcher. `{"op":"status"}` is answered with `{"generation":..,"mode":..,"phase":..,"switching":..,"ready":..}`:
//! the 64 digits of the generation that serves, what its rules do (`block` or `detect`), the phase of its kernel
//! (`starting`, `ready`, `stopping`, `stopped` or `failed`), whether a switch is under way, and whether `/readyz`
//! says `ready`. `{"op":"switch","expect":"<64 digits>"}` reads the rules store, and if the generation it chooses is
//! not `expect` it does nothing and answers `refused` (`current changed`). Otherwise it does what SIGUSR1 does and
//! answers when the switch has ended, `{"result":..,"generation":..}` with the generation that serves then and, when
//! the result is not `switched`, a `reason`: `unchanged` (`already serving`), `refused` (`current changed`,
//! `store refused`), `failed` (`driver did not take the order`, `not switched`) or `busy` (`starting`, `switch under
//! way`, `too many orders`, `stopping`). A switch is waited for as long as the kernel may take to be ready and a
//! margin; a client that has waited that long gets `busy` and `switch under way`, and the switch goes on. A line
//! that is not a request gets `{"result":"error","reason":..}` with `line too long`, `malformed request`, `unknown
//! op` or `bad expect`, and a status that the main loop does not answer within 2 s gets `no answer`. Each answer to a
//! switch order is one line in the records (`control: switch ..`), the busy answers of the connection itself included
//! (the queue of orders is full, the wait is over, the order was dropped); an order that gets such an answer and then
//! ends gets a second line when it ends.

use std::fs;
use std::future::poll_fn;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream as StdStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use serde::Deserialize;
use tokio::io::AsyncReadExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{Semaphore, mpsc, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{sleep, timeout};
use tukuyomi_kernel::Phase;

use super::host;
use super::status::Readiness;
use crate::inbound::session::send_and_close;
use crate::inspect::driver::State;
use crate::log::Log;
use crate::rules::bundle::Fingerprint;

/// The most connections served at once; another one is accepted and closed.
const SEATS: usize = 4;
/// The most bytes of a line, its line feed included.
const LINE_MAX: usize = 4096;
/// The time for the line, and the time to write the answer.
const READ_WAIT: Duration = Duration::from_secs(2);
const WRITE_WAIT: Duration = Duration::from_secs(2);
/// The time a switch is waited for besides the time the kernel may take to be ready.
pub(super) const SWITCH_MARGIN: Duration = Duration::from_secs(5);
/// The pause after an accept failed.
const ACCEPT_PAUSE: Duration = Duration::from_millis(100);

/// How a switch order ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    Switched,
    Unchanged,
    Refused,
    Failed,
    Busy,
}

impl Outcome {
    fn word(self) -> &'static str {
        match self {
            Outcome::Switched => "switched",
            Outcome::Unchanged => "unchanged",
            Outcome::Refused => "refused",
            Outcome::Failed => "failed",
            Outcome::Busy => "busy",
        }
    }
}

/// The answer to a line, as the connection writes it.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Answer {
    Status {
        generation: Fingerprint,
        mode: &'static str,
        phase: &'static str,
        switching: bool,
        ready: bool,
    },
    Switch {
        outcome: Outcome,
        reason: Option<&'static str>,
        generation: Fingerprint,
    },
    Error(&'static str),
}

impl Answer {
    /// The line of JSON with its line feed. Every value is a fixed word, a boolean or hexadecimal digits, so
    /// nothing needs to be escaped.
    fn line(&self) -> String {
        match self {
            Answer::Status {
                generation,
                mode,
                phase,
                switching,
                ready,
            } => format!(
                "{{\"generation\":\"{}\",\"mode\":\"{mode}\",\"phase\":\"{phase}\",\"switching\":{switching},\"ready\":{ready}}}\n",
                generation.hex()
            ),
            Answer::Switch {
                outcome,
                reason: Some(reason),
                generation,
            } => format!(
                "{{\"result\":\"{}\",\"reason\":\"{reason}\",\"generation\":\"{}\"}}\n",
                outcome.word(),
                generation.hex()
            ),
            Answer::Switch {
                outcome,
                reason: None,
                generation,
            } => format!(
                "{{\"result\":\"{}\",\"generation\":\"{}\"}}\n",
                outcome.word(),
                generation.hex()
            ),
            Answer::Error(reason) => format!("{{\"result\":\"error\",\"reason\":\"{reason}\"}}\n"),
        }
    }
}

/// The record line of an answer to a switch order. `serving` is the generation that serves then.
fn switch_line(
    expect: Fingerprint,
    outcome: Outcome,
    reason: Option<&'static str>,
    serving: Fingerprint,
) -> String {
    let why = reason.map_or_else(String::new, |reason| format!(" ({reason})"));
    format!(
        "control: switch expect {}: {}{why}, serving {}",
        expect.hex(),
        outcome.word(),
        serving.hex()
    )
}

/// A request to switch, and where its answer goes.
pub(super) struct SwitchOrder {
    expect: Fingerprint,
    reply: oneshot::Sender<Answer>,
}

impl SwitchOrder {
    /// The generation the client expects the store to choose.
    pub(super) fn expect(&self) -> Fingerprint {
        self.expect
    }

    /// Answers the client, and writes the record line of the order. `serving` is the generation that serves now.
    pub(super) fn finish(
        self,
        outcome: Outcome,
        reason: Option<&'static str>,
        serving: Fingerprint,
        log: &Log,
    ) {
        log.line(&switch_line(self.expect, outcome, reason, serving));
        let _ = self.reply.send(Answer::Switch {
            outcome,
            reason,
            generation: serving,
        });
    }
}

/// What a connection asks of the main loop.
pub(super) enum Order {
    Status(oneshot::Sender<Answer>),
    Switch(SwitchOrder),
}

/// What a line asks for.
#[derive(Debug, PartialEq, Eq)]
enum Ask {
    Status,
    Switch(Fingerprint),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    op: String,
    expect: Option<String>,
}

/// What the line asks for, or the word that says why it is not a request.
fn parse(line: &[u8]) -> Result<Ask, &'static str> {
    const MALFORMED: &str = "malformed request";
    let raw: Raw = serde_json::from_slice(line).map_err(|_| MALFORMED)?;
    match (raw.op.as_str(), raw.expect) {
        ("status", None) => Ok(Ask::Status),
        ("switch", Some(expect)) => Fingerprint::from_hex(expect.as_bytes())
            .map(Ask::Switch)
            .ok_or("bad expect"),
        ("status" | "switch", _) => Err(MALFORMED),
        _ => Err("unknown op"),
    }
}

/// The word for the phase of a kernel.
fn phase_word(phase: Phase) -> &'static str {
    match phase {
        Phase::Starting => "starting",
        Phase::Ready => "ready",
        Phase::Stopping => "stopping",
        Phase::Stopped => "stopped",
        Phase::Failed(_) => "failed",
    }
}

/// The file of the socket, which is removed when this is dropped, if it is still the file that was made (the same
/// device and inode).
struct Guard {
    path: PathBuf,
    id: (u64, u64),
}

impl Drop for Guard {
    fn drop(&mut self) {
        let ours = fs::symlink_metadata(&self.path)
            .is_ok_and(|meta| (meta.dev(), meta.ino()) == self.id && meta.file_type().is_socket());
        if ours {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// The socket, bound and not yet served.
pub(super) struct Bound {
    listener: UnixListener,
    guard: Guard,
}

/// Looks at the directory, replaces an old socket of this user that nobody listens at, binds the socket and sets its
/// mode to 0600. The runtime has to be entered. A refusal is a sentence.
pub(super) fn bind(path: &Path) -> Result<Bound, &'static str> {
    let uid = host::fs_uid()?;
    let parent = path.parent().ok_or("the path has no directory")?;
    host::private_dir(parent, uid)?;
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() && meta.uid() == uid => {
            match StdStream::connect(path) {
                // A process listens: the file is not taken away from it.
                Ok(_) => return Err("the control socket is in use by another process"),
                Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                    fs::remove_file(path).map_err(|_| "the old socket cannot be removed")?;
                }
                // Anything else: the file stays, and the bind below refuses.
                Err(_) => {}
            }
        }
        Ok(_) => return Err("something other than a socket of this user is at the path"),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err("the path cannot be looked at"),
    }
    let listener = UnixListener::bind(path).map_err(|_| "the socket cannot be bound")?;
    // The directory is closed to others, so nobody else can connect before the mode is set.
    let made = fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .and_then(|()| fs::symlink_metadata(path));
    match made {
        Ok(meta) => Ok(Bound {
            listener,
            guard: Guard {
                path: path.to_path_buf(),
                id: (meta.dev(), meta.ino()),
            },
        }),
        Err(_) => {
            let _ = fs::remove_file(path);
            Err("the mode of the socket cannot be set")
        }
    }
}

/// What the connections share.
struct Shared {
    orders: mpsc::Sender<Order>,
    state: watch::Receiver<State>,
    /// How long a switch is waited for.
    switch_wait: Duration,
    /// For the record line of a busy answer.
    log: Log,
}

impl Shared {
    /// Hands the request to the main loop and waits for its answer.
    async fn ask(&self, ask: Ask) -> Answer {
        let (reply, told) = oneshot::channel();
        // What a switch order expects; a status order has none.
        let expect = match ask {
            Ask::Status => None,
            Ask::Switch(expect) => Some(expect),
        };
        let order = match expect {
            None => Order::Status(reply),
            Some(expect) => Order::Switch(SwitchOrder { expect, reply }),
        };
        match self.orders.try_send(order) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => return self.busy("too many orders", expect),
            Err(TrySendError::Closed(_)) => return self.busy("stopping", expect),
        }
        let wait = if expect.is_some() {
            self.switch_wait
        } else {
            READ_WAIT
        };
        match timeout(wait, told).await {
            Ok(Ok(answer)) => answer,
            // The order was dropped: the proxy is stopping.
            Ok(Err(_)) => self.busy("stopping", expect),
            Err(_) => self.busy("switch under way", expect),
        }
    }

    /// The answer of a connection that could not get one from the main loop. A switch order (`expect` is there) gets
    /// its record line as well.
    fn busy(&self, reason: &'static str, expect: Option<Fingerprint>) -> Answer {
        let Some(expect) = expect else {
            return Answer::Error("no answer");
        };
        let generation = self.state.borrow().generation;
        self.log.line(&switch_line(
            expect,
            Outcome::Busy,
            Some(reason),
            generation,
        ));
        Answer::Switch {
            outcome: Outcome::Busy,
            reason: Some(reason),
            generation,
        }
    }
}

/// The line the client sent, without its line feed, or why it is not a line. `None`: the client went away. The end of
/// the stream ends a line as well.
async fn read_line(sock: &mut UnixStream) -> Option<Result<Vec<u8>, &'static str>> {
    let mut buf = [0u8; LINE_MAX];
    let mut len = 0;
    loop {
        match sock.read(&mut buf[len..]).await {
            Ok(0) => return (len > 0).then(|| Ok(buf[..len].to_vec())),
            Ok(n) => len += n,
            Err(_) => return None,
        }
        if let Some(end) = buf[..len].iter().position(|&b| b == b'\n') {
            return Some(Ok(buf[..end].to_vec()));
        }
        if len == buf.len() {
            return Some(Err("line too long"));
        }
    }
}

/// Serves one connection: one line, one answer, close.
async fn serve_connection(mut sock: UnixStream, shared: &Shared) {
    let Ok(Some(line)) = timeout(READ_WAIT, read_line(&mut sock)).await else {
        return;
    };
    let answer = match line.and_then(|line| parse(&line)) {
        Ok(ask) => shared.ask(ask).await,
        Err(why) => Answer::Error(why),
    };
    let _ = timeout(
        WRITE_WAIT,
        send_and_close(&mut sock, answer.line().as_bytes()),
    )
    .await;
}

/// Accepts connections for ever; the task ends when `Control` aborts it, and takes its connections with it.
async fn accept(listener: UnixListener, shared: Arc<Shared>) {
    let seats = Arc::new(Semaphore::new(SEATS));
    let mut conns = JoinSet::new();
    loop {
        let accepted = poll_fn(|cx| {
            // A connection that is done is joined here, so the set holds only those that are being served.
            while let Poll::Ready(Some(_)) = conns.poll_join_next(cx) {}
            listener.poll_accept(cx)
        })
        .await;
        match accepted {
            Ok((sock, _)) => match seats.clone().try_acquire_owned() {
                Ok(seat) => {
                    let shared = shared.clone();
                    conns.spawn(async move {
                        let _seat = seat;
                        serve_connection(sock, &shared).await;
                    });
                }
                // No place is free: the connection is closed.
                Err(_) => drop(sock),
            },
            Err(_) => sleep(ACCEPT_PAUSE).await,
        }
    }
}

/// The running socket, the main loop's side of it. Dropping it closes the listener, ends the connections and
/// removes the file of the socket.
pub(super) struct Control {
    task: JoinHandle<()>,
    orders: mpsc::Receiver<Order>,
    state: watch::Receiver<State>,
    readiness: Arc<Readiness>,
    /// The switch order whose switch is under way.
    asked: Option<SwitchOrder>,
    /// Removes the file after the task is aborted: the fields are dropped in order, after `drop`.
    _guard: Guard,
}

impl Drop for Control {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Starts to serve `bound`. A switch is waited for `switch_wait`. `log` gets the lines of the busy answers of the
/// connections. The runtime has to be entered.
pub(super) fn serve(
    bound: Bound,
    state: watch::Receiver<State>,
    readiness: Arc<Readiness>,
    switch_wait: Duration,
    log: Log,
) -> Control {
    let Bound { listener, guard } = bound;
    let (orders, taken) = mpsc::channel(SEATS);
    let shared = Arc::new(Shared {
        orders,
        state: state.clone(),
        switch_wait,
        log,
    });
    Control {
        task: tokio::spawn(accept(listener, shared)),
        orders: taken,
        state,
        readiness,
        asked: None,
        _guard: guard,
    }
}

impl Control {
    /// The next order. `None`: the task is gone and no order will come.
    pub(super) fn poll_order(&mut self, cx: &mut Context<'_>) -> Poll<Option<Order>> {
        self.orders.poll_recv(cx)
    }

    /// The answer to a status order. `switching`: a switch is under way.
    pub(super) fn status(&self, switching: bool) -> Answer {
        let state = *self.state.borrow();
        Answer::Status {
            generation: state.generation,
            mode: state.mode.name(),
            phase: phase_word(state.phase),
            switching,
            ready: self.readiness.check(state.phase).is_ok(),
        }
    }

    /// The driver has the switch of this order; the answer is given when it ends.
    pub(super) fn hold(&mut self, order: SwitchOrder) {
        self.asked = Some(order);
    }

    /// The driver answered the switch that is under way: the order that asked for it, if there is one, gets its
    /// answer. `serving` is the generation that serves now.
    pub(super) fn switch_ended(&mut self, switched: bool, serving: Fingerprint, log: &Log) {
        if let Some(order) = self.asked.take() {
            if switched {
                order.finish(Outcome::Switched, None, serving, log);
            } else {
                order.finish(Outcome::Failed, Some("not switched"), serving, log);
            }
        }
    }
}

#[cfg(test)]
mod tests;
