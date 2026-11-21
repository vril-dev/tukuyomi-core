//! The control socket: how another process of this user (the admin process) asks the proxy for its state, to switch
//! an engine to the generation of rules that the rules store chooses for it, and to read the configuration again with
//! a managed version. The path is `admin.control` of the configuration.
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
//! line in time, or goes away, gets no answer. The ops are carried out by the main loop (`Order`), which owns the
//! switcher and the reading of the configuration. `{"op":"status"}` is answered with
//! `{"generation":..,"mode":..,"engine":..,"phase":..,"switching":..,"reloading":..,"ready":..}`: the 64 digits of the
//! generation that serves the default engine, what its rules do (`block` or `detect`), that engine (`coraza` or
//! `modsecurity`), the phase of its kernel (`starting`, `ready`, `stopping`, `stopped` or `failed`), whether a switch
//! is under way, whether a reading of the configuration file again is under way (of SIGHUP or of a reload order), and
//! whether `/readyz` says `ready`. The same object has `engines`, the state of every engine that runs, in the order of
//! their names: `[{"engine":..,"generation":..,"mode":..,"phase":..}, ..]`, in the words of the fields above. An answer
//! without `engines` is the answer of a proxy that runs one engine only. The same object holds the figures of the proxy: `uptime_ms` (the milliseconds since
//! the proxy started), `requests` (the requests of every class of the records, `closed` included, which got no answer,
//! and those of a route that writes no record for them), `blocked` (the requests a rule blocked), `policy_refused` (the
//! requests the access list or the rate limit turned away), `upstream_failures` (the failures of the servers of every
//! upstream group of the configuration in force; they start from 0 when a reading of the configuration file again
//! replaces it, as they do in `/metrics`), `config` (the 64 digits of the SHA-256 of the configuration file in force),
//! `managed` (the 64 digits of the name of the managed version in force, or `null` for a file without `managed`),
//! `resolve_timeout_ms` (the `forward.resolve_timeout_ms` of the configuration in force) and `config_reloads`
//! (`{"replaced":..,"refused":..}`, the readings of the configuration file again by how they ended). The counts are
//! those that `/metrics` shows; an answer without the figures is the answer of an older proxy.
//! `{"op":"switch","engine"?:"<engine>","expect":"<64 digits>"}` reads the rules store for the engine (the default
//! engine if the order names none), and if the generation it chooses is not `expect` it does nothing and answers
//! `refused` (`current changed`). Otherwise it does what SIGUSR1 does for that engine, which starts the engine if it
//! does not run, and answers when the switch has ended, `{"result":..,"generation":..}` with the generation that serves
//! the engine then (`null` if the engine does not run) and, when the result is not `switched`, a `reason`: `unchanged` (`already serving`), `refused` (`current changed`, `store refused`), `failed`
//! (`driver did not take the order`, `not switched`) or `busy` (`starting`, `switch under way`, `too many orders`,
//! `stopping`). A switch is waited for as long as the kernel may take to be ready and a margin; a client that has
//! waited that long gets `busy` and `switch under way`, and the switch goes on.
//! `{"op":"reload","managed":"<64 digits>"}` reads the configuration file again as SIGHUP does (see `reload`), with the
//! managed version of that name in the place of the one that the managed store chooses: its record `current` is not
//! read. The version is read again also when it is the one in force. The order gives the user of the socket no power
//! that the user has not got already by writing `current` and sending SIGHUP, and the name can only be 64 digits, from
//! which the path in the store is made again. The order is answered when the reading has ended, and every answer to it
//! has the managed version in force then, `managed` (64 digits, or `null`): `{"result":"replaced","config":..,
//! "managed":..}` with the SHA-256 of the main file and the version that now serve; `{"result":"refused","reason":..,
//! "detail":..,"managed":..}`, nothing replaced, with the part that refused (`configuration`, `version`, `store`,
//! `upstream`, `tls`, `fixed`, `listener` or `thread`, see `start::Reason`) and the sentence of its record line, or
//! `unmanaged` and `the configuration in force has no managed object`, which is answered before anything else is
//! looked at and starts no reading; or `{"result":"busy","reason":..,"managed":..}` with `starting`, `reload under way`
//! (a reading of SIGHUP or of another order is under way), `too many orders` or `stopping`. A reading is waited for as
//! long as the names of the configuration in force may take to be looked up (`resolve_timeout`) and the margin; a
//! client that has waited that long gets `busy` and `reload under way`, and the reading goes on.
//! A line that is not a request gets `{"result":"error","reason":..}` with `line too long`, `malformed request`,
//! `unknown op`, `bad expect`, `bad engine` or `bad managed`, and a status that the main loop does not answer within 2 s gets `no
//! answer`. Each answer to a switch order or a reload order is one line in the records (`control: switch ..`,
//! `control: reload <64 digits>: <result> (<reason>)`), the busy answers of the connection itself included (the queue
//! of orders is full, the wait is over, the order was dropped); an order that gets such an answer and then ends gets a
//! second line when it ends.

use std::fs;
use std::future::poll_fn;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream as StdStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{Semaphore, mpsc, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{sleep, timeout};
use tukuyomi_kernel::{Engine, Phase};

use self::answer::{EngineLine, reload_line, switch_line};
use self::order::{Ask, SwitchOrder, parse};
use super::host;
use super::start::Refusal;
use super::status::Readiness;
use crate::inbound::conn::{Setup, SharedSetup};
use crate::inbound::session::send_and_close;
use crate::inspect::engines::States;
use crate::log::Log;
use crate::rules::bundle::Fingerprint;

mod answer;
mod order;

pub(super) use self::answer::{Answer, Figures, Outcome, Reloaded};
pub(super) use self::order::{Order, ReloadOrder};

/// The most connections served at once; another one is accepted and closed.
const SEATS: usize = 4;
/// The most bytes of a line, its line feed included.
const LINE_MAX: usize = 4096;
/// The time for the line, and the time to write the answer.
const READ_WAIT: Duration = Duration::from_secs(2);
const WRITE_WAIT: Duration = Duration::from_secs(2);
/// The time a switch is waited for besides the time the kernel may take to be ready, and a reading of the
/// configuration besides the time the names of its servers may take to be looked up.
pub(super) const SWITCH_MARGIN: Duration = Duration::from_secs(5);
/// The pause after an accept failed.
const ACCEPT_PAUSE: Duration = Duration::from_millis(100);

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
    state: watch::Receiver<States>,
    /// The engine of a switch order that names none.
    default_engine: Engine,
    /// How long a switch is waited for.
    switch_wait: Duration,
    /// The setup in force: how long a reading of the configuration is waited for, and the managed version that a busy
    /// answer to a reload order names.
    setup: SharedSetup,
    /// For the record line of a busy answer.
    log: Log,
}

impl Shared {
    /// Hands the request to the main loop and waits for its answer. A reading of the configuration is waited for as
    /// long as the names of the setup in force may take to be looked up, and the margin.
    async fn ask(&self, ask: Ask) -> Answer {
        let (reply, told) = oneshot::channel();
        let (order, wait, late) = match ask {
            Ask::Status => (Order::Status(reply), READ_WAIT, "no answer"),
            Ask::Switch(engine, expect) => (
                Order::Switch(SwitchOrder {
                    engine: engine.unwrap_or(self.default_engine),
                    expect,
                    reply,
                }),
                self.switch_wait,
                "switch under way",
            ),
            Ask::Reload(managed) => (
                Order::Reload(ReloadOrder { managed, reply }),
                self.setup
                    .current()
                    .resolve_timeout
                    .saturating_add(SWITCH_MARGIN),
                "reload under way",
            ),
        };
        match self.orders.try_send(order) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => return self.busy("too many orders", ask),
            Err(TrySendError::Closed(_)) => return self.busy("stopping", ask),
        }
        match timeout(wait, told).await {
            Ok(Ok(answer)) => answer,
            // The order was dropped: the proxy is stopping.
            Ok(Err(_)) => self.busy("stopping", ask),
            Err(_) => self.busy(late, ask),
        }
    }

    /// The answer of a connection that could not get one from the main loop. A switch order and a reload order get
    /// their record line as well; a status gets `no answer`.
    fn busy(&self, reason: &'static str, ask: Ask) -> Answer {
        match ask {
            Ask::Status => Answer::Error("no answer"),
            Ask::Switch(engine, expect) => {
                let engine = engine.unwrap_or(self.default_engine);
                let generation = self.state.borrow().of(engine).map(|state| state.generation);
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
            Ask::Reload(managed) => {
                let reloaded = Reloaded::Busy(reason);
                self.log.line(&reload_line(managed, &reloaded));
                Answer::reload(reloaded, &self.setup.current())
            }
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
    state: watch::Receiver<States>,
    /// The engine whose state the fields of a status answer have besides `engines`.
    default_engine: Engine,
    readiness: Arc<Readiness>,
    /// The switch order whose switch is under way.
    asked: Option<SwitchOrder>,
    /// The reload order whose reading of the configuration is under way.
    reload: Option<ReloadOrder>,
    /// Removes the file after the task is aborted: the fields are dropped in order, after `drop`.
    _guard: Guard,
}

impl Drop for Control {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Starts to serve `bound`. A switch is waited for `switch_wait`, and a reading of the configuration as `setup`, the
/// setup in force, says when it is asked for. `default_engine` is the engine of an order that names none. `log` gets the
/// lines of the busy answers of the connections. The runtime has to be entered.
pub(super) fn serve(
    bound: Bound,
    state: watch::Receiver<States>,
    default_engine: Engine,
    readiness: Arc<Readiness>,
    switch_wait: Duration,
    setup: SharedSetup,
    log: Log,
) -> Control {
    let Bound { listener, guard } = bound;
    let (orders, taken) = mpsc::channel(SEATS);
    let shared = Arc::new(Shared {
        orders,
        state: state.clone(),
        default_engine,
        switch_wait,
        setup,
        log,
    });
    Control {
        task: tokio::spawn(accept(listener, shared)),
        orders: taken,
        state,
        default_engine,
        readiness,
        asked: None,
        reload: None,
        _guard: guard,
    }
}

impl Control {
    /// The next order. `None`: the task is gone and no order will come.
    pub(super) fn poll_order(&mut self, cx: &mut Context<'_>) -> Poll<Option<Order>> {
        self.orders.poll_recv(cx)
    }

    /// The answer to a status order. `switching`: a switch is under way; `reloading`: a reading of the configuration
    /// file again. `figures` are read by the caller.
    pub(super) fn status(&self, switching: bool, reloading: bool, figures: Figures) -> Answer {
        let states = *self.state.borrow();
        let Some(lead) = states
            .of(self.default_engine)
            .or_else(|| states.started().next())
        else {
            return Answer::Error("no answer");
        };
        Answer::Status {
            generation: lead.generation,
            mode: lead.mode.name(),
            engine: lead.engine.name(),
            phase: phase_word(lead.phase),
            switching,
            reloading,
            ready: self.readiness.check(&states).is_ok(),
            figures,
            engines: states
                .started()
                .map(|state| EngineLine {
                    engine: state.engine.name(),
                    generation: state.generation,
                    mode: state.mode.name(),
                    phase: phase_word(state.phase),
                })
                .collect(),
        }
    }

    /// The driver has the switch of this order; the answer is given when it ends.
    pub(super) fn hold(&mut self, order: SwitchOrder) {
        self.asked = Some(order);
    }

    /// The driver answered the switch of `engine` that is under way: the order that asked for it, if there is one and
    /// it is for that engine, gets its answer. `serving` is the generation that serves the engine now.
    pub(super) fn switch_ended(
        &mut self,
        engine: Engine,
        switched: bool,
        serving: Option<Fingerprint>,
        log: &Log,
    ) {
        if self
            .asked
            .as_ref()
            .is_some_and(|order| order.engine() != engine)
        {
            return;
        }
        if let Some(order) = self.asked.take() {
            if switched {
                order.finish(Outcome::Switched, None, serving, log);
            } else {
                order.finish(Outcome::Failed, Some("not switched"), serving, log);
            }
        }
    }

    /// The reading of the configuration of this order is under way; the answer is given when it ends.
    pub(super) fn hold_reload(&mut self, order: ReloadOrder) {
        self.reload = Some(order);
    }

    /// A reading of the configuration file again ended, `Ok` if it replaced the configuration: the order that asked
    /// for it, if there is one, gets its answer. `setup` is the setup in force now.
    pub(super) fn reload_ended(&mut self, reading: Result<(), Refusal>, setup: &Setup, log: &Log) {
        if let Some(order) = self.reload.take() {
            let reloaded = match reading {
                Ok(()) => Reloaded::Replaced,
                Err(refusal) => Reloaded::Refused(refusal),
            };
            order.finish(reloaded, setup, log);
        }
    }
}

#[cfg(test)]
mod tests;
