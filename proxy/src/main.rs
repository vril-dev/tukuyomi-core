#![forbid(unsafe_code)]
//! The proxy process: start-up, the wait for the kernel, the accept loop and the stop. When the first argument is
//! `rules` the process is a short command on the rules store instead (`rules::command`), and nothing of the proxy
//! starts.
//!
//! Start-up runs in this order: the logger thread, one argument (the absolute clean path of the configuration
//! file), the host checks, the configuration, the rules store (the chosen generation, the hold on it, its directory,
//! mode and routes, and with them the kernel configuration), the runtime and the signal handlers, the driver
//! thread, the wait for the kernel to be ready, bind, accept. The rules store is read here, and again when SIGUSR1
//! comes. Handlers exist for SIGTERM, SIGINT, SIGHUP and SIGUSR1 only and are installed before the kernel starts
//! its child process; SIGCHLD is never handled. The listener is bound only after the kernel is ready, and a
//! connection permit is taken before every accept.
//!
//! SIGUSR1 makes the proxy switch to the generation that the rules store chooses now (`rules::switch` reads the
//! store, the driver starts the new inspector and moves the requests over when it is ready). It is a line in the
//! records and nothing else before the listener is bound, while a switch is under way, and while the proxy stops.
//!
//! The first cause of a stop (a signal, or a failure of start-up or of the driver) fixes the time `t0`. The stop
//! closes the listener, tells the driver to finish inspecting by `t0 + stop_inspect`, waits for the connections
//! until `t0 + stop_wait` and aborts what is left, then waits for the driver's end until
//! `t0 + stop_wait + kill_grace`. The exit code is 0 only when the stop was not caused by a failure and the driver
//! reports a stopped kernel whose child exit and per-start directory removal are confirmed, and the same for every
//! kernel that was stopped before it; 1 for any other end, and for a refused rules store or generation (nothing
//! has been started then); 2 for a wrong argument or a refused configuration. The log is flushed for at most
//! 200 ms at the end.

use std::ffi::OsString;
use std::future::{Future, poll_fn};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::mpsc::SyncSender;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::{AcquireError, OwnedSemaphorePermit, Semaphore, oneshot};
use tokio::task::{JoinError, JoinSet};
use tokio::time::{Instant, Sleep, sleep, timeout_at};
use tukuyomi_kernel::{Failure, Phase};
use tukuyomi_proxy::config::{self, ProxyConfig};
use tukuyomi_proxy::host;
use tukuyomi_proxy::inbound::conn::{self, Ctx};
use tukuyomi_proxy::inspect::driver::{self, Driver, End, Limits, Msg, Switch, Switched};
use tukuyomi_proxy::log::{self, Log};
use tukuyomi_proxy::rules::bundle::{Fingerprint, Mode};
use tukuyomi_proxy::rules::command;
use tukuyomi_proxy::rules::routes::{Routes, SharedRoutes};
use tukuyomi_proxy::rules::store;
use tukuyomi_proxy::rules::switch::{Next, Switcher};

const EXIT_OK: u8 = 0;
const EXIT_FAILED: u8 = 1;
const EXIT_USAGE: u8 = 2;
/// The longest the end of the process waits for the logger.
const FLUSH_WAIT: Duration = Duration::from_millis(200);
/// The pause of the accept loop after the system ran out of a resource.
const ACCEPT_PAUSE: Duration = Duration::from_millis(100);
/// Linux errno values (the same on x86_64 and aarch64).
const ENOMEM: i32 = 12;
const ENFILE: i32 = 23;
const EMFILE: i32 = 24;
const ENOBUFS: i32 = 105;

fn main() -> ExitCode {
    let log = match log::start_logger() {
        Ok(log) => log,
        Err(text) => {
            let _ = writeln!(io::stderr(), "{text}");
            return ExitCode::from(EXIT_FAILED);
        }
    };
    log::install_panic_hook(log.clone());
    // A panic on this thread is reported through the log and ends the process with the failure code.
    let code = panic::catch_unwind(AssertUnwindSafe(|| start(&log))).unwrap_or(EXIT_FAILED);
    log.flush(FLUSH_WAIT);
    ExitCode::from(code)
}

/// Everything before the runtime runs, then the runtime. Returns the exit code.
fn start(log: &Log) -> u8 {
    let mut args = std::env::args_os().skip(1).peekable();
    if args.peek().is_some_and(|arg| arg == "rules") {
        args.next();
        let args: Vec<OsString> = args.collect();
        return match command::run(&args, &mut io::stdout(), &mut io::stderr()) {
            command::Exit::Done => EXIT_OK,
            command::Exit::Failed => EXIT_FAILED,
            command::Exit::Usage => EXIT_USAGE,
        };
    }
    let path = match (args.next(), args.next()) {
        (Some(path), None) if config::clean_abs(Path::new(&path)) => PathBuf::from(path),
        _ => {
            log.line(
                "start: expected one argument, the absolute clean path of the configuration file",
            );
            return EXIT_USAGE;
        }
    };
    if let Err(text) = host::check() {
        log.line(&format!("start: host check refused: {text}"));
        return EXIT_FAILED;
    }
    let loaded = match config::load(&path) {
        Ok(loaded) => loaded,
        Err(e) => {
            log.line(&format!("start: configuration refused: {}", e.0));
            return EXIT_USAGE;
        }
    };
    log.line("start: configuration accepted");
    let rules = match store::open(&loaded.store) {
        Ok(rules) => rules,
        Err(e) => {
            log.line(&format!("start: rules store refused: {}", e.0));
            return EXIT_FAILED;
        }
    };
    let generation = match rules.current() {
        Ok(Some(generation)) => generation,
        Ok(None) => {
            log.line("start: rules store refused: no generation is chosen");
            return EXIT_FAILED;
        }
        Err(e) => {
            log.line(&format!("start: rules store refused: {}", e.0));
            return EXIT_FAILED;
        }
    };
    // The hold comes before the directory is looked at: a removal that has finished is found there, and one that
    // is going on keeps the hold from being taken.
    let hold = match rules.hold(generation) {
        Ok(hold) => hold,
        Err(e) => {
            log.line(&format!("start: rules store refused: {}", e.0));
            return EXIT_FAILED;
        }
    };
    let dir = match rules.generation_dir(generation) {
        Ok(dir) => dir,
        Err(e) => {
            log.line(&format!("start: rules store refused: {}", e.0));
            return EXIT_FAILED;
        }
    };
    let mode = match rules.mode(generation) {
        Ok(mode) => mode,
        Err(e) => {
            log.line(&format!("start: rules store refused: {}", e.0));
            return EXIT_FAILED;
        }
    };
    let routes = match rules.routes(generation) {
        Ok(routes) => routes,
        Err(e) => {
            log.line(&format!("start: rules store refused: {}", e.0));
            return EXIT_FAILED;
        }
    };
    let kernel = match loaded.kernel.for_generation(dir, generation) {
        Ok(kernel) => kernel,
        Err(e) => {
            log.line(&format!("start: rules generation refused: {}", e.0));
            return EXIT_FAILED;
        }
    };
    log.line(&format!("start: rules generation {}", generation.hex()));
    log.line(&format!("start: rules mode {}", mode.name()));
    log.line(&format!("start: rules routes {}", routes.len()));
    let switcher = Switcher::new(rules, loaded.kernel, generation, hold);
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            log.line("start: cannot build the runtime");
            return EXIT_FAILED;
        }
    };
    runtime.block_on(run(
        loaded.proxy,
        kernel,
        generation,
        mode,
        routes,
        switcher,
        log.clone(),
    ))
}

/// The runtime part: handlers, driver, the wait for ready, serving, and the stop. The holds of the switcher live
/// to the end, so the generations in use are held until the stop is over.
async fn run(
    proxy: ProxyConfig,
    kernel: tukuyomi_kernel::Config,
    generation: Fingerprint,
    mode: Mode,
    routes: Routes,
    mut switcher: Switcher,
    log: Log,
) -> u8 {
    let signals = match Signals::install() {
        Ok(signals) => signals,
        Err(_) => {
            log.line("start: cannot install the signal handlers");
            return EXIT_FAILED;
        }
    };
    let wait_queue = kernel.wait_queue;
    let kill_grace = kernel.kill_grace;
    let limits = Limits {
        slice: proxy.drive_slice,
        ready_wait: proxy.ready_wait,
        stop_inspect: proxy.stop_inspect,
    };
    // The connections read the routes of the generation that serves, and the driver replaces them when another
    // generation takes over.
    let routes = SharedRoutes::new(routes);
    let driver = match driver::start(
        kernel,
        generation,
        mode,
        routes.clone(),
        limits,
        log.clone(),
    ) {
        Ok(driver) => driver,
        Err(text) => {
            log.line(&format!("start: cannot start the driver: {text}"));
            return EXIT_FAILED;
        }
    };
    let Driver {
        ingress,
        ready,
        failed,
        end,
    } = driver;
    let mut waits = Waits::new(signals, ready, failed, end);
    let cause = until_stop(
        &mut waits,
        &proxy,
        wait_queue,
        &ingress,
        &routes,
        &mut switcher,
        &log,
    )
    .await;
    stop(waits, cause, ingress, &proxy, kill_grace, &log).await
}

/// Waits for the kernel, binds, and accepts until something asks for a stop. Returns that cause.
async fn until_stop(
    waits: &mut Waits,
    proxy: &ProxyConfig,
    wait_queue: usize,
    ingress: &SyncSender<Msg>,
    routes: &SharedRoutes,
    switcher: &mut Switcher,
    log: &Log,
) -> Cause {
    let Some(ready_by) = Instant::now().checked_add(proxy.ready_wait) else {
        return Cause::Late;
    };
    loop {
        match waits.wait(Some(ready_by)).await {
            Event::Ready(Ok(())) => break,
            Event::Reload => log.line("reload: ignored while starting"),
            event => {
                if let Some(cause) = Cause::of(event) {
                    return cause;
                }
            }
        }
    }
    log.line("start: the kernel is ready");

    let listener = match TcpListener::bind(proxy.listen).await {
        Ok(listener) => listener,
        Err(_) => return Cause::Bind,
    };
    let ctx = Arc::new(Ctx {
        cfg: proxy.clone(),
        budget: Arc::new(Semaphore::new(proxy.max_buffered_bytes)),
        inspect: Arc::new(Semaphore::new(wait_queue)),
        routes: routes.clone(),
        log: log.clone(),
    });
    let permits = Arc::new(Semaphore::new(proxy.max_conns));
    waits.accept = Some(Acceptor::new(listener, permits));
    log.line("start: listening");

    loop {
        match waits.wait(None).await {
            Event::Conn(sock, peer, permit) => {
                spawn_connection(&mut waits.conns, sock, peer, permit, &ctx, ingress, log);
            }
            Event::AcceptErr(Some(errno)) => log.line(&format!("accept: failed, errno {errno}")),
            Event::AcceptErr(None) => log.line("accept: failed"),
            Event::Joined(done) => note_joined(done, log),
            Event::Reload => reload(waits, switcher, ingress, log),
            Event::Switched(switched) => switcher.finish(switched),
            event => {
                if let Some(cause) = Cause::of(event) {
                    return cause;
                }
            }
        }
    }
}

/// SIGUSR1: reads the rules store, and if it chooses another generation, orders the driver to switch to it. The
/// answer comes as `Event::Switched`. Every other case is a record line, and the proxy goes on as it is.
fn reload(waits: &mut Waits, switcher: &mut Switcher, ingress: &SyncSender<Msg>, log: &Log) {
    log.line("reload: SIGUSR1");
    match switcher.prepare() {
        Next::Busy => log.line("reload: a switch is in progress, ignored"),
        Next::Running(generation) => log.line(&format!(
            "reload: generation {} is already running",
            generation.hex()
        )),
        Next::Refused(why) => log.line(&format!("reload: rules store refused: {why}")),
        Next::Ready {
            generation,
            mode,
            routes,
            kernel,
        } => {
            log.line(&format!("reload: starting generation {}", generation.hex()));
            log.line(&format!("reload: rules mode {}", mode.name()));
            log.line(&format!("reload: rules routes {}", routes.len()));
            let (reply, told) = oneshot::channel();
            let order = Msg::Switch(Switch {
                generation,
                mode,
                routes,
                kernel: *kernel,
                reply,
            });
            if ingress.try_send(order).is_err() {
                log.line("reload: the driver did not take the switch");
                switcher.finish(false);
                return;
            }
            waits.switch = Some(told);
        }
    }
}

/// Starts one connection. The permit lives as long as the connection and goes back when it ends or is aborted.
fn spawn_connection(
    conns: &mut JoinSet<()>,
    sock: TcpStream,
    peer: SocketAddr,
    permit: OwnedSemaphorePermit,
    ctx: &Arc<Ctx>,
    ingress: &SyncSender<Msg>,
    log: &Log,
) {
    let local = match (sock.set_nodelay(true), sock.local_addr()) {
        (Ok(()), Ok(local)) => local,
        _ => {
            log.line("accept: the connection is not usable");
            return;
        }
    };
    let ctx = ctx.clone();
    let ingress = ingress.clone();
    conns.spawn(async move {
        let _permit = permit;
        conn::serve(sock, peer, local, ctx, ingress).await;
    });
}

fn note_joined(done: Result<(), JoinError>, log: &Log) {
    if let Err(e) = done
        && e.is_panic()
    {
        log.line("connection: a connection panicked");
    }
}

/// Whether the accept error means the system is out of descriptors, memory or buffers.
fn is_resource_error(errno: i32) -> bool {
    matches!(errno, ENOMEM | ENFILE | EMFILE | ENOBUFS)
}

/// The driver's end counts as clean only for a stopped kernel whose child exit and directory removal are
/// confirmed, when every kernel that was stopped before it stopped cleanly too.
fn clean_shutdown(end: &End) -> bool {
    matches!(end, End::Done { kernel, retired_clean: true }
        if kernel.phase == Phase::Stopped && kernel.exit_confirmed && kernel.dir_removed)
}

/// Why the process stops.
enum Cause {
    Signal(&'static str),
    /// The kernel failed (before ready, or after).
    Failed(Failure),
    /// The driver ended without being told to.
    Ended(End),
    /// A channel closed without an answer.
    Lost(Source),
    /// The kernel was not ready within `ready_wait`.
    Late,
    Bind,
}

impl Cause {
    /// The cause that an event stands for, or none if the event only keeps the process going.
    fn of(event: Event) -> Option<Cause> {
        match event {
            Event::Signal(name) => Some(Cause::Signal(name)),
            Event::Ready(Err(failure)) | Event::Failed(failure) => Some(Cause::Failed(failure)),
            Event::Ended(end) => Some(Cause::Ended(end)),
            Event::Lost(source) => Some(Cause::Lost(source)),
            Event::Late => Some(Cause::Late),
            Event::Ready(Ok(()))
            | Event::Reload
            | Event::Switched(_)
            | Event::Conn(..)
            | Event::AcceptErr(_)
            | Event::Joined(_) => None,
        }
    }
}

/// What the stop learned while it ran.
struct Stop {
    /// The stop was caused by a failure: the exit code is 1 whatever the driver reports.
    fault: bool,
    ended: Option<End>,
    end_lost: bool,
}

impl Stop {
    fn begin(cause: Cause, log: &Log) -> Stop {
        let mut stop = Stop {
            fault: true,
            ended: None,
            end_lost: false,
        };
        match cause {
            Cause::Signal(name) => {
                stop.fault = false;
                log.line(&format!("stop: {name}"));
            }
            Cause::Failed(failure) => log.line(&format!("stop: the kernel failed: {failure:?}")),
            Cause::Ended(end) => {
                log.line("stop: the driver ended before it was told to stop");
                stop.ended = Some(end);
            }
            Cause::Lost(source) => {
                log.line(&format!(
                    "stop: the {} channel closed without an answer",
                    source.name()
                ));
                stop.end_lost = source == Source::End;
            }
            Cause::Late => log.line("stop: the kernel was not ready in time"),
            Cause::Bind => log.line("stop: the listen address cannot be bound"),
        }
        stop
    }

    /// Takes in an event that arrives while the stop runs. Later signals are only logged.
    fn note(&mut self, event: Event, log: &Log) {
        match event {
            Event::Ended(end) => self.ended = Some(end),
            Event::Lost(Source::End) => self.end_lost = true,
            Event::Signal(name) => log.line(&format!("stop: {name} again")),
            Event::Failed(failure) => {
                log.line(&format!("stop: the kernel failed: {failure:?}"));
            }
            Event::Joined(done) => note_joined(done, log),
            Event::Reload => log.line("reload: ignored while stopping"),
            Event::Lost(_)
            | Event::Ready(_)
            | Event::Switched(_)
            | Event::Late
            | Event::Conn(..)
            | Event::AcceptErr(_) => {}
        }
    }

    fn answered(&self) -> bool {
        self.ended.is_some() || self.end_lost
    }
}

/// The stop procedure. `t0` is taken here, at the first cause.
async fn stop(
    mut waits: Waits,
    cause: Cause,
    ingress: SyncSender<Msg>,
    proxy: &ProxyConfig,
    kill_grace: Duration,
    log: &Log,
) -> u8 {
    let t0 = Instant::now();
    let after = |d: Duration| t0.checked_add(d).unwrap_or(t0);
    let mut stop = Stop::begin(cause, log);

    // The listener is closed here; a connection that was not accepted yet is never accepted.
    waits.accept = None;

    // The driver finishes what it holds by `inspect_by`. The channel has room for this message by construction;
    // if it does not take it, the driver ends when the last connection is gone.
    let inspect_by = after(proxy.stop_inspect).into_std();
    if ingress.try_send(Msg::Stop { inspect_by }).is_err() {
        log.line("stop: the driver did not take the stop message");
    }
    drop(ingress);

    // The connections get until `t0 + stop_wait`; what is left is aborted.
    let abort_at = after(proxy.stop_wait);
    while !waits.conns.is_empty() {
        let event = waits.wait(Some(abort_at)).await;
        if matches!(event, Event::Late) {
            log.line("stop: the remaining connections are aborted");
            waits.conns.abort_all();
            break;
        }
        stop.note(event, log);
    }
    // Aborted connections are dropped when the runtime next runs them; a connection that does not end by then
    // is left to the process exit.
    let end_by = abort_at.checked_add(kill_grace).unwrap_or(abort_at);
    while let Ok(Some(done)) = timeout_at(end_by, waits.conns.join_next()).await {
        note_joined(done, log);
    }

    // The driver's end.
    while !stop.answered() {
        let event = waits.wait(Some(end_by)).await;
        if matches!(event, Event::Late) {
            log.line("stop: the driver did not answer in time");
            break;
        }
        stop.note(event, log);
    }

    match &stop.ended {
        Some(End::Done {
            kernel: done,
            retired_clean,
        }) => log.line(&format!(
            "stop: kernel {:?}, bye {}, exit_confirmed {}, dir_removed {}, held_left {}, waiting_left {}, results {}, retired_clean {}",
            done.phase,
            done.bye,
            done.exit_confirmed,
            done.dir_removed,
            done.held_left,
            done.waiting_left,
            done.results.len(),
            retired_clean
        )),
        Some(End::Fatal(text)) => log.line(&format!("stop: the driver stopped: {text}")),
        None => log.line("stop: the driver gave no end"),
    }
    let clean = stop.ended.as_ref().is_some_and(clean_shutdown);
    if !stop.fault && clean {
        EXIT_OK
    } else {
        EXIT_FAILED
    }
}

/// The four signal streams. They are created before the driver starts.
struct Signals {
    term: Signal,
    int: Signal,
    hup: Signal,
    usr1: Signal,
}

impl Signals {
    fn install() -> io::Result<Signals> {
        Ok(Signals {
            term: signal(SignalKind::terminate())?,
            int: signal(SignalKind::interrupt())?,
            hup: signal(SignalKind::hangup())?,
            usr1: signal(SignalKind::user_defined1())?,
        })
    }
}

/// The channel an answer did not come through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Source {
    Ready,
    Failed,
    End,
    Permits,
    Switch,
}

impl Source {
    fn name(self) -> &'static str {
        match self {
            Source::Ready => "ready",
            Source::Failed => "failed",
            Source::End => "end",
            Source::Permits => "connection permit",
            Source::Switch => "switch",
        }
    }
}

/// What ended one wait.
enum Event {
    Ready(Result<(), Failure>),
    Signal(&'static str),
    /// SIGUSR1.
    Reload,
    /// The driver answered a switch: whether the new generation serves.
    Switched(bool),
    Failed(Failure),
    Ended(End),
    Lost(Source),
    /// The deadline of the wait passed.
    Late,
    Conn(TcpStream, SocketAddr, OwnedSemaphorePermit),
    AcceptErr(Option<i32>),
    Joined(Result<(), JoinError>),
}

type Acquire = Pin<Box<dyn Future<Output = Result<OwnedSemaphorePermit, AcquireError>>>>;

/// The accept side: one connection permit first, then the accept it is for.
struct Acceptor {
    listener: TcpListener,
    permits: Arc<Semaphore>,
    acquire: Option<Acquire>,
    permit: Option<OwnedSemaphorePermit>,
    pause: Option<Pin<Box<Sleep>>>,
}

impl Acceptor {
    fn new(listener: TcpListener, permits: Arc<Semaphore>) -> Acceptor {
        Acceptor {
            listener,
            permits,
            acquire: None,
            permit: None,
            pause: None,
        }
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Event> {
        if let Some(pause) = self.pause.as_mut() {
            if pause.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            self.pause = None;
        }
        let permit = match self.permit.take() {
            Some(permit) => permit,
            None => {
                let permits = &self.permits;
                let acquire = self
                    .acquire
                    .get_or_insert_with(|| Box::pin(permits.clone().acquire_owned()));
                match acquire.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(permit)) => {
                        self.acquire = None;
                        permit
                    }
                    Poll::Ready(Err(_)) => return Poll::Ready(Event::Lost(Source::Permits)),
                }
            }
        };
        match self.listener.poll_accept(cx) {
            Poll::Pending => {
                self.permit = Some(permit);
                Poll::Pending
            }
            Poll::Ready(Ok((sock, peer))) => Poll::Ready(Event::Conn(sock, peer, permit)),
            Poll::Ready(Err(e)) => {
                self.permit = Some(permit);
                let errno = e.raw_os_error();
                if errno.is_some_and(is_resource_error) {
                    self.pause = Some(Box::pin(sleep(ACCEPT_PAUSE)));
                }
                Poll::Ready(Event::AcceptErr(errno))
            }
        }
    }
}

/// Everything main waits for, behind one poll. The order of the polls is the order of precedence: the driver's
/// answers and the signals before the connections that ended, those before the next accept.
struct Waits {
    term: Signal,
    int: Signal,
    hup: Signal,
    usr1: Signal,
    ready: Option<oneshot::Receiver<Result<(), Failure>>>,
    failed: Option<oneshot::Receiver<Failure>>,
    /// The answer to the switch that is under way, if there is one.
    switch: Option<oneshot::Receiver<Switched>>,
    end: Option<oneshot::Receiver<End>>,
    accept: Option<Acceptor>,
    conns: JoinSet<()>,
}

impl Waits {
    fn new(
        signals: Signals,
        ready: oneshot::Receiver<Result<(), Failure>>,
        failed: oneshot::Receiver<Failure>,
        end: oneshot::Receiver<End>,
    ) -> Waits {
        Waits {
            term: signals.term,
            int: signals.int,
            hup: signals.hup,
            usr1: signals.usr1,
            ready: Some(ready),
            failed: Some(failed),
            switch: None,
            end: Some(end),
            accept: None,
            conns: JoinSet::new(),
        }
    }

    /// The next event, or `Event::Late` at `by`. A channel that answered or closed is not polled again.
    async fn wait(&mut self, by: Option<Instant>) -> Event {
        let next = poll_fn(|cx| self.poll(cx));
        match by {
            Some(by) => timeout_at(by, next).await.unwrap_or(Event::Late),
            None => next.await,
        }
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Event> {
        if let Some(ready) = self.ready.as_mut()
            && let Poll::Ready(answer) = Pin::new(ready).poll(cx)
        {
            self.ready = None;
            return Poll::Ready(answer.map_or(Event::Lost(Source::Ready), Event::Ready));
        }
        for (name, stream) in [
            ("SIGTERM", &mut self.term),
            ("SIGINT", &mut self.int),
            ("SIGHUP", &mut self.hup),
        ] {
            if stream.poll_recv(cx).is_ready() {
                return Poll::Ready(Event::Signal(name));
            }
        }
        if self.usr1.poll_recv(cx).is_ready() {
            return Poll::Ready(Event::Reload);
        }
        if let Some(failed) = self.failed.as_mut()
            && let Poll::Ready(answer) = Pin::new(failed).poll(cx)
        {
            self.failed = None;
            return Poll::Ready(answer.map_or(Event::Lost(Source::Failed), Event::Failed));
        }
        if let Some(switch) = self.switch.as_mut()
            && let Poll::Ready(answer) = Pin::new(switch).poll(cx)
        {
            self.switch = None;
            return Poll::Ready(answer.map_or(Event::Lost(Source::Switch), |switched| {
                Event::Switched(switched == Switched::Yes)
            }));
        }
        if let Some(end) = self.end.as_mut()
            && let Poll::Ready(answer) = Pin::new(end).poll(cx)
        {
            self.end = None;
            return Poll::Ready(answer.map_or(Event::Lost(Source::End), Event::Ended));
        }
        if let Poll::Ready(Some(done)) = self.conns.poll_join_next(cx) {
            return Poll::Ready(Event::Joined(done));
        }
        match self.accept.as_mut() {
            Some(accept) => accept.poll(cx),
            None => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::sync_channel;
    use std::thread;
    use tokio::runtime::{Builder, Runtime};
    use tukuyomi_kernel::Shutdown;

    fn runtime() -> Runtime {
        Builder::new_current_thread().enable_all().build().unwrap()
    }

    struct Fixture {
        waits: Waits,
        ready: oneshot::Sender<Result<(), Failure>>,
        _failed: oneshot::Sender<Failure>,
        end: oneshot::Sender<End>,
    }

    /// Needs a runtime to be entered.
    fn fixture() -> Fixture {
        let (ready, ready_rx) = oneshot::channel();
        let (failed, failed_rx) = oneshot::channel();
        let (end, end_rx) = oneshot::channel();
        Fixture {
            waits: Waits::new(Signals::install().unwrap(), ready_rx, failed_rx, end_rx),
            ready,
            _failed: failed,
            end,
        }
    }

    fn after(ms: u64) -> Option<Instant> {
        Some(Instant::now() + Duration::from_millis(ms))
    }

    fn shutdown(phase: Phase, confirmed: bool, removed: bool) -> End {
        End::Done {
            kernel: Shutdown {
                results: Vec::new(),
                phase,
                bye: true,
                exit_confirmed: confirmed,
                dir_removed: removed,
                held_left: 0,
                waiting_left: 0,
            },
            retired_clean: true,
        }
    }

    #[test]
    fn only_a_stopped_confirmed_removed_kernel_is_a_clean_end() {
        assert!(clean_shutdown(&shutdown(Phase::Stopped, true, true)));
        assert!(!clean_shutdown(&shutdown(Phase::Stopped, false, true)));
        assert!(!clean_shutdown(&shutdown(Phase::Stopped, true, false)));
        assert!(!clean_shutdown(&shutdown(Phase::Ready, true, true)));
        assert!(!clean_shutdown(&shutdown(
            Phase::Failed(Failure::ReapUnknown),
            true,
            true
        )));
        assert!(!clean_shutdown(&End::Fatal(
            "result for an unknown request"
        )));
        // A kernel that was stopped before, and did not stop cleanly, makes the end unclean too.
        let End::Done { kernel, .. } = shutdown(Phase::Stopped, true, true) else {
            unreachable!()
        };
        assert!(!clean_shutdown(&End::Done {
            kernel,
            retired_clean: false
        }));
    }

    #[test]
    fn only_running_out_of_a_resource_pauses_the_accept_loop() {
        for errno in [12, 23, 24, 105] {
            assert!(is_resource_error(errno), "{errno}");
        }
        // EAGAIN, EINTR, ECONNABORTED
        for errno in [11, 4, 103] {
            assert!(!is_resource_error(errno), "{errno}");
        }
    }

    #[test]
    fn a_wait_returns_what_the_driver_answered_once() {
        runtime().block_on(async {
            let mut f = fixture();
            f.ready.send(Ok(())).unwrap();
            assert!(matches!(
                f.waits.wait(after(2000)).await,
                Event::Ready(Ok(()))
            ));
            // The answered channel is not polled again: the next wait runs to its deadline.
            assert!(matches!(f.waits.wait(after(30)).await, Event::Late));

            let mut f = fixture();
            f.ready.send(Err(Failure::BudgetExhausted)).unwrap();
            assert!(matches!(
                f.waits.wait(after(2000)).await,
                Event::Ready(Err(Failure::BudgetExhausted))
            ));

            let mut f = fixture();
            drop(f.ready);
            assert!(matches!(
                f.waits.wait(after(2000)).await,
                Event::Lost(Source::Ready)
            ));
        });
    }

    #[test]
    fn a_wait_returns_the_answer_to_a_switch_once() {
        runtime().block_on(async {
            let mut f = fixture();
            let (reply, told) = oneshot::channel();
            f.waits.switch = Some(told);
            reply.send(Switched::Yes).unwrap();
            assert!(matches!(
                f.waits.wait(after(2000)).await,
                Event::Switched(true)
            ));
            assert!(matches!(f.waits.wait(after(30)).await, Event::Late));

            let (reply, told) = oneshot::channel::<Switched>();
            f.waits.switch = Some(told);
            drop(reply);
            assert!(matches!(
                f.waits.wait(after(2000)).await,
                Event::Lost(Source::Switch)
            ));
        });
    }

    #[test]
    fn a_connection_permit_is_taken_before_accept() {
        runtime().block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let permits = Arc::new(Semaphore::new(1));
            let mut f = fixture();
            f.waits.accept = Some(Acceptor::new(listener, permits.clone()));
            let _first = TcpStream::connect(addr).await.unwrap();
            let _second = TcpStream::connect(addr).await.unwrap();

            let Event::Conn(_, _, permit) = f.waits.wait(after(5000)).await else {
                panic!("the first connection was not accepted");
            };
            assert_eq!(permits.available_permits(), 0);
            // The second connection waits in the backlog: no permit, no accept.
            assert!(matches!(f.waits.wait(after(150)).await, Event::Late));
            drop(permit);
            assert!(matches!(f.waits.wait(after(5000)).await, Event::Conn(..)));
        });
    }

    fn proxy_config(stop_inspect_ms: u64, stop_wait_ms: u64) -> ProxyConfig {
        let loaded = config_for_tests();
        ProxyConfig {
            stop_inspect: Duration::from_millis(stop_inspect_ms),
            stop_wait: Duration::from_millis(stop_wait_ms),
            ..loaded
        }
    }

    fn config_for_tests() -> ProxyConfig {
        let any: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let ms = Duration::from_millis;
        ProxyConfig {
            listen: any,
            upstream: any,
            max_conns: 1,
            max_head_bytes: 1024,
            max_body: 0,
            max_body_wire: 0,
            max_buffered_bytes: 0,
            upstream_max_headers: 1,
            upstream_max_head_bytes: 8192,
            upstream_head_wire: 16384,
            drive_slice: ms(1),
            ready_wait: ms(1),
            head_read: ms(1),
            body_read: ms(1),
            inspect_wait: ms(1),
            upstream_connect: ms(1),
            upstream_header: ms(1),
            request_total: ms(1),
            response_idle: ms(1),
            conn_total: ms(1),
            stop_inspect: ms(1),
            stop_wait: ms(1),
        }
    }

    /// A stand-in driver thread: takes the stop message, then ends as `end` says.
    fn driver_thread(
        end: Option<End>,
        end_tx: oneshot::Sender<End>,
    ) -> (
        SyncSender<Msg>,
        thread::JoinHandle<Option<std::time::Instant>>,
    ) {
        let (tx, rx) = sync_channel::<Msg>(2);
        let handle = thread::spawn(move || {
            let inspect_by = match rx.recv() {
                Ok(Msg::Stop { inspect_by }) => Some(inspect_by),
                _ => None,
            };
            if let Some(end) = end {
                let _ = end_tx.send(end);
            }
            inspect_by
        });
        (tx, handle)
    }

    #[test]
    fn the_stop_gives_the_driver_its_deadline_and_exits_zero_after_a_clean_end() {
        let log = log::start_logger().unwrap();
        runtime().block_on(async {
            let f = fixture();
            let (tx, driver) = driver_thread(Some(shutdown(Phase::Stopped, true, true)), f.end);
            let before = std::time::Instant::now();
            let code = stop(
                f.waits,
                Cause::Signal("SIGTERM"),
                tx,
                &proxy_config(700, 2000),
                Duration::from_millis(500),
                &log,
            )
            .await;
            assert_eq!(code, EXIT_OK);
            let inspect_by = driver.join().unwrap().expect("the stop message");
            assert!(inspect_by >= before + Duration::from_millis(700));
            assert!(inspect_by <= std::time::Instant::now() + Duration::from_millis(700));
        });
    }

    #[test]
    fn the_stop_exits_one_unless_the_end_is_clean_and_the_cause_is_not_a_failure() {
        let log = log::start_logger().unwrap();
        let cfg = proxy_config(10, 100);
        let grace = Duration::from_millis(50);
        runtime().block_on(async {
            // A kernel that did not stop cleanly.
            for end in [
                shutdown(Phase::Stopped, false, true),
                End::Fatal("result for an unknown request"),
            ] {
                let f = fixture();
                let (tx, driver) = driver_thread(Some(end), f.end);
                assert_eq!(
                    stop(f.waits, Cause::Signal("SIGINT"), tx, &cfg, grace, &log).await,
                    EXIT_FAILED
                );
                driver.join().unwrap();
            }
            // A failure as the cause, although the driver ends cleanly.
            for cause in [Cause::Failed(Failure::BudgetExhausted), Cause::Late] {
                let f = fixture();
                let (tx, driver) = driver_thread(Some(shutdown(Phase::Stopped, true, true)), f.end);
                assert_eq!(
                    stop(f.waits, cause, tx, &cfg, grace, &log).await,
                    EXIT_FAILED
                );
                driver.join().unwrap();
            }
            // The driver gone without an end.
            let f = fixture();
            let (tx, driver) = driver_thread(None, f.end);
            assert_eq!(
                stop(f.waits, Cause::Signal("SIGHUP"), tx, &cfg, grace, &log).await,
                EXIT_FAILED
            );
            driver.join().unwrap();
        });
    }

    #[test]
    fn the_stop_aborts_connections_that_outlive_it() {
        let log = log::start_logger().unwrap();
        runtime().block_on(async {
            let mut f = fixture();
            f.waits.conns.spawn(std::future::pending());
            let (tx, driver) = driver_thread(Some(shutdown(Phase::Stopped, true, true)), f.end);
            let start = Instant::now();
            let code = stop(
                f.waits,
                Cause::Signal("SIGTERM"),
                tx,
                &proxy_config(10, 150),
                Duration::from_millis(100),
                &log,
            )
            .await;
            let spent = start.elapsed();
            assert_eq!(code, EXIT_OK);
            assert!(spent >= Duration::from_millis(150) && spent < Duration::from_secs(5));
            driver.join().unwrap();
        });
    }
}
