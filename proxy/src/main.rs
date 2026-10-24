#![forbid(unsafe_code)]
//! The proxy process: start-up, the wait for the kernel, the listeners and the stop. When the first argument is
//! `rules` the process is a short command on the rules store instead (`rules::command`), and nothing of the proxy
//! starts.
//!
//! Start-up runs in this order: the logger thread, one argument (the absolute clean path of the configuration file),
//! the host checks, the configuration, the lookup of the names of the upstream servers (in the same step, the CA file
//! of each upstream group that has `tls` is read), the certificate and key files of the TLS listeners, the rules store
//! (the chosen generation, the hold on it, its directory, mode and routes, and with them the kernel configuration), the
//! runtime and the signal handlers, the driver thread, the wait for the kernel to be ready, bind, accept. The rules
//! store is read here, and again when SIGUSR1 comes; the certificate and key files are read here, and again when
//! SIGUSR2 comes. Handlers exist for SIGTERM, SIGINT, SIGHUP, SIGUSR1 and SIGUSR2 only and are installed before the
//! kernel starts its child process; SIGCHLD is never handled. The listeners are bound only after the kernel is ready,
//! all of them or none, and the accept side takes a connection permit before every accept (see
//! `inbound::transport::accept`).
//!
//! The upstream groups and the routes to them are read from the configuration file when the proxy starts, and stay
//! as they are until it is started again; so do the addresses that the names of the servers have then, the
//! authorities in the CA files of the groups that have `tls` (SIGUSR2 does not read them again), and the listeners
//! with the hosts of their certificates.
//!
//! SIGUSR1 makes the proxy switch to the generation that the rules store chooses now (`rules::switch` reads the
//! store, the driver starts the new inspector and moves the requests over when it is ready). It is a line in the
//! records and nothing else before the listeners are bound, while a switch is under way, and while the proxy stops.
//! SIGUSR2 reads every certificate and key file of every TLS listener again. If all of them pass the checks, they
//! replace the old ones for the handshakes that start from then on (a connection that is open keeps what it has);
//! if one does not, none is replaced and a line says which. It is a line and nothing else before the listeners are
//! bound and while the proxy stops, and it has nothing to do with SIGUSR1.
//!
//! The first cause of a stop (a signal, or a failure of start-up or of the driver) fixes the time `t0`. The stop
//! closes the listeners and the way from the connections to the driver (a request that starts from then on is
//! refused, and a connection that waits for its next request is closed), tells the driver to finish inspecting by
//! `t0 + stop_inspect`, waits for the connections until `t0 + stop_wait` and aborts what is left (a tunnel, which is
//! a WebSocket that the proxy copies, is not ended by the stop: it runs until it ends by itself or is aborted
//! there), then waits for the driver's end until `t0 + stop_wait + kill_grace`. The exit code is 0 only when the
//! stop was not caused by a failure and the driver reports a stopped kernel whose child exit and per-start
//! directory removal are confirmed, and the same for every kernel that was stopped before it; 1 for any other end,
//! and for names of upstream servers that cannot be looked up, a CA file of an upstream group that cannot be used, a
//! refused certificate or key file, or a refused rules store or generation (nothing has been started then); 2 for a
//! wrong argument or a refused configuration. The log is flushed for at most 200 ms at the end.

use std::ffi::OsString;
use std::future::{Future, poll_fn};
use std::io::{self, Write};
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::mpsc::SyncSender;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::{Semaphore, oneshot};
use tokio::task::{JoinError, JoinSet};
use tokio::time::{Instant, timeout_at};
use tukuyomi_kernel::{Failure, Phase};
use tukuyomi_proxy::config::{self, ForwardConfig, ProxyConfig, addresses};
use tukuyomi_proxy::forward::group::Upstreams;
use tukuyomi_proxy::forward::resolve;
use tukuyomi_proxy::host;
use tukuyomi_proxy::inbound::conn::Ctx;
use tukuyomi_proxy::inbound::session;
use tukuyomi_proxy::inbound::transport::accept::{Accepted, Acceptor, Arrival};
use tukuyomi_proxy::inbound::transport::tls::{Files, Tls};
use tukuyomi_proxy::inspect::driver::{self, Driver, End, Ingress, Limits, Msg, Switch, Switched};
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
    let listening = addresses(&loaded.proxy.listeners);
    let forward = match resolve::complete(loaded.forward, &listening, resolve::system) {
        Ok(done) => {
            for line in &done.lines {
                log.line(line);
            }
            done.forward
        }
        Err(refusal) => {
            log.line(&format!("start: upstream refused: {refusal}"));
            return EXIT_FAILED;
        }
    };
    let tls = match Tls::load(&loaded.proxy.listeners, &Files) {
        Ok(tls) => tls,
        Err(refusal) => {
            log.line(&format!("start: tls refused: {refusal}"));
            return EXIT_FAILED;
        }
    };
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
        forward,
        tls,
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
// One argument for each part of what the configuration, the rules store and the logger give; a struct of them would
// only repeat their names.
#[allow(clippy::too_many_arguments)]
async fn run(
    proxy: ProxyConfig,
    forward: ForwardConfig,
    tls: Tls,
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
    // What the connections share. They take a sender from its handle for every request, and the stop closes it.
    let ctx = Arc::new(Ctx {
        cfg: proxy.clone(),
        budget: Arc::new(Semaphore::new(proxy.max_buffered_bytes)),
        inspect: Arc::new(Semaphore::new(wait_queue)),
        routes: routes.clone(),
        upstreams: Upstreams::new(&forward, &proxy),
        log: log.clone(),
        ingress: Arc::new(Ingress::new(ingress.clone())),
        tls,
    });
    let cause = until_stop(&mut waits, &ctx, &ingress, &mut switcher).await;
    stop(
        waits,
        cause,
        ingress,
        &ctx.ingress,
        &proxy,
        kill_grace,
        &log,
    )
    .await
}

/// Waits for the kernel, binds, and accepts until something asks for a stop. Returns that cause.
async fn until_stop(
    waits: &mut Waits,
    ctx: &Arc<Ctx>,
    ingress: &SyncSender<Msg>,
    switcher: &mut Switcher,
) -> Cause {
    let (proxy, log) = (&ctx.cfg, &ctx.log);
    let Some(ready_by) = Instant::now().checked_add(proxy.ready_wait) else {
        return Cause::Late;
    };
    loop {
        match waits.wait(Some(ready_by)).await {
            Event::Ready(Ok(())) => break,
            Event::Reload => log.line("reload: ignored while starting"),
            Event::Certificates => log.line("reload: certificates ignored while starting"),
            event => {
                if let Some(cause) = Cause::of(event) {
                    return cause;
                }
            }
        }
    }
    log.line("start: the kernel is ready");

    let permits = Arc::new(Semaphore::new(proxy.max_conns));
    let acceptor =
        match Acceptor::bind(&addresses(&proxy.listeners), permits, ctx.ingress.clone()).await {
            Ok(acceptor) => acceptor,
            Err(_) => return Cause::Bind,
        };
    waits.accept = Some(acceptor);
    log.line("start: listening");

    loop {
        match waits.wait(None).await {
            Event::Conn(arrival) => spawn_connection(&mut waits.conns, arrival, ctx, log),
            Event::AcceptErr(Some(errno)) => log.line(&format!("accept: failed, errno {errno}")),
            Event::AcceptErr(None) => log.line("accept: failed"),
            Event::Joined(done) => note_joined(done, log),
            Event::Reload => reload(waits, switcher, ingress, log),
            Event::Certificates => reload_certificates(ctx),
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

/// SIGUSR2: reads the certificate and key files of the TLS listeners again. They all replace the ones in use, or none
/// does; the result is a record line, and the proxy goes on as it is.
fn reload_certificates(ctx: &Ctx) {
    ctx.log.line("reload: SIGUSR2");
    match ctx.tls.reload(&ctx.cfg.listeners, &Files) {
        Ok(()) => ctx.log.line("reload: certificates replaced"),
        Err(refusal) => ctx
            .log
            .line(&format!("reload: certificates refused: {refusal}")),
    }
}

/// Starts one connection. The permit lives as long as the connection and goes back when it ends or is aborted.
fn spawn_connection(conns: &mut JoinSet<()>, arrival: Arrival, ctx: &Arc<Ctx>, log: &Log) {
    let Arrival {
        sock,
        peer,
        permit,
        listener,
    } = arrival;
    let local = match (sock.set_nodelay(true), sock.local_addr()) {
        (Ok(()), Ok(local)) => local,
        _ => {
            log.line("accept: the connection is not usable");
            return;
        }
    };
    let ctx = ctx.clone();
    conns.spawn(async move {
        let _permit = permit;
        session::serve_on(sock, peer, local, ctx, listener).await;
    });
}

fn note_joined(done: Result<(), JoinError>, log: &Log) {
    if let Err(e) = done
        && e.is_panic()
    {
        log.line("connection: a connection panicked");
    }
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
            | Event::Certificates
            | Event::Switched(_)
            | Event::Conn(_)
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
            Cause::Bind => log.line("stop: a listen address cannot be bound"),
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
            Event::Certificates => log.line("reload: certificates ignored while stopping"),
            Event::Lost(_)
            | Event::Ready(_)
            | Event::Switched(_)
            | Event::Late
            | Event::Conn(_)
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
    connections: &Ingress,
    proxy: &ProxyConfig,
    kill_grace: Duration,
    log: &Log,
) -> u8 {
    let t0 = Instant::now();
    let after = |d: Duration| t0.checked_add(d).unwrap_or(t0);
    let mut stop = Stop::begin(cause, log);

    // The listeners are closed here; a connection that was not accepted yet is never accepted. The connections get
    // no sender for a request that starts from now on, and the ones that wait for a request end.
    waits.accept = None;
    connections.close();

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

/// The five signal streams. They are created before the driver starts.
struct Signals {
    term: Signal,
    int: Signal,
    hup: Signal,
    usr1: Signal,
    usr2: Signal,
}

impl Signals {
    fn install() -> io::Result<Signals> {
        Ok(Signals {
            term: signal(SignalKind::terminate())?,
            int: signal(SignalKind::interrupt())?,
            hup: signal(SignalKind::hangup())?,
            usr1: signal(SignalKind::user_defined1())?,
            usr2: signal(SignalKind::user_defined2())?,
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
    /// SIGUSR2.
    Certificates,
    /// The driver answered a switch: whether the new generation serves.
    Switched(bool),
    Failed(Failure),
    Ended(End),
    Lost(Source),
    /// The deadline of the wait passed.
    Late,
    Conn(Arrival),
    AcceptErr(Option<i32>),
    Joined(Result<(), JoinError>),
}

/// Everything main waits for, behind one poll. The order of the polls is the order of precedence: the driver's
/// answers and the signals before the connections that ended, those before the next accept.
struct Waits {
    term: Signal,
    int: Signal,
    hup: Signal,
    usr1: Signal,
    usr2: Signal,
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
            usr2: signals.usr2,
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
        if self.usr2.poll_recv(cx).is_ready() {
            return Poll::Ready(Event::Certificates);
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
        match self.accept.as_mut().map(|accept| accept.poll(cx)) {
            Some(Poll::Ready(Accepted::Conn(arrival))) => Poll::Ready(Event::Conn(arrival)),
            Some(Poll::Ready(Accepted::Failed(errno))) => Poll::Ready(Event::AcceptErr(errno)),
            Some(Poll::Ready(Accepted::PermitsGone)) => Poll::Ready(Event::Lost(Source::Permits)),
            Some(Poll::Pending) | None => Poll::Pending,
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

    fn proxy_config(stop_inspect_ms: u64, stop_wait_ms: u64) -> ProxyConfig {
        let loaded = config_for_tests();
        ProxyConfig {
            stop_inspect: Duration::from_millis(stop_inspect_ms),
            stop_wait: Duration::from_millis(stop_wait_ms),
            ..loaded
        }
    }

    fn config_for_tests() -> ProxyConfig {
        let ms = Duration::from_millis;
        ProxyConfig {
            listeners: Vec::new(),
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
            keepalive_timeout: ms(1),
            keepalive_requests: 1,
            keepalive_time: ms(1),
            lingering_time: ms(1),
            lingering_timeout: ms(1),
            lingering_bytes: 1,
            trusted_proxies: Vec::new(),
            upstream_keepalive: 0,
            upstream_keepalive_timeout: ms(1),
            upstream_keepalive_requests: 1,
        }
    }

    /// The way from the connections to a stand-in driver.
    fn connections(tx: &SyncSender<Msg>) -> Ingress {
        Ingress::new(tx.clone())
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
            let connections = connections(&tx);
            let before = std::time::Instant::now();
            assert!(connections.sender().is_some());
            let code = stop(
                f.waits,
                Cause::Signal("SIGTERM"),
                tx,
                &connections,
                &proxy_config(700, 2000),
                Duration::from_millis(500),
                &log,
            )
            .await;
            assert_eq!(code, EXIT_OK);
            // The stop closes the way from the connections to the driver.
            assert!(connections.sender().is_none());
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
                let connections = connections(&tx);
                assert_eq!(
                    stop(
                        f.waits,
                        Cause::Signal("SIGINT"),
                        tx,
                        &connections,
                        &cfg,
                        grace,
                        &log
                    )
                    .await,
                    EXIT_FAILED
                );
                driver.join().unwrap();
            }
            // A failure as the cause, although the driver ends cleanly.
            for cause in [Cause::Failed(Failure::BudgetExhausted), Cause::Late] {
                let f = fixture();
                let (tx, driver) = driver_thread(Some(shutdown(Phase::Stopped, true, true)), f.end);
                let connections = connections(&tx);
                assert_eq!(
                    stop(f.waits, cause, tx, &connections, &cfg, grace, &log).await,
                    EXIT_FAILED
                );
                driver.join().unwrap();
            }
            // The driver gone without an end.
            let f = fixture();
            let (tx, driver) = driver_thread(None, f.end);
            let connections = connections(&tx);
            assert_eq!(
                stop(
                    f.waits,
                    Cause::Signal("SIGHUP"),
                    tx,
                    &connections,
                    &cfg,
                    grace,
                    &log
                )
                .await,
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
            let connections = connections(&tx);
            let start = Instant::now();
            let code = stop(
                f.waits,
                Cause::Signal("SIGTERM"),
                tx,
                &connections,
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
