//! The runtime part of the start: the signal handlers, the driver, the wait for the kernel to be ready, the
//! listeners, and the accept side until something asks for a stop.

use std::sync::Arc;
use std::sync::mpsc::SyncSender;

use tokio::sync::Semaphore;
use tokio::task::{JoinError, JoinSet};
use tokio::time::Instant;

use super::EXIT_FAILED;
use super::reload::{reload, reload_certificates};
use super::signals::{Event, Signals, Waits};
use super::stop::{Cause, stop};
use crate::config::{ForwardConfig, ProxyConfig, addresses};
use crate::forward::group::Upstreams;
use crate::inbound::challenge::Challenge;
use crate::inbound::conn::Ctx;
use crate::inbound::session;
use crate::inbound::transport::accept::{Acceptor, Arrival};
use crate::inbound::transport::tls::Tls;
use crate::inspect::driver::{self, Driver, Ingress, Limits, Msg};
use crate::log::Log;
use crate::rules::bundle::{Fingerprint, Mode};
use crate::rules::routes::{Routes, SharedRoutes};
use crate::rules::switch::Switcher;

/// The runtime part: handlers, driver, the wait for ready, serving, and the stop. The holds of the switcher live
/// to the end, so the generations in use are held until the stop is over.
// One argument for each part of what the configuration, the rules store and the logger give; a struct of them would
// only repeat their names.
#[allow(clippy::too_many_arguments)]
pub(super) async fn run(
    proxy: ProxyConfig,
    forward: ForwardConfig,
    tls: Tls,
    challenge: Option<Challenge>,
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
        challenge,
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

pub(super) fn note_joined(done: Result<(), JoinError>, log: &Log) {
    if let Err(e) = done
        && e.is_panic()
    {
        log.line("connection: a connection panicked");
    }
}
