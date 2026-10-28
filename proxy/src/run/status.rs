//! The status listener: `GET /healthz`, `GET /readyz` and `GET /metrics` on a loopback address (the `status` object of
//! the configuration), for a program on the same host.
//!
//! The listener is bound after `prepare` and before the driver starts, so an address that cannot be bound ends the
//! start before the inspector runs; the answers begin when the driver has started, and until the forwarding listeners
//! are bound `/readyz` says `starting`. It does not use hyper, whose read buffer cannot be set under 8 KiB: it reads at
//! most 4 KiB of the head within 2 s, reads it with `httparse`, answers with fixed bytes and closes (as the listener
//! that redirects does), with 2 s to write the answer. At most 8 connections are served at once, with permits of the
//! listener's own and not those of forwarding, so a program that watches cannot take a place from a client; a
//! connection that finds none is accepted and closed. Nothing of a request here is inspected, forwarded or recorded.
//!
//! The pages: `/healthz` is 200 `ok` as long as the process answers; `/readyz` is 200 `ready`, or 503 and a word that
//! says why not (`stopping` from the first cause of a stop, then `starting` until the forwarding listeners are bound,
//! then `inspector down` while the kernel that serves is not in the phase `Ready`, as in the restart of the
//! inspector; a switch to another generation keeps it ready); `/metrics` is the text of `metrics`. A `HEAD` has the
//! status and the fields of the `GET` and no body. Another method is 405 (with `Allow`), another target, a query
//! included, is 404. HTTP/1.1 only: a head that is not one (HTTP/1.0 included), that `httparse` refuses, or that is
//! not complete in 4 KiB is 400; a head that is not complete within 2 s, or a client that is gone, gets no answer.
//! Every answer has `Content-Length` and `Connection: close`, and the connection is closed after it.
//!
//! The listener stays open through the stop until the connections of the proxy have ended or `stop_wait` has passed,
//! and `Status` is dropped then: the listener closes and the connections it is answering are ended.

use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{sleep, timeout};
use tukuyomi_kernel::Phase;

use crate::inbound::conn::Ctx;
use crate::inbound::session::send_and_close;
use crate::inspect::driver::State;
use crate::policy::RateLimit;

mod metrics;

/// The most connections served at once; another one is accepted and closed.
const SEATS: usize = 8;
/// The most bytes of a head that are read.
const HEAD_MAX: usize = 4096;
/// The most fields of a head that are read: a head that has more is refused.
const FIELDS: usize = 64;
/// The time for the head, and the time to write the answer.
const HEAD_WAIT: Duration = Duration::from_secs(2);
const WRITE_WAIT: Duration = Duration::from_secs(2);
/// The pause after an accept failed.
const ACCEPT_PAUSE: Duration = Duration::from_millis(100);

const TEXT: &str = "Content-Type: text/plain; charset=utf-8\r\n";
const EXPOSITION: &str = "Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n";

/// What the main side says of the proxy besides the state of the kernel: that the forwarding listeners are bound, and
/// that the stop has begun. Both are said once, and never taken back.
pub(super) struct Readiness {
    bound: AtomicBool,
    stopping: AtomicBool,
}

impl Readiness {
    pub(super) fn new() -> Readiness {
        Readiness {
            bound: AtomicBool::new(false),
            stopping: AtomicBool::new(false),
        }
    }

    /// Every forwarding listener is bound.
    pub(super) fn bound(&self) {
        self.bound.store(true, Ordering::Release);
    }

    /// The first cause of a stop has come.
    pub(super) fn stopping(&self) {
        self.stopping.store(true, Ordering::Release);
    }

    /// `Ok` if requests can be served: the stop has not begun, the forwarding listeners are bound and the kernel that
    /// serves is in `phase` `Ready`. Otherwise the word that says why not.
    pub(super) fn check(&self, phase: Phase) -> Result<(), &'static str> {
        if self.stopping.load(Ordering::Acquire) {
            Err("stopping")
        } else if !self.bound.load(Ordering::Acquire) {
            Err("starting")
        } else if phase != Phase::Ready {
            Err("inspector down")
        } else {
            Ok(())
        }
    }
}

/// What the answers are made of. The proxy gives `View`; the tests give a stand-in.
pub(super) trait Source: Send + Sync + 'static {
    /// `Ok` if the proxy is ready for requests, otherwise the word that says why not.
    fn ready(&self) -> Result<(), &'static str>;

    /// The page of `/metrics`.
    fn metrics(&self) -> String;
}

/// What the proxy shares with the listener: the connections' context, the state that the driver publishes and what
/// the main side says.
pub(super) struct View {
    ctx: Arc<Ctx>,
    /// The inspection permits `ctx` holds were made for this many waiting inspections.
    wait_queue: usize,
    state: watch::Receiver<State>,
    readiness: Arc<Readiness>,
}

impl View {
    pub(super) fn new(
        ctx: Arc<Ctx>,
        wait_queue: usize,
        state: watch::Receiver<State>,
        readiness: Arc<Readiness>,
    ) -> View {
        View {
            ctx,
            wait_queue,
            state,
            readiness,
        }
    }
}

impl Source for View {
    fn ready(&self) -> Result<(), &'static str> {
        let phase = self.state.borrow().phase;
        self.readiness.check(phase)
    }

    fn metrics(&self) -> String {
        let ctx = &self.ctx;
        let state = *self.state.borrow();
        metrics::render(&metrics::Scrape {
            counters: &ctx.counters,
            state,
            connections_open: ctx.counters.open.get(),
            permit_waits: ctx.ingress.drains(),
            body_buffer_bytes: ctx
                .cfg
                .max_buffered_bytes
                .saturating_sub(ctx.budget.available_permits()),
            inspections_waiting: self
                .wait_queue
                .saturating_sub(ctx.inspect.available_permits()),
            upstream_failures: ctx.upstreams.failures().collect(),
            rate_limit_keys: ctx.rate_limit.as_ref().map_or(0, RateLimit::keys),
            rate_limit_evicted: ctx.rate_limit.as_ref().map_or(0, RateLimit::evicted),
            records_dropped: ctx.log.dropped(),
            record_write_errors: ctx.log.write_errors(),
            record_file_errors: ctx.log.file_errors(),
        })
    }
}

/// The running listener. Dropping it closes the listener and ends the connections it is answering.
pub(super) struct Status {
    task: JoinHandle<()>,
}

impl Drop for Status {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Binds the listener.
pub(super) async fn bind(address: SocketAddr) -> io::Result<TcpListener> {
    TcpListener::bind(address).await
}

/// Starts to answer on `listener`. The runtime has to be entered.
pub(super) fn serve<S: Source>(listener: TcpListener, source: Arc<S>) -> Status {
    Status {
        task: tokio::spawn(accept(listener, source)),
    }
}

/// Accepts connections for ever; the task ends when `Status` aborts it, and takes its connections with it.
async fn accept<S: Source>(listener: TcpListener, source: Arc<S>) {
    let seats = Arc::new(Semaphore::new(SEATS));
    let mut conns = JoinSet::new();
    loop {
        let accepted = poll_fn(|cx| {
            // A connection that is done is joined here, so the set holds only those that are being answered.
            while let Poll::Ready(Some(_)) = conns.poll_join_next(cx) {}
            listener.poll_accept(cx)
        })
        .await;
        match accepted {
            Ok((sock, _)) => match seats.clone().try_acquire_owned() {
                Ok(seat) => {
                    let source = source.clone();
                    conns.spawn(async move {
                        let _seat = seat;
                        answer(sock, source.as_ref()).await;
                    });
                }
                // No place is free: the connection is closed.
                Err(_) => drop(sock),
            },
            Err(_) => sleep(ACCEPT_PAUSE).await,
        }
    }
}

/// What a head asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Page {
    Healthz,
    Readyz,
    Metrics,
}

/// What the head of a connection came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Asked {
    Page {
        page: Page,
        head_only: bool,
    },
    /// A method that is neither `GET` nor `HEAD`.
    NotAllowed,
    /// Another target.
    NotFound,
    /// A head that is not served.
    Bad,
}

/// Reads the head of the connection, in the time it has and the bytes it may have. `None`: the client went away.
async fn read_head(sock: &mut TcpStream) -> Option<Asked> {
    let mut buf = [0u8; HEAD_MAX];
    let mut len = 0;
    loop {
        let mut fields = [httparse::EMPTY_HEADER; FIELDS];
        let mut head = httparse::Request::new(&mut fields);
        match head.parse(&buf[..len]) {
            Ok(httparse::Status::Complete(_)) => return Some(ask(&head)),
            // The head does not end within the bytes that are read.
            Ok(httparse::Status::Partial) if len == buf.len() => return Some(Asked::Bad),
            Ok(httparse::Status::Partial) => {}
            Err(_) => return Some(Asked::Bad),
        }
        match sock.read(&mut buf[len..]).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => len += n,
        }
    }
}

/// What a complete head asks for. The method comes first: another method than `GET` and `HEAD` is refused for any
/// target.
fn ask(head: &httparse::Request<'_, '_>) -> Asked {
    let (Some(method), Some(target), Some(1)) = (head.method, head.path, head.version) else {
        return Asked::Bad;
    };
    if method != "GET" && method != "HEAD" {
        return Asked::NotAllowed;
    }
    let page = match target {
        "/healthz" => Page::Healthz,
        "/readyz" => Page::Readyz,
        "/metrics" => Page::Metrics,
        _ => return Asked::NotFound,
    };
    Asked::Page {
        page,
        head_only: method == "HEAD",
    }
}

/// The whole answer as it is written to the socket: the status line, `fields` (each ends with a line break),
/// `Content-Length` of `body` and `Connection: close`, and the body unless `head_only`.
fn fixed(status: &str, fields: &str, body: &[u8], head_only: bool) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status}\r\n{fields}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    if !head_only {
        out.extend_from_slice(body);
    }
    out
}

/// The answer to `asked`.
fn reply<S: Source>(asked: Asked, source: &S) -> Vec<u8> {
    match asked {
        Asked::Page { page, head_only } => match page {
            Page::Healthz => fixed("200 OK", TEXT, b"ok", head_only),
            Page::Readyz => match source.ready() {
                Ok(()) => fixed("200 OK", TEXT, b"ready", head_only),
                Err(why) => fixed("503 Service Unavailable", TEXT, why.as_bytes(), head_only),
            },
            Page::Metrics => fixed("200 OK", EXPOSITION, source.metrics().as_bytes(), head_only),
        },
        Asked::NotAllowed => fixed("405 Method Not Allowed", "Allow: GET, HEAD\r\n", b"", false),
        Asked::NotFound => fixed("404 Not Found", "", b"", false),
        Asked::Bad => fixed("400 Bad Request", "", b"", false),
    }
}

/// Answers one connection: reads the head, writes the answer and closes. A connection that does not give a head in
/// time, or goes away, is closed without an answer.
async fn answer<S: Source>(mut sock: TcpStream, source: &S) {
    let Ok(Some(asked)) = timeout(HEAD_WAIT, read_head(&mut sock)).await else {
        return;
    };
    let bytes = reply(asked, source);
    let _ = timeout(WRITE_WAIT, send_and_close(&mut sock, &bytes)).await;
}

#[cfg(test)]
mod tests;
