//! An HTTP/2 connection, from the preface to the close.
//!
//! hyper serves the connection with `request` as its service, and every stream is a task of its own on the runtime
//! (`TokioExecutor`), so a stream that panics or is aborted is reset and the connection and the other streams go
//! on; a panic has one line in the record. The bytes come to hyper through the `Watch` of `frames`, which gives the
//! preface and the header blocks their times. The settings of hyper are all written out in `drive`, none is left to
//! its defaults, which it does not promise to keep; the only limit that stays with h2 is the number of `CONTINUATION`
//! frames of a header block, which h2 derives from the size of the header list (5 at least).
//!
//! Every stream is made into the head of an HTTP/1.1 request (see `head`) and then goes the way of every request
//! (see `conn`), and is answered as one. A stream that hyper or h2 refuses before it reaches the service (a reset,
//! a head over the size, a stream over `max_streams`, a client that floods the connection with resets) has no line of
//! its own. The connection has one at its end, with a fixed reason and the number of streams that reached the
//! service. A stream is counted when the service is called, before anything is waited for.
//!
//! A connection is wound down by one `graceful_shutdown` of hyper, which tells the client with a `GOAWAY` that no
//! new stream is taken, and ends the connection when the streams that are open are done. That is done when one of
//! these happens: the connection has served `keepalive_requests` streams or has lived `keepalive_time`, counted
//! when a stream begins (the streams that the client sent in the same write are taken, so the number is a measure
//! and the hard limit is `max_streams`); `keepalive_timeout` is 0 (after the first stream begins); the response of
//! a route with a `stream` is ready, which is then the last one; the stop has begun; the accept side calls to drain
//! the connections and none of its streams is open; or no stream is open and none has begun in the time that a
//! connection waits for the first one (the same time as the first head of a plain connection) or, after the last
//! stream ended, for `keepalive_timeout`.
//!
//! Winding down does not always end the connection: hyper waits for the client to answer a `PING` that it sends
//! with the `GOAWAY`, and for ever if it does not, and until it is answered h2 takes new streams. So a client that
//! was told `lingering_timeout` ago is not waited for any more. A stream that begins after that is turned away: it is
//! reset, is not counted, is not inspected and has no line of its own, and when more than `max_streams` of them have
//! been turned away the connection is dropped at once. Otherwise it is dropped when no stream has been open for
//! `lingering_timeout`, counted from the end of the last stream or from the `GOAWAY`, whichever is later: a client
//! that answers the `PING` has that time to take the end of a response that began earlier. Only the streams that began
//! before the client had its time can end later and put the drop off, and they keep their own limits. The time of the
//! connection (`conn_total`) ends it in any case, and a response of a route with a `stream` puts that time off as it
//! does for HTTP/1.1.
//!
//! A client may also take no more of a response: h2 holds the next chunk back while the window of the client has no
//! room for it, and does not ask the body for another one, so no write is pending and nothing in `io` times it. So
//! a chunk that a body has handed on has an instant by which it has to be taken in: hyper asks the body for the next
//! frame as soon as h2 has taken the chunk in, and that ends the wait. The time is `response_idle`, or `idle_ms` of
//! the route if it has a `stream`: what a response that stands still has on HTTP/1.1. When it has passed for a chunk,
//! the connection is ended. Progress is counted per chunk that the body hands to the client side, not per byte, so a
//! client has to take each chunk within that time. A body that waits for the upstream is not counted: the client does
//! not hold it back, and the read of the upstream fails that stream alone when it is silent for too long.
//!
//! The close is done here: the writing direction is ended (on TLS that sends the closing alert first) and the
//! connection lingers, reads and discards what the client still sends for a while (see `session`), so that a
//! `GOAWAY` that hyper has sent is not taken away by a reset. It does not linger when the connection was cut at
//! its time, when the preface or a header block did not come in time, when it was dropped for not answering, or when
//! a response stood still.

use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::panic::{self, AssertUnwindSafe};
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use http::{Request, Response};
use http_body::Body;
use hyper::body::Incoming;
use hyper::server::conn::http2::Builder;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::{Instant, sleep_until, timeout_at};

use super::frames::Watch;
use super::head::{build, upstream_uri};
use crate::config::{Http2Config, ProxyConfig};
use crate::inbound::answer::{Abort, Noted, Reply, answer};
use crate::inbound::conn::{Ctx, Handled, Scheme, after, peer_gone};
use crate::inbound::head::{Limits, Reject};
use crate::inbound::session::{
    Progress, Session, Summary, Tracked, close_write, first_head_by, linger, lock,
};
use crate::inbound::transport::tls::Hosts;
use crate::log::Log;

/// The streams that a client may reset before they are accepted, and the streams that the proxy may reset because
/// of what the client sent, before the connection is ended with a `GOAWAY`.
const PENDING_RESETS: usize = 20;
const LOCAL_ERROR_RESETS: usize = 1024;
/// The size of a frame (the least that HTTP/2 allows), and of the table of HPACK, in bytes.
const FRAME_SIZE: u32 = 16384;
const HEADER_TABLE: u32 = 4096;

/// What the connection and its streams share.
struct Life {
    /// Streams that reached the service.
    served: AtomicU64,
    /// Streams that are open: the service has been called and the response is not complete.
    active: AtomicU64,
    /// When the last stream ended (the accept, before there was one).
    last_end: Mutex<Instant>,
    /// No more streams are taken: the connection is to be wound down.
    wind_down: AtomicBool,
    /// When the client was told that no more streams are taken (the `GOAWAY` goes out then).
    told: OnceLock<Instant>,
    /// Streams that began too late and were turned away.
    refused: AtomicU64,
    /// The streams whose body has handed a chunk on that h2 has not taken in yet, by their numbers, with the instant
    /// by which it has to.
    held: Mutex<BTreeMap<u64, Instant>>,
    /// The task of the connection, woken when something here changes.
    parked: Mutex<Option<Waker>>,
}

/// A stream that is open. It is dropped with the response, or with the service if that ends without one.
struct Guard {
    life: Arc<Life>,
    /// The place of the stream among those that reached the service.
    n: u64,
    /// How long a chunk of the response may wait for the client.
    limit: Duration,
}

impl Life {
    fn new(accept: Instant) -> Arc<Life> {
        Arc::new(Life {
            served: AtomicU64::new(0),
            active: AtomicU64::new(0),
            last_end: Mutex::new(accept),
            wind_down: AtomicBool::new(false),
            told: OnceLock::new(),
            refused: AtomicU64::new(0),
            held: Mutex::new(BTreeMap::new()),
            parked: Mutex::new(None),
        })
    }

    /// A stream begins: it is counted, and the connection is wound down if it has served enough. A client that
    /// was told `lingering_timeout` ago has had its time: its stream is not counted as served but as turned away,
    /// and there is no guard for it.
    fn enter(self: &Arc<Self>, cfg: &ProxyConfig, accept: Instant) -> Option<Guard> {
        if let Some(told) = self.told.get()
            && Instant::now() >= after(*told, cfg.lingering_timeout)
        {
            self.refused.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let n = self
            .served
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        self.active.fetch_add(1, Ordering::AcqRel);
        if n >= u64::try_from(cfg.keepalive_requests).unwrap_or(u64::MAX)
            || accept.elapsed() >= cfg.keepalive_time
            || cfg.keepalive_timeout.is_zero()
        {
            self.wind_down();
        }
        Some(Guard {
            life: self.clone(),
            n,
            limit: cfg.response_idle,
        })
    }

    fn wind_down(&self) {
        self.wind_down.store(true, Ordering::Release);
        self.wake();
    }

    fn idle(&self) -> bool {
        self.active.load(Ordering::Acquire) == 0
    }

    /// The earliest instant by which a chunk that waits for the client has to be taken in, if one waits.
    fn held_by(&self) -> Option<Instant> {
        lock(&self.held).values().min().copied()
    }

    fn park(&self, waker: &Waker) {
        *lock(&self.parked) = Some(waker.clone());
    }

    fn wake(&self) {
        let waker = lock(&self.parked).take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl Progress for Guard {
    fn taken(&mut self) {
        lock(&self.life.held).remove(&self.n);
    }

    fn held(&mut self) {
        let by = after(Instant::now(), self.limit);
        let earliest = {
            let mut held = lock(&self.life.held);
            held.insert(self.n, by);
            held.values().min() == Some(&by)
        };
        // The connection waits for the earliest instant. A later one is found when that one has come, so only an
        // instant that is not later than what it waits for has to wake it.
        if earliest {
            self.life.wake();
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        lock(&self.life.held).remove(&self.n);
        // The time comes first, so that a connection that sees no stream open sees when the last one ended.
        *lock(&self.life.last_end) = Instant::now();
        self.life.active.fetch_sub(1, Ordering::AcqRel);
        self.life.wake();
    }
}

/// How the work of the connection ended.
enum Ended {
    Conn(hyper::Result<()>),
    /// The time of the connection passed.
    Limit,
    /// The client was told `lingering_timeout` ago and the connection did not end: no stream has been open since
    /// then or since the last one ended, or the client goes on opening streams that are turned away.
    Dropped,
    /// A chunk of a response waited for the client for as long as it may.
    Stalled,
}

/// Serves the connection to its end. `hosts` are those of the certificate of the handshake.
pub(in crate::inbound) async fn run<T>(
    stream: T,
    peer: SocketAddr,
    local: SocketAddr,
    ctx: &Arc<Ctx>,
    accept: Instant,
    hosts: Arc<Hosts>,
    settings: Http2Config,
) -> Summary
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let cfg = &ctx.cfg;
    let head_by = first_head_by(cfg, accept);
    let (mut watch, gauge) = Watch::new(
        stream,
        head_by,
        cfg.head_read,
        cfg.conn_total,
        cfg.response_idle,
    );
    let session = Session::new(ctx, peer, local, accept, Scheme::Https(hosts), gauge);
    let life = Life::new(accept);
    let ended = drive(&session, &life, &settings, &mut watch, head_by).await;
    let (reason, lingers) = if watch.timed_out() {
        (Reject::Timeout.reason(), false)
    } else {
        match &ended {
            Ended::Conn(Ok(())) => ("h2 connection ended", true),
            Ended::Conn(Err(e)) if peer_gone(e) => ("connection error", true),
            Ended::Conn(Err(_)) => ("h2 protocol error", true),
            Ended::Limit => ("connection time limit", false),
            Ended::Dropped => ("h2 goaway not answered", false),
            Ended::Stalled => ("closed while the response was sent", false),
        }
    };
    if !matches!(ended, Ended::Limit) {
        let by = after(Instant::now(), cfg.response_idle).min(session.conn_by());
        let sock = watch.stream();
        let _ = timeout_at(by, close_write(sock)).await;
        if lingers {
            linger(sock, cfg, session.conn_by()).await;
        }
    }
    let line = Reply {
        reason,
        ..Reply::NONE
    };
    session
        .summary(Some(line))
        .counted(life.served.load(Ordering::Relaxed))
}

/// Lets hyper serve the connection, winds it down when it is time (see the module documentation), and drops it when
/// it does not end.
async fn drive<T>(
    session: &Arc<Session>,
    life: &Arc<Life>,
    settings: &Http2Config,
    watch: &mut Watch<T>,
    head_by: Instant,
) -> Ended
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let ctx = &session.ctx;
    let cfg = &ctx.cfg;
    let service = {
        let (session, life) = (session.clone(), life.clone());
        let limits = Limits {
            max_head_bytes: cfg.max_head_bytes,
            max_body: u64::try_from(cfg.max_body).unwrap_or(u64::MAX),
        };
        service_fn(move |req: Request<Incoming>| {
            // A stream that begins too late has no guard, and `request` turns it away.
            let guard = life.enter(&session.ctx.cfg, session.accept);
            Watched {
                inner: Box::pin(request(session.clone(), limits, req, guard)),
                log: session.ctx.log.clone(),
                id: session.id,
            }
        })
    };
    let mut server = Builder::new(TokioExecutor::new());
    server
        .timer(TokioTimer::new())
        .max_concurrent_streams(settings.max_streams)
        .initial_stream_window_size(settings.stream_window)
        .initial_connection_window_size(settings.connection_window)
        .adaptive_window(false)
        .max_header_list_size(settings.max_header_list)
        .max_send_buf_size(settings.send_buffer)
        .max_frame_size(FRAME_SIZE)
        .header_table_size(HEADER_TABLE)
        .auto_date_header(true)
        .max_pending_accept_reset_streams(PENDING_RESETS)
        .max_local_error_reset_streams(LOCAL_ERROR_RESETS);
    let mut stop = ctx.ingress.watch();
    let mut changed = pin!(stop.changed());
    // A call to drain the connections: it counts only if none of the streams of this one is open.
    let mut calls = ctx.ingress.drained();
    let idle = life.clone();
    let mut drained = pin!(async move {
        loop {
            if calls.changed().await.is_err() {
                std::future::pending::<()>().await;
            } else if idle.idle() {
                return;
            }
        }
    });
    let mut conn = pin!(server.serve_connection(TokioIo::new(&mut *watch), service));
    // The connection is wound down once, and `life.told` has the instant. A stop that began before this is not seen
    // by `changed`.
    let mut down = ctx.ingress.is_closed();
    let mut by = session.conn_by();
    let mut limit = pin!(sleep_until(by));
    let mut wait = pin!(sleep_until(by));
    let mut waiting: Option<Instant> = None;
    let mut stall = pin!(sleep_until(by));
    let mut stalling: Option<Instant> = None;
    poll_fn(|cx| {
        life.park(cx.waker());
        loop {
            if life.told.get().is_none()
                && (down
                    || changed.as_mut().poll(cx).is_ready()
                    || drained.as_mut().poll(cx).is_ready()
                    || life.wind_down.load(Ordering::Acquire))
            {
                down = true;
                let _ = life.told.set(Instant::now());
                conn.as_mut().graceful_shutdown();
            }
            if let Poll::Ready(done) = conn.as_mut().poll(cx) {
                return Poll::Ready(Ended::Conn(done));
            }
            // The service is called inside that poll, which is where the streams that begin too late are turned
            // away: a client that goes on sending them is not answered any more.
            if life.refused.load(Ordering::Relaxed) > u64::from(settings.max_streams) {
                return Poll::Ready(Ended::Dropped);
            }
            // The service may have put off the end of the connection while it was polled.
            let now_by = session.conn_by();
            if now_by != by {
                limit.as_mut().reset(now_by);
                by = now_by;
            }
            if limit.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Ended::Limit);
            }
            // A chunk that waits for the client. This task is not woken when a chunk is taken in, so the instant that
            // was waited for can be too early: it is taken again.
            match life.held_by() {
                Some(at) => {
                    if stalling != Some(at) {
                        stall.as_mut().reset(at);
                        stalling = Some(at);
                    }
                    if stall.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(Ended::Stalled);
                    }
                }
                None => stalling = None,
            }
            // While no stream is open there is a time to wait for one, or for the client to end the connection that
            // was wound down: the client is not waited for longer than `lingering_timeout` from the `GOAWAY` or from
            // the end of the last stream, whichever is later.
            let ended = *lock(&life.last_end);
            let at = life.idle().then(|| match life.told.get() {
                Some(told) => after(ended.max(*told), cfg.lingering_timeout),
                None if life.served.load(Ordering::Relaxed) == 0 => head_by,
                None => after(ended, cfg.keepalive_timeout),
            });
            let Some(at) = at else {
                waiting = None;
                return Poll::Pending;
            };
            if waiting != Some(at) {
                wait.as_mut().reset(at);
                waiting = Some(at);
            }
            if wait.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            if life.told.get().is_some() {
                return Poll::Ready(Ended::Dropped);
            }
            // The wait is over, and the connection is wound down.
            down = true;
        }
    })
    .await
}

/// The service: one stream, from its head to its response.
async fn request(
    session: Arc<Session>,
    limits: Limits,
    req: Request<Incoming>,
    guard: Option<Guard>,
) -> Result<Response<Tracked<Guard>>, Abort> {
    // A stream that began too late is reset, with no line in the record.
    let mut guard = guard.ok_or(Abort)?;
    let start = Instant::now();
    let no_body = req.body().is_end_stream();
    let (mut parts, body) = req.into_parts();
    let head = build(&parts, no_body, &limits).and_then(|head| {
        parts.uri = upstream_uri(&head)?;
        Ok(head)
    });
    let head = match head {
        Ok(head) => head,
        Err(reject) => {
            let reply = Reply::of(reject);
            let noted = Noted {
                reply,
                client: session.peer.ip(),
                via: None,
            };
            return Ok(session.track(noted, answer(reply.status), start, guard));
        }
    };
    let conn = session.conn(head, start);
    let Handled {
        noted,
        response,
        stream,
        ..
    } = conn.handle(parts, body).await;
    match response {
        Ok(response) => {
            // The response may take long, so it is the last one, as on an HTTP/1.1 connection.
            if let Some(stream) = &stream {
                session.lengthen(stream);
                guard.life.wind_down();
                guard.limit = stream.idle;
            }
            Ok(session.track(noted, response, start, guard))
        }
        Err(abort) => {
            session.note(&noted, start);
            Err(abort)
        }
    }
}

/// A future whose panic has a line in the record before it goes on.
struct Watched<F> {
    inner: Pin<Box<F>>,
    log: Log,
    id: u64,
}

impl<F: Future> Future for Watched<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        let this = self.get_mut();
        match panic::catch_unwind(AssertUnwindSafe(|| this.inner.as_mut().poll(cx))) {
            Ok(polled) => polled,
            Err(payload) => {
                this.log
                    .line(&format!("conn {}: h2 stream panicked", this.id));
                panic::resume_unwind(payload)
            }
        }
    }
}

#[cfg(test)]
mod tests;
