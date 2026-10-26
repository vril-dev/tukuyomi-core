//! An HTTP/1.1 connection, from the first head to the close.
//!
//! The first head is read through the gate before hyper starts, so that a refused one can be answered with the
//! fixed answer of `head`. Then hyper serves the connection for as long as it lasts, with the gate as its input
//! and `Serving::request` as its service: every request that hyper makes is matched with the head the gate passed,
//! handled by `conn`, and answered. The time of a request counts from its own start (`gate::Taken`), and a
//! connection that has answered all its requests waits for the next one for `keepalive_timeout` (see `gate`).
//!
//! The connection goes on after a response unless one of these closes it: the request was HTTP/1.0 or chunked or
//! said `Connection: close` or has an `Upgrade` line (the gate reads nothing behind such a head); the route of the
//! request has a `stream`, so the response may take long and is the last one; `keepalive_timeout` is 0; the
//! connection has served `keepalive_requests` requests or has lived `keepalive_time`; the body of the request was
//! not read to its end when the answer was given; the stop has begun (an idle connection is closed at once, one
//! with a request under way after its response). A response that closes the connection says `Connection: close`,
//! so the client knows. The 101 of a WebSocket does not: it ends the connection by itself, and once that head has
//! been passed hyper is not told to wind the connection down, for it would add a `Connection: close` of its own to
//! the 101. A connection that waits for its next request is also closed at once when the accept side runs out of
//! connection permits (`Ingress::drain`); one that is in a request is left alone.
//!
//! A response from a route with a `stream` that is not a 101 may last longer than the connection time: when its
//! head is ready, the end of the connection becomes the later of the old end and `total` after the head, and the
//! client may be silent for that long. After a 101 hyper is done with the connection, and the connection time ends
//! with it: the tunnel (see `tunnel`) runs over the stream of the client, with the bytes that the gate had read
//! behind the handshake in front, for the time that the route says. The stop does not end it; the abort at the end
//! of the time that the connections get does.
//!
//! The close is done here, after hyper is done with the connection: the writing direction is ended, and after a
//! response that closed the connection, or a head that was refused with bytes behind it, the connection lingers
//! (see `session`). A connection that ends because nothing came for `keepalive_timeout` does not linger: there is no
//! response to protect.

use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;

use http::{Request, Response, Version};
use hyper::body::Incoming;
use hyper::server::conn::http1::Builder;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::{Instant, sleep_until, timeout_at};
use tukuyomi_kernel::limits;

use super::gate::{Finish, Gate, Link, Settings, Taken};
use crate::forward::tunnel::Tunnel;
use crate::inbound::answer::{Abort, Noted, Out, Reply, answer, close_after};
use crate::inbound::conn::{Conn, Ctx, Handled, Scheme, after};
use crate::inbound::head::Reject;
use crate::inbound::session::{
    End, Progress, Proto, Session, Summary, Tracked, close_write, first_head_by, linger, lock,
    send_and_close,
};

/// What the connection does after the response of a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Then {
    /// Waits for the next request.
    Keep,
    /// Closes after the response, and reads and discards what the client still sends.
    Close,
}

/// The state of one HTTP/1.1 connection beyond what every connection has: the checked heads that the gate and the
/// service pass between them, and what follows from the responses that were given.
pub(super) struct Serving {
    pub(super) session: Arc<Session>,
    pub(super) link: Arc<Link>,
    /// Requests that hyper handed to the service.
    served: AtomicU64,
    /// A response that ends the connection was given.
    closing: AtomicBool,
    /// The tunnel that the 101 response started. It runs once hyper is done with the connection. It has the record for
    /// its end from the start, so it is written also if the tunnel is dropped here.
    tunnel: Mutex<Option<Tunnel>>,
}

/// The gate has nothing to do while the body of a response is sent.
impl Progress for Finish {}

/// Reads the first head, serves the requests, closes. `listener` is the place of the listener that took the
/// connection, and `accept` the instant of the accept.
pub(in crate::inbound) async fn run<T>(
    stream: T,
    peer: SocketAddr,
    local: SocketAddr,
    ctx: &Arc<Ctx>,
    listener: usize,
    accept: Instant,
    scheme: Scheme,
) -> Summary
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let (serving, mut gate) = Serving::start(stream, peer, local, ctx, listener, accept, scheme);
    if let Err(reject) = gate.first_head(first_head_by(&ctx.cfg, accept)).await {
        return serving.refuse(&mut gate, reject).await;
    }
    let end = serving.drive(&mut gate).await;
    match serving.take_tunnel(end) {
        Some(tunnel) => serving.run_tunnel(&mut gate, tunnel).await,
        None => serving.close(&mut gate, end).await,
    }
    serving.summary(&gate, end)
}

impl Serving {
    /// The state of a connection, and the gate over its stream.
    pub(super) fn start<T>(
        stream: T,
        peer: SocketAddr,
        local: SocketAddr,
        ctx: &Arc<Ctx>,
        listener: usize,
        accept: Instant,
        scheme: Scheme,
    ) -> (Arc<Serving>, Gate<T>) {
        let link = Link::new(accept);
        let (gate, gauge) = Gate::new(stream, Settings::new(&ctx.cfg), link.clone(), accept);
        let serving = Arc::new(Serving {
            session: Session::new(ctx, peer, local, listener, Proto::H1, accept, scheme, gauge),
            link,
            served: AtomicU64::new(0),
            closing: AtomicBool::new(false),
            tunnel: Mutex::new(None),
        });
        (serving, gate)
    }

    /// Lets hyper serve the connection to its end. The stop makes hyper close the connection when it is idle, and
    /// after the response of the request under way otherwise, unless the last head has an `Upgrade` line: nothing
    /// follows that, and hyper would add `Connection: close` to a 101. A stop that began before this is seen by
    /// `then`. If a 101 was given, hyper must not have read a byte behind the handshake (the gate gives it none),
    /// or the connection ends in an error.
    async fn drive<T>(self: &Arc<Self>, gate: &mut Gate<T>) -> End
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let ctx = &self.session.ctx;
        let cfg = &ctx.cfg;
        let service = {
            let serving = self.clone();
            service_fn(move |req: Request<Incoming>| {
                let serving = serving.clone();
                // Boxed, for a connection that is polled without its shutdown needs a future that is `Unpin`.
                Box::pin(async move { serving.request(req).await })
            })
        };
        let mut server = Builder::new();
        server
            .keep_alive(true)
            .half_close(false)
            .timer(TokioTimer::new())
            .header_read_timeout(None)
            .max_headers(limits::HEADERS)
            .max_header_size(cfg.max_head_bytes)
            .max_buf_size(cfg.max_head_bytes.max(8192))
            .title_case_headers(true);
        let mut stop = ctx.ingress.watch();
        let mut changed = pin!(stop.changed());
        // A call to drain the connections that wait for a request: it counts only if this one waits for one.
        let mut calls = ctx.ingress.drained();
        let link = self.link.clone();
        let mut drained = pin!(async move {
            loop {
                if calls.changed().await.is_err() {
                    std::future::pending::<()>().await;
                } else if link.waiting() {
                    return;
                }
            }
        });
        let mut told = false;
        let mut conn = server.serve_connection(TokioIo::new(&mut *gate), service);
        let mut by = self.session.conn_by();
        let mut limit = pin!(sleep_until(by));
        let ended = poll_fn(|cx| {
            if !told
                && (changed.as_mut().poll(cx).is_ready() || drained.as_mut().poll(cx).is_ready())
            {
                told = true;
                if !self.link.last() {
                    Pin::new(&mut conn).graceful_shutdown();
                }
            }
            if let Poll::Ready(done) = conn.poll_without_shutdown(cx) {
                return Poll::Ready(Some(done));
            }
            // The service may have put off the end of the connection while it was polled.
            let now_by = self.session.conn_by();
            if now_by != by {
                limit.as_mut().reset(now_by);
                by = now_by;
            }
            if limit.as_mut().poll(cx).is_ready() {
                Poll::Ready(None)
            } else {
                Poll::Pending
            }
        })
        .await;
        match ended {
            None => End::Limit,
            Some(Err(_)) => End::Error,
            Some(Ok(())) => {
                let tunnel = lock(&self.tunnel).is_some();
                if tunnel && !conn.into_parts().read_buf.is_empty() {
                    End::Error
                } else {
                    End::Done
                }
            }
        }
    }

    /// The service: one request that hyper made of the bytes the gate passed.
    async fn request(
        self: &Arc<Self>,
        req: Request<Incoming>,
    ) -> Result<Response<Tracked<Finish>>, Abort> {
        let n = self
            .served
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        let (parts, body) = req.into_parts();
        let Some(Taken { head, start }) = self.link.take_for(&parts) else {
            // Hyper made a request of bytes that the head check did not pass as that request.
            let noted = Noted::new(
                self.session.ctx.ids.mint(),
                Reply::rejected(400, "the two parsers disagree"),
                self.session.peer.ip(),
            );
            return Ok(self.respond(noted, answer(400), Then::Close, false, Instant::now()));
        };
        let conn = self.session.conn(head, start);
        let Handled {
            noted,
            response,
            tunnel,
            stream,
        } = conn.handle(parts, body).await;
        match response {
            Ok(response) => {
                // The 101 ends the connection by itself, so it is not marked as the last response.
                let then = if let Some(tunnel) = tunnel {
                    *lock(&self.tunnel) = Some(tunnel);
                    Then::Keep
                } else {
                    self.then(&conn, n, stream.is_some())
                };
                if let Some(stream) = &stream {
                    self.session.lengthen(stream);
                }
                let old = conn.head().http10();
                Ok(self.respond(noted, response, then, old, start))
            }
            Err(abort) => {
                let mut noted = noted;
                self.session.note(&mut noted, start, 0);
                Err(abort)
            }
        }
    }

    /// What the connection does after the response to the `n`th request. `long` is true for a response that may take
    /// long: it is the last.
    fn then(&self, conn: &Conn, n: u64, long: bool) -> Then {
        let ctx = &self.session.ctx;
        let cfg = &ctx.cfg;
        let head = conn.head();
        let spent = n >= u64::try_from(cfg.keepalive_requests).unwrap_or(u64::MAX)
            || self.session.accept.elapsed() >= cfg.keepalive_time;
        let closing = !conn.body_read()
            || head.http10()
            || head.chunked()
            || head.close()
            || head.upgrade()
            || long
            || cfg.keepalive_timeout.is_zero();
        if closing || spent || ctx.ingress.is_closed() {
            Then::Close
        } else {
            Then::Keep
        }
    }

    /// The response as it goes to hyper: marked as the last one if the connection ends with it, an HTTP/1.0
    /// response to an HTTP/1.0 request (hyper then does not add `keep-alive` to the `Connection` field of a
    /// request that asked for it), and followed by the record of the request and the note to the gate once it is
    /// complete.
    fn respond(
        self: &Arc<Self>,
        noted: Noted,
        mut response: Response<Out>,
        then: Then,
        old: bool,
        start: Instant,
    ) -> Response<Tracked<Finish>> {
        if then == Then::Close {
            close_after(&mut response);
            self.closing.store(true, Ordering::Release);
        }
        if old {
            *response.version_mut() = Version::HTTP_10;
        }
        self.session
            .track(noted, response, start, self.link.finish())
    }

    /// Answers a first head that was refused, and closes. A head that did not come in time gets its answer and
    /// no more; any other has bytes behind it that the client may still be sending.
    pub(super) async fn refuse<T>(&self, gate: &mut Gate<T>, reject: Reject) -> Summary
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let session = &self.session;
        let cfg = &session.ctx.cfg;
        let id = session.ctx.ids.mint();
        let Some(answer) = reject.response(&id) else {
            let reply = Reply {
                reason: reject.reason(),
                ..Reply::NONE
            };
            return Summary::of(session.id, reply);
        };
        let by = after(Instant::now(), cfg.response_idle).min(session.conn_by());
        let sock = gate.stream();
        let _ = timeout_at(by, send_and_close(sock, &answer)).await;
        // The record of the answer comes before the wait for the client to stop sending.
        let mut noted = Noted::new(id, Reply::of(reject), session.peer.ip());
        session.note(&mut noted, session.accept, 0);
        if reject != Reject::Timeout {
            linger(sock, cfg, session.conn_by()).await;
        }
        session.summary(None)
    }

    /// Ends the writing direction, and lingers if a response closed the connection or a head was refused.
    async fn close<T>(&self, gate: &mut Gate<T>, end: End)
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        if end == End::Limit {
            return;
        }
        let session = &self.session;
        let cfg = &session.ctx.cfg;
        let lingers = self.closing.load(Ordering::Acquire) || gate.failure().is_some();
        let by = after(Instant::now(), cfg.response_idle).min(session.conn_by());
        let sock = gate.stream();
        let _ = timeout_at(by, close_write(sock)).await;
        if lingers {
            linger(sock, cfg, session.conn_by()).await;
        }
    }

    /// The tunnel of a 101 that was given and whose connection ended well; any other is given up, which closes the
    /// connection to the upstream and writes the record for its end.
    fn take_tunnel(&self, end: End) -> Option<Tunnel> {
        let tunnel = lock(&self.tunnel).take()?;
        if end == End::Done {
            Some(tunnel)
        } else {
            tunnel.failed();
            None
        }
    }

    /// Runs the tunnel over the stream of the client, with what the gate had read behind the handshake in front,
    /// and ends the writing direction. The time of the connection is not asked: the tunnel has its own.
    async fn run_tunnel<T>(&self, gate: &mut Gate<T>, tunnel: Tunnel)
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let rest = gate.take_rest();
        let sock = gate.stream();
        tunnel.run(&mut *sock, rest, &self.session.ctx.cfg).await;
        let by = after(Instant::now(), self.session.ctx.cfg.response_idle);
        let _ = timeout_at(by, close_write(sock)).await;
    }

    /// The reply of the last request, and the reply that the record of the type `connection` shows at the end of the
    /// connection: for a head that was refused after the first, and for a connection that had no response to show for
    /// itself.
    fn summary<T>(&self, gate: &Gate<T>, end: End) -> Summary {
        let line = if let Some(reject) = gate.failure() {
            Some(Reply {
                reason: reject.reason(),
                ..Reply::NONE
            })
        } else if self.session.recorded.load(Ordering::Relaxed) == 0 {
            Some(Reply {
                reason: match end {
                    End::Done => Reply::NONE.reason,
                    End::Error => "connection error",
                    End::Limit => "connection time limit",
                },
                ..Reply::NONE
            })
        } else {
            None
        };
        self.session.summary(line)
    }
}

#[cfg(test)]
mod tests;
