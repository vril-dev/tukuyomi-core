//! One client connection, from the accept to the close.
//!
//! The first head is read through the gate before hyper starts, so that a refused one can be answered with the
//! fixed answer of `head`. Then hyper serves the connection for as long as it lasts, with the gate as its input
//! and `Session::request` as its service: every request that hyper makes is matched with the head the gate passed,
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
//! response that closed the connection, or a head that was refused with bytes behind it, the connection reads and
//! discards what the client still sends for a while (`linger`). A close with unread bytes in the socket resets the
//! connection, and the reset can take the response away from a client that is still sending, or whose next
//! request crossed the response. A connection that ends because nothing came for `keepalive_timeout` does not
//! linger: there is no response to protect.
//!
//! Every response has one line in the record, written when the response has been given to the connection or was
//! cut off. The line has the address of the client that the inspection was told (see `conn`); a line that is
//! written before a request has been read has the address of the peer. A request that was sent to an upstream has
//! the group and the server in its line. A connection that never had a response, and
//! one that was closed over a head that was refused after the first, have a line of their own when they end. So does
//! a tunnel, also one that never ran (see `tunnel`).

use std::future::{Future, poll_fn};
use std::io;
use std::net::SocketAddr;
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};

use bytes::Bytes;
use http::{Request, Response, Version};
use http_body::{Body, Frame, SizeHint};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time::{Instant, sleep_until, timeout_at};
use tukuyomi_kernel::limits;

use crate::config::{ProxyConfig, Stream};
use crate::forward::tunnel::Tunnel;
use crate::inbound::answer::{Abort, Class, Noted, Out, Reply, answer, close_after, record};
use crate::inbound::conn::{Conn, Ctx, Handled, after};
use crate::inbound::gate::{Finish, Gate, Link, Settings, Taken};
use crate::inbound::head::Reject;
use crate::inbound::io::Gauge;

/// Numbers the connections for the records. They say nothing else.
static NEXT_CONN: AtomicU64 = AtomicU64::new(1);

/// How the hyper connection ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    Done,
    Error,
    Limit,
}

/// What the connection does after the response of a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Then {
    /// Waits for the next request.
    Keep,
    /// Closes after the response, and reads and discards what the client still sends.
    Close,
}

/// What came of a connection: the reply of its last request, and the line that its end adds to the record if it
/// has to.
pub(super) struct Summary {
    id: u64,
    /// For the tests of the record.
    #[cfg(test)]
    pub(super) last: Reply,
    line: Option<Reply>,
}

/// The state of one client connection that its service and its responses share.
struct Session {
    ctx: Arc<Ctx>,
    peer: SocketAddr,
    local: SocketAddr,
    id: u64,
    accept: Instant,
    /// End of the connection. A response that may take long puts it off (`lengthen`).
    conn_by: Mutex<Instant>,
    link: Arc<Link>,
    gauge: Gauge,
    /// Requests that hyper handed to the service.
    served: AtomicU64,
    /// Lines written for responses.
    recorded: AtomicU64,
    /// A response that ends the connection was given.
    closing: AtomicBool,
    /// The tunnel that the 101 response started. It runs once hyper is done with the connection. It has the line for
    /// its end from the start, so it is written also if the tunnel is dropped here.
    tunnel: Mutex<Option<Tunnel>>,
    /// The reply of the response that was recorded last, for the tests of the record.
    #[cfg(test)]
    last: Mutex<Reply>,
}

/// Serves one accepted connection to its end.
pub async fn serve(sock: TcpStream, peer: SocketAddr, local: SocketAddr, ctx: Arc<Ctx>) {
    let accept = Instant::now();
    let summary = run(sock, peer, local, &ctx, accept).await;
    if let Some(reply) = summary.line {
        if reply.internal {
            ctx.log.line(&format!(
                "conn {}: internal fault: {}",
                summary.id, reply.reason
            ));
        }
        ctx.log.line(&record(
            summary.id,
            &reply,
            accept.elapsed(),
            peer.ip(),
            None,
        ));
    }
}

/// Reads the first head, serves the requests, closes. `accept` is the instant of the accept.
pub(super) async fn run(
    sock: TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
    ctx: &Arc<Ctx>,
    accept: Instant,
) -> Summary {
    let cfg = &ctx.cfg;
    let (session, mut gate) = Session::start(sock, peer, local, ctx, accept);
    let head_by = after(accept, cfg.head_read).min(after(accept, cfg.request_total));
    if let Err(reject) = gate.first_head(head_by).await {
        return session.refuse(&mut gate, reject).await;
    }
    let end = session.drive(&mut gate).await;
    match session.take_tunnel(end) {
        Some(tunnel) => session.run_tunnel(&mut gate, tunnel).await,
        None => session.close(&mut gate, end).await,
    }
    session.summary(&gate, end)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Session {
    /// The state of a connection, and the gate over its stream.
    fn start<T>(
        stream: T,
        peer: SocketAddr,
        local: SocketAddr,
        ctx: &Arc<Ctx>,
        accept: Instant,
    ) -> (Arc<Session>, Gate<T>) {
        let cfg = &ctx.cfg;
        let link = Link::new(accept);
        let (gate, gauge) = Gate::new(stream, Settings::new(cfg), link.clone(), accept);
        let session = Arc::new(Session {
            ctx: ctx.clone(),
            peer,
            local,
            id: NEXT_CONN.fetch_add(1, Ordering::Relaxed),
            accept,
            conn_by: Mutex::new(after(accept, cfg.conn_total)),
            link,
            gauge,
            served: AtomicU64::new(0),
            recorded: AtomicU64::new(0),
            closing: AtomicBool::new(false),
            tunnel: Mutex::new(None),
            #[cfg(test)]
            last: Mutex::new(Reply::NONE),
        });
        (session, gate)
    }

    fn conn_by(&self) -> Instant {
        *lock(&self.conn_by)
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
        let cfg = &self.ctx.cfg;
        let service = {
            let session = self.clone();
            service_fn(move |req: Request<Incoming>| {
                let session = session.clone();
                // Boxed, for a connection that is polled without its shutdown needs a future that is `Unpin`.
                Box::pin(async move { session.request(req).await })
            })
        };
        let mut server = http1::Builder::new();
        server
            .keep_alive(true)
            .half_close(false)
            .timer(TokioTimer::new())
            .header_read_timeout(None)
            .max_headers(limits::HEADERS)
            .max_header_size(cfg.max_head_bytes)
            .max_buf_size(cfg.max_head_bytes.max(8192))
            .title_case_headers(true);
        let mut stop = self.ctx.ingress.watch();
        let mut changed = pin!(stop.changed());
        // A call to drain the connections that wait for a request: it counts only if this one waits for one.
        let mut calls = self.ctx.ingress.drained();
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
        let mut by = self.conn_by();
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
            let now_by = self.conn_by();
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
    async fn request(self: &Arc<Self>, req: Request<Incoming>) -> Result<Response<Tracked>, Abort> {
        let n = self
            .served
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        let (parts, body) = req.into_parts();
        let Some(Taken { head, start }) = self.link.take_for(&parts) else {
            // Hyper made a request of bytes that the head check did not pass as that request.
            let noted = Noted {
                reply: Reply::rejected(400, "the two parsers disagree"),
                client: self.peer.ip(),
                via: None,
            };
            return Ok(self.respond(noted, answer(400), Then::Close, false, Instant::now()));
        };
        let conn = Conn::new(
            &self.ctx,
            self.id,
            head,
            self.peer,
            self.local,
            self.gauge.clone(),
            after(start, self.ctx.cfg.request_total),
        );
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
                    self.lengthen(stream);
                }
                let old = conn.head().http10();
                Ok(self.respond(noted, response, then, old, start))
            }
            Err(abort) => {
                self.note(&noted, start);
                Err(abort)
            }
        }
    }

    /// What the connection does after the response to the `n`th request. `long` is true for a response that may take
    /// long: it is the last.
    fn then(&self, conn: &Conn, n: u64, long: bool) -> Then {
        let cfg = &self.ctx.cfg;
        let head = conn.head();
        let spent = n >= u64::try_from(cfg.keepalive_requests).unwrap_or(u64::MAX)
            || self.accept.elapsed() >= cfg.keepalive_time;
        let closing = !conn.body_read()
            || head.http10()
            || head.chunked()
            || head.close()
            || head.upgrade()
            || long
            || cfg.keepalive_timeout.is_zero();
        if closing || spent || self.ctx.ingress.is_closed() {
            Then::Close
        } else {
            Then::Keep
        }
    }

    /// The head of a response that may take long is ready: the connection lasts until `total` after now at the
    /// earliest, and the client may be silent for that long (and for the connection time, if that is more). The old
    /// end has not come: the head was ready within the request time, which `keepalive_time` leaves inside the
    /// connection time.
    fn lengthen(&self, stream: &Stream) {
        let by = after(Instant::now(), stream.total);
        {
            let mut conn_by = lock(&self.conn_by);
            *conn_by = (*conn_by).max(by);
        }
        self.gauge
            .restart(stream.total.max(self.ctx.cfg.conn_total));
    }

    /// The response as it goes to hyper: marked as the last one if the connection ends with it, an HTTP/1.0
    /// response to an HTTP/1.0 request (hyper then does not add `keep-alive` to the `Connection` field of a
    /// request that asked for it), and followed by the line in the record and the note to the gate once it is
    /// complete.
    fn respond(
        self: &Arc<Self>,
        noted: Noted,
        mut response: Response<Out>,
        then: Then,
        old: bool,
        start: Instant,
    ) -> Response<Tracked> {
        if then == Then::Close {
            close_after(&mut response);
            self.closing.store(true, Ordering::Release);
        }
        if old {
            *response.version_mut() = Version::HTTP_10;
        }
        response.map(|body| Tracked {
            body,
            session: self.clone(),
            noted,
            start,
            ended: false,
            _finish: self.link.finish(),
        })
    }

    /// Writes the line of a request in the record, under the client address that `noted` has.
    fn note(&self, noted: &Noted, start: Instant) {
        let reply = noted.reply;
        #[cfg(test)]
        {
            *lock(&self.last) = reply;
        }
        self.recorded.fetch_add(1, Ordering::Relaxed);
        if reply.internal {
            self.ctx.log.line(&format!(
                "conn {}: internal fault: {}",
                self.id, reply.reason
            ));
        }
        self.ctx.log.line(&record(
            self.id,
            &reply,
            start.elapsed(),
            noted.client,
            noted.via.as_ref(),
        ));
    }

    /// Answers a first head that was refused, and closes. A head that did not come in time gets its answer and
    /// no more; any other has bytes behind it that the client may still be sending.
    async fn refuse(&self, gate: &mut Gate<TcpStream>, reject: Reject) -> Summary {
        let cfg = &self.ctx.cfg;
        let reply = if let Some(answer) = reject.response() {
            let by = after(Instant::now(), cfg.response_idle).min(self.conn_by());
            let sock = gate.stream();
            let _ = timeout_at(by, send_and_close(sock, answer)).await;
            if reject != Reject::Timeout {
                linger(sock, cfg, self.conn_by()).await;
            }
            Reply::of(reject)
        } else {
            Reply {
                reason: reject.reason(),
                ..Reply::NONE
            }
        };
        Summary {
            id: self.id,
            #[cfg(test)]
            last: reply,
            line: Some(reply),
        }
    }

    /// Ends the writing direction, and lingers if a response closed the connection or a head was refused.
    async fn close(&self, gate: &mut Gate<TcpStream>, end: End) {
        if end == End::Limit {
            return;
        }
        let cfg = &self.ctx.cfg;
        let lingers = self.closing.load(Ordering::Acquire) || gate.failure().is_some();
        let by = after(Instant::now(), cfg.response_idle).min(self.conn_by());
        let sock = gate.stream();
        let _ = timeout_at(by, close_write(sock)).await;
        if lingers {
            linger(sock, cfg, self.conn_by()).await;
        }
    }

    /// The tunnel of a 101 that was given and whose connection ended well; any other is given up, which closes the
    /// connection to the upstream and writes the line for its end.
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
    async fn run_tunnel(&self, gate: &mut Gate<TcpStream>, tunnel: Tunnel) {
        let rest = gate.take_rest();
        let sock = gate.stream();
        tunnel.run(&mut *sock, rest, &self.ctx.cfg).await;
        let by = after(Instant::now(), self.ctx.cfg.response_idle);
        let _ = timeout_at(by, close_write(sock)).await;
    }

    /// The reply of the last request, and the line the end of the connection adds: for a head that was refused
    /// after the first, and for a connection that had no response to show for itself.
    fn summary(&self, gate: &Gate<TcpStream>, end: End) -> Summary {
        let line = if let Some(reject) = gate.failure() {
            Some(Reply {
                reason: reject.reason(),
                ..Reply::NONE
            })
        } else if self.recorded.load(Ordering::Relaxed) == 0 {
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
        Summary {
            id: self.id,
            #[cfg(test)]
            last: *lock(&self.last),
            line,
        }
    }
}

/// The body of a response, and the end of its request. The line in the record is written, and the gate is told
/// that the request is answered, when this is dropped: hyper drops it when it has encoded the last frame of the
/// body, which can be before the bytes are out (the gate also waits for the flush), and when the connection goes
/// away.
struct Tracked {
    body: Out,
    session: Arc<Session>,
    noted: Noted,
    start: Instant,
    /// The body gave its end.
    ended: bool,
    _finish: Finish,
}

impl Body for Tracked {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.body).poll_frame(cx);
        if matches!(polled, Poll::Ready(None)) {
            this.ended = true;
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

impl Drop for Tracked {
    fn drop(&mut self) {
        // A body whose length is known is not asked for its end, only for its last frame.
        let whole = self.ended || self.body.is_end_stream();
        if !whole && self.noted.reply.class == Class::Forwarded {
            self.noted.reply.reason = "closed while the response was sent";
        }
        self.session.note(&self.noted, self.start);
    }
}

/// Writes all of `bytes`, then ends the sending direction.
async fn send_and_close(sock: &mut TcpStream, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        if sock.writable().await.is_err() {
            return;
        }
        match sock.try_write(bytes) {
            Ok(0) => return,
            Ok(n) => bytes = &bytes[n..],
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => return,
        }
    }
    close_write(sock).await;
}

/// Ends the sending direction: the client reads the end of the response.
async fn close_write(sock: &mut TcpStream) {
    let _ = poll_fn(|cx| Pin::new(&mut *sock).poll_shutdown(cx)).await;
}

/// Reads and discards what the client still sends, until the end of its stream (a client that has closed its side
/// ends it at once), `lingering_bytes` bytes, a read that waits for `lingering_timeout`, `lingering_time` after the
/// start or the end of the connection time.
async fn linger(sock: &mut TcpStream, cfg: &ProxyConfig, conn_by: Instant) {
    let end = after(Instant::now(), cfg.lingering_time).min(conn_by);
    let mut left = cfg.lingering_bytes;
    let mut buf = [0u8; 4096];
    while left > 0 {
        let by = after(Instant::now(), cfg.lingering_timeout).min(end);
        match timeout_at(by, sock.readable()).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) | Err(_) => return,
        }
        // Not a byte over the limit is read.
        let room = left.min(buf.len());
        match sock.try_read(&mut buf[..room]) {
            Ok(0) => return,
            Ok(n) => left = left.saturating_sub(n),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => return,
        }
    }
}

#[cfg(test)]
mod tests;
