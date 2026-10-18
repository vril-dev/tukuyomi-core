//! One client connection, from the accept to the close.
//!
//! The first head is read through the gate before hyper starts, so that a refused one can be answered with the
//! fixed answer of `head`. Then hyper serves the connection for as long as it lasts, with the gate as its input
//! and `Session::request` as its service: every request that hyper makes is matched with the head the gate passed,
//! handled by `conn`, and answered. The time of a request counts from its own start (`gate::Taken`), and a
//! connection that has answered all its requests waits for the next one for `keepalive_timeout` (see `gate`).
//!
//! The connection goes on after a response unless one of these closes it: the request was HTTP/1.0 or chunked or
//! said `Connection: close`; `keepalive_timeout` is 0; the connection has served `keepalive_requests` requests or
//! has lived `keepalive_time`; the body of the request was not read to its end when the answer was given; the stop
//! has begun (an idle connection is closed at once, one with a request under way after its response). A response
//! that closes the connection says `Connection: close`, so the client knows. A connection that waits for its
//! next request is also closed at once when the accept side runs out of connection permits (`Ingress::drain`);
//! one that is in a request is left alone.
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
//! written before a request has been read has the address of the peer. A connection that never had a response, and
//! one that was closed over a head that was refused after the first, have a line of their own when they end.

use std::future::{Future, poll_fn};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(test)]
use std::sync::{Mutex, PoisonError};
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
use tokio::time::{Instant, timeout_at};
use tukuyomi_kernel::limits;

use crate::config::ProxyConfig;
use crate::inbound::answer::{Abort, Class, Out, Reply, answer, close_after, record};
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
    /// End of the connection.
    conn_by: Instant,
    link: Arc<Link>,
    gauge: Gauge,
    /// Requests that hyper handed to the service.
    served: AtomicU64,
    /// Lines written for responses.
    recorded: AtomicU64,
    /// A response that ends the connection was given.
    closing: AtomicBool,
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
        ctx.log
            .line(&record(summary.id, &reply, accept.elapsed(), peer.ip()));
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
    session.close(&mut gate, end).await;
    session.summary(&gate, end)
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
            conn_by: after(accept, cfg.conn_total),
            link,
            gauge,
            served: AtomicU64::new(0),
            recorded: AtomicU64::new(0),
            closing: AtomicBool::new(false),
            #[cfg(test)]
            last: Mutex::new(Reply::NONE),
        });
        (session, gate)
    }

    /// Lets hyper serve the connection to its end. The stop makes hyper close the connection when it is idle, and
    /// after the response of the request under way otherwise. A stop that began before this is seen by `then`.
    async fn drive<T>(self: &Arc<Self>, gate: &mut Gate<T>) -> End
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let cfg = &self.ctx.cfg;
        let service = {
            let session = self.clone();
            service_fn(move |req: Request<Incoming>| {
                let session = session.clone();
                async move { session.request(req).await }
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
        let mut conn = pin!(server.serve_connection(TokioIo::new(&mut *gate), service));
        let ended = timeout_at(
            self.conn_by,
            poll_fn(|cx| {
                if !told
                    && (changed.as_mut().poll(cx).is_ready()
                        || drained.as_mut().poll(cx).is_ready())
                {
                    told = true;
                    conn.as_mut().graceful_shutdown();
                }
                conn.as_mut().poll(cx)
            }),
        )
        .await;
        match ended {
            Ok(Ok(())) => End::Done,
            Ok(Err(_)) => End::Error,
            Err(_) => End::Limit,
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
            let reply = Reply::rejected(400, "the two parsers disagree");
            let client = self.peer.ip();
            return Ok(self.respond(
                reply,
                client,
                answer(400),
                Then::Close,
                false,
                Instant::now(),
            ));
        };
        let conn = Conn::new(
            &self.ctx,
            head,
            self.peer,
            self.local,
            self.gauge.clone(),
            after(start, self.ctx.cfg.request_total),
        );
        let Handled {
            reply,
            client,
            response,
        } = conn.handle(parts, body).await;
        match response {
            Ok(response) => {
                let then = self.then(&conn, n);
                let old = conn.head().http10();
                Ok(self.respond(reply, client, response, then, old, start))
            }
            Err(abort) => {
                self.note(reply, client, start);
                Err(abort)
            }
        }
    }

    /// What the connection does after the response to the `n`th request.
    fn then(&self, conn: &Conn, n: u64) -> Then {
        let cfg = &self.ctx.cfg;
        let head = conn.head();
        let spent = n >= u64::try_from(cfg.keepalive_requests).unwrap_or(u64::MAX)
            || self.accept.elapsed() >= cfg.keepalive_time;
        let closing = !conn.body_read()
            || head.http10()
            || head.chunked()
            || head.close()
            || cfg.keepalive_timeout.is_zero();
        if closing || spent || self.ctx.ingress.is_closed() {
            Then::Close
        } else {
            Then::Keep
        }
    }

    /// The response as it goes to hyper: marked as the last one if the connection ends with it, an HTTP/1.0
    /// response to an HTTP/1.0 request (hyper then does not add `keep-alive` to the `Connection` field of a
    /// request that asked for it), and followed by the line in the record and the note to the gate once it is
    /// complete.
    fn respond(
        self: &Arc<Self>,
        reply: Reply,
        client: IpAddr,
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
            reply,
            client,
            start,
            ended: false,
            _finish: self.link.finish(),
        })
    }

    /// Writes the line of a request in the record; `client` is the address it is recorded under.
    fn note(&self, reply: Reply, client: IpAddr, start: Instant) {
        #[cfg(test)]
        {
            *self.last.lock().unwrap_or_else(PoisonError::into_inner) = reply;
        }
        self.recorded.fetch_add(1, Ordering::Relaxed);
        if reply.internal {
            self.ctx.log.line(&format!(
                "conn {}: internal fault: {}",
                self.id, reply.reason
            ));
        }
        self.ctx
            .log
            .line(&record(self.id, &reply, start.elapsed(), client));
    }

    /// Answers a first head that was refused, and closes. A head that did not come in time gets its answer and
    /// no more; any other has bytes behind it that the client may still be sending.
    async fn refuse(&self, gate: &mut Gate<TcpStream>, reject: Reject) -> Summary {
        let cfg = &self.ctx.cfg;
        let reply = if let Some(answer) = reject.response() {
            let by = after(Instant::now(), cfg.response_idle).min(self.conn_by);
            let sock = gate.stream();
            let _ = timeout_at(by, send_and_close(sock, answer)).await;
            if reject != Reject::Timeout {
                linger(sock, cfg, self.conn_by).await;
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
        let by = after(Instant::now(), cfg.response_idle).min(self.conn_by);
        let sock = gate.stream();
        let _ = timeout_at(by, close_write(sock)).await;
        if lingers {
            linger(sock, cfg, self.conn_by).await;
        }
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
            last: *self.last.lock().unwrap_or_else(PoisonError::into_inner),
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
    reply: Reply,
    client: IpAddr,
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
        let mut reply = self.reply;
        if !whole && reply.class == Class::Forwarded {
            reply.reason = "closed while the response was sent";
        }
        self.session.note(reply, self.client, self.start);
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
