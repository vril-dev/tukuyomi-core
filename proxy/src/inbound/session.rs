//! One client connection, from the accept to the close: what every connection has in common, and where it goes
//! from there.
//!
//! What the connection is depends on the listener that took it (`serve_on`). On a plain listener it speaks
//! HTTP/1.1 (see `http1`). On a TLS listener the handshake runs first, within the time that the first head has (it
//! counts from the accept), and the rest is the same over the TLS stream, unless the handshake chose `h2` as the
//! protocol, which is then spoken (see `http2`); a handshake that fails or is not done in time ends the connection
//! with one line in the record and no more. On a listener that redirects to https the first head is read as
//! everywhere else, and then it is answered with the redirect, or with 404, without hyper, the inspection or the
//! upstream, and without reading its body (see `http1::redirect_to`).
//!
//! Every response has one line in the record, written when the response has been given to the connection or was
//! cut off. The line has the address of the client that the inspection was told (see `conn`); a line that is
//! written before a request has been read has the address of the peer. A request that was sent to an upstream has
//! the group and the server in its line. A connection that never had a response, and one that was closed over a head
//! that was refused after the first, have a line of their own when they end. So does a tunnel, also one that never
//! ran (see `tunnel`), and a connection that speaks HTTP/2, which has one at its end in any case.
//!
//! A connection is closed by whoever served it, after hyper is done with it: the writing direction is ended (on TLS
//! that sends the closing alert of TLS first), and after a response that closed the connection, or a head that was
//! refused with bytes behind it, the connection reads and discards what the client still sends for a while
//! (`linger`). A close with unread bytes in the socket resets the connection, and the reset can take the response
//! away from a client that is still sending, or whose next request crossed the response.

use std::future::poll_fn;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};

use bytes::Bytes;
use http::Response;
use http_body::{Body, Frame, SizeHint};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout_at};

use crate::config::{Http2Config, ListenerKind, ProxyConfig, Stream};
use crate::inbound::answer::{Class, Noted, Out, Reply, record};
use crate::inbound::conn::{Conn, Ctx, Scheme, after};
use crate::inbound::head::Head;
use crate::inbound::transport::io::Gauge;
use crate::inbound::{http1, http2};

/// Numbers the connections for the records. They say nothing else.
static NEXT_CONN: AtomicU64 = AtomicU64::new(1);

/// How the hyper connection ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum End {
    Done,
    Error,
    Limit,
}

/// What came of a connection: the reply of its last request, and the line that its end adds to the record if it
/// has to.
pub(super) struct Summary {
    pub(super) id: u64,
    /// For the tests of the record.
    #[cfg(test)]
    pub(super) last: Reply,
    pub(super) line: Option<Reply>,
    /// The streams of an HTTP/2 connection, for its line.
    streams: Option<u64>,
}

impl Summary {
    /// A connection whose one line in the record is `reply`.
    pub(super) fn of(id: u64, reply: Reply) -> Summary {
        Summary {
            id,
            #[cfg(test)]
            last: reply,
            line: Some(reply),
            streams: None,
        }
    }

    /// A connection that never got as far as a request, for `reason`.
    pub(super) fn unserved(reason: &'static str) -> Summary {
        let id = NEXT_CONN.fetch_add(1, Ordering::Relaxed);
        Summary::of(
            id,
            Reply {
                reason,
                ..Reply::NONE
            },
        )
    }

    /// The same, with the number of streams that the connection carried.
    pub(super) fn counted(self, streams: u64) -> Summary {
        Summary {
            streams: Some(streams),
            ..self
        }
    }
}

/// The state of one client connection that its service and its responses share, whatever the connection speaks.
pub(super) struct Session {
    pub(super) ctx: Arc<Ctx>,
    pub(super) peer: SocketAddr,
    local: SocketAddr,
    scheme: Scheme,
    pub(super) id: u64,
    pub(super) accept: Instant,
    /// End of the connection. A response that may take long puts it off (`lengthen`).
    conn_by: Mutex<Instant>,
    pub(super) gauge: Gauge,
    /// Lines written for responses.
    pub(super) recorded: AtomicU64,
    /// The reply of the response that was recorded last, for the tests of the record.
    #[cfg(test)]
    pub(super) last: Mutex<Reply>,
}

/// Serves one accepted connection of the listener at `listener` to its end, as that listener says.
pub async fn serve_on(
    sock: TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
    ctx: Arc<Ctx>,
    listener: usize,
) {
    match ctx.cfg.listeners.get(listener).map(|l| &l.kind) {
        Some(ListenerKind::Plain) => serve(sock, peer, local, ctx).await,
        Some(ListenerKind::Tls(tls)) => {
            let http2 = tls.http2;
            serve_tls(sock, peer, local, ctx, listener, http2).await;
        }
        Some(&ListenerKind::Redirect { https_port }) => {
            serve_redirect(sock, peer, local, ctx, https_port).await;
        }
        None => {}
    }
}

/// Serves one accepted connection of a plain listener to its end.
pub async fn serve(sock: TcpStream, peer: SocketAddr, local: SocketAddr, ctx: Arc<Ctx>) {
    let accept = Instant::now();
    let summary = http1::run(sock, peer, local, &ctx, accept, Scheme::Http).await;
    finish(&ctx, summary, accept, peer);
}

/// Serves one accepted connection of the TLS listener at `listener` to its end. The handshake has the time that the
/// first head has, and the head the time that is left. `http2` holds the settings of the listener for HTTP/2, if it
/// speaks it.
async fn serve_tls(
    sock: TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
    ctx: Arc<Ctx>,
    listener: usize,
    http2: Option<Http2Config>,
) {
    let accept = Instant::now();
    let summary = match ctx.tls.handshake(listener) {
        Some(handshake) => {
            match timeout_at(first_head_by(&ctx.cfg, accept), handshake.accept(sock)).await {
                Ok(Ok((stream, hosts))) => {
                    let h2 = stream.get_ref().1.alpn_protocol() == Some(&b"h2"[..]);
                    match (h2, http2) {
                        (true, Some(settings)) => {
                            http2::run(stream, peer, local, &ctx, accept, hosts, settings).await
                        }
                        (true, None) => Summary::unserved("no http2 for the listener"),
                        (false, _) => {
                            http1::run(stream, peer, local, &ctx, accept, Scheme::Https(hosts))
                                .await
                        }
                    }
                }
                Ok(Err(_)) => Summary::unserved("tls handshake failed"),
                Err(_) => Summary::unserved("tls handshake not finished in time"),
            }
        }
        None => Summary::unserved("no tls for the listener"),
    };
    finish(&ctx, summary, accept, peer);
}

/// Serves one accepted connection of a listener that redirects to https at `https_port` to its end.
async fn serve_redirect(
    sock: TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
    ctx: Arc<Ctx>,
    https_port: u16,
) {
    let accept = Instant::now();
    let summary = http1::redirect_to(sock, peer, local, &ctx, accept, https_port).await;
    finish(&ctx, summary, accept, peer);
}

/// The line in the record that the end of a connection adds, if it has to.
fn finish(ctx: &Ctx, summary: Summary, accept: Instant, peer: SocketAddr) {
    if let Some(reply) = summary.line {
        if reply.internal {
            ctx.log.line(&format!(
                "conn {}: internal fault: {}",
                summary.id, reply.reason
            ));
        }
        let line = record(summary.id, &reply, accept.elapsed(), peer.ip(), None);
        match summary.streams {
            Some(streams) => ctx.log.line(&format!("{line} streams {streams}")),
            None => ctx.log.line(&line),
        }
    }
}

/// When the first head of a connection that was accepted at `accept` has to be complete.
pub(super) fn first_head_by(cfg: &ProxyConfig, accept: Instant) -> Instant {
    after(accept, cfg.head_read).min(after(accept, cfg.request_total))
}

pub(super) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Session {
    /// The state of a connection. `gauge` counts the bytes read from its stream.
    pub(super) fn new(
        ctx: &Arc<Ctx>,
        peer: SocketAddr,
        local: SocketAddr,
        accept: Instant,
        scheme: Scheme,
        gauge: Gauge,
    ) -> Arc<Session> {
        Arc::new(Session {
            ctx: ctx.clone(),
            peer,
            local,
            scheme,
            id: NEXT_CONN.fetch_add(1, Ordering::Relaxed),
            accept,
            conn_by: Mutex::new(after(accept, ctx.cfg.conn_total)),
            gauge,
            recorded: AtomicU64::new(0),
            #[cfg(test)]
            last: Mutex::new(Reply::NONE),
        })
    }

    pub(super) fn conn_by(&self) -> Instant {
        *lock(&self.conn_by)
    }

    /// The state of the request whose checked head is `head` and whose time counts from `start`.
    pub(super) fn conn(&self, head: Head, start: Instant) -> Conn {
        Conn::new(
            &self.ctx,
            self.id,
            head,
            self.peer,
            self.local,
            self.scheme.clone(),
            self.gauge.clone(),
            after(start, self.ctx.cfg.request_total),
        )
    }

    /// The head of a response that may take long is ready: the connection lasts until `total` after now at the
    /// earliest, and the client may be silent for that long (and for the connection time, if that is more). The old
    /// end has not come: the head was ready within the request time, which `keepalive_time` leaves inside the
    /// connection time.
    pub(super) fn lengthen(&self, stream: &Stream) {
        let by = after(Instant::now(), stream.total);
        {
            let mut conn_by = lock(&self.conn_by);
            *conn_by = (*conn_by).max(by);
        }
        self.gauge
            .restart(stream.total.max(self.ctx.cfg.conn_total));
    }

    /// The response as it goes to hyper, followed by the line in the record and the drop of `guard` once it is
    /// complete (see `Tracked`).
    pub(super) fn track<G>(
        self: &Arc<Self>,
        noted: Noted,
        response: Response<Out>,
        start: Instant,
        guard: G,
    ) -> Response<Tracked<G>> {
        response.map(|body| Tracked {
            body,
            session: self.clone(),
            noted,
            start,
            ended: false,
            guard,
        })
    }

    /// Writes the line of a request in the record, under the client address that `noted` has.
    pub(super) fn note(&self, noted: &Noted, start: Instant) {
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

    /// What came of the connection: the reply of the last response, and `line` for its end.
    pub(super) fn summary(&self, line: Option<Reply>) -> Summary {
        Summary {
            id: self.id,
            #[cfg(test)]
            last: *lock(&self.last),
            line,
            streams: None,
        }
    }
}

/// What a response tells its guard while it is sent. The guard of a stream of HTTP/2 keeps from it how long a chunk of
/// the response has waited for the client (see `http2`). The gate of HTTP/1.1 has no use for it: the writes to the
/// client have their own limit (see `Guarded`).
pub(super) trait Progress {
    /// The body is asked for its next frame, which hyper does when it has handed the last chunk to h2: that chunk
    /// does not wait for the client any more.
    fn taken(&mut self) {}

    /// The body handed a chunk on: it waits for the client from now on.
    fn held(&mut self) {}
}

/// The body of a response, and the end of its request. The line in the record is written, and `guard` (the gate of
/// HTTP/1.1 is told that the request is answered, a stream of HTTP/2 that it is done) is dropped, when this is
/// dropped: hyper drops it when it has encoded the last frame of the body, which can be before the bytes are out,
/// and when the connection goes away.
pub(super) struct Tracked<G> {
    body: Out,
    session: Arc<Session>,
    noted: Noted,
    start: Instant,
    /// The body gave its end.
    ended: bool,
    guard: G,
}

impl<G: Unpin + Progress> Body for Tracked<G> {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let this = self.get_mut();
        this.guard.taken();
        let polled = Pin::new(&mut this.body).poll_frame(cx);
        match &polled {
            Poll::Ready(None) => this.ended = true,
            Poll::Ready(Some(Ok(frame))) if frame.is_data() => this.guard.held(),
            _ => {}
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

impl<G> Drop for Tracked<G> {
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
pub(super) async fn send_and_close<T>(stream: &mut T, bytes: &[u8])
where
    T: AsyncWrite + Unpin,
{
    if stream.write_all(bytes).await.is_err() {
        return;
    }
    close_write(stream).await;
}

/// Ends the sending direction: the client reads the end of the response.
pub(super) async fn close_write<T>(stream: &mut T)
where
    T: AsyncWrite + Unpin,
{
    let _ = poll_fn(|cx| Pin::new(&mut *stream).poll_shutdown(cx)).await;
}

/// Reads and discards what the client still sends, until the end of its stream (a client that has closed its side
/// ends it at once), `lingering_bytes` bytes, a read that waits for `lingering_timeout`, `lingering_time` after the
/// start or the end of the connection time.
pub(super) async fn linger<T>(stream: &mut T, cfg: &ProxyConfig, conn_by: Instant)
where
    T: AsyncRead + Unpin,
{
    let end = after(Instant::now(), cfg.lingering_time).min(conn_by);
    let mut left = cfg.lingering_bytes;
    let mut buf = [0u8; 4096];
    while left > 0 {
        let by = after(Instant::now(), cfg.lingering_timeout).min(end);
        // Not a byte over the limit is read.
        let room = left.min(buf.len());
        match timeout_at(by, stream.read(&mut buf[..room])).await {
            Ok(Ok(0) | Err(_)) | Err(_) => return,
            Ok(Ok(n)) => left = left.saturating_sub(n),
        }
    }
}

#[cfg(test)]
pub(super) mod tests;
