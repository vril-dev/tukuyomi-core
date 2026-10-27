//! One client connection, from the accept to the close: what every connection has in common, and where it goes
//! from there.
//!
//! What the connection is depends on the listener that took it (`serve_on`). On a plain listener it speaks
//! HTTP/1.1 (see `http1`). On a TLS listener the handshake runs first, within the time that the first head has (it
//! counts from the accept), and the rest is the same over the TLS stream, unless the handshake chose `h2` as the
//! protocol, which is then spoken (see `http2`); a handshake that fails or is not done in time ends the connection
//! with one record and no more. On a listener that redirects to https the first head is read as
//! everywhere else, and then it is answered with the redirect, or with 404, without hyper, the inspection or the
//! upstream, and without reading its body (see `http1::redirect_to`). A plain listener and a listener that redirects
//! first answer a request for the challenge of the CA that issues the certificates with `acme` (see `challenge`).
//!
//! Every answer that is written to a client has a record of the type `request`, written when the response has been
//! given to the connection or was cut off, and has a number (`RequestIds`) that the record and the response (in an
//! `X-Request-ID` field) share. That includes the answer to a first head that was refused, the answers of a listener
//! that redirects, and the answer to a stream whose head could not be made. The record has the address of the client
//! that the inspection was told (see `conn`); a record that is written before a request has been read has the
//! address of the peer, and no method, `Host` or path, which are written only when the head of the request passed
//! the head check. A request that was sent to an upstream has the group and the server in its record, and one that
//! was judged by the rules has the generation and the mode of the rules and the rules that matched it. A connection
//! that never had a response, one that was closed over a head that was refused after the first, and one that fails
//! in the handshake of TLS have a record of the type `connection` when they end, and so does a connection that
//! speaks HTTP/2, in any case. A tunnel has a record of its own, also one that never ran (see `tunnel`).
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
use http::{HeaderName, HeaderValue, Response};
use http_body::{Body, Frame, SizeHint};
use rustls::crypto::aws_lc_rs::default_provider;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout_at};

use crate::config::{Http2Config, ListenerKind, ProxyConfig, Stream};
use crate::inbound::answer::{Class, Noted, Out, Reply, Sizes};
use crate::inbound::conn::{Conn, Ctx, Scheme, after};
use crate::inbound::head::Head;
use crate::inbound::transport::io::Gauge;
use crate::inbound::{http1, http2};
use crate::log::record::{Connection, Record, Request, millis};

/// Numbers the connections for the records. They say nothing else.
static NEXT_CONN: AtomicU64 = AtomicU64::new(1);

/// Numbers the requests, for the records and for the `X-Request-ID` fields. They say nothing else.
static NEXT_REQUEST: AtomicU64 = AtomicU64::new(1);

/// The field that carries the number of a request, to the upstream and back to the client.
static X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// The numbers of the requests of one start of the proxy: 8 random bytes from the crypto provider, taken once, and a
/// count from 1. A number is the 16 lower-case hexadecimal digits of the random bytes, a `-` and the count in
/// lower-case hexadecimal, as in `9f3a51c0e2b47d18-2a`.
pub struct RequestIds {
    prefix: String,
}

impl RequestIds {
    /// The ids of this start; none if the provider has no random number.
    pub fn new() -> Option<RequestIds> {
        let mut random = [0u8; 8];
        default_provider().secure_random.fill(&mut random).ok()?;
        Some(RequestIds {
            prefix: random.iter().map(|b| format!("{b:02x}")).collect(),
        })
    }

    /// The number of one more request.
    pub fn mint(&self) -> String {
        let count = NEXT_REQUEST.fetch_add(1, Ordering::Relaxed);
        format!("{}-{count:x}", self.prefix)
    }
}

/// What a connection speaks, for the records.
#[derive(Clone, Copy)]
pub(super) enum Proto {
    H1,
    H2,
}

impl Proto {
    fn name(self) -> &'static str {
        match self {
            Proto::H1 => "h1",
            Proto::H2 => "h2",
        }
    }
}

/// How the hyper connection ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum End {
    Done,
    Error,
    Limit,
}

/// What came of a connection: the reply of its last request, and the reply that its record of the type
/// `connection` shows if it has to have one.
pub(super) struct Summary {
    pub(super) id: u64,
    /// For the tests of the record.
    #[cfg(test)]
    pub(super) last: Reply,
    pub(super) line: Option<Reply>,
    /// The streams of an HTTP/2 connection, for its record.
    streams: Option<u64>,
}

impl Summary {
    /// A connection whose record of the type `connection` shows `reply`.
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
    /// The place of the listener that took the connection among the listeners of the configuration, and what the
    /// connection speaks, for the records.
    listener: usize,
    proto: Proto,
    /// End of the connection. A response that may take long puts it off (`lengthen`).
    conn_by: Mutex<Instant>,
    pub(super) gauge: Gauge,
    /// Records written for responses.
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
        Some(ListenerKind::Plain) => serve(sock, peer, local, ctx, listener).await,
        Some(ListenerKind::Tls(tls)) => {
            let http2 = tls.http2;
            serve_tls(sock, peer, local, ctx, listener, http2).await;
        }
        Some(&ListenerKind::Redirect { https_port }) => {
            serve_redirect(sock, peer, local, ctx, listener, https_port).await;
        }
        None => {}
    }
}

/// Serves one accepted connection of the plain listener at `listener` to its end.
pub async fn serve(
    sock: TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
    ctx: Arc<Ctx>,
    listener: usize,
) {
    let accept = Instant::now();
    let summary = http1::run(sock, peer, local, &ctx, listener, accept, Scheme::Http).await;
    finish(&ctx, summary, accept, peer, listener);
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
                            http2::run(stream, peer, local, &ctx, listener, accept, hosts, settings)
                                .await
                        }
                        (true, None) => Summary::unserved("no http2 for the listener"),
                        (false, _) => {
                            let scheme = Scheme::Https(hosts);
                            http1::run(stream, peer, local, &ctx, listener, accept, scheme).await
                        }
                    }
                }
                Ok(Err(_)) => Summary::unserved("tls handshake failed"),
                Err(_) => Summary::unserved("tls handshake not finished in time"),
            }
        }
        None => Summary::unserved("no tls for the listener"),
    };
    finish(&ctx, summary, accept, peer, listener);
}

/// Serves one accepted connection of the listener at `listener` that redirects to https at `https_port` to its end.
async fn serve_redirect(
    sock: TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
    ctx: Arc<Ctx>,
    listener: usize,
    https_port: u16,
) {
    let accept = Instant::now();
    let summary = http1::redirect_to(sock, peer, local, &ctx, listener, accept, https_port).await;
    finish(&ctx, summary, accept, peer, listener);
}

/// The record of the type `connection` that the end of a connection adds, if it has to.
fn finish(ctx: &Ctx, summary: Summary, accept: Instant, peer: SocketAddr, listener: usize) {
    if let Some(reply) = summary.line {
        ctx.log.record(Record::Connection(Connection {
            conn: summary.id,
            listener,
            client: peer.ip(),
            class: reply.class.name(),
            status: reply.status,
            reason: reply.reason,
            ms: millis(accept.elapsed()),
            streams: summary.streams,
        }));
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
    /// The state of a connection that the listener at `listener` took and that speaks `proto`. `gauge` counts the
    /// bytes read from its stream.
    // One argument for each part of the connection that the state is made of; a struct of them would only repeat
    // their names.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        ctx: &Arc<Ctx>,
        peer: SocketAddr,
        local: SocketAddr,
        listener: usize,
        proto: Proto,
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
            listener,
            proto,
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
            self.ctx.ids.mint(),
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

    /// The response as it goes to hyper, with exactly one `X-Request-ID` field, the number of its request (also in
    /// place of one that the upstream sent), followed by the record and the drop of `guard` once it is complete (see
    /// `Tracked`).
    pub(super) fn track<G>(
        self: &Arc<Self>,
        noted: Noted,
        mut response: Response<Out>,
        start: Instant,
        guard: G,
    ) -> Response<Tracked<G>> {
        match HeaderValue::from_str(&noted.id) {
            Ok(id) => {
                response.headers_mut().insert(X_REQUEST_ID.clone(), id);
            }
            Err(_) => {
                response.headers_mut().remove(&X_REQUEST_ID);
            }
        }
        response.map(|body| Tracked {
            body,
            session: self.clone(),
            noted,
            start,
            ended: false,
            sent: 0,
            guard,
        })
    }

    /// Writes the record of a request, under the client address that `noted` has. `sent` is the number of bytes of
    /// the body of the response that were handed on.
    pub(super) fn note(&self, noted: &mut Noted, start: Instant, sent: u64) {
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
        let lengths = noted.body.as_ref().and_then(Sizes::lengths);
        self.ctx.log.record(Record::Request(Box::new(Request {
            id: std::mem::take(&mut noted.id),
            conn: self.id,
            listener: self.listener,
            proto: self.proto.name(),
            tls: matches!(self.scheme, Scheme::Https(_)),
            client: noted.client,
            seen: noted.seen.take(),
            class: reply.class.name(),
            status: reply.status,
            reason: reply.reason,
            ms: millis(start.elapsed()),
            upstream: noted.via.as_ref().map(|via| via.group.clone()),
            server: noted.via.as_ref().and_then(|via| via.server),
            mode: noted.judged.map(|judge| judge.mode.name()),
            generation: noted.judged.map(|judge| judge.generation.bytes()),
            rule: reply.rule,
            matched: noted.judged.map(|judge| judge.matched).unwrap_or_default(),
            body: lengths.map(|(length, _)| length),
            inspected: lengths.and_then(|(_, inspected)| inspected),
            sent,
        })));
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

/// The body of a response, and the end of its request. The record of the request is written, and `guard` (the gate of
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
    /// The bytes of the body that were handed on.
    sent: u64,
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
            Poll::Ready(Some(Ok(frame))) if frame.is_data() => {
                let len = frame.data_ref().map_or(0, Bytes::len);
                this.sent = this
                    .sent
                    .saturating_add(u64::try_from(len).unwrap_or(u64::MAX));
                this.guard.held();
            }
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
        self.session.note(&mut self.noted, self.start, self.sent);
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
