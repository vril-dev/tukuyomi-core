//! Forwarding an allowed request to the one upstream, and checking its answer.
//!
//! The request leaves in the form that was inspected, with these changes only: the fields that belong to the
//! connection with the client are removed, the forwarding fields are added (and `Connection: close` when the
//! connections to the upstream are not kept), and the body is the inspected bytes. The names that the client
//! listed in `Connection` are collected before anything is removed and are removed with the other hop-by-hop
//! fields. The fields that are added come after the removal, so a client cannot take them away by naming them.
//!
//! The forwarding fields tell the upstream who the client is. A peer that is in `trusted_proxies` is believed: its
//! `X-Forwarded-For` lines are kept and its own address is added at the end, and its `X-Forwarded-Proto` is kept if
//! it is exactly `http` or `https`; its other claims (see `CLIENT_CLAIMS`) pass as they are. From any other peer
//! all of those claims are dropped, `X-Forwarded-For` is the address of the peer alone and `X-Forwarded-Proto` is
//! `http`. `X-Forwarded-Host` is the `Host` of the request whoever the peer is.
//!
//! The connection to the upstream is the newest one in the pool that is ready, or a new one. It goes back to the
//! pool when the body of the answer has been read to its end and nothing in the exchange ended it; a body that is
//! dropped before its end ends the connection. A pooled connection that fails before any byte of an answer was
//! read may have been closed by the upstream while it waited: a request that does no harm when it is sent twice
//! (GET, HEAD, OPTIONS, PUT, DELETE, TRACE) is then sent once more on a new connection, and any other is not.
//!
//! The answer is checked before it is passed on. A status outside 200..=599, unclear framing, and a `Connection`
//! field that is not a list of tokens or that names a field the answer must keep are refused, and the connection
//! to the upstream is dropped with it. A refused answer is never partly passed on. The fields that belong to the
//! connection with the upstream are removed, and the trailers of the answer are dropped.
//!
//! Every wait before the head of the answer ends at an absolute instant that is never extended, and a stage whose
//! end has already been reached does not start. Informational responses are read over and not passed on; the bytes
//! read from the upstream up to the final head, they included, are capped as a whole.

use std::convert::Infallible;
use std::error::Error;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::header::{
    CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, HOST,
    InvalidHeaderName, TRANSFER_ENCODING,
};
use http::response::Parts;
use http::{
    Extensions, HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri,
    Version,
};
use http_body::{Body, Frame, SizeHint};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout_at};

use crate::config::ProxyConfig;
use crate::forward::client_ip;
use crate::forward::pool::{Lease, Pool};
use crate::inbound::conn::Ctx;
use crate::inbound::head::trim_ows;
use crate::inbound::io::{Gauge, Guarded};
use crate::inspect::driver::BodyHold;

static X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
static X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");
static X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");

/// Fields of the request that belong to the connection with the client or to a single hop. `Connection` and the
/// names it lists go as well.
const REQUEST_HOP: [&str; 10] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "expect",
];

/// Fields of the answer that belong to the connection with the upstream. `Connection` and the names it lists go
/// as well.
const RESPONSE_HOP: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Fields by which a peer says who the client is and how it came, in the spellings that servers and proxies in
/// common use take for the address of the client. They are believed from a trusted peer only. `X-Forwarded-Host` is
/// not among them: it is always made from the `Host` of the request. The names with an underscore never get here
/// (see `represent`).
const CLIENT_CLAIMS: [&str; 13] = [
    "x-forwarded-for",
    "x-real-ip",
    "forwarded",
    "x-forwarded-proto",
    "x-forwarded-port",
    "x-forwarded-ssl",
    "x-forwarded-scheme",
    "x-client-ip",
    "true-client-ip",
    "x-cluster-client-ip",
    "cf-connecting-ip",
    "fastly-client-ip",
    "x-original-forwarded-for",
];

/// An allowed request, as it is forwarded. `peer` is the address of the connection the request came on.
pub struct Forward {
    pub method: Method,
    pub uri: Uri,
    pub fields: HeaderMap,
    pub body: Arc<BodyHold>,
    pub peer: SocketAddr,
}

/// The upstream's response body without its trailers. At its end the connection to the upstream goes back to the
/// pool, if the exchange allows it. Dropping the body before that ends the connection.
pub struct OriginBody {
    body: Incoming,
    /// The connection, until the body has ended.
    lease: Option<Lease>,
    pool: Pool,
    /// Nothing in the answer ends the connection.
    reuse: bool,
}

impl OriginBody {
    /// The body has ended: the connection goes back to the pool, or is closed if the answer ended it.
    fn end(&mut self) {
        if let Some(lease) = self.lease.take()
            && self.reuse
        {
            self.pool.put(lease);
        }
    }
}

impl Body for OriginBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let this = self.get_mut();
        loop {
            match Pin::new(&mut this.body).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) if frame.is_trailers() => {}
                Poll::Ready(Some(Ok(frame))) => {
                    // The server side stops asking for frames once the end is known, so it is looked for here.
                    if this.body.is_end_stream() {
                        this.end();
                    }
                    return Poll::Ready(Some(Ok(frame)));
                }
                Poll::Ready(None) => {
                    this.end();
                    return Poll::Ready(None);
                }
                other => return other,
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

/// Every one of these is answered with 502.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OriginError {
    /// The connection to the upstream could not be made in time.
    Connect,
    /// The request could not be sent: the connection failed before any byte of an answer had been read.
    Send,
    /// The head of the answer did not arrive in time, was cut off, was not valid, or was longer than the cap.
    Head,
    /// The head of the answer is valid HTTP but is refused.
    Invalid,
}

/// The request body: the inspected bytes. It keeps the share of the byte budget until hyper drops it, which is
/// when the bytes are written or the connection is gone.
pub(super) struct Sent {
    bytes: Full<Bytes>,
    _hold: Arc<BodyHold>,
}

impl Sent {
    fn new(hold: Arc<BodyHold>) -> Sent {
        Sent {
            bytes: Full::new(hold.bytes.clone()),
            _hold: hold,
        }
    }
}

impl Body for Sent {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        Pin::new(&mut self.get_mut().bytes).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.bytes.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.bytes.size_hint()
    }
}

/// The end of a stage that starts at `start` and lasts `len`, within `by`. A sum that does not fit into the clock
/// counts as passed.
fn stage(start: Instant, len: Duration, by: Instant) -> Instant {
    start.checked_add(len).unwrap_or(start).min(by)
}

/// True once `by` has been reached: a stage whose end is already here does not start.
fn reached(by: Instant) -> bool {
    Instant::now() >= by
}

/// The names of one `Connection` line: its comma separated items, each of which must be a token.
fn listed(line: &HeaderValue) -> impl Iterator<Item = Result<HeaderName, InvalidHeaderName>> + '_ {
    line.as_bytes()
        .split(|&b| b == b',')
        .map(|item| HeaderName::from_bytes(trim_ows(item)))
}

/// The `X-Forwarded-For` value: the lines the request has, in order, and then the address of the peer. The
/// address is the one of the connection, not the client address that the lines may lead to.
fn forwarded_for(fields: &HeaderMap, peer: IpAddr) -> Result<HeaderValue, OriginError> {
    let mut chain = Vec::new();
    for line in fields.get_all(&X_FORWARDED_FOR) {
        chain.extend_from_slice(line.as_bytes());
        chain.extend_from_slice(b", ");
    }
    chain.extend_from_slice(peer.to_canonical().to_string().as_bytes());
    HeaderValue::from_bytes(&chain).map_err(|_| OriginError::Send)
}

/// The `X-Forwarded-Proto` value: the one line the request has if it is exactly `http` or `https`, `http` otherwise.
fn forwarded_proto(fields: &HeaderMap) -> HeaderValue {
    let mut lines = fields.get_all(&X_FORWARDED_PROTO).iter();
    match (lines.next(), lines.next()) {
        (Some(line), None) if matches!(line.as_bytes(), b"http" | b"https") => line.clone(),
        _ => HeaderValue::from_static("http"),
    }
}

/// The fields the upstream gets, in this order: the names listed in `Connection` are collected from the fields as
/// they were inspected; the hop-by-hop fields and the listed names are removed; if the peer is not `trusted`, so
/// are the fields by which it says who the client is; then the forwarding fields are put in, and `Connection:
/// close` if `close`. All other fields stay as they were inspected.
fn forwarded_fields(
    mut fields: HeaderMap,
    peer: IpAddr,
    trusted: bool,
    close: bool,
) -> Result<HeaderMap, OriginError> {
    let named: Vec<HeaderName> = fields
        .get_all(CONNECTION)
        .iter()
        .flat_map(listed)
        .filter_map(Result::ok)
        .collect();
    for name in REQUEST_HOP {
        fields.remove(name);
    }
    for name in &named {
        fields.remove(name);
    }
    if !trusted {
        for name in CLIENT_CLAIMS {
            fields.remove(name);
        }
    }
    let chain = forwarded_for(&fields, peer)?;
    let proto = forwarded_proto(&fields);
    let host = fields.get(HOST).cloned();
    fields.insert(X_FORWARDED_FOR.clone(), chain);
    match host {
        Some(host) => {
            fields.insert(X_FORWARDED_HOST.clone(), host);
        }
        None => {
            fields.remove(&X_FORWARDED_HOST);
        }
    }
    fields.insert(X_FORWARDED_PROTO.clone(), proto);
    if close {
        fields.insert(CONNECTION, HeaderValue::from_static("close"));
    }
    Ok(fields)
}

/// Digits only and a value that fits in 64 bits (a leading `+` is not a digit).
fn is_length(value: &[u8]) -> bool {
    !value.is_empty()
        && value.iter().all(u8::is_ascii_digit)
        && std::str::from_utf8(value).is_ok_and(|digits| digits.parse::<u64>().is_ok())
}

/// The only line of `name`, if there is one; more than one line is refused whatever the lines say.
fn single<'a>(
    headers: &'a HeaderMap,
    name: &HeaderName,
) -> Result<Option<&'a HeaderValue>, OriginError> {
    let mut lines = headers.get_all(name).iter();
    let first = lines.next();
    if lines.next().is_some() {
        return Err(OriginError::Invalid);
    }
    Ok(first)
}

/// Checks the head of the final response and takes out what belongs to the connection with the upstream.
/// `head_request` is true when the request was a HEAD request. The checked `Content-Length` of the upstream stays
/// in the head for a HEAD request and for a 304 only; otherwise it goes, and hyper sets the length from the body it
/// sends. hyper's server writes a kept length only in the answer to a HEAD request: a 304 to any other request goes
/// out without one.
fn check_head(parts: &mut Parts, head_request: bool) -> Result<(), OriginError> {
    if !(200..=599).contains(&parts.status.as_u16()) {
        return Err(OriginError::Invalid);
    }
    let headers = &mut parts.headers;
    match (
        single(headers, &TRANSFER_ENCODING)?,
        single(headers, &CONTENT_LENGTH)?,
    ) {
        (Some(_), Some(_)) => return Err(OriginError::Invalid),
        (Some(coding), None) if !coding.as_bytes().eq_ignore_ascii_case(b"chunked") => {
            return Err(OriginError::Invalid);
        }
        (None, Some(length)) if !is_length(length.as_bytes()) => return Err(OriginError::Invalid),
        _ => {}
    }
    // The names are removed as the lines are read. An answer that is refused is not used at all, so this is the
    // same as removing them afterwards, and no list of names is built from what the upstream sent.
    let lines: Vec<HeaderValue> = headers.get_all(CONNECTION).iter().cloned().collect();
    for line in &lines {
        for name in listed(line) {
            let name = name.map_err(|_| OriginError::Invalid)?;
            if name == CONTENT_LENGTH
                || name == CONTENT_TYPE
                || name == CONTENT_ENCODING
                || name == CONTENT_RANGE
            {
                return Err(OriginError::Invalid);
            }
            headers.remove(&name);
        }
    }
    for name in RESPONSE_HOP {
        headers.remove(name);
    }
    if !head_request && parts.status != StatusCode::NOT_MODIFIED {
        headers.remove(CONTENT_LENGTH);
    }
    parts.version = Version::HTTP_11;
    parts.extensions = Extensions::new();
    Ok(())
}

/// True when the error was caused by an idle limit of the connection that ran out.
fn idle_timeout(e: &hyper::Error) -> bool {
    let mut cause = e.source();
    while let Some(c) = cause {
        if c.downcast_ref::<io::Error>()
            .is_some_and(|e| e.kind() == io::ErrorKind::TimedOut)
        {
            return true;
        }
        cause = c.source();
    }
    false
}

/// Where a failure of the exchange belongs: `Head` once any byte of an answer has been read (`base` is what had
/// been read from the connection before the exchange), when the cap for the head was hit, or when the connection
/// made no progress for the idle limit; `Send` when nothing of an answer had arrived and the connection failed in
/// another way.
fn failure(e: &hyper::Error, gauge: &Gauge, base: u64) -> OriginError {
    if gauge.read() > base || gauge.over() || idle_timeout(e) {
        OriginError::Head
    } else {
        OriginError::Send
    }
}

/// The methods whose request does no harm when it reaches the upstream twice.
fn idempotent(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::PUT | Method::DELETE | Method::TRACE
    )
}

/// True when nothing in the head of the answer ends the connection with the upstream: it is HTTP/1.1, no
/// `Connection` line lists `close` or `upgrade`, and the body is not the bytes up to the end of the connection
/// (the answer to a HEAD request, a 204 and a 304 have none, the others say how long they are).
fn lasts(parts: &Parts, head_request: bool) -> bool {
    let framed = head_request
        || matches!(parts.status.as_u16(), 204 | 304)
        || parts.headers.contains_key(CONTENT_LENGTH)
        || parts.headers.contains_key(TRANSFER_ENCODING);
    framed
        && parts.version == Version::HTTP_11
        && !parts
            .headers
            .get_all(CONNECTION)
            .iter()
            .flat_map(listed)
            .any(|name| name.is_ok_and(|name| name == "close" || name == "upgrade"))
}

/// The most bytes that are read from the upstream up to the final head. A value that does not fit into 64 bits
/// cannot happen; if it did, nothing could be read.
fn head_cap(cfg: &ProxyConfig) -> u64 {
    u64::try_from(cfg.upstream_head_wire).unwrap_or(0)
}

/// The end of the stage in which a connection to the upstream is taken or made; `Connect` if it is already past.
fn connect_end(cfg: &ProxyConfig, by: Instant) -> Result<Instant, OriginError> {
    let end = stage(Instant::now(), cfg.upstream_connect, by);
    if reached(end) {
        return Err(OriginError::Connect);
    }
    Ok(end)
}

/// Makes a connection to the upstream within `connect_by`.
async fn connect(cfg: &ProxyConfig, connect_by: Instant) -> Result<Lease, OriginError> {
    let Ok(Ok(stream)) = timeout_at(connect_by, TcpStream::connect(cfg.upstream)).await else {
        return Err(OriginError::Connect);
    };
    stream.set_nodelay(true).map_err(|_| OriginError::Connect)?;
    // Up to the final head the reads are capped as a whole; the cap is lifted as soon as the head is here.
    let (guarded, gauge) = Guarded::new(
        stream,
        Bytes::new(),
        cfg.response_idle,
        cfg.response_idle,
        head_cap(cfg),
    );
    let mut client = http1::Builder::new();
    client
        .max_headers(cfg.upstream_max_headers)
        .max_header_size(cfg.upstream_max_head_bytes)
        .max_buf_size(cfg.upstream_max_head_bytes.max(8192))
        .title_case_headers(true);
    let (sender, conn) = client
        .handshake(TokioIo::new(guarded))
        .await
        .map_err(|_| OriginError::Connect)?;
    let task = tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok(Lease::new(sender, gauge, task.abort_handle()))
}

/// Sends `request` on the connection and returns the checked head of the answer; `head_by` bounds that. The
/// connection is closed if this fails. It goes back to `pool` at the end of the body of the answer if nothing in
/// the head ends it.
async fn exchange(
    mut lease: Lease,
    request: Request<Sent>,
    head_by: Instant,
    head_request: bool,
    pool: &Pool,
) -> Result<Response<OriginBody>, OriginError> {
    if reached(head_by) {
        return Err(OriginError::Head);
    }
    let base = lease.gauge.read();
    lease.used = lease.used.saturating_add(1);
    let response = match timeout_at(head_by, lease.sender.send_request(request)).await {
        Ok(Ok(response)) => response,
        Ok(Err(e)) => return Err(failure(&e, &lease.gauge, base)),
        Err(_) => return Err(OriginError::Head),
    };
    lease.gauge.lift();
    // The connection may have started reading the body before the cap was lifted. A read that was refused
    // has cut the answer off, so it is not passed on.
    if lease.gauge.over() {
        return Err(OriginError::Head);
    }
    let (mut parts, body) = response.into_parts();
    let reuse = lasts(&parts, head_request);
    check_head(&mut parts, head_request)?;
    let mut body = OriginBody {
        body,
        lease: Some(lease),
        pool: pool.clone(),
        reuse,
    };
    // An answer without a body (to a HEAD request, a 204, a 304, a length of 0) is whole with its head.
    if body.is_end_stream() {
        body.end();
    }
    Ok(Response::from_parts(parts, body))
}

/// Sends the request to the upstream and returns its checked response head; `by` bounds the whole exchange up to
/// the head.
pub async fn forward(
    f: Forward,
    ctx: &Ctx,
    by: Instant,
) -> Result<Response<OriginBody>, OriginError> {
    let cfg = &ctx.cfg;
    let Forward {
        method,
        uri,
        fields,
        body,
        peer,
    } = f;
    let trusted = client_ip::trusts(&cfg.trusted_proxies, peer.ip());
    let fields = forwarded_fields(fields, peer.ip(), trusted, cfg.upstream_keepalive == 0)?;
    let head_request = method == Method::HEAD;
    let request = || {
        let mut request = Request::new(Sent::new(body.clone()));
        *request.method_mut() = method.clone();
        *request.uri_mut() = uri.clone();
        *request.version_mut() = Version::HTTP_11;
        *request.headers_mut() = fields.clone();
        request
    };

    if let Some(lease) = ctx.pool.take(connect_end(cfg, by)?).await {
        lease.gauge.rearm(head_cap(cfg), cfg.response_idle);
        let head_by = stage(Instant::now(), cfg.upstream_header, by);
        match exchange(lease, request(), head_by, head_request, &ctx.pool).await {
            // The upstream may have closed the connection while it waited. If nothing of an answer had arrived,
            // a request that does no harm when it is sent twice is sent on a new connection, once. The stages of
            // that go on to end by `by`.
            Err(OriginError::Send) if idempotent(&method) => {}
            done => return done,
        }
    }
    let lease = connect(cfg, connect_end(cfg, by)?).await?;
    let head_by = stage(Instant::now(), cfg.upstream_header, by);
    exchange(lease, request(), head_by, head_request, &ctx.pool).await
}

#[cfg(test)]
pub(super) mod tests;
