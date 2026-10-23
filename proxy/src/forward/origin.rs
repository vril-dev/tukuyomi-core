//! Forwarding an allowed request to a server of an upstream group, and checking its answer.
//!
//! The request leaves in the form that was inspected, with these changes only: the fields that belong to the
//! connection with the client are removed, the forwarding fields are added (and `Connection: close` when the
//! connections to the upstream are not kept), the edits of the route are made (see `rewrite`), and the body is the
//! inspected bytes. The names that the client listed in `Connection` are collected before anything is removed and
//! are removed with the other hop-by-hop fields. The fields that are added come after the removal, so a client
//! cannot take them away by naming them.
//!
//! The forwarding fields tell the upstream who the client is. A peer that is in `trusted_proxies` is believed: its
//! `X-Forwarded-For` lines are kept and its own address is added at the end, and its `X-Forwarded-Proto` is kept if
//! it is exactly `http` or `https`; its other claims (see `CLIENT_CLAIMS`) pass as they are. From any other peer
//! all of those claims are dropped, `X-Forwarded-For` is the address of the peer alone and `X-Forwarded-Proto` is
//! `http`. `X-Forwarded-Host` is the `Host` of the request whoever the peer is, as the client wrote it: a route that
//! sets another `Host` does so after that.
//!
//! The server is chosen by the group (see `group`). The connection to it is the newest one that waits for that server
//! in the pool of the group and is ready, or a new one. It goes back to the pool when the body of the answer has been
//! read to its end and nothing in the exchange ended it; a body that is dropped before its end ends the connection.
//! A pooled connection that fails before any byte of an answer was read may have been closed by the server while it
//! waited: a request that does no harm when it is sent twice (GET, HEAD, OPTIONS, PUT, DELETE, TRACE) is then sent
//! once more on a new connection to the same server, and any other is not.
//!
//! A server fails a request when the connection to it is refused or reset, the server cannot be reached, or the
//! connection is not made within `upstream_connect` (`Connect`), when the request cannot be sent, or the head of
//! the answer is not read within `upstream_header` or is cut off (`Send`, `Head`). The group counts such a failure
//! against the server, except one on a waiting connection that was not sent again: the server may only have closed
//! that connection while it waited. An answer whose head cannot be parsed, is longer than the limits for a head, or
//! is refused (`Invalid`), and any status the server gave, are not a failure of the server, and are never tried
//! again on another one: what a server answers can follow from the request (a path, `Origin` or `Cookie` that it
//! repeats into a long `Location` or `Set-Cookie`), so one request could otherwise take every server out of the
//! group. After a failure the request goes on to the next server of the group, which has not been tried, when the
//! connection could not be made (nothing was sent), or when the method does no harm when it is sent twice (the list
//! above). It does not go on after the head of an answer was returned: from then on the response is on its way to
//! the client, and this function has ended. At most as many servers are tried as the group has, within the time
//! that bounds the exchange. A request that no server could take is `Unavailable`.
//!
//! Two kinds of failure are not the fault of a server, so nothing is counted against one and the request is not
//! tried on another. A stage that the end of the request time cut short, or that was not started because that end
//! had been reached, is `Late`: a slow client may have used the time up, and it must not be able to take servers
//! out of the group by that. A connection that the proxy itself could not make (no descriptor, port or memory
//! left, a socket that cannot be set up) is `Local`: another server would fail in the same way.
//!
//! The answer is checked before it is passed on. A status outside 200..=599, unclear framing, and a `Connection`
//! field that is not a list of tokens or that names a field the answer must keep are refused, and the connection
//! to the upstream is dropped with it. A refused answer is never partly passed on. The fields that belong to the
//! connection with the upstream are removed, and the trailers of the answer are dropped. The response edits of the
//! route are made on the head that is left, so they do not reach an answer the proxy makes itself.
//!
//! Every wait before the head of the answer ends at an absolute instant that is never extended, and a stage whose
//! end has already been reached does not start (see `Stage`). Informational responses are read over and not passed
//! on; the bytes read from the upstream up to the final head, they included, are capped as a whole.

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
use crate::forward::group::{Group, Server, Tried};
use crate::forward::pool::{Lease, Pool};
use crate::forward::rewrite::Rewrite;
use crate::inbound::conn::Ctx;
use crate::inbound::head::trim_ows;
use crate::inbound::io::{Gauge, Guarded};
use crate::inspect::driver::BodyHold;

static X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
static X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");
static X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");

/// Fields of the request that belong to the connection with the client or to a single hop. `Connection` and the
/// names it lists go as well.
pub(super) const REQUEST_HOP: [&str; 10] = [
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
pub(super) const RESPONSE_HOP: [&str; 8] = [
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
pub(super) const CLIENT_CLAIMS: [&str; 13] = [
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

/// Why a request got no response head from the upstream. `Late` and `Local` are answered with 503, the others with
/// 502.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OriginError {
    /// No server of the group could be tried: each one is left out.
    Unavailable,
    /// The connection to the upstream was refused or reset, could not be reached, or was not made in time.
    Connect,
    /// The request could not be sent: the connection failed before any byte of an answer had been read.
    Send,
    /// The head of the answer did not arrive in time, or the connection ended or was reset after it began.
    Head,
    /// The head of the answer cannot be parsed, is longer than the limits for a head (its size, the number of its
    /// fields, the bytes read up to the final head), or is valid HTTP but is refused. The server did answer.
    Invalid,
    /// The time of the request was used up, in a stage of the exchange or before it began. No server is at fault.
    Late,
    /// The proxy could not make the connection for a reason of its own. No server is at fault.
    Local,
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

/// A stage of the exchange with the upstream: the instant it ends at, and who set it, the stage itself (the time the
/// server may take) or the end of the request time.
#[derive(Clone, Copy)]
struct Stage {
    end: Instant,
    /// The limit of the stage comes before the end of the request time. When they are the same instant, the end of
    /// the request time is the one that counts.
    own: bool,
}

impl Stage {
    /// The stage that starts at `start` and lasts `len`, within `by`. A sum that does not fit into the clock counts
    /// as passed, and is not the fault of the server.
    fn new(start: Instant, len: Duration, by: Instant) -> Stage {
        let own = start.checked_add(len);
        Stage {
            end: own.unwrap_or(start).min(by),
            own: own.is_some_and(|own| own < by),
        }
    }

    /// What it comes to when the time of the stage has run out: `error` if the limit of the stage ended it, `Late`
    /// if the end of the request time did.
    fn ran_out(self, error: OriginError) -> OriginError {
        if self.own { error } else { OriginError::Late }
    }
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

/// Where a failure of the exchange belongs: `Invalid` when the head of the answer cannot be parsed or is too long
/// (hyper reports a head with too many bytes or fields as a parse error) or when the cap for the head was hit; the
/// server answered, and what it answers can follow from the request. `Head` once any byte of an answer has been
/// read (`base` is what had been read from the connection before the exchange), or when the connection made no
/// progress for the idle limit; `Send` when nothing of an answer had arrived and the connection failed in another
/// way.
fn failure(e: &hyper::Error, gauge: &Gauge, base: u64) -> OriginError {
    // The cap fails the read, so hyper reports it as an I/O error and not as a parse error.
    if e.is_parse() || gauge.over() {
        OriginError::Invalid
    } else if gauge.read() > base || idle_timeout(e) {
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

/// The stage in which a connection to the upstream is taken or made; the error if its end is already past.
fn connect_stage(cfg: &ProxyConfig, by: Instant) -> Result<Stage, OriginError> {
    let stage = Stage::new(Instant::now(), cfg.upstream_connect, by);
    if reached(stage.end) {
        return Err(stage.ran_out(OriginError::Connect));
    }
    Ok(stage)
}

/// Where a failed attempt to connect belongs. The server refusing the connection, resetting it, not being reachable
/// or not answering is its fault (`Connect`). Anything else is an error of the proxy itself (`Local`): no
/// descriptor, buffer, memory or port is left, or the system does not allow the connection.
fn connect_error(e: &io::Error) -> OriginError {
    match e.kind() {
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::HostUnreachable
        | io::ErrorKind::NetworkUnreachable
        | io::ErrorKind::TimedOut => OriginError::Connect,
        _ => OriginError::Local,
    }
}

/// Makes a connection to the server at `address` within `stage`.
async fn connect(
    address: SocketAddr,
    cfg: &ProxyConfig,
    stage: Stage,
) -> Result<Lease, OriginError> {
    let stream = match timeout_at(stage.end, TcpStream::connect(address)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => return Err(connect_error(&e)),
        Err(_) => return Err(stage.ran_out(OriginError::Connect)),
    };
    stream.set_nodelay(true).map_err(|_| OriginError::Local)?;
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
        .map_err(|_| OriginError::Local)?;
    let task = tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok(Lease::new(sender, gauge, task.abort_handle()))
}

/// Sends `request` on the connection and returns the checked head of the answer; `head` bounds that. The
/// connection is closed if this fails. It goes back to `pool` at the end of the body of the answer if nothing in
/// the head ends it.
async fn exchange(
    mut lease: Lease,
    request: Request<Sent>,
    head: Stage,
    head_request: bool,
    pool: &Pool,
) -> Result<Response<OriginBody>, OriginError> {
    if reached(head.end) {
        return Err(head.ran_out(OriginError::Head));
    }
    let base = lease.gauge.read();
    lease.used = lease.used.saturating_add(1);
    let response = match timeout_at(head.end, lease.sender.send_request(request)).await {
        Ok(Ok(response)) => response,
        Ok(Err(e)) => return Err(failure(&e, &lease.gauge, base)),
        Err(_) => return Err(head.ran_out(OriginError::Head)),
    };
    lease.gauge.lift();
    // The connection may have started reading the body before the cap was lifted. A read that was refused
    // has cut the answer off, so it is not passed on; as in `failure`, the cap is not the fault of the server.
    if lease.gauge.over() {
        return Err(OriginError::Invalid);
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

/// What came of sending a request to a group: the address of the server that was tried last (none if no server
/// was tried), and the checked head of its response or why there is none.
pub struct Dispatched {
    pub server: Option<SocketAddr>,
    pub result: Result<Response<OriginBody>, OriginError>,
}

/// Whether `error` is a failure of the server: the group counts it, and the request may go to another one.
fn failure_of_server(error: OriginError) -> bool {
    matches!(
        error,
        OriginError::Connect | OriginError::Send | OriginError::Head
    )
}

/// Whether a request may go to another server after `error`: always if the connection could not be made, for
/// nothing was sent then, and otherwise only if it does no harm when it reaches a server twice.
fn may_go_on(error: OriginError, method: &Method) -> bool {
    match error {
        OriginError::Connect => true,
        OriginError::Send | OriginError::Head => idempotent(method),
        OriginError::Invalid
        | OriginError::Unavailable
        | OriginError::Late
        | OriginError::Local => false,
    }
}

/// Why a try on a server gave no response head, and whether the group counts it against the server.
struct Failed {
    error: OriginError,
    counted: bool,
}

impl Failed {
    fn counted(error: OriginError) -> Failed {
        Failed {
            error,
            counted: failure_of_server(error),
        }
    }
}

/// One try on one server. `request` makes the request for each send.
async fn attempt(
    server: &Server,
    cfg: &ProxyConfig,
    request: &impl Fn() -> Request<Sent>,
    method: &Method,
    head_request: bool,
    by: Instant,
) -> Result<Response<OriginBody>, Failed> {
    let pool = server.pool();
    if let Some(lease) = pool
        .take(connect_stage(cfg, by).map_err(Failed::counted)?.end)
        .await
    {
        lease.gauge.rearm(head_cap(cfg), cfg.response_idle);
        let head = Stage::new(Instant::now(), cfg.upstream_header, by);
        match exchange(lease, request(), head, head_request, pool).await {
            // The server may have closed the connection while it waited. If nothing of an answer had arrived,
            // a request that does no harm when it is sent twice is sent on a new connection, once. The stages of
            // that go on to end by `by`. Any other request is not sent again, and the failure is not counted.
            Err(OriginError::Send) if idempotent(method) => {}
            Err(OriginError::Send) => {
                return Err(Failed {
                    error: OriginError::Send,
                    counted: false,
                });
            }
            done => return done.map_err(Failed::counted),
        }
    }
    let lease = connect(
        server.address(),
        cfg,
        connect_stage(cfg, by).map_err(Failed::counted)?,
    )
    .await
    .map_err(Failed::counted)?;
    let head = Stage::new(Instant::now(), cfg.upstream_header, by);
    exchange(lease, request(), head, head_request, pool)
        .await
        .map_err(Failed::counted)
}

/// Sends the request to a server of the group and returns its checked response head; `by` bounds the whole exchange
/// up to the head, the tries on other servers included. The edits of `rewrite` are made once, before the first try,
/// on the request and, when a server has answered, on the head of the response. A request whose edits cannot be made
/// is not sent (`Send`, with no server).
pub async fn forward(
    f: Forward,
    group: &Group,
    rewrite: &Rewrite,
    ctx: &Ctx,
    by: Instant,
) -> Dispatched {
    let cfg = &ctx.cfg;
    let Forward {
        method,
        uri,
        fields,
        body,
        peer,
    } = f;
    let trusted = client_ip::trusts(&cfg.trusted_proxies, peer.ip());
    let made = forwarded_fields(fields, peer.ip(), trusted, cfg.upstream_keepalive == 0)
        .and_then(|fields| rewrite.request(fields, uri).map_err(|_| OriginError::Send));
    let (fields, uri) = match made {
        Ok(made) => made,
        Err(error) => {
            return Dispatched {
                server: None,
                result: Err(error),
            };
        }
    };
    let head_request = method == Method::HEAD;
    let request = || {
        let mut request = Request::new(Sent::new(body.clone()));
        *request.method_mut() = method.clone();
        *request.uri_mut() = uri.clone();
        *request.version_mut() = Version::HTTP_11;
        *request.headers_mut() = fields.clone();
        request
    };

    let mut tried = Tried::default();
    let mut server = None;
    let mut error = OriginError::Unavailable;
    for _ in 0..group.len() {
        if reached(by) {
            // A try that cannot start for want of time is the fault of no server.
            error = OriginError::Late;
            break;
        }
        let Some(index) = group.pick(tried, Instant::now()) else {
            break;
        };
        tried.add(index);
        let chosen = group.server(index);
        server = Some(chosen.address());
        match attempt(chosen, cfg, &request, &method, head_request, by).await {
            Ok(mut response) => {
                rewrite.respond(response.headers_mut());
                return Dispatched {
                    server,
                    result: Ok(response),
                };
            }
            Err(failed) => {
                error = failed.error;
                if failed.counted {
                    group.fail(index, Instant::now());
                }
                if !failure_of_server(error) || !may_go_on(error, &method) {
                    break;
                }
            }
        }
    }
    Dispatched {
        server,
        result: Err(error),
    }
}

#[cfg(test)]
pub(super) mod tests;
