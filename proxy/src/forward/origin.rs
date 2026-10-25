//! Forwarding an allowed request to a server of an upstream group, and checking its answer.
//!
//! The request leaves in the form that was inspected, with these changes only: the fields that belong to the
//! connection with the client are removed, the forwarding fields are added (and `Connection: close` when the
//! connections to the upstream are not kept), the edits of the route are made (see `rewrite`), and the body is the
//! inspected bytes, followed by the rest of the body, if it is longer, as the client sends it: with the framing the
//! client used (the length it announced, or chunked), and not held (see `upload`). The names that the client listed
//! in `Connection` are collected before anything is removed and
//! are removed with the other hop-by-hop fields. The fields that are added come after the removal, so a client
//! cannot take them away by naming them. The handshake of a WebSocket that the route lets through is the one request
//! that asks the upstream to switch protocols: it gets `Connection: upgrade` and `Upgrade: websocket` as fixed
//! values, which neither the client nor the route can change.
//!
//! The forwarding fields tell the upstream who the client is. A peer that is in `trusted_proxies` is believed: its
//! `X-Forwarded-For` lines are kept and its own address is added at the end, and its `X-Forwarded-Proto` is kept if
//! it is exactly `http` or `https`, and otherwise it is the scheme of the listener the request came in on; its other
//! claims (see `CLIENT_CLAIMS`) pass as they are. From any other peer all of those claims are dropped,
//! `X-Forwarded-For` is the address of the peer alone and `X-Forwarded-Proto` is the scheme of the listener: `https`
//! on a listener that ends TLS, `http` on any other. `X-Forwarded-Host` is the `Host` of the request whoever the peer is, as the client wrote it: a route that
//! sets another `Host` does so after that.
//!
//! The server is chosen by the group (see `group`). The connection to it is the newest one that waits for that server
//! in the pool of the group and is ready, or a new one (see `connect`; over TLS if the group has `tls`). It goes back
//! to the pool when the body of the answer has been read to its end and nothing in the exchange ended it; a body that
//! is dropped before its end ends the connection.
//! A pooled connection that fails before any byte of an answer was read may have been closed by the server while it
//! waited: a request that does no harm when it is sent twice (GET, HEAD, OPTIONS, PUT, DELETE, TRACE) is then sent
//! once more on a new connection to the same server, and any other is not. A request whose body is read from the
//! client as it is sent is sent once, on a connection made for it, and after a failure goes on to the next server only
//! if the connection could not be made, for nothing was sent then. The server answers such a request after it has
//! read the body, so until the last piece of the body has been handed to the connection (see `upload`) the head of
//! the answer is due by the end of the request time only, and the connection is not held to `response_idle`, which
//! the pauses of a slow client in the body would use up: the client is held to `body_read` between two reads. A
//! server that is waited for in that time counts against no server. From the moment the last piece has been handed
//! on, the head is due `upstream_header` later, as for a request whose body is held, within the end of the request
//! time; a server that does not answer in that time fails the request (`Head`).
//!
//! A server fails a request when the connection to it is refused or reset, the server cannot be reached, or the
//! connection is not made within `upstream_connect` (`Connect`; over TLS the handshake is part of making the
//! connection, and a handshake that fails in any way, a certificate that is not trusted or is for another name
//! included, is such a failure), when the request cannot be sent, or the head of
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
//! route are made on the head that is left, so they do not reach an answer the proxy makes itself. A 101 is such an
//! answer that is refused, except to a handshake of a WebSocket: if its `Upgrade` is one line that is `websocket`
//! and its `Connection` lists `upgrade`, the head goes on with those two fields as fixed values and without a
//! length, and the connection to the upstream is not kept in the pool but handed over for a tunnel (`Switch`, see
//! `tunnel`); any other 101 is refused. Any other answer to the handshake is an answer like that to any request.
//!
//! Every wait before the head of the answer ends at an absolute instant that is never extended, and a stage whose
//! end has already been reached does not start (see `Stage`). Informational responses are read over and not passed
//! on; the bytes read from the upstream up to the final head, they included, are capped as a whole.

use std::error::Error;
use std::future::{Future, poll_fn};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::{Pin, pin};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::header::{CONNECTION, HOST, InvalidHeaderName, UPGRADE};
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri, Version,
};
use http_body::{Body, Frame, SizeHint};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use tokio::sync::watch;
use tokio::time::{Instant, sleep_until};

use self::head::{check_head, check_switch, lasts};
use crate::config::ProxyConfig;
use crate::forward::client_ip;
use crate::forward::connect::{connect, connect_stage};
use crate::forward::group::{Group, Server, Tried};
use crate::forward::pool::{Lease, Pool};
use crate::forward::rewrite::Rewrite;
use crate::forward::tunnel::Switch;
use crate::inbound::conn::Ctx;
use crate::inbound::head::trim_ows;
use crate::inbound::transport::io::Gauge;
use crate::inbound::upload::{Cut, Upload};
use crate::inspect::driver::BodyHold;

mod head;

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

/// An allowed request, as it is forwarded. `body` is the body, or its first bytes if it goes on in `upload`, which is
/// read from the client as the upstream takes it. `peer` is the address of the connection the request came on. `https`
/// is true when the listener ended TLS. `websocket` is true for the handshake of a WebSocket that the route lets
/// through.
pub struct Forward {
    pub method: Method,
    pub uri: Uri,
    pub fields: HeaderMap,
    pub body: Arc<BodyHold>,
    pub upload: Option<Upload>,
    pub peer: SocketAddr,
    pub https: bool,
    pub websocket: bool,
}

/// The upstream's response body without its trailers. At its end the connection to the upstream goes back to the
/// pool, if the exchange allows it. Dropping the body before that ends the connection. The body of a 101 is empty and
/// holds the connection as a `Switch`, which is taken out before the response is passed on.
pub struct OriginBody {
    body: Incoming,
    /// The connection, until the body has ended.
    lease: Option<Lease>,
    pool: Pool,
    /// Nothing in the answer ends the connection.
    reuse: bool,
    switch: Option<Switch>,
}

impl OriginBody {
    /// The answer may take long: the upstream may be silent for `idle` from now on, until the connection goes back
    /// to the pool, which sets the limit of the wait there.
    pub fn stream(&self, idle: Duration) {
        if let Some(lease) = &self.lease {
            lease.gauge.restart(idle);
        }
    }

    /// The connection to the upstream, if the answer was the 101 of a handshake.
    pub fn take_switch(&mut self) -> Option<Switch> {
        self.switch.take()
    }

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
    /// The body of the request, which was read from the client as it was sent, failed on the client's side. The
    /// reason is with the caller (see `upload`).
    Body,
}

/// The request body: the inspected bytes, and, if the body goes on, the rest of it as the client sends it. It keeps
/// the share of the byte budget until hyper drops it, which is when the bytes are written or the connection is gone.
pub(super) struct Sent {
    bytes: Full<Bytes>,
    upload: Option<Upload>,
    /// The rest of the body was meant to go, and is not here: the body fails at once, rather than end as if it were
    /// whole.
    lost: bool,
    _hold: Arc<BodyHold>,
}

impl Sent {
    /// The body of one send. `streamed` tells that the rest of the body goes in `upload`, which only one send can
    /// have.
    fn new(hold: Arc<BodyHold>, upload: Option<Upload>, streamed: bool) -> Sent {
        Sent {
            bytes: Full::new(hold.bytes.clone()),
            lost: streamed && upload.is_none(),
            upload,
            _hold: hold,
        }
    }
}

impl Body for Sent {
    type Data = Bytes;
    type Error = Cut;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Cut>>> {
        let this = self.get_mut();
        if this.lost {
            return Poll::Ready(Some(Err(Cut)));
        }
        if let Poll::Ready(Some(Ok(frame))) = Pin::new(&mut this.bytes).poll_frame(cx) {
            return Poll::Ready(Some(Ok(frame)));
        }
        let Some(upload) = this.upload.as_mut() else {
            return Poll::Ready(None);
        };
        upload.poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        !self.lost
            && self.bytes.is_end_stream()
            && self.upload.as_ref().is_none_or(Upload::is_end_stream)
    }

    fn size_hint(&self) -> SizeHint {
        match &self.upload {
            None => self.bytes.size_hint(),
            Some(upload) => upload
                .length()
                .map_or_else(SizeHint::default, SizeHint::with_exact),
        }
    }
}

/// A stage of the exchange with the upstream: the instant it ends at, and who set it, the stage itself (the time the
/// server may take) or the end of the request time.
#[derive(Clone, Copy)]
pub(super) struct Stage {
    pub(super) end: Instant,
    /// The limit of the stage comes before the end of the request time. When they are the same instant, the end of
    /// the request time is the one that counts.
    own: bool,
}

impl Stage {
    /// The stage that starts at `start` and lasts `len`, within `by`. A sum that does not fit into the clock counts
    /// as passed, and is not the fault of the server.
    pub(super) fn new(start: Instant, len: Duration, by: Instant) -> Stage {
        let own = start.checked_add(len);
        Stage {
            end: own.unwrap_or(start).min(by),
            own: own.is_some_and(|own| own < by),
        }
    }

    /// The stage that has no limit of its own and ends with the request time.
    pub(super) fn until(by: Instant) -> Stage {
        Stage {
            end: by,
            own: false,
        }
    }

    /// What it comes to when the time of the stage has run out: `error` if the limit of the stage ended it, `Late`
    /// if the end of the request time did.
    pub(super) fn ran_out(self, error: OriginError) -> OriginError {
        if self.own { error } else { OriginError::Late }
    }
}

/// True once `by` has been reached: a stage whose end is already here does not start.
pub(super) fn reached(by: Instant) -> bool {
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

/// The `X-Forwarded-Proto` value: the one line the request has if it is exactly `http` or `https`, the scheme of the
/// listener (`https` if `https`) otherwise.
fn forwarded_proto(fields: &HeaderMap, https: bool) -> HeaderValue {
    let mut lines = fields.get_all(&X_FORWARDED_PROTO).iter();
    match (lines.next(), lines.next()) {
        (Some(line), None) if matches!(line.as_bytes(), b"http" | b"https") => line.clone(),
        _ if https => HeaderValue::from_static("https"),
        _ => HeaderValue::from_static("http"),
    }
}

/// The fields the upstream gets, in this order: the names listed in `Connection` are collected from the fields as
/// they were inspected; the hop-by-hop fields and the listed names are removed; if the peer is not `trusted`, so
/// are the fields by which it says who the client is; then the forwarding fields are put in, and `Connection:
/// upgrade` with `Upgrade: websocket` for a handshake, or `Connection: close` if `close`. All other fields stay as
/// they were inspected. `https` is whether the listener ended TLS.
fn forwarded_fields(
    mut fields: HeaderMap,
    peer: IpAddr,
    trusted: bool,
    close: bool,
    websocket: bool,
    https: bool,
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
    let proto = forwarded_proto(&fields, https);
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
    if websocket {
        fields.insert(CONNECTION, HeaderValue::from_static("upgrade"));
        fields.insert(UPGRADE, HeaderValue::from_static("websocket"));
    } else if close {
        fields.insert(CONNECTION, HeaderValue::from_static("close"));
    }
    Ok(fields)
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

/// True when the error was caused by the body of the request failing on the client's side.
fn from_body(e: &hyper::Error) -> bool {
    let mut cause = e.source();
    while let Some(c) = cause {
        if c.downcast_ref::<Cut>().is_some() {
            return true;
        }
        cause = c.source();
    }
    false
}

/// Where a failure of the exchange belongs: `Body` when the body of the request failed on the client's side;
/// `Invalid` when the head of the answer cannot be parsed or is too long
/// (hyper reports a head with too many bytes or fields as a parse error) or when the cap for the head was hit; the
/// server answered, and what it answers can follow from the request. `Head` once any byte of an answer has been
/// read (`base` is what had been read from the connection before the exchange), or when the connection made no
/// progress for the idle limit; `Send` when nothing of an answer had arrived and the connection failed in another
/// way.
fn failure(e: &hyper::Error, gauge: &Gauge, base: u64) -> OriginError {
    if from_body(e) {
        OriginError::Body
    } else if e.is_parse() || gauge.over() {
        // The cap fails the read, so hyper reports it as an I/O error and not as a parse error.
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

/// The most bytes that are read from the upstream up to the final head. A value that does not fit into 64 bits
/// cannot happen; if it did, nothing could be read.
pub(super) fn head_cap(cfg: &ProxyConfig) -> u64 {
    u64::try_from(cfg.upstream_head_wire).unwrap_or(0)
}

/// Sends `request` on `sender` and waits for the head of the answer, which is due at the end of `head`. If the rest
/// of the body is read from the client as it is sent, `handed` sees `true` when the last piece of it has been handed
/// to the connection: the server answers only after it has read all of it, so until then the head is due at the end
/// of `head`, which is the end of the request time, and from then on `header` later, or at the end of the request
/// time if that comes first. `Err` is the stage that ran out.
async fn await_head(
    sender: &mut SendRequest<Sent>,
    request: Request<Sent>,
    mut head: Stage,
    header: Duration,
    handed: Option<watch::Receiver<bool>>,
) -> Result<Result<Response<Incoming>, hyper::Error>, Stage> {
    let by = head.end;
    let mut sending = pin!(sender.send_request(request));
    let mut limit = pin!(sleep_until(by));
    let mut told =
        handed.map(|mut rx| Box::pin(async move { rx.wait_for(|handed| *handed).await.is_ok() }));
    poll_fn(|cx| {
        if let Poll::Ready(done) = sending.as_mut().poll(cx) {
            return Poll::Ready(Ok(done));
        }
        if let Some(wait) = told.as_mut()
            && let Poll::Ready(is_told) = wait.as_mut().poll(cx)
        {
            // A sender that is gone without telling means the body will not be handed on: the end stays.
            told = None;
            if is_told {
                head = Stage::new(Instant::now(), header, by);
                limit.as_mut().reset(head.end);
            }
        }
        if limit.as_mut().poll(cx).is_ready() {
            Poll::Ready(Err(head))
        } else {
            Poll::Pending
        }
    })
    .await
}

/// Sends `request` on the connection and returns the checked head of the answer; `head` bounds that (see
/// `await_head`). The connection is closed if this fails. It goes back to `pool` at the end of the body of the answer
/// if nothing in the head ends it. If the request is the handshake of a WebSocket (`websocket`) and the answer is a
/// 101, the connection is kept in the answer for a tunnel instead. If the rest of the body is read from the client
/// as it is sent, the server answers only after it has read all of it, so the connection has no limit on its
/// silence until the head is here, and is held to `response_idle` from then on.
async fn exchange(
    mut lease: Lease,
    request: Request<Sent>,
    head: Stage,
    head_request: bool,
    websocket: bool,
    pool: &Pool,
    cfg: &ProxyConfig,
) -> Result<Response<OriginBody>, OriginError> {
    if reached(head.end) {
        return Err(head.ran_out(OriginError::Head));
    }
    let handed = request.body().upload.as_ref().map(Upload::watch);
    let streamed = handed.is_some();
    if streamed {
        lease.gauge.pause();
    }
    let base = lease.gauge.read();
    lease.used = lease.used.saturating_add(1);
    let sent = await_head(
        &mut lease.sender,
        request,
        head,
        cfg.upstream_header,
        handed,
    )
    .await;
    let mut response = match sent {
        Ok(Ok(response)) => response,
        Ok(Err(e)) => return Err(failure(&e, &lease.gauge, base)),
        Err(stage) => return Err(stage.ran_out(OriginError::Head)),
    };
    lease.gauge.lift();
    if streamed {
        lease.gauge.restart(cfg.response_idle);
    }
    // The connection may have started reading the body before the cap was lifted. A read that was refused
    // has cut the answer off, so it is not passed on; as in `failure`, the cap is not the fault of the server.
    if lease.gauge.over() {
        return Err(OriginError::Invalid);
    }
    if websocket && response.status() == StatusCode::SWITCHING_PROTOCOLS {
        // The handle is taken before the head is checked, which drops the extensions.
        let on = hyper::upgrade::on(&mut response);
        let (mut parts, body) = response.into_parts();
        check_switch(&mut parts)?;
        let body = OriginBody {
            body,
            lease: None,
            pool: pool.clone(),
            reuse: false,
            switch: Some(Switch::new(on, lease)),
        };
        return Ok(Response::from_parts(parts, body));
    }
    let (mut parts, body) = response.into_parts();
    let reuse = lasts(&parts, head_request);
    check_head(&mut parts, head_request)?;
    let mut body = OriginBody {
        body,
        lease: Some(lease),
        pool: pool.clone(),
        reuse,
        switch: None,
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

/// How the body of a request is sent, which says what can be done again after a failure.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Payload {
    /// All the bytes are held. `again`: the method does no harm when it reaches a server twice.
    Held { again: bool },
    /// The rest of the body is read from the client as it is sent, so it can be sent once.
    Streamed,
}

impl Payload {
    /// Whether the request may be sent once more after a failure that came when it was on its way.
    fn again(self) -> bool {
        matches!(self, Payload::Held { again: true })
    }
}

/// Whether `error` is a failure of the server: the group counts it, and the request may go to another one.
fn failure_of_server(error: OriginError) -> bool {
    matches!(
        error,
        OriginError::Connect | OriginError::Send | OriginError::Head
    )
}

/// Whether a request may go to another server after `error`: always if the connection could not be made, for
/// nothing was sent then, and otherwise only if all of its body is held and it does no harm when it reaches a server
/// twice.
fn may_go_on(error: OriginError, payload: Payload) -> bool {
    match error {
        OriginError::Connect => true,
        OriginError::Send | OriginError::Head => payload.again(),
        OriginError::Invalid
        | OriginError::Unavailable
        | OriginError::Late
        | OriginError::Local
        | OriginError::Body => false,
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

/// One try on one server. `request` makes the request for each send. A request whose body is read from the client
/// as it is sent is sent once, on a connection that is made for it: a waiting connection may have been closed by the
/// server, which is found out only when the request is on its way, and then it cannot be sent again. Its server
/// answers after it has read the body, so the head is due by `by` until the body has been handed on, and
/// `upstream_header` after that (see `await_head`).
async fn attempt(
    server: &Server,
    cfg: &ProxyConfig,
    request: &impl Fn() -> Request<Sent>,
    payload: Payload,
    head_request: bool,
    websocket: bool,
    by: Instant,
) -> Result<Response<OriginBody>, Failed> {
    let pool = server.pool();
    let streamed = payload == Payload::Streamed;
    if !streamed
        && let Some(lease) = pool
            .take(connect_stage(cfg, by).map_err(Failed::counted)?.end)
            .await
    {
        lease.gauge.rearm(head_cap(cfg), cfg.response_idle);
        let head = Stage::new(Instant::now(), cfg.upstream_header, by);
        match exchange(lease, request(), head, head_request, websocket, pool, cfg).await {
            // The server may have closed the connection while it waited. If nothing of an answer had arrived,
            // a request that does no harm when it is sent twice is sent on a new connection, once. The stages of
            // that go on to end by `by`. Any other request is not sent again, and the failure is not counted.
            Err(OriginError::Send) if payload.again() => {}
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
        server.secure(),
        cfg,
        connect_stage(cfg, by).map_err(Failed::counted)?,
    )
    .await
    .map_err(Failed::counted)?;
    let head = if streamed {
        Stage::until(by)
    } else {
        Stage::new(Instant::now(), cfg.upstream_header, by)
    };
    exchange(lease, request(), head, head_request, websocket, pool, cfg)
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
        upload,
        peer,
        https,
        websocket,
    } = f;
    let trusted = client_ip::trusts(&cfg.trusted_proxies, peer.ip());
    let made = forwarded_fields(
        fields,
        peer.ip(),
        trusted,
        cfg.upstream_keepalive == 0,
        websocket,
        https,
    )
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
    let payload = if upload.is_some() {
        Payload::Streamed
    } else {
        Payload::Held {
            again: idempotent(&method),
        }
    };
    let streamed = payload == Payload::Streamed;
    // The rest of the body is in one request only; `Sent` fails a request made without it.
    let upload = Mutex::new(upload);
    let request = || {
        let upload = upload.lock().unwrap_or_else(PoisonError::into_inner).take();
        let mut request = Request::new(Sent::new(body.clone(), upload, streamed));
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
        match attempt(chosen, cfg, &request, payload, head_request, websocket, by).await {
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
                if !failure_of_server(error) || !may_go_on(error, payload) {
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
