//! One try on one server and the exchange on its connection: sending the request, waiting for the head of the
//! answer, where a failure belongs (`failure`), and whether the request may go to another server (`may_go_on`).

use std::error::Error;
use std::future::{Future, poll_fn};
use std::io;
use std::net::SocketAddr;
use std::pin::pin;
use std::task::Poll;
use std::time::Duration;

use http::{Method, Request, Response, StatusCode};
use http_body::Body;
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use tokio::sync::watch;
use tokio::time::{Instant, sleep_until};

use super::head::{check_head, check_switch, lasts};
use super::{OriginBody, OriginError, Sent, Stage, reached};
use crate::config::ProxyConfig;
use crate::forward::connect::{connect, connect_stage};
use crate::forward::group::Server;
use crate::forward::pool::{Lease, Pool};
use crate::forward::tunnel::Switch;
use crate::inbound::transport::io::Gauge;
use crate::inbound::upload::{Cut, Upload};

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
pub(super) fn idempotent(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::PUT | Method::DELETE | Method::TRACE
    )
}

/// The most bytes that are read from the upstream up to the final head. A value that does not fit into 64 bits
/// cannot happen; if it did, nothing could be read.
pub(in crate::forward) fn head_cap(cfg: &ProxyConfig) -> u64 {
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
pub(super) enum Payload {
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
pub(super) fn failure_of_server(error: OriginError) -> bool {
    matches!(
        error,
        OriginError::Connect | OriginError::Send | OriginError::Head
    )
}

/// Whether a request may go to another server after `error`: always if the connection could not be made, for
/// nothing was sent then, and otherwise only if all of its body is held and it does no harm when it reaches a server
/// twice.
pub(super) fn may_go_on(error: OriginError, payload: Payload) -> bool {
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
pub(super) struct Failed {
    pub(super) error: OriginError,
    pub(super) counted: bool,
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
pub(super) async fn attempt(
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
