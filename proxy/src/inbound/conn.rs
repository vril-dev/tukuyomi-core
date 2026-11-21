//! One request of a connection: the route, the body, the inspection, and then the answer or the forwarding.
//!
//! The head was checked by `head` before this runs. On an HTTP/1.1 connection `http1::gate` passed it, and the session
//! hands it over with the request that hyper made of the same bytes; on an HTTP/2 connection it was made from the
//! fields of the stream (see `http2::head`). A request for the challenge of the CA that issues the certificates with
//! `acme`, on a plain listener, is answered before all that follows (see `challenge`). The first thing that follows is
//! the policy for the `Host` (see `policy::Scopes`): a client that the `access` turns away, by its network or country,
//! gets 403, and one that is over the rate limit gets 429 with a `Retry-After`, before any route is looked for,
//! whether the route skips the inspection or not. The country of the client, which those lists and the lists of the
//! route may name, is looked up once for the request, if the configuration has a country database (see
//! `policy::country`). The route for the request is looked up next, by its `Host` and its target as the client sent
//! them. A request that no route holds for, with no default group, is answered with 404, and one
//! from a client that the access lists of its route turn away with 403, before anything of its body is read and before
//! the inspection is asked for. So is a request on a connection that ended TLS, whose `Host` is not one of the hosts of
//! the certificate that the handshake used, or cannot be read (421; it comes before the route is looked up), and so is
//! a request with a `Content-Length` over the `max_body` of its route (413). Then the request either matches a rule of
//! the generation that serves that skips the inspection, and is forwarded without being inspected, or its first
//! `inspect_body` bytes are read through hyper into a budgeted buffer and handed to the inspection driver as a
//! ticket, and only an `Allow` or a `Detected` is forwarded. An inspected body has to be of a type that the
//! inspection reads (`Head::inspectable_type`), or the answer is 415: before the body is read if it has a length,
//! after it if it is chunked and not empty. So is a body with more than one `Content-Type` line, whether the
//! inspection runs or not. A body that ends within those bytes is held whole and is
//! forwarded as it was inspected (or, under a route that skips the inspection, as it was read). A longer one goes on
//! past them: the ticket says that the body is cut, and once the request is let through the rest is passed on to the
//! upstream as the client sends it (see `upload`), so what the request holds does not grow with the length of the
//! body. The part of the body behind the inspected bytes is not inspected. A gzip body that is to be inspected is
//! held whole and decoded by `represent::gunzip` (exactly one member), and the coded and the decoded body are each
//! at most `inspect_body` bytes; a longer one is refused with 413. A gzip body under a route that skips the
//! inspection is never decoded: it is held or passed on as it came, like any other body, and the limit of the body
//! counts the coded bytes. The request is forwarded to a server of the group of the route that was looked up, with the
//! edits of that route (see `rewrite`). If the route has a `stream` that lets a WebSocket through
//! and the request is the handshake of one, the share of the byte budget that a tunnel holds is taken first (and the
//! request is answered with 503 if it cannot be had, before anything is sent), and if the upstream answers with 101 the
//! response comes with the tunnel (see `tunnel`). Any other response on a route with a `stream` comes marked as one
//! that may take long. A request under a rule that skips the inspection takes no inspection permit, no byte of the
//! kernel's copy and no place in the driver's channel, so it goes on also when the inspection is full or the inspector
//! is down. What is inspected and what is forwarded is the same request, in the form that `represent` builds it: the
//! decoded body, without its `Content-Encoding`, with its decoded length, or, for a body that goes on past the
//! inspected bytes or is not decoded, the body as the client sent it with its own framing. The edits of the route
//! come after the inspection. The other difference is the `Transfer-Encoding` that an HTTP/1.1 client sent with a
//! chunked body that goes on: the inspection gets it, and the upstream gets the body chunked by the client side of
//! the proxy. The record gives the length of the body: its `Content-Length` if it has one, and otherwise the bytes
//! read so far.
//!
//! A request whose `Host` is the host of the way to the admin process asks only the access list of the way (`admin`).
//!
//! The route is found on the bytes received, but an application behind the proxy may read another spelling of a path
//! as the path of a route that limits who may use it (`/priv%61te/x` for `/private/x`). So if some route has an
//! access list, the client has to pass the lists of every route the request could be taken for, not only those of the
//! route it goes to (see `route`).
//!
//! Every answer that `answer` makes, and the fixed answer that `head` holds for a refused head, has an empty
//! body and `Content-Length: 0` (not for 204 and 304); the answer to the challenge of the CA has the file for its body,
//! or is the 404 of `answer`. Whether the connection goes on after the response is not
//! decided here (see `session`); this only tells whether the body of the request was read to its end. A request
//! whose peer went away is closed without an answer, and a response that fails after its head was sent is cut off
//! without its terminator.
//!
//! Deadlines are absolute instants and are never extended: a stage ends at the earlier of its own start plus its
//! length and the end of the request time, counted from the start of the request, and the whole connection ends at
//! the connection time counted from the accept. The one exception is the response of a route with a `stream`, which
//! puts off the end of the connection once its head is ready (see `session`). A sum that does not fit into the
//! clock counts as passed.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use http::{Response, request::Parts};
use hyper::body::Incoming;
use tokio::time::Instant;

use self::body::Taken;
use self::fault::{PEER_CLOSED, upstream_stop};
use crate::config::Stream;
use crate::forward::client_ip::{self, Cidr, Country};
use crate::forward::group::Route;
use crate::forward::origin::{self, Forward, OriginBody};
use crate::forward::tunnel::{self, Record, Tunnel};
use crate::inbound::answer::{
    Abort, Keeping, Noted, Out, Passed, Reply, Sizes, Stop, Via, answer, answer_after, text,
};
use crate::inbound::challenge::Proof;
use crate::inbound::head::{Head, Reject};
use crate::inbound::represent::{Represented, represent};
use crate::inbound::transport::io::Gauge;
use crate::inbound::transport::tls::Hosts;
use crate::inspect::driver::{BodyHold, Judge, Msg};

mod body;
mod ctx;
mod fault;
mod keep;
mod routing;
mod ticket;

pub use self::ctx::{Ctx, Setup, Shared, SharedSetup};
pub(super) use self::fault::peer_gone;
pub(super) use self::keep::Unanswered;

/// How the listener that took a connection carries its requests: over plain HTTP, or over TLS, with the hosts of the
/// certificate that the handshake used.
#[derive(Clone)]
pub enum Scheme {
    Http,
    Https(Arc<Hosts>),
}

/// `start + len`; a sum that does not fit into the clock is a deadline that has passed.
pub(super) fn after(start: Instant, len: Duration) -> Instant {
    start.checked_add(len).unwrap_or(start)
}

/// The deadline of a stage that starts at `start` and lasts `len`, within the request time that ends at
/// `request_by`.
fn stage(start: Instant, len: Duration, request_by: Instant) -> Instant {
    after(start, len).min(request_by)
}

/// The address that stands for the client of the request with `head` that came from `peer`: the peer, or what a peer
/// in `trusted` says in its `X-Forwarded-For` lines (see `client_ip`).
pub(super) fn client_of(head: &Head, peer: SocketAddr, trusted: &[Cidr]) -> SocketAddr {
    let lines: Vec<&[u8]> = head
        .fields()
        .filter(|(name, _)| name.eq_ignore_ascii_case(b"x-forwarded-for"))
        .map(|(_, value)| value)
        .collect();
    client_ip::effective(peer, trusted, &lines)
}

/// The country of the client at `client`, which is `Country::Unknown` if there is no database, for then no list asks.
pub(super) fn country_of(ctx: &Ctx, client: IpAddr) -> Country {
    ctx.setup
        .country
        .as_ref()
        .map_or(Country::Unknown, |geo| geo.country(client))
}

/// The state of one request that its service reads.
pub(super) struct Conn {
    ctx: Arc<Ctx>,
    /// The number of the connection, for the record.
    id: u64,
    /// The number of the request: in the record, to the upstream and in the response.
    request: String,
    head: Head,
    peer: SocketAddr,
    /// The address that stands for the client: the peer, or what a trusted peer says (see `client_ip`). The
    /// inspection and the record use it.
    client: SocketAddr,
    /// The country of `client`, found once for the request.
    country: Country,
    local: SocketAddr,
    scheme: Scheme,
    gauge: Gauge,
    /// End of the request time: the last instant for the answer, or for the upstream's response head.
    request_by: Instant,
    /// When the head was complete: the body stage counts from here.
    head_end: Instant,
    /// The way to the driver, taken for the one ticket and dropped as soon as it is sent, or as soon as a route
    /// lets the request through without one. Holding it for the life of a streaming response would keep the driver
    /// from seeing that no sender is left. A request that starts after the stop has none.
    ingress: Mutex<Option<SyncSender<Msg>>>,
    /// The body of the request was read to its end.
    read_done: Arc<AtomicBool>,
    /// Where the request was sent, set when it is.
    via: Mutex<Option<Via>>,
    /// The size of the body, set when it has been read (or, if it goes on, as far as it has).
    sizes: Mutex<Option<Sizes>>,
    /// The generation whose rules gave a verdict, and that verdict, set when one did.
    judged: Mutex<Option<Judge>>,
    /// How the record is kept (see `keep`), set once the route is found.
    keeping: Mutex<Keeping>,
}

/// What a request came to: what the record shows of it, and the response, or the order to close without one. A
/// response of the upstream comes with the tunnel it starts (the 101 of a WebSocket), or, if it is any other and the
/// route has a `stream`, with the times of that.
pub(super) struct Handled {
    pub(super) noted: Noted,
    pub(super) response: Result<Response<Out>, Abort>,
    pub(super) tunnel: Option<Tunnel>,
    pub(super) stream: Option<Stream>,
}

/// The response of the upstream and what goes with it.
struct Answered {
    response: Response<OriginBody>,
    passed: Passed,
    tunnel: Option<Tunnel>,
    stream: Option<Stream>,
}

impl Conn {
    // One argument for each part of the connection and of the request that the state is made of; a struct of them
    // would only repeat their names.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        ctx: &Arc<Ctx>,
        id: u64,
        request: String,
        head: Head,
        peer: SocketAddr,
        local: SocketAddr,
        scheme: Scheme,
        gauge: Gauge,
        request_by: Instant,
    ) -> Conn {
        let client = client_of(&head, peer, &ctx.setup.cfg.trusted_proxies);
        Conn {
            ctx: ctx.clone(),
            id,
            request,
            country: country_of(ctx, client.ip()),
            client,
            head,
            peer,
            local,
            scheme,
            gauge,
            request_by,
            head_end: Instant::now(),
            ingress: Mutex::new(ctx.shared.ingress.sender()),
            read_done: Arc::new(AtomicBool::new(false)),
            via: Mutex::new(None),
            sizes: Mutex::new(None),
            judged: Mutex::new(None),
            keeping: Mutex::new(Keeping::default()),
        }
    }

    pub(super) fn head(&self) -> &Head {
        &self.head
    }

    /// The body of the request was read to its end, so the connection is at the start of the next request.
    pub(super) fn body_read(&self) -> bool {
        self.read_done.load(Ordering::Acquire)
    }

    /// The service: one request.
    pub(super) async fn handle(&self, parts: Parts, body: Incoming) -> Handled {
        if let Some(handled) = self.challenge() {
            return handled;
        }
        let (reply, response, tunnel, stream) = match self.exchange(parts, body).await {
            Ok(Answered {
                response,
                passed,
                tunnel,
                stream,
            }) => {
                let reply = Reply::forwarded(response.status().as_u16(), passed);
                let response = Ok(response.map(|body| Out::Origin(Box::pin(body))));
                (reply, response, tunnel, stream)
            }
            Err(Stop::Reply(reply)) => (reply, Ok(answer(reply.status)), None, None),
            Err(Stop::Retry(reply, seconds)) => {
                (reply, Ok(answer_after(reply.status, seconds)), None, None)
            }
            Err(Stop::Close(reason)) => (
                Reply {
                    reason,
                    ..Reply::NONE
                },
                Err(Abort),
                None,
                None,
            ),
        };
        let mut noted = self.noted(reply);
        // A request whose client went away while its body was read is kept on a route that keeps only some records,
        // as one that is dropped before its answer is (`unanswered`).
        if reply.reason == PEER_CLOSED {
            noted.keeping.only_security = false;
        }
        Handled {
            noted,
            response,
            tunnel,
            stream,
        }
    }

    /// The answer to the challenge of the CA if the request is one and the listener is a plain one: nothing of it is
    /// read or checked besides its head, and it takes no inspection and no route. The connection goes on only if
    /// there is no body to read, as after an answer that turns a request away.
    fn challenge(&self) -> Option<Handled> {
        if !matches!(self.scheme, Scheme::Http) {
            return None;
        }
        let proof = self.ctx.setup.challenge.as_ref()?.proof(&self.head)?;
        self.note_empty_body();
        let (reply, response) = match proof {
            Proof::Found(body) => (
                Reply::answered(200),
                text(Bytes::from(body), self.head.method() == b"HEAD"),
            ),
            Proof::Missing => (Reply::answered(404), answer(404)),
        };
        Some(Handled {
            noted: Noted::new(self.request.clone(), reply, self.client.ip()).of(&self.head),
            response: Ok(response),
            tunnel: None,
            stream: None,
        })
    }

    /// Everything up to the response of the upstream, and how the request was let through.
    async fn exchange(&self, parts: Parts, body: Incoming) -> Result<Answered, Stop> {
        let route = self.route()?;
        let cfg = &self.ctx.setup.cfg;
        let bypass = self
            .ctx
            .shared
            .routes
            .current()
            .matches(self.head.host(), self.head.target());
        // A gzip body that is inspected is held whole to be decoded, and what it decodes to is held too, so neither
        // may be longer than the bytes that are inspected: a longer one is refused. One that is not inspected is
        // never decoded: it is held or goes on as it came, as does any other body.
        let limit = route.max_body.unwrap_or(cfg.max_body);
        let held_max = limit.min(cfg.inspect_body);
        let decode = self.head.gzip() && !bypass;
        let (keep, limit) = if decode {
            (held_max, held_max)
        } else {
            (cfg.inspect_body, limit)
        };
        // The type of a body that is inspected has to be one that the inspection reads; under a route that skips the
        // inspection any type goes, but not more than one `Content-Type` line. A body with a length is judged before
        // it is read (the head check refuses the lines); a chunked one, which may be empty, below.
        let typed = self.head.inspectable_type() || (bypass && !self.head.repeated_type());
        if !typed && self.head.content_length().is_some_and(|n| n > 0) {
            return Err(Reject::UnsupportedMedia.into());
        }
        let Taken {
            bytes,
            budget,
            upload,
        } = self.read_body(body, keep, limit).await?;
        let read = bytes.len();
        // An empty chunked body is not a gzip stream (a body with a length of 0 is refused by the head check).
        if self.head.gzip() && bytes.is_empty() {
            return Err(Reply::rejected(400, "empty gzip body").into());
        }
        let (bytes, budget) = if decode {
            self.unpack(bytes, budget, held_max)?
        } else {
            (bytes, budget)
        };
        let Represented {
            fields,
            headers,
            field_bytes,
        } = represent(&self.head, upload.is_none().then_some(bytes.len()), decode)?;
        // A chunked body is not known to be empty before it has been read, so the rule on the body type is applied
        // here, with the same test (on the decoded body, when it was decoded).
        if !typed && self.head.chunked() && (!bytes.is_empty() || upload.is_some()) {
            return Err(Reject::UnsupportedMedia.into());
        }
        let cut = upload.is_some() && !bypass;
        let (upload, fate) = match upload {
            Some((upload, fate)) => (Some(upload), Some(fate)),
            None => (None, None),
        };
        let declared = self.head.content_length();
        *self.sizes.lock().unwrap_or_else(PoisonError::into_inner) = Some(match &fate {
            Some(fate) => Sizes::passed(declared, bytes.len(), fate.clone(), cut),
            None => Sizes::whole(declared, read),
        });
        let body = Arc::new(BodyHold::new(bytes, budget));
        let passed = if bypass {
            self.bypassed()
        } else {
            self.ask(headers, field_bytes, &body, cut)
                .await
                .inspect_err(|_| self.inspection_stopped())?
        };
        if Instant::now() >= self.request_by {
            return Err(Reply::failed(503, "request time used up").into());
        }
        // A tunnel holds its share of the budget from before the handshake is sent.
        let websocket = self.websocket(&route);
        let hold = websocket.map(|_| self.take(tunnel::HOLD)).transpose()?;
        let forward = Forward {
            method: parts.method,
            uri: parts.uri,
            fields,
            body,
            upload,
            peer: self.peer,
            https: matches!(self.scheme, Scheme::Https(_)),
            websocket: websocket.is_some(),
            id: self.request.clone(),
        };
        let sent = origin::forward(
            forward,
            route.group,
            route.rewrite,
            &self.ctx,
            self.request_by,
        )
        .await;
        *self.via.lock().unwrap_or_else(PoisonError::into_inner) = Some(Via {
            group: route.group.name().clone(),
            server: sent.server,
        });
        let mut response = sent.result.map_err(|e| upstream_stop(e, fate.as_deref()))?;
        let tunnel = match (response.body_mut().take_switch(), websocket, hold) {
            (Some(switch), Some(stream), Some(hold)) => {
                Some(Tunnel::new(switch, *stream, hold, self.record()))
            }
            _ => None,
        };
        // A tunnel has its own times; any other response on a route with a `stream` may take long.
        let stream = route.stream.copied().filter(|_| tunnel.is_none());
        if let Some(stream) = &stream {
            response.body_mut().stream(stream.idle);
        }
        Ok(Answered {
            response,
            passed,
            tunnel,
            stream,
        })
    }

    /// What the record for the end of the tunnel of this request says besides how it ended, which the tunnel holds
    /// from the moment it is made.
    fn record(&self) -> Record {
        let via = self.via.lock().unwrap_or_else(PoisonError::into_inner);
        Record {
            log: self.ctx.shared.log.clone(),
            id: self.request.clone(),
            conn: self.id,
            client: self.client.ip(),
            upstream: via.as_ref().map(|via| via.group.clone()),
            server: via.as_ref().and_then(|via| via.server),
        }
    }

    /// The `stream` of the route if the request is the handshake of a WebSocket and the route lets one through. After
    /// the stop has begun no tunnel starts: the handshake goes on as any request does.
    fn websocket<'a>(&self, route: &Route<'a>) -> Option<&'a Stream> {
        route.stream.filter(|stream| {
            stream.websocket && self.head.websocket() && !self.ctx.shared.ingress.is_closed()
        })
    }
}

#[cfg(test)]
pub(super) mod tests;
