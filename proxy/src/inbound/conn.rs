//! One request of a connection: the route, the body, the inspection, and then the answer or the forwarding.
//!
//! The head was checked by `head` before this runs. On an HTTP/1.1 connection `http1::gate` passed it, and the session
//! hands it over with the request that hyper made of the same bytes; on an HTTP/2 connection it was made from the
//! fields of the stream (see `http2::head`). A request for the challenge of the CA that issues the certificates with
//! `acme`, on a plain listener, is answered before all that follows (see `challenge`). The route for the request is
//! looked up first, by its `Host` and its target
//! as the client sent them. A request that no route holds for, with no default group, is answered with 404, and one
//! from a client that the access lists of its route turn away with 403, before anything of its body is read and before
//! the inspection is asked for. So is a request on a connection that ended TLS, whose `Host` is not one of the hosts of
//! the certificate that the handshake used, or cannot be read (421; it comes before the route is looked up), and so is
//! a request with a `Content-Length` over the `max_body` of its route (413). Then the request either matches a rule of
//! the generation that serves that skips the inspection, and is forwarded without being inspected, or its first
//! `inspect_body` bytes are read through hyper into a budgeted buffer and handed to the inspection driver as a
//! ticket, and only an `Allow` or a `Detected` is forwarded. A body that ends within those bytes is held whole and is
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
//! inspected bytes or is not decoded, the body as the client sent it with its own framing; the edits of the route
//! come after the inspection and are the only difference. The record gives the length of the body: its
//! `Content-Length` if it has one, and otherwise the bytes read so far.
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

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http::{Response, request::Parts};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};
use tokio::time::{Instant, timeout_at};

use crate::config::{ProxyConfig, STREAM_HOLD, Stream};
use crate::forward::client_ip;
use crate::forward::group::{Route, Upstreams};
use crate::forward::origin::{self, Forward, OriginBody, OriginError};
use crate::forward::tunnel::{self, Record, Tunnel};
use crate::inbound::answer::{
    Abort, Decision, Noted, Out, Passed, Reply, Sizes, Stop, Via, answer, decide, text,
};
use crate::inbound::challenge::{Challenge, Proof};
use crate::inbound::head::{Head, Reject};
use crate::inbound::represent::{Represented, gunzip, represent};
use crate::inbound::session::RequestIds;
use crate::inbound::transport::io::Gauge;
use crate::inbound::transport::tls::{Hosts, Tls};
use crate::inbound::upload::{Cause, Fate, Terms, Upload};
use crate::inspect::driver::{Answer, BodyHold, Hold, Ingress, InspectReq, Judge, Msg, Ticket};
use crate::log::Log;
use crate::log::counters::Counters;
use crate::rules::routes::SharedRoutes;

/// What every connection shares: the configuration, the byte budget of held bodies and of the kernel's copies,
/// the inspection permits (as many as the kernel's waiting queue), the routes of the generation that serves, the
/// upstream groups with the routes to them and the connections that wait to be used again, the way to the driver,
/// the TLS of the listeners that end it, the answer to the challenge of the CA, if the configuration has `acme`, the
/// numbers of the requests, and the counters that `/metrics` shows.
pub struct Ctx {
    pub cfg: ProxyConfig,
    pub budget: Arc<Semaphore>,
    pub inspect: Arc<Semaphore>,
    pub routes: SharedRoutes,
    pub upstreams: Upstreams,
    pub log: Log,
    pub ingress: Arc<Ingress>,
    pub tls: Tls,
    pub challenge: Option<Challenge>,
    pub ids: RequestIds,
    pub counters: Counters,
}

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
}

/// The first bytes of a body, which `read_body` holds, and the rest of it if the body goes on.
struct Taken {
    bytes: Bytes,
    budget: OwnedSemaphorePermit,
    upload: Option<(Upload, Arc<Fate>)>,
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
        let lines: Vec<&[u8]> = head
            .fields()
            .filter(|(name, _)| name.eq_ignore_ascii_case(b"x-forwarded-for"))
            .map(|(_, value)| value)
            .collect();
        let client = client_ip::effective(peer, &ctx.cfg.trusted_proxies, &lines);
        Conn {
            ctx: ctx.clone(),
            id,
            request,
            client,
            head,
            peer,
            local,
            scheme,
            gauge,
            request_by,
            head_end: Instant::now(),
            ingress: Mutex::new(ctx.ingress.sender()),
            read_done: Arc::new(AtomicBool::new(false)),
            via: Mutex::new(None),
            sizes: Mutex::new(None),
            judged: Mutex::new(None),
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
        let via = self
            .via
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let body = self
            .sizes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let judged = self
            .judged
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        Handled {
            noted: Noted {
                via,
                body,
                judged,
                ..Noted::new(self.request.clone(), reply, self.client.ip()).of(&self.head)
            },
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
        let proof = self.ctx.challenge.as_ref()?.proof(&self.head)?;
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
        let cfg = &self.ctx.cfg;
        let bypass = self
            .ctx
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
        // The head check cannot tell whether a chunked body is empty, so its rule on the body type is applied
        // here, with the same test (on the decoded body, when it was decoded).
        if self.head.chunked()
            && (!bytes.is_empty() || upload.is_some())
            && !self.head.inspectable_type()
        {
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
            self.ask(headers, field_bytes, &body, cut).await?
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
            log: self.ctx.log.clone(),
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
            stream.websocket && self.head.websocket() && !self.ctx.ingress.is_closed()
        })
    }

    /// The route the request takes. A request that no route holds for, and that has no default group, is answered
    /// with 404 here, and one from a client that the access lists turn away with 403, before the body is read. If
    /// some route has an access list, every route that the request could be taken for, however it is written, has to
    /// allow the client (see `Upstreams::accesses`); if none has, nobody is turned away and that is not asked. On a
    /// connection that ended TLS the `Host` has to be covered by the certificate of the handshake first, or the
    /// answer is 421: the client may not use a connection for a site that its certificate does not stand for.
    fn route(&self) -> Result<Route<'_>, Stop> {
        let (host, target) = (self.head.host(), self.head.target());
        if let Scheme::Https(hosts) = &self.scheme
            && !hosts.covers_host(host)
        {
            return Err(self.turned_away(421, "host not covered by the certificate"));
        }
        let upstreams = &self.ctx.upstreams;
        let route = upstreams
            .find(host, target)
            .ok_or_else(|| self.turned_away(404, "no route matches"))?;
        let client = self.client.ip();
        if upstreams.guarded()
            && !upstreams
                .accesses(host, target)
                .all(|access| access.permits(client))
        {
            return Err(self.turned_away(403, "denied by route access"));
        }
        // The limit of the route is looked at before the body is read, as the other limits that turn a request away.
        if let Some(max) = route.max_body
            && self
                .head
                .content_length()
                .is_some_and(|length| length > u64::try_from(max).unwrap_or(u64::MAX))
        {
            return Err(self.turned_away(413, "body over the limit of the route"));
        }
        Ok(route)
    }

    /// The answer to a request that is turned away before its body is read. The connection goes on after it only if
    /// there was no body to read.
    fn turned_away(&self, status: u16, reason: &'static str) -> Stop {
        self.note_empty_body();
        Reply::rejected(status, reason).into()
    }

    /// A request with no body has been read to its end, whatever the answer is.
    fn note_empty_body(&self) {
        if !self.head.chunked() && self.head.content_length().unwrap_or(0) == 0 {
            self.read_done.store(true, Ordering::Release);
        }
    }

    /// Takes `n` bytes of the budget.
    fn take(&self, n: usize) -> Result<OwnedSemaphorePermit, Stop> {
        u32::try_from(n)
            .ok()
            .and_then(|n| self.ctx.budget.clone().try_acquire_many_owned(n).ok())
            .ok_or_else(|| Reply::failed(503, "byte budget exhausted").into())
    }

    /// Reads the first `keep` bytes of the decoded body, or all of it if it ends sooner. A body that goes on past
    /// them is passed on while the client sends it (see `upload`): the bytes read behind the first ones are the
    /// start of the rest, and the request holds `STREAM_HOLD` more of the budget while that goes on. A body that
    /// is longer than `limit` is refused with 413. The budget of the bytes held is taken before the first byte is
    /// read (so no `100 Continue` is sent for a body that cannot be held), the budget of a chunked body frame by
    /// frame.
    async fn read_body(
        &self,
        mut body: Incoming,
        keep: usize,
        limit: usize,
    ) -> Result<Taken, Stop> {
        let chunked = self.head.chunked();
        let declared = match self.head.content_length() {
            Some(n) => usize::try_from(n).map_err(|_| Reject::ContentTooLarge)?,
            None => 0,
        };
        if !chunked && declared == 0 {
            self.read_done.store(true, Ordering::Release);
            return Ok(Taken {
                bytes: Bytes::new(),
                budget: self.take(0)?,
                upload: None,
            });
        }
        if declared > limit {
            return Err(Reject::ContentTooLarge.into());
        }
        // A body with a length that is longer than `keep` goes on past the bytes held.
        let goes_on = declared > keep;
        let mut budget = self.take(declared.min(keep))?;
        if goes_on {
            budget.merge(self.take(STREAM_HOLD)?);
        }
        let mut data = BytesMut::with_capacity(declared.min(keep));
        let mut rest = Bytes::new();
        let mut ended = false;
        let by = stage(self.head_end, self.ctx.cfg.body_read, self.request_by);
        loop {
            if goes_on && data.len() == keep {
                break;
            }
            let frame = match timeout_at(by, body.frame()).await {
                Err(_) => return Err(Reply::rejected(408, "body not received in time").into()),
                Ok(None) => {
                    ended = true;
                    break;
                }
                Ok(Some(Err(e))) => return Err(self.body_fault(&e)),
                Ok(Some(Ok(frame))) => frame,
            };
            match frame.into_data() {
                Ok(mut chunk) => {
                    if data
                        .len()
                        .checked_add(chunk.len())
                        .is_none_or(|total| total > limit)
                    {
                        return Err(Reply::rejected(413, "body over the limit").into());
                    }
                    // The bytes of this chunk behind the first `keep` are the start of the rest.
                    let room = keep - data.len();
                    if chunk.len() > room {
                        rest = chunk.split_off(room);
                    }
                    if chunked {
                        budget.merge(self.take(chunk.len())?);
                    }
                    data.extend_from_slice(&chunk);
                    if !rest.is_empty() {
                        if chunked {
                            budget.merge(self.take(STREAM_HOLD)?);
                        }
                        break;
                    }
                }
                Err(frame) => {
                    if frame
                        .into_trailers()
                        .is_ok_and(|trailers| !trailers.is_empty())
                    {
                        return Err(Reply::rejected(400, "request trailers not supported").into());
                    }
                }
            }
        }
        if ended {
            self.read_done.store(true, Ordering::Release);
            if !chunked && data.len() != declared {
                return Err(
                    Reply::rejected(400, "body length differs from the declared one").into(),
                );
            }
            return Ok(Taken {
                bytes: data.freeze(),
                budget,
                upload: None,
            });
        }
        let terms = Terms {
            length: self.head.content_length(),
            max: u64::try_from(limit).unwrap_or(u64::MAX),
            gap: self.ctx.cfg.body_read,
            by: self.request_by,
        };
        let held = u64::try_from(data.len()).unwrap_or(u64::MAX);
        let upload = Upload::new(
            body,
            rest,
            held,
            terms,
            self.read_done.clone(),
            self.gauge.clone(),
        );
        Ok(Taken {
            bytes: data.freeze(),
            budget,
            upload: Some(upload),
        })
    }

    /// Replaces a gzip body and its share of the byte budget by the decoded body and the share of its length. The
    /// coded body is at most `inspect_body` bytes, and the decoded one at most `max`, which is no more: the new
    /// share is taken before the old one is given back, and the two together are within what the lower bound of
    /// `max_buffered_bytes` covers. There is no await between the decoding and the taking, so a decoded body that
    /// the budget cannot hold is dropped at once.
    fn unpack(
        &self,
        coded: Bytes,
        held: OwnedSemaphorePermit,
        max: usize,
    ) -> Result<(Bytes, OwnedSemaphorePermit), Stop> {
        let plain = gunzip(&coded, max)?;
        let budget = self.take(plain.len())?;
        drop(coded);
        drop(held);
        Ok((Bytes::from(plain), budget))
    }

    /// What a failed body read means: too many bytes on the wire, the peer gone, or a body that is not valid.
    fn body_fault(&self, e: &hyper::Error) -> Stop {
        if self.gauge.over() {
            Stop::Reply(Reply::rejected(413, "body over the limit on the wire"))
        } else if peer_gone(e) {
            Stop::Close("peer closed during the body")
        } else {
            Stop::Reply(Reply::rejected(400, "malformed body"))
        }
    }

    /// The request is let through at once by a route of the generation that serves: no ticket will be sent, so the
    /// way to the driver is let go as it is after a ticket. The route is looked up before the body is read, so that
    /// a request under a route does not depend on the inspection, and a body that is longer than the bytes that
    /// are inspected is not held.
    fn bypassed(&self) -> Passed {
        drop(
            self.ingress
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take(),
        );
        Passed::Bypassed
    }

    /// Hands the request to the driver and waits for the verdict. `cut` tells that the body goes on after the
    /// bytes in `body`. `Ok` is how the request is let through (an `Allow` or a `Detected`); everything else is
    /// the answer to give.
    async fn ask(
        &self,
        headers: Vec<(Bytes, Bytes)>,
        field_bytes: usize,
        body: &Arc<BodyHold>,
        cut: bool,
    ) -> Result<Passed, Stop> {
        let permit = self
            .ctx
            .inspect
            .clone()
            .try_acquire_owned()
            .map_err(|_| Reply::failed(503, "no inspection permit"))?;
        let copy = self.take(body.bytes.len().saturating_add(field_bytes))?;
        let (reply, verdict) = oneshot::channel();
        let ticket = Ticket {
            req: InspectReq {
                client: self.client,
                server: self.local,
                method: Bytes::copy_from_slice(self.head.method()),
                uri: Bytes::copy_from_slice(self.head.target()),
                headers,
                body: body.clone(),
                cut,
                proto: self.head.proto(),
            },
            reply,
            hold: Hold::new(permit, copy),
        };
        let sender = self
            .ingress
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .ok_or_else(|| Reply::failed(503, "inspection queue closed"))?;
        match sender.try_send(Msg::Ticket(ticket)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                return Err(Reply::internal(503, "inspection queue full").into());
            }
            Err(TrySendError::Disconnected(_)) => {
                return Err(Reply::failed(503, "inspection queue closed").into());
            }
        }
        drop(sender);
        let by = stage(Instant::now(), self.ctx.cfg.inspect_wait, self.request_by);
        let Answer { outcome, by } = match timeout_at(by, verdict).await {
            Err(_) => return Err(Reply::failed(503, "inspection wait expired").into()),
            Ok(Err(_)) => return Err(Reply::failed(503, "inspection driver gone").into()),
            Ok(Ok(answer)) => answer,
        };
        *self.judged.lock().unwrap_or_else(PoisonError::into_inner) = by;
        match decide(outcome) {
            Decision::Pass(passed) => Ok(passed),
            Decision::Answer(reply) => Err(reply.into()),
        }
    }
}

/// What the failure of the exchange with the upstream means for the client. `fate` is there if the body of the request
/// was passed on while the client sent it: part of it may have gone to the upstream already, so a failure that comes
/// after the request was sent says so, unless all of the body had been handed on by then: the failure is then the
/// one of a request whose body was held.
fn upstream_stop(error: OriginError, fate: Option<&Fate>) -> Stop {
    Stop::Reply(match error {
        OriginError::Unavailable => Reply::failed(502, "upstream unavailable"),
        OriginError::Connect => Reply::failed(502, "upstream connection failed"),
        OriginError::Send | OriginError::Head if fate.is_some_and(|fate| !fate.handed()) => {
            Reply::failed(502, "upstream failed while the body was sent on")
        }
        OriginError::Send => Reply::failed(502, "upstream send failed"),
        OriginError::Head => Reply::failed(502, "upstream response head failed"),
        OriginError::Invalid => Reply::failed(502, "upstream response invalid"),
        // Not the fault of the upstream: the answers of the proxy's own limits are 503.
        OriginError::Late => Reply::failed(503, "request time used up"),
        OriginError::Local => Reply::failed(503, "local connection failure"),
        // The client's side of the body failed. Without a reason in the fate this is a fault of ours.
        OriginError::Body => match fate.and_then(Fate::cause) {
            Some(cause) => return cause_stop(cause),
            None => Reply::failed(502, "upstream send failed"),
        },
    })
}

/// The answer to a client whose body failed while it was passed on to the upstream. A chunked body that passes the
/// limit, and a client that is gone, get none: the connection is closed.
fn cause_stop(cause: Cause) -> Stop {
    match cause {
        Cause::Idle => Reply::rejected(408, "body not received in time").into(),
        Cause::Late => Reply::failed(503, "request time used up").into(),
        Cause::Over => Stop::Close("body over the limit while it was sent on"),
        Cause::Trailers => Reply::rejected(400, "request trailers not supported").into(),
        Cause::Wire => Reply::rejected(413, "body over the limit on the wire").into(),
        Cause::Gone => Stop::Close("peer closed during the body"),
        Cause::Malformed => Reply::rejected(400, "malformed body").into(),
    }
}

/// Whether the body failed because the peer went away, not because of what it sent.
pub(super) fn peer_gone(e: &hyper::Error) -> bool {
    if e.is_incomplete_message() {
        return true;
    }
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(err) = source {
        if let Some(io) = err.downcast_ref::<io::Error>()
            && matches!(
                io.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::NotConnected
                    | io::ErrorKind::TimedOut
            )
        {
            return true;
        }
        source = err.source();
    }
    false
}

#[cfg(test)]
pub(super) mod tests;
