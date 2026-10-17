//! One connection: the head check, the body, the inspection, and then the answer or the forwarding.
//!
//! The connection serves exactly one request. The head is read and checked by `head` first. The bytes read so
//! far then go back in front of the socket and hyper parses the request again; the service compares what hyper
//! saw with what the head check saw and answers 400 on any difference. The body is read through hyper into a
//! budgeted buffer, a gzip body is decoded by `represent::gunzip` (exactly one member, at most `max_body` bytes
//! of output), the request is handed to the inspection driver as a ticket, and only an `Allow` is forwarded.
//! What is inspected and what is forwarded is the same request, in the form that `represent` builds it: the
//! decoded body, without its `Content-Encoding`, with its decoded length.
//!
//! Every answer that `answer` makes, and the fixed answer that `head` holds for a refused head, has an empty
//! body, `Content-Length: 0` (not for 204 and 304) and `Connection: close`. A connection whose peer went away is
//! closed without an answer, and a response that fails after its head was sent is cut off without its terminator.
//!
//! Deadlines are absolute instants and are never extended: a stage ends at the earlier of its own start plus its
//! length and the end of the request time, counted from the accept, and the whole connection ends at the
//! connection time counted from the accept. A sum that does not fit into the clock counts as passed.

use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http::{HeaderName, Request, Response, Version};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::AsyncWrite;
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};
use tokio::time::{Instant, timeout_at};
use tukuyomi_kernel::limits;

use crate::config::ProxyConfig;
use crate::forward::origin::{self, Forward, OriginBody, OriginError};
use crate::inbound::answer::{Abort, Class, Decision, Out, Reply, Stop, answer, decide, record};
use crate::inbound::head::{self, Head, Limits, Reject, trim_ows};
use crate::inbound::io::{Gauge, Guarded};
use crate::inbound::represent::{Represented, gunzip, represent};
use crate::inspect::driver::{BodyHold, Hold, InspectReq, Msg, Ticket};
use crate::log::Log;

/// What every connection shares: the configuration, the byte budget of held bodies and of the kernel's copies,
/// and the inspection permits (as many as the kernel's waiting queue).
pub struct Ctx {
    pub cfg: ProxyConfig,
    pub budget: Arc<Semaphore>,
    pub inspect: Arc<Semaphore>,
    pub log: Log,
}

/// Numbers the connections for the records. They say nothing else.
static NEXT_CONN: AtomicU64 = AtomicU64::new(1);

/// The instants every stage of one connection is counted from or limited by.
#[derive(Clone, Copy, Debug)]
struct Times {
    accept: Instant,
    /// End of the request time: the last instant for the answer, or for the upstream's response head.
    request_by: Instant,
    /// End of the connection.
    conn_by: Instant,
}

/// `start + len`; a sum that does not fit into the clock is a deadline that has passed.
fn after(start: Instant, len: Duration) -> Instant {
    start.checked_add(len).unwrap_or(start)
}

/// The deadline of a stage that starts at `start` and lasts `len`, within the request time.
fn stage(start: Instant, len: Duration, times: &Times) -> Instant {
    after(start, len).min(times.request_by)
}

/// How the hyper connection ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    Done,
    Error,
    Limit,
}

/// What the record says once the connection has ended: an answer that was written stays as it was, a response
/// that was cut off and a connection that never answered get the reason it ended.
fn ended(mut reply: Reply, end: End) -> Reply {
    match (end, reply.class) {
        (End::Done, _) => {}
        (_, Class::Forwarded) => reply.reason = "closed while the response was sent",
        (End::Error, Class::Closed) => reply.reason = "connection error",
        (End::Limit, Class::Closed) => reply.reason = "connection time limit",
        _ => {}
    }
    reply
}

/// Serves one accepted connection to its end.
pub async fn serve(
    sock: TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
    ctx: Arc<Ctx>,
    ingress: SyncSender<Msg>,
) {
    let accept = Instant::now();
    let id = NEXT_CONN.fetch_add(1, Ordering::Relaxed);
    let times = Times {
        accept,
        request_by: after(accept, ctx.cfg.request_total),
        conn_by: after(accept, ctx.cfg.conn_total),
    };
    let reply = run(sock, peer, local, &ctx, ingress, times).await;
    if reply.internal {
        ctx.log
            .line(&format!("conn {id}: internal fault: {}", reply.reason));
    }
    ctx.log.line(&record(id, &reply, accept.elapsed()));
}

/// Checks the head, then lets hyper serve the one request. Returns what happened for the record.
async fn run(
    mut sock: TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
    ctx: &Arc<Ctx>,
    ingress: SyncSender<Msg>,
    times: Times,
) -> Reply {
    let cfg = &ctx.cfg;
    let lim = Limits {
        max_head_bytes: cfg.max_head_bytes,
        max_body: u64::try_from(cfg.max_body).unwrap_or(u64::MAX),
    };
    let head_by = after(times.accept, cfg.head_read).min(times.request_by);
    let (head, rest) = match head::read(&mut sock, &lim, head_by).await {
        Ok(read) => read,
        Err(reject) => return refuse(&mut sock, reject, cfg.response_idle, times).await,
    };
    // The bytes after the head count against the limit of the wire like every later byte. The ones that are
    // already here are given back in front of the socket, so the cap for what is still to come is what is left.
    let room = u64::try_from(cfg.max_body_wire)
        .ok()
        .and_then(|wire| wire.checked_sub(u64::try_from(rest.len()).unwrap_or(u64::MAX)));
    let Some(room) = room else {
        return refuse(&mut sock, Reject::ContentTooLarge, cfg.response_idle, times).await;
    };
    // A read that waits is bounded by the connection time alone: while the request is inspected or the response
    // is sent, hyper may wait for the peer for as long as the connection lives. The body stage has its own limit.
    let (guarded, gauge) = Guarded::new(
        sock,
        head.buf.clone(),
        cfg.conn_total,
        cfg.response_idle,
        room,
    );
    let conn = Arc::new(Conn {
        ctx: ctx.clone(),
        head,
        peer,
        local,
        gauge,
        times,
        head_end: Instant::now(),
        ingress: Mutex::new(Some(ingress)),
        reply: Mutex::new(Reply::NONE),
    });
    let service = {
        let conn = conn.clone();
        service_fn(move |req: Request<Incoming>| {
            let conn = conn.clone();
            async move { conn.handle(req).await }
        })
    };
    let mut server = http1::Builder::new();
    server
        .keep_alive(false)
        .half_close(false)
        .timer(TokioTimer::new())
        .header_read_timeout(None)
        .max_headers(limits::HEADERS)
        .max_header_size(cfg.max_head_bytes)
        .max_buf_size(cfg.max_head_bytes.max(8192))
        .title_case_headers(true);
    let end = match timeout_at(
        times.conn_by,
        server.serve_connection(TokioIo::new(guarded), service),
    )
    .await
    {
        Ok(Ok(())) => End::Done,
        Ok(Err(_)) => End::Error,
        Err(_) => End::Limit,
    };
    let reply = *conn.reply.lock().unwrap_or_else(PoisonError::into_inner);
    ended(reply, end)
}

/// Writes the fixed answer of a refused head and closes. The write is bounded by `idle` and by the connection
/// time.
async fn refuse(sock: &mut TcpStream, reject: Reject, idle: Duration, times: Times) -> Reply {
    if let Some(answer) = reject.response() {
        let by = after(Instant::now(), idle).min(times.conn_by);
        let _ = timeout_at(by, send_and_close(sock, answer)).await;
        Reply::of(reject)
    } else {
        Reply {
            reason: reject.reason(),
            ..Reply::NONE
        }
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
    let _ = poll_fn(|cx| Pin::new(&mut *sock).poll_shutdown(cx)).await;
}

/// The state of one connection that its service reads.
struct Conn {
    ctx: Arc<Ctx>,
    head: Head,
    peer: SocketAddr,
    local: SocketAddr,
    gauge: Gauge,
    times: Times,
    /// When the head was complete: the body stage counts from here.
    head_end: Instant,
    /// The way to the driver, taken for the one ticket and dropped as soon as it is sent. Holding it for the
    /// life of a streaming response would keep the driver from seeing that no sender is left.
    ingress: Mutex<Option<SyncSender<Msg>>>,
    reply: Mutex<Reply>,
}

impl Conn {
    /// The service: one request per connection.
    async fn handle(&self, req: Request<Incoming>) -> Result<Response<Out>, Abort> {
        let (reply, response) = match self.exchange(req).await {
            Ok(response) => {
                let reply = Reply {
                    status: response.status().as_u16(),
                    class: Class::Forwarded,
                    reason: "forwarded",
                    rule: None,
                    internal: false,
                };
                (reply, Ok(response.map(|body| Out::Origin(Box::pin(body)))))
            }
            Err(Stop::Reply(reply)) => (reply, Ok(answer(reply.status))),
            Err(Stop::Close(reason)) => (
                Reply {
                    reason,
                    ..Reply::NONE
                },
                Err(Abort),
            ),
        };
        *self.reply.lock().unwrap_or_else(PoisonError::into_inner) = reply;
        response
    }

    /// Everything up to the response of the upstream.
    async fn exchange(&self, req: Request<Incoming>) -> Result<Response<OriginBody>, Stop> {
        let (parts, body) = req.into_parts();
        if !same_head(&self.head, &parts) {
            return Err(Reply::rejected(400, "the two parsers disagree").into());
        }
        let (bytes, budget) = self.read_body(body).await?;
        let (bytes, budget) = if self.head.gzip() {
            self.unpack(bytes, budget)?
        } else {
            (bytes, budget)
        };
        let Represented {
            fields,
            headers,
            field_bytes,
        } = represent(&self.head, bytes.len())?;
        // The head check cannot tell whether a chunked body is empty, so its rule on the body type is applied
        // here, with the same test (on the decoded body, when it was gzip).
        if self.head.chunked() && !bytes.is_empty() && !self.head.inspectable_type() {
            return Err(Reject::UnsupportedMedia.into());
        }
        let body = Arc::new(BodyHold::new(bytes, budget));
        self.ask(headers, field_bytes, &body).await?;
        if Instant::now() >= self.times.request_by {
            return Err(Reply::failed(503, "request time used up").into());
        }
        let forward = Forward {
            method: parts.method,
            uri: parts.uri,
            fields,
            body,
            peer: self.peer,
        };
        origin::forward(forward, &self.ctx, self.times.request_by)
            .await
            .map_err(|e| {
                Reply::failed(
                    502,
                    match e {
                        OriginError::Connect => "upstream connection failed",
                        OriginError::Send => "upstream send failed",
                        OriginError::Head => "upstream response head failed",
                        OriginError::Invalid => "upstream response invalid",
                    },
                )
                .into()
            })
    }

    /// Takes `n` bytes of the budget.
    fn take(&self, n: usize) -> Result<OwnedSemaphorePermit, Stop> {
        u32::try_from(n)
            .ok()
            .and_then(|n| self.ctx.budget.clone().try_acquire_many_owned(n).ok())
            .ok_or_else(|| Reply::failed(503, "byte budget exhausted").into())
    }

    /// Reads the whole decoded body. The budget of a body with a length is taken before the first byte is read
    /// (so no `100 Continue` is sent for a body that cannot be held), the budget of a chunked body frame by frame.
    async fn read_body(&self, mut body: Incoming) -> Result<(Bytes, OwnedSemaphorePermit), Stop> {
        let max = self.ctx.cfg.max_body;
        let chunked = self.head.chunked();
        let declared = match self.head.content_length() {
            Some(n) => usize::try_from(n).map_err(|_| Reject::ContentTooLarge)?,
            None => 0,
        };
        if !chunked && declared == 0 {
            return Ok((Bytes::new(), self.take(0)?));
        }
        if declared > max {
            return Err(Reject::ContentTooLarge.into());
        }
        let mut budget = self.take(declared)?;
        let mut data = BytesMut::with_capacity(declared);
        let by = stage(self.head_end, self.ctx.cfg.body_read, &self.times);
        loop {
            let frame = match timeout_at(by, body.frame()).await {
                Err(_) => return Err(Reply::rejected(408, "body not received in time").into()),
                Ok(None) => break,
                Ok(Some(Err(e))) => return Err(self.body_fault(&e)),
                Ok(Some(Ok(frame))) => frame,
            };
            match frame.into_data() {
                Ok(chunk) => {
                    if data
                        .len()
                        .checked_add(chunk.len())
                        .is_none_or(|total| total > max)
                    {
                        return Err(Reply::rejected(413, "body over the limit").into());
                    }
                    if chunked {
                        budget.merge(self.take(chunk.len())?);
                    }
                    data.extend_from_slice(&chunk);
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
        if !chunked && data.len() != declared {
            return Err(Reply::rejected(400, "body length differs from the declared one").into());
        }
        Ok((data.freeze(), budget))
    }

    /// Replaces a gzip body and its share of the byte budget by the decoded body and the share of its length.
    /// The new share is taken before the old one is given back, so both are held at once: at most twice
    /// `max_body`, which the lower bound of `max_buffered_bytes` covers. There is no await between the decoding
    /// and the taking, so a decoded body that the budget cannot hold is dropped at once.
    fn unpack(
        &self,
        coded: Bytes,
        held: OwnedSemaphorePermit,
    ) -> Result<(Bytes, OwnedSemaphorePermit), Stop> {
        // An empty chunked body is not a gzip stream (a body with a length of 0 is refused by the head check).
        if coded.is_empty() {
            return Err(Reply::rejected(400, "empty gzip body").into());
        }
        let plain = gunzip(&coded, self.ctx.cfg.max_body)?;
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

    /// Hands the request to the driver and waits for the verdict. `Ok` is an `Allow`; everything else is the
    /// answer to give.
    async fn ask(
        &self,
        headers: Vec<(Bytes, Bytes)>,
        field_bytes: usize,
        body: &Arc<BodyHold>,
    ) -> Result<(), Stop> {
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
                client: self.peer,
                server: self.local,
                method: Bytes::copy_from_slice(self.head.method()),
                uri: Bytes::copy_from_slice(self.head.target()),
                headers,
                body: body.clone(),
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
        let by = stage(Instant::now(), self.ctx.cfg.inspect_wait, &self.times);
        let outcome = match timeout_at(by, verdict).await {
            Err(_) => return Err(Reply::failed(503, "inspection wait expired").into()),
            Ok(Err(_)) => return Err(Reply::failed(503, "inspection driver gone").into()),
            Ok(Ok(outcome)) => outcome,
        };
        match decide(outcome) {
            Decision::Allow => Ok(()),
            Decision::Answer(reply) => Err(reply.into()),
        }
    }
}

/// Whether the body failed because the peer went away, not because of what it sent.
fn peer_gone(e: &hyper::Error) -> bool {
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

/// Whether hyper saw the same request as the head check: method, target, version, the number of fields and the
/// values of every name, in order and without the blanks around them.
fn same_head(head: &Head, parts: &http::request::Parts) -> bool {
    parts.method.as_str().as_bytes() == head.method()
        && parts.version == Version::HTTP_11
        && parts.uri.scheme().is_none()
        && parts.uri.authority().is_none()
        && parts
            .uri
            .path_and_query()
            .is_some_and(|target| target.as_str().as_bytes() == head.target())
        && parts.headers.len() == head.fields().len()
        && head.fields().all(|(name, _)| {
            let Ok(name) = HeaderName::from_bytes(name) else {
                return false;
            };
            let mine = head
                .fields()
                .filter(|(other, _)| other.eq_ignore_ascii_case(name.as_str().as_bytes()))
                .map(|(_, value)| value);
            let theirs = parts
                .headers
                .get_all(&name)
                .iter()
                .map(|value| trim_ows(value.as_bytes()));
            mine.eq(theirs)
        })
}

#[cfg(test)]
pub(super) mod tests;
