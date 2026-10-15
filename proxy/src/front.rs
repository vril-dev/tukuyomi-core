//! One connection: the head check, the body, the inspection, and then the answer or the forwarding.
//!
//! The connection serves exactly one request. The head is read and checked by `head` first. The bytes read so
//! far then go back in front of the socket and hyper parses the request again; the service compares what hyper
//! saw with what the head check saw and answers 400 on any difference. The body is read through hyper into a
//! budgeted buffer, the request is handed to the inspection driver as a ticket, and only an `Allow` is forwarded.
//!
//! Every answer that is made here has an empty body, `Content-Length: 0` (not for 204 and 304) and
//! `Connection: close`. A connection whose peer went away is closed without an answer, and a response that fails
//! after its head was sent is cut off without its terminator.
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
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http::header::{CONNECTION, CONTENT_LENGTH, HOST, TRANSFER_ENCODING};
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Version};
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::AsyncWrite;
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};
use tokio::time::{Instant, timeout_at};
use tukuyomi_kernel::{Reason, Refused, Verdict, limits};

use crate::config::ProxyConfig;
use crate::driver::{BodyHold, Hold, InspectReq, Msg, Outcome, Ticket};
use crate::head::{self, Head, Limits, Reject, trim_ows};
use crate::io::{Gauge, Guarded};
use crate::log::Log;
use crate::origin::{self, Forward, OriginBody, OriginError};

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

/// How a connection ended, for the record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    /// The request was allowed and the response head was sent.
    Forwarded,
    /// An inspection rule blocked the request.
    Blocked,
    /// The request was refused as malformed, too large or not supported.
    Rejected,
    /// The request was not served for a reason on our side: busy, unavailable, an upstream failure.
    Failed,
    /// No answer was written.
    Closed,
}

impl Class {
    fn name(self) -> &'static str {
        match self {
            Class::Forwarded => "forwarded",
            Class::Blocked => "blocked",
            Class::Rejected => "rejected",
            Class::Failed => "failed",
            Class::Closed => "closed",
        }
    }
}

/// An answer, or the lack of one, as the record shows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Reply {
    status: u16,
    class: Class,
    /// A fixed text; never a value from the request.
    reason: &'static str,
    rule: Option<i64>,
    /// The answer points at a fault in this program and also gets a line of its own in the record.
    internal: bool,
}

impl Reply {
    /// Nothing was answered.
    const NONE: Reply = Reply {
        status: 0,
        class: Class::Closed,
        reason: "no answer",
        rule: None,
        internal: false,
    };

    fn rejected(status: u16, reason: &'static str) -> Reply {
        Reply {
            status,
            class: Class::Rejected,
            reason,
            rule: None,
            internal: false,
        }
    }

    fn failed(status: u16, reason: &'static str) -> Reply {
        Reply {
            status,
            class: Class::Failed,
            reason,
            rule: None,
            internal: false,
        }
    }

    fn internal(status: u16, reason: &'static str) -> Reply {
        Reply {
            internal: true,
            ..Reply::failed(status, reason)
        }
    }

    /// The answer of a head refusal that has one.
    fn of(reject: Reject) -> Reply {
        Reply::rejected(reject.status().unwrap_or(400), reject.reason())
    }
}

/// Why the exchange ends without a response to forward.
enum Stop {
    Reply(Reply),
    /// Close the connection without an answer; the text is for the record.
    Close(&'static str),
}

impl From<Reply> for Stop {
    fn from(reply: Reply) -> Stop {
        Stop::Reply(reply)
    }
}

impl From<Reject> for Stop {
    fn from(reject: Reject) -> Stop {
        match reject.status() {
            Some(_) => Stop::Reply(Reply::of(reject)),
            None => Stop::Close(reject.reason()),
        }
    }
}

/// The service error that makes hyper drop the connection without writing anything.
#[derive(Debug)]
struct Abort;

impl std::fmt::Display for Abort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("connection closed without an answer")
    }
}

impl std::error::Error for Abort {}

/// The response body: empty for our own answers, the upstream's for a forwarded request.
enum Out {
    Empty,
    Origin(Pin<Box<OriginBody>>),
}

impl Body for Out {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        match self.get_mut() {
            Out::Empty => Poll::Ready(None),
            Out::Origin(body) => body.as_mut().poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Out::Empty => true,
            Out::Origin(body) => body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Out::Empty => SizeHint::with_exact(0),
            Out::Origin(body) => body.size_hint(),
        }
    }
}

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

/// The one record line of a connection: its number, class, status, reason, rule id and the time it took. Only
/// numbers and fixed texts, so nothing the peer sent can get in.
fn record(id: u64, reply: &Reply, elapsed: Duration) -> String {
    let rule = reply
        .rule
        .map_or_else(|| "-".to_string(), |rule| rule.to_string());
    format!(
        "conn {id}: {} {} {} rule {rule} {} ms",
        reply.class.name(),
        reply.status,
        reply.reason,
        elapsed.as_millis()
    )
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
        let Represented {
            fields,
            headers,
            field_bytes,
        } = represent(&self.head, bytes.len())?;
        // The head check cannot tell whether a chunked body is empty, so its rule on the body type is applied
        // here, with the same test.
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

/// The request as it is inspected and, unchanged, forwarded.
struct Represented {
    /// The fields in the order received; this is the one map the forwarding is made from.
    fields: HeaderMap,
    /// What the inspection gets: `Host` first, then the others in the order received.
    headers: Vec<(Bytes, Bytes)>,
    /// Bytes of all names and values of `headers`.
    field_bytes: usize,
}

/// A field name the way hyper writes it: the first letter and each letter after a hyphen in upper case.
fn title_case(name: &str) -> Bytes {
    let mut out = Vec::with_capacity(name.len());
    let mut upper = true;
    for &b in name.as_bytes() {
        out.push(if upper {
            b.to_ascii_uppercase()
        } else {
            b.to_ascii_lowercase()
        });
        upper = b == b'-';
    }
    Bytes::from(out)
}

/// Builds the inspected and forwarded form of the request, whose body is `body_len` bytes once decoded. The one
/// change to the framing: a chunked request loses its `Transfer-Encoding` and gets a `Content-Length` of the
/// decoded length; a POST, PUT or PATCH with neither gets `Content-Length: 0`. The limits of the kernel are
/// checked on the result, so a request that fit before the change and not after it is refused here and never
/// reaches the kernel.
fn represent(head: &Head, body_len: usize) -> Result<Represented, Reject> {
    let mut fields = HeaderMap::with_capacity(head.fields().len() + 1);
    let mut host = None;
    let mut others = Vec::with_capacity(head.fields().len() + 1);
    for (name, value) in head.fields() {
        let name = HeaderName::from_bytes(name).map_err(|_| Reject::BadRequest)?;
        if head.chunked() && name == TRANSFER_ENCODING {
            continue;
        }
        let entry = (title_case(name.as_str()), Bytes::copy_from_slice(value));
        fields.append(
            name.clone(),
            HeaderValue::from_bytes(value).map_err(|_| Reject::BadRequest)?,
        );
        if name == HOST {
            host = Some(entry);
        } else {
            others.push(entry);
        }
    }
    let length = if head.chunked() {
        Some(body_len)
    } else if head.content_length().is_none()
        && matches!(head.method(), b"POST" | b"PUT" | b"PATCH")
    {
        Some(0)
    } else {
        None
    };
    if let Some(length) = length {
        let value = HeaderValue::from(u64::try_from(length).map_err(|_| Reject::FieldsTooLarge)?);
        others.push((
            title_case(CONTENT_LENGTH.as_str()),
            Bytes::copy_from_slice(value.as_bytes()),
        ));
        fields.append(CONTENT_LENGTH, value);
    }
    let mut headers = Vec::with_capacity(others.len() + 1);
    headers.extend(host);
    headers.extend(others);
    let mut field_bytes = 0usize;
    for (name, value) in &headers {
        if name.len() > limits::HEADER_NAME || value.len() > limits::HEADER_VALUE {
            return Err(Reject::FieldsTooLarge);
        }
        field_bytes = field_bytes
            .checked_add(name.len())
            .and_then(|sum| sum.checked_add(value.len()))
            .filter(|&sum| sum <= limits::HEADER_TOTAL)
            .ok_or(Reject::FieldsTooLarge)?;
    }
    if headers.len() > limits::HEADERS {
        return Err(Reject::FieldsTooLarge);
    }
    Ok(Represented {
        fields,
        headers,
        field_bytes,
    })
}

/// What the verdict of the driver means for the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Decision {
    Allow,
    Answer(Reply),
}

/// The answer table. Only `Allow` goes on to the upstream.
fn decide(outcome: Outcome) -> Decision {
    match outcome {
        Outcome::Verdict(Verdict::Allow) => Decision::Allow,
        Outcome::Verdict(Verdict::Block {
            rule_id, status, ..
        }) => Decision::Answer(match status {
            200..=599 => Reply {
                status,
                class: Class::Blocked,
                reason: "blocked by a rule",
                rule: Some(rule_id),
                internal: false,
            },
            _ => Reply {
                rule: Some(rule_id),
                ..Reply::internal(500, "block status out of range")
            },
        }),
        Outcome::Verdict(Verdict::Uninspectable(reason)) => Decision::Answer(match reason {
            Reason::Invalid => Reply::internal(500, "inspection request invalid"),
            Reason::Cancelled => Reply::internal(500, "inspection cancelled"),
            Reason::QueueFull => Reply::failed(503, "inspection queue full"),
            Reason::Unavailable => Reply::failed(503, "inspector unavailable"),
            Reason::WaitDeadline => Reply::failed(503, "inspection wait deadline"),
            Reason::VerdictDeadline => Reply::failed(503, "inspection verdict deadline"),
            Reason::InspectorLost => Reply::failed(503, "inspector lost"),
            Reason::Protocol => Reply::failed(503, "inspector protocol error"),
            Reason::InspectorError { .. } => Reply::failed(503, "inspector error"),
            Reason::NotCreated { .. } => Reply::failed(503, "transaction not created"),
        }),
        Outcome::Refused(refused) => Decision::Answer(match refused {
            Refused::Invalid(why) | Refused::Unsupported(why) => Reply::internal(500, why),
            Refused::Full => Reply::failed(503, "kernel full"),
            Refused::IdsExhausted => Reply::failed(503, "kernel ids exhausted"),
        }),
        Outcome::Unavailable => Decision::Answer(Reply::failed(503, "inspection unavailable")),
    }
}

/// An answer with an empty body. 204 and 304 carry no `Content-Length`.
fn answer(status: u16) -> Response<Out> {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut response = Response::new(Out::Empty);
    *response.status_mut() = status;
    let headers = response.headers_mut();
    if status != StatusCode::NO_CONTENT && status != StatusCode::NOT_MODIFIED {
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("0"));
    }
    headers.insert(CONNECTION, HeaderValue::from_static("close"));
    response
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::{Receiver, sync_channel};
    use std::thread::{self, JoinHandle};

    use tokio::net::TcpListener;
    use tokio::runtime::{Builder, Runtime};
    use tokio::task::JoinHandle as Served;
    use tokio::time::{sleep, timeout};

    use super::*;
    use crate::log::start_logger;

    const FORM: &str = "application/x-www-form-urlencoded";
    const LIM: Limits = Limits {
        max_head_bytes: 32 * 1024,
        max_body: 1 << 20,
    };
    const BUDGET: usize = 1 << 20;
    const PERMITS: usize = 4;

    fn head_of(raw: &str) -> Head {
        head::parse(raw.as_bytes(), &LIM)
            .expect("accepted")
            .expect("complete")
    }

    fn represented(raw: &str, body_len: usize) -> Represented {
        represent(&head_of(raw), body_len).expect("represented")
    }

    fn pairs(rep: &Represented) -> Vec<(String, String)> {
        rep.headers
            .iter()
            .map(|(name, value)| {
                (
                    String::from_utf8_lossy(name).into_owned(),
                    String::from_utf8_lossy(value).into_owned(),
                )
            })
            .collect()
    }

    fn pair(name: &str, value: &str) -> (String, String) {
        (name.to_string(), value.to_string())
    }

    #[test]
    fn a_chunked_request_loses_its_encoding_and_gets_the_decoded_length() {
        let raw = format!(
            "POST /x HTTP/1.1\r\nContent-Type: {FORM}\r\nHost: h\r\nTransfer-Encoding: chunked\r\nx-forwarded-for: 1.2.3.4\r\n\r\n"
        );
        let rep = represented(&raw, 3);
        assert_eq!(
            pairs(&rep),
            [
                pair("Host", "h"),
                pair("Content-Type", FORM),
                pair("X-Forwarded-For", "1.2.3.4"),
                pair("Content-Length", "3"),
            ]
        );
        assert!(rep.fields.get(TRANSFER_ENCODING).is_none());
        assert_eq!(rep.fields.get_all(CONTENT_LENGTH).iter().count(), 1);
        assert_eq!(rep.fields.get(CONTENT_LENGTH).unwrap(), "3");
        assert_eq!(rep.fields.get(HOST).unwrap(), "h");
        assert_eq!(rep.fields.len(), 4);
        // An empty chunked body is a length of 0 as well.
        let rep = represented(
            "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n",
            0,
        );
        assert_eq!(
            pairs(&rep),
            [pair("Host", "h"), pair("Content-Length", "0")]
        );
    }

    #[test]
    fn a_post_put_or_patch_without_a_length_gets_content_length_0() {
        for method in ["POST", "PUT", "PATCH"] {
            let rep = represented(&format!("{method} / HTTP/1.1\r\nHost: h\r\n\r\n"), 0);
            assert_eq!(
                pairs(&rep),
                [pair("Host", "h"), pair("Content-Length", "0")],
                "{method}"
            );
            assert_eq!(rep.fields.get(CONTENT_LENGTH).unwrap(), "0");
        }
        for method in ["GET", "HEAD", "DELETE", "OPTIONS", "post"] {
            let rep = represented(&format!("{method} / HTTP/1.1\r\nHost: h\r\n\r\n"), 0);
            assert_eq!(pairs(&rep), [pair("Host", "h")], "{method}");
            assert!(rep.fields.get(CONTENT_LENGTH).is_none());
        }
        // A request that already has a length keeps its own and gets no second one.
        let rep = represented("POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n", 0);
        assert_eq!(
            pairs(&rep),
            [pair("Host", "h"), pair("Content-Length", "0")]
        );
        assert_eq!(rep.fields.get_all(CONTENT_LENGTH).iter().count(), 1);
    }

    #[test]
    fn names_are_title_case_and_values_stay_as_received() {
        let rep = represented(
            "GET / HTTP/1.1\r\nhost: h\r\nx-a-b: a\tb\r\nACCEPT-ENCODING: gzip\r\nx: 1\r\nA.b_c-d: \tv \r\n\r\n",
            0,
        );
        assert_eq!(
            pairs(&rep),
            [
                pair("Host", "h"),
                pair("X-A-B", "a\tb"),
                pair("Accept-Encoding", "gzip"),
                pair("X", "1"),
                pair("A.b_c-D", "v"),
            ]
        );
        assert_eq!(&title_case("content-length")[..], b"Content-Length");
        assert_eq!(&title_case("-x--y")[..], b"-X--Y");
        assert_eq!(&title_case("")[..], b"");
    }

    #[test]
    fn host_comes_first_and_the_others_keep_the_order_received() {
        let rep = represented(
            "GET / HTTP/1.1\r\na: 1\r\nHost: h\r\nb: 2\r\nA: 3\r\n\r\n",
            0,
        );
        assert_eq!(
            pairs(&rep),
            [
                pair("Host", "h"),
                pair("A", "1"),
                pair("B", "2"),
                pair("A", "3")
            ]
        );
        // The map holds the same fields; the values of one name keep their order.
        let a: Vec<&str> = rep
            .fields
            .get_all("a")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(a, ["1", "3"]);
        assert_eq!(rep.fields.len(), 4);
        assert_eq!(rep.field_bytes, "Host".len() + 1 + 2 * (1 + 1) + 1 + 1);
    }

    fn numbered(count: usize, method: &str) -> String {
        let mut raw = format!("{method} / HTTP/1.1\r\nHost: h\r\n");
        for n in 1..count {
            raw.push_str(&format!("X-{n}: v\r\n"));
        }
        raw.push_str("\r\n");
        raw
    }

    #[test]
    fn a_64_field_request_that_gets_content_length_0_is_65_fields_and_refused() {
        let head = head_of(&numbered(64, "POST"));
        assert_eq!(head.fields().len(), 64);
        assert_eq!(represent(&head, 0).err(), Some(Reject::FieldsTooLarge));
        // The same head with a method that gets nothing added, and 63 fields plus the added one, pass.
        assert_eq!(
            represent(&head_of(&numbered(64, "GET")), 0)
                .unwrap()
                .headers
                .len(),
            64
        );
        let rep = represent(&head_of(&numbered(63, "POST")), 0).unwrap();
        assert_eq!(rep.headers.len(), 64);
        assert_eq!(rep.fields.len(), 64);
        // A chunked request swaps one field for another, so 64 stay 64.
        let mut raw = numbered(63, "POST");
        raw.truncate(raw.len() - 2);
        raw.push_str("Transfer-Encoding: chunked\r\n\r\n");
        let head = head_of(&raw);
        assert_eq!(head.fields().len(), 64);
        assert_eq!(represent(&head, 123_456).unwrap().headers.len(), 64);
    }

    #[test]
    fn the_size_limits_are_checked_after_the_framing_is_added() {
        // The total of names and values is 24576 with the added `Content-Length: 0` (14 + 1 bytes), or 24577.
        let with_last = |last: usize| {
            let mut raw = String::from("POST / HTTP/1.1\r\nHost: example.test\r\n");
            for n in 1..=5 {
                raw.push_str(&format!("F00{n}: {}\r\n", "a".repeat(4096)));
            }
            raw.push_str(&format!("F006: {}\r\n\r\n", "a".repeat(last)));
            raw
        };
        let rep = represent(&head_of(&with_last(4041)), 0).unwrap();
        assert_eq!(rep.field_bytes, limits::HEADER_TOTAL);
        assert_eq!(rep.headers.len(), 8);
        assert_eq!(
            represent(&head_of(&with_last(4042)), 0).err(),
            Some(Reject::FieldsTooLarge)
        );
        // The head itself was within the limits; only the added field is over.
        assert!(
            head::parse(with_last(4042).as_bytes(), &LIM)
                .unwrap()
                .is_some()
        );
    }

    fn parts(request: Request<()>) -> http::request::Parts {
        request.into_parts().0
    }

    #[test]
    fn hyper_and_the_head_check_must_see_the_same_request() {
        let head =
            head_of("POST /a?b=%41 HTTP/1.1\r\nHost: h\r\nX-A: 1\r\nx-a: 2 \r\nX-B:\tv\r\n\r\n");
        let base = || {
            Request::builder()
                .method("POST")
                .uri("/a?b=%41")
                .version(Version::HTTP_11)
                .header("host", "h")
                .header("x-a", "1")
                .header("x-a", "2")
                .header("x-b", "v")
        };
        assert!(same_head(&head, &parts(base().body(()).unwrap())));
        // A value with blanks around it is the same value; the trim is the same on both sides.
        assert!(same_head(
            &head,
            &parts(
                Request::builder()
                    .method("POST")
                    .uri("/a?b=%41")
                    .header("host", " h")
                    .header("x-a", "1")
                    .header("x-a", " 2 \t")
                    .header("x-b", "v")
                    .body(())
                    .unwrap()
            )
        ));
        let different = [
            base().method("PUT").body(()).unwrap(),
            base().method("post").body(()).unwrap(),
            base().uri("/a?b=%42").body(()).unwrap(),
            base().uri("/a").body(()).unwrap(),
            base().uri("http://h/a?b=%41").body(()).unwrap(),
            base().version(Version::HTTP_10).body(()).unwrap(),
            base().header("x-c", "3").body(()).unwrap(),
            Request::builder()
                .method("POST")
                .uri("/a?b=%41")
                .header("host", "h")
                .header("x-a", "1")
                .header("x-a", "2")
                .body(())
                .unwrap(),
            // The same fields with the values of one name swapped, or changed.
            Request::builder()
                .method("POST")
                .uri("/a?b=%41")
                .header("host", "h")
                .header("x-a", "2")
                .header("x-a", "1")
                .header("x-b", "v")
                .body(())
                .unwrap(),
            Request::builder()
                .method("POST")
                .uri("/a?b=%41")
                .header("host", "h")
                .header("x-a", "1")
                .header("x-a", "2")
                .header("x-b", "w")
                .body(())
                .unwrap(),
            // One field counted twice and another missing: the count is right and the names are not.
            Request::builder()
                .method("POST")
                .uri("/a?b=%41")
                .header("host", "h")
                .header("x-a", "1")
                .header("x-a", "2")
                .header("x-c", "v")
                .body(())
                .unwrap(),
        ];
        for (n, request) in different.into_iter().enumerate() {
            assert!(!same_head(&head, &parts(request)), "case {n}");
        }
    }

    #[test]
    fn the_answer_table() {
        use Reason::*;
        let answer = |outcome| match decide(outcome) {
            Decision::Answer(reply) => reply,
            Decision::Allow => panic!("not an answer"),
        };
        assert_eq!(decide(Outcome::Verdict(Verdict::Allow)), Decision::Allow);
        let block = |status| {
            Outcome::Verdict(Verdict::Block {
                phase: 1,
                rule_id: 9201,
                status,
            })
        };
        for status in [200, 204, 302, 304, 403, 418, 503, 599] {
            let reply = answer(block(status));
            assert_eq!(
                (reply.status, reply.class, reply.rule, reply.internal),
                (status, Class::Blocked, Some(9201), false)
            );
        }
        for status in [0, 1, 99, 100, 199, 600, 999, 1000, u16::MAX] {
            let reply = answer(block(status));
            assert_eq!(
                (reply.status, reply.class, reply.rule, reply.internal),
                (500, Class::Failed, Some(9201), true),
                "{status}"
            );
        }
        let uninspectable = |reason| answer(Outcome::Verdict(Verdict::Uninspectable(reason)));
        for reason in [Invalid, Cancelled] {
            let reply = uninspectable(reason);
            assert_eq!((reply.status, reply.internal), (500, true), "{reason:?}");
        }
        let others = [
            QueueFull,
            Reason::Unavailable,
            WaitDeadline,
            VerdictDeadline,
            InspectorLost,
            Protocol,
            InspectorError { code: 7 },
            NotCreated { code: 8 },
        ];
        for reason in others {
            let reply = uninspectable(reason);
            assert_eq!(
                (reply.status, reply.class, reply.internal),
                (503, Class::Failed, false),
                "{reason:?}"
            );
        }
        for refused in [
            Refused::Invalid("header count out of range"),
            Refused::Unsupported("content-type"),
        ] {
            let reply = answer(Outcome::Refused(refused));
            assert_eq!((reply.status, reply.internal), (500, true), "{refused:?}");
        }
        assert_eq!(
            answer(Outcome::Refused(Refused::Invalid(
                "header count out of range"
            )))
            .reason,
            "header count out of range"
        );
        for refused in [Refused::Full, Refused::IdsExhausted] {
            let reply = answer(Outcome::Refused(refused));
            assert_eq!(
                (reply.status, reply.class, reply.internal),
                (503, Class::Failed, false),
                "{refused:?}"
            );
        }
        let reply = answer(Outcome::Unavailable);
        assert_eq!((reply.status, reply.internal), (503, false));
    }

    #[test]
    fn an_answer_is_empty_with_a_length_of_0_and_close() {
        for status in [200, 400, 403, 413, 500, 503, 599] {
            let response = answer(status);
            assert_eq!(response.status().as_u16(), status);
            assert_eq!(response.headers().get(CONTENT_LENGTH).unwrap(), "0");
            assert_eq!(response.headers().get(CONNECTION).unwrap(), "close");
            assert_eq!(response.headers().len(), 2);
            assert!(response.body().is_end_stream());
            assert_eq!(response.body().size_hint().exact(), Some(0));
        }
        for status in [204, 304] {
            let response = answer(status);
            assert!(response.headers().get(CONTENT_LENGTH).is_none());
            assert_eq!(response.headers().get(CONNECTION).unwrap(), "close");
        }
    }

    #[test]
    fn the_record_has_numbers_and_fixed_texts_only() {
        let blocked = Reply {
            status: 403,
            class: Class::Blocked,
            reason: "blocked by a rule",
            rule: Some(9201),
            internal: false,
        };
        assert_eq!(
            record(7, &blocked, Duration::from_millis(12)),
            "conn 7: blocked 403 blocked by a rule rule 9201 12 ms"
        );
        assert_eq!(
            record(8, &Reply::NONE, Duration::from_micros(1999)),
            "conn 8: closed 0 no answer rule - 1 ms"
        );
        let negative = Reply {
            rule: Some(-1),
            ..blocked
        };
        assert!(record(1, &negative, Duration::ZERO).contains("rule -1 0 ms"));
    }

    #[test]
    fn what_the_record_says_when_the_connection_has_ended() {
        let sent = Reply {
            status: 200,
            class: Class::Forwarded,
            reason: "forwarded",
            rule: None,
            internal: false,
        };
        assert_eq!(ended(sent, End::Done), sent);
        assert_eq!(
            ended(sent, End::Error).reason,
            "closed while the response was sent"
        );
        assert_eq!(
            ended(sent, End::Limit).reason,
            "closed while the response was sent"
        );
        assert_eq!(ended(sent, End::Limit).status, 200);
        assert_eq!(ended(Reply::NONE, End::Done), Reply::NONE);
        assert_eq!(ended(Reply::NONE, End::Error).reason, "connection error");
        assert_eq!(
            ended(Reply::NONE, End::Limit).reason,
            "connection time limit"
        );
        let refused = Reply::rejected(400, "malformed body");
        assert_eq!(ended(refused, End::Error), refused);
        assert_eq!(ended(refused, End::Limit), refused);
    }

    #[test]
    fn a_stage_ends_at_the_earlier_of_its_own_end_and_the_request_time() {
        let start = Instant::now();
        let times = Times {
            accept: start,
            request_by: start + Duration::from_secs(10),
            conn_by: start + Duration::from_secs(20),
        };
        assert_eq!(
            stage(start, Duration::from_secs(3), &times),
            start + Duration::from_secs(3)
        );
        assert_eq!(
            stage(start, Duration::from_secs(10), &times),
            start + Duration::from_secs(10)
        );
        assert_eq!(
            stage(start, Duration::from_secs(11), &times),
            start + Duration::from_secs(10)
        );
        // A stage that starts late still ends with the request time.
        let late = start + Duration::from_secs(8);
        assert_eq!(
            stage(late, Duration::from_secs(5), &times),
            start + Duration::from_secs(10)
        );
        // A sum that does not fit into the clock has passed.
        assert_eq!(after(start, Duration::MAX), start);
        assert_eq!(stage(start, Duration::MAX, &times), start);
    }

    // ---- the connection, over real sockets, with a driver that is a thread in this test ----

    fn config() -> ProxyConfig {
        let secs = Duration::from_secs;
        ProxyConfig {
            listen: "127.0.0.1:1".parse().unwrap(),
            upstream: "127.0.0.1:2".parse().unwrap(),
            max_conns: 16,
            max_head_bytes: 8192,
            max_body: 1024,
            max_body_wire: 4096,
            max_buffered_bytes: BUDGET,
            upstream_max_headers: 64,
            upstream_max_head_bytes: 8192,
            upstream_head_wire: 65536,
            drive_slice: Duration::from_millis(10),
            ready_wait: secs(5),
            head_read: secs(5),
            body_read: secs(5),
            inspect_wait: secs(5),
            upstream_connect: secs(5),
            upstream_header: secs(5),
            request_total: secs(10),
            response_idle: secs(5),
            conn_total: secs(20),
            stop_inspect: secs(1),
            stop_wait: secs(5),
        }
    }

    /// What the driver of a test does with a ticket.
    #[derive(Clone, Copy)]
    enum Mode {
        /// Answers every ticket with this.
        Answer(Outcome),
        /// Keeps every ticket and never answers.
        Hold,
        /// The driver is gone: the way to it is closed.
        Gone,
        /// The way to the driver is full.
        Full,
        /// Takes every ticket and drops it without an answer.
        Drop,
    }

    #[derive(Debug)]
    struct Seen {
        client: SocketAddr,
        server: SocketAddr,
        method: String,
        uri: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        /// For a ticket that was kept: the connection had dropped its end when the driver stopped.
        abandoned: bool,
    }

    fn driver(rx: Receiver<Msg>, answer: Option<Outcome>) -> JoinHandle<Vec<Seen>> {
        thread::spawn(move || {
            let mut kept = Vec::new();
            while let Ok(msg) = rx.recv() {
                let Msg::Ticket(ticket) = msg else { continue };
                let req = &ticket.req;
                let seen = Seen {
                    client: req.client,
                    server: req.server,
                    method: String::from_utf8_lossy(&req.method).into_owned(),
                    uri: String::from_utf8_lossy(&req.uri).into_owned(),
                    headers: req
                        .headers
                        .iter()
                        .map(|(n, v)| {
                            (
                                String::from_utf8_lossy(n).into_owned(),
                                String::from_utf8_lossy(v).into_owned(),
                            )
                        })
                        .collect(),
                    body: req.body.bytes.to_vec(),
                    abandoned: false,
                };
                match answer {
                    Some(outcome) => {
                        let _ = ticket.reply.send(outcome);
                        kept.push((seen, None));
                    }
                    None => kept.push((seen, Some(ticket))),
                }
            }
            kept.into_iter()
                .map(|(seen, ticket)| Seen {
                    abandoned: ticket.is_some_and(|t| t.reply.is_closed()),
                    ..seen
                })
                .collect()
        })
    }

    /// A driver that receives every ticket and drops it.
    fn dropper(rx: Receiver<Msg>) -> JoinHandle<Vec<Seen>> {
        thread::spawn(move || {
            while let Ok(msg) = rx.recv() {
                drop(msg);
            }
            Vec::new()
        })
    }

    struct Rig {
        ctx: Arc<Ctx>,
        listener: TcpListener,
        tx: Option<SyncSender<Msg>>,
        driver: Option<JoinHandle<Vec<Seen>>>,
        /// The receiving end of a way that is full, kept so that it stays open.
        _full: Option<Receiver<Msg>>,
    }

    fn runtime() -> Runtime {
        Builder::new_current_thread().enable_all().build().unwrap()
    }

    /// Runs a test body; a body that hangs fails the test instead of the run.
    fn run<F: std::future::Future>(body: F) -> F::Output {
        runtime().block_on(async {
            timeout(Duration::from_secs(60), body)
                .await
                .expect("the test hung")
        })
    }

    impl Rig {
        async fn new(cfg: ProxyConfig, mode: Mode) -> Rig {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let budget = Arc::new(Semaphore::new(cfg.max_buffered_bytes));
            let ctx = Arc::new(Ctx {
                cfg,
                budget,
                inspect: Arc::new(Semaphore::new(PERMITS)),
                log: start_logger().unwrap(),
            });
            let (tx, rx) = sync_channel(if matches!(mode, Mode::Full) {
                1
            } else {
                PERMITS + 1
            });
            let (driver, full) = match mode {
                Mode::Answer(outcome) => (Some(driver(rx, Some(outcome))), None),
                Mode::Hold => (Some(driver(rx, None)), None),
                Mode::Drop => (Some(dropper(rx)), None),
                Mode::Gone => (None, None),
                Mode::Full => {
                    tx.try_send(Msg::Stop {
                        inspect_by: std::time::Instant::now(),
                    })
                    .unwrap();
                    (None, Some(rx))
                }
            };
            Rig {
                ctx,
                listener,
                tx: Some(tx),
                driver,
                _full: full,
            }
        }

        /// A client connects and the connection is served in the background.
        async fn connect(&self) -> (TcpStream, Served<()>) {
            let client = TcpStream::connect(self.listener.local_addr().unwrap())
                .await
                .unwrap();
            let (sock, peer) = self.listener.accept().await.unwrap();
            let local = sock.local_addr().unwrap();
            let task = tokio::spawn(serve(
                sock,
                peer,
                local,
                self.ctx.clone(),
                self.tx.clone().unwrap(),
            ));
            (client, task)
        }

        /// Waits for the connection to end and the driver to stop; checks that nothing is held any more.
        async fn finish(mut self, served: Served<()>) -> Vec<Seen> {
            timeout(Duration::from_secs(30), served)
                .await
                .expect("the connection ended")
                .unwrap();
            drop(self.tx.take());
            let seen = self
                .driver
                .take()
                .map(|d| d.join().unwrap())
                .unwrap_or_default();
            assert_eq!(
                self.ctx.budget.available_permits(),
                self.ctx.cfg.max_buffered_bytes
            );
            assert_eq!(self.ctx.inspect.available_permits(), PERMITS);
            seen
        }
    }

    async fn put(sock: &TcpStream, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            sock.writable().await.unwrap();
            match sock.try_write(bytes) {
                Ok(n) => bytes = &bytes[n..],
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("write failed: {e}"),
            }
        }
    }

    /// Ends the sending direction of a client.
    async fn finish_sending(sock: &mut TcpStream) {
        poll_fn(|cx| Pin::new(&mut *sock).poll_shutdown(cx))
            .await
            .unwrap();
    }

    /// Everything the server sends until it closes.
    async fn read_all(sock: &TcpStream) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        timeout(Duration::from_secs(30), async {
            loop {
                sock.readable().await.unwrap();
                match sock.try_read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => out.extend_from_slice(&buf[..n]),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => break,
                }
            }
        })
        .await
        .expect("the server closed the connection");
        out
    }

    struct Parsed {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    impl Parsed {
        fn all(&self, name: &str) -> Vec<&str> {
            self.headers
                .iter()
                .filter(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
                .collect()
        }
    }

    fn parse_response(raw: &[u8]) -> Parsed {
        let mut storage = [httparse::EMPTY_HEADER; 32];
        let mut response = httparse::Response::new(&mut storage);
        let httparse::Status::Complete(n) = response.parse(raw).expect("a response") else {
            panic!("an incomplete response: {:?}", String::from_utf8_lossy(raw));
        };
        Parsed {
            status: response.code.unwrap(),
            headers: response
                .headers
                .iter()
                .map(|h| {
                    (
                        h.name.to_string(),
                        String::from_utf8_lossy(h.value).into_owned(),
                    )
                })
                .collect(),
            body: raw[n..].to_vec(),
        }
    }

    /// One request, one connection, and what came back and what the driver saw.
    async fn exchange(cfg: ProxyConfig, mode: Mode, request: &[u8]) -> (Vec<u8>, Vec<Seen>) {
        let rig = Rig::new(cfg, mode).await;
        let (client, task) = rig.connect().await;
        put(&client, request).await;
        let response = read_all(&client).await;
        let seen = rig.finish(task).await;
        (response, seen)
    }

    /// Like `exchange`, but the connection is run as `serve` runs it, and the reply that its record line is made
    /// of comes back as well.
    async fn exchange_with_reply(
        cfg: ProxyConfig,
        mode: Mode,
        request: &[u8],
    ) -> (Vec<u8>, Vec<Seen>, Reply) {
        let rig = Rig::new(cfg, mode).await;
        let client = TcpStream::connect(rig.listener.local_addr().unwrap())
            .await
            .unwrap();
        let (sock, peer) = rig.listener.accept().await.unwrap();
        let local = sock.local_addr().unwrap();
        let accept = Instant::now();
        let times = Times {
            accept,
            request_by: after(accept, rig.ctx.cfg.request_total),
            conn_by: after(accept, rig.ctx.cfg.conn_total),
        };
        let (ctx, ingress) = (rig.ctx.clone(), rig.tx.clone().unwrap());
        let (sent, reply) = oneshot::channel();
        let task = tokio::spawn(async move {
            let _ = sent.send(super::run(sock, peer, local, &ctx, ingress, times).await);
        });
        put(&client, request).await;
        let response = read_all(&client).await;
        let seen = rig.finish(task).await;
        (response, seen, reply.await.unwrap())
    }

    fn form_post(body_lines: &str) -> Vec<u8> {
        format!(
            "POST /p?q=1 HTTP/1.1\r\nHost: example.test\r\nContent-Type: {FORM}\r\n{body_lines}"
        )
        .into_bytes()
    }

    const BLOCK: Outcome = Outcome::Verdict(Verdict::Block {
        phase: 2,
        rule_id: 9202,
        status: 403,
    });

    #[test]
    fn a_blocked_request_is_answered_with_the_status_of_the_rule() {
        run(async {
            let (raw, seen) = exchange(
                config(),
                Mode::Answer(BLOCK),
                b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n",
            )
            .await;
            let response = parse_response(&raw);
            assert_eq!(response.status, 403);
            assert_eq!(response.all("content-length"), ["0"]);
            assert_eq!(response.all("connection"), ["close"]);
            assert!(response.body.is_empty());
            assert_eq!(seen.len(), 1);
            assert_eq!(
                (seen[0].method.as_str(), seen[0].uri.as_str()),
                ("GET", "/a")
            );
            assert_eq!(seen[0].headers, [pair("Host", "h")]);
        });
    }

    #[test]
    fn a_block_with_204_or_304_has_no_content_length() {
        run(async {
            for status in [204u16, 304] {
                let outcome = Outcome::Verdict(Verdict::Block {
                    phase: 1,
                    rule_id: 1,
                    status,
                });
                let (raw, _) = exchange(
                    config(),
                    Mode::Answer(outcome),
                    b"GET / HTTP/1.1\r\nHost: h\r\n\r\n",
                )
                .await;
                let response = parse_response(&raw);
                assert_eq!(response.status, status);
                assert!(response.all("content-length").is_empty(), "{status}");
                assert_eq!(response.all("connection"), ["close"]);
                assert!(response.body.is_empty());
            }
        });
    }

    #[test]
    fn the_other_outcomes_are_answered_as_the_table_says() {
        run(async {
            let cases = [
                (
                    Outcome::Verdict(Verdict::Block {
                        phase: 1,
                        rule_id: 5,
                        status: 700,
                    }),
                    500,
                ),
                (
                    Outcome::Verdict(Verdict::Block {
                        phase: 1,
                        rule_id: 5,
                        status: 0,
                    }),
                    500,
                ),
                (
                    Outcome::Verdict(Verdict::Uninspectable(Reason::InspectorLost)),
                    503,
                ),
                (
                    Outcome::Verdict(Verdict::Uninspectable(Reason::Invalid)),
                    500,
                ),
                (Outcome::Refused(Refused::Unsupported("content-type")), 500),
                (Outcome::Refused(Refused::Full), 503),
                (Outcome::Unavailable, 503),
            ];
            for (outcome, status) in cases {
                let (raw, seen) = exchange(
                    config(),
                    Mode::Answer(outcome),
                    b"GET / HTTP/1.1\r\nHost: h\r\n\r\n",
                )
                .await;
                let response = parse_response(&raw);
                assert_eq!(response.status, status, "{outcome:?}");
                assert_eq!(response.all("content-length"), ["0"], "{outcome:?}");
                assert_eq!(response.all("connection"), ["close"], "{outcome:?}");
                assert_eq!(seen.len(), 1);
            }
        });
    }

    /// A GET head whose names and values add up to exactly 24 KiB.
    fn total_24_kib() -> String {
        let mut raw = String::from("GET / HTTP/1.1\r\nHost: example.test\r\n");
        for n in 1..=5 {
            raw.push_str(&format!("F00{n}: {}\r\n", "a".repeat(4096)));
        }
        raw.push_str(&format!("F006: {}\r\n\r\n", "a".repeat(4056)));
        raw
    }

    #[test]
    fn heads_at_every_limit_are_served_by_hyper_as_well() {
        run(async {
            let target = format!("GET /{} HTTP/1.1\r\nHost: h\r\n\r\n", "a".repeat(4095));
            let name = format!(
                "GET / HTTP/1.1\r\nHost: h\r\n{}: {}\r\n\r\n",
                "N".repeat(256),
                "v".repeat(4096)
            );
            let exact = {
                let fixed = "GET / HTTP/1.1\r\nHost: a\r\nX-Pad: \r\n\r\n".len();
                format!(
                    "GET / HTTP/1.1\r\nHost: a\r\nX-Pad: {}\r\n\r\n",
                    "p".repeat(1024 - fixed)
                )
            };
            assert_eq!(exact.len(), 1024);
            let cases = [
                (numbered(64, "GET"), 8192),
                (target, 8192),
                (name, 8192),
                (total_24_kib(), 32 * 1024),
                (exact, 1024),
            ];
            for (n, (request, max_head_bytes)) in cases.into_iter().enumerate() {
                let mut cfg = config();
                cfg.max_head_bytes = max_head_bytes;
                let (raw, seen) = exchange(cfg, Mode::Answer(BLOCK), request.as_bytes()).await;
                assert_eq!(parse_response(&raw).status, 403, "case {n}");
                assert_eq!(seen.len(), 1, "case {n}");
            }
        });
    }

    #[test]
    fn a_request_target_that_hyper_does_not_accept_is_a_400_and_nothing_is_inspected() {
        run(async {
            // The head check refuses these bytes itself: the answer is its fixed one (hyper's own 400 would carry a
            // `Date`), the record says why, and hyper never sees the request.
            for target in ["/a<b", "/a>b", "/a`b", "/?q=\"x\"", "/?q=<x>", "/?q=>"] {
                let request = format!("GET {target} HTTP/1.1\r\nHost: h\r\n\r\n");
                let (raw, seen, reply) =
                    exchange_with_reply(config(), Mode::Answer(BLOCK), request.as_bytes()).await;
                assert_eq!(raw, Reject::BadRequest.response().unwrap(), "{target}");
                assert!(seen.is_empty(), "{target}");
                assert_eq!(reply, Reply::of(Reject::BadRequest), "{target}");
                assert_eq!(
                    record(1, &reply, Duration::ZERO),
                    "conn 1: rejected 400 malformed request head rule - 0 ms",
                    "{target}"
                );
            }
        });
    }

    #[test]
    fn a_request_target_that_hyper_accepts_in_one_part_only_is_inspected() {
        run(async {
            // `"` is taken in the path and not in the query; the backtick is taken in the query and not in the path.
            for target in ["/a\"b", "/{\"k\":1}", "/?q=`x`"] {
                let request = format!("GET {target} HTTP/1.1\r\nHost: h\r\n\r\n");
                let (raw, seen) = exchange(config(), Mode::Answer(BLOCK), request.as_bytes()).await;
                assert_eq!(parse_response(&raw).status, 403, "{target}");
                assert_eq!(seen.len(), 1, "{target}");
                assert_eq!(seen[0].uri, target);
            }
        });
    }

    #[test]
    fn no_inspection_permit_or_a_driver_that_drops_the_ticket_is_503() {
        run(async {
            let rig = Rig::new(config(), Mode::Answer(BLOCK)).await;
            let all = rig
                .ctx
                .inspect
                .clone()
                .try_acquire_many_owned(PERMITS as u32)
                .unwrap();
            let (client, served) = rig.connect().await;
            put(&client, b"GET / HTTP/1.1\r\nHost: h\r\n\r\n").await;
            let response = parse_response(&read_all(&client).await);
            assert_eq!(response.status, 503);
            assert_eq!(response.all("content-length"), ["0"]);
            drop(all);
            assert!(rig.finish(served).await.is_empty());
            // One permit left is enough.
            let rig = Rig::new(config(), Mode::Answer(BLOCK)).await;
            let most = rig
                .ctx
                .inspect
                .clone()
                .try_acquire_many_owned(PERMITS as u32 - 1)
                .unwrap();
            let (client, served) = rig.connect().await;
            put(&client, b"GET / HTTP/1.1\r\nHost: h\r\n\r\n").await;
            assert_eq!(parse_response(&read_all(&client).await).status, 403);
            drop(most);
            assert_eq!(rig.finish(served).await.len(), 1);
            // The reply end is dropped without a verdict: the wait ends at once, not at its deadline.
            let start = std::time::Instant::now();
            let (raw, _) =
                exchange(config(), Mode::Drop, b"GET / HTTP/1.1\r\nHost: h\r\n\r\n").await;
            assert_eq!(parse_response(&raw).status, 503);
            assert!(start.elapsed() < Duration::from_secs(4));
        });
    }

    /// Names and values of the fields `form_post` makes, with the `Content-Length` of a 3 byte body.
    fn form_post_field_bytes() -> usize {
        (4 + 12) + (12 + FORM.len()) + (14 + 1)
    }

    #[test]
    fn the_byte_budget_covers_the_body_and_the_kernels_copy_of_it() {
        run(async {
            let request = form_post("Content-Length: 3\r\n\r\na=b");
            let needed = 3 + (3 + form_post_field_bytes());
            let mut cfg = config();
            cfg.max_buffered_bytes = needed;
            let (raw, seen) = exchange(cfg, Mode::Answer(BLOCK), &request).await;
            assert_eq!(parse_response(&raw).status, 403);
            assert_eq!(seen[0].body, b"a=b");
            // One byte less: the body is held and the copy is not.
            let mut cfg = config();
            cfg.max_buffered_bytes = needed - 1;
            let (raw, seen) = exchange(cfg, Mode::Answer(BLOCK), &request).await;
            assert_eq!(parse_response(&raw).status, 503);
            assert!(seen.is_empty());
            // Only the body fits.
            let mut cfg = config();
            cfg.max_buffered_bytes = 3;
            let (raw, seen) = exchange(cfg, Mode::Answer(BLOCK), &request).await;
            assert_eq!(parse_response(&raw).status, 503);
            assert!(seen.is_empty());
        });
    }

    #[test]
    fn the_budget_of_a_chunked_body_is_taken_frame_by_frame() {
        run(async {
            let request =
                form_post("Transfer-Encoding: chunked\r\n\r\n3\r\na=b\r\n4\r\n&c=d\r\n0\r\n\r\n");
            // 7 bytes of body, held once and copied once, and the fields with `Content-Length: 7`.
            let needed = 7 + (7 + form_post_field_bytes());
            let mut cfg = config();
            cfg.max_buffered_bytes = needed;
            let (raw, seen) = exchange(cfg, Mode::Answer(BLOCK), &request).await;
            assert_eq!(parse_response(&raw).status, 403);
            assert_eq!(seen[0].body, b"a=b&c=d");
            // The second frame does not fit.
            let mut cfg = config();
            cfg.max_buffered_bytes = 6;
            let (raw, seen) = exchange(cfg, Mode::Answer(BLOCK), &request).await;
            assert_eq!(parse_response(&raw).status, 503);
            assert!(seen.is_empty());
            // The copy does not fit.
            let mut cfg = config();
            cfg.max_buffered_bytes = needed - 1;
            let (raw, seen) = exchange(cfg, Mode::Answer(BLOCK), &request).await;
            assert_eq!(parse_response(&raw).status, 503);
            assert!(seen.is_empty());
        });
    }

    #[test]
    fn the_wire_limit_is_exact_and_hypers_reads_after_the_body_do_not_trip_it() {
        run(async {
            // One chunk of 1024 bytes with an extension as long as it takes to bring the bytes after the head
            // to `max_body_wire` (4096): 4 + 3059 + 2 + 1024 + 2 + 5.
            let wire = |padding: usize| {
                let mut request = form_post("Transfer-Encoding: chunked\r\n\r\n");
                request.extend_from_slice(format!("400;{}\r\n", "e".repeat(padding)).as_bytes());
                request.extend_from_slice("a".repeat(1024).as_bytes());
                request.extend_from_slice(b"\r\n0\r\n\r\n");
                request
            };
            let head_len = form_post("Transfer-Encoding: chunked\r\n\r\n").len();
            assert_eq!(wire(3059).len() - head_len, 4096);
            for pause in [false, true] {
                for (padding, status) in [(3059, 403), (3060, 413)] {
                    let rig = Rig::new(config(), Mode::Answer(BLOCK)).await;
                    let (client, served) = rig.connect().await;
                    let request = wire(padding);
                    if pause {
                        // The head is served first and the rest of the bytes come afterwards.
                        put(&client, &request[..head_len]).await;
                        sleep(Duration::from_millis(100)).await;
                        put(&client, &request[head_len..]).await;
                    } else {
                        put(&client, &request).await;
                    }
                    let response = parse_response(&read_all(&client).await);
                    assert_eq!(response.status, status, "padding {padding}, pause {pause}");
                    let seen = rig.finish(served).await;
                    assert_eq!(seen.len(), usize::from(status == 403));
                }
            }
        });
    }

    #[test]
    fn a_form_body_with_a_length_is_inspected_as_received() {
        run(async {
            let (_, seen) = exchange(
                config(),
                Mode::Answer(BLOCK),
                &form_post("Content-Length: 3\r\n\r\na=b"),
            )
            .await;
            assert_eq!(seen.len(), 1);
            let seen = &seen[0];
            assert_eq!(seen.body, b"a=b");
            assert_eq!(
                seen.headers,
                [
                    pair("Host", "example.test"),
                    pair("Content-Type", FORM),
                    pair("Content-Length", "3")
                ]
            );
            assert_eq!(
                (seen.method.as_str(), seen.uri.as_str()),
                ("POST", "/p?q=1")
            );
            assert_eq!(seen.server.ip().to_string(), "127.0.0.1");
            assert_ne!(seen.client.port(), seen.server.port());
        });
    }

    #[test]
    fn a_post_without_a_length_is_inspected_with_content_length_0() {
        run(async {
            let (_, seen) = exchange(
                config(),
                Mode::Answer(BLOCK),
                b"POST /e HTTP/1.1\r\nHost: h\r\n\r\n",
            )
            .await;
            assert_eq!(
                seen[0].headers,
                [pair("Host", "h"), pair("Content-Length", "0")]
            );
            assert!(seen[0].body.is_empty());
        });
    }

    #[test]
    fn a_chunked_form_body_is_decoded_and_inspected_with_its_length() {
        run(async {
            let request = form_post(
                "Transfer-Encoding: chunked\r\n\r\n3;ext=1\r\na=b\r\n2\r\n&c\r\n0\r\n\r\n",
            );
            let (raw, seen) = exchange(config(), Mode::Answer(BLOCK), &request).await;
            assert_eq!(parse_response(&raw).status, 403);
            assert_eq!(seen[0].body, b"a=b&c");
            assert_eq!(
                seen[0].headers,
                [
                    pair("Host", "example.test"),
                    pair("Content-Type", FORM),
                    pair("Content-Length", "5")
                ]
            );
        });
    }

    #[test]
    fn a_chunked_json_body_is_decoded_and_inspected_with_its_length() {
        run(async {
            let request = b"POST /j HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n5\r\n:\"b\"}\r\n0\r\n\r\n";
            let (raw, seen) = exchange(config(), Mode::Answer(BLOCK), request).await;
            assert_eq!(parse_response(&raw).status, 403);
            assert_eq!(seen.len(), 1);
            assert_eq!(seen[0].body, b"{\"a\":\"b\"}");
            assert_eq!(
                seen[0].headers,
                [
                    pair("Host", "h"),
                    pair("Content-Type", "application/json"),
                    pair("Content-Length", "9")
                ]
            );
        });
    }

    #[test]
    fn a_chunked_json_suffix_body_is_decoded_and_inspected_with_its_length() {
        run(async {
            let request = b"POST /j HTTP/1.1\r\nHost: h\r\nContent-Type: application/vnd.api+json\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n5\r\n:\"b\"}\r\n0\r\n\r\n";
            let (raw, seen) = exchange(config(), Mode::Answer(BLOCK), request).await;
            assert_eq!(parse_response(&raw).status, 403);
            assert_eq!(seen.len(), 1);
            assert_eq!(seen[0].body, b"{\"a\":\"b\"}");
            assert_eq!(
                seen[0].headers,
                [
                    pair("Host", "h"),
                    pair("Content-Type", "application/vnd.api+json"),
                    pair("Content-Length", "9")
                ]
            );
        });
    }

    #[test]
    fn a_chunked_body_of_another_type_is_415_but_an_empty_one_is_not() {
        run(async {
            let request = b"POST / HTTP/1.1\r\nHost: h\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n";
            let (raw, seen) = exchange(config(), Mode::Answer(BLOCK), request).await;
            assert_eq!(parse_response(&raw).status, 415);
            assert!(seen.is_empty());
            // A `+json` type outside `application/` is not JSON.
            let request = b"POST / HTTP/1.1\r\nHost: h\r\nContent-Type: text/x+json\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n";
            let (raw, seen) = exchange(config(), Mode::Answer(BLOCK), request).await;
            assert_eq!(parse_response(&raw).status, 415);
            assert!(seen.is_empty());
            let request = b"POST / HTTP/1.1\r\nHost: h\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
            let (raw, seen) = exchange(config(), Mode::Answer(BLOCK), request).await;
            assert_eq!(parse_response(&raw).status, 403);
            assert_eq!(seen.len(), 1);
        });
    }

    #[test]
    fn a_trailer_or_a_broken_chunk_is_400_and_nothing_is_inspected() {
        run(async {
            let trailer =
                form_post("Transfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\nX-T: 1\r\n\r\n");
            let broken = form_post("Transfer-Encoding: chunked\r\n\r\nzz\r\na\r\n0\r\n\r\n");
            for request in [trailer, broken] {
                let (raw, seen) = exchange(config(), Mode::Answer(BLOCK), &request).await;
                let response = parse_response(&raw);
                assert_eq!(response.status, 400);
                assert_eq!(response.all("content-length"), ["0"]);
                assert!(seen.is_empty());
            }
        });
    }

    #[test]
    fn a_decoded_body_over_the_limit_is_413_and_one_at_the_limit_is_inspected() {
        run(async {
            let chunk = |len: usize| format!("{len:x}\r\n{}\r\n0\r\n\r\n", "a".repeat(len));
            let at = form_post(&format!(
                "Transfer-Encoding: chunked\r\n\r\n{}",
                chunk(1024)
            ));
            let (_, seen) = exchange(config(), Mode::Answer(BLOCK), &at).await;
            assert_eq!(seen.len(), 1);
            assert_eq!(seen[0].body.len(), 1024);
            let over = form_post(&format!(
                "Transfer-Encoding: chunked\r\n\r\n{}",
                chunk(1025)
            ));
            let (raw, seen) = exchange(config(), Mode::Answer(BLOCK), &over).await;
            assert_eq!(parse_response(&raw).status, 413);
            assert!(seen.is_empty());
            // Two chunks that are each within the limit and together over it.
            let two = form_post("Transfer-Encoding: chunked\r\n\r\n400\r\n");
            let mut two = two;
            two.extend_from_slice("a".repeat(1024).as_bytes());
            two.extend_from_slice(b"\r\n1\r\nb\r\n0\r\n\r\n");
            let (raw, seen) = exchange(config(), Mode::Answer(BLOCK), &two).await;
            assert_eq!(parse_response(&raw).status, 413);
            assert!(seen.is_empty());
        });
    }

    #[test]
    fn a_length_over_the_limit_is_refused_with_the_fixed_answer_before_any_body() {
        run(async {
            let (raw, seen) = exchange(
                config(),
                Mode::Answer(BLOCK),
                &form_post("Content-Length: 1025\r\n\r\n"),
            )
            .await;
            assert_eq!(raw, Reject::ContentTooLarge.response().unwrap());
            assert!(seen.is_empty());
            let (raw, _) = exchange(config(), Mode::Answer(BLOCK), b"GET / HTTP/1.0\r\n\r\n").await;
            assert_eq!(raw, Reject::VersionNotSupported.response().unwrap());
            let (raw, _) = exchange(config(), Mode::Answer(BLOCK), b"GET /\n\n").await;
            assert_eq!(raw, Reject::BadRequest.response().unwrap());
        });
    }

    #[test]
    fn a_refusal_reaches_a_client_that_is_still_sending() {
        run(async {
            let rig = Rig::new(config(), Mode::Answer(BLOCK)).await;
            let (client, task) = rig.connect().await;
            let mut request = form_post("Content-Length: 2000000\r\n\r\n");
            request.extend_from_slice(&vec![b'a'; 200_000]);
            put(&client, &request).await;
            let raw = read_all(&client).await;
            assert_eq!(raw, Reject::ContentTooLarge.response().unwrap());
            assert!(rig.finish(task).await.is_empty());
        });
    }

    #[test]
    fn the_bytes_on_the_wire_after_the_head_are_limited() {
        run(async {
            let rig = Rig::new(config(), Mode::Answer(BLOCK)).await;
            let (client, task) = rig.connect().await;
            put(&client, &form_post("Transfer-Encoding: chunked\r\n\r\n")).await;
            // The head is read and served by now; a chunk header with a long extension is what follows.
            sleep(Duration::from_millis(100)).await;
            let mut more = b"1;".to_vec();
            more.extend_from_slice(&vec![b'e'; 6000]);
            put(&client, &more).await;
            let raw = read_all(&client).await;
            assert_eq!(parse_response(&raw).status, 413);
            assert!(rig.finish(task).await.is_empty());
        });
    }

    #[test]
    fn a_peer_that_goes_away_during_the_body_gets_no_answer_and_leaves_nothing_held() {
        run(async {
            let rig = Rig::new(config(), Mode::Answer(BLOCK)).await;
            let (mut client, task) = rig.connect().await;
            put(&client, &form_post("Content-Length: 10\r\n\r\nabc")).await;
            sleep(Duration::from_millis(100)).await;
            finish_sending(&mut client).await;
            assert!(read_all(&client).await.is_empty());
            assert!(rig.finish(task).await.is_empty());
        });
    }

    #[test]
    fn the_head_and_the_body_have_their_own_time() {
        run(async {
            let mut cfg = config();
            cfg.head_read = Duration::from_millis(200);
            let rig = Rig::new(cfg, Mode::Answer(BLOCK)).await;
            let (client, task) = rig.connect().await;
            put(&client, b"GET / HT").await;
            let start = std::time::Instant::now();
            assert_eq!(read_all(&client).await, Reject::Timeout.response().unwrap());
            assert!(start.elapsed() >= Duration::from_millis(190));
            assert!(rig.finish(task).await.is_empty());

            let mut cfg = config();
            cfg.body_read = Duration::from_millis(200);
            let rig = Rig::new(cfg, Mode::Answer(BLOCK)).await;
            let (client, task) = rig.connect().await;
            put(&client, &form_post("Content-Length: 10\r\n\r\nabc")).await;
            let start = std::time::Instant::now();
            let response = parse_response(&read_all(&client).await);
            assert_eq!(response.status, 408);
            assert_eq!(response.all("content-length"), ["0"]);
            assert!(start.elapsed() >= Duration::from_millis(190));
            assert!(rig.finish(task).await.is_empty());
        });
    }

    #[test]
    fn an_inspection_that_does_not_answer_is_503_and_the_ticket_is_abandoned() {
        run(async {
            let mut cfg = config();
            cfg.inspect_wait = Duration::from_millis(200);
            let rig = Rig::new(cfg, Mode::Hold).await;
            let (client, task) = rig.connect().await;
            put(&client, b"GET / HTTP/1.1\r\nHost: h\r\n\r\n").await;
            let start = std::time::Instant::now();
            let response = parse_response(&read_all(&client).await);
            assert_eq!(response.status, 503);
            assert!(start.elapsed() >= Duration::from_millis(190));
            let seen = rig.finish(task).await;
            assert_eq!(seen.len(), 1);
            assert!(seen[0].abandoned);
        });
    }

    #[test]
    fn a_driver_that_is_gone_or_a_way_to_it_that_is_full_gives_503() {
        run(async {
            for mode in [Mode::Gone, Mode::Full] {
                let (raw, seen) =
                    exchange(config(), mode, b"GET / HTTP/1.1\r\nHost: h\r\n\r\n").await;
                let response = parse_response(&raw);
                assert_eq!(response.status, 503);
                assert_eq!(response.all("content-length"), ["0"]);
                assert!(seen.is_empty());
            }
        });
    }

    #[test]
    fn a_body_that_does_not_fit_the_budget_is_503_before_any_100_continue() {
        run(async {
            let mut cfg = config();
            cfg.max_buffered_bytes = 2;
            let request = form_post("Content-Length: 3\r\nExpect: 100-continue\r\n\r\n");
            let (raw, seen) = exchange(cfg, Mode::Answer(BLOCK), &request).await;
            assert!(
                raw.starts_with(b"HTTP/1.1 503 "),
                "{:?}",
                String::from_utf8_lossy(&raw)
            );
            assert!(!String::from_utf8_lossy(&raw).contains("100 Continue"));
            assert!(seen.is_empty());
        });
    }

    #[test]
    fn a_request_that_expects_100_continue_gets_it_once_the_body_can_be_held() {
        run(async {
            let rig = Rig::new(config(), Mode::Answer(BLOCK)).await;
            let (client, task) = rig.connect().await;
            put(
                &client,
                &form_post("Content-Length: 3\r\nExpect: 100-continue\r\n\r\n"),
            )
            .await;
            let mut got = Vec::new();
            let mut buf = [0u8; 256];
            while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                client.readable().await.unwrap();
                if let Ok(n) = client.try_read(&mut buf) {
                    got.extend_from_slice(&buf[..n]);
                }
            }
            assert_eq!(got, b"HTTP/1.1 100 Continue\r\n\r\n");
            put(&client, b"a=b").await;
            let response = parse_response(&read_all(&client).await);
            assert_eq!(response.status, 403);
            assert_eq!(rig.finish(task).await[0].body, b"a=b");
        });
    }
}
