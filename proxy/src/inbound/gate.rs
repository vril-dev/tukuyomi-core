//! The read side of a client connection, in front of hyper: the bytes are cut into requests, and the head of every
//! request is checked by `head` before hyper sees a byte of it.
//!
//! The gate keeps a head back until it is complete and has passed every rule. Then it hands hyper the bytes of the
//! head and as many body bytes as the one `Content-Length` says, and puts a copy of the head into the queue of
//! its `Link`. The service takes the copies in order, one for every request that hyper hands it, and compares
//! each with what hyper made of the same bytes (`same_head`); a request without a copy, or with a copy that
//! differs, is not served. The body of a request is never looked at, so a body that looks like a request is only
//! a body. A chunked request is the last one of its connection: the gate cannot find the end of a chunked body
//! without a second parser, so everything after its head goes on to hyper, up to the cap of the bytes on the
//! wire, and the connection is closed after the response.
//!
//! No more than `QUEUE_MAX` copies wait at a time; while the queue is full the gate hands on nothing and reads
//! nothing, and the service's next `take` lets it go on.
//!
//! A refused head after the first one is not answered, for the response of the request before it must not be
//! broken: the gate keeps the refusal and shows hyper the end of the stream once every request it has passed has
//! been answered (`Link::finish`) and everything hyper wrote has been flushed. The same holds for a head that does
//! not come in time. The first head of the connection is read with `first_head` before hyper starts, so that its
//! refusal can be answered.
//!
//! The waits of the gate are the three it can tell from the bytes: the head of the first request is bounded by the
//! caller; the head of a later request ends `head_read` after its first byte; and a connection whose requests have
//! all been answered and flushed, and that has no byte of a next head, ends `keepalive_timeout` after the later of
//! the last answer and the last flush, as if the client had closed it. Hyper drops the body of a response when it
//! has encoded the last frame, which can be before the bytes are out, so an answer alone does not make the
//! connection quiet: the gate sees the writes, and the stream shows its end only when nothing is left to flush.
//!
//! Empty lines in front of a head after the first one are dropped, at most two (a client may add a line end after
//! a body); hyper never sees them. A third is a refused head.
//!
//! The writes go through to the stream. The end of the writing direction does not: whoever owns the gate closes the
//! connection when it has decided how.

use std::collections::VecDeque;
use std::future::{Future, poll_fn};
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker, ready};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderName, Version};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep, sleep_until, timeout_at};

use crate::config::ProxyConfig;
use crate::inbound::conn::after;
use crate::inbound::head::{self, Head, Limits, Reject, trim_ows};
use crate::inbound::io::{Gauge, Guarded};

/// The most checked heads that wait for hyper to ask for their requests.
pub const QUEUE_MAX: usize = 16;

/// The most empty lines dropped in front of a head after the first one.
const BLANK_LINES_MAX: u8 = 2;

/// What the gate takes from the configuration.
#[derive(Clone, Copy, Debug)]
pub struct Settings {
    pub limits: Limits,
    /// How long a head may take from its first byte.
    pub head_read: Duration,
    /// How long a connection that has nothing to do waits for the first byte of its next request.
    pub keepalive_timeout: Duration,
    /// The most bytes after the head of a chunked request that are read from the stream.
    pub max_body_wire: u64,
    /// The idle limits of the stream (see `Guarded`). A read that waits is bounded by the connection time alone:
    /// while a request is inspected or its response is sent, hyper may wait for the peer for as long as the
    /// connection lives. The stages of a request have limits of their own.
    pub read_idle: Duration,
    pub write_idle: Duration,
}

impl Settings {
    pub fn new(cfg: &ProxyConfig) -> Settings {
        Settings {
            limits: Limits {
                max_head_bytes: cfg.max_head_bytes,
                max_body: u64::try_from(cfg.max_body).unwrap_or(u64::MAX),
            },
            head_read: cfg.head_read,
            keepalive_timeout: cfg.keepalive_timeout,
            max_body_wire: u64::try_from(cfg.max_body_wire).unwrap_or(u64::MAX),
            read_idle: cfg.conn_total,
            write_idle: cfg.response_idle,
        }
    }
}

/// A checked head that waits for its request, and the instant of its first byte.
struct Queued {
    head: Head,
    began: Instant,
}

/// A head taken for the request that hyper handed over, and the instant the time of that request counts from:
/// its first byte, or the end of the answer before it if that came later.
pub struct Taken {
    pub head: Head,
    pub start: Instant,
}

struct Shared {
    queue: VecDeque<Queued>,
    /// Heads that were put into the queue, and responses that are complete.
    released: u64,
    completed: u64,
    /// When the last response was complete (the accept before the first one).
    last_done: Instant,
    /// The gate, when it waits for the queue to have room or for the last response.
    parked: Option<Waker>,
    /// The gate waits for the first byte of a next request, and nothing is left to answer or to flush.
    waiting: bool,
}

/// What the gate and the service of one connection share: the queue of checked heads, and the count of the
/// responses that are complete.
pub struct Link {
    shared: Mutex<Shared>,
}

impl Link {
    /// `now` is the accept of the connection.
    pub fn new(now: Instant) -> Arc<Link> {
        Arc::new(Link {
            shared: Mutex::new(Shared {
                queue: VecDeque::new(),
                released: 0,
                completed: 0,
                last_done: now,
                parked: None,
                waiting: false,
            }),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Shared> {
        self.shared.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Takes the head of the oldest request that hyper has not handed over yet, if it is the one `parts` came
    /// from. `None` when there is no such head or it is another request: hyper and the head check disagree.
    pub fn take_for(&self, parts: &http::request::Parts) -> Option<Taken> {
        let (taken, waker) = {
            let mut shared = self.lock();
            let queued = shared.queue.pop_front()?;
            let start = queued.began.max(shared.last_done);
            let taken = same_head(&queued.head, parts).then_some(Taken {
                head: queued.head,
                start,
            });
            (taken, shared.parked.take())
        };
        if let Some(waker) = waker {
            waker.wake();
        }
        taken
    }

    /// The response of one request is complete, or it was cut off and the connection ends with it.
    fn done(&self, now: Instant) {
        let waker = {
            let mut shared = self.lock();
            shared.completed = shared.completed.saturating_add(1);
            shared.last_done = now;
            shared.parked.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// The guard that tells the gate when the response of a request is complete: it does so when it is dropped,
    /// which the response does once it has been written or the connection is gone.
    pub fn finish(self: &Arc<Link>) -> Finish {
        Finish(self.clone())
    }

    fn has_room(&self) -> bool {
        self.lock().queue.len() < QUEUE_MAX
    }

    /// Wakes `waker` when the queue has lost a head.
    fn park(&self, waker: &Waker) {
        self.lock().parked = Some(waker.clone());
    }

    fn push(&self, queued: Queued) {
        let mut shared = self.lock();
        shared.queue.push_back(queued);
        shared.released = shared.released.saturating_add(1);
    }

    /// The gate is, or is no longer, waiting for the first byte of a next request.
    fn set_waiting(&self, waiting: bool) {
        self.lock().waiting = waiting;
    }

    /// The connection waits for a next request: it has nothing to answer or to flush, and no byte of a next head.
    pub fn waiting(&self) -> bool {
        self.lock().waiting
    }

    /// The instant of the last answer if every request that was passed has been answered; otherwise `waker` is
    /// woken at the next answer.
    fn idle_since_or_park(&self, waker: &Waker) -> Option<Instant> {
        let mut shared = self.lock();
        if shared.released <= shared.completed {
            Some(shared.last_done)
        } else {
            shared.parked = Some(waker.clone());
            None
        }
    }
}

/// Dropped when the response of a request is complete. See `Link::finish`.
pub struct Finish(Arc<Link>);

impl Drop for Finish {
    fn drop(&mut self) {
        self.0.done(Instant::now());
    }
}

/// Whether hyper saw the same request as the head check: method, target, version, the number of fields and the
/// values of every name, in order and without the blanks around them.
pub fn same_head(head: &Head, parts: &http::request::Parts) -> bool {
    let version = if head.http10() {
        Version::HTTP_10
    } else {
        Version::HTTP_11
    };
    parts.method.as_str().as_bytes() == head.method()
        && parts.version == version
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

/// What a look for the next head found.
enum Look {
    /// A head passed: its bytes, and the bytes of its body, go on to hyper.
    Released,
    /// The stream ended between two requests.
    Eof,
    /// A head passed, and the queue is full.
    Blocked,
    /// The stream has nothing yet.
    Waiting,
}

/// The stream of a client connection, as hyper reads it. See the module documentation.
pub struct Gate<T> {
    inner: Guarded<T>,
    gauge: Gauge,
    settings: Settings,
    link: Arc<Link>,
    /// Bytes read from the stream that have not gone on: the head that is being collected, and what follows it.
    store: Box<[u8]>,
    lo: usize,
    hi: usize,
    /// Bytes that go on to hyper before the next head is looked for: the rest of the head that passed and its
    /// body. With `open`, everything goes on after them.
    pass: u64,
    open: bool,
    /// The store may hold a complete head that has not been looked at.
    scan: bool,
    /// The stream ended.
    eof: bool,
    /// The first byte of the head that is being collected (the accept, for the first head).
    began: Option<Instant>,
    /// The refusal of the head after the first one, which hyper is shown once the answers are done.
    failed: Option<Reject>,
    /// A head has been passed: the next one may be preceded by empty lines, and `blanks` of them were dropped.
    later: bool,
    blanks: u8,
    /// Hyper tried to write after the last flush that finished.
    unflushed: bool,
    /// When the last flush of written bytes finished (the accept before the first one).
    flushed: Instant,
    /// The read that waits for the flush.
    flush_waker: Option<Waker>,
    timer: Option<(Instant, Pin<Box<Sleep>>)>,
}

impl<T> Gate<T> {
    /// `accept` is the instant of the accept. The gauge counts the bytes read from `stream` and tells whether
    /// the cap of a chunked request was passed.
    pub fn new(
        stream: T,
        settings: Settings,
        link: Arc<Link>,
        accept: Instant,
    ) -> (Gate<T>, Gauge) {
        let (inner, gauge) = Guarded::new(
            stream,
            Bytes::new(),
            settings.read_idle,
            settings.write_idle,
            u64::MAX,
        );
        let gate = Gate {
            inner,
            gauge: gauge.clone(),
            settings,
            link,
            store: vec![0; settings.limits.max_head_bytes].into_boxed_slice(),
            lo: 0,
            hi: 0,
            pass: 0,
            open: false,
            scan: false,
            eof: false,
            began: Some(accept),
            failed: None,
            later: false,
            blanks: 0,
            unflushed: false,
            flushed: accept,
            flush_waker: None,
            timer: None,
        };
        (gate, gauge)
    }

    /// The stream, for what is done to it when hyper is done with the gate.
    pub fn stream(&mut self) -> &mut T {
        self.inner.get_mut()
    }

    /// The refusal that ended the connection, if a head after the first one was refused or did not come in time.
    pub fn failure(&self) -> Option<Reject> {
        self.failed
    }
}

impl<T: AsyncRead + Unpin> Gate<T> {
    /// Reads the first head of the connection, which must be complete before `by`. The head is queued and its
    /// bytes go on to hyper once it reads.
    pub async fn first_head(&mut self, by: Instant) -> Result<(), Reject> {
        let looked = timeout_at(
            by,
            poll_fn(|cx| match self.look(cx) {
                Ok(Look::Released) => Poll::Ready(Ok(true)),
                Ok(Look::Eof) => Poll::Ready(Ok(false)),
                Ok(Look::Blocked | Look::Waiting) => Poll::Pending,
                Err(reject) => Poll::Ready(Err(reject)),
            }),
        )
        .await;
        match looked {
            Err(_) => Err(Reject::Timeout),
            Ok(Ok(true)) => Ok(()),
            Ok(Ok(false)) => Err(Reject::Closed),
            Ok(Err(reject)) => Err(reject),
        }
    }

    /// Looks for the next head in what has been read, and reads more until there is one.
    fn look(&mut self, cx: &mut Context<'_>) -> Result<Look, Reject> {
        loop {
            if self.scan && self.hi > self.lo {
                self.scan = false;
                self.skip_blank_lines()?;
                if let Some(head) =
                    head::parse(&self.store[self.lo..self.hi], &self.settings.limits)?
                {
                    if !self.link.has_room() {
                        self.scan = true;
                        self.link.park(cx.waker());
                        return Ok(Look::Blocked);
                    }
                    self.release(head)?;
                    return Ok(Look::Released);
                }
            }
            if self.eof {
                return if self.lo == self.hi {
                    Ok(Look::Eof)
                } else {
                    Err(Reject::Closed)
                };
            }
            if self.lo == self.hi {
                self.lo = 0;
                self.hi = 0;
            }
            if self.hi == self.store.len() {
                if self.lo == 0 {
                    // Without a line end the request line is still incomplete.
                    return Err(if self.store.contains(&b'\n') {
                        Reject::FieldsTooLarge
                    } else {
                        Reject::UriTooLong
                    });
                }
                self.store.copy_within(self.lo..self.hi, 0);
                self.hi -= self.lo;
                self.lo = 0;
            }
            let mut buf = ReadBuf::new(&mut self.store[self.hi..]);
            match Pin::new(&mut self.inner).poll_read(cx, &mut buf) {
                Poll::Pending => return Ok(Look::Waiting),
                Poll::Ready(Err(_)) => return Err(Reject::Closed),
                Poll::Ready(Ok(())) => {}
            }
            let got = buf.filled().len();
            if got == 0 {
                self.eof = true;
                continue;
            }
            // The head can only become complete by a line feed, so a read without one is not looked at again.
            // A full store is looked at once more in any case.
            let before = self.hi;
            self.hi += got;
            self.scan = self.hi == self.store.len() || self.store[before..self.hi].contains(&b'\n');
            self.link.set_waiting(false);
            if self.began.is_none() {
                self.began = Some(Instant::now());
            }
        }
    }

    /// Drops the empty lines (a line end alone: CRLF, or LF as the parser takes it) in front of the head that is
    /// being collected, if a head has been passed before; the first head of a connection starts at its first byte.
    /// The bytes go nowhere, so hyper sees the head exactly as it was checked.
    fn skip_blank_lines(&mut self) -> Result<(), Reject> {
        if !self.later {
            return Ok(());
        }
        loop {
            let len = match self.store[self.lo..self.hi] {
                [b'\n', ..] => 1,
                [b'\r', b'\n', ..] => 2,
                _ => break,
            };
            if self.blanks == BLANK_LINES_MAX {
                return Err(Reject::BadRequest);
            }
            self.blanks += 1;
            self.lo += len;
        }
        // The time of the head counts from the first byte of its request line, not from the empty lines.
        if self.lo == self.hi {
            self.began = None;
        }
        Ok(())
    }

    /// Puts the head that passed into the queue and sets how many bytes go on.
    fn release(&mut self, head: Head) -> Result<(), Reject> {
        let extra = u64::try_from(self.hi - self.lo - head.len).unwrap_or(u64::MAX);
        let head_len = u64::try_from(head.len).unwrap_or(u64::MAX);
        if head.chunked() {
            // The bytes that are here count against the cap like every later byte.
            let room = self
                .settings
                .max_body_wire
                .checked_sub(extra)
                .ok_or(Reject::ContentTooLarge)?;
            self.gauge.limit(room);
            self.open = true;
            self.pass = head_len;
        } else {
            self.pass = head_len
                .checked_add(head.content_length().unwrap_or(0))
                .ok_or(Reject::ContentTooLarge)?;
        }
        let began = self.began.take().unwrap_or_else(Instant::now);
        self.link.push(Queued { head, began });
        self.later = true;
        self.blanks = 0;
        Ok(())
    }

    /// Hands bytes of the head that passed, or of its body, on to hyper.
    fn deliver(&mut self, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        // With a chunked request, what is left of the head goes first and then everything.
        let allowed = if self.pass > 0 { self.pass } else { u64::MAX };
        let want = usize::try_from(allowed).map_or(out.remaining(), |n| n.min(out.remaining()));
        if self.lo < self.hi {
            let n = want.min(self.hi - self.lo);
            out.put_slice(&self.store[self.lo..self.lo + n]);
            self.lo += n;
            self.passed(n);
            return Poll::Ready(Ok(()));
        }
        if self.eof {
            return Poll::Ready(Ok(()));
        }
        let window = out.initialize_unfilled_to(want);
        let mut part = ReadBuf::new(window);
        ready!(Pin::new(&mut self.inner).poll_read(cx, &mut part))?;
        let n = part.filled().len();
        out.advance(n);
        if n == 0 {
            self.eof = true;
        }
        self.passed(n);
        Poll::Ready(Ok(()))
    }

    /// `n` bytes went on. At the end of a body the next head is looked for, in what has been read already first.
    fn passed(&mut self, n: usize) {
        if self.lo == self.hi {
            self.lo = 0;
            self.hi = 0;
        }
        if self.pass == 0 {
            return;
        }
        self.pass = self
            .pass
            .saturating_sub(u64::try_from(n).unwrap_or(u64::MAX));
        if self.pass == 0 && !self.open {
            self.scan = true;
            if self.hi > self.lo {
                self.began = Some(Instant::now());
            }
        }
    }

    /// The instant since which every request that passed has been answered and everything hyper wrote has been
    /// flushed. Otherwise the waker is woken at the next answer or flush.
    fn quiet_since(&mut self, cx: &mut Context<'_>) -> Option<Instant> {
        let answered = self.link.idle_since_or_park(cx.waker())?;
        if self.unflushed {
            self.flush_waker = Some(cx.waker().clone());
            return None;
        }
        Some(answered.max(self.flushed))
    }

    /// Shows hyper the end of the stream for the refusal that was kept, once every request that passed has been
    /// answered and flushed; until then hyper is left waiting.
    fn surface(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.quiet_since(cx).is_some() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }

    /// The stream has nothing yet and no head is complete. A partial head has a time of its own; a connection
    /// with all its answers given and flushed has the time to wait for the next request; a connection that has a
    /// request in service, or a response not yet out, waits for it without a time, for the service and the
    /// writes have their own.
    fn wait(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let deadline = if self.hi > self.lo {
            self.link.set_waiting(false);
            let began = *self.began.get_or_insert_with(Instant::now);
            Some(after(began, self.settings.head_read))
        } else {
            // With a request still in service the gate is woken at its answer, and at the flush after it.
            let quiet = self.quiet_since(cx);
            self.link.set_waiting(quiet.is_some());
            quiet.map(|since| after(since, self.settings.keepalive_timeout))
        };
        let Some(at) = deadline else {
            self.timer = None;
            return Poll::Pending;
        };
        if self.timer.as_ref().map(|(was, _)| *was) != Some(at) {
            match self.timer.as_mut() {
                Some((was, sleep)) => {
                    sleep.as_mut().reset(at);
                    *was = at;
                }
                None => self.timer = Some((at, Box::pin(sleep_until(at)))),
            }
        }
        let up = self
            .timer
            .as_mut()
            .is_some_and(|(_, sleep)| sleep.as_mut().poll(cx).is_ready());
        if !up {
            return Poll::Pending;
        }
        if self.hi > self.lo {
            self.failed = Some(Reject::Timeout);
            self.surface(cx)
        } else {
            // Nothing came for the whole wait: the end of the stream, as if the client had closed it.
            Poll::Ready(Ok(()))
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Gate<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if this.pass > 0 || this.open {
                return this.deliver(cx, out);
            }
            if this.failed.is_some() {
                return this.surface(cx);
            }
            match this.look(cx) {
                Ok(Look::Released) => {}
                Ok(Look::Eof) | Err(Reject::Closed) => return Poll::Ready(Ok(())),
                Ok(Look::Blocked) => return Poll::Pending,
                Ok(Look::Waiting) => return this.wait(cx),
                Err(reject) => this.failed = Some(reject),
            }
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Gate<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.unflushed |= !buf.is_empty();
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_flush(cx);
        if this.unflushed && matches!(polled, Poll::Ready(Ok(()))) {
            this.unflushed = false;
            this.flushed = Instant::now();
            if let Some(waker) = this.flush_waker.take() {
                waker.wake();
            }
        }
        polled
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests;
