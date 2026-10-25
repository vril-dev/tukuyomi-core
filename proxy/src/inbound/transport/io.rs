//! The socket wrapper: bytes read ahead are returned first, a read or a write fails when it makes no progress for
//! too long, and the bytes read from the socket are counted against a cap.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use bytes::{Buf, Bytes};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep, sleep_until};

/// What a `Guarded` and its `Gauge` share.
struct Shared {
    /// Bytes read from the inner stream. Only the `Guarded` writes it.
    read: AtomicU64,
    cap: AtomicU64,
    lifted: AtomicBool,
    over: AtomicBool,
    /// The read idle period starts again, with the limit in `read_limit`, at the next read call. Only the `Guarded`
    /// clears it.
    restart: AtomicBool,
    /// The read idle limit of a restarted period, in nanoseconds, or `OFF`.
    read_limit: AtomicU64,
    /// The task that reads, to be woken when the period is restarted, so that a read that is pending does not
    /// wait for the end of the old period.
    reader: Mutex<Option<Waker>>,
    /// The last write could not go on: some bytes it was given are not written yet.
    blocked: AtomicBool,
}

impl Shared {
    /// Bytes that may still be read from the inner stream.
    fn room(&self) -> u64 {
        if self.lifted.load(Ordering::Acquire) {
            u64::MAX
        } else {
            self.cap
                .load(Ordering::Acquire)
                .saturating_sub(self.read.load(Ordering::Relaxed))
        }
    }

    fn count(&self, n: usize) {
        let n = u64::try_from(n).unwrap_or(u64::MAX);
        let total = self.read.load(Ordering::Relaxed).saturating_add(n);
        self.read.store(total, Ordering::Relaxed);
    }

    /// Notes the task that reads.
    fn park(&self, waker: &Waker) {
        let mut slot = self.reader.lock().unwrap_or_else(PoisonError::into_inner);
        if !slot.as_ref().is_some_and(|have| have.will_wake(waker)) {
            *slot = Some(waker.clone());
        }
    }

    /// Wakes the task that reads, if one has read. The lock is not held while it is woken.
    fn wake(&self) {
        let waker = self
            .reader
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

/// The value of `read_limit` that stands for no read idle limit at all (see `Gauge::pause`).
const OFF: u64 = u64::MAX;

/// A limit in nanoseconds, cut at the most that fits in 64 bits short of `OFF` (some 584 years).
fn nanos(limit: Duration) -> u64 {
    u64::try_from(limit.as_nanos()).unwrap_or(OFF).min(OFF - 1)
}

/// The idle limit of one direction. The timer starts at the first call that cannot go on and stops as soon as
/// something moved, so a call that is pending for longer than the limit without any progress fails, and a slow
/// call that keeps moving does not. Without a limit nothing fails.
struct Idle {
    limit: Option<Duration>,
    sleep: Option<Pin<Box<Sleep>>>,
    armed: bool,
}

impl Idle {
    fn new(limit: Duration) -> Idle {
        Idle {
            limit: Some(limit),
            sleep: None,
            armed: false,
        }
    }

    /// Bytes moved (or the end was reached): the next stall starts a new period.
    fn moved(&mut self) {
        self.armed = false;
    }

    /// The limit is `limit` from now on (`None`: there is none), and the next stall starts a new period.
    fn restart(&mut self, limit: Option<Duration>) {
        self.limit = limit;
        self.armed = false;
    }

    /// The call is pending. True when it has been without progress for the whole limit. A limit that does not
    /// fit into the clock never ends, and without a limit the call never fails.
    fn stalled(&mut self, cx: &mut Context<'_>) -> bool {
        let Some(limit) = self.limit else {
            return false;
        };
        if !self.armed {
            let Some(deadline) = Instant::now().checked_add(limit) else {
                return false;
            };
            match self.sleep.as_mut() {
                Some(sleep) => sleep.as_mut().reset(deadline),
                None => self.sleep = Some(Box::pin(sleep_until(deadline))),
            }
            self.armed = true;
        }
        match self.sleep.as_mut() {
            Some(sleep) => sleep.as_mut().poll(cx).is_ready(),
            None => false,
        }
    }

    /// Applies the limit to the result of one inner call.
    fn judge<R>(
        &mut self,
        cx: &mut Context<'_>,
        polled: Poll<io::Result<R>>,
    ) -> Poll<io::Result<R>> {
        match polled {
            Poll::Ready(done) => {
                if done.is_ok() {
                    self.moved();
                }
                Poll::Ready(done)
            }
            Poll::Pending if self.stalled(cx) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "no progress within the idle limit",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// A stream with three guards. Bytes given as `prefix` are read first and are not counted. At most `read_cap`
/// bytes are read from the inner stream: the read that would take the next byte fails and sets the over flag, and
/// every read after it fails too. A read or a write that is pending without progress for `read_idle` or
/// `write_idle` fails with `TimedOut`. The owner of the `Gauge` can change the read limit (`Gauge::restart`).
pub struct Guarded<T> {
    inner: T,
    prefix: Bytes,
    read_idle: Idle,
    write_idle: Idle,
    shared: Arc<Shared>,
}

/// The counts and flags of one `Guarded`, seen by its owner after the stream moved into hyper.
#[derive(Clone)]
pub struct Gauge {
    shared: Arc<Shared>,
}

impl<T> Guarded<T> {
    /// `prefix` is returned first and not counted. At most `read_cap` bytes are read from `inner`; the read of the
    /// next byte fails and sets the over flag. A read or a write that makes no progress for `read_idle` or
    /// `write_idle` fails with `TimedOut`.
    pub fn new(
        inner: T,
        prefix: Bytes,
        read_idle: Duration,
        write_idle: Duration,
        read_cap: u64,
    ) -> (Guarded<T>, Gauge) {
        let shared = Arc::new(Shared {
            read: AtomicU64::new(0),
            cap: AtomicU64::new(read_cap),
            lifted: AtomicBool::new(false),
            over: AtomicBool::new(false),
            restart: AtomicBool::new(false),
            read_limit: AtomicU64::new(nanos(read_idle)),
            reader: Mutex::new(None),
            blocked: AtomicBool::new(false),
        });
        let gauge = Gauge {
            shared: shared.clone(),
        };
        let guarded = Guarded {
            inner,
            prefix,
            read_idle: Idle::new(read_idle),
            write_idle: Idle::new(write_idle),
            shared,
        };
        (guarded, gauge)
    }
}

impl<T> Guarded<T> {
    /// The inner stream, for what is done to it after the connection that used this wrapper has ended.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

fn over_error() -> io::Error {
    io::Error::other("read limit exceeded")
}

impl<T: AsyncRead + Unpin> AsyncRead for Guarded<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        // The task is noted before the flag is looked at, so a restart that comes after the look wakes it.
        this.shared.park(cx.waker());
        if this.shared.restart.swap(false, Ordering::AcqRel) {
            let limit = this.shared.read_limit.load(Ordering::Acquire);
            this.read_idle
                .restart((limit != OFF).then(|| Duration::from_nanos(limit)));
        }
        if !this.prefix.is_empty() {
            let n = this.prefix.len().min(buf.remaining());
            buf.put_slice(&this.prefix[..n]);
            this.prefix.advance(n);
            if this.prefix.is_empty() {
                this.prefix = Bytes::new();
            }
            this.read_idle.moved();
            return Poll::Ready(Ok(()));
        }
        if this.shared.over.load(Ordering::Acquire) {
            return Poll::Ready(Err(over_error()));
        }
        let room = this.shared.room();
        if room == 0 {
            // The cap is used up. One more byte decides: the end of the stream is fine, a byte is over the cap.
            let mut one = [0u8; 1];
            let mut probe = ReadBuf::new(&mut one);
            let polled = Pin::new(&mut this.inner)
                .poll_read(cx, &mut probe)
                .map_ok(|()| probe.filled().len());
            return match this.read_idle.judge(cx, polled) {
                Poll::Ready(Ok(0)) => Poll::Ready(Ok(())),
                Poll::Ready(Ok(_)) => {
                    this.shared.over.store(true, Ordering::Release);
                    Poll::Ready(Err(over_error()))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            };
        }
        let want = usize::try_from(room).map_or(buf.remaining(), |room| room.min(buf.remaining()));
        let window = buf.initialize_unfilled_to(want);
        let mut part = ReadBuf::new(window);
        let polled = Pin::new(&mut this.inner)
            .poll_read(cx, &mut part)
            .map_ok(|()| part.filled().len());
        match this.read_idle.judge(cx, polled) {
            Poll::Ready(Ok(n)) => {
                buf.advance(n);
                this.shared.count(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Guarded<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_write(cx, buf);
        this.shared
            .blocked
            .store(polled.is_pending(), Ordering::Release);
        this.write_idle.judge(cx, polled)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_flush(cx);
        this.write_idle.judge(cx, polled)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_shutdown(cx);
        this.write_idle.judge(cx, polled)
    }
}

impl Gauge {
    /// A read was refused because it would pass the cap (that read returned an I/O error).
    pub fn over(&self) -> bool {
        self.shared.over.load(Ordering::Acquire)
    }

    /// The last write could not go on, so bytes that the writer handed over are still waiting to be written: a
    /// peer that does not read keeps them there. It is false again as soon as a write goes through.
    pub fn write_blocked(&self) -> bool {
        self.shared.blocked.load(Ordering::Acquire)
    }

    /// Bytes read from `inner` so far; the prefix is not counted.
    pub fn read(&self) -> u64 {
        self.shared.read.load(Ordering::Relaxed)
    }

    /// No cap from now on; the counting goes on. A read that was already refused stays refused.
    pub fn lift(&self) {
        self.shared.lifted.store(true, Ordering::Release);
    }

    /// A new cap: at most `more` bytes may be read from the inner stream after the ones counted so far. The bytes
    /// counted stay counted. A read that was already refused stays refused.
    pub fn limit(&self, more: u64) {
        let total = self
            .shared
            .read
            .load(Ordering::Relaxed)
            .saturating_add(more);
        self.shared.cap.store(total, Ordering::Release);
    }

    /// The read idle limit is `limit` from now on, and its period starts again at once, not at the time the
    /// stream went quiet. This holds for a read that is pending as well as for the next one: the task that reads
    /// is woken. A stream that waits for another exchange is kept to a shorter limit this way.
    pub fn restart(&self, limit: Duration) {
        self.set_limit(nanos(limit));
    }

    /// There is no read idle limit from now on, until `restart` or `rearm` gives one: a read that is pending waits
    /// as long as it takes (the task that reads is woken, as for `restart`). For an exchange whose wait for the
    /// stream is bounded by something else.
    pub fn pause(&self) {
        self.set_limit(OFF);
    }

    fn set_limit(&self, limit: u64) {
        self.shared.read_limit.store(limit, Ordering::Release);
        self.shared.restart.store(true, Ordering::Release);
        self.shared.wake();
    }

    /// For a stream that is used for another exchange after it waited: the cap is back as a new one of `more`
    /// bytes (see `limit`), and the read idle limit is `read_idle` with a period that counts from now (see
    /// `restart`). A read that was already refused stays refused.
    pub fn rearm(&self, more: u64, read_idle: Duration) {
        self.limit(more);
        self.shared.lifted.store(false, Ordering::Release);
        self.restart(read_idle);
    }
}

#[cfg(test)]
mod tests;
