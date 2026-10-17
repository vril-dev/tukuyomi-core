//! The socket wrapper: bytes read ahead are returned first, a read or a write fails when it makes no progress for
//! too long, and the bytes read from the socket are counted against a cap.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Buf, Bytes};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep, sleep_until};

/// What a `Guarded` and its `Gauge` share.
struct Shared {
    /// Bytes read from the inner stream. Only the `Guarded` writes it.
    read: AtomicU64,
    cap: u64,
    lifted: AtomicBool,
    over: AtomicBool,
}

impl Shared {
    /// Bytes that may still be read from the inner stream.
    fn room(&self) -> u64 {
        if self.lifted.load(Ordering::Acquire) {
            u64::MAX
        } else {
            self.cap.saturating_sub(self.read.load(Ordering::Relaxed))
        }
    }

    fn count(&self, n: usize) {
        let n = u64::try_from(n).unwrap_or(u64::MAX);
        let total = self.read.load(Ordering::Relaxed).saturating_add(n);
        self.read.store(total, Ordering::Relaxed);
    }
}

/// The idle limit of one direction. The timer starts at the first call that cannot go on and stops as soon as
/// something moved, so a call that is pending for longer than the limit without any progress fails, and a slow
/// call that keeps moving does not.
struct Idle {
    limit: Duration,
    sleep: Option<Pin<Box<Sleep>>>,
    armed: bool,
}

impl Idle {
    fn new(limit: Duration) -> Idle {
        Idle {
            limit,
            sleep: None,
            armed: false,
        }
    }

    /// Bytes moved (or the end was reached): the next stall starts a new period.
    fn moved(&mut self) {
        self.armed = false;
    }

    /// The call is pending. True when it has been without progress for the whole limit. A limit that does not
    /// fit into the clock never ends.
    fn stalled(&mut self, cx: &mut Context<'_>) -> bool {
        if !self.armed {
            let Some(deadline) = Instant::now().checked_add(self.limit) else {
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
/// `write_idle` fails with `TimedOut`.
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
            cap: read_cap,
            lifted: AtomicBool::new(false),
            over: AtomicBool::new(false),
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

    /// Bytes read from `inner` so far; the prefix is not counted.
    pub fn read(&self) -> u64 {
        self.shared.read.load(Ordering::Relaxed)
    }

    /// No cap from now on; the counting goes on. A read that was already refused stays refused.
    pub fn lift(&self) {
        self.shared.lifted.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests;
