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
mod tests {
    use std::collections::VecDeque;
    use std::future::{Future, poll_fn};
    use std::sync::Mutex;
    use std::task::{Waker, ready};
    use std::time::Instant as StdInstant;

    use tokio::runtime::{Builder, Runtime};
    use tokio::time::{sleep, timeout};

    use super::*;

    const LONG: Duration = Duration::from_secs(60);

    #[derive(Default)]
    struct Pipe {
        data: VecDeque<u8>,
        eof: bool,
        read_waker: Option<Waker>,
        written: Vec<u8>,
        writable: bool,
        write_waker: Option<Waker>,
    }

    /// An inner stream that the test feeds. A read with nothing to give and a write that is not allowed are
    /// pending until the test lets them go on.
    #[derive(Clone, Default)]
    struct Mock(Arc<Mutex<Pipe>>);

    impl Mock {
        fn feed(&self, bytes: &[u8]) {
            let mut pipe = self.0.lock().unwrap();
            pipe.data.extend(bytes);
            if let Some(waker) = pipe.read_waker.take() {
                waker.wake();
            }
        }

        fn finish(&self) {
            let mut pipe = self.0.lock().unwrap();
            pipe.eof = true;
            if let Some(waker) = pipe.read_waker.take() {
                waker.wake();
            }
        }

        fn allow_writes(&self) {
            let mut pipe = self.0.lock().unwrap();
            pipe.writable = true;
            if let Some(waker) = pipe.write_waker.take() {
                waker.wake();
            }
        }

        fn left(&self) -> usize {
            self.0.lock().unwrap().data.len()
        }

        fn written(&self) -> Vec<u8> {
            self.0.lock().unwrap().written.clone()
        }
    }

    impl AsyncRead for Mock {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let mut pipe = self.0.lock().unwrap();
            if pipe.data.is_empty() {
                if pipe.eof {
                    return Poll::Ready(Ok(()));
                }
                pipe.read_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            let n = pipe.data.len().min(buf.remaining());
            let chunk: Vec<u8> = pipe.data.drain(..n).collect();
            buf.put_slice(&chunk);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for Mock {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let mut pipe = self.0.lock().unwrap();
            if !pipe.writable {
                pipe.write_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            pipe.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn runtime() -> Runtime {
        Builder::new_current_thread().enable_time().build().unwrap()
    }

    /// Runs the test body; a body that hangs fails the test instead of the run.
    fn run<F: Future>(body: F) -> F::Output {
        runtime().block_on(async {
            timeout(Duration::from_secs(30), body)
                .await
                .expect("the test hung")
        })
    }

    async fn read_some<T: AsyncRead + Unpin>(io: &mut T, room: usize) -> io::Result<Vec<u8>> {
        let mut out = vec![0u8; room];
        let n = poll_fn(|cx| {
            let mut buf = ReadBuf::new(&mut out);
            ready!(Pin::new(&mut *io).poll_read(cx, &mut buf))?;
            Poll::Ready(Ok::<usize, io::Error>(buf.filled().len()))
        })
        .await?;
        out.truncate(n);
        Ok(out)
    }

    async fn write_some<T: AsyncWrite + Unpin>(io: &mut T, bytes: &[u8]) -> io::Result<usize> {
        poll_fn(|cx| Pin::new(&mut *io).poll_write(cx, bytes)).await
    }

    fn guarded(
        mock: &Mock,
        prefix: &[u8],
        read_idle: Duration,
        write_idle: Duration,
        cap: u64,
    ) -> (Guarded<Mock>, Gauge) {
        Guarded::new(
            mock.clone(),
            Bytes::copy_from_slice(prefix),
            read_idle,
            write_idle,
            cap,
        )
    }

    #[test]
    fn the_prefix_comes_first_and_is_not_counted() {
        run(async {
            let mock = Mock::default();
            mock.feed(b"WORLD");
            let (mut io, gauge) = guarded(&mock, b"HELLO ", LONG, LONG, 5);
            assert_eq!(read_some(&mut io, 2).await.unwrap(), b"HE");
            assert_eq!(read_some(&mut io, 100).await.unwrap(), b"LLO ");
            assert_eq!((gauge.read(), gauge.over()), (0, false));
            assert_eq!(read_some(&mut io, 100).await.unwrap(), b"WORLD");
            assert_eq!((gauge.read(), gauge.over()), (5, false));
            // The cap is used up and the stream ends there: that is the end of the stream, not an excess.
            mock.finish();
            assert_eq!(read_some(&mut io, 100).await.unwrap(), b"");
            assert!(!gauge.over());
        });
    }

    #[test]
    fn the_read_of_the_next_byte_fails_and_stays_failed() {
        run(async {
            let mock = Mock::default();
            mock.feed(b"0123456789");
            let (mut io, gauge) = guarded(&mock, b"", LONG, LONG, 4);
            // A buffer larger than the cap still gets no more than the cap.
            assert_eq!(read_some(&mut io, 16).await.unwrap(), b"0123");
            assert_eq!((gauge.read(), gauge.over()), (4, false));
            assert!(read_some(&mut io, 16).await.is_err());
            assert_eq!((gauge.read(), gauge.over()), (4, true));
            // Once refused, every later read is refused, whatever the inner stream does.
            assert!(read_some(&mut io, 16).await.is_err());
            mock.finish();
            assert!(read_some(&mut io, 16).await.is_err());
            assert_eq!(gauge.read(), 4);
        });
    }

    #[test]
    fn a_cap_of_zero_refuses_any_byte_but_accepts_the_end() {
        run(async {
            let mock = Mock::default();
            mock.finish();
            let (mut io, gauge) = guarded(&mock, b"", LONG, LONG, 0);
            assert_eq!(read_some(&mut io, 8).await.unwrap(), b"");
            assert!(!gauge.over());
            let mock = Mock::default();
            mock.feed(b"x");
            let (mut io, gauge) = guarded(&mock, b"", LONG, LONG, 0);
            assert!(read_some(&mut io, 8).await.is_err());
            assert!(gauge.over());
        });
    }

    #[test]
    fn lift_removes_the_cap_and_the_counting_goes_on() {
        run(async {
            let mock = Mock::default();
            mock.feed(b"0123456789");
            let (mut io, gauge) = guarded(&mock, b"", LONG, LONG, 4);
            assert_eq!(read_some(&mut io, 16).await.unwrap(), b"0123");
            gauge.lift();
            assert_eq!(read_some(&mut io, 16).await.unwrap(), b"456789");
            assert_eq!((gauge.read(), gauge.over()), (10, false));
            mock.feed(b"more");
            assert_eq!(read_some(&mut io, 16).await.unwrap(), b"more");
            assert_eq!(gauge.read(), 14);
            // A read that was refused before the lift stays refused.
            let mock = Mock::default();
            mock.feed(b"01234");
            let (mut io, gauge) = guarded(&mock, b"", LONG, LONG, 4);
            assert_eq!(read_some(&mut io, 16).await.unwrap(), b"0123");
            assert!(read_some(&mut io, 16).await.is_err());
            gauge.lift();
            assert!(gauge.over());
            assert!(read_some(&mut io, 16).await.is_err());
        });
    }

    #[test]
    fn a_read_without_progress_times_out_and_a_slow_one_that_moves_does_not() {
        run(async {
            let idle = Duration::from_millis(400);
            let mock = Mock::default();
            let (mut io, _gauge) = guarded(&mock, b"", idle, LONG, 100);
            let feeder = mock.clone();
            tokio::spawn(async move {
                sleep(Duration::from_millis(200)).await;
                feeder.feed(b"a");
                sleep(Duration::from_millis(200)).await;
                feeder.feed(b"b");
            });
            // 400 ms pass in all, but neither wait lasts as long as the limit.
            assert_eq!(read_some(&mut io, 8).await.unwrap(), b"a");
            assert_eq!(read_some(&mut io, 8).await.unwrap(), b"b");
            let start = StdInstant::now();
            let err = read_some(&mut io, 8).await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::TimedOut);
            assert!(start.elapsed() >= Duration::from_millis(350));
            assert!(start.elapsed() < Duration::from_secs(10));
        });
    }

    #[test]
    fn a_write_without_progress_times_out_and_a_slow_one_that_moves_does_not() {
        run(async {
            let idle = Duration::from_millis(400);
            let mock = Mock::default();
            let (mut io, _gauge) = guarded(&mock, b"", LONG, idle, 100);
            let start = StdInstant::now();
            let err = write_some(&mut io, b"abc").await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::TimedOut);
            assert!(start.elapsed() >= Duration::from_millis(350));
            assert!(start.elapsed() < Duration::from_secs(10));
            assert!(mock.written().is_empty());
            // A write that gets through after a wait shorter than the limit is not cut off.
            let mock = Mock::default();
            let (mut io, _gauge) = guarded(&mock, b"", LONG, idle, 100);
            let opener = mock.clone();
            tokio::spawn(async move {
                sleep(Duration::from_millis(150)).await;
                opener.allow_writes();
            });
            assert_eq!(write_some(&mut io, b"abc").await.unwrap(), 3);
            assert_eq!(mock.written(), b"abc");
        });
    }

    #[test]
    fn a_limit_that_does_not_fit_into_the_clock_never_ends() {
        run(async {
            let mock = Mock::default();
            let (mut io, _gauge) = guarded(&mock, b"", Duration::MAX, Duration::MAX, 100);
            let feeder = mock.clone();
            tokio::spawn(async move {
                sleep(Duration::from_millis(50)).await;
                feeder.feed(b"a");
                feeder.allow_writes();
            });
            assert_eq!(read_some(&mut io, 8).await.unwrap(), b"a");
            assert_eq!(write_some(&mut io, b"b").await.unwrap(), 1);
            assert_eq!(mock.left(), 0);
        });
    }
}
