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
fn lift_removes_the_cap_and_the_counting_goes_on() {
    run(async {
        let mock = Mock::default();
        mock.feed(b"0123456789");
        let (mut io, gauge) = guarded(&mock, b"", LONG, LONG, 4);
        assert_eq!(read_some(&mut io, 16).await.unwrap(), b"0123");
        gauge.lift();
        assert_eq!(read_some(&mut io, 16).await.unwrap(), b"456789");
        assert_eq!((gauge.read(), gauge.over()), (10, false));
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
fn limit_sets_a_cap_that_counts_from_the_bytes_read_so_far() {
    run(async {
        let mock = Mock::default();
        mock.feed(b"0123456789");
        let (mut io, gauge) = guarded(&mock, b"", LONG, LONG, u64::MAX);
        assert_eq!(read_some(&mut io, 3).await.unwrap(), b"012");
        gauge.limit(4);
        assert_eq!(read_some(&mut io, 16).await.unwrap(), b"3456");
        assert_eq!((gauge.read(), gauge.over()), (7, false));
        // The next byte is over the cap, and the end of the stream is not.
        assert!(read_some(&mut io, 16).await.is_err());
        assert_eq!((gauge.read(), gauge.over()), (7, true));
    });
}

#[test]
fn rearm_gives_a_new_cap_and_a_new_idle_period() {
    run(async {
        let idle = Duration::from_millis(600);
        let mock = Mock::default();
        mock.feed(b"0123");
        let (mut io, gauge) = guarded(&mock, b"", idle, LONG, 4);
        assert_eq!(read_some(&mut io, 16).await.unwrap(), b"0123");
        gauge.lift();
        // The stream goes quiet: a read that waits starts the idle period, and the period runs out.
        assert!(
            timeout(Duration::from_millis(200), read_some(&mut io, 16))
                .await
                .is_err()
        );
        sleep(Duration::from_millis(500)).await;
        let err = read_some(&mut io, 16).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        // Used again: the period counts from now, so a wait shorter than the limit is not cut off.
        gauge.rearm(4, idle);
        assert!(
            timeout(Duration::from_millis(300), read_some(&mut io, 16))
                .await
                .is_err()
        );
        // The cap is back, counted from the bytes read so far, and nothing was lost.
        mock.feed(b"abcdefg");
        assert_eq!(read_some(&mut io, 16).await.unwrap(), b"abcd");
        assert_eq!((gauge.read(), gauge.over()), (8, false));
        assert!(read_some(&mut io, 16).await.is_err());
        assert_eq!((gauge.read(), gauge.over()), (8, true));
    });
}

#[test]
fn a_write_that_cannot_go_on_is_reported_until_it_goes_on() {
    run(async {
        let mock = Mock::default();
        let (mut io, gauge) = guarded(&mock, b"", LONG, LONG, 100);
        assert!(!gauge.write_blocked());
        let writing = tokio::spawn(async move { write_some(&mut io, b"abc").await });
        sleep(Duration::from_millis(50)).await;
        assert!(gauge.write_blocked());
        mock.allow_writes();
        assert_eq!(writing.await.unwrap().unwrap(), 3);
        assert!(!gauge.write_blocked());
    });
}

#[test]
fn restart_changes_the_limit_of_a_read_that_is_already_pending() {
    run(async {
        let mock = Mock::default();
        let (mut io, gauge) = guarded(&mock, b"", LONG, LONG, 100);
        let reading = tokio::spawn(async move { read_some(&mut io, 8).await });
        // The read waits under the long limit. It is not polled again by anything but the restart.
        sleep(Duration::from_millis(100)).await;
        let start = StdInstant::now();
        gauge.restart(Duration::from_millis(300));
        let err = reading.await.unwrap().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() >= Duration::from_millis(250));
        assert!(start.elapsed() < Duration::from_secs(10));
    });
}

#[test]
fn pause_takes_the_read_limit_from_a_read_that_is_already_pending_and_restart_gives_one_again() {
    run(async {
        let mock = Mock::default();
        let (mut io, gauge) = guarded(&mock, b"", Duration::from_millis(300), LONG, 100);
        let reading = tokio::spawn(async move {
            let got = read_some(&mut io, 8).await;
            (io, got)
        });
        sleep(Duration::from_millis(100)).await;
        gauge.pause();
        // Twice the limit it had passes, and the read still waits.
        sleep(Duration::from_millis(600)).await;
        assert!(!reading.is_finished());
        mock.feed(b"a");
        let (mut io, got) = reading.await.unwrap();
        assert_eq!(got.unwrap(), b"a");
        gauge.restart(Duration::from_millis(200));
        let start = StdInstant::now();
        let err = read_some(&mut io, 8).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() >= Duration::from_millis(150));
        assert!(start.elapsed() < Duration::from_secs(10));
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
