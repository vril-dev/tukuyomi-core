use std::task::{Context, Waker};

use tokio::io::ReadBuf;

use super::*;

/// A writer that keeps what it is given until it is flushed, as a TLS stream does when its socket cannot take more.
#[derive(Default)]
struct Holding {
    queued: Vec<u8>,
    sent: Vec<u8>,
    ended: bool,
}

impl AsyncWrite for Holding {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().queued.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let queued = std::mem::take(&mut this.queued);
        this.sent.extend(queued);
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().ended = true;
        Poll::Ready(Ok(()))
    }
}

/// A reader that gives its bytes once and then has nothing ready for ever, without ending.
struct OneChunk(Option<Vec<u8>>);

impl AsyncRead for OneChunk {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.0.take() {
            Some(bytes) => {
                buf.put_slice(&bytes);
                Poll::Ready(Ok(()))
            }
            None => Poll::Pending,
        }
    }
}

#[test]
fn what_was_written_is_flushed_when_the_reader_has_nothing_ready_and_not_only_at_its_end() {
    let mut writer = Holding::default();
    {
        let mut copy = pin!(pump(
            OneChunk(Some(b"end of a message".to_vec())),
            &mut writer
        ));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(copy.as_mut().poll(&mut cx).is_pending());
    }
    assert_eq!(writer.sent, b"end of a message");
    assert!(!writer.ended);
}

#[test]
fn the_end_of_the_reader_flushes_the_writer_and_ends_its_writing_direction() {
    let mut writer = Holding::default();
    {
        let mut copy = pin!(pump(&b"abc"[..], &mut writer));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(copy.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));
    }
    assert_eq!(writer.sent, b"abc");
    assert!(writer.ended);
}
