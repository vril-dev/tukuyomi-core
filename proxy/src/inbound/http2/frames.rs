//! A look at the frames that a client of HTTP/2 sends, in front of hyper, to give the preface and the header blocks
//! a time that hyper and h2 do not give them: a client may send them one byte at a time for as long as it likes.
//!
//! `Watch` is the stream as hyper reads it. It hands every byte on unchanged and only follows the frames: the 24
//! bytes of the preface, the head of every frame (9 bytes: the length, the type and the flags), and which frames
//! carry a header block, that is `HEADERS` and the `CONTINUATION` frames after it up to the one with `END_HEADERS`.
//! The payloads are skipped by their lengths, so what hyper does with them is not looked at, and a frame that is
//! wrong is left to hyper to refuse.
//!
//! The preface has to be complete by the instant the caller gives (the first head of a plain connection has the
//! same one). A header block has `head_read` from the first byte of its `HEADERS` frame to the last byte of the
//! frame that ends it, however many frames that takes. Nothing else has a time here: a connection that sends no
//! request is ended by `drive`, and a body has the times of `conn`. When a time has passed the read fails with
//! `TimedOut`, once, and again at every later read, and `timed_out` tells that this was the reason. The time is
//! counted in the reads, so it needs hyper to read the connection, which it does while it waits for a preface or a
//! header block.
//!
//! The writes go through to the stream. The end of the writing direction does not: whoever owns the watch closes the
//! connection when it has decided how.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep, sleep_until};

use crate::inbound::conn::after;
use crate::inbound::transport::io::{Gauge, Guarded};

/// The bytes of the connection preface of a client.
const PREFACE: usize = 24;
/// The bytes of the head of a frame.
const FRAME_HEAD: usize = 9;
/// The types of the frames that carry a header block, and the flag of the one that ends it.
const HEADERS: u8 = 0x1;
const CONTINUATION: u8 = 0x9;
const END_HEADERS: u8 = 0x4;

/// The stream of a client connection, as hyper reads it. See the module documentation.
pub(super) struct Watch<T> {
    inner: Guarded<T>,
    /// When the preface has to be complete, and how long a header block may take.
    preface_by: Instant,
    block_limit: Duration,
    /// Bytes of the preface that are still to come.
    preface_left: usize,
    /// The head of the frame that is being read.
    head: [u8; FRAME_HEAD],
    head_have: usize,
    /// Bytes of the payload of the frame that are still to come.
    skip: usize,
    /// A header block has begun and is not complete.
    in_block: bool,
    /// The frame that is being read ends the block.
    ends_block: bool,
    /// The first byte of the frame that may begin a header block, or of the header block that is going on.
    since: Option<Instant>,
    timer: Option<(Instant, Pin<Box<Sleep>>)>,
    timed_out: bool,
}

impl<T> Watch<T> {
    /// `preface_by` is when the preface has to be complete and `block_limit` the time of a header block. The gauge
    /// counts the bytes read from `stream`, which fails a read or a write that makes no progress for `read_idle`
    /// or `write_idle` (see `Guarded`).
    pub(super) fn new(
        stream: T,
        preface_by: Instant,
        block_limit: Duration,
        read_idle: Duration,
        write_idle: Duration,
    ) -> (Watch<T>, Gauge) {
        let (inner, gauge) = Guarded::new(stream, Bytes::new(), read_idle, write_idle, u64::MAX);
        let watch = Watch {
            inner,
            preface_by,
            block_limit,
            preface_left: PREFACE,
            head: [0; FRAME_HEAD],
            head_have: 0,
            skip: 0,
            in_block: false,
            ends_block: false,
            since: None,
            timer: None,
            timed_out: false,
        };
        (watch, gauge)
    }

    /// The stream, for what is done to it when hyper is done with the watch.
    pub(super) fn stream(&mut self) -> &mut T {
        self.inner.get_mut()
    }

    /// A read failed because the preface or a header block did not come in time.
    pub(super) fn timed_out(&self) -> bool {
        self.timed_out
    }

    /// Follows `bytes`, which were read from the stream.
    fn feed(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            if self.preface_left > 0 {
                let n = self.preface_left.min(bytes.len());
                self.preface_left -= n;
                bytes = &bytes[n..];
            } else if self.skip > 0 {
                let n = self.skip.min(bytes.len());
                self.skip -= n;
                bytes = &bytes[n..];
                if self.skip == 0 {
                    self.frame_done();
                }
            } else {
                if self.head_have == 0 && self.since.is_none() {
                    // It may be the first byte of a header block: the type is known only with the whole head.
                    self.since = Some(Instant::now());
                }
                let n = (FRAME_HEAD - self.head_have).min(bytes.len());
                self.head[self.head_have..self.head_have + n].copy_from_slice(&bytes[..n]);
                self.head_have += n;
                bytes = &bytes[n..];
                if self.head_have == FRAME_HEAD {
                    self.head_have = 0;
                    self.frame_head();
                }
            }
        }
    }

    /// The head of a frame is complete. A frame that does not carry a header block has no time, unless it comes in the
    /// middle of one.
    fn frame_head(&mut self) {
        let [a, b, c, kind, flags, ..] = self.head;
        if kind == HEADERS || kind == CONTINUATION {
            self.in_block = true;
            self.ends_block = flags & END_HEADERS != 0;
        } else if !self.in_block {
            self.since = None;
        }
        self.skip = usize::try_from(u32::from_be_bytes([0, a, b, c])).unwrap_or(usize::MAX);
        if self.skip == 0 {
            self.frame_done();
        }
    }

    /// The last byte of a frame has been read: the header block is complete if the frame ends it.
    fn frame_done(&mut self) {
        if self.ends_block {
            self.in_block = false;
            self.ends_block = false;
            self.since = None;
        }
    }

    /// The instant by which what is being read has to be complete, if it has a time.
    fn deadline(&self) -> Option<Instant> {
        if self.preface_left > 0 {
            Some(self.preface_by)
        } else {
            self.since.map(|since| after(since, self.block_limit))
        }
    }

    /// Whether `at` has passed; the task is woken when it does.
    fn passed(&mut self, at: Instant, cx: &mut Context<'_>) -> bool {
        if self.timer.as_ref().map(|(was, _)| *was) != Some(at) {
            match self.timer.as_mut() {
                Some((was, sleep)) => {
                    sleep.as_mut().reset(at);
                    *was = at;
                }
                None => self.timer = Some((at, Box::pin(sleep_until(at)))),
            }
        }
        self.timer
            .as_mut()
            .is_some_and(|(_, sleep)| sleep.as_mut().poll(cx).is_ready())
    }
}

fn timed_out() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "the preface or a header block did not come in time",
    )
}

impl<T: AsyncRead + Unpin> AsyncRead for Watch<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.timed_out {
            return Poll::Ready(Err(timed_out()));
        }
        let before = buf.filled().len();
        let polled = Pin::new(&mut this.inner).poll_read(cx, buf);
        if matches!(polled, Poll::Ready(Ok(()))) {
            this.feed(&buf.filled()[before..]);
        }
        match this.deadline() {
            Some(at) if this.passed(at, cx) => {
                this.timed_out = true;
                Poll::Ready(Err(timed_out()))
            }
            Some(_) => polled,
            None => {
                this.timer = None;
                polled
            }
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Watch<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests;
