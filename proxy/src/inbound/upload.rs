//! The rest of a request body, passed on to the upstream while it is read from the client.
//!
//! A body that is longer than the bytes that are inspected is not held. `conn` reads its first bytes into the byte
//! budget and inspects them; once the request is let through, `Upload` is the body that follows those bytes: it hands
//! each piece to the upstream as the client's connection delivers it, so what is held does not grow with the
//! length of the body. `pending` is the part of the last piece read for the inspection that lies behind those bytes.
//!
//! The pieces are counted against the limit of the request (`max`), which for a chunked body is the only place the
//! length is checked; a body with a length was checked against the limit before it was read. Between two reads the
//! client has `gap` (`body_read`), and the request as a whole has until `by` (the end of the request time). When any of
//! that fails, or the client's body is not valid, or the client goes away, the body fails and the request to the
//! upstream is abandoned. The reason is kept in the `Fate`, which `conn` reads, because the error that reaches the
//! caller is the one of the upstream's connection and says nothing of the client.
//!
//! `read_done` tells the connection that the body was read to its end, which is true as soon as the last byte of a
//! body with a length is here, and at the end of a chunked body. The `Fate` says when the last piece has been handed
//! to the upstream's connection as well (`handed`), and `watch` tells the exchange with the upstream, which then
//! starts the time that the upstream has to answer (see `origin`).

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body::{Body, Frame};
use hyper::body::Incoming;
use tokio::sync::watch;
use tokio::time::{Instant, Sleep, sleep_until};

use crate::inbound::conn::{after, peer_gone};
use crate::inbound::transport::io::Gauge;

/// Why the body of a request failed while it was passed on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Cause {
    /// The client sent nothing for `body_read`.
    Idle,
    /// The end of the request time came.
    Late,
    /// The body passed the limit (only a body without a length can).
    Over,
    /// The body has trailers.
    Trailers,
    /// The client's connection has read the most bytes it may.
    Wire,
    /// The client went away.
    Gone,
    /// The body is not valid.
    Malformed,
}

/// What `conn` learns about an upload after the request to the upstream has ended: the first reason it failed, how
/// many bytes of the body have been read from the client (the bytes held for the inspection included), and whether
/// the whole body had been handed to the upstream's connection.
pub(super) struct Fate {
    cause: OnceLock<Cause>,
    seen: AtomicU64,
    handed: watch::Sender<bool>,
}

impl Fate {
    pub(super) fn cause(&self) -> Option<Cause> {
        self.cause.get().copied()
    }

    /// The client's body was read to its end and its last piece was handed on.
    pub(super) fn handed(&self) -> bool {
        *self.handed.borrow()
    }

    pub(super) fn seen(&self) -> u64 {
        self.seen.load(Ordering::Relaxed)
    }
}

/// The error of an upload that failed. The reason is in the `Fate`.
#[derive(Debug)]
pub struct Cut;

impl fmt::Display for Cut {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("request body failed while it was passed on")
    }
}

impl std::error::Error for Cut {}

/// What bounds an upload.
pub(super) struct Terms {
    /// The length of the whole body, if it has one.
    pub(super) length: Option<u64>,
    /// The most bytes the body may have.
    pub(super) max: u64,
    /// The longest the client may be silent.
    pub(super) gap: Duration,
    /// The end of the request time.
    pub(super) by: Instant,
}

/// The rest of the body of a request: what was read behind the inspected bytes, and what the client still sends.
pub struct Upload {
    pending: Bytes,
    body: Incoming,
    terms: Terms,
    /// Bytes read from the client, the ones held for the inspection included.
    seen: u64,
    /// What the client still has to send, if the body has a length.
    left: Option<u64>,
    /// The client's body gave its end.
    ended: bool,
    /// The body failed: it gives an error from then on.
    failed: bool,
    timer: Option<Pin<Box<Sleep>>>,
    /// The timer in `timer` ends at the end of the request time, not at the end of the gap.
    late: bool,
    read_done: Arc<AtomicBool>,
    client: Gauge,
    fate: Arc<Fate>,
}

impl Upload {
    /// The rest of `body`, behind `held` bytes that were read for the inspection and `pending` that was read with
    /// them. `read_done` is set when the body has been read to its end; `client` is the gauge of the client's
    /// connection.
    pub(super) fn new(
        body: Incoming,
        pending: Bytes,
        held: u64,
        terms: Terms,
        read_done: Arc<AtomicBool>,
        client: Gauge,
    ) -> (Upload, Arc<Fate>) {
        let seen = held.saturating_add(u64::try_from(pending.len()).unwrap_or(u64::MAX));
        let left = terms.length.map(|length| length.saturating_sub(seen));
        let fate = Arc::new(Fate {
            cause: OnceLock::new(),
            seen: AtomicU64::new(seen),
            handed: watch::channel(false).0,
        });
        if left == Some(0) {
            read_done.store(true, Ordering::Release);
        }
        let upload = Upload {
            pending,
            body,
            terms,
            seen,
            left,
            ended: false,
            failed: false,
            timer: None,
            late: false,
            read_done,
            client,
            fate: fate.clone(),
        };
        (upload, fate)
    }

    /// The length of the whole body, if it has one.
    pub fn length(&self) -> Option<u64> {
        self.terms.length
    }

    /// A receiver that sees `true` once the body has been read to its end and its last piece has been handed on. It
    /// is for the exchange with the upstream, which waits for the answer from then on.
    pub fn watch(&self) -> watch::Receiver<bool> {
        self.fate.handed.subscribe()
    }

    /// The last piece, or the end, has been handed on.
    fn hand_over(&self) {
        self.fate.handed.send_replace(true);
    }

    /// Nothing more comes.
    pub fn is_end_stream(&self) -> bool {
        !self.failed && self.pending.is_empty() && (self.ended || self.left == Some(0))
    }

    pub fn poll_frame(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Cut>>> {
        if self.failed {
            return Poll::Ready(Some(Err(Cut)));
        }
        if !self.pending.is_empty() {
            if self.left == Some(0) {
                self.hand_over();
            }
            return Poll::Ready(Some(Ok(Frame::data(std::mem::take(&mut self.pending)))));
        }
        loop {
            if self.ended || self.left == Some(0) {
                return Poll::Ready(None);
            }
            match Pin::new(&mut self.body).poll_frame(cx) {
                Poll::Pending => return self.wait(cx),
                Poll::Ready(None) => {
                    self.ended = true;
                    // A body with a length that ends before it should is not the body that was announced.
                    if self.left.is_some_and(|left| left != 0) {
                        return self.fail(Cause::Malformed);
                    }
                    self.read_done.store(true, Ordering::Release);
                    self.hand_over();
                    return Poll::Ready(None);
                }
                Poll::Ready(Some(Err(e))) => {
                    let cause = if self.client.over() {
                        Cause::Wire
                    } else if peer_gone(&e) {
                        Cause::Gone
                    } else {
                        Cause::Malformed
                    };
                    return self.fail(cause);
                }
                Poll::Ready(Some(Ok(frame))) => {
                    self.timer = None;
                    let data = match frame.into_data() {
                        Ok(data) => data,
                        Err(frame) => {
                            if frame
                                .into_trailers()
                                .is_ok_and(|trailers| !trailers.is_empty())
                            {
                                return self.fail(Cause::Trailers);
                            }
                            continue;
                        }
                    };
                    if data.is_empty() {
                        continue;
                    }
                    let len = u64::try_from(data.len()).unwrap_or(u64::MAX);
                    self.seen = self.seen.saturating_add(len);
                    self.fate.seen.store(self.seen, Ordering::Relaxed);
                    if self.seen > self.terms.max {
                        return self.fail(Cause::Over);
                    }
                    if let Some(left) = self.left {
                        let Some(left) = left.checked_sub(len) else {
                            return self.fail(Cause::Malformed);
                        };
                        self.left = Some(left);
                        if left == 0 {
                            self.read_done.store(true, Ordering::Release);
                            self.hand_over();
                        }
                    }
                    return Poll::Ready(Some(Ok(Frame::data(data))));
                }
            }
        }
    }

    /// The client has nothing for us yet: it has until the end of the gap, or of the request time if that comes
    /// first.
    fn wait(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Cut>>> {
        if self.timer.is_none() {
            let gap_end = after(Instant::now(), self.terms.gap);
            self.late = self.terms.by <= gap_end;
            self.timer = Some(Box::pin(sleep_until(gap_end.min(self.terms.by))));
        }
        let due = self
            .timer
            .as_mut()
            .is_some_and(|timer| timer.as_mut().poll(cx).is_ready());
        if due {
            let cause = if self.late { Cause::Late } else { Cause::Idle };
            self.fail(cause)
        } else {
            Poll::Pending
        }
    }

    fn fail(&mut self, cause: Cause) -> Poll<Option<Result<Frame<Bytes>, Cut>>> {
        self.failed = true;
        // Only the first reason is kept.
        let _ = self.fate.cause.set(cause);
        Poll::Ready(Some(Err(Cut)))
    }
}

#[cfg(test)]
mod tests;
