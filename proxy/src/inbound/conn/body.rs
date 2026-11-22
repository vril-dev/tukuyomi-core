//! The body of a request: the reading of it, the decoding of a gzip body, and what a failed read means; and `take`,
//! which takes bytes of the byte budget for the body, for the hold of a tunnel and for the copy of the inspection.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use bytes::{Bytes, BytesMut};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::timeout_at;

use super::fault::{PEER_CLOSED, peer_gone};
use super::{Conn, stage};
use crate::config::STREAM_HOLD;
use crate::inbound::answer::{Reply, Stop};
use crate::inbound::head::Reject;
use crate::inbound::represent::gunzip;
use crate::inbound::upload::{Fate, Terms, Upload};

/// The first bytes of a body, which `read_body` holds, and the rest of it if the body goes on.
pub(super) struct Taken {
    pub(super) bytes: Bytes,
    pub(super) budget: OwnedSemaphorePermit,
    pub(super) upload: Option<(Upload, Arc<Fate>)>,
}

impl Conn {
    /// Takes `n` bytes of the budget.
    pub(super) fn take(&self, n: usize) -> Result<OwnedSemaphorePermit, Stop> {
        u32::try_from(n)
            .ok()
            .and_then(|n| {
                self.ctx
                    .shared
                    .budget
                    .clone()
                    .try_acquire_many_owned(n)
                    .ok()
            })
            .ok_or_else(|| Reply::failed(503, "byte budget exhausted").into())
    }

    /// Reads the first `keep` bytes of the decoded body, or all of it if it ends sooner. A body that goes on past
    /// them is passed on while the client sends it (see `upload`): the bytes read behind the first ones are the
    /// start of the rest, and the request holds `STREAM_HOLD` more of the budget while that goes on. A body that
    /// is longer than `limit` is refused with 413. The budget of the bytes held is taken before the first byte is
    /// read (so no `100 Continue` is sent for a body that cannot be held), the budget of a chunked body frame by
    /// frame.
    pub(super) async fn read_body(
        &self,
        mut body: Incoming,
        keep: usize,
        limit: usize,
    ) -> Result<Taken, Stop> {
        let chunked = self.head.chunked();
        let declared = match self.head.content_length() {
            Some(n) => usize::try_from(n).map_err(|_| Reject::ContentTooLarge)?,
            None => 0,
        };
        if !chunked && declared == 0 {
            self.read_done.store(true, Ordering::Release);
            return Ok(Taken {
                bytes: Bytes::new(),
                budget: self.take(0)?,
                upload: None,
            });
        }
        if declared > limit {
            return Err(Reject::ContentTooLarge.into());
        }
        // A body with a length that is longer than `keep` goes on past the bytes held.
        let goes_on = declared > keep;
        let mut budget = self.take(declared.min(keep))?;
        if goes_on {
            budget.merge(self.take(STREAM_HOLD)?);
        }
        let mut data = BytesMut::with_capacity(declared.min(keep));
        let mut rest = Bytes::new();
        let mut ended = false;
        let by = stage(self.head_end, self.ctx.setup.cfg.body_read, self.request_by);
        loop {
            if goes_on && data.len() == keep {
                break;
            }
            let frame = match timeout_at(by, body.frame()).await {
                Err(_) => return Err(Reply::rejected(408, "body not received in time").into()),
                Ok(None) => {
                    ended = true;
                    break;
                }
                Ok(Some(Err(e))) => return Err(self.body_fault(&e)),
                Ok(Some(Ok(frame))) => frame,
            };
            match frame.into_data() {
                Ok(mut chunk) => {
                    if data
                        .len()
                        .checked_add(chunk.len())
                        .is_none_or(|total| total > limit)
                    {
                        return Err(Reply::rejected(413, "body over the limit").into());
                    }
                    // The bytes of this chunk behind the first `keep` are the start of the rest.
                    let room = keep - data.len();
                    if chunk.len() > room {
                        rest = chunk.split_off(room);
                    }
                    if chunked {
                        budget.merge(self.take(chunk.len())?);
                    }
                    data.extend_from_slice(&chunk);
                    if !rest.is_empty() {
                        if chunked {
                            budget.merge(self.take(STREAM_HOLD)?);
                        }
                        break;
                    }
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
        if ended {
            self.read_done.store(true, Ordering::Release);
            if !chunked && data.len() != declared {
                return Err(
                    Reply::rejected(400, "body length differs from the declared one").into(),
                );
            }
            return Ok(Taken {
                bytes: data.freeze(),
                budget,
                upload: None,
            });
        }
        let terms = Terms {
            length: self.head.content_length(),
            max: u64::try_from(limit).unwrap_or(u64::MAX),
            gap: self.ctx.setup.cfg.body_read,
            by: self.request_by,
        };
        let held = u64::try_from(data.len()).unwrap_or(u64::MAX);
        let upload = Upload::new(
            body,
            rest,
            held,
            terms,
            self.read_done.clone(),
            self.gauge.clone(),
        );
        Ok(Taken {
            bytes: data.freeze(),
            budget,
            upload: Some(upload),
        })
    }

    /// Replaces a gzip body and its share of the byte budget by the decoded body and the share of its length. The
    /// coded body is at most `inspect_body` bytes, and the decoded one at most `max`, which is no more: the new
    /// share is taken before the old one is given back, and the two together are within what the lower bound of
    /// `max_buffered_bytes` covers. There is no await between the decoding and the taking, so a decoded body that
    /// the budget cannot hold is dropped at once.
    pub(super) fn unpack(
        &self,
        coded: Bytes,
        held: OwnedSemaphorePermit,
        max: usize,
    ) -> Result<(Bytes, OwnedSemaphorePermit), Stop> {
        let plain = gunzip(&coded, max)?;
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
            Stop::Close(PEER_CLOSED)
        } else {
            Stop::Reply(Reply::rejected(400, "malformed body"))
        }
    }
}
