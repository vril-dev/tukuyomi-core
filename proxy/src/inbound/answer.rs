//! What a connection answers: its reply and class, the answer table, the empty response and the record line.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::header::{CONNECTION, CONTENT_LENGTH};
use http::{HeaderValue, Response, StatusCode};
use http_body::{Body, Frame, SizeHint};
use tukuyomi_kernel::{Reason, Refused, Verdict};

use crate::forward::origin::OriginBody;
use crate::inbound::head::Reject;
use crate::inspect::driver::Outcome;

/// How a connection ended, for the record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Class {
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
pub(super) struct Reply {
    pub(super) status: u16,
    pub(super) class: Class,
    /// A fixed text; never a value from the request.
    pub(super) reason: &'static str,
    pub(super) rule: Option<i64>,
    /// The answer points at a fault in this program and also gets a line of its own in the record.
    pub(super) internal: bool,
}

impl Reply {
    /// Nothing was answered.
    pub(super) const NONE: Reply = Reply {
        status: 0,
        class: Class::Closed,
        reason: "no answer",
        rule: None,
        internal: false,
    };

    pub(super) fn rejected(status: u16, reason: &'static str) -> Reply {
        Reply {
            status,
            class: Class::Rejected,
            reason,
            rule: None,
            internal: false,
        }
    }

    pub(super) fn failed(status: u16, reason: &'static str) -> Reply {
        Reply {
            status,
            class: Class::Failed,
            reason,
            rule: None,
            internal: false,
        }
    }

    pub(super) fn internal(status: u16, reason: &'static str) -> Reply {
        Reply {
            internal: true,
            ..Reply::failed(status, reason)
        }
    }

    /// The answer of a head refusal that has one.
    pub(super) fn of(reject: Reject) -> Reply {
        Reply::rejected(reject.status().unwrap_or(400), reject.reason())
    }
}

/// Why the exchange ends without a response to forward.
pub(super) enum Stop {
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
pub(super) struct Abort;

impl std::fmt::Display for Abort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("connection closed without an answer")
    }
}

impl std::error::Error for Abort {}

/// The response body: empty for our own answers, the upstream's for a forwarded request.
pub(super) enum Out {
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

/// The one record line of a connection: its number, class, status, reason, rule id and the time it took. Only
/// numbers and fixed texts, so nothing the peer sent can get in.
pub(super) fn record(id: u64, reply: &Reply, elapsed: Duration) -> String {
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

/// What the verdict of the driver means for the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Decision {
    Allow,
    Answer(Reply),
}

/// The answer table. Only `Allow` goes on to the upstream.
pub(super) fn decide(outcome: Outcome) -> Decision {
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
pub(super) fn answer(status: u16) -> Response<Out> {
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
mod tests;
