//! What a request is answered with: its reply and class, the answer table, the empty response, the response that holds
//! the file of a challenge of the CA, the answers that are written to the socket as bytes, and what the record of the
//! request is made of.

use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::header::{CONNECTION, CONTENT_LENGTH, CONTENT_TYPE};
use http::{HeaderValue, Response, StatusCode};
use http_body::{Body, Frame, SizeHint};
use tukuyomi_kernel::{Reason, Refused, Verdict};

use crate::forward::origin::OriginBody;
use crate::inbound::head::{Head, Reject};
use crate::inbound::upload::Fate;
use crate::inspect::driver::{Judge, Outcome};
use crate::log::counters::RuleHit;
use crate::log::record::Seen;

/// How a connection ended, for the record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Class {
    /// The request was allowed and the response head was sent.
    Forwarded,
    /// An inspection rule blocked the request.
    Blocked,
    /// The request was refused as malformed, too large or not supported.
    Rejected,
    /// A listener that redirects to https sent the client there.
    Redirected,
    /// The proxy answered the request itself: the challenge of the CA that issues the certificates with `acme`.
    Answered,
    /// The request was not served for a reason on our side: busy, unavailable, an upstream failure.
    Failed,
    /// No answer was written.
    Closed,
}

impl Class {
    pub(super) fn name(self) -> &'static str {
        match self {
            Class::Forwarded => "forwarded",
            Class::Blocked => "blocked",
            Class::Rejected => "rejected",
            Class::Redirected => "redirected",
            Class::Answered => "answered",
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

    /// The client was sent to the https address of its request.
    pub(super) fn redirected() -> Reply {
        Reply {
            status: 308,
            class: Class::Redirected,
            reason: "redirected",
            rule: None,
            internal: false,
        }
    }

    /// The challenge of the CA was answered with `status`: 200 with the file, or 404.
    pub(super) fn answered(status: u16) -> Reply {
        Reply {
            status,
            class: Class::Answered,
            reason: "acme challenge",
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

    /// The response of the upstream was sent. `passed` is how the request was let through.
    pub(super) fn forwarded(status: u16, passed: Passed) -> Reply {
        let (reason, rule) = match passed {
            Passed::Allowed => ("forwarded", None),
            Passed::Detected { rule } => ("detected by a rule", Some(rule)),
            Passed::Bypassed => ("bypassed by a route", None),
        };
        Reply {
            status,
            class: Class::Forwarded,
            reason,
            rule,
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

    /// What a rule did to the request, if one decided it: it blocked it, or it matched while the rules only detect.
    pub(super) fn hit(&self) -> Option<RuleHit> {
        match (self.class, self.rule) {
            (Class::Blocked, _) => Some(RuleHit::Block),
            (Class::Forwarded, Some(_)) => Some(RuleHit::Detect),
            _ => None,
        }
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

/// The response body: empty for our own answers, the upstream's for a forwarded request, and the bytes of the file
/// that answers the challenge of the CA.
pub(super) enum Out {
    Empty,
    /// One piece of data, which is gone once it is taken.
    Bytes(Option<Bytes>),
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
            Out::Bytes(data) => Poll::Ready(data.take().map(|data| Ok(Frame::data(data)))),
            Out::Origin(body) => body.as_mut().poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Out::Empty => true,
            Out::Bytes(data) => data.is_none(),
            Out::Origin(body) => body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Out::Empty => SizeHint::with_exact(0),
            Out::Bytes(data) => SizeHint::with_exact(
                data.as_ref()
                    .map_or(0, |data| u64::try_from(data.len()).unwrap_or(u64::MAX)),
            ),
            Out::Origin(body) => body.size_hint(),
        }
    }
}

/// The upstream a request went to, for the record: the name of the group, and the address of the server that was
/// tried last, if any was.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Via {
    pub(super) group: Arc<str>,
    pub(super) server: Option<SocketAddr>,
}

/// The size of the body of a request, for the record: its `Content-Length` if it has one, the bytes that were held,
/// and the body that followed them when it was passed on while it was read.
pub(super) struct Sizes {
    declared: Option<u64>,
    held: u64,
    rest: Option<Arc<Fate>>,
    /// The held bytes were inspected and the body goes on behind them.
    cut: bool,
}

impl Sizes {
    /// A body that was held whole: `held` bytes were read.
    pub(super) fn whole(declared: Option<u64>, held: usize) -> Sizes {
        Sizes {
            declared,
            held: u64::try_from(held).unwrap_or(u64::MAX),
            rest: None,
            cut: false,
        }
    }

    /// A body that was passed on behind the `held` bytes. `inspected` tells whether those bytes were inspected.
    pub(super) fn passed(
        declared: Option<u64>,
        held: usize,
        rest: Arc<Fate>,
        inspected: bool,
    ) -> Sizes {
        Sizes {
            declared,
            held: u64::try_from(held).unwrap_or(u64::MAX),
            rest: Some(rest),
            cut: inspected,
        }
    }

    /// What the record adds for the body: its length, which is the `Content-Length` if the request has one and
    /// otherwise what was read so far, and for a body that was cut the length that was inspected. Nothing for a
    /// request with no body.
    pub(super) fn lengths(&self) -> Option<(u64, Option<u64>)> {
        let length = self
            .declared
            .unwrap_or_else(|| self.rest.as_ref().map_or(self.held, |rest| rest.seen()));
        (length != 0).then_some((length, self.cut.then_some(self.held)))
    }
}

/// What the record shows of a request besides the time it took: its number, its reply, the address of the client it
/// is recorded under, its method, `Host` and path if its head passed the check, the upstream it went to, if it got as
/// far as that, the size of its body, if it has one, and the generation whose rules gave a verdict, with that verdict
/// and the rules that matched the request, if any did. The record shows the generation, the mode and the rules; the
/// counters read the verdict. Only numbers, fixed texts, the name of a group from the configuration,
/// addresses in their canonical forms and the request's own text as the record writes it (see `log::record`), so
/// nothing the peer sent gets in as it is.
pub(super) struct Noted {
    pub(super) id: String,
    pub(super) reply: Reply,
    pub(super) client: IpAddr,
    pub(super) seen: Option<Seen>,
    pub(super) via: Option<Via>,
    pub(super) body: Option<Sizes>,
    pub(super) judged: Option<Judge>,
}

impl Noted {
    /// The answer `reply`, with the number `id`, for a client that sent no head that passed the check.
    pub(super) fn new(id: String, reply: Reply, client: IpAddr) -> Noted {
        Noted {
            id,
            reply,
            client,
            seen: None,
            via: None,
            body: None,
            judged: None,
        }
    }

    /// The same, for a request whose head passed the check.
    pub(super) fn of(self, head: &Head) -> Noted {
        Noted {
            seen: Some(Seen::of(head.method(), head.host(), head.target())),
            ..self
        }
    }
}

/// How a request that goes on to the upstream was let through, for the record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Passed {
    /// The rules allowed it.
    Allowed,
    /// A rule matched while the rules only detect. The request goes on like an allowed one; the rule is for the
    /// record. The status of the verdict is not used.
    Detected { rule: i64 },
    /// A route of the generation that serves skipped the inspection.
    Bypassed,
}

/// What the verdict of the driver means for the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Decision {
    Pass(Passed),
    Answer(Reply),
}

/// The answer table. Only `Pass` goes on to the upstream.
pub(super) fn decide(outcome: Outcome) -> Decision {
    match outcome {
        Outcome::Verdict(Verdict::Allow) => Decision::Pass(Passed::Allowed),
        Outcome::Verdict(Verdict::Detected { rule_id, .. }) => {
            Decision::Pass(Passed::Detected { rule: rule_id })
        }
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

/// The whole answer of a listener that redirects to https to a request it does not redirect, as it is written to the
/// socket (like the answers of `head::Reject`), with the number `id` of the request.
pub(super) fn not_redirected(id: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 404 Not Found\r\nX-Request-ID: {id}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

/// The whole answer of a listener that redirects to https, as it is written to the socket: 308 to the name and the
/// target of the request at `https_port`, which is left out of the address if it is 443. `name` is a name that the
/// request's `Host` held, in lowercase; `target` is the origin-form target that the head check passed, so it starts
/// with `/`, which keeps the address on the host of the name, and holds no byte that ends a line. `id` is the number
/// of the request.
pub(super) fn redirect(name: &str, https_port: u16, target: &[u8], id: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(190 + name.len() + target.len());
    out.extend_from_slice(b"HTTP/1.1 308 Permanent Redirect\r\nLocation: https://");
    out.extend_from_slice(name.as_bytes());
    if https_port != 443 {
        out.push(b':');
        out.extend_from_slice(https_port.to_string().as_bytes());
    }
    out.extend_from_slice(target);
    out.extend_from_slice(b"\r\nX-Request-ID: ");
    out.extend_from_slice(id.as_bytes());
    out.extend_from_slice(b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    out
}

/// An answer with an empty body. 204 and 304 carry no `Content-Length`.
pub(super) fn answer(status: u16) -> Response<Out> {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut response = Response::new(Out::Empty);
    *response.status_mut() = status;
    if status != StatusCode::NO_CONTENT && status != StatusCode::NOT_MODIFIED {
        response
            .headers_mut()
            .insert(CONTENT_LENGTH, HeaderValue::from_static("0"));
    }
    response
}

/// The `200` answer to the challenge of the CA: `body` as `text/plain`. The answer to a `HEAD` has no body and the
/// length that the body would have.
pub(super) fn text(body: Bytes, head_only: bool) -> Response<Out> {
    let length = HeaderValue::from(body.len());
    let mut response = if head_only {
        Response::new(Out::Empty)
    } else {
        Response::new(Out::Bytes(Some(body)))
    };
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    headers.insert(CONTENT_LENGTH, length);
    response
}

/// Makes the response the last one of its connection: hyper closes the connection after it.
pub(super) fn close_after<B>(response: &mut Response<B>) {
    response
        .headers_mut()
        .insert(CONNECTION, HeaderValue::from_static("close"));
}

#[cfg(test)]
mod tests;
