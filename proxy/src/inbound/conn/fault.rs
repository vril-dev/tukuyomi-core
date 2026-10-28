//! What a failure means for the client: a failure of the exchange with the upstream, a failure of the body of the
//! request while it is passed on, and whether a failure of the body is the peer going away.

use std::io;

use crate::forward::origin::OriginError;
use crate::inbound::answer::{Reply, Stop};
use crate::inbound::upload::{Cause, Fate};

/// What the failure of the exchange with the upstream means for the client. `fate` is there if the body of the request
/// was passed on while the client sent it: part of it may have gone to the upstream already, so a failure that comes
/// after the request was sent says so, unless all of the body had been handed on by then: the failure is then the
/// one of a request whose body was held.
pub(super) fn upstream_stop(error: OriginError, fate: Option<&Fate>) -> Stop {
    Stop::Reply(match error {
        OriginError::Unavailable => Reply::failed(502, "upstream unavailable"),
        OriginError::Connect => Reply::failed(502, "upstream connection failed"),
        OriginError::Send | OriginError::Head if fate.is_some_and(|fate| !fate.handed()) => {
            Reply::failed(502, "upstream failed while the body was sent on")
        }
        OriginError::Send => Reply::failed(502, "upstream send failed"),
        OriginError::Head => Reply::failed(502, "upstream response head failed"),
        OriginError::Invalid => Reply::failed(502, "upstream response invalid"),
        // Not the fault of the upstream: the answers of the proxy's own limits are 503.
        OriginError::Late => Reply::failed(503, "request time used up"),
        OriginError::Local => Reply::failed(503, "local connection failure"),
        // The client's side of the body failed. Without a reason in the fate this is a fault of ours.
        OriginError::Body => match fate.and_then(Fate::cause) {
            Some(cause) => return cause_stop(cause),
            None => Reply::failed(502, "upstream send failed"),
        },
    })
}

/// The answer to a client whose body failed while it was passed on to the upstream. A chunked body that passes the
/// limit, and a client that is gone, get none: the connection is closed.
fn cause_stop(cause: Cause) -> Stop {
    match cause {
        Cause::Idle => Reply::rejected(408, "body not received in time").into(),
        Cause::Late => Reply::failed(503, "request time used up").into(),
        Cause::Over => Stop::Close("body over the limit while it was sent on"),
        Cause::Trailers => Reply::rejected(400, "request trailers not supported").into(),
        Cause::Wire => Reply::rejected(413, "body over the limit on the wire").into(),
        Cause::Gone => Stop::Close("peer closed during the body"),
        Cause::Malformed => Reply::rejected(400, "malformed body").into(),
    }
}

/// Whether the body failed because the peer went away, not because of what it sent.
pub(in crate::inbound) fn peer_gone(e: &hyper::Error) -> bool {
    if e.is_incomplete_message() {
        return true;
    }
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(err) = source {
        if let Some(io) = err.downcast_ref::<io::Error>()
            && matches!(
                io.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::NotConnected
                    | io::ErrorKind::TimedOut
            )
        {
            return true;
        }
        source = err.source();
    }
    false
}
