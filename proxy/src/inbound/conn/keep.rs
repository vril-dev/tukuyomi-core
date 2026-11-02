//! How the record of a request is kept, as its route says (`records` of the route, or else `records.keep` of the
//! configuration).
//!
//! A route with `required` lets a request in only if its record can be kept: the last write to the record file went
//! through, the shipper, if there is one, is not so far behind that records would be lost before it ships them, and
//! the queue of the records has a seat free for it (seats take at most half of the places of the queue, so at most
//! that many requests that need their record kept are in flight at once). The request takes the seat before its body
//! is read and holds it until its record is queued, so the record is not dropped for a full queue. A request that
//! finds no seat, an unhealthy file or a shipper that is behind is answered with 503 and the reason `records cannot be
//! kept`, and counted. Its own record is queued as any record is, without a seat, except when the shipper is the
//! cause: that record would use up the room that is left before the records not yet shipped are deleted, so only the
//! count shows it. The answer is written before the record of the request is, and a write may fail after the request
//! was let in: the record of a request that was in flight when the writes began to fail, and one that the machine
//! loses in a power cut before it is synced, can be missing. A route with `security` is best effort, and writes the
//! record of a request only if a rule decided it, the inspection could not be done or a policy turned it away
//! (`Noted::security`), or if the request was let in and dropped before its answer (see `Unanswered`).
//!
//! Only a request that gets as far as the end of the choice of its route is reached. What is answered before that has
//! no route, or a route that sends nothing to the upstream, so the value of a route cannot hold for it: a request
//! that the `access` or the `rate_limit` of the configuration turns away, one on TLS whose `Host` the certificate does
//! not cover (421), one for which no route holds (404), the heads that the head check refuses, the answers of a
//! listener that redirects to https, the answer to the challenge of the CA, the records of a connection and of a
//! tunnel, and the answers of the route itself that it gives without reading the body: the `access` list of the route
//! (403) and its `max_body` (413). Their records are best effort, whatever `records.keep` says, and are written when
//! the answer is.
//!
//! A request that was let in and whose service is dropped before it comes to an answer (the client closed the
//! connection of HTTP/1.1, or reset the stream of HTTP/2) has a record all the same, whatever its route is: it may
//! have reached the upstream (see `Unanswered`).

use std::sync::PoisonError;

use tokio::time::Instant;

use super::Conn;
use super::fault::PEER_CLOSED;
use crate::config::RouteKeep;
use crate::forward::group::Route;
use crate::inbound::answer::{Keeping, Noted, Reply, Stop};
use crate::inbound::session::Session;
use crate::log::Unkept;

impl Conn {
    /// Chooses how the record of the request is kept, now that its route is found. The record of a request of a
    /// route with `security` is marked at once, so that the answers of the lists of the route are among those it
    /// writes.
    pub(super) fn keep_by(&self, route: &Route<'_>) -> RouteKeep {
        let keeps = self.ctx.setup.keep.for_route(route.records);
        if keeps == RouteKeep::Security {
            self.keeping
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .only_security = true;
        }
        keeps
    }

    /// The admission of a request that needs its record kept: a seat, or the answer 503. A request of any route that
    /// is let in is marked, for the record of one that is dropped before its answer (see `Unanswered`).
    pub(super) fn admit_records(&self, keeps: RouteKeep) -> Result<(), Stop> {
        let seat = if keeps == RouteKeep::Required {
            match self.ctx.shared.log.admit() {
                Ok(seat) => Some(seat),
                Err(why) => {
                    self.ctx.shared.counters.records_refused.add();
                    self.note_empty_body();
                    self.keeping
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .counted_only = why == Unkept::Behind;
                    return Err(Reply::failed(503, "records cannot be kept").into());
                }
            }
        } else {
            None
        };
        let mut keeping = self.keeping.lock().unwrap_or_else(PoisonError::into_inner);
        keeping.seat = seat;
        keeping.admitted = true;
        Ok(())
    }

    /// The inspection did not let the request through.
    pub(super) fn inspection_stopped(&self) {
        self.keeping
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .stopped = true;
    }

    /// Takes how the record is kept, for the record of the request.
    pub(super) fn take_keeping(&self) -> Keeping {
        std::mem::take(&mut *self.keeping.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// What the record of the request shows, as `reply` is its answer: the upstream it went to, the size of its
    /// body and the verdict, as far as they are known, and how its record is kept.
    pub(super) fn noted(&self, reply: Reply) -> Noted {
        let via = self
            .via
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let body = self
            .sizes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let judged = self
            .judged
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        Noted {
            via,
            body,
            judged,
            keeping: self.take_keeping(),
            ..Noted::new(self.request.clone(), reply, self.client.ip()).of(&self.head)
        }
    }

    /// What the record shows of a request that was let in and has not come to an answer. None: it was not let in, or
    /// it came to an answer, which has taken how its record is kept. The upstream may have the request, so a route
    /// that keeps only some records keeps this one as well.
    fn unanswered(&self) -> Option<Noted> {
        let admitted = self
            .keeping
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .admitted;
        admitted.then(|| {
            let mut noted = self.noted(Reply {
                reason: PEER_CLOSED,
                ..Reply::NONE
            });
            noted.keeping.only_security = false;
            noted
        })
    }
}

/// Writes the record of a request whose service is dropped before it comes to an answer, when it is dropped itself.
/// A request that waits for its body, for the inspection or for the upstream is dropped when the client closes the
/// connection of HTTP/1.1 or resets the stream of HTTP/2; nothing else would write a record for it, though the
/// upstream may have it. It is written as the record of any other request that is closed without an answer, with
/// the seat that the request took, if it took one. A request that has come to an answer has handed its record on, and
/// this does nothing.
pub(in crate::inbound) struct Unanswered<'a> {
    conn: &'a Conn,
    session: &'a Session,
    start: Instant,
}

impl<'a> Unanswered<'a> {
    /// Watches `conn`, a request of `session` that began at `start`. It has to be declared after `conn`, so that it
    /// is dropped first.
    pub(in crate::inbound) fn new(
        conn: &'a Conn,
        session: &'a Session,
        start: Instant,
    ) -> Unanswered<'a> {
        Unanswered {
            conn,
            session,
            start,
        }
    }
}

impl Drop for Unanswered<'_> {
    fn drop(&mut self) {
        if let Some(mut noted) = self.conn.unanswered() {
            self.session.note(&mut noted, self.start, 0);
        }
    }
}

#[cfg(test)]
mod tests;
