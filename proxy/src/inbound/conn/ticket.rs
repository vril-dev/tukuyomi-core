//! How a request is let through: at once, by a route of the generation that serves, or by the verdict of the
//! inspection driver, to which the request is handed over on a ticket.

use std::sync::mpsc::TrySendError;
use std::sync::{Arc, PoisonError};

use bytes::Bytes;
use tokio::sync::oneshot;
use tokio::time::{Instant, timeout_at};
use tukuyomi_kernel::Engine;

use super::{Conn, stage};
use crate::inbound::answer::{Decision, Passed, Reply, Stop, decide};
use crate::inspect::driver::{Answer, BodyHold, Hold, InspectReq, Msg, Ticket};

impl Conn {
    /// The request is let through at once by a route of the generation that serves: no ticket will be sent, so the
    /// way to the driver is let go as it is after a ticket. The route is looked up before the body is read, so that
    /// a request under a route does not depend on the inspection, and a body that is longer than the bytes that
    /// are inspected is not held.
    pub(super) fn bypassed(&self) -> Passed {
        drop(
            self.ingress
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take(),
        );
        Passed::Bypassed
    }

    /// Hands the request to the driver, for the engine of the group it goes to, and waits for the verdict. `cut` tells
    /// that the body goes on after the bytes in `body`. `Ok` is how the request is let through (an `Allow` or a `Detected`); everything else is
    /// the answer to give.
    pub(super) async fn ask(
        &self,
        engine: Engine,
        headers: Vec<(Bytes, Bytes)>,
        field_bytes: usize,
        body: &Arc<BodyHold>,
        cut: bool,
    ) -> Result<Passed, Stop> {
        let permit = self
            .ctx
            .shared
            .gates
            .of(engine)
            .inspect
            .clone()
            .try_acquire_owned()
            .map_err(|_| Reply::failed(503, "no inspection permit"))?;
        let copy = self.take(body.bytes.len().saturating_add(field_bytes))?;
        let (reply, verdict) = oneshot::channel();
        let ticket = Ticket {
            engine,
            req: InspectReq {
                client: self.client,
                server: self.local,
                method: Bytes::copy_from_slice(self.head.method()),
                uri: Bytes::copy_from_slice(self.head.target()),
                headers,
                body: body.clone(),
                cut,
                proto: self.head.proto(),
            },
            reply,
            hold: Hold::new(permit, copy),
        };
        let sender = self
            .ingress
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .ok_or_else(|| Reply::failed(503, "inspection queue closed"))?;
        match sender.try_send(Msg::Ticket(ticket)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                return Err(Reply::internal(503, "inspection queue full").into());
            }
            Err(TrySendError::Disconnected(_)) => {
                return Err(Reply::failed(503, "inspection queue closed").into());
            }
        }
        drop(sender);
        let by = stage(
            Instant::now(),
            self.ctx.setup.cfg.inspect_wait,
            self.request_by,
        );
        let Answer { outcome, by } = match timeout_at(by, verdict).await {
            Err(_) => return Err(Reply::failed(503, "inspection wait expired").into()),
            Ok(Err(_)) => return Err(Reply::failed(503, "inspection driver gone").into()),
            Ok(Ok(answer)) => answer,
        };
        *self.judged.lock().unwrap_or_else(PoisonError::into_inner) = by;
        match decide(outcome) {
            Decision::Pass(passed) => Ok(passed),
            Decision::Answer(reply) => Err(reply.into()),
        }
    }
}
