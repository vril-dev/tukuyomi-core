use super::*;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Semaphore, oneshot};
use tukuyomi_kernel::{Config, Phase, Reason};

use crate::inspect::driver::{Answer, BodyHold, Hold};

/// A kernel that is stopped by the test: `shutdown` gives the answer the test chose.
struct Stub {
    done: Option<Shutdown>,
}

impl Kernel for Stub {
    fn create(_cfg: Config) -> Result<Stub, &'static str> {
        Err("a stub is made by the test")
    }

    fn submit(&mut self, _req: &Request<'_>) -> Result<ReqId, Refused> {
        Err(Refused::Full)
    }

    fn cancel(&mut self, _id: ReqId) {}

    fn poll(&mut self, _until: Instant) -> Vec<(ReqId, Verdict)> {
        Vec::new()
    }

    fn status(&self) -> Status {
        Status {
            phase: Phase::Ready,
            inc: 1,
            restarts: 0,
            waiting: 0,
            held: 0,
            records: 0,
        }
    }

    fn start_detail(&self) -> Option<Vec<u8>> {
        None
    }

    fn shutdown(&mut self, _deadline: Instant) -> Shutdown {
        self.done.take().expect("shutdown is called once")
    }
}

fn shutdown(results: Vec<(ReqId, Verdict)>, exit_confirmed: bool) -> Shutdown {
    Shutdown {
        results,
        phase: Phase::Stopped,
        bye: true,
        exit_confirmed,
        dir_removed: true,
        held_left: 0,
        waiting_left: 0,
    }
}

/// A slot of a generation with the mode `mode` that holds one request, with the id 0, and the answer of the
/// request.
fn slot_with_a_request(mode: Mode, done: Shutdown) -> (Slot<Stub>, oneshot::Receiver<Answer>) {
    let permits = Arc::new(Semaphore::new(3));
    let take = || permits.clone().try_acquire_owned().unwrap();
    let (reply, answer) = oneshot::channel();
    let ticket = Ticket {
        req: InspectReq {
            client: "192.0.2.10:40000".parse().unwrap(),
            server: "192.0.2.1:8080".parse().unwrap(),
            method: Default::default(),
            uri: Default::default(),
            headers: Vec::new(),
            body: Arc::new(BodyHold::new(Default::default(), take())),
            cut: false,
            proto: b"HTTP/1.1",
        },
        reply,
        hold: Hold::new(take(), take()),
    };
    let generation = Fingerprint::from_hex(&[b'7'; 64]).unwrap();
    let mut slot = Slot::new(generation, mode, Stub { done: Some(done) });
    slot.pending.insert(
        0,
        Pending {
            ticket,
            cancelled: false,
        },
    );
    (slot, answer)
}

#[test]
fn a_retired_slot_gets_the_results_of_its_shutdown_and_tells_whether_it_stopped_cleanly() {
    let deadline = Instant::now() + Duration::from_secs(1);
    let unavailable = Verdict::Uninspectable(Reason::Unavailable);
    for confirmed in [true, false] {
        let (slot, mut answer) =
            slot_with_a_request(Mode::Block, shutdown(vec![(0, unavailable)], confirmed));
        let generation = slot.generation;
        let retired = slot.retire(deadline).wait();
        assert_eq!(
            retired,
            Ok(Retired {
                generation,
                clean: confirmed
            })
        );
        assert_eq!(answer.try_recv(), Ok(verdict(unavailable, Mode::Block)));
    }
}

/// What a verdict of the slot of `slot_with_a_request` is answered with: the verdict, and the generation of the slot
/// and the mode of its rules.
fn verdict(verdict: Verdict, mode: Mode) -> Answer {
    Answer {
        outcome: Outcome::Verdict(verdict),
        by: Some(Judge {
            generation: Fingerprint::from_hex(&[b'7'; 64]).unwrap(),
            mode,
        }),
    }
}

#[test]
fn a_retirement_with_a_request_left_or_a_result_of_nobody_is_a_fault() {
    let deadline = Instant::now() + Duration::from_secs(1);
    let (slot, _answer) = slot_with_a_request(Mode::Block, shutdown(Vec::new(), true));
    assert_eq!(
        slot.retire(deadline).wait(),
        Err("request left after shutdown")
    );
    let (slot, _answer) =
        slot_with_a_request(Mode::Block, shutdown(vec![(1, Verdict::Allow)], true));
    assert_eq!(
        slot.retire(deadline).wait(),
        Err("result for an unknown request")
    );
}

#[test]
fn a_retired_slot_does_not_deliver_a_detection_of_a_generation_that_blocks() {
    let deadline = Instant::now() + Duration::from_secs(1);
    let detected = Verdict::Detected {
        rule_id: 949110,
        status: 403,
    };
    let (slot, mut answer) = slot_with_a_request(Mode::Block, shutdown(vec![(0, detected)], true));
    assert!(slot.retire(deadline).wait().is_ok());
    assert_eq!(
        answer.try_recv(),
        Ok(verdict(
            Verdict::Uninspectable(Reason::Protocol),
            Mode::Block
        ))
    );

    // A generation that detects gets it as it is.
    let (slot, mut answer) = slot_with_a_request(Mode::Detect, shutdown(vec![(0, detected)], true));
    assert!(slot.retire(deadline).wait().is_ok());
    assert_eq!(answer.try_recv(), Ok(verdict(detected, Mode::Detect)));
}
