use super::*;
use crate::run::start::Reason;
use crate::run::stop::Cause;
use std::time::Duration;
use tokio::runtime::{Builder, Runtime};

pub(in crate::run) fn runtime() -> Runtime {
    Builder::new_current_thread().enable_all().build().unwrap()
}

pub(in crate::run) struct Fixture {
    pub(in crate::run) waits: Waits,
    ready: oneshot::Sender<Result<(), Failure>>,
    _failed: oneshot::Sender<Failure>,
    pub(in crate::run) end: oneshot::Sender<End>,
}

/// Needs a runtime to be entered.
pub(in crate::run) fn fixture() -> Fixture {
    let (ready, ready_rx) = oneshot::channel();
    let (failed, failed_rx) = oneshot::channel();
    let (end, end_rx) = oneshot::channel();
    Fixture {
        waits: Waits::new(Signals::install().unwrap(), ready_rx, failed_rx, end_rx),
        ready,
        _failed: failed,
        end,
    }
}

fn after(ms: u64) -> Option<Instant> {
    Some(Instant::now() + Duration::from_millis(ms))
}

#[test]
fn a_wait_returns_what_the_driver_answered_once() {
    runtime().block_on(async {
        let mut f = fixture();
        f.ready.send(Ok(())).unwrap();
        assert!(matches!(
            f.waits.wait(after(2000)).await,
            Event::Ready(Ok(()))
        ));
        // The answered channel is not polled again: the next wait runs to its deadline.
        assert!(matches!(f.waits.wait(after(30)).await, Event::Late));

        let mut f = fixture();
        f.ready.send(Err(Failure::BudgetExhausted)).unwrap();
        assert!(matches!(
            f.waits.wait(after(2000)).await,
            Event::Ready(Err(Failure::BudgetExhausted))
        ));

        let mut f = fixture();
        drop(f.ready);
        assert!(matches!(
            f.waits.wait(after(2000)).await,
            Event::Lost(Source::Ready)
        ));
    });
}

#[test]
fn a_wait_returns_the_answer_to_a_switch_once() {
    runtime().block_on(async {
        let mut f = fixture();
        let (reply, told) = oneshot::channel();
        f.waits.switch = Some(told);
        reply.send(Switched::Yes).unwrap();
        assert!(matches!(
            f.waits.wait(after(2000)).await,
            Event::Switched(true)
        ));
        assert!(matches!(f.waits.wait(after(30)).await, Event::Late));

        let (reply, told) = oneshot::channel::<Switched>();
        f.waits.switch = Some(told);
        drop(reply);
        assert!(matches!(
            f.waits.wait(after(2000)).await,
            Event::Lost(Source::Switch)
        ));
    });
}

#[test]
fn a_wait_returns_the_answer_of_a_configuration_reload_once_and_a_lost_answer_is_no_cause_of_a_stop()
 {
    runtime().block_on(async {
        let mut f = fixture();
        let (reply, told) = oneshot::channel();
        f.waits.config = Some(told);
        let refusal = Refusal {
            reason: Reason::Configuration,
            detail: "configuration file is not UTF-8".to_owned(),
        };
        assert!(reply.send(Err(refusal.clone())).is_ok());
        assert!(matches!(
            f.waits.wait(after(2000)).await,
            Event::Configured(Err(answer)) if answer == refusal
        ));
        assert!(matches!(f.waits.wait(after(30)).await, Event::Late));

        let (reply, told) = oneshot::channel::<Result<Box<Parts>, Refusal>>();
        f.waits.config = Some(told);
        drop(reply);
        let event = f.waits.wait(after(2000)).await;
        assert!(matches!(event, Event::ConfigurationLost));
        assert!(Cause::of(event).is_none());
    });
}
