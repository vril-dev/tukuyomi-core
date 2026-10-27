//! The stop: why the process stops (`Cause`), what the stop learns while it runs (`Stop`), the procedure, and the
//! exit code.

use std::sync::mpsc::SyncSender;
use std::time::Duration;

use tokio::time::{Instant, timeout_at};
use tukuyomi_kernel::{Failure, Phase};

use super::serve::note_joined;
use super::signals::{Event, Source, Waits};
use super::{EXIT_FAILED, EXIT_OK};
use crate::config::ProxyConfig;
use crate::inspect::driver::{End, Ingress, Msg};
use crate::log::Log;

/// The driver's end counts as clean only for a stopped kernel whose child exit and directory removal are
/// confirmed, when every kernel that was stopped before it stopped cleanly too.
fn clean_shutdown(end: &End) -> bool {
    matches!(end, End::Done { kernel, retired_clean: true }
        if kernel.phase == Phase::Stopped && kernel.exit_confirmed && kernel.dir_removed)
}

/// Why the process stops.
pub(super) enum Cause {
    Signal(&'static str),
    /// The kernel failed (before ready, or after).
    Failed(Failure),
    /// The driver ended without being told to.
    Ended(End),
    /// A channel closed without an answer.
    Lost(Source),
    /// The kernel was not ready within `ready_wait`.
    Late,
    Bind,
}

impl Cause {
    /// The cause that an event stands for, or none if the event only keeps the process going.
    pub(super) fn of(event: Event) -> Option<Cause> {
        match event {
            Event::Signal(name) => Some(Cause::Signal(name)),
            Event::Ready(Err(failure)) | Event::Failed(failure) => Some(Cause::Failed(failure)),
            Event::Ended(end) => Some(Cause::Ended(end)),
            Event::Lost(source) => Some(Cause::Lost(source)),
            Event::Late => Some(Cause::Late),
            Event::Ready(Ok(()))
            | Event::Reload
            | Event::Certificates
            | Event::Switched(_)
            | Event::Conn(_)
            | Event::AcceptErr(_)
            | Event::Joined(_) => None,
        }
    }
}

/// What the stop learned while it ran.
struct Stop {
    /// The stop was caused by a failure: the exit code is 1 whatever the driver reports.
    fault: bool,
    ended: Option<End>,
    end_lost: bool,
}

impl Stop {
    fn begin(cause: Cause, log: &Log) -> Stop {
        let mut stop = Stop {
            fault: true,
            ended: None,
            end_lost: false,
        };
        match cause {
            Cause::Signal(name) => {
                stop.fault = false;
                log.line(&format!("stop: {name}"));
            }
            Cause::Failed(failure) => log.line(&format!("stop: the kernel failed: {failure:?}")),
            Cause::Ended(end) => {
                log.line("stop: the driver ended before it was told to stop");
                stop.ended = Some(end);
            }
            Cause::Lost(source) => {
                log.line(&format!(
                    "stop: the {} channel closed without an answer",
                    source.name()
                ));
                stop.end_lost = source == Source::End;
            }
            Cause::Late => log.line("stop: the kernel was not ready in time"),
            Cause::Bind => log.line("stop: a listen address cannot be bound"),
        }
        stop
    }

    /// Takes in an event that arrives while the stop runs. Later signals are only logged.
    fn note(&mut self, event: Event, log: &Log) {
        match event {
            Event::Ended(end) => self.ended = Some(end),
            Event::Lost(Source::End) => self.end_lost = true,
            Event::Signal(name) => log.line(&format!("stop: {name} again")),
            Event::Failed(failure) => {
                log.line(&format!("stop: the kernel failed: {failure:?}"));
            }
            Event::Joined(done) => note_joined(done, log),
            Event::Reload => log.line("reload: ignored while stopping"),
            Event::Certificates => log.line("reload: certificates ignored while stopping"),
            Event::Lost(_)
            | Event::Ready(_)
            | Event::Switched(_)
            | Event::Late
            | Event::Conn(_)
            | Event::AcceptErr(_) => {}
        }
    }

    fn answered(&self) -> bool {
        self.ended.is_some() || self.end_lost
    }
}

/// The stop procedure. `t0` is taken here, at the first cause.
pub(super) async fn stop(
    mut waits: Waits,
    cause: Cause,
    ingress: SyncSender<Msg>,
    connections: &Ingress,
    proxy: &ProxyConfig,
    kill_grace: Duration,
    log: &Log,
) -> u8 {
    let t0 = Instant::now();
    let after = |d: Duration| t0.checked_add(d).unwrap_or(t0);
    let mut stop = Stop::begin(cause, log);

    // The listeners are closed here; a connection that was not accepted yet is never accepted. The connections get
    // no sender for a request that starts from now on, and the ones that wait for a request end.
    waits.accept = None;
    connections.close();

    // The driver finishes what it holds by `inspect_by`. The channel has room for this message by construction;
    // if it does not take it, the driver ends when the last connection is gone.
    let inspect_by = after(proxy.stop_inspect).into_std();
    if ingress.try_send(Msg::Stop { inspect_by }).is_err() {
        log.line("stop: the driver did not take the stop message");
    }
    drop(ingress);

    // The connections get until `t0 + stop_wait`; what is left is aborted.
    let abort_at = after(proxy.stop_wait);
    while !waits.conns.is_empty() {
        let event = waits.wait(Some(abort_at)).await;
        if matches!(event, Event::Late) {
            log.line("stop: the remaining connections are aborted");
            waits.conns.abort_all();
            break;
        }
        stop.note(event, log);
    }
    // The status listener answered, also about the stop, until the connections were done or aborted; it closes now,
    // and the connections it is answering end with it.
    waits.status = None;
    // Aborted connections are dropped when the runtime next runs them; a connection that does not end by then
    // is left to the process exit.
    let end_by = abort_at.checked_add(kill_grace).unwrap_or(abort_at);
    while let Ok(Some(done)) = timeout_at(end_by, waits.conns.join_next()).await {
        note_joined(done, log);
    }

    // The driver's end.
    while !stop.answered() {
        let event = waits.wait(Some(end_by)).await;
        if matches!(event, Event::Late) {
            log.line("stop: the driver did not answer in time");
            break;
        }
        stop.note(event, log);
    }

    match &stop.ended {
        Some(End::Done {
            kernel: done,
            retired_clean,
        }) => log.line(&format!(
            "stop: kernel {:?}, bye {}, exit_confirmed {}, dir_removed {}, held_left {}, waiting_left {}, results {}, retired_clean {}",
            done.phase,
            done.bye,
            done.exit_confirmed,
            done.dir_removed,
            done.held_left,
            done.waiting_left,
            done.results.len(),
            retired_clean
        )),
        Some(End::Fatal(text)) => log.line(&format!("stop: the driver stopped: {text}")),
        None => log.line("stop: the driver gave no end"),
    }
    let clean = stop.ended.as_ref().is_some_and(clean_shutdown);
    if !stop.fault && clean {
        EXIT_OK
    } else {
        EXIT_FAILED
    }
}

#[cfg(test)]
mod tests;
