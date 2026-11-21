//! SIGUSR1 and SIGUSR2: the switch to the generations that the rules store chooses now, and the reading of the
//! certificate and key files again. SIGUSR1 reads the generation chosen for each engine, the default engine first and
//! the others in the order of their names, and switches the engines whose chosen generation is not the one that runs,
//! one after the other: the next engine is taken when the switch of the one before has ended, for there is one switch
//! under way at a time, and a SIGUSR1 that comes while one is under way is a line and nothing more. An engine that has
//! a generation chosen and does not run is started by its switch. The orders of the control socket are carried out here
//! too: a status is answered, a switch is the switch of SIGUSR1 for the engine of the order once the store chooses the
//! generation that the order expects, and a reload is the reading of SIGHUP with the managed version that the order
//! names. SIGHUP, the reading of the configuration file again, is in `config`, with the values that it may not change
//! in `fixed`.

mod config;
mod fixed;

use std::sync::mpsc::SyncSender;

use tokio::sync::oneshot;

use tukuyomi_kernel::Engine;

use super::control::{Answer, Figures, Order, Outcome};
use super::signals::Waits;
use crate::inbound::conn::{Setup, Shared};
use crate::inbound::transport::tls::Files;
use crate::inspect::driver::{Msg, Switch};
use crate::log::Log;
use crate::log::counters::{Counters, ReloadResult, SwitchResult};
use crate::rules::bundle::Fingerprint;
use crate::rules::store::engines_from;
use crate::rules::switch::{Next, Switcher};

pub(super) use config::Reloader;
use config::reload_while_starting;
pub(super) use fixed::Fixed;

/// What a try to switch came to.
enum Begun {
    /// The driver was ordered to switch; the answer comes as `Event::Switched`.
    Started,
    /// A switch is under way already.
    Busy,
    /// The store chooses the generation that runs, which is the one expected if one was.
    Running,
    /// The store chooses another generation than the one expected.
    Changed,
    /// The store or the configuration refused.
    Refused,
    /// The driver did not take the order.
    Failed,
    /// The store chooses no generation for an engine that does not run: nothing to do, and nothing to say.
    Nothing,
}

/// SIGUSR1: reads the rules store for each engine, the default engine first, and orders the driver to switch to the
/// generation chosen for an engine that is not the one that runs. The first switch is started here and the others
/// when each switch before it has ended (`continue_reload`); the answer of each comes as `Event::Switched`. A switch
/// that is under way when SIGUSR1 comes is a record line and nothing more: the engines that an earlier SIGUSR1 has
/// still to switch stay in the queue, and go on when that switch has ended. Every other case is a record line too, and
/// the proxy goes on as it is.
pub(super) fn reload(
    waits: &mut Waits,
    switcher: &mut Switcher,
    ingress: &SyncSender<Msg>,
    counters: &Counters,
    log: &Log,
) {
    log.line("reload: SIGUSR1");
    if waits.switch.is_some() {
        log.line("reload: a switch is in progress, ignored");
        return;
    }
    waits.queue = engines_from(switcher.default_engine()).collect();
    continue_reload(waits, switcher, ingress, counters, log);
}

/// Takes the engines that SIGUSR1 has still to switch, in order, until a switch is started; an engine that needs none
/// is passed over. Called when SIGUSR1 comes and no switch is under way, and when a switch has ended: no switch is
/// under way then, so the switcher is never busy here.
pub(super) fn continue_reload(
    waits: &mut Waits,
    switcher: &mut Switcher,
    ingress: &SyncSender<Msg>,
    counters: &Counters,
    log: &Log,
) {
    while let Some(engine) = waits.queue.pop_front() {
        if let Begun::Started = begin(waits, switcher, ingress, counters, log, engine, None) {
            return;
        }
    }
}

/// The switch of SIGUSR1 and of a switch order of the control socket, for `engine`: reads the rules store, and if it
/// chooses another generation for the engine than the one that runs, or the engine does not run, orders the driver to
/// switch to it. With `expect` the generation that the store chooses has to be that one; if it is not, nothing is
/// started and nothing is counted. The store is read once, so what is checked is what is switched to.
fn begin(
    waits: &mut Waits,
    switcher: &mut Switcher,
    ingress: &SyncSender<Msg>,
    counters: &Counters,
    log: &Log,
    engine: Engine,
    expect: Option<Fingerprint>,
) -> Begun {
    match switcher.prepare(engine) {
        Next::Busy => {
            log.line("reload: a switch is in progress, ignored");
            Begun::Busy
        }
        Next::Running(generation) => {
            log.line(&format!(
                "reload: generation {} is already running",
                generation.hex()
            ));
            if expect.is_none_or(|expect| expect == generation) {
                Begun::Running
            } else {
                Begun::Changed
            }
        }
        Next::Unchosen if expect.is_some() => Begun::Changed,
        Next::Unchosen if switcher.running(engine).is_none() => Begun::Nothing,
        Next::Unchosen => {
            counters.add_switch(SwitchResult::Refused);
            log.line("reload: rules store refused: no generation is chosen");
            Begun::Refused
        }
        Next::Refused(why) => {
            counters.add_switch(SwitchResult::Refused);
            log.line(&format!("reload: rules store refused: {why}"));
            Begun::Refused
        }
        Next::Ready {
            generation,
            mode,
            routes,
            kernel,
        } => {
            if expect.is_some_and(|expect| expect != generation) {
                // The hold on the generation that was not expected is given back.
                switcher.finish(false);
                return Begun::Changed;
            }
            log.line(&format!("reload: starting generation {}", generation.hex()));
            log.line(&format!("reload: rules engine {}", kernel.engine.name()));
            log.line(&format!("reload: rules mode {}", mode.name()));
            log.line(&format!("reload: rules routes {}", routes.len()));
            let (reply, told) = oneshot::channel();
            let order = Msg::Switch(Switch {
                generation,
                mode,
                routes,
                kernel: *kernel,
                reply,
            });
            if ingress.try_send(order).is_err() {
                log.line("reload: the driver did not take the switch");
                counters.add_switch(SwitchResult::Failed);
                switcher.finish(false);
                return Begun::Failed;
            }
            waits.switch = Some((engine, told));
            Begun::Started
        }
    }
}

/// An order of the control socket while the proxy serves. A status is answered at once. A switch that the driver
/// has taken is answered when the driver answers (`Control::switch_ended`); every other case is answered here. A
/// reload order goes to `reloader` (`Reloader::order`), and is answered when its reading ends.
pub(super) fn control_order(
    order: Order,
    waits: &mut Waits,
    switcher: &mut Switcher,
    reloader: &Reloader,
    ingress: &SyncSender<Msg>,
    shared: &Shared,
) {
    let switch = match order {
        Order::Status(reply) => return answer_status(waits, shared, reply),
        Order::Reload(order) => return reloader.order(order, waits, shared),
        Order::Switch(switch) => switch,
    };
    let engine = switch.engine();
    let serving = switcher.running(engine);
    let expect = Some(switch.expect());
    let (outcome, reason) = match begin(
        waits,
        switcher,
        ingress,
        &shared.counters,
        &shared.log,
        engine,
        expect,
    ) {
        Begun::Started => {
            if let Some(control) = waits.control.as_mut() {
                control.hold(switch);
            }
            return;
        }
        Begun::Busy => (Outcome::Busy, "switch under way"),
        Begun::Running => (Outcome::Unchanged, "already serving"),
        Begun::Changed | Begun::Nothing => (Outcome::Refused, "current changed"),
        Begun::Refused => (Outcome::Refused, "store refused"),
        Begun::Failed => (Outcome::Failed, "driver did not take the order"),
    };
    switch.finish(outcome, Some(reason), serving, &shared.log);
}

/// An order of the control socket before the listeners are bound: a status is answered, and neither a switch nor a
/// reload is done.
pub(super) fn control_while_starting(
    order: Order,
    waits: &Waits,
    switcher: &Switcher,
    shared: &Shared,
) {
    match order {
        Order::Status(reply) => answer_status(waits, shared, reply),
        Order::Switch(switch) => {
            let serving = switcher.running(switch.engine());
            switch.finish(Outcome::Busy, Some("starting"), serving, &shared.log);
        }
        Order::Reload(order) => reload_while_starting(order, shared),
    }
}

fn answer_status(waits: &Waits, shared: &Shared, reply: oneshot::Sender<Answer>) {
    if let Some(control) = &waits.control {
        let _ = reply.send(control.status(
            waits.switch.is_some(),
            waits.config.is_some(),
            figures(shared),
        ));
    }
}

/// The figures of a status answer, read where `/metrics` reads them: the counters of the process and the upstream
/// groups, and the SHA-256, the managed version and the `resolve_timeout` of the configuration in force.
fn figures(shared: &Shared) -> Figures {
    let counters = &shared.counters;
    let setup = shared.setup.current();
    Figures {
        uptime_ms: u64::try_from(counters.uptime().as_millis()).unwrap_or(u64::MAX),
        requests: counters.requests.total(),
        blocked: counters.blocked(),
        policy_refused: counters.policy_refusals.total(),
        upstream_failures: setup
            .upstreams
            .failures()
            .fold(0, |sum, (_, failures)| sum.saturating_add(failures)),
        config: setup.sha256,
        managed: setup.managed,
        resolve_timeout_ms: u64::try_from(setup.resolve_timeout.as_millis()).unwrap_or(u64::MAX),
        config_replaced: counters.config_reloaded(ReloadResult::Replaced),
        config_refused: counters.config_reloaded(ReloadResult::Refused),
    }
}

/// SIGUSR2: reads the certificate and key files of the TLS listeners of `setup`, the one that is current, again. They
/// all replace the ones in use, or none does; the result is a record line, and the proxy goes on as it is.
pub(super) fn reload_certificates(shared: &Shared, setup: &Setup) {
    shared.log.line("reload: SIGUSR2");
    match setup.tls.reload(&setup.cfg.listeners, &Files) {
        Ok(()) => {
            shared.counters.add_reload(ReloadResult::Replaced);
            shared.log.line("reload: certificates replaced");
            for place in setup.tls.waiting() {
                shared
                    .log
                    .line(&format!("reload: tls certificate not issued yet ({place})"));
            }
        }
        Err(refusal) => {
            shared.counters.add_reload(ReloadResult::Refused);
            shared
                .log
                .line(&format!("reload: certificates refused: {refusal}"));
        }
    }
}

#[cfg(test)]
mod tests;
