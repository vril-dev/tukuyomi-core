//! SIGUSR1 and SIGUSR2: the switch to the generation that the rules store chooses now, and the reading of the
//! certificate and key files again. The orders of the control socket are carried out here too: a status is
//! answered, and a switch is the switch of SIGUSR1 once the store chooses the generation that the order expects.

use std::sync::mpsc::SyncSender;

use tokio::sync::oneshot;

use super::control::{Answer, Order, Outcome};
use super::signals::Waits;
use crate::inbound::conn::Ctx;
use crate::inbound::transport::tls::Files;
use crate::inspect::driver::{Msg, Switch};
use crate::log::Log;
use crate::log::counters::{Counters, ReloadResult, SwitchResult};
use crate::rules::bundle::Fingerprint;
use crate::rules::switch::{Next, Switcher};

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
}

/// SIGUSR1: reads the rules store, and if it chooses another generation, orders the driver to switch to it. The
/// answer comes as `Event::Switched`. Every other case is a record line, and the proxy goes on as it is.
pub(super) fn reload(
    waits: &mut Waits,
    switcher: &mut Switcher,
    ingress: &SyncSender<Msg>,
    counters: &Counters,
    log: &Log,
) {
    log.line("reload: SIGUSR1");
    begin(waits, switcher, ingress, counters, log, None);
}

/// The switch of SIGUSR1 and of a switch order of the control socket: reads the rules store, and if it chooses
/// another generation, orders the driver to switch to it. With `expect` the generation that the store chooses has to
/// be that one; if it is not, nothing is started and nothing is counted. The store is read once, so what is checked
/// is what is switched to.
fn begin(
    waits: &mut Waits,
    switcher: &mut Switcher,
    ingress: &SyncSender<Msg>,
    counters: &Counters,
    log: &Log,
    expect: Option<Fingerprint>,
) -> Begun {
    match switcher.prepare() {
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
            waits.switch = Some(told);
            Begun::Started
        }
    }
}

/// An order of the control socket while the proxy serves. A status is answered at once. A switch that the driver
/// has taken is answered when the driver answers (`Control::switch_ended`); every other case is answered here.
pub(super) fn control_order(
    order: Order,
    waits: &mut Waits,
    switcher: &mut Switcher,
    ingress: &SyncSender<Msg>,
    counters: &Counters,
    log: &Log,
) {
    let switch = match order {
        Order::Status(reply) => return answer_status(waits, reply),
        Order::Switch(switch) => switch,
    };
    let serving = switcher.running();
    let expect = Some(switch.expect());
    let (outcome, reason) = match begin(waits, switcher, ingress, counters, log, expect) {
        Begun::Started => {
            if let Some(control) = waits.control.as_mut() {
                control.hold(switch);
            }
            return;
        }
        Begun::Busy => (Outcome::Busy, "switch under way"),
        Begun::Running => (Outcome::Unchanged, "already serving"),
        Begun::Changed => (Outcome::Refused, "current changed"),
        Begun::Refused => (Outcome::Refused, "store refused"),
        Begun::Failed => (Outcome::Failed, "driver did not take the order"),
    };
    switch.finish(outcome, Some(reason), serving, log);
}

/// An order of the control socket before the listeners are bound: a status is answered, and a switch is not done.
pub(super) fn control_while_starting(order: Order, waits: &Waits, switcher: &Switcher, log: &Log) {
    match order {
        Order::Status(reply) => answer_status(waits, reply),
        Order::Switch(switch) => {
            switch.finish(Outcome::Busy, Some("starting"), switcher.running(), log);
        }
    }
}

fn answer_status(waits: &Waits, reply: oneshot::Sender<Answer>) {
    if let Some(control) = &waits.control {
        let _ = reply.send(control.status(waits.switch.is_some()));
    }
}

/// SIGUSR2: reads the certificate and key files of the TLS listeners again. They all replace the ones in use, or none
/// does; the result is a record line, and the proxy goes on as it is.
pub(super) fn reload_certificates(ctx: &Ctx) {
    ctx.log.line("reload: SIGUSR2");
    match ctx.tls.reload(&ctx.cfg.listeners, &Files) {
        Ok(()) => {
            ctx.counters.add_reload(ReloadResult::Replaced);
            ctx.log.line("reload: certificates replaced");
            for place in ctx.tls.waiting() {
                ctx.log
                    .line(&format!("reload: tls certificate not issued yet ({place})"));
            }
        }
        Err(refusal) => {
            ctx.counters.add_reload(ReloadResult::Refused);
            ctx.log
                .line(&format!("reload: certificates refused: {refusal}"));
        }
    }
}
