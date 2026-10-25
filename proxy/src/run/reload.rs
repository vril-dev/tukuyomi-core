//! SIGUSR1 and SIGUSR2: the switch to the generation that the rules store chooses now, and the reading of the
//! certificate and key files again.

use std::sync::mpsc::SyncSender;

use tokio::sync::oneshot;

use super::signals::Waits;
use crate::inbound::conn::Ctx;
use crate::inbound::transport::tls::Files;
use crate::inspect::driver::{Msg, Switch};
use crate::log::Log;
use crate::rules::switch::{Next, Switcher};

/// SIGUSR1: reads the rules store, and if it chooses another generation, orders the driver to switch to it. The
/// answer comes as `Event::Switched`. Every other case is a record line, and the proxy goes on as it is.
pub(super) fn reload(
    waits: &mut Waits,
    switcher: &mut Switcher,
    ingress: &SyncSender<Msg>,
    log: &Log,
) {
    log.line("reload: SIGUSR1");
    match switcher.prepare() {
        Next::Busy => log.line("reload: a switch is in progress, ignored"),
        Next::Running(generation) => log.line(&format!(
            "reload: generation {} is already running",
            generation.hex()
        )),
        Next::Refused(why) => log.line(&format!("reload: rules store refused: {why}")),
        Next::Ready {
            generation,
            mode,
            routes,
            kernel,
        } => {
            log.line(&format!("reload: starting generation {}", generation.hex()));
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
                switcher.finish(false);
                return;
            }
            waits.switch = Some(told);
        }
    }
}

/// SIGUSR2: reads the certificate and key files of the TLS listeners again. They all replace the ones in use, or none
/// does; the result is a record line, and the proxy goes on as it is.
pub(super) fn reload_certificates(ctx: &Ctx) {
    ctx.log.line("reload: SIGUSR2");
    match ctx.tls.reload(&ctx.cfg.listeners, &Files) {
        Ok(()) => {
            ctx.log.line("reload: certificates replaced");
            for place in ctx.tls.waiting() {
                ctx.log
                    .line(&format!("reload: tls certificate not issued yet ({place})"));
            }
        }
        Err(refusal) => ctx
            .log
            .line(&format!("reload: certificates refused: {refusal}")),
    }
}
