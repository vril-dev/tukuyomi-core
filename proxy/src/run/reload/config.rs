//! SIGHUP and the reload order of the control socket: the configuration file read again, with the managed version
//! that the managed store chooses (SIGHUP) or with the one that the order names.
//!
//! The steps before the rules store (`start::read_parts`, which the start takes too) run on a thread of their own,
//! for the lookup of the names of the upstream servers and the country database take time that the main loop does not
//! have. The thread answers with what it made, and the main loop checks that none of the values that cannot change
//! while the proxy runs (see `fixed`) differs, binds the addresses of the listeners that no listener of the accept side
//! has, builds the new setup of it, and puts it in place of the old one in a single step, with the listeners of the
//! accept side put in the order of the file. A file that is refused anywhere, or has an address that cannot be bound,
//! leaves everything as it is. The listeners of the addresses that are gone are closed, and the old setup is retired:
//! the connections that hold it wind down after the request they serve, and the ones that are idle end. The rules store
//! is not read, so the generation that serves stays as it is.
//!
//! One reading is under way at a time, of either: SIGHUP while one is under way is a line, and a reload order then is
//! answered `busy` (`reload under way`). A reload order for a configuration without `managed` is refused
//! (`unmanaged`) before that, and starts nothing: `managed` cannot come or go while the proxy runs, so the reading
//! could only be refused. The order is answered when its reading has ended (`Control::reload_ended`), with the part
//! that refused and the sentence of its line when it was refused anywhere, the thread and the main loop alike. A
//! reading of either kind is counted, and an order that started none is not.
//!
//! The managed version of the setup that is current is held (see `managed::Hold`) by the reloader, so that a removal
//! does not take it, nor the files and `acme/` that SIGUSR2 reads again for it. A reading holds the version it read
//! from the store; when its setup replaces the current one, its hold replaces the old one, which is given back before
//! the line that says the configuration is replaced, and a reading that is refused drops its hold and leaves the old
//! one.

use std::path::PathBuf;
use std::thread;

use tokio::sync::oneshot;

use super::{Fixed, reload_certificates};
use crate::config::{Keep, addresses};
use crate::inbound::conn::{Setup, Shared};
use crate::inbound::transport::accept::Acceptor;
use crate::log::Log;
use crate::log::counters::ReloadResult;
use crate::managed::{Choice, Hold};
use crate::rules::bundle::hex;
use crate::run::control::{ReloadOrder, Reloaded};
use crate::run::signals::Waits;
use crate::run::start::{Parts, Reason, Refusal, read_parts};

/// The reading of the configuration file again: where the file is, the values that do not change while the proxy runs,
/// the hold on the managed version of the setup that is current, and whether SIGUSR2 came while a reading was under
/// way.
pub(in crate::run) struct Reloader {
    path: PathBuf,
    fixed: Fixed,
    /// The shared lock on the file of the managed version that serves (none without `managed`): the version is not
    /// removed while the proxy serves with it, and so the files and `acme/` that SIGUSR2 reads again for it are not
    /// cleaned up. The setup does not hold it, for a retired setup reads nothing of the store any more.
    hold: Option<Hold>,
    /// The certificates are to be read when the reading that is under way has ended.
    certificates: bool,
}

impl Reloader {
    /// For the file at `path`, whose values at the start are `fixed`, and the hold on the version it started with.
    pub(in crate::run) fn new(path: PathBuf, fixed: Fixed, hold: Option<Hold>) -> Reloader {
        Reloader {
            path,
            fixed,
            hold,
            certificates: false,
        }
    }

    /// SIGHUP: starts the thread that reads the file, unless one is at work already. The answer comes as
    /// `Event::Configured`. Every other case is a record line, and the proxy goes on as it is.
    pub(in crate::run) fn hangup(&self, waits: &mut Waits, shared: &Shared) {
        shared.log.line("reload: SIGHUP");
        if waits.config.is_some() {
            shared
                .log
                .line("reload: a configuration reload is in progress, ignored");
            return;
        }
        // A thread that cannot be started is counted and on a line, and SIGHUP has nobody else to tell.
        let _ = self.read(Choice::Current, waits, shared);
    }

    /// A reload order of the control socket: the reading of SIGHUP, with the version that the order names, unless the
    /// configuration in force has no `managed` (refused at once) or a reading is under way (`busy`). Once the thread
    /// is started the order waits in the control socket for the end of the reading.
    pub(in crate::run) fn order(&self, order: ReloadOrder, waits: &mut Waits, shared: &Shared) {
        let setup = shared.setup.current();
        let Some(order) = managed_only(order, &setup, &shared.log) else {
            return;
        };
        if waits.config.is_some() {
            order.finish(Reloaded::Busy("reload under way"), &setup, &shared.log);
            return;
        }
        let name = order.managed();
        shared
            .log
            .line(&format!("reload: control reload {}", hex(&name)));
        match self.read(Choice::Named(name), waits, shared) {
            Ok(()) => {
                if let Some(control) = waits.control.as_mut() {
                    control.hold_reload(order);
                }
            }
            Err(refusal) => order.finish(Reloaded::Refused(refusal), &setup, &shared.log),
        }
    }

    /// Starts the thread that reads the file with the version of `choice`; its answer comes as `Event::Configured`. A
    /// thread that cannot be started is a refusal of the reading.
    fn read(&self, choice: Choice, waits: &mut Waits, shared: &Shared) -> Result<(), Refusal> {
        let (reply, told) = oneshot::channel();
        let (path, thread_log) = (self.path.clone(), shared.log.clone());
        let spawned = thread::Builder::new().name("reload".into()).spawn(move || {
            let reading = read_parts(&path, &choice, "reload", &thread_log);
            let _ = reply.send(reading.map(Box::new));
        });
        match spawned {
            Ok(_) => {
                waits.config = Some(told);
                Ok(())
            }
            Err(_) => Err(refused(
                shared,
                Reason::Thread,
                "the reload thread cannot be started",
            )),
        }
    }

    /// The answer of the thread: why it refused the file, which it has said on a line, or the parts that replace those
    /// of the setup that is current, and the listeners of the accept side follow them, if no value that cannot change
    /// differs and every address that is new can be bound.
    pub(in crate::run) async fn answered(
        &mut self,
        parts: Result<Box<Parts>, Refusal>,
        waits: &mut Waits,
        shared: &Shared,
    ) {
        let reading = match (parts, waits.accept.as_mut()) {
            (Ok(parts), Some(acceptor)) => self.replace(*parts, acceptor, shared).await,
            // The thread is only started once the listeners are bound, so this cannot be; the file is refused all the
            // same.
            (Ok(_), None) => Err(refused(
                shared,
                Reason::Listener,
                "the listeners are not bound yet",
            )),
            (Err(refusal), _) => {
                shared.counters.add_config_reload(ReloadResult::Refused);
                Err(refusal)
            }
        };
        self.ended(reading, waits, shared);
    }

    /// The thread ended without an answer.
    pub(in crate::run) fn unanswered(&mut self, waits: &mut Waits, shared: &Shared) {
        let refusal = refused(shared, Reason::Thread, "the reload thread gave no answer");
        self.ended(Err(refusal), waits, shared);
    }

    /// SIGUSR2: reads the certificates now, or, while the file is being read again, when that has ended: the parts
    /// that the thread made have the files as they were when it read them.
    pub(in crate::run) fn certificates(&mut self, waits: &Waits, shared: &Shared) {
        if waits.config.is_some() {
            self.certificates = true;
        } else {
            reload_certificates(shared, &shared.setup.current());
        }
    }

    /// Binds the addresses of the listeners of `parts` that `acceptor` has not, builds the setup of `parts` and makes
    /// it the current one, with the rate limit of the old setup going on if it can. The listeners of `acceptor` are
    /// put in the order of the file in the same step, so a connection that is accepted from then on is numbered by the
    /// listeners of the setup it takes. The listeners of the addresses that are gone are closed, and the old setup is
    /// retired. The hold on the version of `parts` takes the place of the one of the old setup, which goes before the
    /// line that says the configuration is replaced. A refusal drops `parts` with its hold before its line, and keeps
    /// the old one.
    async fn replace(
        &mut self,
        parts: Parts,
        acceptor: &mut Acceptor,
        shared: &Shared,
    ) -> Result<(), Refusal> {
        if let Some(key) = self.fixed.first_difference(&parts.fixed) {
            // The hold on the version that was read goes before the line, as the old one does at a replacement.
            drop(parts);
            return Err(refused(
                shared,
                Reason::Fixed,
                &format!("{key} cannot change while running"),
            ));
        }
        let listening = addresses(&parts.proxy.listeners);
        let bound = match acceptor.bind_new(&listening).await {
            Ok(bound) => bound,
            Err(at) => {
                drop(parts);
                return Err(refused(
                    shared,
                    Reason::Listener,
                    &format!("listener {} cannot be bound", at + 1),
                ));
            }
        };
        let keep = parts
            .records
            .as_ref()
            .map_or(Keep::BestEffort, |records| records.keep);
        let earlier = shared.setup.current();
        let setup = Setup::new(
            parts.proxy,
            parts.sha256,
            &parts.forward,
            parts.tls,
            parts.challenge,
            parts.policy,
            keep,
            earlier.rate_limit.as_ref(),
        )
        .with_managed(parts.managed);
        let carried = match (&setup.rate_limit, &earlier.rate_limit) {
            (Some(limit), Some(old)) => limit.continues(old),
            _ => false,
        };
        if setup.rate_limit.is_some() && !carried {
            shared.log.line("reload: rate limit table started anew");
        }
        acceptor.arrange(&listening, bound);
        shared.setup.replace(setup);
        earlier.retire();
        self.hold = parts.hold;
        shared.counters.add_config_reload(ReloadResult::Replaced);
        // With `managed`, the line names the version too.
        let managed = parts
            .managed
            .map_or_else(String::new, |name| format!(" managed {}", hex(&name)));
        shared.log.line(&format!(
            "reload: configuration replaced {}{managed}",
            hex(&parts.sha256)
        ));
        Ok(())
    }

    /// The reading has ended, replaced or not: the reload order that asked for it, if there is one, gets its answer,
    /// and a SIGUSR2 that came meanwhile reads the certificates of the setup that is current now.
    fn ended(&mut self, reading: Result<(), Refusal>, waits: &mut Waits, shared: &Shared) {
        if let Some(control) = waits.control.as_mut() {
            control.reload_ended(reading, &shared.setup.current(), &shared.log);
        }
        if std::mem::take(&mut self.certificates) {
            reload_certificates(shared, &shared.setup.current());
        }
    }
}

/// A reload order before the listeners are bound: refused if the configuration in force has no `managed`, else
/// `busy` (`starting`).
pub(in crate::run) fn reload_while_starting(order: ReloadOrder, shared: &Shared) {
    let setup = shared.setup.current();
    if let Some(order) = managed_only(order, &setup, &shared.log) {
        order.finish(Reloaded::Busy("starting"), &setup, &shared.log);
    }
}

/// The order, if `setup`, the setup in force, has `managed`; else the order is refused (`unmanaged`) here.
fn managed_only(order: ReloadOrder, setup: &Setup, log: &Log) -> Option<ReloadOrder> {
    if setup.managed.is_some() {
        return Some(order);
    }
    let refusal = Refusal {
        reason: Reason::Unmanaged,
        detail: "the configuration in force has no managed object".to_owned(),
    };
    order.finish(Reloaded::Refused(refusal), setup, log);
    None
}

/// A refusal of the main loop: counted, and on its line, `reload: configuration refused: <detail>`.
fn refused(shared: &Shared, reason: Reason, detail: &str) -> Refusal {
    shared.counters.add_config_reload(ReloadResult::Refused);
    shared
        .log
        .line(&format!("reload: configuration refused: {detail}"));
    Refusal {
        reason,
        detail: detail.to_owned(),
    }
}
