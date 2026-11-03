//! SIGHUP: the configuration file read again.
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

use std::path::PathBuf;
use std::thread;

use tokio::sync::oneshot;

use super::{Fixed, reload_certificates};
use crate::config::{Keep, addresses};
use crate::inbound::conn::{Setup, Shared};
use crate::inbound::transport::accept::Acceptor;
use crate::log::Log;
use crate::log::counters::{Counters, ReloadResult};
use crate::rules::bundle::hex;
use crate::run::signals::Waits;
use crate::run::start::{Parts, read_parts};

/// The reading of the configuration file again: where the file is, the values that do not change while the proxy runs,
/// and whether SIGUSR2 came while a reading was under way.
pub(in crate::run) struct Reloader {
    path: PathBuf,
    fixed: Fixed,
    /// The certificates are to be read when the reading that is under way has ended.
    certificates: bool,
}

impl Reloader {
    /// For the file at `path`, whose values at the start are `fixed`.
    pub(in crate::run) fn new(path: PathBuf, fixed: Fixed) -> Reloader {
        Reloader {
            path,
            fixed,
            certificates: false,
        }
    }

    /// SIGHUP: starts the thread that reads the file, unless one is at work already. The answer comes as
    /// `Event::Configured`. Every other case is a record line, and the proxy goes on as it is.
    pub(in crate::run) fn hangup(&self, waits: &mut Waits, counters: &Counters, log: &Log) {
        log.line("reload: SIGHUP");
        if waits.config.is_some() {
            log.line("reload: a configuration reload is in progress, ignored");
            return;
        }
        let (reply, told) = oneshot::channel();
        let (path, thread_log) = (self.path.clone(), log.clone());
        let spawned = thread::Builder::new().name("reload".into()).spawn(move || {
            let _ = reply.send(read_parts(&path, "reload", &thread_log).ok().map(Box::new));
        });
        match spawned {
            Ok(_) => waits.config = Some(told),
            Err(_) => {
                counters.add_config_reload(ReloadResult::Refused);
                log.line("reload: configuration refused: the reload thread cannot be started");
            }
        }
    }

    /// The answer of the thread: `None` if it refused the file and said why. Otherwise the parts replace those of the
    /// setup that is current, and the listeners of the accept side follow them, if no value that cannot change differs
    /// and every address that is new can be bound.
    pub(in crate::run) async fn answered(
        &mut self,
        parts: Option<Box<Parts>>,
        waits: &mut Waits,
        shared: &Shared,
    ) {
        match (parts, waits.accept.as_mut()) {
            (Some(parts), Some(acceptor)) => self.replace(*parts, acceptor, shared).await,
            // The thread is only started once the listeners are bound, so this cannot be; the file is refused all the
            // same.
            (Some(_), None) => {
                shared.counters.add_config_reload(ReloadResult::Refused);
                shared
                    .log
                    .line("reload: configuration refused: the listeners are not bound yet");
            }
            // The thread refused the file and said why.
            (None, _) => shared.counters.add_config_reload(ReloadResult::Refused),
        }
        self.ended(shared);
    }

    /// The thread ended without an answer.
    pub(in crate::run) fn unanswered(&mut self, shared: &Shared) {
        shared.counters.add_config_reload(ReloadResult::Refused);
        shared
            .log
            .line("reload: configuration refused: the reload thread gave no answer");
        self.ended(shared);
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
    /// retired.
    async fn replace(&self, parts: Parts, acceptor: &mut Acceptor, shared: &Shared) {
        if let Some(key) = self.fixed.first_difference(&parts.fixed) {
            shared.counters.add_config_reload(ReloadResult::Refused);
            shared.log.line(&format!(
                "reload: configuration refused: {key} cannot change while running"
            ));
            return;
        }
        let listening = addresses(&parts.proxy.listeners);
        let bound = match acceptor.bind_new(&listening).await {
            Ok(bound) => bound,
            Err(at) => {
                shared.counters.add_config_reload(ReloadResult::Refused);
                shared.log.line(&format!(
                    "reload: configuration refused: listener {} cannot be bound",
                    at + 1
                ));
                return;
            }
        };
        let keep = parts
            .records
            .as_ref()
            .map_or(Keep::BestEffort, |records| records.keep);
        let earlier = shared.setup.current();
        let setup = Setup::new(
            parts.proxy,
            &parts.forward,
            parts.tls,
            parts.challenge,
            parts.policy,
            keep,
            earlier.rate_limit.as_ref(),
        );
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
        shared.counters.add_config_reload(ReloadResult::Replaced);
        shared.log.line(&format!(
            "reload: configuration replaced {}",
            hex(&parts.sha256)
        ));
    }

    /// The reading has ended, replaced or not: a SIGUSR2 that came meanwhile reads the certificates of the setup that
    /// is current now.
    fn ended(&mut self, shared: &Shared) {
        if std::mem::take(&mut self.certificates) {
            reload_certificates(shared, &shared.setup.current());
        }
    }
}
