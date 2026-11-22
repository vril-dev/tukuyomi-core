//! What a connection holds: the state that every connection of the process shares (`Shared`), the part that one
//! configuration makes (`Setup`), and the `Ctx` of one connection, which has both.
//!
//! A connection takes the setup that is current when it starts (see `SharedSetup`) and uses that one to its end, so
//! what it was started with does not change under it. When the configuration is read again the new setup takes the
//! place of the old one, which is retired: the connections that hold it wind down after the request they serve.

use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use tokio::sync::{Semaphore, watch};

use crate::config::{ForwardConfig, Keep, PolicyConfig, ProxyConfig};
use crate::forward::group::Upstreams;
use crate::inbound::challenge::Challenge;
use crate::inbound::session::RequestIds;
use crate::inbound::transport::tls::Tls;
use crate::inspect::driver::Ingress;
use crate::inspect::engines::Gates;
use crate::log::Log;
use crate::log::counters::Counters;
use crate::policy::country::Geo;
use crate::policy::{Scope, Scopes};

/// What every connection shares for as long as the process runs: the byte budget of held bodies and of the kernel's
/// copies, the gate of each engine (the inspection permits, as many as the kernel's waiting queue, and the routes of
/// the generation that serves), the way to the driver, the numbers of the requests, the counters that `/metrics`
/// shows, the logger, and the setup that the connections that start now take.
pub struct Shared {
    pub budget: Arc<Semaphore>,
    pub gates: Gates,
    pub log: Log,
    pub ingress: Arc<Ingress>,
    pub ids: RequestIds,
    pub counters: Counters,
    pub setup: SharedSetup,
}

/// What a configuration makes for the connections: the configuration, the SHA-256 of its file, the time the lookup of
/// the names of its servers could take, the upstream groups with the routes to them and the connections that wait to be
/// used again, the TLS of the listeners that end it, the answer to the challenge of the CA, if the configuration has
/// `acme`, the `access` and the rate limits of the configuration and of its host policies, the country database if some
/// list of countries needs one, and what a route does with a request whose record
/// cannot be kept when it does not say (`records.keep`). It is not
/// changed once it is made, except that it can be retired, once, and that SIGUSR2 replaces the certificates in its
/// `tls` (`Tls::reload`).
pub struct Setup {
    pub cfg: ProxyConfig,
    /// The SHA-256 of the bytes of the configuration file that this setup was made from.
    pub sha256: [u8; 32],
    /// The name of the managed version it was made with, for a file with `managed` (see `with_managed`).
    pub managed: Option<[u8; 32]>,
    /// The `forward.resolve_timeout_ms` of the file: what a reload order of the control socket waits for, with a
    /// margin, while this setup is in force.
    pub resolve_timeout: Duration,
    pub upstreams: Upstreams,
    pub tls: Tls,
    pub challenge: Option<Challenge>,
    /// The country database, there if some list of countries of the `access`, of a host policy or of a route needs one.
    pub country: Option<Geo>,
    /// The `access` and the rate limits of the configuration and of its host policies: asked of every request before
    /// its route is looked for (see `scope`).
    pub scopes: Scopes,
    /// What a route without `records` does when the record of a request cannot be kept.
    pub keep: Keep,
    /// Set once the setup has been replaced by another. The connections that hold it are told.
    retired: watch::Sender<bool>,
}

impl Setup {
    /// The setup of `cfg`, which is read from a file whose SHA-256 is `sha256`, with the upstream groups of `forward`,
    /// and the country database and the scopes of `policy`. Each table of the rate limits goes on counting the
    /// clients of the one it follows in `earlier`, the scopes of the setup that this one replaces, if there is one and
    /// the two have the same `keys`, `rate` and `burst` (see `policy::Scopes`).
    // One argument for each part of what the configuration file gives; a struct of them would only repeat their names.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cfg: ProxyConfig,
        sha256: [u8; 32],
        forward: &ForwardConfig,
        tls: Tls,
        challenge: Option<Challenge>,
        mut policy: PolicyConfig,
        keep: Keep,
        earlier: Option<&Scopes>,
    ) -> Setup {
        Setup {
            upstreams: Upstreams::new(forward, &cfg),
            cfg,
            sha256,
            managed: None,
            resolve_timeout: forward.resolve_timeout,
            tls,
            challenge,
            country: policy.country.take(),
            scopes: Scopes::new(policy, earlier),
            keep,
            retired: watch::channel(false).0,
        }
    }

    /// What the policy asks of a request whose `Host` is `host` (see `policy::Scopes::scope`): the request of a
    /// connection and the first request on the listener that redirects to https alike.
    pub fn scope(&self, host: Option<&[u8]>) -> Scope<'_> {
        self.scopes.scope(host)
    }

    /// The setup, made with the managed version `name` (none for a file without `managed`).
    pub fn with_managed(mut self, name: Option<[u8; 32]>) -> Setup {
        self.managed = name;
        self
    }

    /// Retires the setup: the receivers of `watch` see `true`. Retiring it again does nothing more. Nothing is
    /// refused to the connections that hold it; they wind down.
    pub fn retire(&self) {
        self.retired.send_replace(true);
    }

    /// The setup is retired.
    pub fn is_retired(&self) -> bool {
        *self.retired.borrow()
    }

    /// A receiver that is told when the setup is retired. One that is made after that sees no change; it asks
    /// `is_retired` first.
    pub fn watch(&self) -> watch::Receiver<bool> {
        self.retired.subscribe()
    }
}

/// The setup that the connections that start now take. A connection reads it once, when it starts, and uses that one
/// to its end.
#[derive(Clone)]
pub struct SharedSetup(Arc<RwLock<Arc<Setup>>>);

impl SharedSetup {
    pub fn new(setup: Setup) -> SharedSetup {
        SharedSetup(Arc::new(RwLock::new(Arc::new(setup))))
    }

    /// The setup as it is now. A connection keeps this one.
    pub fn current(&self) -> Arc<Setup> {
        Arc::clone(&self.0.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Makes `setup` the one that the connections that start from now on take.
    pub fn replace(&self, setup: Setup) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(setup);
    }
}

/// What one connection holds: the state that every connection shares, and the setup that was current when the
/// connection started.
pub struct Ctx {
    pub shared: Arc<Shared>,
    pub setup: Arc<Setup>,
}
