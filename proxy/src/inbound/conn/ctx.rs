//! What a connection holds: the state that every connection of the process shares (`Shared`), the part that one
//! configuration makes (`Setup`), and the `Ctx` of one connection, which has both.
//!
//! A connection takes the setup that is current when it starts (see `SharedSetup`) and uses that one to its end, so
//! what it was started with does not change under it.

use std::sync::{Arc, PoisonError, RwLock};

use tokio::sync::Semaphore;

use crate::config::{ForwardConfig, Keep, PolicyConfig, ProxyConfig};
use crate::forward::client_ip::Access;
use crate::forward::group::Upstreams;
use crate::inbound::challenge::Challenge;
use crate::inbound::session::RequestIds;
use crate::inbound::transport::tls::Tls;
use crate::inspect::driver::Ingress;
use crate::log::Log;
use crate::log::counters::Counters;
use crate::policy::RateLimit;
use crate::policy::country::Geo;
use crate::rules::routes::SharedRoutes;

/// What every connection shares for as long as the process runs: the byte budget of held bodies and of the kernel's
/// copies, the inspection permits (as many as the kernel's waiting queue), the routes of the generation that serves,
/// the way to the driver, the numbers of the requests, the counters that `/metrics` shows, the logger, and the setup
/// that the connections that start now take.
pub struct Shared {
    pub budget: Arc<Semaphore>,
    pub inspect: Arc<Semaphore>,
    pub routes: SharedRoutes,
    pub log: Log,
    pub ingress: Arc<Ingress>,
    pub ids: RequestIds,
    pub counters: Counters,
    pub setup: SharedSetup,
}

/// What a configuration makes for the connections: the configuration, the upstream groups with the routes to them and
/// the connections that wait to be used again, the TLS of the listeners that end it, the answer to the challenge of
/// the CA, if the configuration has `acme`, the networks and countries that may not use the proxy at all, the country
/// database if some list of countries needs one, the rate limit if the configuration has one, and what a route does
/// with a request whose record cannot be kept when it does not say (`records.keep`). It is not changed once it is
/// made.
pub struct Setup {
    pub cfg: ProxyConfig,
    pub upstreams: Upstreams,
    pub tls: Tls,
    pub challenge: Option<Challenge>,
    /// The `access` of the configuration: asked of every request before its route is looked for.
    pub access: Access,
    /// The country database, there if some list of countries of the `access` or of a route needs one.
    pub country: Option<Geo>,
    /// The `rate_limit` of the configuration, if it has one.
    pub rate_limit: Option<RateLimit>,
    /// What a route without `records` does when the record of a request cannot be kept.
    pub keep: Keep,
}

impl Setup {
    /// The setup of `cfg`, with the upstream groups of `forward`, and the `access`, the country database and the
    /// `rate_limit` of `policy`.
    pub fn new(
        cfg: ProxyConfig,
        forward: &ForwardConfig,
        tls: Tls,
        challenge: Option<Challenge>,
        policy: PolicyConfig,
        keep: Keep,
    ) -> Setup {
        Setup {
            upstreams: Upstreams::new(forward, &cfg),
            cfg,
            tls,
            challenge,
            access: policy.access,
            country: policy.country,
            rate_limit: policy.rate_limit.as_ref().map(RateLimit::new),
            keep,
        }
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
}

/// What one connection holds: the state that every connection shares, and the setup that was current when the
/// connection started.
pub struct Ctx {
    pub shared: Arc<Shared>,
    pub setup: Arc<Setup>,
}
