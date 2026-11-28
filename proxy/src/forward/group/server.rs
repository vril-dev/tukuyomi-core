//! A server of a group, what it counts of its failures to be left out, and how many requests it has.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::lasting::{InUse, Lasting};
use crate::config::ServerConfig;
use crate::forward::pool::Pool;
use crate::forward::tls::Secure;

/// A server of a group: where it is, its weight, how it counts, its view of the pool of the group, how it is spoken
/// to if the group has `tls`, what has failed, and how many requests it has. What has failed is shared with the same
/// server of the group that this one replaces, and of the group that replaces this one, if it counts and is spoken to
/// as they are; how many requests it has is shared with it whatever the two are like (see `follow`).
pub struct Server {
    address: SocketAddr,
    weight: i64,
    max_fails: u32,
    fail_timeout_ms: u64,
    pool: Pool,
    secure: Option<Secure>,
    passive: Arc<PassiveHealth>,
    lasting: Arc<Lasting>,
}

/// What a server counts of its failures to be left out: the failures in the window, and the time until which the
/// server is left out. The times are milliseconds from the start that the groups of all the readings of the
/// configuration count from (see `Group::since`).
#[derive(Default)]
struct PassiveHealth {
    /// Failures in the window that began at `window`.
    fails: AtomicU32,
    window: AtomicU64,
    /// The server is left out until this time.
    down_until: AtomicU64,
}

impl Server {
    pub(super) fn new(cfg: &ServerConfig, pool: Pool, secure: Option<Secure>) -> Server {
        Server {
            address: cfg.address,
            weight: i64::from(cfg.weight),
            max_fails: cfg.max_fails,
            // The configuration bounds it to an hour, so this is exact.
            fail_timeout_ms: u64::try_from(cfg.fail_timeout.as_millis()).unwrap_or(u64::MAX),
            pool,
            secure,
            passive: Arc::default(),
            lasting: Arc::default(),
        }
    }

    /// Goes on with what `earlier` keeps. The requests that it has are counted together whatever the two servers are
    /// like, for a request is the same request whatever their `max_fails`, `fail_timeout` and TLS are. The failures
    /// that it counts are counted together only if this server counts and is spoken to as it is: the same `max_fails`
    /// and `fail_timeout`, and either neither has TLS or both check for the same name against authorities that are
    /// the same bytes. The failures in the window and the time until which a server is left out are counted with
    /// these, so with another `max_fails` or `fail_timeout` they would not mean what they meant, and a failure of TLS
    /// may not be one with other authorities.
    pub(super) fn follow(&mut self, earlier: &Server) {
        self.lasting = Arc::clone(&earlier.lasting);
        let spoken_alike = match (&self.secure, &earlier.secure) {
            (None, None) => true,
            (Some(secure), Some(earlier)) => secure.same_as(earlier),
            (Some(_), None) | (None, Some(_)) => false,
        };
        if spoken_alike
            && self.max_fails == earlier.max_fails
            && self.fail_timeout_ms == earlier.fail_timeout_ms
        {
            self.passive = Arc::clone(&earlier.passive);
        }
    }

    /// Whether this server counts the failures of `earlier`: the two have what has failed in common.
    pub(super) fn continues(&self, earlier: &Server) -> bool {
        Arc::ptr_eq(&self.passive, &earlier.passive)
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// The weight of the server in the choice among the servers of its group, as the configuration gives it.
    pub(super) fn weight(&self) -> i64 {
        self.weight
    }

    pub(in crate::forward) fn pool(&self) -> &Pool {
        &self.pool
    }

    /// The number of requests that the server has: those that were chosen for it and whose answers are not over.
    pub(in crate::forward) fn in_use(&self) -> u64 {
        self.lasting.in_use()
    }

    /// Counts a request against the server, until the value that is returned is dropped.
    pub(in crate::forward) fn count_request(&self) -> InUse {
        InUse::new(&self.lasting)
    }

    /// How to speak TLS to the server, if the group has `tls`; `None`: the connection is plain.
    pub(in crate::forward) fn secure(&self) -> Option<&Secure> {
        self.secure.as_ref()
    }

    /// Counts a failure that came `now` milliseconds after the start that the times are counted from (see
    /// `Group::since`).
    pub(super) fn fail(&self, now: u64) {
        if self.max_fails == 0 {
            return;
        }
        let expired =
            now.saturating_sub(self.passive.window.load(Ordering::Relaxed)) >= self.fail_timeout_ms;
        let fails = if self.passive.fails.load(Ordering::Relaxed) == 0 || expired {
            self.passive.window.store(now, Ordering::Relaxed);
            1
        } else {
            self.passive.fails.load(Ordering::Relaxed).saturating_add(1)
        };
        self.passive.fails.store(fails, Ordering::Relaxed);
        if fails >= self.max_fails {
            self.passive
                .down_until
                .store(now.saturating_add(self.fail_timeout_ms), Ordering::Relaxed);
        }
    }

    pub(super) fn up(&self, now: u64) -> bool {
        self.max_fails == 0 || now >= self.passive.down_until.load(Ordering::Relaxed)
    }
}
