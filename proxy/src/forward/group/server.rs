//! A server of a group, and what it counts of its failures to be left out.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::config::ServerConfig;
use crate::forward::pool::Pool;
use crate::forward::tls::Secure;

/// A server of a group: where it is, its weight, how it counts, its view of the pool of the group, how it is spoken
/// to if the group has `tls`, and what has failed.
pub struct Server {
    address: SocketAddr,
    weight: i64,
    max_fails: u32,
    fail_timeout_ms: u64,
    pool: Pool,
    secure: Option<Secure>,
    passive: PassiveHealth,
}

/// What a server counts of its failures to be left out: the failures in the window, and the time until which the
/// server is left out.
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
            passive: PassiveHealth::default(),
        }
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

    /// How to speak TLS to the server, if the group has `tls`; `None`: the connection is plain.
    pub(in crate::forward) fn secure(&self) -> Option<&Secure> {
        self.secure.as_ref()
    }

    /// Counts a failure that came `now` milliseconds after the start of the group.
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
