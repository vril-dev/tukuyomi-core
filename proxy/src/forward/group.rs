//! The upstream groups, the routes that choose one, and which servers of a group can be used.
//!
//! A request goes to the group that the most exact route holding for it names, or to the default group; with
//! neither it has no group (`Upstreams::find`). A group has one or more servers and one pool of waiting connections
//! that they share, so the connections that wait are bounded for the group, not for each server. The server a
//! request goes to is chosen by weight among the servers that can be used and that the request has not tried yet
//! (see `select`).
//!
//! A server counts the failures of its requests (`Group::fail`; what a failure is, is said at `origin`). When
//! `max_fails` of them come within `fail_timeout`, counted from the first, the server is left out for
//! `fail_timeout`; after that it is used again, and needs `max_fails` new failures to be left out again. A server
//! with a `max_fails` of 0 is never left out, nor is the only server of a group. A group of which no server can be
//! used has none to give (`Group::pick` is `None`).
//!
//! The counts are atomic numbers that are read and written one at a time, so two failures that come in the same
//! instant may count as one; a count that is a little low or high changes how soon a server is left out, nothing
//! that a client sees. The times are milliseconds from the start of the group.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use tokio::time::Instant;

use crate::config::{ForwardConfig, GroupConfig, ProxyConfig, ServerConfig};
use crate::forward::pool::Pool;
use crate::forward::select::Turn;
use crate::route::Table;

/// The groups of the configuration, and the routes to them.
pub struct Upstreams {
    groups: Vec<Group>,
    /// The target of a route is the index of its group.
    routes: Table<usize>,
    default: Option<usize>,
}

impl Upstreams {
    /// The groups, with a pool for each group as `proxy` says. `cfg` has been checked.
    pub fn new(cfg: &ForwardConfig, proxy: &ProxyConfig) -> Upstreams {
        let born = Instant::now();
        Upstreams {
            groups: cfg
                .groups
                .iter()
                .map(|group| Group::new(group, proxy, born))
                .collect(),
            routes: cfg.routes.clone(),
            default: cfg.default,
        }
    }

    /// The group for a request with this `Host` value and this request target: that of the most exact route that
    /// holds for it, or else the default group.
    pub fn find(&self, host: Option<&[u8]>, target: &[u8]) -> Option<&Group> {
        let index = self.routes.find(host, target).copied().or(self.default)?;
        self.groups.get(index)
    }

    /// The group at `index`, for the tests.
    #[cfg(test)]
    pub(crate) fn group(&self, index: usize) -> &Group {
        &self.groups[index]
    }
}

/// The servers of a request that were tried already. A group has at most 64.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Tried(u64);

impl Tried {
    fn has(self, index: usize) -> bool {
        // An index past the last bit counts as tried, so that it is never chosen.
        u32::try_from(index)
            .ok()
            .and_then(|bit| self.0.checked_shr(bit))
            .is_none_or(|rest| rest & 1 == 1)
    }

    pub(super) fn add(&mut self, index: usize) {
        if let Some(bit) = u32::try_from(index)
            .ok()
            .and_then(|bit| 1u64.checked_shl(bit))
        {
            self.0 |= bit;
        }
    }
}

/// A server of a group: where it is, how it counts, its view of the pool of the group, and what has failed.
pub struct Server {
    address: SocketAddr,
    max_fails: u32,
    fail_timeout_ms: u64,
    pool: Pool,
    /// Failures in the window that began at `window`.
    fails: AtomicU32,
    window: AtomicU64,
    /// The server is left out until this time.
    down_until: AtomicU64,
}

impl Server {
    fn new(cfg: &ServerConfig, pool: Pool) -> Server {
        Server {
            address: cfg.address,
            max_fails: cfg.max_fails,
            // The configuration bounds it to an hour, so this is exact.
            fail_timeout_ms: u64::try_from(cfg.fail_timeout.as_millis()).unwrap_or(u64::MAX),
            pool,
            fails: AtomicU32::new(0),
            window: AtomicU64::new(0),
            down_until: AtomicU64::new(0),
        }
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }

    pub(super) fn pool(&self) -> &Pool {
        &self.pool
    }

    /// Counts a failure that came `now` milliseconds after the start of the group.
    fn fail(&self, now: u64) {
        if self.max_fails == 0 {
            return;
        }
        let expired =
            now.saturating_sub(self.window.load(Ordering::Relaxed)) >= self.fail_timeout_ms;
        let fails = if self.fails.load(Ordering::Relaxed) == 0 || expired {
            self.window.store(now, Ordering::Relaxed);
            1
        } else {
            self.fails.load(Ordering::Relaxed).saturating_add(1)
        };
        self.fails.store(fails, Ordering::Relaxed);
        if fails >= self.max_fails {
            self.down_until
                .store(now.saturating_add(self.fail_timeout_ms), Ordering::Relaxed);
        }
    }

    fn up(&self, now: u64) -> bool {
        self.max_fails == 0 || now >= self.down_until.load(Ordering::Relaxed)
    }
}

/// A group: its name, its servers and the state of the choice among them.
pub struct Group {
    name: Arc<str>,
    servers: Vec<Server>,
    turn: Turn,
    born: Instant,
}

impl Group {
    fn new(cfg: &GroupConfig, proxy: &ProxyConfig, born: Instant) -> Group {
        let pool = Pool::new(proxy);
        Group {
            name: Arc::from(cfg.name.as_str()),
            servers: cfg
                .servers
                .iter()
                .enumerate()
                .map(|(index, server)| Server::new(server, pool.of(index)))
                .collect(),
            turn: Turn::new(&cfg.servers),
            born,
        }
    }

    pub fn name(&self) -> &Arc<str> {
        &self.name
    }

    /// The number of servers: a request tries each of them once at most.
    pub(super) fn len(&self) -> usize {
        self.servers.len()
    }

    pub(super) fn server(&self, index: usize) -> &Server {
        &self.servers[index]
    }

    /// Milliseconds from the start of the group to `at`.
    fn since(&self, at: Instant) -> u64 {
        u64::try_from(at.saturating_duration_since(self.born).as_millis()).unwrap_or(u64::MAX)
    }

    /// Whether the server can be used at `now`. The only server of a group always can.
    fn usable(&self, index: usize, now: u64) -> bool {
        self.servers.len() == 1 || self.servers[index].up(now)
    }

    /// The server to try next: chosen by weight among those that can be used at `now` and are not in `tried`, the
    /// `backup` servers only when no other can be chosen.
    pub(super) fn pick(&self, tried: Tried, now: Instant) -> Option<usize> {
        let now = self.since(now);
        self.turn
            .pick(|index| !tried.has(index) && self.usable(index, now))
    }

    /// Counts a failure of the server at `index`, at `now`.
    pub(super) fn fail(&self, index: usize, now: Instant) {
        self.servers[index].fail(self.since(now));
    }
}

#[cfg(test)]
mod tests;
