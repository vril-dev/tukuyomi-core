//! The upstream groups, the routes that choose one, and which servers of a group can be used.
//!
//! A request goes to the route that is the most exact of those holding for it, or to the default route, which
//! names the default group and turns nobody away, edits nothing and has no `stream`; with neither it has no route
//! (`Upstreams::find`). A route names a group, tells which clients may use it (`Access`), how the request and the
//! response are edited (`Rewrite`), whether its responses may take long (`Stream`) and, if it is to take less than the
//! proxy does, how long a request body may be. A request may be another way
//! to write a request for a route that it does not hold for, so the access lists of every route that it could be
//! taken for are asked for, not only those of the route it goes to (`Upstreams::accesses`), and only if some route
//! has a list (`Upstreams::guarded`). A group has one or more servers and one pool of waiting connections
//! that they share, so the connections that wait are bounded for the group, not for each server. A group with `tls`
//! is reached over TLS at every server, and a group without it never is (see `tls`); as a waiting connection is
//! taken only for the server it is connected to, a plain connection is never used where TLS is wanted, nor the other
//! way round. The server a request goes to is chosen by weight among the servers that can be used and that the
//! request has not tried yet (see `select`).
//!
//! A server counts the failures of its requests (`Group::fail`; what a failure is, is said at `origin`). When
//! `max_fails` of them come within `fail_timeout`, counted from the first, the server is left out for
//! `fail_timeout`; after that it is used again, and needs `max_fails` new failures to be left out again. A server
//! with a `max_fails` of 0 is never left out, nor is the only server of a group. A group of which no server can be
//! used has none to give (`Group::pick` is `None`).
//!
//! A group also counts all the failures of its servers from the start of the proxy (`Group::failures`), also those of
//! a server with a `max_fails` of 0, for `/metrics`.
//!
//! A configuration with `managed` and `admin` has the way to the admin process besides (`Upstreams::admin`): a route
//! that the proxy makes itself, which a request takes by its `Host` alone, whatever the routes say, to a group of its
//! own with the one server `admin.listen`. The group is not one of the groups of the configuration, so no route can
//! name it, and its name cannot be the name of one: it is not counted in `failures`.
//!
//! The counts are atomic numbers that are read and written one at a time, so two failures that come in the same
//! instant may count as one; a count that is a little low or high changes how soon a server is left out, nothing
//! that a client sees. The times are milliseconds from the start of the group.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use tokio::time::Instant;

use crate::config::{
    AdminWay, ForwardConfig, GroupConfig, ProxyConfig, RouteConfig, RouteKeep, ServerConfig, Stream,
};
use crate::forward::client_ip::Access;
use crate::forward::pool::Pool;
use crate::forward::rewrite::Rewrite;
use crate::forward::select::Turn;
use crate::forward::tls::Secure;
use crate::route::{RequestHost, Table};

/// The name of the group of the way to the admin process: not the name of a group of the configuration, which is made
/// of letters, digits, `-` and `_`.
const ADMIN_GROUP: &str = "admin route";

/// The groups of the configuration, and the routes to them.
pub struct Upstreams {
    groups: Vec<Group>,
    routes: Table<RouteConfig>,
    /// The route for a request that no other route holds for.
    default: Option<RouteConfig>,
    /// Some route has an access list.
    guarded: bool,
    admin: Option<Admin>,
}

/// The way to the admin process: the name of its host, in lowercase, who may use it, and its group.
struct Admin {
    host: String,
    access: Access,
    group: Group,
    /// No edit: the request goes to the admin process as it came.
    rewrite: Rewrite,
}

/// The route a request takes: the group it goes to, how it edits the request and the response, the times of a
/// response that may take long, the limit on the body of a request that is lower than the proxy's, and how the
/// records of its requests are kept.
#[derive(Clone, Copy)]
pub struct Route<'a> {
    pub group: &'a Group,
    pub rewrite: &'a Rewrite,
    pub stream: Option<&'a Stream>,
    pub max_body: Option<usize>,
    /// How the records of its requests are kept, if the route says; the default route does not.
    pub records: Option<RouteKeep>,
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
            default: cfg.default.map(RouteConfig::plain),
            guarded: cfg.routes.targets().any(|route| !route.access.is_empty()),
            admin: cfg.admin.as_ref().map(|way| Admin::new(way, proxy, born)),
        }
    }

    /// The way to the admin process for a request with this `Host` value, if it has the name of the host of the way
    /// (in any case, with a port or a last `.`), and the access list that its client has to pass. No route of the
    /// configuration is asked for such a request.
    pub fn admin(&self, host: Option<&[u8]>) -> Option<(Route<'_>, &Access)> {
        let admin = self.admin.as_ref()?;
        let named = RequestHost::parse(host?)?
            .name()
            .eq_ignore_ascii_case(admin.host.as_bytes());
        named.then_some((
            Route {
                group: &admin.group,
                rewrite: &admin.rewrite,
                stream: None,
                max_body: None,
                records: None,
            },
            &admin.access,
        ))
    }

    /// Whether some route has an access list. If none has, no request is turned away by one, and `accesses` need
    /// not be asked.
    pub fn guarded(&self) -> bool {
        self.guarded
    }

    /// The route for a request with this `Host` value and this request target: the most exact one that holds for it,
    /// or else the default route.
    pub fn find(&self, host: Option<&[u8]>, target: &[u8]) -> Option<Route<'_>> {
        let found = self.routes.find(host, target).or(self.default.as_ref())?;
        Some(Route {
            group: self.groups.get(found.group)?,
            rewrite: &found.rewrite,
            stream: found.stream.as_ref(),
            max_body: found.max_body,
            records: found.records,
        })
    }

    /// The access lists that a request with this `Host` value and this request target has to pass: those of the routes
    /// it could be taken for, however it is written, the route it goes to among them (see `Table::could_hold`). The
    /// default route has none.
    pub fn accesses<'a>(
        &'a self,
        host: Option<&'a [u8]>,
        target: &'a [u8],
    ) -> impl Iterator<Item = &'a Access> {
        self.routes
            .could_hold(host, target)
            .map(|route| &route.access)
    }

    /// The name of every group with the failures counted for it since the start, in the order of the configuration.
    pub fn failures(&self) -> impl Iterator<Item = (&str, u64)> {
        self.groups
            .iter()
            .map(|group| (&**group.name(), group.failures()))
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

/// A server of a group: where it is, how it counts, its view of the pool of the group, how it is spoken to if the
/// group has `tls`, and what has failed.
pub struct Server {
    address: SocketAddr,
    max_fails: u32,
    fail_timeout_ms: u64,
    pool: Pool,
    secure: Option<Secure>,
    /// Failures in the window that began at `window`.
    fails: AtomicU32,
    window: AtomicU64,
    /// The server is left out until this time.
    down_until: AtomicU64,
}

impl Server {
    fn new(cfg: &ServerConfig, pool: Pool, secure: Option<Secure>) -> Server {
        Server {
            address: cfg.address,
            max_fails: cfg.max_fails,
            // The configuration bounds it to an hour, so this is exact.
            fail_timeout_ms: u64::try_from(cfg.fail_timeout.as_millis()).unwrap_or(u64::MAX),
            pool,
            secure,
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

    /// How to speak TLS to the server, if the group has `tls`; `None`: the connection is plain.
    pub(super) fn secure(&self) -> Option<&Secure> {
        self.secure.as_ref()
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
    /// The failures of all the servers, counted since the start.
    failures: AtomicU64,
}

impl Admin {
    /// The group has the one server, which is never left out, as the only server of a group is not.
    fn new(way: &AdminWay, proxy: &ProxyConfig, born: Instant) -> Admin {
        let group = GroupConfig {
            name: ADMIN_GROUP.to_owned(),
            servers: vec![ServerConfig {
                address: way.server,
                weight: 1,
                max_fails: 0,
                fail_timeout: Duration::from_secs(1),
                backup: false,
            }],
            tls: None,
        };
        Admin {
            host: way.host.clone(),
            access: way.access.clone(),
            group: Group::new(&group, proxy, born),
            rewrite: Rewrite::default(),
        }
    }
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
                .map(|(index, server)| {
                    let secure = cfg.tls.as_ref().map(|tls| tls.secure(index));
                    Server::new(server, pool.of(index), secure)
                })
                .collect(),
            turn: Turn::new(&cfg.servers),
            born,
            failures: AtomicU64::new(0),
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
        self.failures.fetch_add(1, Ordering::Relaxed);
        self.servers[index].fail(self.since(now));
    }

    /// The failures of all the servers since the start.
    pub fn failures(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }

    /// Whether the server at `index` is left out at the moment, for the tests.
    #[cfg(test)]
    pub(crate) fn left_out(&self, index: usize) -> bool {
        !self.servers[index].up(self.since(Instant::now()))
    }
}

#[cfg(test)]
mod tests;
