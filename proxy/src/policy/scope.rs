//! The scope of a request: the `access` and the rate limit that the policy asks of it (see `check`), chosen by its
//! `Host` from the host policies of the configuration (see `config::policy`).
//!
//! A request whose `Host` is a host of a host policy is asked by that policy: by its `access`, if it has one, in the
//! place of the `access` of the configuration, and by its rate limit, which counts the request in a table of its own,
//! in the table of the configuration (when the policy leaves it out) or nowhere (`{}`). Any other request is asked by
//! the `access` and the `rate_limit` of the configuration. The policy is looked up as a route is, in the table of the
//! hosts that the check of the configuration made (`PolicyConfig::by_host`), so a request meets the policy of the host
//! that the routes take it for: the case of its `Host` and one `.` at its end do not count, its port is not looked at,
//! a name comes before a `*.` host and a longer `*.` host before a shorter one.
//!
//! A request whose `Host` cannot be read as a name and a port (see `route::RequestHost`), or that has none, holds for
//! no route that has a host, and goes to a route without one or to the default group, which may well be the group
//! behind a host that has a policy of its own. So it is taken as a request for any host, as the access lists of the
//! routes take it (see `route::Table::could_hold`): it has to pass the `access` of the configuration and the `access`
//! of every host policy that has one, and it is counted in the table of the configuration and in the table of every
//! host policy that has one, up to the first table that turns it away, at most 65 tables for one request. A request
//! whose `Host` can be read but is a host that no policy names (an IPv6 literal among them, for the host of a policy
//! has no `[`) is asked by the policy of the
//! configuration alone, even where a route takes it to the same group as a host with a policy of its own.
//!
//! When the configuration is read again, each table goes on counting the clients of the table that it follows, as
//! `RateLimit::following` allows: the table of the configuration follows the old table of the configuration, and the
//! table of a host policy the old table of the host policy of the same name, whose hosts may have changed. A table of
//! a host policy that had no table of its own before, or had another name, counts from nothing. The clients that the
//! old tables dropped to make room are not lost from their sum (`evicted`, a counter of `/metrics`) when no new table
//! follows them: the new policy keeps their number, so that the sum never falls.

use std::net::IpAddr;

use super::RateLimit;
use crate::config::{HostRateLimit, PolicyConfig, RateLimitConfig};
use crate::forward::client_ip::{Access, Country};
use crate::route::{RequestHost, Table};

/// The rate limit of a host policy, made.
enum Limit {
    /// The requests are counted in the table of the configuration.
    Inherited,
    /// The requests are not counted.
    Off,
    /// The requests are counted in a table of the policy's own.
    Own(RateLimit),
}

/// A host policy, made: its name, its `access` if it has one, and its rate limit.
struct Host {
    name: String,
    access: Option<Access>,
    limit: Limit,
}

/// The policy of one configuration, made: the `access` and the rate limit of the configuration, the host policies, and
/// the table of their hosts with the index of the policy of each.
pub struct Scopes {
    access: Access,
    rate_limit: Option<RateLimit>,
    hosts: Vec<Host>,
    by_host: Table<usize>,
    /// The clients that the tables of the policies before this one dropped to make room, in the tables that no table
    /// of this one follows.
    evicted_before: u64,
}

/// What the policy asks of one request (see the module documentation).
pub enum Scope<'a> {
    /// The `access` and the rate limit of the configuration, or those of one host policy.
    One {
        access: &'a Access,
        rate_limit: Option<&'a RateLimit>,
    },
    /// Every `access` and every table, for a request whose `Host` cannot be read.
    Every(&'a Scopes),
}

/// The table of `config`, which goes on counting the clients of `earlier` if it can (see `RateLimit::following`).
fn table(config: &RateLimitConfig, earlier: Option<&RateLimit>) -> RateLimit {
    earlier
        .and_then(|earlier| RateLimit::following(config, earlier))
        .unwrap_or_else(|| RateLimit::new(config))
}

impl Scopes {
    /// The policy of `config`, whose tables go on counting the clients of those of `earlier`, the policy that it
    /// replaces, if there is one (see the module documentation).
    pub fn new(config: PolicyConfig, earlier: Option<&Scopes>) -> Scopes {
        let rate_limit = config.rate_limit.as_ref().map(|limit| {
            table(
                limit,
                earlier.and_then(|earlier| earlier.rate_limit.as_ref()),
            )
        });
        let hosts = config
            .host_policies
            .into_iter()
            .map(|policy| {
                let limit = match &policy.rate_limit {
                    HostRateLimit::Inherited => Limit::Inherited,
                    HostRateLimit::Off => Limit::Off,
                    HostRateLimit::Own(limit) => Limit::Own(table(
                        limit,
                        earlier.and_then(|earlier| earlier.own(&policy.name)),
                    )),
                };
                Host {
                    name: policy.name,
                    access: policy.access,
                    limit,
                }
            })
            .collect();
        let mut scopes = Scopes {
            access: config.access,
            rate_limit,
            hosts,
            by_host: config.by_host,
            evicted_before: 0,
        };
        if let Some(earlier) = earlier {
            let gone = earlier
                .tables()
                .filter(|old| !scopes.tables().any(|table| table.continues(old)));
            scopes.evicted_before = gone
                .map(RateLimit::evicted)
                .fold(earlier.evicted_before, u64::saturating_add);
        }
        scopes
    }

    /// The table of the host policy named `name`, if it has one of its own.
    fn own(&self, name: &str) -> Option<&RateLimit> {
        let host = self.hosts.iter().find(|host| host.name == name)?;
        match &host.limit {
            Limit::Own(limit) => Some(limit),
            Limit::Inherited | Limit::Off => None,
        }
    }

    /// What the policy asks of a request whose `Host` is `host`, the value of its field as the request wrote it.
    pub fn scope(&self, host: Option<&[u8]>) -> Scope<'_> {
        if host.and_then(RequestHost::parse).is_none() {
            return Scope::Every(self);
        }
        // The rules of the table have no path, so the target does not count.
        let policy = self
            .by_host
            .find(host, b"/")
            .and_then(|&at| self.hosts.get(at));
        let Some(policy) = policy else {
            return Scope::One {
                access: &self.access,
                rate_limit: self.rate_limit.as_ref(),
            };
        };
        Scope::One {
            access: policy.access.as_ref().unwrap_or(&self.access),
            rate_limit: match &policy.limit {
                Limit::Inherited => self.rate_limit.as_ref(),
                Limit::Off => None,
                Limit::Own(limit) => Some(limit),
            },
        }
    }

    /// The tables, each once: the one of the configuration, then those of the host policies in their order.
    fn tables(&self) -> impl Iterator<Item = &RateLimit> {
        let own = self.hosts.iter().filter_map(|host| match &host.limit {
            Limit::Own(limit) => Some(limit),
            Limit::Inherited | Limit::Off => None,
        });
        self.rate_limit.iter().chain(own)
    }

    /// How many clients the tables count now, all together: a host policy that counts in the table of the
    /// configuration adds none.
    pub fn keys(&self) -> usize {
        self.tables().map(RateLimit::keys).sum()
    }

    /// How many clients the tables dropped to make room while their number was still in force, all together, with
    /// those that the tables of the policies before this one dropped in the tables that no table of this one follows:
    /// the sum never falls when the configuration is read again.
    pub fn evicted(&self) -> u64 {
        self.tables()
            .map(RateLimit::evicted)
            .fold(self.evicted_before, u64::saturating_add)
    }

    /// The tables that do not go on counting the clients of `earlier`, the policy that this one replaces: `None` for
    /// the table of the configuration, and the name of the host policy for the table of a host policy.
    pub fn anew<'a>(&'a self, earlier: &'a Scopes) -> impl Iterator<Item = Option<&'a str>> {
        let configuration = self
            .rate_limit
            .as_ref()
            .filter(|limit| {
                !earlier
                    .rate_limit
                    .as_ref()
                    .is_some_and(|old| limit.continues(old))
            })
            .map(|_| None);
        let hosts = self.hosts.iter().filter_map(move |host| match &host.limit {
            Limit::Own(limit)
                if !earlier
                    .own(&host.name)
                    .is_some_and(|old| limit.continues(old)) =>
            {
                Some(Some(host.name.as_str()))
            }
            Limit::Own(_) | Limit::Inherited | Limit::Off => None,
        });
        configuration.into_iter().chain(hosts)
    }
}

#[cfg(test)]
impl Scopes {
    /// The policy of a configuration with this `access` and this rate limit, and no host policy.
    pub(crate) fn of(access: Access, rate_limit: Option<RateLimit>) -> Scopes {
        Scopes {
            access,
            rate_limit,
            hosts: Vec::new(),
            by_host: Table::default(),
            evicted_before: 0,
        }
    }
}

impl Scope<'_> {
    /// Whether the client at `client`, which is in `country`, may use the proxy.
    pub fn permits(&self, client: IpAddr, country: Country) -> bool {
        match self {
            Scope::One { access, .. } => access.permits(client, country),
            Scope::Every(scopes) => {
                scopes.access.permits(client, country)
                    && scopes
                        .hosts
                        .iter()
                        .filter_map(|host| host.access.as_ref())
                        .all(|access| access.permits(client, country))
            }
        }
    }

    /// Counts a request of `client` and says whether it passes (see `RateLimit::admit`): `Err` holds the seconds until
    /// the client may make one. A request that no table counts passes.
    pub fn admit(&self, client: IpAddr) -> Result<(), u32> {
        match self {
            Scope::One { rate_limit, .. } => rate_limit.map_or(Ok(()), |limit| limit.admit(client)),
            Scope::Every(scopes) => scopes.tables().try_for_each(|limit| limit.admit(client)),
        }
    }
}

#[cfg(test)]
mod tests;
