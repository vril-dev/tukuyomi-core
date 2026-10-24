//! Making the upstream groups whole when the proxy starts: the name of a server becomes its addresses.
//!
//! The names are looked up once, here, and never again, so a name that comes to have other addresses later is not
//! followed: the proxy has to be started again. One thread looks the names up, one after the other, in the order of
//! the file, and a name with a port that is written more than once is looked up once. The caller waits for all of them
//! until one deadline, `resolve_timeout` after the start. A lookup of the system cannot be stopped, so when the
//! deadline passes the thread is left to end by itself, and the proxy does not start. The lookup is an argument, so
//! that a test can replace it.
//!
//! Each address of a name is a server of its group with the weight, `max_fails`, `fail_timeout` and `backup` of the
//! server that was written, and the servers are in the place of the name. An address that a name has more than once
//! is one server. Another server that comes to the same address is a server of its own, as it is when two servers are
//! written with the same IP literal.
//!
//! The proxy does not start if a name cannot be looked up, has no address, or has one that is unspecified, a
//! multicast address, or the address of a listener (or a loopback address at its port, if the listener is
//! unspecified), if the lookups are not done in time, or if a group has more than 64 servers once the names are
//! looked up. The sentences of the refusals are fixed: the error of the system is not kept, and each tells the group
//! and the place of the server (from 1) it is about.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::mpsc::{RecvTimeoutError, sync_channel};
use std::thread;
use std::time::{Duration, Instant};

use crate::config::{
    Address, ForwardConfig, ForwardSettings, GroupConfig, MAX_SERVERS, ServerConfig, same,
};

/// Why the names were not made into addresses: a fixed sentence, and the group and the place of the server (from 1)
/// it is about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub why: &'static str,
    pub group: String,
    pub position: usize,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} (upstream {}, server {})",
            self.why, self.group, self.position
        )
    }
}

/// The groups with every name made into addresses, and a line for each name to put in the record.
#[derive(Debug)]
pub struct Completed {
    pub forward: ForwardConfig,
    pub lines: Vec<String>,
}

/// The lookup of the system.
pub fn system(name: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    Ok((name, port).to_socket_addrs()?.collect())
}

/// A name with a port to look up, and where it was written first.
struct Wanted {
    name: String,
    port: u16,
    group: String,
    position: usize,
}

impl Wanted {
    fn refusal(&self, why: &'static str) -> Refusal {
        Refusal {
            why,
            group: self.group.clone(),
            position: self.position,
        }
    }
}

/// The names with their ports in the order they are first written.
fn wanted(groups: &[GroupConfig<Address>]) -> Vec<Wanted> {
    let mut seen = BTreeSet::new();
    let mut names = Vec::new();
    for group in groups {
        for (place, server) in group.servers.iter().enumerate() {
            if let Address::Name { name, port } = &server.address
                && seen.insert((name.as_str(), *port))
            {
                names.push(Wanted {
                    name: name.clone(),
                    port: *port,
                    group: group.name.clone(),
                    position: place + 1,
                });
            }
        }
    }
    names
}

/// The addresses a lookup found: each one once, and none that a server must not have.
fn accepted(
    found: Vec<SocketAddr>,
    listeners: &[SocketAddr],
) -> Result<Vec<SocketAddr>, &'static str> {
    let mut seen = BTreeSet::new();
    let mut once = Vec::new();
    for address in found {
        let ip = address.ip().to_canonical();
        if ip.is_unspecified() || ip.is_multicast() {
            return Err("a server name has an address that is unspecified or a multicast address");
        }
        if listeners.iter().any(|listener| same(*listener, address)) {
            return Err("a server name has the address of a listener");
        }
        if seen.insert(address) {
            once.push(address);
        }
    }
    if once.is_empty() {
        return Err("a server name has no address");
    }
    Ok(once)
}

/// The addresses of each name, looked up by `lookup` on a thread of its own within `wait`.
fn look_up<L>(
    wanted: &[Wanted],
    wait: Duration,
    listeners: &[SocketAddr],
    lookup: L,
) -> Result<BTreeMap<(String, u16), Vec<SocketAddr>>, Refusal>
where
    L: Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + 'static,
{
    let Some(first) = wanted.first() else {
        return Ok(BTreeMap::new());
    };
    let deadline = Instant::now().checked_add(wait);
    let names: Vec<(String, u16)> = wanted.iter().map(|w| (w.name.clone(), w.port)).collect();
    // The channel has room for every answer, so the thread never waits for the caller.
    let (send, receive) = sync_channel(names.len());
    thread::Builder::new()
        .name("resolver".into())
        .spawn(move || {
            for (name, port) in names {
                if send.send(lookup(&name, port)).is_err() {
                    return;
                }
            }
        })
        .map_err(|_| first.refusal("the thread that looks the names up cannot be started"))?;
    let mut found = BTreeMap::new();
    for at in wanted {
        let left = deadline.map_or(Duration::ZERO, |end| {
            end.saturating_duration_since(Instant::now())
        });
        let addresses = match receive.recv_timeout(left) {
            Ok(Ok(addresses)) => addresses,
            Ok(Err(_)) => return Err(at.refusal("a server name cannot be looked up")),
            Err(RecvTimeoutError::Timeout) => {
                return Err(at.refusal("the names were not looked up within resolve_timeout_ms"));
            }
            Err(RecvTimeoutError::Disconnected) => {
                return Err(at.refusal("the lookup of the names stopped"));
            }
        };
        let addresses = accepted(addresses, listeners).map_err(|why| at.refusal(why))?;
        found.insert((at.name.clone(), at.port), addresses);
    }
    Ok(found)
}

/// Looks the names of the servers up with `lookup`, and returns the groups with a server for each address.
/// `listeners` are the addresses the proxy listens on.
pub fn complete<L>(
    settings: ForwardSettings,
    listeners: &[SocketAddr],
    lookup: L,
) -> Result<Completed, Refusal>
where
    L: Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + 'static,
{
    let ForwardSettings {
        resolve_timeout,
        groups,
        routes,
        default,
    } = settings;
    let found = look_up(&wanted(&groups), resolve_timeout, listeners, lookup)?;
    let mut lines = Vec::new();
    let mut done = Vec::with_capacity(groups.len());
    for group in groups {
        let mut servers = Vec::with_capacity(group.servers.len());
        for (place, server) in group.servers.into_iter().enumerate() {
            let refusal = |why| Refusal {
                why,
                group: group.name.clone(),
                position: place + 1,
            };
            let addresses = match server.address {
                Address::Literal(address) => vec![address],
                Address::Name { name, port } => {
                    let key = (name, port);
                    let addresses = found
                        .get(&key)
                        .ok_or_else(|| refusal("a server name was not looked up"))?;
                    let list: Vec<String> = addresses.iter().map(SocketAddr::to_string).collect();
                    lines.push(format!(
                        "start: upstream {} {}:{} resolved to {}",
                        group.name,
                        key.0,
                        key.1,
                        list.join(", ")
                    ));
                    addresses.clone()
                }
            };
            for address in addresses {
                if servers.len() >= MAX_SERVERS {
                    return Err(refusal(
                        "an upstream has more than 64 servers once the names are looked up",
                    ));
                }
                servers.push(ServerConfig {
                    address,
                    weight: server.weight,
                    max_fails: server.max_fails,
                    fail_timeout: server.fail_timeout,
                    backup: server.backup,
                });
            }
        }
        done.push(GroupConfig {
            name: group.name,
            servers,
        });
    }
    Ok(Completed {
        forward: ForwardConfig {
            groups: done,
            routes,
            default,
        },
        lines,
    })
}

#[cfg(test)]
mod tests;
