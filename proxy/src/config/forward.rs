//! The `forward` object of the configuration: the upstream groups, and the routes that choose a group for a request.
//!
//! `upstreams` is an object from the name of a group to `{"servers": [..]}`. A name is 1 to 64 letters, digits, `-`
//! and `_`, and there are 1 to 64 groups. A group has 1 to 64 servers, each `{"address", "weight", "max_fails",
//! "fail_timeout_ms", "backup"}` with every key present: the address is an IP literal and a port (not the address of
//! `listen`), the weight is 1 to 100, `max_fails` is 0 to 100 (0: failures are not counted), `fail_timeout_ms` is the
//! time a failing server is left out, and `backup` tells that the server is used only when no other one can be.
//! `routes` has at most 1024 entries `{"host"?, "path"?, "upstream"}` that follow the rules of `route` for a forwarding
//! rule, and each names a group. `default_upstream` is the group that serves a request no route holds for, or the
//! empty string, and then such a request is answered with 404.

use std::collections::BTreeSet;
use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use serde::Deserialize;
use serde::de::{Deserializer, Error, MapAccess, Visitor};

use super::{ConfigError, Object, address, ensure, millis, same};
use crate::route::{Rule, Table};

const MAX_GROUPS: usize = 64;
const MAX_SERVERS: usize = 64;
const MAX_ROUTES: usize = 1024;
const MAX_NAME: usize = 64;

/// One server of a group, checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerConfig {
    pub address: SocketAddr,
    pub weight: u32,
    pub max_fails: u32,
    pub fail_timeout: Duration,
    pub backup: bool,
}

/// One group, checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupConfig {
    pub name: String,
    pub servers: Vec<ServerConfig>,
}

/// The `forward` object, checked: the groups in the order of the file, the routes, and the group for a request that
/// no route holds for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardConfig {
    pub groups: Vec<GroupConfig>,
    /// The target of a route is the index of its group in `groups`.
    pub routes: Table<usize>,
    /// The index of the group for a request that no route holds for.
    pub default: Option<usize>,
}

#[cfg(test)]
impl ForwardConfig {
    /// One group, `main`, of servers at these addresses, each with a weight of 1, one failure leaving it out for a
    /// minute, and no backup; every request goes to it.
    pub(crate) fn of(addresses: &[SocketAddr]) -> ForwardConfig {
        let servers = addresses
            .iter()
            .map(|&address| ServerConfig {
                address,
                weight: 1,
                max_fails: 1,
                fail_timeout: Duration::from_secs(60),
                backup: false,
            })
            .collect();
        ForwardConfig {
            groups: vec![GroupConfig {
                name: "main".to_string(),
                servers,
            }],
            routes: Table::default(),
            default: Some(0),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawForward {
    upstreams: Groups,
    routes: Vec<Object<RawRoute>>,
    default_upstream: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGroup {
    servers: Vec<Object<RawServer>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawServer {
    address: String,
    weight: u32,
    max_fails: u32,
    fail_timeout_ms: u64,
    backup: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRoute {
    host: Option<String>,
    path: Option<String>,
    upstream: String,
}

/// The groups in the order of the file. A name that is repeated is a repeated key, which a map would swallow.
struct Groups(Vec<(String, Object<RawGroup>)>);

impl<'de> Deserialize<'de> for Groups {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(GroupsVisitor)
    }
}

struct GroupsVisitor;

impl<'de> Visitor<'de> for GroupsVisitor {
    type Value = Groups;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Groups, A::Error> {
        let mut seen = BTreeSet::new();
        let mut groups = Vec::new();
        while let Some((name, group)) = map.next_entry::<String, Object<RawGroup>>()? {
            if !seen.insert(name.clone()) {
                return Err(A::Error::duplicate_field("upstreams"));
            }
            groups.push((name, group));
        }
        Ok(Groups(groups))
    }
}

/// A name is 1 to 64 bytes of letters, digits, `-` and `_`.
fn name_ok(name: &str) -> bool {
    (1..=MAX_NAME).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn servers(
    raw: Vec<Object<RawServer>>,
    listen: SocketAddr,
) -> Result<Vec<ServerConfig>, ConfigError> {
    ensure(
        (1..=MAX_SERVERS).contains(&raw.len()),
        "an upstream has no server or more than 64 servers",
    )?;
    raw.into_iter()
        .map(|Object(server)| {
            let address = address(
                &server.address,
                "a server address is not an IP address and port",
                "a server port is 0",
            )?;
            ensure(
                !same(listen, address),
                "listen and a server are the same address",
            )?;
            ensure(
                (1..=100).contains(&server.weight),
                "a server weight is out of range",
            )?;
            ensure(
                server.max_fails <= 100,
                "a server max_fails is out of range",
            )?;
            Ok(ServerConfig {
                address,
                weight: server.weight,
                max_fails: server.max_fails,
                fail_timeout: millis(
                    server.fail_timeout_ms,
                    "a server fail_timeout_ms is out of range",
                )?,
                backup: server.backup,
            })
        })
        .collect()
}

/// Checks the `forward` object. `listen` is the address the proxy listens on.
pub(super) fn check(raw: RawForward, listen: SocketAddr) -> Result<ForwardConfig, ConfigError> {
    ensure(
        (1..=MAX_GROUPS).contains(&raw.upstreams.0.len()),
        "upstreams has no group or more than 64 groups",
    )?;
    let mut groups = Vec::with_capacity(raw.upstreams.0.len());
    for (name, Object(group)) in raw.upstreams.0 {
        ensure(
            name_ok(&name),
            "an upstream name is not 1 to 64 letters, digits, - and _",
        )?;
        groups.push(GroupConfig {
            name,
            servers: servers(group.servers, listen)?,
        });
    }
    ensure(
        raw.routes.len() <= MAX_ROUTES,
        "routes has more than 1024 entries",
    )?;
    let index = |name: &str, undefined: &'static str| {
        groups
            .iter()
            .position(|group| group.name == name)
            .ok_or(ConfigError(undefined))
    };
    let mut entries = Vec::with_capacity(raw.routes.len());
    for Object(route) in raw.routes {
        let rule = Rule::forward(route.host.as_deref(), route.path.as_deref())
            .map_err(|e| ConfigError(e.0))?;
        let group = index(
            &route.upstream,
            "a route names an upstream that is not defined",
        )?;
        entries.push((rule, group));
    }
    let routes = Table::new(entries).map_err(|e| ConfigError(e.0))?;
    let default = match raw.default_upstream.as_str() {
        "" => None,
        name => Some(index(
            name,
            "default_upstream names an upstream that is not defined",
        )?),
    };
    Ok(ForwardConfig {
        groups,
        routes,
        default,
    })
}
