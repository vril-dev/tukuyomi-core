//! The `forward` object of the configuration: the upstream groups, and the routes that choose a group for a request.
//!
//! `resolve_timeout_ms` is the time the proxy may take, when it starts, to look up the names of the servers (1 ms to
//! 3600 s). `upstreams` is an object from the name of a group to `{"servers": [..]}`. A name is 1 to 64 letters,
//! digits, `-` and `_`, and there are 1 to 64 groups. A group has 1 to 64 servers, each `{"address", "weight",
//! "max_fails", "fail_timeout_ms", "backup"}` with every key present: the address is an IP literal and a port
//! (`[..]:port` for IPv6) or a name and a port (`name:port`), the weight is 1 to 100, `max_fails` is 0 to 100 (0:
//! failures are not counted), `fail_timeout_ms` is the time a failing server is left out, and `backup` tells that the
//! server is used only when no other one can be. An IP literal is not the address of a listener (nor a loopback
//! address at the port of one, if that is an unspecified address), and is not unspecified or a multicast address. A
//! name is 1 to 253 bytes of lowercase letters, digits, `-`, `_` and `.`, in labels of 1 to 63 bytes of which the last
//! starts with a letter (an OS takes `127.1` or `0x7f000001` for an address, not for a name); the port is 1 to 65535
//! without a leading zero. The configuration does not look a name up: that is done once, when the proxy starts (see
//! `forward::resolve`), and each address of a name is a server of the group.
//! `routes` has at most 1024 entries `{"host"?, "path"?, "upstream", "access"?, "rewrite"?, "stream"?}`. The `host`
//! and the `path` follow the rules of `route` for a forwarding rule, `upstream` names a group, and `access` and
//! `rewrite` are the networks that may use the route and the edits it makes (see `rewrite`). `stream` is `{"idle_ms",
//! "total_ms", "websocket"}`, all three present: a response on the route may last `total_ms` from its head at the
//! most (1 ms to 24 h) while the upstream may be silent for `idle_ms` (1 ms up to `total_ms`) and `websocket` tells
//! whether a WebSocket handshake is let through. `default_upstream` is the group that serves a request no route
//! holds for, or the empty string, and then such a request is answered with 404. The default group has no
//! `access`, no `rewrite` and no `stream`. The `path` of a route that has an access list is in its canonical
//! form (see `route`): its escapes are in uppercase and none stands for a byte that a path holds as it is, for a
//! request is held to the list of the route that its path in canonical form meets, and would not meet this one. If
//! any route has an access list, no route has a port in its `host`: the client writes the port, and a request that
//! writes a port that a route names would meet that route and not the one with the list.

use std::collections::BTreeSet;
use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use serde::Deserialize;
use serde::de::{Deserializer, Error, MapAccess, Visitor};

use super::rewrite::{self, RawAccess, RawRewrite};
use super::{ConfigError, MAX_CONN_MS, Object, ensure, millis, same};
use crate::forward::client_ip::Access;
use crate::forward::rewrite::Rewrite;
use crate::route::{Rule, Table, parse_port};

const MAX_GROUPS: usize = 64;
/// The most servers a group has, as the file writes them and once the names are looked up.
pub(crate) const MAX_SERVERS: usize = 64;
const MAX_ROUTES: usize = 1024;
const MAX_NAME: usize = 64;

/// Where a server is, as the file writes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Address {
    Literal(SocketAddr),
    /// A name, which is looked up when the proxy starts, and a port.
    Name {
        name: String,
        port: u16,
    },
}

/// One server of a group, checked. `A` is where the server is: an `Address` as the file writes it, or the
/// `SocketAddr` it comes to once the names are looked up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerConfig<A = SocketAddr> {
    pub address: A,
    pub weight: u32,
    pub max_fails: u32,
    pub fail_timeout: Duration,
    pub backup: bool,
}

/// One group, checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupConfig<A = SocketAddr> {
    pub name: String,
    pub servers: Vec<ServerConfig<A>>,
}

/// The times of a response on a route that may take long, and whether the route lets a WebSocket through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stream {
    /// How long the upstream may be silent.
    pub idle: Duration,
    /// The longest a response lasts, counted from its head.
    pub total: Duration,
    pub websocket: bool,
}

/// What a route does with a request: the group it goes to (the index of the group in `groups`), who may use it, the
/// edits it makes to the request and to the response, and whether its responses may take long.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteConfig {
    pub group: usize,
    pub access: Access,
    pub rewrite: Rewrite,
    pub stream: Option<Stream>,
}

impl RouteConfig {
    /// A route to the group at index `group` that turns nobody away, edits nothing and has no `stream`.
    pub fn plain(group: usize) -> RouteConfig {
        RouteConfig {
            group,
            access: Access::default(),
            rewrite: Rewrite::default(),
            stream: None,
        }
    }
}

/// The `forward` object, checked, with the names of the servers not yet looked up: how long the lookup may take,
/// the groups in the order of the file, the routes, and the group for a request that no route holds for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardSettings {
    pub resolve_timeout: Duration,
    pub groups: Vec<GroupConfig<Address>>,
    pub routes: Table<RouteConfig>,
    /// The index of the group for a request that no route holds for.
    pub default: Option<usize>,
}

/// The `forward` object once every name is looked up (see `forward::resolve`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardConfig {
    pub groups: Vec<GroupConfig>,
    pub routes: Table<RouteConfig>,
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
    resolve_timeout_ms: u64,
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
    #[serde(default, deserialize_with = "super::present")]
    host: Option<String>,
    #[serde(default, deserialize_with = "super::present")]
    path: Option<String>,
    upstream: String,
    #[serde(default, deserialize_with = "super::present")]
    access: Option<Object<RawAccess>>,
    #[serde(default, deserialize_with = "super::present")]
    rewrite: Option<Object<RawRewrite>>,
    #[serde(default, deserialize_with = "super::present")]
    stream: Option<Object<RawStream>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStream {
    idle_ms: u64,
    total_ms: u64,
    websocket: bool,
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

/// A label of a server name: 1 to 63 bytes.
fn host_label_ok(label: &str) -> bool {
    (1..=63).contains(&label.len())
}

/// A server name: 1 to 253 bytes of lowercase letters, digits, `-`, `_` and `.` in labels of 1 to 63 bytes, the last
/// of which starts with a letter.
pub(super) fn host_ok(name: &str) -> bool {
    name.len() <= 253
        && name.split('.').all(host_label_ok)
        && name
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.'))
        && name
            .rsplit('.')
            .next()
            .is_some_and(|last| last.starts_with(|c: char| c.is_ascii_lowercase()))
}

/// The address of a server: an IP literal and a port, or a name and a port.
fn server_address(text: &str) -> Result<Address, ConfigError> {
    if let Ok(literal) = text.parse::<SocketAddr>() {
        ensure(literal.port() != 0, "a server port is 0")?;
        let ip = literal.ip().to_canonical();
        ensure(
            !ip.is_unspecified() && !ip.is_multicast(),
            "a server address is unspecified or a multicast address",
        )?;
        return Ok(Address::Literal(literal));
    }
    let (name, port) = text.split_once(':').ok_or(ConfigError(
        "a server address is not an IP address and port, or a name and port",
    ))?;
    ensure(host_ok(name), "a server name is malformed")?;
    let port = parse_port(port.as_bytes()).ok_or(ConfigError("a server port is not 1 to 65535"))?;
    Ok(Address::Name {
        name: name.to_owned(),
        port,
    })
}

/// The `stream` of a route: both times from 1 ms to 24 h, and the idle time not above the total.
fn stream(raw: Option<Object<RawStream>>) -> Result<Option<Stream>, ConfigError> {
    let Some(Object(raw)) = raw else {
        return Ok(None);
    };
    ensure(
        (1..=MAX_CONN_MS).contains(&raw.idle_ms) && (1..=MAX_CONN_MS).contains(&raw.total_ms),
        "a stream idle_ms or total_ms is out of range",
    )?;
    ensure(
        raw.idle_ms <= raw.total_ms,
        "a stream idle_ms is above its total_ms",
    )?;
    Ok(Some(Stream {
        idle: Duration::from_millis(raw.idle_ms),
        total: Duration::from_millis(raw.total_ms),
        websocket: raw.websocket,
    }))
}

fn servers(
    raw: Vec<Object<RawServer>>,
    listeners: &[SocketAddr],
) -> Result<Vec<ServerConfig<Address>>, ConfigError> {
    ensure(
        (1..=MAX_SERVERS).contains(&raw.len()),
        "an upstream has no server or more than 64 servers",
    )?;
    raw.into_iter()
        .map(|Object(server)| {
            let address = server_address(&server.address)?;
            if let Address::Literal(literal) = address {
                ensure(
                    !listeners.iter().any(|listener| same(*listener, literal)),
                    "a listener and a server are the same address",
                )?;
            }
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

/// Checks the `forward` object. `listeners` are the addresses the proxy listens on.
pub(super) fn check(
    raw: RawForward,
    listeners: &[SocketAddr],
) -> Result<ForwardSettings, ConfigError> {
    let resolve_timeout = millis(raw.resolve_timeout_ms, "resolve_timeout_ms is out of range")?;
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
            servers: servers(group.servers, listeners)?,
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
        let access = rewrite::access(route.access)?;
        ensure(
            access.is_empty() || rule.canonical(),
            "a route with an access list has an escape in its path that is lowercase or is for a byte that needs no escape",
        )?;
        entries.push((
            rule,
            RouteConfig {
                group,
                access,
                rewrite: rewrite::rewrite(route.path.as_deref(), route.rewrite)?,
                stream: stream(route.stream)?,
            },
        ));
    }
    ensure(
        entries.iter().all(|(_, route)| route.access.is_empty())
            || entries.iter().all(|(rule, _)| rule.port().is_none()),
        "a route host has a port while a route has an access list",
    )?;
    let routes = Table::new(entries).map_err(|e| ConfigError(e.0))?;
    let default = match raw.default_upstream.as_str() {
        "" => None,
        name => Some(index(
            name,
            "default_upstream names an upstream that is not defined",
        )?),
    };
    Ok(ForwardSettings {
        resolve_timeout,
        groups,
        routes,
        default,
    })
}
