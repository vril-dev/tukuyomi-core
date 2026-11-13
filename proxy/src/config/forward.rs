//! The `forward` object of the configuration: the upstream groups, and the routes that choose a group for a request.
//!
//! `resolve_timeout_ms` is the time the proxy may take to look up the names of the servers each time it reads the
//! configuration: when it starts, at SIGHUP, and for a reload order of the control socket, whose answer is waited for
//! that long and a margin (1 ms to 3600 s).
//! `upstreams` is an object from the name of a group to `{"servers": [..], "tls"?}`. A name is 1 to 64
//! letters, digits, `-` and `_`, and there are 1 to 64 groups. A group has 1 to 64 servers, each `{"address", "weight",
//! "max_fails", "fail_timeout_ms", "backup"}` with every key present: the address is an IP literal and a port
//! (`[..]:port` for IPv6) or a name and a port (`name:port`), the weight is 1 to 100, `max_fails` is 0 to 100 (0:
//! failures are not counted), `fail_timeout_ms` is the time a failing server is left out, and `backup` tells that the
//! server is used only when no other one can be. An IP literal is not the address of a listener, the status listener
//! included (nor a loopback address at the port of one, if that is an unspecified address), and is not unspecified or
//! a multicast address. A name is 1 to 253 bytes of lowercase letters, digits, `-`, `_` and `.`, in labels of 1 to 63
//! bytes of which the last starts with a letter (an OS takes `127.1` or `0x7f000001` for an address, not for a name);
//! the port is 1 to 65535 without a leading zero. The configuration does not look a name up: that is done when the
//! proxy starts and each time it reads the file again (see `forward::resolve`), and each address of a name is a
//! server of the group. `tls` of a group is `{"ca_file", "server_name"?}`: every server of the group is then reached
//! over TLS, and its certificate is checked against the authorities in `ca_file` (see `forward::tls`). `ca_file` is
//! an absolute clean path of at most 3840 bytes; the file is not read here. `server_name` is a name of the form of a
//! server name, and TLS has to be able to use it; without it each server is checked for its own name (so every name
//! of a server of such a group must be one TLS can use), or, written as an IP literal, for its address.
//! `routes` has at most 1024 entries `{"host"?, "path"?, "upstream", "access"?, "rewrite"?, "stream"?, "max_body"?,
//! "records"?}`.
//! The `host` and the `path` follow the rules of `route` for a forwarding rule, `upstream` names a group, and `access`
//! and `rewrite` are the networks and countries that may use the route and the edits it makes (see `rewrite`).
//! `stream` is `{"idle_ms", "total_ms", "websocket"}`, all three present: a response on the route may last `total_ms`
//! from its head at the most (1 ms to 24 h) while the upstream may be silent for `idle_ms` (1 ms up to `total_ms`) and
//! `websocket` tells whether a WebSocket handshake is let through. `records` is `best_effort`, `required` or `security`
//! and says how the records of the requests of the route are kept (see `records`); left out, `records.keep` holds.
//! `max_body` is the most bytes a request body may have on the route
//! (0: none); it is not above the `max_body` of the proxy, which the route can only lower. `default_upstream` is the group that serves a request no route
//! holds for, or the empty string, and then such a request is answered with 404. The default group has no
//! `access`, no `rewrite`, no `stream`, no `max_body` and no `records`. The `path` of a route that has an access list is in its canonical
//! form (see `route`): its escapes are in uppercase and none stands for a byte that a path holds as it is, for a
//! request is held to the list of the route that its path in canonical form meets, and would not meet this one. If
//! any route has an access list, no route has a port in its `host`: the client writes the port, and a request that
//! writes a port that a route names would meet that route and not the one with the list.
//!
//! In a file with `managed`, `forward` has `resolve_timeout_ms` alone: the groups, the routes and the default group
//! are those of the managed version, checked by the same rules (`located`, which `managed::version` calls), but for
//! the `tls` of a group, which names the file of its authorities by the SHA-256 of a file of the managed store
//! (`StoredTls`, see `managed`). A refusal of `located` also tells where in the version it is (`At`), which the admin
//! process answers; the main file is checked through `routing`, which keeps the sentence alone, and the commands and
//! the proxy take the sentence alone from the check of the version (`managed::version`, `Raw::check`).

use std::collections::BTreeSet;
use std::fmt;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;
use serde::de::{DeserializeOwned, Deserializer, Error, MapAccess, Visitor};
use serde_json::Value;

use super::records;
use super::rewrite::{self, RawAccess, RawRewrite};
use super::{
    ConfigError, MAX_CONN_MS, MAX_STORE_DIR, Object, RouteKeep, clean_abs, ensure, millis, same,
};
use crate::forward::client_ip::Access;
use crate::forward::rewrite::Rewrite;
use crate::forward::tls::{self, Authorities, Client, Settings};
use crate::route::{Rule, Table, parse_port};

const MAX_GROUPS: usize = 64;
/// The most servers a group has, as the file writes them and once the names are looked up.
pub(crate) const MAX_SERVERS: usize = 64;
const MAX_ROUTES: usize = 1024;
const MAX_NAME: usize = 64;

/// The key of a route that each sentence of `Rule::forward` and of `Rewrite::new` is about: each is about one key.
const ROUTE_KEYS: [(&str, &str); 11] = [
    ("a route host is not 1 to 253 bytes", "host"),
    ("a route host is malformed", "host"),
    ("a route path is not 1 to 255 bytes", "path"),
    ("a route path does not start with /", "path"),
    ("a route path has a character that is not allowed", "path"),
    (
        "a % in a route path is not followed by two hexadecimal digits",
        "path",
    ),
    ("a route path can be read in more than one way", "path"),
    ("a rewrite host is malformed", "rewrite.host"),
    (
        "a rewrite path is set on a route that has no path",
        "rewrite.path",
    ),
    ("a rewrite path is malformed", "rewrite.path"),
    (
        "a rewrite path for a route path that ends in / does not end in /",
        "rewrite.path",
    ),
];

/// Where in a managed version a refusal of its check is: an item by its number from 0 and, when the refusal is about
/// one key of the item, that key, as the code names it (`managed::version` writes the place as a path, such as
/// `upstreams.app.servers[2].address`). A group is numbered in the order the groups are written, which in a version is
/// the byte order of their names. The place that the check of a main file or of a document finds is not used: their
/// refusals are the sentence alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum At {
    /// A key at the top of the version, and a key in it.
    Top(&'static str, Option<&'static str>),
    /// The site of this number, and a key in it.
    Site(usize, Option<&'static str>),
    /// A host of a site: the numbers of the site and of the host.
    Host(usize, usize),
    /// The group of this number, and a key in it.
    Group(usize, Option<&'static str>),
    /// A key of a server: the numbers of the group and of the server.
    Server(usize, usize, &'static str),
    /// The route of this number, and a key in it.
    Route(usize, Option<&'static str>),
}

/// Where a server is, as the file writes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Address {
    Literal(SocketAddr),
    /// A name, which is looked up when the proxy starts and each time it reads the file again, and a port.
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

/// One group, checked. `A` is where the servers are (see `ServerConfig`). `T` is the TLS to the servers if the group
/// has any: the `Settings` as the file writes them, or the `Client` they come to once the names are looked up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupConfig<A = SocketAddr, T = Client> {
    pub name: String,
    pub servers: Vec<ServerConfig<A>>,
    pub tls: Option<T>,
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
    /// The most bytes a request body on this route may have, if that is less than `max_body` of the proxy.
    pub max_body: Option<usize>,
    /// How the records of the requests of this route are kept, if the route says; else `records.keep` holds.
    pub records: Option<RouteKeep>,
}

impl RouteConfig {
    /// A route to the group at index `group` that turns nobody away, edits nothing, has no `stream`, no limit of its
    /// own on the body and no word on its records.
    pub fn plain(group: usize) -> RouteConfig {
        RouteConfig {
            group,
            access: Access::default(),
            rewrite: Rewrite::default(),
            stream: None,
            max_body: None,
            records: None,
        }
    }
}

/// The `forward` object, checked, with the names of the servers not yet looked up: how long the lookup may take,
/// the groups in the order of the file, the routes, and the group for a request that no route holds for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardSettings {
    pub resolve_timeout: Duration,
    pub groups: Vec<GroupConfig<Address, Settings>>,
    pub routes: Table<RouteConfig>,
    /// The index of the group for a request that no route holds for.
    pub default: Option<usize>,
}

/// The `forward` object once every name is looked up (see `forward::resolve`).
#[derive(Clone, Debug)]
pub struct ForwardConfig {
    /// The time the lookup of the names could take (`resolve_timeout_ms`): a reading of the file that a reload order
    /// of the control socket asks for is waited for that long, and a margin (see `run::control`).
    pub resolve_timeout: Duration,
    pub groups: Vec<GroupConfig>,
    pub routes: Table<RouteConfig>,
    /// The index of the group for a request that no route holds for.
    pub default: Option<usize>,
    /// The way to the admin process, for a file with `managed` and `admin` (see `admin`).
    pub admin: Option<AdminWay>,
}

/// The way to the admin process that the proxy makes itself: a request whose `Host` is `host` goes to the one server
/// at `server` (`admin.listen`), if `access` lets its client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminWay {
    pub host: String,
    pub access: Access,
    pub server: SocketAddr,
}

#[cfg(test)]
impl ForwardConfig {
    /// One group, `main`, of servers at these addresses, each with a weight of 1, one failure leaving it out for a
    /// minute, and no backup; every request goes to it. The lookup could take 30 s.
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
            resolve_timeout: Duration::from_secs(30),
            groups: vec![GroupConfig {
                name: "main".to_string(),
                servers,
                tls: None,
            }],
            routes: Table::default(),
            default: Some(0),
            admin: None,
        }
    }
}

/// The `forward` object as the file writes it. A file without `managed` has every key, and a file with `managed` has
/// `resolve_timeout_ms` only: its groups, routes and default group are those of the managed version (see `managed`).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawForward {
    resolve_timeout_ms: u64,
    #[serde(default, deserialize_with = "super::present")]
    upstreams: Option<Groups<RawTls>>,
    #[serde(default, deserialize_with = "super::present")]
    routes: Option<Vec<Object<RawRoute>>>,
    #[serde(default, deserialize_with = "super::present")]
    default_upstream: Option<String>,
}

impl RawForward {
    /// Whether `upstreams`, `routes` and `default_upstream` are all there (`Some(true)`), none is (`Some(false)`), or
    /// some are and some are not (`None`).
    pub(super) fn routes_written(&self) -> Option<bool> {
        match (
            self.upstreams.is_some(),
            self.routes.is_some(),
            self.default_upstream.is_some(),
        ) {
            (true, true, true) => Some(true),
            (false, false, false) => Some(false),
            _ => None,
        }
    }
}

/// A group as it is written. `T` is its `tls`: `RawTls` in the main file and in the document of `managed import`,
/// `StoredTls` in a managed version.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "T: Deserialize<'de>"))]
struct RawGroup<T> {
    servers: Vec<Object<RawServer>>,
    #[serde(default, deserialize_with = "super::present")]
    tls: Option<Object<T>>,
}

/// The `tls` of a group that names the file of its authorities by its path.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawTls {
    ca_file: String,
    #[serde(default, deserialize_with = "super::present")]
    server_name: Option<String>,
}

impl RawTls {
    /// The file of the authorities, an absolute clean path of at most 3840 bytes, and the name to check the servers
    /// for, which `routing` checks.
    pub(crate) fn split(self) -> Result<(Authorities, Option<String>), ConfigError> {
        let ca_file = PathBuf::from(self.ca_file);
        ensure(
            clean_abs(&ca_file) && ca_file.as_os_str().as_bytes().len() <= MAX_STORE_DIR,
            "an upstream tls ca_file is not an absolute clean path of at most 3840 bytes",
        )?;
        Ok((Authorities::File(ca_file), self.server_name))
    }
}

/// The `tls` of a group of a managed version: the file of the authorities by the SHA-256 of a file of the store.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredTls {
    pub(crate) ca: String,
    #[serde(default, deserialize_with = "super::present")]
    pub(crate) server_name: Option<String>,
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
pub(crate) struct RawRoute {
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
    #[serde(default, deserialize_with = "super::present")]
    max_body: Option<usize>,
    #[serde(default, deserialize_with = "super::present")]
    records: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStream {
    idle_ms: u64,
    total_ms: u64,
    websocket: bool,
}

/// The groups in the order of the file. A name that is repeated is a repeated key, which a map would swallow. `T` is
/// the `tls` of a group, as for `RawGroup`.
pub(crate) struct Groups<T>(Vec<(String, Object<RawGroup<T>>)>);

impl<T> Groups<T> {
    /// The names of the groups, in order: what the place of a refusal names a group by (see `At`).
    pub(crate) fn names(&self) -> Vec<String> {
        self.0.iter().map(|(name, _)| name.clone()).collect()
    }
}

impl Groups<StoredTls> {
    /// The `ca` of each group of a version that has `tls`, as it is written: the files of the store that the groups
    /// name, for the cleaning of the store (see `managed::version`).
    pub(crate) fn authorities(&self) -> impl Iterator<Item = &str> {
        self.0
            .iter()
            .filter_map(|(_, Object(group))| group.tls.as_ref())
            .map(|Object(tls)| tls.ca.as_str())
    }
}

impl<T: DeserializeOwned> Groups<T> {
    /// Reads `value` as one group is read here, for the reading of a version item by item (see `managed::version`).
    pub(crate) fn read_one(value: &Value) -> Result<(), ConfigError> {
        Object::<RawGroup<T>>::deserialize(value)
            .map(drop)
            .map_err(|e| super::refusal(&e))
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Groups<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(GroupsVisitor(PhantomData))
    }
}

struct GroupsVisitor<T>(PhantomData<T>);

impl<'de, T: Deserialize<'de>> Visitor<'de> for GroupsVisitor<T> {
    type Value = Groups<T>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Groups<T>, A::Error> {
        let mut seen = BTreeSet::new();
        let mut groups = Vec::new();
        while let Some((name, group)) = map.next_entry::<String, Object<RawGroup<T>>>()? {
            if !seen.insert(name.clone()) {
                return Err(A::Error::duplicate_field("upstreams"));
            }
            groups.push((name, group));
        }
        Ok(Groups(groups))
    }
}

/// A name is 1 to 64 bytes of letters, digits, `-` and `_`.
pub(crate) fn name_ok(name: &str) -> bool {
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

/// The servers of the group at `group`.
fn servers(
    group: usize,
    raw: Vec<Object<RawServer>>,
    listeners: &[SocketAddr],
) -> Result<Vec<ServerConfig<Address>>, (ConfigError, At)> {
    ensure(
        (1..=MAX_SERVERS).contains(&raw.len()),
        "an upstream has no server or more than 64 servers",
    )
    .map_err(|e| (e, At::Group(group, Some("servers"))))?;
    raw.into_iter()
        .enumerate()
        .map(|(at, Object(server))| {
            let key = |key: &'static str| move |e: ConfigError| (e, At::Server(group, at, key));
            let address = server_address(&server.address).map_err(key("address"))?;
            if let Address::Literal(literal) = address {
                ensure(
                    !listeners.iter().any(|listener| same(*listener, literal)),
                    "a listener and a server are the same address",
                )
                .map_err(key("address"))?;
            }
            ensure(
                (1..=100).contains(&server.weight),
                "a server weight is out of range",
            )
            .map_err(key("weight"))?;
            ensure(
                server.max_fails <= 100,
                "a server max_fails is out of range",
            )
            .map_err(key("max_fails"))?;
            Ok(ServerConfig {
                address,
                weight: server.weight,
                max_fails: server.max_fails,
                fail_timeout: millis(
                    server.fail_timeout_ms,
                    "a server fail_timeout_ms is out of range",
                )
                .map_err(key("fail_timeout_ms"))?,
                backup: server.backup,
            })
        })
        .collect()
}

/// The `tls` of the group at `group`, whose servers are `servers`: `split` checks the file of the authorities as it is
/// written, and every name that a server is checked for (the `server_name`, or else the name of each server written
/// with a name) is one that TLS can use.
fn tls<T>(
    group: usize,
    raw: Option<Object<T>>,
    servers: &[ServerConfig<Address>],
    split: &impl Fn(T) -> Result<(Authorities, Option<String>), ConfigError>,
) -> Result<Option<Settings>, (ConfigError, At)> {
    let Some(Object(raw)) = raw else {
        return Ok(None);
    };
    let (authorities, server_name) =
        split(raw).map_err(|e| (e, At::Group(group, Some("tls.ca"))))?;
    match &server_name {
        Some(name) => ensure(
            host_ok(name) && tls::dns_name(name).is_some(),
            "an upstream tls server_name is not a name that TLS can use",
        )
        .map_err(|e| (e, At::Group(group, Some("tls.server_name"))))?,
        None => {
            let unfit = servers.iter().position(|server| match &server.address {
                Address::Name { name, .. } => tls::dns_name(name).is_none(),
                Address::Literal(_) => false,
            });
            if let Some(at) = unfit {
                return Err((
                    ConfigError(
                        "a server name of an upstream with tls is not a name that TLS can use",
                    ),
                    At::Server(group, at, "address"),
                ));
            }
        }
    }
    Ok(Some(Settings {
        authorities,
        server_name,
    }))
}

/// Checks the `forward` object of a file without `managed`. `listeners` are the addresses the proxy listens on, the
/// status listener's included, and `max_body` is the limit on a request body that the proxy has: a route may lower it,
/// not raise it.
pub(super) fn check(
    raw: RawForward,
    listeners: &[SocketAddr],
    max_body: usize,
) -> Result<ForwardSettings, ConfigError> {
    let (Some(upstreams), Some(routes), Some(default_upstream)) =
        (raw.upstreams, raw.routes, raw.default_upstream)
    else {
        // The three keys are required here, as serde requires every key that is not optional.
        return Err(ConfigError("configuration has a missing key"));
    };
    let resolve_timeout = millis(raw.resolve_timeout_ms, "resolve_timeout_ms is out of range")?;
    routing(
        resolve_timeout,
        upstreams,
        routes,
        &default_upstream,
        listeners,
        max_body,
        RawTls::split,
    )
}

/// The `forward` object of a file with `managed`: its `resolve_timeout_ms`, the one key it has.
pub(super) fn timeout_only(raw: RawForward) -> Result<Duration, ConfigError> {
    ensure(
        raw.routes_written() == Some(false),
        "forward has upstreams, routes or default_upstream while the configuration has managed",
    )?;
    millis(raw.resolve_timeout_ms, "resolve_timeout_ms is out of range")
}

/// The upstream groups, the routes and the default group of the `forward` object of a file without `managed`, checked,
/// with `resolve_timeout` taken as it is. `listeners` and `max_body` are as for `check`, and `split` checks the `tls`
/// of a group as it is written. A refusal is the sentence of `located`.
fn routing<T>(
    resolve_timeout: Duration,
    upstreams: Groups<T>,
    routes: Vec<Object<RawRoute>>,
    default_upstream: &str,
    listeners: &[SocketAddr],
    max_body: usize,
    split: impl Fn(T) -> Result<(Authorities, Option<String>), ConfigError>,
) -> Result<ForwardSettings, ConfigError> {
    located(
        resolve_timeout,
        upstreams,
        routes,
        default_upstream,
        listeners,
        max_body,
        split,
    )
    .map_err(|(e, _)| e)
}

/// The upstream groups, the routes and the default group, checked: the routing of a managed version (see
/// `managed::version`), and, through `routing`, that of a file without `managed`. A refusal also tells where in a
/// managed version it is (see `At`): a refusal about two items is about the later one, and one about a rule that the
/// routes break together is about the first route that breaks it.
pub(crate) fn located<T>(
    resolve_timeout: Duration,
    upstreams: Groups<T>,
    routes: Vec<Object<RawRoute>>,
    default_upstream: &str,
    listeners: &[SocketAddr],
    max_body: usize,
    split: impl Fn(T) -> Result<(Authorities, Option<String>), ConfigError>,
) -> Result<ForwardSettings, (ConfigError, Option<At>)> {
    let top = |key: &'static str| move |e: ConfigError| (e, Some(At::Top(key, None)));
    let placed = |(e, at): (ConfigError, At)| (e, Some(at));
    ensure(
        (1..=MAX_GROUPS).contains(&upstreams.0.len()),
        "upstreams has no group or more than 64 groups",
    )
    .map_err(top("upstreams"))?;
    let mut groups = Vec::with_capacity(upstreams.0.len());
    for (at, (name, Object(group))) in upstreams.0.into_iter().enumerate() {
        // A name that is not a name is not written in a place.
        ensure(
            name_ok(&name),
            "an upstream name is not 1 to 64 letters, digits, - and _",
        )
        .map_err(top("upstreams"))?;
        let servers = servers(at, group.servers, listeners).map_err(placed)?;
        let tls = tls(at, group.tls, &servers, &split).map_err(placed)?;
        groups.push(GroupConfig { name, servers, tls });
    }
    ensure(
        routes.len() <= MAX_ROUTES,
        "routes has more than 1024 entries",
    )
    .map_err(top("routes"))?;
    let index = |name: &str, undefined: &'static str| {
        groups
            .iter()
            .position(|group| group.name == name)
            .ok_or(ConfigError(undefined))
    };
    let mut entries = Vec::with_capacity(routes.len());
    for (at, Object(route)) in routes.into_iter().enumerate() {
        let key = |key: &'static str| move |e: ConfigError| (e, Some(At::Route(at, Some(key))));
        // The host and the path of a rule, and of an edit, are told apart by the sentence.
        let by_sentence = |e: ConfigError| {
            let key = ROUTE_KEYS.iter().find(|(text, _)| *text == e.0);
            (e, Some(At::Route(at, key.map(|(_, key)| *key))))
        };
        let rule = Rule::forward(route.host.as_deref(), route.path.as_deref())
            .map_err(|e| by_sentence(ConfigError(e.0)))?;
        let group = index(
            &route.upstream,
            "a route names an upstream that is not defined",
        )
        .map_err(key("upstream"))?;
        ensure(
            route.max_body.is_none_or(|limit| limit <= max_body),
            "a route max_body is above the max_body of the proxy",
        )
        .map_err(key("max_body"))?;
        let access = rewrite::access(route.access).map_err(key("access"))?;
        ensure(
            access.is_empty() || rule.canonical(),
            "a route with an access list has an escape in its path that is lowercase or is for a byte that needs no escape",
        )
        .map_err(key("path"))?;
        let rewrite = rewrite::rewrite(route.path.as_deref(), route.rewrite).map_err(
            |(e, part)| match part {
                Some(part) => (e, Some(At::Route(at, Some(part)))),
                None => by_sentence(e),
            },
        )?;
        let stream = stream(route.stream).map_err(key("stream"))?;
        let records = route
            .records
            .as_deref()
            .map(records::route_keep)
            .transpose()
            .map_err(key("records"))?;
        entries.push((
            rule,
            RouteConfig {
                group,
                access,
                rewrite,
                stream,
                max_body: route.max_body,
                records,
            },
        ));
    }
    if entries.iter().any(|(_, route)| !route.access.is_empty())
        && let Some(at) = entries.iter().position(|(rule, _)| rule.port().is_some())
    {
        return Err((
            ConfigError("a route host has a port while a route has an access list"),
            Some(At::Route(at, Some("host"))),
        ));
    }
    // The later of two routes with the same host and path, which `Table::new` refuses: its refusal is about that route.
    let twice = {
        let mut seen = BTreeSet::new();
        entries
            .iter()
            .position(|(rule, _)| !seen.insert((rule.host(), rule.path())))
    };
    let routes = Table::new(entries);
    if let (Err(e), Some(at)) = (&routes, twice) {
        return Err((ConfigError(e.0), Some(At::Route(at, None))));
    }
    let routes = routes.map_err(|e| (ConfigError(e.0), None))?;
    let default = match default_upstream {
        "" => None,
        name => Some(
            index(
                name,
                "default_upstream names an upstream that is not defined",
            )
            .map_err(top("default_upstream"))?,
        ),
    };
    Ok(ForwardSettings {
        resolve_timeout,
        groups,
        routes,
        default,
    })
}

#[cfg(test)]
mod tests;
