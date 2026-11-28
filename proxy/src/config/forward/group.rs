//! The groups of `upstreams` as they are written, and what is checked of them: the name of a group, the address of a
//! server, the `tls` of a group, and its `engine`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use serde::Deserialize;
use serde::de::{DeserializeOwned, Deserializer, Error, MapAccess, Visitor};
use serde_json::Value;
use tukuyomi_kernel::Engine;

use super::{Address, At, GroupConfig, ServerConfig};
use crate::config::{
    ConfigError, KernelSettings, MAX_STORE_DIR, Object, clean_abs, ensure, millis, same,
};
use crate::forward::tls::{self, Authorities, Settings};
use crate::route::parse_port;

pub(super) const MAX_GROUPS: usize = 64;
/// The most servers a group has, as the file writes them and once the names are looked up.
pub(crate) const MAX_SERVERS: usize = 64;
const MAX_NAME: usize = 64;

/// A group as it is written. `T` is its `tls`: `RawTls` in the main file and in the document of `managed import`,
/// `StoredTls` in a managed version.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "T: Deserialize<'de>"))]
pub(super) struct RawGroup<T> {
    pub(super) servers: Vec<Object<RawServer>>,
    #[serde(default, deserialize_with = "crate::config::present")]
    pub(super) tls: Option<Object<T>>,
    #[serde(default, deserialize_with = "crate::config::present")]
    pub(super) engine: Option<String>,
    #[serde(default, deserialize_with = "crate::config::present")]
    pub(super) balance: Option<String>,
    #[serde(default, deserialize_with = "crate::config::present")]
    pub(super) hash_policy: Option<String>,
    #[serde(default, deserialize_with = "crate::config::present")]
    pub(super) hash_key: Option<String>,
}

/// The `tls` of a group that names the file of its authorities by its path.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawTls {
    ca_file: String,
    #[serde(default, deserialize_with = "crate::config::present")]
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
    #[serde(default, deserialize_with = "crate::config::present")]
    pub(crate) server_name: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawServer {
    address: String,
    weight: u32,
    max_fails: u32,
    fail_timeout_ms: u64,
    backup: bool,
}

/// The groups in the order of the file. A name that is repeated is a repeated key, which a map would swallow. `T` is
/// the `tls` of a group, as for `RawGroup`.
pub(crate) struct Groups<T>(pub(super) Vec<(String, Object<RawGroup<T>>)>);

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
            .map_err(|e| crate::config::refusal(&e))
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
pub(in crate::config) fn host_ok(name: &str) -> bool {
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

/// The servers of the group at `group`.
pub(super) fn servers(
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
pub(super) fn tls<T>(
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

/// The engine that inspects the requests to the group at `group`: the one `raw` names, `coraza` or `modsecurity`, or
/// the default of the configuration when the group names none. The configuration must have an inspector for it.
pub(super) fn engine(
    group: usize,
    raw: Option<String>,
    kernel: &KernelSettings,
) -> Result<Engine, (ConfigError, At)> {
    let at = At::Group(group, Some("engine"));
    let engine = match raw {
        None => kernel.default_engine(),
        Some(name) => Engine::parse(&name).ok_or((
            ConfigError("an upstream engine is not coraza or modsecurity"),
            at,
        ))?,
    };
    kernel.check_engine(engine).map_err(|_| {
        (
            ConfigError("kernel.engines has no inspector for the engine of an upstream"),
            at,
        )
    })?;
    Ok(engine)
}

/// Where a server is, as two groups can be told to have the same one: an IP literal in its canonical form (an IPv4
/// address written as IPv6 is the IPv4 address) and the port, or a name and the port. Two names that come to the same
/// address are not told apart.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Backend<'a> {
    Literal(SocketAddr),
    Name(&'a str, u16),
}

impl<'a> Backend<'a> {
    fn of(address: &'a Address) -> Backend<'a> {
        match address {
            Address::Literal(literal) => {
                Backend::Literal(SocketAddr::new(literal.ip().to_canonical(), literal.port()))
            }
            Address::Name { name, port } => Backend::Name(name, *port),
        }
    }
}

/// Checks that no two groups that have a server at the same address have different engines: a request reaches the
/// backend through whichever of its groups the client's `Host` chooses, so the weakest engine and mode among them
/// would be its protection. The refusal is about the engine of the later group.
pub(super) fn engines_apart(
    groups: &[GroupConfig<Address, Settings>],
) -> Result<(), (ConfigError, At)> {
    let mut seen = BTreeMap::new();
    for (at, group) in groups.iter().enumerate() {
        for server in &group.servers {
            let backend = Backend::of(&server.address);
            if seen
                .get(&backend)
                .is_some_and(|engine| *engine != group.engine)
            {
                return Err((
                    ConfigError(
                        "two upstreams with a server at the same address have different engines",
                    ),
                    At::Group(at, Some("engine")),
                ));
            }
            seen.insert(backend, group.engine);
        }
    }
    Ok(())
}
