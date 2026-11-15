//! The `access`, `rate_limit`, `host_policies` and `geo` objects at the top of the configuration: what turns a
//! request away before a
//! route is looked for (see `policy`; `inbound::conn` and the listener that redirects to https apply them).
//!
//! Each may be left out. `access` is `{"deny_cidrs"?, "allow_cidrs"?, "deny_countries"?, "allow_countries"?}`, read
//! exactly as the `access` of a route is (see `rewrite`): lists of at most 256 networks and of at most 256 countries
//! each. When it is left out nobody is turned away. `rate_limit` is `{"rate", "burst", "keys", "exempt_cidrs"?}`:
//! - `rate` (1 to 100000) is how many requests a second one client may keep up;
//! - `burst` (0 to 100000) is how many requests a client may make beyond the first without a pause: requests that come
//!   back to back pass up to `burst + 1` and the next one is refused, and after that one passes for every `1 / rate`
//!   seconds that the client waits;
//! - `keys` (1024 to 1048576) is the most clients the proxy keeps a count for, each about 100 bytes, see
//!   `policy::rate` for what happens when there are more;
//! - `exempt_cidrs` is a list of at most 256 networks (written as for `trusted_proxies`) whose requests are not
//!   counted at all, such as a monitoring tool; left out, it is empty.
//!
//! `host_policies` is a list of 0 to 64 host policies `{"name", "hosts", "access"?, "rate_limit"?}`: what holds for the
//! requests whose `Host` is one of `hosts` in the place of the `access` and the `rate_limit` of the configuration, each
//! of the two on its own. The name is written as the name of an upstream group is, and no two policies have the same.
//! A policy has 1 to 64 hosts, and all the policies together at most 1024. A host is written as the host of a route is,
//! but without a port (a name, or `*.` and a name, see `route`); no host is in two places, and none is the host of the
//! way to the admin process (`admin.route`, see `admin`), which a `*.` host may cover, for the way to the admin
//! process is looked for before the policy. A
//! request is matched to a policy as it is to a route (see `route::Table`): by its `Host`, whose case and one `.` at
//! its end do not count and whose port is not looked at, a name before a `*.` host and a longer `*.` host before a
//! shorter one. A policy has `access`, `rate_limit` or both. A key that a policy leaves out is the one of the
//! configuration, which goes on for its hosts: their requests are counted in the table of the configuration. Its
//! `access` is written as the `access` of the configuration is and holds instead of that one; `{}` turns nobody away.
//! Its `rate_limit` is `{}`, and then the requests of its hosts are not counted, or `rate`, `burst` and `keys` with
//! `exempt_cidrs` or without, checked as the `rate_limit` of the configuration is, and then they are counted in a
//! table of the policy's own; any other form is refused. The `keys` of the configuration and of the policies with a
//! table of their own are at most 1048576 together, as many as one table may hold.
//!
//! `geo` is `{"country_db", "sha256"}`, both present: the country database that the lists of countries need
//! (see `policy::country`). `country_db` is an absolute clean path of a file in the MaxMind DB format, and
//! `sha256` is the SHA-256 of that file as 64 lower-case hexadecimal digits. A list of countries in `access`,
//! here, in a host policy or in a route, needs `geo`; without it the file is refused. `GeoConfig::open` reads the
//! file when the
//! proxy starts and each time it reads the configuration file again (`config::load` calls it, so `config check`
//! does too): a regular file that is not a link, at most 256 MiB, read whole, whose SHA-256 is the one written
//! here, and which `policy::country::Geo::open` accepts. The database is kept only if some list of countries is
//! there to use it. It is not read between: to change it, write the SHA-256 of the new file in the
//! configuration file, and have the proxy read that file again.
//!
//! The address that counts is the client of the request, as `forward::client_ip` finds it: the peer, or what a
//! trusted proxy says in `X-Forwarded-For`.
//!
//! The objects are checked in the order `access`, `rate_limit`, `host_policies`, `geo`, and the host policies one by
//! one, each its `name`, its `hosts`, its `access` and its `rate_limit`; then, over all of them, that no host is
//! written twice, that none is the host of the way to the admin process, the count of all the hosts and the sum of the
//! `keys`.
//! A refusal of the check of a managed version (`routed`) tells the place it is about (see `forward::At`); the main
//! file takes the sentence alone (`check`).

use std::collections::BTreeSet;
use std::io;
use std::path::PathBuf;

use serde::Deserialize;

use super::rewrite::{self, RawAccess};
use super::{
    At, ConfigError, ForwardSettings, Loaded, Object, clean_abs, ensure, name_ok, networks,
};
use crate::forward::client_ip::{Access, Cidr};
use crate::policy::country::Geo;
use crate::route::{Rule, Table};
use crate::rules::bundle::{Fingerprint, sha256};
use crate::rules::file_store::read_regular;

/// The most requests a second that `rate` takes, and the most that `burst` takes.
const MAX_RATE: u32 = 100_000;
const MAX_BURST: u32 = 100_000;
/// The fewest and the most clients that `keys` takes, and the most that all the tables count together.
const MIN_KEYS: usize = 1024;
const MAX_KEYS: usize = 1 << 20;
/// The longest country database in bytes.
const MAX_COUNTRY_DB: u64 = 256 << 20;
/// The most host policies, the most hosts of one, and the most hosts of all of them: as many as there may be routes,
/// so that a request is looked up in a table no longer than the one of the routes.
const MAX_HOST_POLICIES: usize = 64;
const MAX_POLICY_HOSTS: usize = 64;
const MAX_ALL_HOSTS: usize = 1024;

/// The objects, checked.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicyConfig {
    /// The networks and countries that may use the proxy at all.
    pub access: Access,
    /// There if the file has the `rate_limit` object.
    pub rate_limit: Option<RateLimitConfig>,
    /// The host policies, in the order they are written.
    pub host_policies: Vec<HostPolicyConfig>,
    /// The hosts of the host policies, each with the index of its policy in `host_policies`: the table that a request
    /// is looked up in by its `Host`, as the table of the routes is.
    pub by_host: Table<usize>,
    /// There if the file has the `geo` object.
    pub geo: Option<GeoConfig>,
    /// The country database that `geo` names, read and checked. `config::load` sets it, and only if some list of
    /// countries is there to use it.
    pub country: Option<Geo>,
}

/// The `rate_limit` object, checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RateLimitConfig {
    /// The requests a second that a client may keep up.
    pub rate: u32,
    /// The requests beyond the first that a client may make at once.
    pub burst: u32,
    /// The most clients that are counted.
    pub keys: usize,
    /// The networks whose requests are not counted.
    pub exempt: Vec<Cidr>,
}

/// A host policy, checked: its name, and what holds for the requests to its hosts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostPolicyConfig {
    pub name: String,
    /// The `access` that holds in the place of the one of the configuration; none if that one goes on. An `Access`
    /// with no list (`{}`) turns nobody away.
    pub access: Option<Access>,
    pub rate_limit: HostRateLimit,
}

/// The `rate_limit` of a host policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostRateLimit {
    /// Left out: the requests are counted in the table of the configuration, if it has a `rate_limit`.
    Inherited,
    /// `{}`: the requests are not counted.
    Off,
    /// The requests are counted in a table of the policy's own.
    Own(RateLimitConfig),
}

/// The `geo` object, checked. The file is not read yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeoConfig {
    /// The country database.
    pub country_db: PathBuf,
    /// The SHA-256 that the file must have.
    pub sha256: [u8; 32],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawRateLimit {
    rate: u32,
    burst: u32,
    keys: usize,
    #[serde(default)]
    exempt_cidrs: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawHostPolicy {
    name: String,
    hosts: Vec<String>,
    #[serde(default, deserialize_with = "super::present")]
    access: Option<Object<RawAccess>>,
    #[serde(default, deserialize_with = "super::present")]
    rate_limit: Option<Object<RawHostRate>>,
}

/// The `rate_limit` of a host policy as it is written: every key may be left out, for `{}` is one of its forms.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHostRate {
    #[serde(default, deserialize_with = "super::present")]
    rate: Option<u32>,
    #[serde(default, deserialize_with = "super::present")]
    burst: Option<u32>,
    #[serde(default, deserialize_with = "super::present")]
    keys: Option<usize>,
    #[serde(default, deserialize_with = "super::present")]
    exempt_cidrs: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawGeo {
    country_db: String,
    sha256: String,
}

/// Checks the objects of a main file. A file with `managed` has none of them but `geo`, and a file without it has no
/// way to the admin process of its own (see `admin`), so no host is the host of one.
pub(super) fn check(
    access: Option<Object<RawAccess>>,
    rate_limit: Option<Object<RawRateLimit>>,
    host_policies: Option<Vec<Object<RawHostPolicy>>>,
    geo: Option<Object<RawGeo>>,
) -> Result<PolicyConfig, ConfigError> {
    let policy = routed(access, rate_limit, host_policies, None, None).map_err(|(e, _)| e)?;
    Ok(PolicyConfig {
        geo: geo.map(|Object(raw)| located(raw)).transpose()?,
        ..policy
    })
}

/// Checks the `access`, the `rate_limit` and the `host_policies` of a managed version, which goes with the `geo` of its
/// main file, checked already, and with the host of the way to the admin process that the main file writes, `admin`. A
/// refusal comes with the place it is about: `access`, `rate_limit` (the key in it is for the caller to find by the
/// sentence) or a place in `host_policies`.
pub(crate) fn routed(
    access: Option<Object<RawAccess>>,
    rate_limit: Option<Object<RawRateLimit>>,
    host_policies: Option<Vec<Object<RawHostPolicy>>>,
    geo: Option<GeoConfig>,
    admin: Option<&str>,
) -> Result<PolicyConfig, (ConfigError, At)> {
    let access = rewrite::access(access).map_err(|e| (e, At::Top("access", None)))?;
    let rate_limit = rate_limit
        .map(|Object(raw)| limit(raw))
        .transpose()
        .map_err(|e| (e, At::Top("rate_limit", None)))?;
    let keys = rate_limit.as_ref().map_or(0, |limit| limit.keys);
    let (host_policies, by_host) = hosted(host_policies.unwrap_or_default(), keys, admin)?;
    Ok(PolicyConfig {
        access,
        rate_limit,
        host_policies,
        by_host,
        geo,
        country: None,
    })
}

fn limit(raw: RawRateLimit) -> Result<RateLimitConfig, ConfigError> {
    ensure(
        (1..=MAX_RATE).contains(&raw.rate),
        "rate_limit rate is not 1 to 100000",
    )?;
    ensure(
        raw.burst <= MAX_BURST,
        "rate_limit burst is not 0 to 100000",
    )?;
    ensure(
        (MIN_KEYS..=MAX_KEYS).contains(&raw.keys),
        "rate_limit keys is not 1024 to 1048576",
    )?;
    Ok(RateLimitConfig {
        rate: raw.rate,
        burst: raw.burst,
        keys: raw.keys,
        exempt: networks(
            &raw.exempt_cidrs,
            "rate_limit exempt_cidrs has more than 256 entries",
            "rate_limit exempt_cidrs has an entry that is not a network",
        )?,
    })
}

/// The `rate_limit` of a host policy: `{}`, or `rate`, `burst` and `keys`, which `limit` checks.
fn host_limit(raw: RawHostRate) -> Result<HostRateLimit, ConfigError> {
    match raw {
        RawHostRate {
            rate: None,
            burst: None,
            keys: None,
            exempt_cidrs: None,
        } => Ok(HostRateLimit::Off),
        RawHostRate {
            rate: Some(rate),
            burst: Some(burst),
            keys: Some(keys),
            exempt_cidrs,
        } => limit(RawRateLimit {
            rate,
            burst,
            keys,
            exempt_cidrs: exempt_cidrs.unwrap_or_default(),
        })
        .map(HostRateLimit::Own),
        _ => Err(ConfigError(
            "a host policy rate_limit is neither empty nor rate, burst and keys",
        )),
    }
}

/// The host policies, checked in the order of the module documentation, and the table of their hosts. `keys` is the
/// `keys` of the `rate_limit` of the configuration (0 without one), and `admin` the host of the way to the admin
/// process. A refusal about two places is about the later one.
fn hosted(
    raw: Vec<Object<RawHostPolicy>>,
    keys: usize,
    admin: Option<&str>,
) -> Result<(Vec<HostPolicyConfig>, Table<usize>), (ConfigError, At)> {
    ensure(
        raw.len() <= MAX_HOST_POLICIES,
        "host_policies has more than 64 entries",
    )
    .map_err(|e| (e, At::Top("host_policies", None)))?;
    let mut policies: Vec<HostPolicyConfig> = Vec::with_capacity(raw.len());
    // Each host with the policy it is of, and where it is written.
    let mut entries = Vec::new();
    let mut places = Vec::new();
    for (at, Object(policy)) in raw.into_iter().enumerate() {
        let key =
            |key: &'static str| move |e: ConfigError| (e, At::HostPolicy(at, Some(key), None));
        ensure(
            name_ok(&policy.name),
            "a host policy name is not 1 to 64 letters, digits, - and _",
        )
        .map_err(key("name"))?;
        ensure(
            policies.iter().all(|other| other.name != policy.name),
            "a host policy name is written twice",
        )
        .map_err(key("name"))?;
        ensure(
            (1..=MAX_POLICY_HOSTS).contains(&policy.hosts.len()),
            "a host policy has no host or more than 64",
        )
        .map_err(key("hosts"))?;
        for (host, text) in policy.hosts.iter().enumerate() {
            let rule = Rule::forward(Some(text.as_str()), None)
                .ok()
                .filter(|rule| rule.port().is_none())
                .ok_or((
                    ConfigError("a host policy host is malformed or has a port"),
                    At::PolicyHost(at, host),
                ))?;
            entries.push((rule, at));
            places.push(At::PolicyHost(at, host));
        }
        ensure(
            policy.access.is_some() || policy.rate_limit.is_some(),
            "a host policy has neither access nor rate_limit",
        )
        .map_err(|e| (e, At::HostPolicy(at, None, None)))?;
        let access = policy
            .access
            .map(|access| rewrite::access(Some(access)))
            .transpose()
            .map_err(key("access"))?;
        let rate_limit = match policy.rate_limit {
            Some(Object(raw)) => host_limit(raw).map_err(key("rate_limit"))?,
            None => HostRateLimit::Inherited,
        };
        policies.push(HostPolicyConfig {
            name: policy.name,
            access,
            rate_limit,
        });
    }
    // Two of the same host would be refused by `Table::new` with the sentence of the routes.
    let mut seen = BTreeSet::new();
    if let Some(twice) = entries
        .iter()
        .position(|(rule, _)| !seen.insert(rule.host()))
    {
        return Err((
            ConfigError("a host policy host is written twice in the host policies"),
            places[twice],
        ));
    }
    if let Some(at) = admin.and_then(|admin| {
        entries
            .iter()
            .position(|(rule, _)| rule.host() == Some(admin))
    }) {
        return Err((
            ConfigError("a host policy host is the host of the admin route"),
            places[at],
        ));
    }
    if let Some(&past) = places.get(MAX_ALL_HOSTS) {
        return Err((
            ConfigError("the host policies have more than 1024 hosts in all"),
            past,
        ));
    }
    let mut counted = keys;
    for (at, policy) in policies.iter().enumerate() {
        if let HostRateLimit::Own(limit) = &policy.rate_limit {
            counted = counted.saturating_add(limit.keys);
            ensure(
                counted <= MAX_KEYS,
                "the rate limits keep count of more than 1048576 clients in all",
            )
            .map_err(|e| (e, At::HostPolicy(at, Some("rate_limit"), Some("keys"))))?;
        }
    }
    let table =
        Table::new(entries).map_err(|e| (ConfigError(e.0), At::Top("host_policies", None)))?;
    Ok((policies, table))
}

fn located(raw: RawGeo) -> Result<GeoConfig, ConfigError> {
    let country_db = PathBuf::from(raw.country_db);
    ensure(
        clean_abs(&country_db),
        "geo country_db is not an absolute clean path",
    )?;
    let sha256 = Fingerprint::from_hex(raw.sha256.as_bytes())
        .ok_or(ConfigError(
            "geo sha256 is not 64 lower-case hexadecimal digits",
        ))?
        .bytes();
    Ok(GeoConfig { country_db, sha256 })
}

impl GeoConfig {
    /// Reads the country database and checks it: see the module documentation.
    pub fn open(&self) -> Result<Geo, ConfigError> {
        let bytes = read_regular(&self.country_db, MAX_COUNTRY_DB, None).map_err(|e| {
            ConfigError(if e.kind() == io::ErrorKind::InvalidData {
                "geo country_db is not a regular file of at most 256 MiB"
            } else {
                "geo country_db cannot be read, or is a link"
            })
        })?;
        ensure(
            sha256(&bytes) == self.sha256,
            "geo country_db does not have the sha256 that geo gives",
        )?;
        Geo::open(bytes).map_err(|fault| ConfigError(fault.0))
    }
}

/// Reads the country database that the `geo` of a whole configuration names (see `policy`). The database is read and
/// checked whether or not a list uses it, so that a bad one is found at once; it is kept only if one does.
pub(crate) fn read_countries(loaded: &mut Loaded) -> Result<(), ConfigError> {
    if let Some(geo) = &loaded.policy.geo {
        let country = geo.open()?;
        let route = loaded.admin_route.as_ref();
        if uses_countries(&loaded.policy, &loaded.forward)
            || route.is_some_and(|route| route.access.has_countries())
        {
            loaded.policy.country = Some(country);
        }
    }
    Ok(())
}

/// Whether the `access` of the configuration, of some host policy or of some route has a list of countries.
pub(crate) fn uses_countries(policy: &PolicyConfig, forward: &ForwardSettings) -> bool {
    countries_at(policy, forward).is_some()
}

/// The first `access` with a list of countries: the one of the configuration, then the one of a host policy, then the
/// one of a route, each in the order they are written; none if no list of countries is there.
pub(crate) fn countries_at(policy: &PolicyConfig, forward: &ForwardSettings) -> Option<At> {
    if policy.access.has_countries() {
        return Some(At::Top("access", None));
    }
    let host = policy.host_policies.iter().position(|policy| {
        policy
            .access
            .as_ref()
            .is_some_and(|access| access.has_countries())
    });
    if let Some(at) = host {
        return Some(At::HostPolicy(at, Some("access"), None));
    }
    forward
        .routes
        .targets()
        .position(|route| route.access.has_countries())
        .map(|at| At::Route(at, Some("access")))
}
