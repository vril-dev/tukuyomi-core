//! The `access`, `rate_limit` and `geo` objects at the top of the configuration: what turns a request away before a
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
//! `geo` is `{"country_db", "sha256"}`, both present: the country database that the lists of countries need (see
//! `policy::country`). `country_db` is an absolute clean path of a file in the MaxMind DB format, and `sha256` is the
//! SHA-256 of that file as 64 lower-case hexadecimal digits. A list of countries in `access`, here or in a route, needs
//! `geo`; without it the file is refused. `GeoConfig::open` reads the file when the proxy starts (`config::load` calls
//! it, so `config check` does too): a regular file that is not a link, at most 256 MiB, read whole, whose SHA-256 is the
//! one written here, and which `policy::country::Geo::open` accepts. The database is kept only if some list of
//! countries is there to use it. It is not read again: to change it, start the proxy again.
//!
//! The address that counts is the client of the request, as `forward::client_ip` finds it: the peer, or what a
//! trusted proxy says in `X-Forwarded-For`.

use std::io;
use std::path::PathBuf;

use serde::Deserialize;

use super::rewrite::{self, RawAccess};
use super::{ConfigError, Object, clean_abs, ensure, networks};
use crate::forward::client_ip::{Access, Cidr};
use crate::policy::country::Geo;
use crate::rules::bundle::{Fingerprint, sha256};
use crate::rules::file_store::read_regular;

/// The most requests a second that `rate` takes, and the most that `burst` takes.
const MAX_RATE: u32 = 100_000;
const MAX_BURST: u32 = 100_000;
/// The fewest and the most clients that `keys` takes.
const MIN_KEYS: usize = 1024;
const MAX_KEYS: usize = 1 << 20;
/// The longest country database in bytes.
const MAX_COUNTRY_DB: u64 = 256 << 20;

/// The objects, checked.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicyConfig {
    /// The networks and countries that may use the proxy at all.
    pub access: Access,
    /// There if the file has the `rate_limit` object.
    pub rate_limit: Option<RateLimitConfig>,
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
pub(super) struct RawRateLimit {
    rate: u32,
    burst: u32,
    keys: usize,
    #[serde(default)]
    exempt_cidrs: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawGeo {
    country_db: String,
    sha256: String,
}

/// Checks the objects.
pub(super) fn check(
    access: Option<Object<RawAccess>>,
    rate_limit: Option<Object<RawRateLimit>>,
    geo: Option<Object<RawGeo>>,
) -> Result<PolicyConfig, ConfigError> {
    Ok(PolicyConfig {
        access: rewrite::access(access)?,
        rate_limit: rate_limit.map(|Object(raw)| limit(raw)).transpose()?,
        geo: geo.map(|Object(raw)| located(raw)).transpose()?,
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
