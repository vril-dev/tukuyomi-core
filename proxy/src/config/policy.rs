//! The `access` and the `rate_limit` object at the top of the configuration: what turns a request away before a route
//! is looked for (see `policy`; `inbound::conn` and the listener that redirects to https apply them).
//!
//! Either may be left out. `access` is `{"deny_cidrs"?, "allow_cidrs"?}`, read exactly as the `access` of a route is
//! (see `rewrite`): lists of at most 256 networks each, written as for `trusted_proxies`. When it is left out nobody
//! is turned away. `rate_limit` is `{"rate", "burst", "keys", "exempt_cidrs"?}`:
//! - `rate` (1 to 100000) is how many requests a second one client may keep up;
//! - `burst` (0 to 100000) is how many requests a client may make beyond the first without a pause: requests that come
//!   back to back pass up to `burst + 1` and the next one is refused, and after that one passes for every `1 / rate`
//!   seconds that the client waits;
//! - `keys` (1024 to 1048576) is the most clients the proxy keeps a count for, each about 100 bytes, see
//!   `policy::rate` for what happens when there are more;
//! - `exempt_cidrs` is a list of at most 256 networks (written as for `trusted_proxies`) whose requests are not
//!   counted at all, such as a monitoring tool; left out, it is empty.
//!
//! The address that counts is the client of the request, as `forward::client_ip` finds it: the peer, or what a
//! trusted proxy says in `X-Forwarded-For`.

use serde::Deserialize;

use super::rewrite::{self, RawAccess};
use super::{ConfigError, Object, ensure, networks};
use crate::forward::client_ip::{Access, Cidr};

/// The most requests a second that `rate` takes, and the most that `burst` takes.
const MAX_RATE: u32 = 100_000;
const MAX_BURST: u32 = 100_000;
/// The fewest and the most clients that `keys` takes.
const MIN_KEYS: usize = 1024;
const MAX_KEYS: usize = 1 << 20;

/// The two objects, checked.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicyConfig {
    /// The networks that may use the proxy at all.
    pub access: Access,
    /// There if the file has the `rate_limit` object.
    pub rate_limit: Option<RateLimitConfig>,
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawRateLimit {
    rate: u32,
    burst: u32,
    keys: usize,
    #[serde(default)]
    exempt_cidrs: Vec<String>,
}

/// Checks the two objects.
pub(super) fn check(
    access: Option<Object<RawAccess>>,
    rate_limit: Option<Object<RawRateLimit>>,
) -> Result<PolicyConfig, ConfigError> {
    Ok(PolicyConfig {
        access: rewrite::access(access)?,
        rate_limit: rate_limit.map(|Object(raw)| limit(raw)).transpose()?,
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
