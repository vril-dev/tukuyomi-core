//! The `access` and the `rewrite` object of a route in the configuration.
//!
//! `access` is `{"deny_cidrs"?, "allow_cidrs"?, "deny_countries"?, "allow_countries"?}`: lists of at most 256 networks
//! each, written as for `trusted_proxies`, and of at most 256 countries each, each written as the two upper-case
//! letters of its ISO 3166-1 alpha-2 code or `UNKNOWN` (see `policy::country`). `rewrite` is `{"host"?, "path"?,
//! "query"?, "request_headers"?, "response_headers"?}`: `host` is
//! a name and an optional port as the host of a route is written, without a wildcard, and `path` is a path as the
//! path of a route is written (see `forward::rewrite` for what the path of a route with and without a `/` at the end
//! allows). `query` is `{"remove"?, "remove_prefixes"?, "set"?, "add"?}`, and `request_headers` and
//! `response_headers` are `{"remove"?, "set"?, "add"?}`; `remove` and `remove_prefixes` are lists of names, `set` and
//! `add` lists of `{"name", "value"}`. A key that is left out is an empty list, or no edit. The values are checked by
//! `forward::rewrite`; the sentences of its refusals are returned as they are.

use serde::Deserialize;

use super::{ConfigError, Object, ensure};
use crate::forward::client_ip::{Access, Cidr, Country};
use crate::forward::rewrite::{Headers, Query, Rewrite, RewriteError};

/// The most networks in each list of `access`, and the most countries.
const MAX_NETWORKS: usize = 256;
const MAX_COUNTRIES: usize = 256;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawAccess {
    #[serde(default)]
    deny_cidrs: Vec<String>,
    #[serde(default)]
    allow_cidrs: Vec<String>,
    #[serde(default)]
    deny_countries: Vec<String>,
    #[serde(default)]
    allow_countries: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawRewrite {
    #[serde(default, deserialize_with = "super::present")]
    host: Option<String>,
    #[serde(default, deserialize_with = "super::present")]
    path: Option<String>,
    #[serde(default, deserialize_with = "super::present")]
    query: Option<Object<RawQuery>>,
    #[serde(default, deserialize_with = "super::present")]
    request_headers: Option<Object<RawHeaders>>,
    #[serde(default, deserialize_with = "super::present")]
    response_headers: Option<Object<RawHeaders>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawQuery {
    #[serde(default)]
    remove: Vec<String>,
    #[serde(default)]
    remove_prefixes: Vec<String>,
    #[serde(default)]
    set: Vec<Object<RawPair>>,
    #[serde(default)]
    add: Vec<Object<RawPair>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHeaders {
    #[serde(default)]
    remove: Vec<String>,
    #[serde(default)]
    set: Vec<Object<RawPair>>,
    #[serde(default)]
    add: Vec<Object<RawPair>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPair {
    name: String,
    value: String,
}

fn pairs(list: Vec<Object<RawPair>>) -> Vec<(String, String)> {
    list.into_iter()
        .map(|Object(pair)| (pair.name, pair.value))
        .collect()
}

fn refused(e: RewriteError) -> ConfigError {
    ConfigError(e.0)
}

fn networks(list: &[String]) -> Result<Vec<Cidr>, ConfigError> {
    ensure(
        list.len() <= MAX_NETWORKS,
        "access has a list of more than 256 networks",
    )?;
    list.iter()
        .map(|text| Cidr::parse(text))
        .collect::<Option<Vec<Cidr>>>()
        .ok_or(ConfigError("access has an entry that is not a network"))
}

fn countries(list: &[String]) -> Result<Vec<Country>, ConfigError> {
    ensure(
        list.len() <= MAX_COUNTRIES,
        "access has a list of more than 256 countries",
    )?;
    list.iter()
        .map(|text| Country::parse(text))
        .collect::<Option<Vec<Country>>>()
        .ok_or(ConfigError("access has an entry that is not a country"))
}

/// The networks and countries of a route, or of the configuration as a whole.
pub(super) fn access(raw: Option<Object<RawAccess>>) -> Result<Access, ConfigError> {
    let Some(Object(raw)) = raw else {
        return Ok(Access::default());
    };
    Ok(
        Access::new(networks(&raw.deny_cidrs)?, networks(&raw.allow_cidrs)?).with_countries(
            countries(&raw.deny_countries)?,
            countries(&raw.allow_countries)?,
        ),
    )
}

fn query(raw: Option<Object<RawQuery>>) -> Result<Query, ConfigError> {
    let Some(Object(raw)) = raw else {
        return Ok(Query::default());
    };
    Query::new(
        raw.remove,
        raw.remove_prefixes,
        pairs(raw.set),
        pairs(raw.add),
    )
    .map_err(refused)
}

/// The names to take out, and the pairs to set and to add.
type Make =
    fn(Vec<String>, Vec<(String, String)>, Vec<(String, String)>) -> Result<Headers, RewriteError>;

fn headers(raw: Option<Object<RawHeaders>>, make: Make) -> Result<Headers, ConfigError> {
    let Some(Object(raw)) = raw else {
        return Ok(Headers::default());
    };
    make(raw.remove, pairs(raw.set), pairs(raw.add)).map_err(refused)
}

/// The edits of a route whose path is `route_path`.
pub(super) fn rewrite(
    route_path: Option<&str>,
    raw: Option<Object<RawRewrite>>,
) -> Result<Rewrite, ConfigError> {
    let Some(Object(raw)) = raw else {
        return Ok(Rewrite::default());
    };
    Rewrite::new(
        route_path,
        raw.host.as_deref(),
        raw.path.as_deref(),
        query(raw.query)?,
        headers(raw.request_headers, Headers::request)?,
        headers(raw.response_headers, Headers::response)?,
    )
    .map_err(refused)
}
