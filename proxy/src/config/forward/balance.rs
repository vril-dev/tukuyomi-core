//! The `balance` of a group: how the server for a request is chosen from the servers of the group, and what the key of
//! `hash` is made of.

use http::HeaderName;

use super::At;
use crate::config::{ConfigError, ensure};
use crate::inbound::head::is_token;

/// The longest name of a header or of a cookie that `hash_key` gives.
const MAX_KEY_NAME: usize = 64;
const BAD_KEY: &str = "an upstream hash_key is not a name of 1 to 64 token characters";
/// A header whose name has an underscore is dropped from every request (see `inbound::represent`), so it could never
/// give a key.
const UNDERSCORE: &str = "an upstream hash_key header name has an underscore";

/// How the first server of a request is chosen from the servers of a group. A request that goes on to another server
/// after a failure is given one by the weighted round robin, whatever this is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Balance {
    /// The weighted round robin: the choice that a group without `balance` has.
    RoundRobin,
    /// The server with the fewest requests in use for its weight.
    LeastConn,
    /// The server that the key of the request chooses, as long as that server is one that can be used.
    Hash(HashKey),
}

/// What the key of a request is made of, for a group that has `balance` `hash`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HashKey {
    /// The address that stands for the client (the /64 network of an IPv6 address).
    ClientIp,
    /// The value of the first field with this name, as the client sent it.
    Header(HeaderName),
    /// The value of the cookie with this name, as the client sent it.
    Cookie(String),
}

/// The `balance` of the group at `group`, from `balance`, `hash_policy` and `hash_key` as they are written. A group
/// that writes none of them has the weighted round robin. `hash_policy` and `hash_key` are for `hash` alone. When
/// more than one key is wrong, the refusal is about the first of them in the order `balance`, `hash_policy`,
/// `hash_key`. The name of a header has no `_`; that of a cookie may.
pub(super) fn check(
    group: usize,
    balance: Option<String>,
    hash_policy: Option<String>,
    hash_key: Option<String>,
) -> Result<Balance, (ConfigError, At)> {
    let at = |key: &'static str| move |e: ConfigError| (e, At::Group(group, Some(key)));
    let method = match balance.as_deref() {
        None | Some("round_robin") => Balance::RoundRobin,
        Some("least_conn") => Balance::LeastConn,
        Some("hash") => return hash(group, hash_policy, hash_key).map(Balance::Hash),
        Some(_) => {
            return Err(at("balance")(ConfigError(
                "an upstream balance is not round_robin, least_conn or hash",
            )));
        }
    };
    ensure(
        hash_policy.is_none(),
        "an upstream has a hash_policy without balance hash",
    )
    .map_err(at("hash_policy"))?;
    ensure(
        hash_key.is_none(),
        "an upstream has a hash_key without balance hash",
    )
    .map_err(at("hash_key"))?;
    Ok(method)
}

/// The key of the group at `group`, which has `balance` `hash`, from its `hash_policy` and `hash_key`.
fn hash(
    group: usize,
    policy: Option<String>,
    key: Option<String>,
) -> Result<HashKey, (ConfigError, At)> {
    let at = |key: &'static str| move |e: ConfigError| (e, At::Group(group, Some(key)));
    let policy = policy
        .ok_or(ConfigError(
            "an upstream with balance hash has no hash_policy",
        ))
        .map_err(at("hash_policy"))?;
    let named = match policy.as_str() {
        "client_ip" => {
            ensure(
                key.is_none(),
                "an upstream hash_policy client_ip has a hash_key",
            )
            .map_err(at("hash_key"))?;
            return Ok(HashKey::ClientIp);
        }
        "header" | "cookie" => key
            .ok_or(ConfigError(
                "an upstream hash_policy header or cookie has no hash_key",
            ))
            .map_err(at("hash_key"))?,
        _ => {
            return Err(at("hash_policy")(ConfigError(
                "an upstream hash_policy is not client_ip, header or cookie",
            )));
        }
    };
    ensure(
        (1..=MAX_KEY_NAME).contains(&named.len()) && named.bytes().all(is_token),
        BAD_KEY,
    )
    .map_err(at("hash_key"))?;
    if policy == "cookie" {
        return Ok(HashKey::Cookie(named));
    }
    ensure(!named.contains('_'), UNDERSCORE).map_err(at("hash_key"))?;
    // Every token character is one that a field name may have, so this does not refuse a name that was checked.
    HeaderName::from_bytes(named.as_bytes())
        .map(HashKey::Header)
        .map_err(|_| at("hash_key")(ConfigError(BAD_KEY)))
}
