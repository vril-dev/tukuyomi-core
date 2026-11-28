//! The server that the key of a request chooses: the weighted rendezvous hash.
//!
//! Every server of the tier gets a score from the key and from the server alone (where it is and which of the servers
//! at that address it is, not the name of the group or the order in the file), and the server with the best score is
//! chosen. A server that cannot be chosen at the moment is not in the tier, so only the keys whose server it was go
//! to the next one; no key moves between two servers that both stay. The score of a server is its weight over the
//! negative logarithm of a number that is drawn from 0 to 1 (0 and 1 left out) by the hash of the key and the server,
//! so that over many keys each server has a share in proportion to its weight. The logarithm is a floating point
//! number: in one build a key always goes to the same server, but another build or another CPU may round the last
//! bit differently, and then a key whose two best scores are almost the same may go to the other server.

use std::net::{IpAddr, SocketAddr};

use http::header::{COOKIE, HeaderMap};
use sha2::{Digest, Sha256};

use super::Turn;
use crate::config::{HashKey, ServerConfig};
use crate::forward::group::canonical;
use crate::inbound::head::trim_ows;

/// The longest key. A request with a longer one, and one with an empty key, has none.
const MAX_KEY: usize = 1024;

/// The bytes that tell a server of a group from the others, to the hash: the family of its address (4 or 6), the
/// address in 16 bytes (an IPv4 address in its first 4), the port, and which of the servers at the same address it is.
type Place = [u8; 1 + 16 + 2 + 4];

/// The key of a request: the SHA-256 of what the policy of the group takes it from.
pub(in crate::forward) struct Key([u8; 32]);

impl Key {
    fn of(bytes: &[u8]) -> Key {
        Key(Sha256::digest(bytes).into())
    }
}

/// The key policy of a `hash` group, and the place of each of its servers.
pub(in crate::forward) struct Hash {
    policy: HashKey,
    places: Vec<Place>,
}

impl Hash {
    pub(super) fn new(policy: &HashKey, servers: &[ServerConfig]) -> Hash {
        let places = servers
            .iter()
            .enumerate()
            .map(|(index, server)| {
                let address = canonical(server.address);
                let same = |other: &&ServerConfig| canonical(other.address) == address;
                let nth = servers.iter().take(index).filter(same).count();
                place(address, nth)
            })
            .collect();
        Hash {
            policy: policy.clone(),
            places,
        }
    }

    /// The key of a request from `client`, whose fields are `fields` as the client sent them. `None` if the request
    /// has none: no such field or cookie, or its value is empty or longer than 1024 bytes.
    pub(super) fn key(&self, client: IpAddr, fields: &HeaderMap) -> Option<Key> {
        let value = match &self.policy {
            HashKey::ClientIp => return Some(client_key(client)),
            HashKey::Header(name) => fields.get(name)?.as_bytes(),
            HashKey::Cookie(name) => cookie(fields, name)?,
        };
        (1..=MAX_KEY).contains(&value.len()).then(|| Key::of(value))
    }

    /// The server of the tier with the best score for `key`, or `None` if `may` accepts no server. `weight` is read
    /// once for each server of the tier.
    pub(super) fn pick(
        &self,
        turn: &Turn,
        may: impl Fn(usize) -> bool,
        weight: impl Fn(usize) -> i64,
        key: &Key,
    ) -> Option<usize> {
        let mut best: Option<(usize, f64)> = None;
        for index in turn.tier(may).indexes() {
            let Some(place) = self.places.get(index) else {
                continue;
            };
            let score = score(key, place, weight(index));
            // A score that is the same as the best one so far leaves the server that comes first.
            if best.is_none_or(|(_, top)| score > top) {
                best = Some((index, score));
            }
        }
        best.map(|(index, _)| index)
    }
}

/// The place of a server at `address`, which is the `nth` of the servers of its group at that address.
fn place(address: SocketAddr, nth: usize) -> Place {
    let mut place = [0; 1 + 16 + 2 + 4];
    match address.ip() {
        IpAddr::V4(v4) => {
            place[0] = 4;
            place[1..5].copy_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            place[0] = 6;
            place[1..17].copy_from_slice(&v6.octets());
        }
    }
    place[17..19].copy_from_slice(&address.port().to_be_bytes());
    place[19..23].copy_from_slice(&u32::try_from(nth).unwrap_or(u32::MAX).to_be_bytes());
    place
}

/// The key of a client: its address if it is IPv4, and the first 64 bits of it if it is IPv6, as `policy::rate` counts a
/// client, so that a client cannot have another key for each address of its network.
fn client_key(client: IpAddr) -> Key {
    match client.to_canonical() {
        IpAddr::V4(v4) => Key::of(&v4.octets()),
        IpAddr::V6(v6) => {
            let [a, b, c, d, e, f, g, h, ..] = v6.octets();
            Key::of(&[a, b, c, d, e, f, g, h])
        }
    }
}

/// The value of the first cookie called `name` of all the `Cookie` fields (an HTTP/1.1 request may have several lines,
/// an HTTP/2 request one for each crumb), without the blanks around it. Cookie names are case sensitive.
fn cookie<'a>(fields: &'a HeaderMap, name: &str) -> Option<&'a [u8]> {
    fields
        .get_all(COOKIE)
        .iter()
        .flat_map(|line| line.as_bytes().split(|&b| b == b';'))
        .filter_map(|pair| {
            let pair = trim_ows(pair);
            let (crumb, rest) = pair.split_at(pair.iter().position(|&b| b == b'=')?);
            (crumb == name.as_bytes()).then(|| trim_ows(rest.get(1..).unwrap_or_default()))
        })
        .next()
}

/// A number from 0 to 1, both left out, of the 52 high bits of `bits`: (`x` + 0.5) / 2^52. 52 bits and not 53, so that
/// the sum and the quotient are exact, and the largest number is below 1 and the smallest above 0: with 53 bits the
/// sum 2^53 - 0.5 is not a double, and the largest number would round to 1, whose logarithm is 0.
fn unit(bits: u64) -> f64 {
    // At most 2^52 - 1, so it is exact as a double.
    let x = (bits >> 12) as f64;
    (x + 0.5) / 4_503_599_627_370_496.0
}

/// The score of the server at `place` for `key`: its `weight` over the negative logarithm of the number that the hash
/// of the key and the place draws. The number is in 0 to 1 and not 0 or 1, so the logarithm is not 0 and the score is
/// finite.
fn score(key: &Key, place: &Place, weight: i64) -> f64 {
    let mut hasher = Sha256::new();
    hasher.update(key.0);
    hasher.update(place);
    let [a, b, c, d, e, f, g, h, ..]: [u8; 32] = hasher.finalize().into();
    let u = unit(u64::from_be_bytes([a, b, c, d, e, f, g, h]));
    weight as f64 / -u.ln()
}

#[cfg(test)]
mod tests;
