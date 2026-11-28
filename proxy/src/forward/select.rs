//! The choice among the servers of a group.
//!
//! The first server of a request is chosen as the `balance` of the group says (`Method`): by the weighted round robin,
//! as the server with the fewest requests in use for its weight (`least`), or as the server that the key of the
//! request chooses (`hash`). A request that goes on to another server after a failure is given one by the weighted
//! round robin, whatever the `balance` is: so is a request that a `hash` group has no key for.
//!
//! The weighted choice is the smooth weighted round robin: every server that may be chosen gets its weight added to a
//! number of its own, the server with the greatest number is chosen, and the sum of the weights of the candidates is
//! taken from its number. Over any run of choices each server is chosen in proportion to its weight, and a server with
//! a greater weight is not chosen several times in a row while the others wait. The servers that are not `backup` are
//! the candidates first; the `backup` servers are the candidates only when no other server may be chosen. Every
//! method makes its choice among those candidates (`Turn::tier`).

use std::net::IpAddr;
use std::sync::{Mutex, PoisonError};

use http::HeaderMap;

use crate::config::{Balance, MAX_SERVERS, ServerConfig};

mod hash;
mod least;

use self::hash::Hash;
pub(super) use self::hash::Key;

// A `Tier` has a bit for each server of a group.
const _: () = assert!(MAX_SERVERS <= u64::BITS as usize);

/// How a group chooses the first server of a request.
pub(super) enum Method {
    RoundRobin,
    LeastConn,
    Hash(Hash),
}

impl Method {
    /// The method for a group with this `balance` and these servers.
    pub(super) fn new(balance: &Balance, servers: &[ServerConfig]) -> Method {
        match balance {
            Balance::RoundRobin => Method::RoundRobin,
            Balance::LeastConn => Method::LeastConn,
            Balance::Hash(key) => Method::Hash(Hash::new(key, servers)),
        }
    }

    /// The key of a request from `client`, with these `fields`, if the method is `hash` and the request has one.
    pub(super) fn key(&self, client: IpAddr, fields: &HeaderMap) -> Option<Key> {
        match self {
            Method::Hash(hash) => hash.key(client, fields),
            Method::RoundRobin | Method::LeastConn => None,
        }
    }

    /// The server for the first try of a request, among those that `may` accepts. `weight` gives the weight of the
    /// server at an index and `in_use` the number of requests it has, as `Turn::pick` and `least::pick` read them. A
    /// `hash` group with no `key` for the request chooses by weight.
    pub(super) fn first(
        &self,
        turn: &Turn,
        may: impl Fn(usize) -> bool,
        weight: impl Fn(usize) -> i64,
        in_use: impl Fn(usize) -> u64,
        key: Option<&Key>,
    ) -> Option<usize> {
        match (self, key) {
            (Method::LeastConn, _) => least::pick(turn, may, weight, in_use),
            (Method::Hash(hash), Some(key)) => hash.pick(turn, may, weight, key),
            (Method::RoundRobin | Method::Hash(_), _) => turn.pick(may, weight),
        }
    }
}

/// The servers that a choice is made among, by their places in the group: the servers that are not `backup` and that
/// may be chosen, or, if there are none, the `backup` servers that may be.
#[derive(Clone, Copy)]
pub(super) struct Tier(u64);

impl Tier {
    fn add(&mut self, index: usize) {
        // A server past the last bit is never a candidate, as it is never tried (see `Tried`); a group has at most 64.
        if let Some(bit) = u32::try_from(index)
            .ok()
            .and_then(|bit| 1u64.checked_shl(bit))
        {
            self.0 |= bit;
        }
    }

    fn has(self, index: usize) -> bool {
        u32::try_from(index)
            .ok()
            .and_then(|bit| self.0.checked_shr(bit))
            .is_some_and(|rest| rest & 1 == 1)
    }

    /// The places of the servers, from the first.
    fn indexes(self) -> impl Iterator<Item = usize> {
        let mut rest = self.0;
        std::iter::from_fn(move || {
            if rest == 0 {
                return None;
            }
            let bit = rest.trailing_zeros();
            rest &= rest - 1;
            usize::try_from(bit).ok()
        })
    }
}

/// The numbers and the `backup` marks of the servers of one group.
pub(super) struct Turn {
    backup: Vec<bool>,
    /// The number of each server. Taken for a choice only, never across a wait.
    current: Mutex<Vec<i64>>,
}

impl Turn {
    pub(super) fn new(servers: &[ServerConfig]) -> Turn {
        Turn {
            backup: servers.iter().map(|s| s.backup).collect(),
            current: Mutex::new(vec![0; servers.len()]),
        }
    }

    /// The servers that a choice is made among, if `may` accepts them: those that are not `backup`, or, if `may`
    /// accepts none of them, the `backup` ones. Empty if it accepts none.
    pub(super) fn tier(&self, may: impl Fn(usize) -> bool) -> Tier {
        for backup in [false, true] {
            let mut tier = Tier(0);
            for i in 0..self.backup.len() {
                if self.backup[i] == backup && may(i) {
                    tier.add(i);
                }
            }
            if tier.0 != 0 {
                return tier;
            }
        }
        Tier(0)
    }

    /// The index of the server to use, among those that `may` accepts, or `None` if it accepts none. `weight` gives the
    /// weight of the server at an index. A choice reads it once for each server that `may` accepts, so that the number
    /// of the server and the sum of the weights are made of the same value.
    pub(super) fn pick(
        &self,
        may: impl Fn(usize) -> bool,
        weight: impl Fn(usize) -> i64,
    ) -> Option<usize> {
        let mut current = self.current.lock().unwrap_or_else(PoisonError::into_inner);
        for backup in [false, true] {
            let mut total = 0;
            let mut best: Option<usize> = None;
            for i in 0..self.backup.len() {
                if self.backup[i] != backup || !may(i) {
                    continue;
                }
                let w = weight(i);
                current[i] += w;
                total += w;
                if best.is_none_or(|most| current[i] > current[most]) {
                    best = Some(i);
                }
            }
            if let Some(chosen) = best {
                current[chosen] -= total;
                return Some(chosen);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests;
