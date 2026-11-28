//! The weighted choice among the servers of a group.
//!
//! The choice is the smooth weighted round robin: every server that may be chosen gets its weight added to a number
//! of its own, the server with the greatest number is chosen, and the sum of the weights of the candidates is taken
//! from its number. Over any run of choices each server is chosen in proportion to its weight, and a server with a
//! greater weight is not chosen several times in a row while the others wait. The servers that are not `backup` are
//! the candidates first; the `backup` servers are the candidates only when no other server may be chosen.

use std::sync::{Mutex, PoisonError};

use crate::config::ServerConfig;

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
