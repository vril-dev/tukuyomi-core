//! The server with the fewest requests in use for its weight.

use super::{Tier, Turn};
use crate::config::MAX_SERVERS;

/// What a choice reads of a server of its tier, once: the requests it has and its weight.
type Read = (u64, i64);

/// The weight as a number that is not below 0, which is what the comparison needs of it.
fn size(weight: i64) -> u128 {
    u128::from(u64::try_from(weight).unwrap_or(0))
}

/// Whether the requests `a.0` for the weight `a.1` are fewer than `b.0` for `b.1`: `a.0 / a.1 < b.0 / b.1`, as products,
/// which a `u128` holds whatever the numbers are.
fn fewer(a: Read, b: Read) -> bool {
    u128::from(a.0) * size(b.1) < u128::from(b.0) * size(a.1)
}

/// The server of the tier with the fewest requests for its weight, among those that `may` accepts. `in_use` gives the
/// requests that the server at an index has and `weight` its weight, each read once for each server of the tier. If
/// several servers are as few as that, the weighted round robin chooses among them, with the weights that were read.
pub(super) fn pick(
    turn: &Turn,
    may: impl Fn(usize) -> bool,
    weight: impl Fn(usize) -> i64,
    in_use: impl Fn(usize) -> u64,
) -> Option<usize> {
    let tier = turn.tier(may);
    let mut read: [Read; MAX_SERVERS] = [(0, 0); MAX_SERVERS];
    let mut fewest: Option<usize> = None;
    for index in tier.indexes() {
        read[index] = (in_use(index), weight(index));
        if fewest.is_none_or(|best| fewer(read[index], read[best])) {
            fewest = Some(index);
        }
    }
    let lowest = read[fewest?];
    let mut tied = Tier(0);
    for index in tier.indexes() {
        // No server has fewer, so a server that does not have more has as few.
        if !fewer(lowest, read[index]) {
            tied.add(index);
        }
    }
    turn.pick(|index| tied.has(index), |index| read[index].1)
}
