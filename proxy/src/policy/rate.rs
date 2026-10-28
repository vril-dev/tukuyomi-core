//! The rate limit: how many requests one client may make, kept as one number for each client.
//!
//! The client is the address that `forward::client_ip` finds for the request, never its port. An IPv4 address is one
//! client; an IPv6 address stands for the /64 network it is in, so a client cannot get more counts by choosing
//! addresses within its own network. An IPv4-mapped IPv6 address counts as the IPv4 address it holds.
//!
//! The count is the generic cell rate algorithm. A client has one number, `tat`: when a request that keeps exactly to
//! the steady rate would be due next, in nanoseconds since the limit was made. `gap` is the time between two requests
//! at `rate` (a second divided by `rate`, rounded up, so a client is never held to more than the rate) and `tolerance`
//! is `burst * gap`. A request at `now` passes if `tat <= now + tolerance`, and `tat` then becomes `max(tat, now) +
//! gap`; otherwise it is refused and nothing changes. So the requests of a client that has been quiet pass back to
//! back up to `burst + 1`, the next one is refused, and after that one passes for every `gap` that the client waits.
//! The answer to a refused request is the seconds until `now + tolerance` reaches `tat`, rounded up and at least 1;
//! as that wait is never more than `gap`, which is at most a second, it is 1. A client that has no number yet is new,
//! and a new client always passes.
//!
//! No number wraps. `gap` is at most 10^9 and `tolerance` at most 10^5 times that, a `tat` is never more than
//! `tolerance + gap` past the `now` of the request that set it, and every sum saturates, so the arithmetic holds also
//! at the end of the 584 years that nanoseconds in 64 bits span.
//!
//! The table holds at most `keys` clients, in the order of their last request (a refused request is a request). It is
//! a vector of slots linked to each other by index and a hash map from client to slot, so a request does constant
//! work and the table has no unsafe code and no pointers. The hash map is the standard one, with a seed chosen at
//! random, so a client cannot choose addresses that fall into one place. At each request up to `SWEEP` clients from
//! the old end whose `tat` has passed are dropped: such a client has nothing to remember, since a new client starts
//! the same way. When the table is full and the oldest client has not passed, that client is dropped to make room for
//! the new one and counted as evicted: it starts again with a full burst when it next comes, so the limit is loosened
//! for it once, and a new client is never refused for the lack of room. A client takes up to about 100 bytes (a slot of
//! 40 bytes, and an entry of the hash map with the room it keeps free), so the table at the most `keys` is about 100
//! MB.
//!
//! The table is behind a `std::sync::Mutex` in the context that the connections share. The runtime of the
//! connections has one thread, so the lock is not contended; it is held for constant work and never across an await.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, PoisonError};
use std::time::Instant;

use crate::config::RateLimitConfig;
use crate::forward::client_ip::{Cidr, trusts};

const NANOS: u64 = 1_000_000_000;
/// The most clients that one request drops from the old end of the table because their number has passed.
const SWEEP: usize = 4;
/// No slot: the end of the list of slots.
const NIL: usize = usize::MAX;

/// One client: an IPv4 address, or the first 64 bits of an IPv6 address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Key {
    V4(u32),
    V6(u64),
}

impl Key {
    fn of(ip: IpAddr) -> Key {
        match ip.to_canonical() {
            IpAddr::V4(v4) => Key::V4(u32::from(v4)),
            IpAddr::V6(v6) => {
                let [a, b, c, d, e, f, g, h, ..] = v6.octets();
                Key::V6(u64::from_be_bytes([a, b, c, d, e, f, g, h]))
            }
        }
    }
}

/// The seconds a client is told to wait when it is `wait` nanoseconds short of its turn: rounded up, at least 1.
fn seconds(wait: u64) -> u32 {
    u32::try_from(wait.div_ceil(NANOS).max(1)).unwrap_or(u32::MAX)
}

/// A client in the table, and its neighbours in the order of the last request.
struct Slot {
    key: Key,
    tat: u64,
    /// The slot of the client whose last request was just after this one's; `NIL` for the newest.
    newer: usize,
    /// The slot of the client whose last request was just before this one's; `NIL` for the oldest.
    older: usize,
}

struct Table {
    max: usize,
    index: HashMap<Key, usize>,
    /// Every slot in use is in `index`; the others are in `free`. The vector never holds more than `max`.
    slots: Vec<Slot>,
    free: Vec<usize>,
    newest: usize,
    oldest: usize,
    evicted: u64,
}

impl Table {
    fn new(max: usize) -> Table {
        Table {
            max: max.max(1),
            index: HashMap::new(),
            slots: Vec::new(),
            free: Vec::new(),
            newest: NIL,
            oldest: NIL,
            evicted: 0,
        }
    }

    /// Counts a request of `key` at `now`. `Err` holds the seconds until the client may make one.
    fn admit(&mut self, key: Key, now: u64, gap: u64, tolerance: u64) -> Result<(), u32> {
        self.sweep(now);
        let Some(&at) = self.index.get(&key) else {
            if self.index.len() >= self.max {
                // The sweep dropped the oldest client if its number had passed, so this one is still in force.
                self.remove(self.oldest);
                self.evicted = self.evicted.saturating_add(1);
            }
            self.insert(key, now.saturating_add(gap));
            return Ok(());
        };
        self.touch(at);
        let latest = now.saturating_add(tolerance);
        let slot = &mut self.slots[at];
        if slot.tat > latest {
            return Err(seconds(slot.tat - latest));
        }
        slot.tat = slot.tat.max(now).saturating_add(gap);
        Ok(())
    }

    /// Drops up to `SWEEP` clients from the old end whose number has passed.
    fn sweep(&mut self, now: u64) {
        for _ in 0..SWEEP {
            if self.oldest == NIL || self.slots[self.oldest].tat > now {
                break;
            }
            self.remove(self.oldest);
        }
    }

    /// Takes `at` out of the order of requests.
    fn unlink(&mut self, at: usize) {
        let (newer, older) = (self.slots[at].newer, self.slots[at].older);
        if newer == NIL {
            self.newest = older;
        } else {
            self.slots[newer].older = older;
        }
        if older == NIL {
            self.oldest = newer;
        } else {
            self.slots[older].newer = newer;
        }
    }

    /// Puts `at`, which is in no order, at the new end.
    fn link(&mut self, at: usize) {
        self.slots[at].newer = NIL;
        self.slots[at].older = self.newest;
        if self.newest == NIL {
            self.oldest = at;
        } else {
            self.slots[self.newest].newer = at;
        }
        self.newest = at;
    }

    /// Makes `at` the client of the last request.
    fn touch(&mut self, at: usize) {
        if self.newest != at {
            self.unlink(at);
            self.link(at);
        }
    }

    fn remove(&mut self, at: usize) {
        self.unlink(at);
        self.index.remove(&self.slots[at].key);
        self.free.push(at);
    }

    /// Adds a client that is not in the table; there is room.
    fn insert(&mut self, key: Key, tat: u64) {
        let slot = Slot {
            key,
            tat,
            newer: NIL,
            older: NIL,
        };
        let at = match self.free.pop() {
            Some(at) => {
                self.slots[at] = slot;
                at
            }
            None => {
                self.slots.push(slot);
                self.slots.len() - 1
            }
        };
        self.index.insert(key, at);
        self.link(at);
    }
}

/// The rate limit of the configuration, and the clients it counts.
pub struct RateLimit {
    /// The networks whose requests are not counted.
    exempt: Vec<Cidr>,
    /// The nanoseconds between two requests at the steady rate.
    gap: u64,
    /// The nanoseconds that a client may be ahead of the steady rate: `burst * gap`.
    tolerance: u64,
    /// The time that every number is counted from.
    start: Instant,
    table: Mutex<Table>,
}

impl RateLimit {
    pub fn new(config: &RateLimitConfig) -> RateLimit {
        let gap = NANOS.div_ceil(u64::from(config.rate).max(1));
        RateLimit {
            exempt: config.exempt.clone(),
            gap,
            tolerance: u64::from(config.burst).saturating_mul(gap),
            start: Instant::now(),
            table: Mutex::new(Table::new(config.keys)),
        }
    }

    /// Counts a request of `client` and says whether it passes. `Err` holds the seconds until the client may make one;
    /// it goes in the `Retry-After` of the answer. A request from an exempt network passes and is not counted.
    pub fn admit(&self, client: IpAddr) -> Result<(), u32> {
        let elapsed = self.start.elapsed().as_nanos();
        self.admit_at(client, u64::try_from(elapsed).unwrap_or(u64::MAX))
    }

    /// `admit` at the time `now`, in nanoseconds since the limit was made.
    fn admit_at(&self, client: IpAddr, now: u64) -> Result<(), u32> {
        if trusts(&self.exempt, client) {
            return Ok(());
        }
        self.table
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .admit(Key::of(client), now, self.gap, self.tolerance)
    }

    /// How many clients are counted now.
    pub fn keys(&self) -> usize {
        self.table
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .index
            .len()
    }

    /// How many clients were dropped to make room while their number was still in force, since the start.
    pub fn evicted(&self) -> u64 {
        self.table
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .evicted
    }
}

#[cfg(test)]
mod tests;
