//! The sessions of the admin process, in memory only.
//!
//! A session has an id of 32 random bytes, which is the value of the cookie `tukuyomi_admin` as base64url without
//! padding (43 characters). The process keeps the session under the SHA-256 of that text and never the id itself, so
//! the table tells nobody the id of a session. The session also has its user's name, the `changed` of the user when
//! the session was made, a token for the CSRF check (another 32 random bytes, in the same form) and two times.
//!
//! A session ends when nothing used it for the idle time, when it is older than the total time, and when it is
//! closed: at the logout, and for every session of a user whose password, role or state changed (`close_user`). A
//! user keeps at most `MAX_PER_USER` sessions of each kind (see below): a session that would be one more closes the
//! oldest session of that kind of that user (the one made first, however lately it was used), after the sessions of
//! the user that have run out are dropped, and `open` says which it closed. At most `MAX_SESSIONS` sessions are kept
//! in all; when the table is full the sessions that have run out are dropped first, and then no new one is made.
//!
//! A session is of one of two kinds. The one that a password opens for a user with a second factor is pending: it
//! ends 5 minutes after it was made, and only the check of the second factor and the logout may use it (see
//! `server`); the check closes it and opens a session of the other kind. The kinds are counted apart, so a person who
//! knows only the password cannot close the sessions that count by logging in again and again. A session may also
//! hold the seed of a second factor that is being set up, for 10 minutes (`set_setup`, `setup`), in memory only, and
//! it is zeroed with the session.
//!
//! The functions take the time as an argument, so that the limits can be tried without waiting.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use zeroize::Zeroize;

use super::auth::totp::Seed;
use super::password::{hex, random};
use crate::acme::base64;
use crate::rules::bundle::sha256;

/// The bytes of an id and of a CSRF token.
const SECRET_BYTES: usize = 32;
/// The characters of an id: 32 bytes as base64url without padding.
const ID_CHARS: usize = 43;
/// The most sessions kept for one user.
const MAX_PER_USER: usize = 16;
/// The most sessions kept.
const MAX_SESSIONS: usize = 1024;
/// The bytes of the digest that the handle of a session shows, as 8 hexadecimal digits.
const HANDLE_BYTES: usize = 4;
/// How long a pending session lives.
const PENDING_FOR: Duration = Duration::from_secs(5 * 60);
/// How long the seed of a setup is kept.
const SETUP_FOR: Duration = Duration::from_secs(10 * 60);

/// A session that was just made. It is not shown by `Debug`: it holds the id of the session.
#[derive(Clone)]
pub struct Opened {
    /// The value of the cookie.
    pub cookie: String,
    pub csrf: String,
    /// What the audit log shows of the session instead of its id.
    pub handle: String,
    /// The handle of the oldest session of the same user, which was closed to make room for this one.
    pub closed: Option<String>,
}

/// A session that a cookie names, and is alive.
#[derive(Clone)]
pub struct Found {
    pub name: String,
    pub changed: u64,
    pub csrf: String,
    pub handle: String,
    /// The session waits for the second factor.
    pub pending: bool,
    /// How long the session lives if it is not used again.
    pub idle_left: Duration,
    /// How long the session lives at the most.
    pub total_left: Duration,
}

struct Entry {
    name: String,
    changed: u64,
    csrf: String,
    created: Instant,
    last: Instant,
    pending: bool,
    /// The seed of a second factor that is being set up, and when it was made.
    setup: Option<(Seed, Instant)>,
}

/// The sessions.
pub struct Sessions {
    idle: Duration,
    total: Duration,
    entries: Mutex<HashMap<[u8; 32], Entry>>,
}

/// The key of the session that the cookie `text` names: its SHA-256. None: `text` is not 43 base64url characters.
fn key(text: &str) -> Option<[u8; 32]> {
    let shaped = text.len() == ID_CHARS
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    shaped.then(|| sha256(text.as_bytes()))
}

fn handle(key: &[u8; 32]) -> String {
    hex(&key[..HANDLE_BYTES])
}

impl Sessions {
    /// Sessions that end after `idle` without use and `total` after they were made.
    pub fn new(idle: Duration, total: Duration) -> Sessions {
        Sessions {
            idle,
            total,
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn expired(&self, entry: &Entry, now: Instant) -> bool {
        now.saturating_duration_since(entry.last) >= self.idle
            || now.saturating_duration_since(entry.created) >= self.total
            || (entry.pending && now.saturating_duration_since(entry.created) >= PENDING_FOR)
    }

    /// Makes room in `entries` for a session of the user `name`, pending or not: when the user has `MAX_PER_USER`
    /// sessions of that kind that are alive, the oldest is removed. Returns the handle of the one that was removed.
    fn make_room(
        &self,
        entries: &mut HashMap<[u8; 32], Entry>,
        name: &str,
        pending: bool,
        now: Instant,
    ) -> Option<String> {
        let ours = |entry: &Entry| entry.name == name && entry.pending == pending;
        if entries.values().filter(|entry| ours(entry)).count() < MAX_PER_USER {
            return None;
        }
        entries.retain(|_, entry| !ours(entry) || !self.expired(entry, now));
        let mine = entries.iter().filter(|(_, entry)| ours(entry));
        if mine.clone().count() < MAX_PER_USER {
            return None;
        }
        let oldest = *mine.min_by_key(|(_, entry)| entry.created)?.0;
        entries.remove(&oldest);
        Some(handle(&oldest))
    }

    /// A new session of the user `name`, whose `changed` is given. None: no random number, or the table is full.
    pub fn open(&self, name: &str, changed: u64, now: Instant) -> Option<Opened> {
        self.make(name, changed, false, now)
    }

    /// As `open`, for a session that waits for the second factor.
    pub fn open_pending(&self, name: &str, changed: u64, now: Instant) -> Option<Opened> {
        self.make(name, changed, true, now)
    }

    fn make(&self, name: &str, changed: u64, pending: bool, now: Instant) -> Option<Opened> {
        let mut id = [0u8; SECRET_BYTES];
        let mut token = [0u8; SECRET_BYTES];
        let drawn = random(&mut id) && random(&mut token);
        let cookie = base64::url(&id);
        let csrf = base64::url(&token);
        id.zeroize();
        token.zeroize();
        if !drawn {
            return None;
        }
        let key = key(&cookie)?;
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        // This comes before the check of the whole table: the session it closes leaves a place.
        let closed = self.make_room(&mut entries, name, pending, now);
        if entries.len() >= MAX_SESSIONS {
            entries.retain(|_, entry| !self.expired(entry, now));
            if entries.len() >= MAX_SESSIONS {
                return None;
            }
        }
        entries.insert(
            key,
            Entry {
                name: name.to_owned(),
                changed,
                csrf: csrf.clone(),
                created: now,
                last: now,
                pending,
                setup: None,
            },
        );
        Some(Opened {
            cookie,
            csrf,
            handle: handle(&key),
            closed,
        })
    }

    /// The session that the cookie `text` names, if there is one and it is alive. It counts as used at `now`. A
    /// session that has run out is removed.
    pub fn find(&self, text: &str, now: Instant) -> Option<Found> {
        let key = key(text)?;
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if self.expired(entries.get(&key)?, now) {
            entries.remove(&key);
            return None;
        }
        let entry = entries.get_mut(&key)?;
        entry.last = now;
        Some(Found {
            name: entry.name.clone(),
            changed: entry.changed,
            csrf: entry.csrf.clone(),
            handle: handle(&key),
            pending: entry.pending,
            idle_left: self.idle,
            total_left: self
                .total
                .saturating_sub(now.saturating_duration_since(entry.created)),
        })
    }

    /// Keeps `seed` in the session that the cookie `text` names, which must be alive and not pending. False: there is
    /// no such session.
    pub fn set_setup(&self, text: &str, seed: Seed, now: Instant) -> bool {
        let Some(key) = key(text) else {
            return false;
        };
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        match entries.get_mut(&key) {
            Some(entry) if !self.expired(entry, now) && !entry.pending => {
                entry.setup = Some((seed, now));
                true
            }
            _ => false,
        }
    }

    /// The seed that `set_setup` kept in the session, if the session is there and the seed is not 10 minutes old.
    pub fn setup(&self, text: &str, now: Instant) -> Option<Seed> {
        let key = key(text)?;
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = entries.get_mut(&key)?;
        let live = entry
            .setup
            .as_ref()
            .map(|(_, since)| now.saturating_duration_since(*since) < SETUP_FOR)?;
        if !live {
            entry.setup = None;
            return None;
        }
        entry.setup.as_ref().map(|(seed, _)| seed.clone())
    }

    /// Ends the session that the cookie `text` names.
    pub fn close(&self, text: &str) {
        if let Some(key) = key(text) {
            self.entries
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&key);
        }
    }

    /// Ends every session of the user `name`.
    pub fn close_user(&self, name: &str) {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|_, entry| entry.name != name);
    }
}

#[cfg(test)]
mod tests;
