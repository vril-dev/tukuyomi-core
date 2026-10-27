//! Who a request is from: the login with its limits, the session of a request, and the change of a password.
//!
//! A login checks the name and the password against the stored user, and always computes one hash, whatever the
//! name: an unknown name, a name that is not a name, a user that is disabled and a user that is locked are all checked
//! against a hash (the stored one or a dummy one), so that the time does not tell them from a wrong password. They
//! all end the same way, as `Login::Refused`, and the server gives all of them the same status and body. The reason
//! is written to the audit log only, and the name that was sent is written with it only when it is the name of a
//! user: what else is sent in the field of the name (a password, for one) never reaches the log.
//!
//! Two limits protect the login. For each user, 5 failures in a row lock it for 15 minutes; a try while it is locked
//! is a failure too and is refused whatever its password, and it starts the 15 minutes again. A success clears the
//! count. For each client address, at most 30 tries a minute are taken (`allow_client`); the others are refused
//! before they cost a hash and before they count against any user. The checking of the current password in a change of
//! the password counts against the same limit of the user. A table of clients is kept for at most `MAX_CLIENTS`
//! addresses, and when it is full of addresses that have tried in the last minute, no other address is taken.
//!
//! A session is made by a login that passed, and is looked at again with the stored user at each request: it
//! counts only while the user exists, is not disabled and has the `changed` that the session saw. A change of the
//! password makes the new `changed`, closes every session of the user, and opens one for the request that changed it.
//!
//! The audit log is written before a session is made and before a password is changed; when it cannot be written the
//! answer is `Unavailable` and nothing was changed. A session is closed whether or not the audit log takes the line,
//! because closing takes rights away: the logout closes the session first, and the audit log tells the logger when
//! it cannot write the line. A user keeps at most 16 sessions (see `session`): the login that would make one more
//! closes the oldest and writes it as a `logout` with the reason `too many sessions`.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use super::audit::{AuditLog, Event, Outcome};
use super::password::{Hash, PASSWORD_MAX, Secret, hex, random, valid_name, valid_password};
use super::session::{Opened, Sessions};
use super::store::{AdminError, AdminStore, CONFLICT};
use super::users::{Role, User, now_ms};

/// The failures in a row that lock a user.
const LOCK_AFTER: u32 = 5;
const LOCK_FOR: Duration = Duration::from_secs(15 * 60);
/// The tries a client may make in `WINDOW`.
const TRIES: usize = 30;
const WINDOW: Duration = Duration::from_secs(60);
/// The most clients kept in the table.
const MAX_CLIENTS: usize = 4096;

/// What an event needs of its request: its number and the address of its client.
#[derive(Clone, Copy, Debug)]
pub struct Cx<'a> {
    pub id: &'a str,
    pub client: IpAddr,
}

/// The user of a request, as the session and the stored user say.
#[derive(Clone)]
pub struct Who {
    pub name: String,
    pub role: Role,
    /// The cookie of the session.
    pub cookie: String,
    pub csrf: String,
    pub handle: String,
    pub changed: u64,
    pub idle_left: Duration,
    pub total_left: Duration,
}

/// How the check of a cookie ended.
pub enum Authed {
    Who(Who),
    /// No session, or one that is over, or one whose user is gone, disabled or changed.
    Unauthorized,
    /// The user could not be read.
    Unavailable,
}

/// How a login ended.
pub enum Login {
    Opened(Opened, Role),
    Refused,
    Unavailable,
}

/// How a change of the password ended.
pub enum Changed {
    /// Changed; the session that replaces the others, if one could be made.
    Done(Option<Opened>),
    /// The current password is wrong, or the user is locked.
    Wrong,
    /// The new password is not one that may be set.
    Invalid,
    /// The user was changed by another request meanwhile.
    Conflict,
    /// The session is no longer one.
    Gone,
    Unavailable,
}

#[derive(Default)]
struct Failures {
    count: u32,
    locked_until: Option<Instant>,
}

/// The limits of the login.
pub struct Guard {
    users: Mutex<HashMap<String, Failures>>,
    clients: Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
}

impl Guard {
    pub fn new() -> Guard {
        Guard {
            users: Mutex::new(HashMap::new()),
            clients: Mutex::new(HashMap::new()),
        }
    }

    /// Whether the client at `ip` may try at `now`; a try that is taken is counted.
    pub fn allow_client(&self, ip: IpAddr, now: Instant) -> bool {
        let mut clients = self.clients.lock().unwrap_or_else(PoisonError::into_inner);
        let recent = |tries: &VecDeque<Instant>| {
            tries
                .back()
                .is_some_and(|&last| now.saturating_duration_since(last) < WINDOW)
        };
        if !clients.contains_key(&ip) && clients.len() >= MAX_CLIENTS {
            clients.retain(|_, tries| recent(tries));
            if clients.len() >= MAX_CLIENTS {
                return false;
            }
        }
        let tries = clients.entry(ip).or_default();
        while tries
            .front()
            .is_some_and(|&first| now.saturating_duration_since(first) >= WINDOW)
        {
            tries.pop_front();
        }
        if tries.len() >= TRIES {
            return false;
        }
        tries.push_back(now);
        true
    }

    /// Whether the user `name` is locked at `now`.
    pub fn locked(&self, name: &str, now: Instant) -> bool {
        self.users
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(name)
            .and_then(|failures| failures.locked_until)
            .is_some_and(|until| now < until)
    }

    /// Counts a failure of the user `name` at `now`. True: this failure locked the user, which was not locked before.
    pub fn failed(&self, name: &str, now: Instant) -> bool {
        let mut users = self.users.lock().unwrap_or_else(PoisonError::into_inner);
        let failures = users.entry(name.to_owned()).or_default();
        let was_locked = failures.locked_until.is_some_and(|until| now < until);
        // A lock that has run out starts the count again.
        if !was_locked && failures.locked_until.is_some() {
            *failures = Failures::default();
        }
        failures.count = failures.count.saturating_add(1);
        if failures.count >= LOCK_AFTER {
            failures.locked_until = Some(now + LOCK_FOR);
            return !was_locked;
        }
        false
    }

    /// The user `name` gave the right password.
    pub fn succeeded(&self, name: &str) {
        self.users
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(name);
    }
}

impl Default for Guard {
    fn default() -> Guard {
        Guard::new()
    }
}

/// A password as it is checked: one that is longer than any password can be is checked as an empty one, which no
/// hash is of.
fn bounded(secret: &Secret) -> &str {
    if secret.as_str().len() <= PASSWORD_MAX {
        secret.as_str()
    } else {
        ""
    }
}

/// The login, the sessions and the change of the password.
pub struct Auth {
    store: Arc<dyn AdminStore>,
    audit: Arc<AuditLog>,
    sessions: Sessions,
    guard: Guard,
    /// The hash that a name no user has is checked against.
    dummy: Hash,
    /// The iterations of a new hash.
    iterations: u32,
}

impl Auth {
    /// None: no random number for the dummy hash.
    pub fn new(
        store: Arc<dyn AdminStore>,
        audit: Arc<AuditLog>,
        idle: Duration,
        total: Duration,
        iterations: u32,
    ) -> Option<Auth> {
        let mut seed = [0u8; 16];
        if !random(&mut seed) {
            return None;
        }
        Some(Auth {
            store,
            audit,
            sessions: Sessions::new(idle, total),
            guard: Guard::new(),
            dummy: Hash::new(&hex(&seed), iterations)?,
            iterations,
        })
    }

    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }

    /// Whether the client may try to log in at `now`.
    pub fn allow_client(&self, ip: IpAddr, now: Instant) -> bool {
        self.guard.allow_client(ip, now)
    }

    /// Logs in the user `name` with `password`.
    pub fn login(&self, name: &str, password: &Secret, cx: &Cx<'_>, now: Instant) -> Login {
        let user = if valid_name(name) {
            match self.store.user(name) {
                Ok(user) => user,
                Err(_) => return Login::Unavailable,
            }
        } else {
            None
        };
        // One hash is computed in every case.
        let stored = user.as_ref().map_or(&self.dummy, |user| &user.password);
        let verified = stored.verify(bounded(password));
        let reason = match &user {
            None => Some("unknown user"),
            Some(user) if self.guard.locked(&user.name, now) => Some("locked"),
            Some(user) if user.disabled => Some("disabled"),
            Some(_) if !verified => Some("wrong password"),
            Some(_) => None,
        };
        match (user, reason) {
            (Some(user), None) => self.admit(&user, cx, now),
            (user, reason) => {
                self.refuse(user.as_ref(), reason.unwrap_or("wrong password"), cx, now)
            }
        }
    }

    fn write(&self, event: &Event<'_>) -> Result<(), AdminError> {
        self.audit.write(event)
    }

    /// A login that failed: counted against the user if there is one, and written.
    fn refuse(
        &self,
        user: Option<&User>,
        reason: &'static str,
        cx: &Cx<'_>,
        now: Instant,
    ) -> Login {
        let locking = user.is_some_and(|user| self.guard.failed(&user.name, now));
        // The name is written only when it is the name of a user, so that what a client sends cannot fill the log
        // and a password typed in the field of the name does not reach it.
        let target = user.map(|user| user.name.as_str());
        let mut event = Event::new(cx.id, cx.client, "login", Outcome::Denied).reason(reason);
        let mut lock =
            Event::new(cx.id, cx.client, "lock", Outcome::Ok).reason("too many failures");
        if let Some(target) = target {
            event = event.target(target);
            lock = lock.target(target);
        }
        let written = self.write(&event);
        if locking {
            let _ = self.write(&lock);
        }
        if written.is_ok() {
            Login::Refused
        } else {
            Login::Unavailable
        }
    }

    /// A login that passed: the audit log first, then the session.
    fn admit(&self, user: &User, cx: &Cx<'_>, now: Instant) -> Login {
        self.guard.succeeded(&user.name);
        let event = Event::new(cx.id, cx.client, "login", Outcome::Ok)
            .actor(&user.name)
            .target(&user.name);
        if self.write(&event).is_err() {
            return Login::Unavailable;
        }
        match self.sessions.open(&user.name, user.changed, now) {
            Some(opened) => {
                if let Some(closed) = &opened.closed {
                    // The oldest session of the user was closed for this one; a line that cannot be written changes
                    // nothing.
                    let _ = self.write(
                        &Event::new(cx.id, cx.client, "logout", Outcome::Ok)
                            .actor(&user.name)
                            .session(closed)
                            .target(&user.name)
                            .reason("too many sessions"),
                    );
                }
                Login::Opened(opened, user.role)
            }
            None => {
                let failed = Event::new(cx.id, cx.client, "login", Outcome::Failed)
                    .actor(&user.name)
                    .target(&user.name)
                    .reason("no session");
                let _ = self.write(&failed);
                Login::Unavailable
            }
        }
    }

    /// The user of the session that the cookie names, with the role the store gives now.
    pub fn session(&self, cookie: &str, now: Instant) -> Authed {
        let Some(found) = self.sessions.find(cookie, now) else {
            return Authed::Unauthorized;
        };
        match self.store.user(&found.name) {
            Ok(Some(user)) if !user.disabled && user.changed == found.changed => Authed::Who(Who {
                name: user.name,
                role: user.role,
                cookie: cookie.to_owned(),
                csrf: found.csrf,
                handle: found.handle,
                changed: found.changed,
                idle_left: found.idle_left,
                total_left: found.total_left,
            }),
            Ok(_) => {
                self.sessions.close(cookie);
                Authed::Unauthorized
            }
            Err(_) => Authed::Unavailable,
        }
    }

    /// Writes that a request of `who` was refused, for `reason`. A line that cannot be written changes nothing: the
    /// request is refused in any case.
    pub fn deny(&self, who: &Who, cx: &Cx<'_>, action: &'static str, reason: &'static str) {
        let _ = self.write(
            &Event::new(cx.id, cx.client, action, Outcome::Denied)
                .actor(&who.name)
                .session(&who.handle)
                .reason(reason),
        );
    }

    /// Ends the session of `who`, also when the audit log cannot take the line: closing takes rights away. The audit
    /// log has told the logger then.
    pub fn logout(&self, who: &Who, cx: &Cx<'_>) {
        self.sessions.close(&who.cookie);
        let _ = self.write(
            &Event::new(cx.id, cx.client, "logout", Outcome::Ok)
                .actor(&who.name)
                .session(&who.handle)
                .target(&who.name),
        );
    }

    /// Changes the password of `who` from `current` to `new`.
    pub fn change_password(
        &self,
        who: &Who,
        current: &Secret,
        new: &Secret,
        cx: &Cx<'_>,
        now: Instant,
    ) -> Changed {
        if !valid_password(new.as_str()) {
            return Changed::Invalid;
        }
        let user = match self.store.user(&who.name) {
            Ok(Some(user)) if !user.disabled && user.changed == who.changed => user,
            Ok(_) => return Changed::Gone,
            Err(_) => return Changed::Unavailable,
        };
        let event = |outcome| {
            Event::new(cx.id, cx.client, "password", outcome)
                .actor(&who.name)
                .session(&who.handle)
                .target(&who.name)
        };
        let locked = self.guard.locked(&who.name, now);
        if !user.password.verify(bounded(current)) || locked {
            let locking = self.guard.failed(&who.name, now);
            let reason = if locked { "locked" } else { "wrong password" };
            let written = self.write(&event(Outcome::Denied).reason(reason));
            if locking {
                let lock = Event::new(cx.id, cx.client, "lock", Outcome::Ok)
                    .target(&who.name)
                    .reason("too many failures");
                let _ = self.write(&lock);
            }
            return if written.is_ok() {
                Changed::Wrong
            } else {
                Changed::Unavailable
            };
        }
        self.guard.succeeded(&who.name);
        let Some(hash) = Hash::new(new.as_str(), self.iterations) else {
            return Changed::Unavailable;
        };
        let next = User {
            password: hash,
            changed: now_ms().max(user.changed.saturating_add(1)),
            ..user.clone()
        };
        if self.write(&event(Outcome::Ok)).is_err() {
            return Changed::Unavailable;
        }
        if let Err(e) = self.store.replace(user.changed, &next) {
            let conflict = e == CONFLICT;
            let reason = if conflict { "conflict" } else { "store" };
            let _ = self.write(&event(Outcome::Failed).reason(reason));
            return if conflict {
                Changed::Conflict
            } else {
                Changed::Unavailable
            };
        }
        self.sessions.close_user(&who.name);
        Changed::Done(self.sessions.open(&who.name, next.changed, now))
    }
}

#[cfg(test)]
mod tests;
