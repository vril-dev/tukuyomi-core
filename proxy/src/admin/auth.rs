//! Who a request is from: the login with its limits, the session or the API token of a request, and the change of a
//! password.
//!
//! A login checks the name and the password against the stored user, and always computes one hash, whatever the
//! name: an unknown name, a name that is not a name, a user that is disabled and a user that is locked are all checked
//! against a hash (the stored one or a dummy one), so that the time does not tell them from a wrong password. They
//! all end the same way, as `Login::Refused`, and the server gives all of them the same status and body. The reason
//! is written to the audit log only, and the name that was sent is written with it only when it is the name of a
//! user: what else is sent in the field of the name (a password, for one) never reaches the log.
//!
//! A user with a second factor (see `totp`) is not logged in by the password: the password opens a pending session,
//! which only the check of the second factor can turn into a session that counts. The failures of the user are not
//! cleared by the password then, but by the code, so a person who knows the password cannot start the count again at
//! every login. A user without one, under `admin.mfa` `required`, gets a session that counts, and is told
//! (`Next::Setup`) to set one up; the server lets such a session do nothing else.
//!
//! Two limits protect the login. For each user, 5 failures in a row lock it for 15 minutes; a try while it is locked
//! is a failure too and is refused whatever its password, and it starts the 15 minutes again. A success clears the
//! count. For each client address, at most 30 tries a minute are taken (`allow_client`); the others are refused
//! before they cost a hash and before they count against any user. The check of the second factor counts against
//! the same limit of the user, and so does the check of the password in the routes that ask for it (the change of
//! the password, the setup and the removal of the second factor, the making of a token: `confirm_password`), which
//! also take a try of the client first. These routes refuse a user who is locked, with the answer of a wrong
//! password, before they compute a hash, and look at the lock again after it: tries of a burst that were counted
//! while the hash was computed may have locked the user, and then even the right password is refused. A token that
//! is not right counts against the limit of the client (`tokens`). A table of clients is kept for at most
//! `MAX_CLIENTS` addresses, and when it is full of addresses that have tried in the last minute, no other address
//! is taken.
//!
//! The failures of a user are kept with the `changed` of the user when they were counted. A user whose stored
//! `changed` is later was changed since, by a password set again with `admin reset` in another process, for one:
//! its failures and its lock no longer count, and the next failure starts the count again.
//!
//! A session is made by a login that passed, and is looked at again with the stored user at each request: it
//! counts only while the user exists, is not disabled and has the `changed` that the session saw. A change of the
//! password makes the new `changed`, closes every session of the user, and opens one for the request that changed it.
//! `Who` is the user of a request, from a session or from a token, with what the server needs to decide which routes
//! the request may use: the role (the token's, for a token), and whether the session is pending, the password must be
//! changed, or the second factor must be set up.
//!
//! The audit log is written before a session is made and before a password is changed; when it cannot be written the
//! answer is `Unavailable` and nothing was changed. A session is closed whether or not the audit log takes the line,
//! because closing takes rights away: the logout closes the session first, and the audit log tells the logger when
//! it cannot write the line. A user keeps at most 16 sessions (see `session`): the login that would make one more
//! closes the oldest and writes it as a `logout` with the reason `too many sessions`.
//!
//! The changes of a user come one at a time in this process (`Auth::lock`): the user is read again under it, so that
//! two requests cannot both pass a check that only one of them may. A hash of 600000 rounds is never computed under
//! it: a route that checks a password reads the user, checks the password, and then takes the lock and reads the
//! user again, which fails if the user was changed meanwhile (`changed` is not the one the session saw).

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use super::audit::{AuditLog, Event, Outcome};
use super::password::{Hash, PASSWORD_MAX, Secret, hex, random, valid_name, valid_password};
use super::session::{Opened, Sessions};
use super::store::{AdminError, AdminStore, CONFLICT};
use super::users::{Role, User, now_ms};

pub mod tokens;
pub mod totp;

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

/// The user of a request, as the session or the token and the stored user say.
#[derive(Clone)]
pub struct Who {
    pub name: String,
    /// The role the request has: the user's, or the token's for a request with a token.
    pub role: Role,
    /// How a request with a token got in, as the audit log shows it (`token:<id>`); none for a session.
    pub auth: Option<String>,
    /// The cookie of the session; empty for a token.
    pub cookie: String,
    pub csrf: String,
    pub handle: String,
    pub changed: u64,
    pub idle_left: Duration,
    pub total_left: Duration,
    /// The session waits for the second factor.
    pub pending: bool,
    /// The password was set by someone else and must be changed.
    pub must_change: bool,
    /// `admin.mfa` is `required` and the user has no second factor.
    pub setup_needed: bool,
    /// The user has a second factor.
    pub mfa: bool,
    /// The recovery codes the user has left.
    pub recovery_left: usize,
}

impl Who {
    /// Whether the request came with a token and not with a session.
    pub fn token(&self) -> bool {
        self.auth.is_some()
    }

    /// Whether nothing limits the routes that the role allows.
    pub fn open(&self) -> bool {
        !self.pending && !self.must_change && !self.setup_needed
    }

    /// An event of the request with the user, and the session or the token it came with.
    pub fn event<'a>(&'a self, cx: &Cx<'a>, action: &'static str, outcome: Outcome) -> Event<'a> {
        let event = Event::new(cx.id, cx.client, action, outcome).actor(&self.name);
        match &self.auth {
            Some(auth) => event.auth(auth),
            None => event.session(&self.handle),
        }
    }
}

/// What a request brings to show who it is from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Credential {
    Missing,
    /// The session cookie; none: the field is there more than once.
    Cookie(Option<String>),
    /// `Authorization: Bearer <token>`; none: an `Authorization` field that is not one.
    Bearer(Option<String>),
    /// Both, which no request may.
    Both,
}

/// How the check of a request ended.
pub enum Authed {
    Who(Who),
    /// No session or token, or one that is over, or one whose user is gone, disabled or changed.
    Unauthorized,
    /// The client has made too many wrong tries with tokens.
    Limited,
    /// The user could not be read.
    Unavailable,
}

/// What a person who logged in must do next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Next {
    /// Nothing: the session counts.
    Off,
    /// Give the second factor.
    Verify,
    /// Set up the second factor.
    Setup,
}

impl Next {
    pub fn word(self) -> &'static str {
        match self {
            Next::Off => "off",
            Next::Verify => "verify",
            Next::Setup => "setup",
        }
    }
}

/// A login that opened a session.
pub struct Entered {
    pub opened: Opened,
    pub role: Role,
    pub next: Next,
    pub must_change: bool,
}

/// How a login ended.
pub enum Login {
    Opened(Entered),
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

/// Why an operation of the account was refused; the server turns each into a status and fixed words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The session or the user is not what it was.
    Gone,
    /// The store or the audit log cannot be used.
    Unavailable,
    /// The password given is wrong, or the user is locked.
    Password,
    /// The code given is wrong, or the user is locked.
    Code,
    /// Not allowed.
    Denied(&'static str),
    /// Not possible in the state the user or the store is in.
    Conflict(&'static str),
    /// The input is not right.
    Invalid(&'static str),
    NotFound,
}

#[derive(Default)]
struct Failures {
    count: u32,
    locked_until: Option<Instant>,
    /// The `changed` of the user when the failures were counted.
    changed: u64,
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

    /// Whether the client at `ip` has used all its tries at `now`. Nothing is counted.
    pub fn exhausted(&self, ip: IpAddr, now: Instant) -> bool {
        self.clients
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&ip)
            .is_some_and(|tries| {
                tries
                    .iter()
                    .filter(|&&at| now.saturating_duration_since(at) < WINDOW)
                    .count()
                    >= TRIES
            })
    }

    /// Whether the user `name`, whose stored `changed` is the one given, is locked at `now`. Failures that were counted
    /// for an earlier `changed` do not count.
    pub fn locked(&self, name: &str, changed: u64, now: Instant) -> bool {
        self.users
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(name)
            .filter(|failures| failures.changed >= changed)
            .and_then(|failures| failures.locked_until)
            .is_some_and(|until| now < until)
    }

    /// Counts a failure of the user `name`, whose stored `changed` is the one given, at `now`. True: this failure
    /// locked the user, which was not locked before.
    pub fn failed(&self, name: &str, changed: u64, now: Instant) -> bool {
        let mut users = self.users.lock().unwrap_or_else(PoisonError::into_inner);
        let failures = users.entry(name.to_owned()).or_default();
        let changed_since = failures.changed < changed;
        let was_locked = !changed_since && failures.locked_until.is_some_and(|until| now < until);
        // A lock that has run out starts the count again, and so does a user who was changed since the failures
        // were counted.
        if changed_since || (!was_locked && failures.locked_until.is_some()) {
            *failures = Failures::default();
        }
        failures.changed = failures.changed.max(changed);
        failures.count = failures.count.saturating_add(1);
        if failures.count >= LOCK_AFTER {
            failures.locked_until = Some(now + LOCK_FOR);
            return !was_locked;
        }
        false
    }

    /// The user `name` gave the right password, and the second factor if it has one.
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

/// The login, the sessions, the tokens and the change of the password.
pub struct Auth {
    pub(crate) store: Arc<dyn AdminStore>,
    pub(crate) audit: Arc<AuditLog>,
    pub(crate) sessions: Sessions,
    guard: Guard,
    /// The hash that a name no user has is checked against.
    dummy: Hash,
    /// The iterations of a new hash.
    pub(crate) iterations: u32,
    /// `admin.mfa` is `required`.
    mfa_required: bool,
    /// The changes of a user come one at a time.
    writing: Mutex<()>,
}

impl Auth {
    /// None: no random number for the dummy hash.
    pub fn new(
        store: Arc<dyn AdminStore>,
        audit: Arc<AuditLog>,
        idle: Duration,
        total: Duration,
        iterations: u32,
        mfa_required: bool,
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
            mfa_required,
            writing: Mutex::new(()),
        })
    }

    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }

    /// Takes the right to change a user; the guard gives it back when it is dropped.
    pub(crate) fn lock(&self) -> MutexGuard<'_, ()> {
        self.writing.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether the request with this credential is of a user who is not limited by a state and whose role is at
    /// least `least`, as the store gives it now; a session then counts as used at `now`. The user is read from the
    /// store, so this is not called on the thread of the runtime.
    pub fn allows(
        &self,
        credential: &Credential,
        least: Role,
        client: IpAddr,
        now: Instant,
    ) -> bool {
        matches!(self.authenticate(credential, client, now), Authed::Who(who) if who.open() && who.role >= least)
    }

    /// Whether the client may try to log in at `now`.
    pub fn allow_client(&self, ip: IpAddr, now: Instant) -> bool {
        self.guard.allow_client(ip, now)
    }

    /// The user of a request with this credential. The user is read from the store.
    pub fn authenticate(&self, credential: &Credential, client: IpAddr, now: Instant) -> Authed {
        match credential {
            Credential::Cookie(Some(cookie)) => self.session(cookie, now),
            Credential::Bearer(Some(text)) => self.token(text, client, now),
            _ => Authed::Unauthorized,
        }
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
            Some(user) if self.guard.locked(&user.name, user.changed, now) => Some("locked"),
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

    /// Writes that the user `name` is locked now. A line that cannot be written changes nothing.
    pub(crate) fn locked_line(&self, cx: &Cx<'_>, name: &str) {
        let _ = self.write(
            &Event::new(cx.id, cx.client, "lock", Outcome::Ok)
                .target(name)
                .reason("too many failures"),
        );
    }

    /// A login that failed: counted against the user if there is one, and written.
    fn refuse(
        &self,
        user: Option<&User>,
        reason: &'static str,
        cx: &Cx<'_>,
        now: Instant,
    ) -> Login {
        let locking = user.is_some_and(|user| self.guard.failed(&user.name, user.changed, now));
        // The name is written only when it is the name of a user, so that what a client sends cannot fill the log
        // and a password typed in the field of the name does not reach it.
        let mut event = Event::new(cx.id, cx.client, "login", Outcome::Denied).reason(reason);
        if let Some(user) = user {
            event = event.target(&user.name);
        }
        let written = self.write(&event);
        if locking && let Some(user) = user {
            self.locked_line(cx, &user.name);
        }
        if written.is_ok() {
            Login::Refused
        } else {
            Login::Unavailable
        }
    }

    /// A login that passed: the audit log first, then the session.
    fn admit(&self, user: &User, cx: &Cx<'_>, now: Instant) -> Login {
        let second = user.mfa.is_some();
        // With a second factor, the code clears the failures and the password does not: else a person who knows the
        // password could start the count again at every login and try codes without end.
        if !second {
            self.guard.succeeded(&user.name);
        }
        let mut event = Event::new(cx.id, cx.client, "login", Outcome::Ok)
            .actor(&user.name)
            .target(&user.name);
        if second {
            event = event.reason("second factor pending");
        }
        if self.write(&event).is_err() {
            return Login::Unavailable;
        }
        match self.start(user, second, cx, now) {
            Some(opened) => {
                let next = if second {
                    Next::Verify
                } else if self.mfa_required {
                    Next::Setup
                } else {
                    Next::Off
                };
                Login::Opened(Entered {
                    opened,
                    role: user.role,
                    next,
                    must_change: user.must_change,
                })
            }
            None => Login::Unavailable,
        }
    }

    /// A session of `user`, pending or not. The oldest session of the user may be closed to make room, and is
    /// written; a session that cannot be made is written too.
    pub(crate) fn start(
        &self,
        user: &User,
        pending: bool,
        cx: &Cx<'_>,
        now: Instant,
    ) -> Option<Opened> {
        let opened = if pending {
            self.sessions.open_pending(&user.name, user.changed, now)
        } else {
            self.sessions.open(&user.name, user.changed, now)
        };
        let Some(opened) = opened else {
            let failed = Event::new(cx.id, cx.client, "login", Outcome::Failed)
                .actor(&user.name)
                .target(&user.name)
                .reason("no session");
            let _ = self.write(&failed);
            return None;
        };
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
        Some(opened)
    }

    /// The user as a request sees it, with the `role` the request has. The fields of a session and of a token are
    /// left for the caller.
    pub(crate) fn who(&self, user: &User, role: Role) -> Who {
        Who {
            name: user.name.clone(),
            role,
            auth: None,
            cookie: String::new(),
            csrf: String::new(),
            handle: String::new(),
            changed: user.changed,
            idle_left: Duration::ZERO,
            total_left: Duration::ZERO,
            pending: false,
            must_change: user.must_change,
            setup_needed: self.mfa_required && user.mfa.is_none(),
            mfa: user.mfa.is_some(),
            recovery_left: user.recovery.len(),
        }
    }

    /// The user of the session that the cookie names, with the role the store gives now.
    pub fn session(&self, cookie: &str, now: Instant) -> Authed {
        let Some(found) = self.sessions.find(cookie, now) else {
            return Authed::Unauthorized;
        };
        match self.store.user(&found.name) {
            Ok(Some(user)) if !user.disabled && user.changed == found.changed => {
                let mut who = self.who(&user, user.role);
                who.cookie = cookie.to_owned();
                who.csrf = found.csrf;
                who.handle = found.handle;
                who.pending = found.pending;
                who.idle_left = found.idle_left;
                who.total_left = found.total_left;
                Authed::Who(who)
            }
            Ok(_) => {
                self.sessions.close(cookie);
                Authed::Unauthorized
            }
            Err(_) => Authed::Unavailable,
        }
    }

    /// The user of `who` as the store has it now, if it is the same as when the request was checked: not disabled,
    /// not changed. Called under `lock`.
    pub(crate) fn current(&self, who: &Who) -> Result<User, Refusal> {
        match self.store.user(&who.name) {
            Ok(Some(user)) if !user.disabled && user.changed == who.changed => Ok(user),
            Ok(_) => Err(Refusal::Gone),
            Err(_) => Err(Refusal::Unavailable),
        }
    }

    /// Stores `next` in place of the user that was read with `seen`. A failure is written for `action` and
    /// `target`, and it is a conflict when the user was changed meanwhile.
    pub(crate) fn replace(
        &self,
        who: &Who,
        action: &'static str,
        target: &str,
        cx: &Cx<'_>,
        seen: u64,
        next: &User,
    ) -> Result<(), Refusal> {
        let Err(e) = self.store.replace(seen, next) else {
            return Ok(());
        };
        let conflict = e == CONFLICT;
        let reason = if conflict { "conflict" } else { "store" };
        let _ = self.write(
            &who.event(cx, action, Outcome::Failed)
                .target(target)
                .reason(reason),
        );
        Err(if conflict {
            Refusal::Conflict("the user was changed since it was read")
        } else {
            Refusal::Unavailable
        })
    }

    /// Checks `password` against the hash of `user`, for the `action` of a request of `who`. A wrong one, and any try
    /// while the user is locked, counts as a failure of the user and is written; a failure that locks is written. A
    /// user who is locked is refused before the hash is computed, and the lock is looked at again after it (see
    /// `password_checked`). Not called under `lock`.
    pub(crate) fn confirm_password(
        &self,
        who: &Who,
        user: &User,
        password: &Secret,
        action: &'static str,
        cx: &Cx<'_>,
        now: Instant,
    ) -> Result<(), Refusal> {
        let verified = !self.guard.locked(&who.name, user.changed, now)
            && user.password.verify(bounded(password));
        self.password_checked(who, user, verified, action, cx, now)
    }

    /// The end of `confirm_password`, once the hash is computed; `verified` is whether the password was right and
    /// the user was not locked before. The lock is looked at again: the tries of a burst that were counted while the
    /// hash was computed may have locked the user, and then even the right password is refused, so that a burst
    /// cannot pass the lock. A refusal is counted and written as `confirm_password` says.
    fn password_checked(
        &self,
        who: &Who,
        user: &User,
        verified: bool,
        action: &'static str,
        cx: &Cx<'_>,
        now: Instant,
    ) -> Result<(), Refusal> {
        let locked = self.guard.locked(&who.name, user.changed, now);
        if verified && !locked {
            return Ok(());
        }
        let locking = self.guard.failed(&who.name, user.changed, now);
        let reason = if locked { "locked" } else { "wrong password" };
        let written = self.write(
            &who.event(cx, action, Outcome::Denied)
                .target(&who.name)
                .reason(reason),
        );
        if locking {
            self.locked_line(cx, &who.name);
        }
        Err(if written.is_ok() {
            Refusal::Password
        } else {
            Refusal::Unavailable
        })
    }

    /// Writes that a request of `who` was refused, for `reason`. A line that cannot be written changes nothing: the
    /// request is refused in any case.
    pub fn deny(&self, who: &Who, cx: &Cx<'_>, action: &'static str, reason: &'static str) {
        let _ = self.write(&who.event(cx, action, Outcome::Denied).reason(reason));
    }

    /// Ends the session of `who`, also when the audit log cannot take the line: closing takes rights away. The audit
    /// log has told the logger then.
    pub fn logout(&self, who: &Who, cx: &Cx<'_>) {
        self.sessions.close(&who.cookie);
        let _ = self.write(&who.event(cx, "logout", Outcome::Ok).target(&who.name));
    }

    /// Changes the password of `who` from `current` to `new`. The password is the user's own from now on: the
    /// request to change it is no longer asked for, the other sessions are closed and the tokens are removed.
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
        // Both hashes are computed before the lock is taken: they take long and nobody else may wait for them.
        let seen = match self.current(who) {
            Ok(user) => user,
            Err(Refusal::Unavailable) => return Changed::Unavailable,
            Err(_) => return Changed::Gone,
        };
        match self.confirm_password(who, &seen, current, "password", cx, now) {
            Ok(()) => {}
            Err(Refusal::Unavailable) => return Changed::Unavailable,
            Err(_) => return Changed::Wrong,
        }
        let Some(hash) = Hash::new(new.as_str(), self.iterations) else {
            return Changed::Unavailable;
        };
        let _writing = self.lock();
        // The user is read again: if it was changed meanwhile, the password that was checked is not its.
        let user = match self.current(who) {
            Ok(user) => user,
            Err(Refusal::Unavailable) => return Changed::Unavailable,
            Err(_) => return Changed::Gone,
        };
        self.guard.succeeded(&who.name);
        let changed = now_ms().max(user.changed.saturating_add(1));
        let next = User {
            password: hash,
            changed,
            tokens_after: changed,
            must_change: false,
            ..user.clone()
        };
        let event = |outcome| who.event(cx, "password", outcome).target(&who.name);
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
        self.drop_tokens(&who.name, None, who, cx);
        Changed::Done(self.sessions.open(&who.name, next.changed, now))
    }
}

#[cfg(test)]
mod tests;
