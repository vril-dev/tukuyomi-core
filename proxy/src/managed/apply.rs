//! The order in which the admin process puts a managed version in force in a running proxy (`apply`): the version is
//! in the store already, the proxy reads its configuration again with it (a reload order of its control socket, see
//! `run::control`), and only once the proxy has replaced its configuration with the version does the store choose it.
//! So `current` never names a version that the proxy refused, and a start, `config check` and SIGHUP never take one
//! that a reading has not passed. The command `managed activate` does not go this way: it chooses after its own reading
//! and asks no proxy.
//!
//! The steps, with the lock of the store held from the first to the seventh, so that no command changes the store in
//! between (`managed import` and `managed activate` are refused meanwhile, and wait for nothing; `acme renew` takes no
//! lock). The lock is a lock of the file, so it goes with a process that ends at any step.
//! 1. The lock: held by another is `busy` (`store in use`), and one that cannot be taken is `store`.
//! 2. `current`: none, or one that cannot be read, is `store`; another version than `from`, the one the caller saw,
//!    is `current changed`.
//! 3. `to` is a version of the store, else `no version`.
//! 4. The state of the proxy: one that cannot be reached is `unreachable`, one without a place for the question is
//!    `busy` (`proxy busy`), one whose configuration has no `managed` is `unmanaged`, and one that reads its
//!    configuration again just now is `busy` (`reload under way`), and is not ordered anything: its reading would not
//!    be this order's. The SHA-256 of its main file, its count of the readings that replaced its configuration, and
//!    the time the lookup of its names may take (that of the main file the admin process read, for a proxy that does
//!    not say) are kept.
//! 5. `before`, once, with the state of step 4 (so that the SHA-256 of the main file before the order can be written
//!    down before anything is changed): what it refuses is the end, and nothing is changed.
//! 6. The reload order for `to`, whose answer is waited for as long as that lookup may take and 7 s (the 5 s the proxy
//!    waits besides the lookup, and 2 s more). `replaced` with `to` goes on to 7. `refused` ends there with the reason
//!    and the sentence of the proxy; a refusal of a certificate (`tls`) is asked again once after 1 s, for a
//!    certificate that `acme renew` was replacing in the moment of the reading is refused for that moment only. `busy`
//!    that is not `reload under way` ends as `busy`, and `error` as `error` (a proxy that does not know the order).
//!    Everything else, `busy` with `reload under way`, no answer in time, a connection that closed without one, and a
//!    line that is not the proxy's, leaves the end of the reading unknown: the proxy is looked at every 250 ms, for as
//!    long as the answer was waited for, until it does not read its configuration again (a look without a place is no
//!    end; a proxy that cannot be reached any more is `unconfirmed`, and so is one that is still reading, or still has
//!    no place for the question, at the end of the time). Then the proxy took `to` only if it has `to` in force and its
//!    count of the readings that replaced its configuration has grown since step 4; else the order is `failed`. Both
//!    are looked at: a proxy that has `to` in force already (an earlier order put it there, and the store did not
//!    follow) and refuses it again shows `to` all the same. Nobody else puts `to` in force meanwhile: SIGHUP reads the
//!    version that `current` names, which is `from`.
//! 7. The store chooses `to` if `current` still names `from` (`Store::choose_if_current`, under the lock of step 1).
//!    Otherwise the proxy serves `to` and the store does not choose it: `not recorded`, with `current changed` (the
//!    store was changed by hand) or `store` (`current` cannot be written).
//!
//! A proxy that serves `to` while the store chooses `from` (the admin process ended between 6 and 7, `not recorded`,
//! or an `unconfirmed` order whose reading replaced the configuration after all) starts with `from` again and goes
//! back to it at SIGHUP; the same order again puts both at `to`. Nothing here mends that by itself: which of the two
//! is right depends on why the order did not end.
//!
//! The longest time of an order is three times the lookup time and 7 s (the answer, the answer to the second ask of a
//! refused certificate, the looks), 1 s, and the questions about the state of the proxy (2 s each at most).

use std::thread::sleep;
use std::time::{Duration, Instant};

use super::store::{IN_USE, ManagedError, NOT_CURRENT, Store};

/// What the answer to a reload order is waited for besides the time the lookup of the names may take, and how long
/// the proxy is looked at when it did not answer: the 5 s the proxy waits besides the lookup and 2 s more.
const EXTRA: Duration = Duration::from_secs(7);
/// The time before a refusal of a certificate is asked again.
const AGAIN: Duration = Duration::from_secs(1);
/// The time between two looks at the proxy.
const POLL: Duration = Duration::from_millis(250);

/// The state of the proxy that the order looks at. A proxy of an older version does not send all of it (`None`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct State {
    /// The SHA-256 of the main file in force.
    pub config: Option<[u8; 32]>,
    /// The managed version in force; `None` also for a configuration without `managed`.
    pub managed: Option<[u8; 32]>,
    /// A reading of the configuration again is under way.
    pub reloading: Option<bool>,
    /// The time the lookup of the names of the configuration in force may take.
    pub resolve_timeout: Option<Duration>,
    /// The readings of the configuration again that replaced it.
    pub replaced: Option<u64>,
}

/// What a question about the state of the proxy found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Look {
    State(State),
    /// The proxy took the connection and closed it without an answer: it has no place for it just now.
    Busy,
    Unreachable,
}

/// How the proxy answered a reload order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answered {
    /// The configuration was replaced: the SHA-256 of the main file and the managed version in force now.
    Replaced {
        config: [u8; 32],
        managed: Option<[u8; 32]>,
    },
    /// Nothing was replaced: the part that refused and the sentence of the proxy.
    Refused {
        reason: &'static str,
        detail: String,
    },
    Busy(&'static str),
    Error(&'static str),
    /// No answer of the proxy: none in time, a connection that closed without one, or a line that is not the proxy's.
    Nothing,
}

/// The proxy, as the order asks it by its control socket. A trait, so that a test can put a proxy of its own in its
/// place; the admin process implements it for its client of the socket.
pub trait Proxy {
    /// The state of the proxy.
    fn status(&self) -> Look;
    /// Orders the proxy to read its configuration again with the managed version `to`, and waits at most `wait` for
    /// the answer.
    fn reload(&self, to: [u8; 32], wait: Duration) -> Answered;
}

/// Why a version that the proxy serves was not chosen by the store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unrecorded {
    /// `current` does not name `from` any more.
    CurrentChanged,
    /// `current` cannot be written.
    Store(ManagedError),
}

/// How an order ended, and what it leaves (see the module documentation). `before` and `after` are the SHA-256 of the
/// main file in force before the order and after it, which differ when the main file was changed and not read again
/// since; `None` from a proxy that did not say.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome<E> {
    /// The proxy serves `to` and the store chooses it.
    Applied {
        before: Option<[u8; 32]>,
        after: Option<[u8; 32]>,
    },
    /// The proxy refused `to`: it serves what it served, and the store chooses `from`.
    Refused {
        reason: &'static str,
        detail: String,
    },
    /// Nothing was changed: the store or the proxy is busy, for the reason of the word.
    Busy(&'static str),
    CurrentChanged,
    NoVersion,
    Unmanaged,
    /// Nothing was changed: the store refused, for its reason.
    Store(ManagedError),
    /// Nothing was changed: `before` refused.
    Before(E),
    /// Nothing was changed: the proxy answered the order with an error.
    Error(&'static str),
    Unreachable,
    /// The proxy did not take `to`; the store chooses `from`.
    Failed,
    /// It is not known whether the proxy took `to`; the store chooses `from`.
    Unconfirmed,
    /// The proxy serves `to`, and the store does not choose it.
    NotRecorded {
        why: Unrecorded,
        before: Option<[u8; 32]>,
        after: Option<[u8; 32]>,
    },
}

/// Puts the managed version `to` in force in `proxy` and has `store` choose it, if the store chooses `from` now (see
/// the module documentation for the steps). `resolve_timeout` is the time the lookup of the names of the main file that
/// the admin process read may take, for a proxy that does not say its own. `before` is called once, with the state of
/// the proxy, when the proxy can take the order and before anything is changed. The order takes the lock of the store
/// itself, so a caller that holds it gets `busy` (`store in use`), and lets it go first. `not recorded` with `store` is
/// also the end when `current.new` was renamed onto `current` and only the sync of the directory after it failed: then
/// `current` may name `to` already.
pub fn apply<E>(
    store: &Store,
    proxy: &dyn Proxy,
    from: [u8; 32],
    to: [u8; 32],
    resolve_timeout: Duration,
    before: impl FnOnce(&State) -> Result<(), E>,
) -> Outcome<E> {
    let _lock = match store.lock() {
        Ok(lock) => lock,
        Err(e) if e == IN_USE => return Outcome::Busy("store in use"),
        Err(e) => return Outcome::Store(e),
    };
    match store.current() {
        Ok(Some(current)) if current == from => {}
        Ok(Some(_)) => return Outcome::CurrentChanged,
        Ok(None) => return Outcome::Store(ManagedError("no managed version is chosen")),
        Err(e) => return Outcome::Store(e),
    }
    match store.versions() {
        Ok(listed) if listed.iter().any(|version| version.name == to) => {}
        Ok(_) => return Outcome::NoVersion,
        Err(e) => return Outcome::Store(e),
    }
    let seen = match proxy.status() {
        Look::State(state) => state,
        Look::Busy => return Outcome::Busy("proxy busy"),
        Look::Unreachable => return Outcome::Unreachable,
    };
    if seen.managed.is_none() {
        return Outcome::Unmanaged;
    }
    if seen.reloading == Some(true) {
        return Outcome::Busy("reload under way");
    }
    let wait = seen
        .resolve_timeout
        .unwrap_or(resolve_timeout)
        .saturating_add(EXTRA);
    if let Err(refusal) = before(&seen) {
        return Outcome::Before(refusal);
    }
    let mut answered = proxy.reload(to, wait);
    if matches!(&answered, Answered::Refused { reason, .. } if *reason == "tls") {
        sleep(AGAIN);
        answered = proxy.reload(to, wait);
    }
    let after = match answered {
        Answered::Replaced { config, managed } if managed == Some(to) => Some(config),
        Answered::Refused { reason, detail } => return Outcome::Refused { reason, detail },
        Answered::Busy(reason) if reason != "reload under way" => return Outcome::Busy(reason),
        Answered::Error(reason) => return Outcome::Error(reason),
        Answered::Replaced { .. } | Answered::Busy(_) | Answered::Nothing => {
            match look(proxy, to, seen.replaced, wait) {
                Looked::Took(config) => config,
                Looked::Not => return Outcome::Failed,
                Looked::Lost => return Outcome::Unconfirmed,
            }
        }
    };
    match store.choose_if_current(from, to) {
        Ok(()) => Outcome::Applied {
            before: seen.config,
            after,
        },
        Err(e) => Outcome::NotRecorded {
            why: if e == NOT_CURRENT {
                Unrecorded::CurrentChanged
            } else {
                Unrecorded::Store(e)
            },
            before: seen.config,
            after,
        },
    }
}

/// What the looks at the proxy after an order without an answer found.
enum Looked {
    /// The proxy took `to`; the SHA-256 of its main file now.
    Took(Option<[u8; 32]>),
    /// It did not.
    Not,
    /// It went away, or it still reads its configuration again at the end of the time.
    Lost,
}

/// Looks at the proxy every `POLL` for at most `wait`, until it does not read its configuration again: then it took
/// `to` if `to` is in force and its count of the readings that replaced its configuration has grown past `replaced`.
/// One such look is enough: the order and the questions are served in the order they come, so once the order has come
/// to the proxy no look finds the state before its reading began.
fn look(proxy: &dyn Proxy, to: [u8; 32], replaced: Option<u64>, wait: Duration) -> Looked {
    let now = Instant::now();
    let by = now.checked_add(wait).unwrap_or(now);
    loop {
        sleep(POLL);
        match proxy.status() {
            Look::Unreachable => return Looked::Lost,
            Look::Busy => {}
            Look::State(state) if state.reloading == Some(true) => {}
            Look::State(state) => {
                let grew = matches!(
                    (state.replaced, replaced),
                    (Some(after), Some(earlier)) if after > earlier
                );
                return if state.managed == Some(to) && grew {
                    Looked::Took(state.config)
                } else {
                    Looked::Not
                };
            }
        }
        if Instant::now() >= by {
            return Looked::Lost;
        }
    }
}

#[cfg(test)]
mod tests;
