//! The users: the role, the user, the file a user is kept in, and the first user.
//!
//! A role is `viewer`, `operator` or `owner`, in that order, and a route may be used by a user whose role is not
//! below the least role that the route names. A user has a name (see `password::valid_name`), a role, whether it is
//! disabled, the hash of its password, the time it was made and the time it was last changed (both in milliseconds
//! since the epoch), and, for the second factor, the seed with the last step used and the hashes of the recovery codes
//! that are left (see `auth::totp`), whether the password must be changed at the next login (`must_change`: a user
//! that an owner made, and one whose password an owner set) and the time after which a token counts
//! (`tokens_after`). `changed` goes up with every change of the user, and a session keeps the value it saw (see
//! `session`), so a session does not outlive a change of the password, the role, the state or the second factor of
//! its user. The one change that does not raise it is the use of the second factor at a login (the last step, or a
//! recovery code that is gone): it changes no right, and the other sessions of the user stay. The tokens of a user
//! (see `auth::tokens`) are not in the file of the user, but `tokens_after` is: a token made at that time or before
//! is void, and the time goes up to the time of the change when the password is set, when the user is disabled and
//! when its role is lowered, so that a token that stays in the store by then stays void when the user is enabled or
//! raised again.
//!
//! A user is kept as one JSON object with the keys `name`, `role`, `disabled`, `password` (`iterations`, `salt` and
//! `hash`, the last two as lowercase hexadecimal), `created` and `changed`, and the keys `mfa` (`secret` as 40
//! lowercase hexadecimal digits and `last_step`), `recovery` (up to 10 hashes as 64 lowercase hexadecimal digits),
//! `must_change` and `tokens_after`, which a file written before they were added does not have: they are read as no
//! second factor, no recovery codes, false, and `created`. The seed is kept as it is: a code can only be checked
//! with the seed itself, and the directory is closed to other users. A file with another key, a name other than the
//! one of its file, or a role, salt, hash, seed or recovery hash that is not understood is not read: the keys of a
//! later version are not dropped by an earlier one.
//!
//! The routes with which an owner manages users are in `manage`.
//!
//! `bootstrap` is the command `admin bootstrap <config> <name>`: it reads the password as one line of the standard
//! input (a line feed, or a carriage return and a line feed, ends it; it is not shown anywhere), and makes the first
//! user, an owner. It makes the checks of the host that the proxy makes (`run::host::check`), which refuse a process
//! that runs as root. It refuses when the store has a user already, whoever made it. It writes `created owner <name>`
//! to the standard output; every other line goes to the standard error and starts with `admin bootstrap:`, except
//! the audit line.
//!
//! The creation is audited before it is made, as a change is (see `audit`): the line has the action `create`, the
//! new name as the target, the role `owner` as `after`, no actor and `auth` `bootstrap`. When the line cannot be
//! written, no user is made and the exit code is 1. When the store then refuses, a line with the result `failed`
//! follows. The line goes to the file `audit/audit.log` of the store, which the admin process may have open as well:
//! both open it for append and write a line whole, and the command runs on a store without users, when the admin
//! process has hardly a line to write. The line goes to the standard error as every audit line does.
//!
//! `reset` is the command `admin reset <config> <name>`, for a user who is locked out (the only owner who lost the
//! password and the second factor, for one). It is made like `bootstrap`: the same checks of the host and of the
//! configuration, the password as one line of the standard input, the texts for a person, the exit codes, and the
//! audit line before the change (the action `reset` and `auth` `reset`, the user as the target, no actor); it
//! refuses a user that the store does not have. It sets the new password, takes the second factor and the recovery
//! codes away, makes the user change the password at the next login, moves `tokens_after` to the time of the change
//! and raises `changed`, so that the sessions of the user end. It runs while the admin process runs: the write goes
//! through the lock of the store and is made only if the user is the one that was read. The files of the tokens of
//! the user are removed afterwards; a failure to remove them is told, and the tokens are void in any case.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::Exit;
use super::audit::{AuditLog, Event, Outcome};
use super::auth::totp::{RECOVERY_CODES, SEED_LEN, Seed, Totp};
use super::file_store::AUDIT_DIR;
use super::password::{
    Hash, ITERATIONS, PASSWORD_MAX, Secret, hex, unhex, valid_name, valid_password,
};
use super::store::{self, AdminError, AdminStore};
use crate::config::{self, AdminStoreConfig};
use crate::log::Log;
use crate::run::host;

pub mod manage;

/// What a user may do: a role may use every route that a lower role may use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    Viewer,
    Operator,
    Owner,
}

impl Role {
    pub fn name(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Operator => "operator",
            Role::Owner => "owner",
        }
    }

    pub fn parse(text: &str) -> Option<Role> {
        match text {
            "viewer" => Some(Role::Viewer),
            "operator" => Some(Role::Operator),
            "owner" => Some(Role::Owner),
            _ => None,
        }
    }
}

/// A user of the admin API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct User {
    pub name: String,
    pub role: Role,
    pub disabled: bool,
    pub password: Hash,
    /// When the user was made, in milliseconds since the epoch.
    pub created: u64,
    /// When the user was last changed, in milliseconds since the epoch; it goes up with every change.
    pub changed: u64,
    /// The second factor, if the user has set one up.
    pub mfa: Option<Totp>,
    /// The SHA-256 of the recovery codes that are left.
    pub recovery: Vec<[u8; 32]>,
    /// The password was set by someone else and must be changed at the next login.
    pub must_change: bool,
    /// A token of the user that was made at this time or before is void, in milliseconds since the epoch. It goes
    /// up with the change or the reset of the password, with a disable and with a lowering of the role.
    pub tokens_after: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredPassword {
    iterations: u32,
    salt: String,
    hash: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredMfa {
    secret: String,
    last_step: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    name: String,
    role: String,
    disabled: bool,
    password: StoredPassword,
    created: u64,
    changed: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mfa: Option<StoredMfa>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    recovery: Vec<String>,
    #[serde(default)]
    must_change: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tokens_after: Option<u64>,
}

/// The time now in milliseconds since the epoch.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

impl User {
    /// A user made at `now` (milliseconds since the epoch), not disabled, without a second factor, whose tokens
    /// count from `now` on.
    pub fn new(name: &str, role: Role, password: Hash, now: u64) -> User {
        User {
            name: name.to_owned(),
            role,
            disabled: false,
            password,
            created: now,
            changed: now,
            mfa: None,
            recovery: Vec::new(),
            must_change: false,
            tokens_after: now,
        }
    }

    /// The bytes of the file of the user.
    pub fn encode(&self) -> Result<Vec<u8>, AdminError> {
        serde_json::to_vec(&Stored {
            name: self.name.clone(),
            role: self.role.name().to_owned(),
            disabled: self.disabled,
            password: StoredPassword {
                iterations: self.password.iterations(),
                salt: hex(self.password.salt()),
                hash: hex(self.password.hash()),
            },
            created: self.created,
            changed: self.changed,
            mfa: self.mfa.as_ref().map(|mfa| StoredMfa {
                secret: hex(mfa.seed.as_bytes()),
                last_step: mfa.last_step,
            }),
            recovery: self.recovery.iter().map(|hash| hex(hash)).collect(),
            must_change: self.must_change,
            tokens_after: Some(self.tokens_after),
        })
        .map_err(|_| AdminError("a user cannot be written"))
    }

    /// The user in `bytes`, which must be the file of the user `name`.
    pub fn decode(bytes: &[u8], name: &str) -> Result<User, AdminError> {
        const BROKEN: AdminError = AdminError("a user file is broken");
        let stored: Stored = serde_json::from_slice(bytes).map_err(|_| BROKEN)?;
        if stored.name != name || !valid_name(name) {
            return Err(BROKEN);
        }
        let password = Hash::from_parts(
            stored.password.iterations,
            unhex(&stored.password.salt).ok_or(BROKEN)?,
            unhex(&stored.password.hash).ok_or(BROKEN)?,
        )
        .ok_or(BROKEN)?;
        let mfa = match stored.mfa {
            Some(mfa) => Some(Totp {
                seed: Seed::from_bytes(unhex::<SEED_LEN>(&mfa.secret).ok_or(BROKEN)?),
                last_step: mfa.last_step,
            }),
            None => None,
        };
        if stored.recovery.len() > RECOVERY_CODES {
            return Err(BROKEN);
        }
        let recovery = stored
            .recovery
            .iter()
            .map(|hash| unhex::<32>(hash).ok_or(BROKEN))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(User {
            name: stored.name,
            role: Role::parse(&stored.role).ok_or(BROKEN)?,
            disabled: stored.disabled,
            password,
            created: stored.created,
            changed: stored.changed,
            mfa,
            recovery,
            must_change: stored.must_change,
            tokens_after: stored.tokens_after.unwrap_or(stored.created),
        })
    }
}

/// The password from the first line of `input`: at most `PASSWORD_MAX` bytes before the line feed (and a carriage
/// return), UTF-8, of the length a password has. The line is zeroed wherever it is dropped.
fn read_password(input: &mut dyn Read) -> Result<Secret, &'static str> {
    // The longest line that is read: the password, a carriage return and a line feed.
    let longest = PASSWORD_MAX + 2;
    let mut line = Vec::with_capacity(longest + 1);
    let mut reader = BufReader::new(input.take(u64::try_from(longest + 1).unwrap_or(u64::MAX)));
    if reader.read_until(b'\n', &mut line).is_err() {
        line.zeroize();
        return Err("the password cannot be read");
    }
    if line.last() == Some(&b'\n') {
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
    } else if line.len() > longest {
        line.zeroize();
        return Err("the password line is too long");
    }
    let text = match String::from_utf8(line) {
        Ok(text) => text,
        Err(e) => {
            e.into_bytes().zeroize();
            return Err("the password is not UTF-8");
        }
    };
    let secret = Secret::new(text);
    if !valid_password(secret.as_str()) {
        return Err("the password is not 12 to 128 bytes");
    }
    Ok(secret)
}

/// Makes `name` the first user, an owner, with a hash of `password` after `iterations` rounds. The audit log has the
/// line first, and no user is made when it cannot be written. The store refuses when it has a user.
pub fn create_owner(
    store: &dyn AdminStore,
    audit: &AuditLog,
    name: &str,
    password: &str,
    iterations: u32,
) -> Result<(), AdminError> {
    let hash =
        Hash::new(password, iterations).ok_or(AdminError("the password cannot be hashed"))?;
    let event = |outcome| {
        Event::command("create", outcome)
            .auth("bootstrap")
            .target(name)
            .after(Role::Owner.name())
    };
    audit.write(&event(Outcome::Ok))?;
    if let Err(e) = store.create_first(&User::new(name, Role::Owner, hash, now_ms())) {
        let _ = audit.write(&event(Outcome::Failed).reason("store"));
        return Err(e);
    }
    Ok(())
}

/// The command `admin bootstrap`: `config` is the configuration file, `name` the name of the user and `input` the
/// standard input.
pub fn bootstrap(config: &Path, name: &str, input: &mut dyn Read, log: &Log) -> Exit {
    const NAME: &str = "admin bootstrap";
    if let Err(text) = host::check() {
        log.line(&format!("{NAME}: host check refused: {text}"));
        return Exit::Failed;
    }
    let loaded = match config::load(config) {
        Ok(loaded) => loaded,
        Err(e) => {
            log.line(&format!("{NAME}: configuration refused: {}", e.0));
            return Exit::Usage;
        }
    };
    let Some(admin) = loaded.admin else {
        log.line(&format!(
            "{NAME}: configuration refused: there is no admin object"
        ));
        return Exit::Usage;
    };
    if !valid_name(name) {
        log.line(&format!(
            "{NAME}: the name is not 1 to 32 bytes of a-z, 0-9, '.', '_' and '-'"
        ));
        return Exit::Usage;
    }
    let password = match read_password(input) {
        Ok(password) => password,
        Err(why) => {
            log.line(&format!("{NAME}: {why}"));
            return Exit::Failed;
        }
    };
    let store = match store::open(&admin.store) {
        Ok(store) => store,
        Err(e) => {
            log.line(&format!("{NAME}: admin store refused: {}", e.0));
            return Exit::Failed;
        }
    };
    let AdminStoreConfig::File { dir } = &admin.store;
    let audit = match AuditLog::open(&dir.join(AUDIT_DIR), log.clone()) {
        Ok(audit) => audit,
        Err(e) => {
            log.line(&format!("{NAME}: audit log refused: {}", e.0));
            return Exit::Failed;
        }
    };
    match create_owner(store.as_ref(), &audit, name, password.as_str(), ITERATIONS) {
        Ok(()) => {
            let _ = writeln!(io::stdout(), "created owner {name}");
            Exit::Done
        }
        Err(e) => {
            log.line(&format!("{NAME}: {}", e.0));
            Exit::Failed
        }
    }
}

/// Sets the password of the user `name`, who must be in the store, to a hash of `password` after `iterations`
/// rounds. The second factor and the recovery codes are taken away, the user must change the password at the next
/// login, the tokens made so far are void and `changed` goes up, which also ends a lock of the user in an admin
/// process that runs (it counted the failures for the earlier `changed`). The audit log has the line first, and
/// nothing is changed when it cannot be written. The store refuses when the user was changed since it was read.
pub fn reset_password(
    store: &dyn AdminStore,
    audit: &AuditLog,
    name: &str,
    password: &str,
    iterations: u32,
) -> Result<(), AdminError> {
    let hash =
        Hash::new(password, iterations).ok_or(AdminError("the password cannot be hashed"))?;
    let user = store
        .user(name)?
        .ok_or(AdminError("the user is not in the store"))?;
    let changed = now_ms().max(user.changed.saturating_add(1));
    let next = User {
        password: hash,
        mfa: None,
        recovery: Vec::new(),
        must_change: true,
        changed,
        tokens_after: changed,
        ..user.clone()
    };
    let event = |outcome| Event::command("reset", outcome).auth("reset").target(name);
    audit.write(&event(Outcome::Ok))?;
    if let Err(e) = store.replace(user.changed, &next) {
        let _ = audit.write(&event(Outcome::Failed).reason("store"));
        return Err(e);
    }
    Ok(())
}

/// The command `admin reset`: `config` is the configuration file, `name` the name of the user and `input` the
/// standard input.
pub fn reset(config: &Path, name: &str, input: &mut dyn Read, log: &Log) -> Exit {
    const NAME: &str = "admin reset";
    if let Err(text) = host::check() {
        log.line(&format!("{NAME}: host check refused: {text}"));
        return Exit::Failed;
    }
    let loaded = match config::load(config) {
        Ok(loaded) => loaded,
        Err(e) => {
            log.line(&format!("{NAME}: configuration refused: {}", e.0));
            return Exit::Usage;
        }
    };
    let Some(admin) = loaded.admin else {
        log.line(&format!(
            "{NAME}: configuration refused: there is no admin object"
        ));
        return Exit::Usage;
    };
    if !valid_name(name) {
        log.line(&format!(
            "{NAME}: the name is not 1 to 32 bytes of a-z, 0-9, '.', '_' and '-'"
        ));
        return Exit::Usage;
    }
    let password = match read_password(input) {
        Ok(password) => password,
        Err(why) => {
            log.line(&format!("{NAME}: {why}"));
            return Exit::Failed;
        }
    };
    let store = match store::open(&admin.store) {
        Ok(store) => store,
        Err(e) => {
            log.line(&format!("{NAME}: admin store refused: {}", e.0));
            return Exit::Failed;
        }
    };
    let AdminStoreConfig::File { dir } = &admin.store;
    let audit = match AuditLog::open(&dir.join(AUDIT_DIR), log.clone()) {
        Ok(audit) => audit,
        Err(e) => {
            log.line(&format!("{NAME}: audit log refused: {}", e.0));
            return Exit::Failed;
        }
    };
    match reset_password(store.as_ref(), &audit, name, password.as_str(), ITERATIONS) {
        Ok(()) => {
            // The tokens are void already; their files are only taken away.
            if store.remove_tokens(name, None).is_err() {
                log.line(&format!(
                    "{NAME}: the token files of the user cannot be removed; the tokens are void"
                ));
            }
            let _ = writeln!(io::stdout(), "reset password of {name}");
            Exit::Done
        }
        Err(e) => {
            log.line(&format!("{NAME}: {}", e.0));
            Exit::Failed
        }
    }
}

#[cfg(test)]
mod tests;
