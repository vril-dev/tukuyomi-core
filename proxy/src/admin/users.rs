//! The users: the role, the user, the file a user is kept in, and the first user.
//!
//! A role is `viewer`, `operator` or `owner`, in that order, and a route may be used by a user whose role is not
//! below the least role that the route names. A user has a name (see `password::valid_name`), a role, whether it is
//! disabled, the hash of its password, the time it was made and the time it was last changed (both in milliseconds
//! since the epoch). `changed` goes up with every change of the user, and a session keeps the value it saw (see
//! `session`), so a session does not outlive a change of the password, the role or the state of its user.
//!
//! A user is kept as one JSON object with the keys `name`, `role`, `disabled`, `password` (`iterations`, `salt` and
//! `hash`, the last two as lowercase hexadecimal), `created` and `changed`. A file with another key, a name other
//! than the one of its file, or a role, salt or hash that is not understood is not read: the keys of a later
//! version are not dropped by an earlier one.
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

use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::Exit;
use super::audit::{AuditLog, Event, Outcome};
use super::file_store::AUDIT_DIR;
use super::password::{
    Hash, ITERATIONS, PASSWORD_MAX, Secret, hex, unhex, valid_name, valid_password,
};
use super::store::{self, AdminError, AdminStore};
use crate::config::{self, AdminStoreConfig};
use crate::log::Log;
use crate::run::host;

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
struct Stored {
    name: String,
    role: String,
    disabled: bool,
    password: StoredPassword,
    created: u64,
    changed: u64,
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
    /// A user made at `now` (milliseconds since the epoch), not disabled.
    pub fn new(name: &str, role: Role, password: Hash, now: u64) -> User {
        User {
            name: name.to_owned(),
            role,
            disabled: false,
            password,
            created: now,
            changed: now,
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
        Ok(User {
            name: stored.name,
            role: Role::parse(&stored.role).ok_or(BROKEN)?,
            disabled: stored.disabled,
            password,
            created: stored.created,
            changed: stored.changed,
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

#[cfg(test)]
mod tests;
