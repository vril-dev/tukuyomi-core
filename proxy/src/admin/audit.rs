//! The audit log: one line of JSON for each event, in `audit/audit.log` of the admin store (kept as the record file
//! is, by size: 16 MiB a file and 8 files, see `log::sink`) and the same line on the standard error through the
//! logger, as a record of the type `audit`.
//!
//! A line has `ts` and `type` as every record has, then `id` (the number of the request), `actor` (the name of the
//! user whose password or session was checked for the request; it is left out when no user was, and it never comes
//! from a header of the request), `session` (the first 8 digits of the SHA-256 of the session id; the id is never
//! written), `auth` (how the actor got in when it was not by a session: `bootstrap` for the command that makes the
//! first user, `reset` for the command that sets a password again, `token:<id>` for a request with an API token),
//! `client` (the address of the client), `action`,
//! `target` (the user, or the token, the action is about), `result`
//! (`ok`, `denied` or `failed`) and `reason` (a fixed word), and, for a change of a user, `before` and `after` (only
//! `after` for a user that was made), or for a switch of the rules the generation chosen before and the one asked for. The line of a command run on the host has no `id` and no `client`: it is not a
//! request. No password, cookie or token is ever written.
//!
//! A change is audited before it is made. `write` fails when the line cannot be encoded or the file does not take
//! it, and then the caller refuses the change and makes none. The file has the line on the disk (`RecordFile::sync`)
//! before `write` returns, and the line goes to the standard error only after that. Requests that are refused before
//! a user is known (no session, no token or a token that is not right, a login that was refused for the rate of the
//! client or for its `Origin`) are not written, so that nobody who has no session can fill the log and push older lines
//! out of it.
//!
//! `recent` reads the newest lines back: from the end of `audit.log`, and from the older files while it needs more,
//! at most 1 MiB of a file; a line that cannot be parsed is left out. It does not take the lock of the writer, so it
//! can meet a rotation between the rename of `audit.log` and the open of a new one: a missing `audit.log` is read as
//! a file without lines, and the older files are read after it.

use std::fs::OpenOptions;
use std::io::{self, Read, Seek, SeekFrom};
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::SystemTime;

use serde::Serialize;
use serde_json::Value;

use super::store::AdminError;
use crate::log::Log;
use crate::log::record::{self, Record};
use crate::log::sink::{self, RecordFile};
use crate::rules::file_store::{O_NOCTTY, O_NOFOLLOW, O_NONBLOCK};

/// The stem of the names of the files.
const STEM: &str = "audit";
const FILE_BYTES: u64 = 16 << 20;
const FILES: usize = 8;
/// The most bytes read from the end of a file.
const TAIL: u64 = 1 << 20;

/// Where the lines are written. The record file is the one that is used; the tests give another.
pub trait Append: Send {
    /// Writes `line`, which ends with its line feed, whole. False: it was not written.
    fn append(&mut self, line: &[u8]) -> bool;
}

impl Append for RecordFile {
    fn append(&mut self, line: &[u8]) -> bool {
        RecordFile::append(self, line) && self.sync()
    }
}

/// How an event ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    Denied,
    Failed,
}

impl Outcome {
    fn word(self) -> &'static str {
        match self {
            Outcome::Ok => "ok",
            Outcome::Denied => "denied",
            Outcome::Failed => "failed",
        }
    }
}

/// One event to be written. `Event::new` or `Event::command` makes it, and the methods after it fill it in.
#[derive(Clone, Debug)]
pub struct Event<'a> {
    request: Option<&'a str>,
    client: Option<IpAddr>,
    action: &'static str,
    outcome: Outcome,
    actor: Option<&'a str>,
    session: Option<&'a str>,
    auth: Option<&'a str>,
    target: Option<&'a str>,
    reason: Option<&'static str>,
    before: Option<&'a str>,
    after: Option<&'a str>,
}

impl<'a> Event<'a> {
    /// An event of the request numbered `request`, from `client`.
    pub fn new(
        request: &'a str,
        client: IpAddr,
        action: &'static str,
        outcome: Outcome,
    ) -> Event<'a> {
        Event::build(Some(request), Some(client), action, outcome)
    }

    /// An event of a command run on the host, which is no request: it has no number and no client.
    pub fn command(action: &'static str, outcome: Outcome) -> Event<'a> {
        Event::build(None, None, action, outcome)
    }

    fn build(
        request: Option<&'a str>,
        client: Option<IpAddr>,
        action: &'static str,
        outcome: Outcome,
    ) -> Event<'a> {
        Event {
            request,
            client,
            action,
            outcome,
            actor: None,
            session: None,
            auth: None,
            target: None,
            reason: None,
            before: None,
            after: None,
        }
    }

    /// The user whose password or session was checked.
    pub fn actor(mut self, name: &'a str) -> Event<'a> {
        self.actor = Some(name);
        self
    }

    /// The handle of the session of the request.
    pub fn session(mut self, handle: &'a str) -> Event<'a> {
        self.session = Some(handle);
        self
    }

    /// How the actor got in, when it was not by a session.
    pub fn auth(mut self, kind: &'a str) -> Event<'a> {
        self.auth = Some(kind);
        self
    }

    pub fn target(mut self, name: &'a str) -> Event<'a> {
        self.target = Some(name);
        self
    }

    pub fn reason(mut self, reason: &'static str) -> Event<'a> {
        self.reason = Some(reason);
        self
    }

    /// What a change of a user was from and to (a role or a state, as a word), or of the generation of the rules.
    pub fn change(mut self, before: &'a str, after: &'a str) -> Event<'a> {
        self.before = Some(before);
        self.after = Some(after);
        self
    }

    /// What a user that was made has (its role, as a word); there is no state before.
    pub fn after(mut self, after: &'a str) -> Event<'a> {
        self.after = Some(after);
        self
    }
}

#[derive(Serialize)]
struct Body<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    actor: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client: Option<IpAddr>,
    action: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<&'a str>,
    result: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    before: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after: Option<&'a str>,
}

/// The audit log.
pub struct AuditLog {
    sink: Mutex<Box<dyn Append>>,
    dir: PathBuf,
    log: Log,
}

impl AuditLog {
    /// Opens `audit.log` in `dir`, which must be a directory of this user closed to others.
    pub fn open(dir: &Path, log: Log) -> Result<AuditLog, AdminError> {
        let file = RecordFile::open_in(STEM, dir, FILE_BYTES, FILES).map_err(AdminError)?;
        Ok(AuditLog::with_sink(Box::new(file), dir, log))
    }

    /// An audit log that writes to `sink` and is read from the files in `dir`.
    pub fn with_sink(sink: Box<dyn Append>, dir: &Path, log: Log) -> AuditLog {
        AuditLog {
            sink: Mutex::new(sink),
            dir: dir.to_path_buf(),
            log,
        }
    }

    /// Writes the event. An error means that it was not written.
    pub fn write(&self, event: &Event<'_>) -> Result<(), AdminError> {
        const CANNOT: AdminError = AdminError("the audit log cannot be written");
        let line = record::framed(
            SystemTime::now(),
            "audit",
            Body {
                id: event.request,
                actor: event.actor,
                session: event.session,
                auth: event.auth,
                client: event.client.map(|client| client.to_canonical()),
                action: event.action,
                target: event.target,
                result: event.outcome.word(),
                reason: event.reason,
                before: event.before,
                after: event.after,
            },
        )
        .ok_or(CANNOT)?;
        let mut bytes = line.clone().into_bytes();
        bytes.push(b'\n');
        let written = self
            .sink
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .append(&bytes);
        if !written {
            self.log.line("admin: the audit log cannot be written");
            return Err(CANNOT);
        }
        self.log.record(Record::Audit(line));
        Ok(())
    }

    /// The newest `limit` lines, the newest first.
    pub fn recent(&self, limit: usize) -> Result<Vec<Value>, AdminError> {
        const CANNOT: AdminError = AdminError("the audit log cannot be read");
        let mut found = Vec::new();
        for n in 0..FILES {
            let (bytes, whole) = match tail(&sink::name(&self.dir, STEM, n)) {
                Ok(read) => read,
                // A rotation has renamed `audit.log` and not yet made the new one: it has no lines for now.
                Err(e) if e.kind() == io::ErrorKind::NotFound && n == 0 => (Vec::new(), true),
                Err(e) if e.kind() == io::ErrorKind::NotFound => break,
                Err(_) => return Err(CANNOT),
            };
            for line in bytes.rsplit(|&b| b == b'\n') {
                if let Ok(entry) = serde_json::from_slice::<Value>(line) {
                    found.push(entry);
                    if found.len() >= limit {
                        return Ok(found);
                    }
                }
            }
            // The part that was read does not reach the start of the file: an older file would leave a gap.
            if !whole {
                break;
            }
        }
        Ok(found)
    }
}

/// The last `TAIL` bytes of the regular file at `path`, from the first whole line on, and whether they are the whole
/// file. It is opened like every file that is read from a store: a link is not followed and a FIFO is not waited for.
pub(super) fn tail(path: &Path) -> io::Result<(Vec<u8>, bool)> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK | O_NOCTTY)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a regular file",
        ));
    }
    let start = meta.len().saturating_sub(TAIL);
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::new();
    file.take(TAIL).read_to_end(&mut bytes)?;
    if start > 0 {
        // The first line is cut off at its start.
        match bytes.iter().position(|&b| b == b'\n') {
            Some(end) => {
                bytes.drain(..=end);
            }
            None => bytes.clear(),
        }
    }
    Ok((bytes, start == 0))
}

#[cfg(test)]
pub(crate) mod tests;
