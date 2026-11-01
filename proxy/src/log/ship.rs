//! The position of the shipper, and how far behind it is.
//!
//! A shipper is a program of its own that reads the record files and puts the records into a database. The proxy
//! does not run it and does not open what it needs to get there; the `ship` object of the configuration says that
//! there is one (see `config`). The shipper keeps how far it has got in the file `ship.state` of the records
//! directory, which it replaces after each batch that it has committed and every second while it has nothing to
//! commit: one line of JSON with a line feed,
//! `{"version":1,"inode":"<decimal>","born":"<decimal>","offset":<n>,"lost_lines":<n>,"ts":"<RFC 3339>"}`. `inode`
//! and `born` tell the record file the shipper is in (see `Identity`), as text, for a rotation renames the files and
//! a number above 2^53 is not safe in JSON; `offset` is the offset in it up to which every line is shipped;
//! `lost_lines` is the number of lines that a rotation deleted before the shipper got to them, and `ts` the time it
//! wrote the position.
//!
//! The proxy reads the position once a second (`watch`) and works out how many bytes of the record files come after
//! it: the rest of the file it names and every newer file. These are the bytes that are lost if the files are
//! rotated away before the shipper has them. When they come to `files - 2` files of `file_bytes` bytes, the shipper
//! is so near the deletion of the oldest file that a request which needs its record kept is turned away, until the
//! number falls below that again (`Log::admit`). The look is a second old at the most, so the bytes that the logger
//! has written since are added to what the look found. A request is turned away as well while the distance is not
//! known: the position cannot be read, is not a position, was written more than `FRESH` ago (a shipper that does
//! not run does not rewrite it), names a file that no record file is, or a file that the file system gives no birth
//! time for. With fewer than 3 files there is no room to judge by, and a request is not turned away for the shipper
//! at all; the distance is still looked at and shown. The configuration does not allow a shipper together with
//! records that must be kept when there are fewer than 3 files (see `config`).

use std::fs::{self, Metadata, OpenOptions};
use std::io::Read;
use std::iter;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::Counts;
use super::sink::{RECORDS, name, rotating};
use super::time::rfc3339;
use crate::config::Records;
use crate::rules::file_store::{O_NOCTTY, O_NOFOLLOW, O_NONBLOCK};

/// The name of the file of the position, in the records directory.
pub const POSITION_FILE: &str = "ship.state";
/// The version that the position has.
const VERSION: u8 = 1;
/// The most bytes of the file of the position that are read; a longer file is not a position.
const POSITION_MAX: u64 = 1024;
/// The longest `ts` of a position in bytes.
const TS_MAX: usize = 64;
/// The most digits of the inode in a position (`u64::MAX` has 20).
const INODE_DIGITS: usize = 20;
/// The most digits of the birth time in a position (`u128::MAX` has 39).
const BORN_DIGITS: usize = 39;
/// The time between two looks at the position.
const LOOK: Duration = Duration::from_secs(1);
/// The wait before a position whose file was not found is looked at again: a rotation takes a moment.
const AGAIN: Duration = Duration::from_millis(50);
/// How far from now, either way, the time of a position may be for the position to count. The shipper writes it at
/// least every second, and gives up a call to its database after 30 seconds.
const FRESH: Duration = Duration::from_secs(90);
/// What the distance is while it is not known.
const UNKNOWN: u64 = u64::MAX;

/// The path of record file number `n` in `dir`: `records.log` for 0, the file in use, and `records.<n>.log` for the
/// files of earlier lines, a larger `n` being older.
pub fn record_file(dir: &Path, n: usize) -> PathBuf {
    name(dir, RECORDS, n)
}

/// The path that the file in use has while the proxy rotates it, between its two renames.
pub fn rotating_file(dir: &Path) -> PathBuf {
    rotating(dir, RECORDS)
}

/// The path of the file of the position in `dir`.
pub fn position_file(dir: &Path) -> PathBuf {
    dir.join(POSITION_FILE)
}

/// The text of `at` as the position writes its time.
pub fn timestamp(at: SystemTime) -> String {
    rfc3339(at)
}

/// What tells one record file from every other, also from a file that had its inode before: a file system gives the
/// inode of a deleted file to the next file it makes, and a rotation deletes the oldest record file just before it
/// makes the new one, so the inode alone does not say which file a position is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub inode: u64,
    /// When the file was made, in nanoseconds since the epoch of Unix time.
    pub born: u128,
}

impl Identity {
    /// The identity of the file that `meta` is of. None: the file system does not tell when the file was made.
    pub fn of(meta: &Metadata) -> Option<Identity> {
        let born = meta
            .created()
            .ok()?
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_nanos();
        Some(Identity {
            inode: meta.ino(),
            born,
        })
    }
}

/// How far the shipper has got.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Position {
    /// The inode of the record file the shipper is in.
    pub inode: u64,
    /// When that file was made (see `Identity`), in nanoseconds since the epoch of Unix time.
    pub born: u128,
    /// The offset in it up to which every line is shipped.
    pub offset: u64,
    /// The lines that a rotation deleted before the shipper got to them.
    pub lost_lines: u64,
    /// When the shipper wrote the position (see `timestamp`).
    pub ts: String,
}

/// The position as the file has it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    version: u8,
    inode: String,
    born: String,
    offset: u64,
    lost_lines: u64,
    ts: String,
}

/// Whether `text` is one to `most` decimal digits.
fn decimal(text: &str, most: usize) -> bool {
    !text.is_empty() && text.len() <= most && text.bytes().all(|b| b.is_ascii_digit())
}

impl Position {
    /// The position that `text` holds: one line of JSON with the line feed at its end, as `line` writes it. None:
    /// anything else, a key that is not known, a version other than 1, an inode or a birth time that is not decimal
    /// digits or does not fit its number.
    pub fn parse(text: &[u8]) -> Option<Position> {
        let text = text.strip_suffix(b"\n")?;
        if text.contains(&b'\n') {
            return None;
        }
        let wire: Wire = serde_json::from_slice(text).ok()?;
        let digits = decimal(&wire.inode, INODE_DIGITS) && decimal(&wire.born, BORN_DIGITS);
        let shown = wire.ts.len() <= TS_MAX && wire.ts.bytes().all(|b| (0x20..0x7f).contains(&b));
        if wire.version != VERSION || !digits || !shown {
            return None;
        }
        Some(Position {
            inode: wire.inode.parse().ok()?,
            born: wire.born.parse().ok()?,
            offset: wire.offset,
            lost_lines: wire.lost_lines,
            ts: wire.ts,
        })
    }

    /// The line of the file of the position, with its line feed.
    pub fn line(&self) -> String {
        let wire = Wire {
            version: VERSION,
            inode: self.inode.to_string(),
            born: self.born.to_string(),
            offset: self.offset,
            lost_lines: self.lost_lines,
            ts: self.ts.clone(),
        };
        let mut line = serde_json::to_string(&wire).unwrap_or_default();
        line.push('\n');
        line
    }

    /// The record file the position is in.
    pub fn identity(&self) -> Identity {
        Identity {
            inode: self.inode,
            born: self.born,
        }
    }
}

/// How much of the record files the shipper has not shipped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unshipped {
    /// The position cannot be read, is too old, or names a file that is not there.
    Unknown,
    Bytes(u64),
}

/// What a look at the shipper found, and how much the logger had written to the record file when it began.
struct Seen {
    /// The distance in bytes, or `UNKNOWN`.
    unshipped: u64,
    written: u64,
}

/// How far behind the shipper was at the last look, and the distance at which a request that needs its record kept is
/// turned away.
pub(super) struct Lag {
    /// The distance in bytes from which on a request is turned away. None: the shipper is not judged (see `watch`).
    limit: Option<u64>,
    /// The last look; `UNKNOWN` before the first.
    seen: Mutex<Seen>,
    /// The bytes that the logger has written to the record file so far.
    written: AtomicU64,
}

impl Lag {
    fn new(limit: Option<u64>) -> Lag {
        Lag {
            limit,
            seen: Mutex::new(Seen {
                unshipped: UNKNOWN,
                written: 0,
            }),
            written: AtomicU64::new(0),
        }
    }

    /// The logger wrote `bytes` to the record file.
    pub(super) fn wrote(&self, bytes: usize) {
        let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
        let _ = self
            .written
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |written| {
                Some(written.saturating_add(bytes))
            });
    }

    /// The distance now: what the last look found, and what the logger has written since it began, for all of that
    /// comes after the position. `UNKNOWN` while the last look found nothing.
    fn distance(&self) -> u64 {
        let seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        if seen.unshipped == UNKNOWN {
            return UNKNOWN;
        }
        let since = self
            .written
            .load(Ordering::Acquire)
            .saturating_sub(seen.written);
        seen.unshipped.saturating_add(since)
    }

    /// The shipper is at the limit or beyond it, or its distance is not known. Never, if there is no limit.
    pub(super) fn behind(&self) -> bool {
        self.limit.is_some_and(|limit| self.distance() >= limit)
    }

    pub(super) fn unshipped(&self) -> Unshipped {
        match self.distance() {
            UNKNOWN => Unshipped::Unknown,
            bytes => Unshipped::Bytes(bytes),
        }
    }
}

/// Whether `ts` is the time of a position that counts: within `FRESH` of `now`. It has to be in the shape that
/// `timestamp` writes, `YYYY-MM-DDTHH:MM:SS.mmmZ`; texts of that shape come in the order of the times they stand
/// for, so they are compared as text.
fn recent(ts: &str, now: SystemTime) -> bool {
    let shaped = ts.len() == 24
        && ts.bytes().enumerate().all(|(at, b)| match at {
            4 | 7 => b == b'-',
            10 => b == b'T',
            13 | 16 => b == b':',
            19 => b == b'.',
            23 => b == b'Z',
            _ => b.is_ascii_digit(),
        });
    let first = timestamp(now.checked_sub(FRESH).unwrap_or(UNIX_EPOCH));
    let last = timestamp(now.checked_add(FRESH).unwrap_or(now));
    shaped && first.as_str() <= ts && ts <= last.as_str()
}

/// The position in `dir`. None: there is no file of the position, it is not a regular file, it is longer than a
/// position can be, or it is not one. A link is not followed and a FIFO is not waited for.
fn read_position(dir: &Path) -> Option<Position> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK | O_NOCTTY)
        .open(position_file(dir))
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(POSITION_MAX + 1).read_to_end(&mut bytes).ok()?;
    if u64::try_from(bytes.len()).ok()? > POSITION_MAX {
        return None;
    }
    Position::parse(&bytes)
}

/// The bytes of the record files in `dir` (at most `files` of them) that come after `position`: the rest of the file
/// it names and every newer file. The files are looked at from the newest: `records.log`, then the file that a
/// rotation is moving, if there is one, then `records.1.log` and the older ones. None: no file is the one it names,
/// a file cannot be looked at, or the file system does not tell when a file was made.
fn unshipped_bytes(dir: &Path, files: usize, position: &Position) -> Option<u64> {
    let named = position.identity();
    let paths = iter::once(record_file(dir, 0))
        .chain(iter::once(rotating_file(dir)))
        .chain((1..files).map(|n| record_file(dir, n)));
    let mut newer = 0u64;
    for path in paths {
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            // `records.log` and `records.1.log` are not there for a moment in a rotation, the file that is moved is
            // there only then, and the older files are not there until the rotations have made them.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return None,
        };
        if !meta.is_file() {
            return None;
        }
        if Identity::of(&meta)? == named {
            let rest = meta.len().saturating_sub(position.offset);
            return Some(newer.saturating_add(rest));
        }
        newer = newer.saturating_add(meta.len());
    }
    None
}

/// The distance now, or `UNKNOWN`. A rotation in the middle of the look can show a file under two names or under
/// none, so a position whose file is not found is read and looked for once more after `again`.
fn look(dir: &Path, files: usize, again: Duration) -> u64 {
    for round in 0..2 {
        if round > 0 {
            thread::sleep(again);
        }
        let Some(position) = read_position(dir).filter(|p| recent(&p.ts, SystemTime::now())) else {
            return UNKNOWN;
        };
        if let Some(bytes) = unshipped_bytes(dir, files, &position) {
            return bytes;
        }
    }
    UNKNOWN
}

/// Looks at the shipper and keeps what the look found. How much the logger has written is read before the look, so
/// that a line which is written during it is in the distance, or in what is added later, or in both, and not in
/// neither.
fn note(counts: &Counts, dir: &Path, files: usize) {
    let Some(lag) = counts.lag.get() else {
        return;
    };
    let written = lag.written.load(Ordering::Acquire);
    let unshipped = look(dir, files, AGAIN);
    *lag.seen.lock().unwrap_or_else(PoisonError::into_inner) = Seen { unshipped, written };
}

/// Makes the lag of the shipper of `config` known to `counts`, looks once now, and starts a thread that looks once a
/// second. The thread ends when nothing but itself holds `counts` any more.
pub(super) fn watch(counts: &Arc<Counts>, config: &Records) -> Result<(), &'static str> {
    // The limit is `files - 2` files; with fewer than 3 that is nothing, which every distance reaches, so there is no
    // limit to judge by.
    let limit = (config.files >= 3).then(|| {
        let room = u64::try_from(config.files - 2).unwrap_or(u64::MAX);
        room.saturating_mul(config.file_bytes)
    });
    if counts.lag.set(Lag::new(limit)).is_err() {
        return Err("the shipper is watched already");
    }
    let (dir, files) = (config.dir.clone(), config.files);
    note(counts, &dir, files);
    let counts = counts.clone();
    thread::Builder::new()
        .name("ship-watch".into())
        .spawn(move || {
            loop {
                thread::sleep(LOOK);
                if Arc::strong_count(&counts) == 1 {
                    return;
                }
                note(&counts, &dir, files);
            }
        })
        .map(|_| ())
        .map_err(|_| "cannot start the thread that watches the shipper")
}

#[cfg(test)]
mod tests;
