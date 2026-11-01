//! The files the shipper reads and writes in the directory of the records, and how it opens them.
//!
//! The record files are `records.log` (in use) and `records.N.log` (older, a higher N is older), and while the proxy
//! rotates them, `records.rotating` holds the file that was in use. Their names, and the name and the form of the
//! position file `ship.state`, come from the proxy library, so that the proxy reads what the shipper writes.
//!
//! The position file is written after the database has committed the same position: a temporary file in the same
//! directory, flushed to the disk, renamed over `ship.state`, and the directory flushed, so that a reader sees the
//! old file or the new one and never a part of one.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use tukuyomi_proxy::log::ship;

use crate::follow::Position;

/// `O_NOFOLLOW` of Linux, which std has no name for. x86_64: the UAPI header `asm-generic/fcntl.h`. aarch64: Go's
/// `syscall/zerrors_linux_arm64.go`, where the value differs.
#[cfg(target_arch = "x86_64")]
const O_NOFOLLOW: i32 = 0o400_000;
#[cfg(target_arch = "aarch64")]
const O_NOFOLLOW: i32 = 0o100_000;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("O_NOFOLLOW is only known for x86_64 and aarch64 Linux");
/// `O_NONBLOCK` of Linux, the same on x86_64 and aarch64.
const O_NONBLOCK: i32 = 0o4_000;
/// `O_NOCTTY` of Linux, the same on x86_64 and aarch64.
const O_NOCTTY: i32 = 0o400;

/// The last second that the text of a time can show: 9999-12-31T23:59:59.
const LAST_SECOND: u64 = 253_402_300_799;

/// The path of record file number `n`: 0 is the file in use.
fn record_path(dir: &Path, n: usize) -> PathBuf {
    ship::record_file(dir, n)
}

/// The path of the file that is being renamed up while the proxy rotates.
fn rotating_path(dir: &Path) -> PathBuf {
    ship::rotating_file(dir)
}

/// The paths where a record file can be, the oldest first: `records.{files-1}.log` down to `records.1.log`, the
/// file that is being rotated, and `records.log`. A file moves towards the start of this list when it is rotated.
pub fn record_paths(dir: &Path, files: usize) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = (1..files).rev().map(|n| record_path(dir, n)).collect();
    paths.push(rotating_path(dir));
    paths.push(record_path(dir, 0));
    paths
}

/// Opens a record file for reading. A link is not followed, a FIFO does not make the open wait, a terminal does
/// not become the controlling terminal, and what is not a regular file is refused.
pub fn open_record(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK | O_NOCTTY)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a regular file",
        ));
    }
    Ok(file)
}

/// Opens a file of the configuration or of the system for reading. A link is followed (the path of a certificate
/// or of a secret is often a link), a FIFO does not make the open wait, a terminal does not become the controlling
/// terminal. The caller looks at the type and the owner of what was opened.
pub fn open_followed(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK | O_NOCTTY)
        .open(path)
}

/// Writes the position file `ship.state` for `position`, as of `at`.
pub fn write_state(dir: &Path, position: &Position, at: SystemTime) -> io::Result<()> {
    let line = ship::Position {
        inode: position.identity.inode,
        born: position.identity.born,
        offset: position.offset,
        lost_lines: position.lost_lines,
        ts: rfc3339(at),
    }
    .line();
    let target = ship::position_file(dir);
    let temporary = dir.join(format!("{}.new", ship::POSITION_FILE));
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK | O_NOCTTY)
        .open(&temporary)?;
    file.write_all(line.as_bytes())?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, &target)?;
    File::open(dir)?.sync_all()
}

/// The text of `at` as RFC 3339 in UTC with milliseconds (`2026-10-25T08:00:00.123Z`), the form of the `ts` of a
/// record. A time before 1970 is written as 1970-01-01T00:00:00.000Z, and one after the year 9999 as the last
/// second of that year, so the text always has the same shape. The date is the inverse of the calendar calculation
/// that the proxy uses to read a date.
pub fn rfc3339(at: SystemTime) -> String {
    let since = at.duration_since(UNIX_EPOCH).unwrap_or_default();
    let (secs, millis) = if since.as_secs() > LAST_SECOND {
        (LAST_SECOND, 999)
    } else {
        (since.as_secs(), u64::from(since.subsec_millis()))
    };
    // At most 253 402 300 799, so the day number fits in an `i64`.
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let (year, month, day) = civil_from_days(days);
    let rest = secs % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// The date of the day that is `days` days from 1970-01-01 (proleptic Gregorian calendar): year, month, day.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_from_march = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_from_march + 2) / 5 + 1;
    let month = if month_from_march < 10 {
        month_from_march + 3
    } else {
        month_from_march - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests;
