//! The record file: a copy of what the logger writes to the standard error, kept in a directory (the `records`
//! object of the configuration, see `config`).
//!
//! `RecordFile::open` looks at the directory (a real directory owned by this user without group or other bits, as for
//! the rules store) and opens `records.log` in it for append, made with mode 0600 when it is not there; a link, a FIFO,
//! a directory or a file of another user is refused, and a file that is there with group or other bits is set to 0600
//! before anything is written to it. The logger gets the file through its queue (`Log::attach`) and writes to it every
//! line it writes to the standard error, one write for each line and after the standard error. What was queued before
//! the file was handed over is not in it.
//!
//! The same file keeps the audit log of the admin process (see `admin::audit`), under the stem `audit` in place of
//! `records`: `audit.log`, `audit.N.log` and `audit.rotating`. What is written here of the names holds for it with
//! the stem changed (`RecordFile::open_in`).
//!
//! A line that would take the file above `file_bytes` first starts the next file. The file in use is renamed to
//! `records.rotating` first; if that fails nothing has moved. Then `records.N.log` becomes `records.N+1.log` for N
//! from `files - 2` down to 1, `records.rotating` becomes `records.1.log`, and a new `records.log` is opened. If one
//! of these renames fails, `records.rotating` is renamed back. So at most `files` files are kept, the one that is
//! replaced is the oldest, and every file holds whole lines. A line longer than `file_bytes` is the only one in its
//! file. A `records.rotating` that a crash in the middle of a rotation left is replaced by the next rotation. When
//! the file is opened and after each rotation, `records.N.log` for N from `files` up to the largest number an
//! earlier, larger `files` can have made is removed if it is a regular file of this user.
//!
//! The path `records.log` is looked at (`lstat`) once a second at most, and before each rotation. If nothing is there
//! or it is another file than the one that is open (another device or inode), the open file is closed, the line is
//! lost for the file, and the next line opens `records.log` again, made anew with mode 0600.
//!
//! A write, an open or a rename that fails loses that line for the file, closes the file, and is told to the logger
//! (the return value of `append`), which counts it (`Log::file_errors`); the standard error has the line, and
//! nothing waits. The lines that come while the file is closed are lost for it the same way, and the file is opened
//! again by the first line that comes a second or more after the failure, so a disk that fails is tried once a
//! second at most. The directory is looked at again, as at the start, before the file is opened again and before a
//! rotation. A write that failed part way is cut off at the size the file had, so no half line stays in it.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::config::{MAX_RECORD_FILES, RecordsConfig};
use crate::rules::file_store::{O_NOCTTY, O_NOFOLLOW, O_NONBLOCK};
use crate::run::host;

/// The least time between a failure and the next try to open the file.
const RETRY: Duration = Duration::from_secs(1);
/// The least time between two looks at the path of the file in use, a look before a rotation apart.
const LOOK: Duration = Duration::from_secs(1);
/// The stem of the names of the record files.
const RECORDS: &str = "records";

/// The file in use, its size, and its device and inode.
struct Current {
    file: File,
    size: u64,
    id: (u64, u64),
}

/// The file in use and the files of earlier lines, in a directory.
pub struct RecordFile {
    dir: PathBuf,
    /// The first part of the names of the files: `records`, or `audit`.
    stem: &'static str,
    file_bytes: u64,
    files: usize,
    /// The user id that the files must have.
    uid: u32,
    /// None after a failure, until the file is opened again.
    current: Option<Current>,
    /// When the last failure was.
    failed: Option<Instant>,
    /// When the path of the file in use was last looked at.
    looked: Instant,
}

/// The path of file number `n`: `<stem>.log` for 0 and `<stem>.<n>.log` for the files of earlier lines.
pub(crate) fn name(dir: &Path, stem: &str, n: usize) -> PathBuf {
    if n == 0 {
        dir.join(format!("{stem}.log"))
    } else {
        dir.join(format!("{stem}.{n}.log"))
    }
}

/// Opens `<stem>.log` for append, made when it is not there, and looks at it. It is opened like every file that is
/// read from the rules store: a link is not followed, a FIFO does not make the open wait, a terminal does not become
/// the controlling terminal, and what is not a regular file of `uid` is refused. The mode of a file that was there
/// with group or other bits is set to 0600 on the open file.
fn open_current(dir: &Path, stem: &str, uid: u32) -> Result<Current, &'static str> {
    let file = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK | O_NOCTTY)
        .open(name(dir, stem, 0))
        .map_err(|_| "the record file cannot be opened")?;
    let meta = file
        .metadata()
        .map_err(|_| "the record file cannot be looked at")?;
    if !meta.is_file() || meta.uid() != uid {
        return Err("the record file is not a regular file of this user");
    }
    if meta.mode() & 0o077 != 0 {
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| "the mode of the record file cannot be set")?;
    }
    Ok(Current {
        file,
        size: meta.len(),
        id: (meta.dev(), meta.ino()),
    })
}

/// Whether `<stem>.log` is the file that `current` has open: the same device and inode, looked at with `lstat`, so
/// that a link in its place is another file.
fn at_path(dir: &Path, stem: &str, current: &Current) -> bool {
    fs::symlink_metadata(name(dir, stem, 0))
        .is_ok_and(|meta| (meta.dev(), meta.ino()) == current.id)
}

impl RecordFile {
    /// Looks at the directory and opens the file in use. A refusal is a sentence.
    pub fn open(config: &RecordsConfig) -> Result<RecordFile, &'static str> {
        RecordFile::open_in(RECORDS, &config.dir, config.file_bytes, config.files)
    }

    /// The same for the files that begin with `stem`, in `dir`: `file_bytes` and `files` are as in the `records`
    /// object (`files` from 2 to `MAX_RECORD_FILES`).
    pub fn open_in(
        stem: &'static str,
        dir: &Path,
        file_bytes: u64,
        files: usize,
    ) -> Result<RecordFile, &'static str> {
        let mut file = RecordFile {
            dir: dir.to_path_buf(),
            stem,
            file_bytes,
            files,
            uid: host::fs_uid()?,
            current: None,
            failed: None,
            looked: Instant::now(),
        };
        file.current = Some(file.reopen()?);
        file.remove_extra();
        Ok(file)
    }

    /// Makes what was written reach the disk. False: it did not, or the file is not open.
    pub fn sync(&self) -> bool {
        self.current
            .as_ref()
            .is_some_and(|current| current.file.sync_data().is_ok())
    }

    /// Writes `line`, which ends with its line feed, in one write. False: the file did not take it.
    pub fn append(&mut self, line: &[u8]) -> bool {
        self.append_at(line, Instant::now())
    }

    /// `append` at the time `now`.
    fn append_at(&mut self, line: &[u8], now: Instant) -> bool {
        let Some(mut current) = self.in_use(now) else {
            return false;
        };
        let len = u64::try_from(line.len()).unwrap_or(u64::MAX);
        let full = current.size > 0 && current.size.saturating_add(len) > self.file_bytes;
        // The path is looked at once a second at most, and always before the file is renamed.
        if full || now.saturating_duration_since(self.looked) >= LOOK {
            self.looked = now;
            if !at_path(&self.dir, self.stem, &current) {
                // The file is closed here. The disk did not fail, so the next line opens the path at once.
                self.failed = None;
                return false;
            }
        }
        if full {
            // The file is closed before it is renamed.
            drop(current);
            let Some(next) = self.rotate() else {
                self.failed = Some(now);
                return false;
            };
            current = next;
        }
        if current.file.write_all(line).is_err() {
            // What was written of the line is cut off, so that the file holds whole lines.
            let _ = current.file.set_len(current.size);
            self.failed = Some(now);
            return false;
        }
        current.size = current.size.saturating_add(len);
        self.current = Some(current);
        self.failed = None;
        true
    }

    /// The file in use: the open one, or, if there is none, one that is opened now unless the last failure was less
    /// than `RETRY` ago. A failed open counts as a failure.
    fn in_use(&mut self, now: Instant) -> Option<Current> {
        if let Some(current) = self.current.take() {
            return Some(current);
        }
        if self
            .failed
            .is_some_and(|at| now.saturating_duration_since(at) < RETRY)
        {
            return None;
        }
        match self.reopen() {
            Ok(current) => Some(current),
            Err(_) => {
                self.failed = Some(now);
                None
            }
        }
    }

    /// Looks at the directory again, as at the start, and opens the file in use.
    fn reopen(&self) -> Result<Current, &'static str> {
        host::private_dir(&self.dir, self.uid)?;
        open_current(&self.dir, self.stem, self.uid)
    }

    /// Renames the files up by one, the last one being replaced by the one before it, and opens a new file in use.
    /// The file in use moves first, so that nothing else has moved if it cannot; if a later rename fails, it is put
    /// back. None: a rename or the open failed.
    fn rotate(&self) -> Option<Current> {
        host::private_dir(&self.dir, self.uid).ok()?;
        let moving = self.dir.join(format!("{}.rotating", self.stem));
        fs::rename(name(&self.dir, self.stem, 0), &moving).ok()?;
        if self.shift(&moving).is_err() {
            let _ = fs::rename(&moving, name(&self.dir, self.stem, 0));
            return None;
        }
        self.remove_extra();
        open_current(&self.dir, self.stem, self.uid).ok()
    }

    /// Renames `<stem>.N.log` to `<stem>.N+1.log` for N from `files - 2` down to 1, and `moving` to `<stem>.1.log`.
    fn shift(&self, moving: &Path) -> io::Result<()> {
        for n in (1..self.files.saturating_sub(1)).rev() {
            match fs::rename(
                name(&self.dir, self.stem, n),
                name(&self.dir, self.stem, n + 1),
            ) {
                Ok(()) => {}
                // A file that is not there is no file to keep.
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        fs::rename(moving, name(&self.dir, self.stem, 1))
    }

    /// Removes `<stem>.N.log` for N from `files` up to the largest number an earlier, larger `files` can have made,
    /// if it is a regular file of this user (looked at with `lstat`, so a link or a directory stays). A file that
    /// cannot be removed stays until the next rotation.
    fn remove_extra(&self) {
        for n in self.files..MAX_RECORD_FILES {
            let path = name(&self.dir, self.stem, n);
            if fs::symlink_metadata(&path)
                .is_ok_and(|meta| meta.is_file() && meta.uid() == self.uid)
            {
                let _ = fs::remove_file(&path);
            }
        }
    }
}

#[cfg(test)]
mod tests;
