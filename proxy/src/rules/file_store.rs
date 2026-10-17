//! The rules store in a directory of the file system.
//!
//! The directory holds one directory per generation, `generations/<64 lowercase hex digits>/`, and the file
//! `current`, which names the chosen generation: its 64 digits and a newline. Only the store directory itself is
//! examined (a real directory, owned by this process's user, no group or other bits): a user who cannot write
//! there cannot make or replace a name inside it. What is read is opened without following a link and without
//! waiting for a writer.

use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use crate::config;
use crate::host;
use crate::rules::bundle::Fingerprint;
use crate::rules::store::{RuleStore, StoreError};

/// `O_NOFOLLOW` of Linux, which std has no name for. x86_64: the UAPI header `asm-generic/fcntl.h` (and Go's
/// `syscall/zerrors_linux_amd64.go`). aarch64: Go's `syscall/zerrors_linux_arm64.go`, where the value differs.
#[cfg(target_arch = "x86_64")]
const O_NOFOLLOW: i32 = 0o400_000;
#[cfg(target_arch = "aarch64")]
const O_NOFOLLOW: i32 = 0o100_000;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("O_NOFOLLOW is only known for x86_64 and aarch64 Linux");
/// `O_NONBLOCK` of Linux, the same on x86_64 and aarch64 (the same sources as for `O_NOFOLLOW`).
const O_NONBLOCK: i32 = 0o4_000;

/// The size of `current`: 64 hexadecimal digits and a newline.
const CURRENT_LEN: u64 = 65;

/// A rules store in a directory of the file system.
pub struct FileStore {
    dir: PathBuf,
}

impl FileStore {
    /// Opens the store in `dir`, which must be an absolute clean path: this is a public entry, so the form is
    /// checked here too, before anything is looked at. Then only `dir` is examined, by `lstat`: it must be a real
    /// directory (not a link) without group or other permission bits and owned by the user that the file system
    /// sees for this process.
    pub fn open(dir: &Path) -> Result<FileStore, StoreError> {
        if !config::clean_abs(dir) {
            return Err(StoreError(
                "the rules store directory is not an absolute clean path",
            ));
        }
        let uid = host::fs_uid().map_err(StoreError)?;
        FileStore::open_as(dir, uid)
    }

    /// `open` for a directory that must be owned by `uid`, once the form of `dir` is known to be right. The tests
    /// give a user id other than the owner's: a directory of another owner cannot be made without privilege.
    fn open_as(dir: &Path, uid: u32) -> Result<FileStore, StoreError> {
        let meta = fs::symlink_metadata(dir)
            .map_err(|_| StoreError("the rules store directory cannot be read"))?;
        if !meta.file_type().is_dir() {
            return Err(StoreError(
                "the rules store directory is not a real directory",
            ));
        }
        if meta.mode() & 0o077 != 0 {
            return Err(StoreError(
                "the rules store directory has group or other permission bits",
            ));
        }
        if meta.uid() != uid {
            return Err(StoreError(
                "the rules store directory is not owned by this user",
            ));
        }
        Ok(FileStore {
            dir: dir.to_path_buf(),
        })
    }
}

impl RuleStore for FileStore {
    /// Reads `current`: absent is no choice yet; a link, a special file, a file over 65 bytes or any failure to
    /// read it is a refusal, and so is a content other than 64 lowercase digits and one newline.
    fn current(&self) -> Result<Option<Fingerprint>, StoreError> {
        const UNREADABLE: StoreError = StoreError("the current generation record cannot be read");
        const BROKEN: StoreError = StoreError("the current generation record is broken");
        let record = match read_regular(&self.dir.join("current"), CURRENT_LEN) {
            Ok(record) => record,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(UNREADABLE),
        };
        match record.split_last() {
            Some((b'\n', hex)) => Fingerprint::from_hex(hex).map(Some).ok_or(BROKEN),
            _ => Err(BROKEN),
        }
    }

    /// `<dir>/generations/<digits>`, after `lstat` has shown that `generations` and the generation are real
    /// directories. The content of the generation is not looked at.
    fn generation_dir(&self, generation: Fingerprint) -> Result<PathBuf, StoreError> {
        let is_dir = |path: &Path| fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_dir());
        let generations = self.dir.join("generations");
        if !is_dir(&generations) {
            return Err(StoreError(
                "the generations directory is not a real directory",
            ));
        }
        let path = generations.join(generation.hex());
        if !is_dir(&path) {
            return Err(StoreError("the generation is not a real directory"));
        }
        Ok(path)
    }
}

/// The content of the regular file at `path`, which must not be a link and must be at most `limit` bytes. The
/// kind of fault is `InvalidData` for a file that is not regular, is over the limit or changed its size while it
/// was read; the faults of the file system keep their own kind (`NotFound` for an absent file).
pub(super) fn read_regular(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    // O_NONBLOCK: opening a FIFO must not wait for a writer; the check of the file type below then refuses it.
    // It does not affect reads of a regular file. std adds close-on-exec.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a regular file",
        ));
    }
    if meta.len() > limit {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "too large"));
    }
    let mut bytes = Vec::new();
    file.take(meta.len().saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).ok() != Some(meta.len()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "size changed while reading",
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;
