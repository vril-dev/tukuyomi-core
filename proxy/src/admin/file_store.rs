//! The admin store in a directory of the file system.
//!
//! The directory holds `users/<name>.json`, one file for each user (see `users`), `audit/` for the audit log (see
//! `audit`; it is made here, with the others), and `lock`, the file that a write holds with `File::try_lock` from
//! the check to the rename, so that two processes (the admin process and a `bootstrap`) cannot interleave. A write
//! goes to `<name>.json.new` first, which is synced and renamed over `<name>.json`, and then the directory is synced;
//! so a reader sees the old file or the new one, whole. A write that stopped halfway leaves at most a `.json.new`,
//! which the next write to that user removes and which is not a user.
//!
//! `activations.log` is the history of the switches of the rules (see `waf::history`). A line is written whole to the
//! end of the file, which is synced before the write returns, and so is the directory. A line that failed part way is
//! cut off, and a file that does not end with a line feed (a write that a crash stopped) gets one before the next
//! line, so that the lines stay apart. Only the last 1 MiB of the file is read back (`audit::tail`).
//!
//! Only the store directory itself is examined, as the directory of the rules store is: a real directory (not a link)
//! without group or other permission bits, owned by the user that the file system sees for this process. A file is
//! opened without following a link and without waiting for a writer. The files are made 0600 and the directories
//! 0700.

use std::fs::{self, DirBuilder, File, OpenOptions, TryLockError};
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use super::audit::tail;
use super::password::valid_name;
use super::store::{AdminError, AdminStore, BUSY, CONFLICT};
use super::users::User;
use super::waf::history::Activation;
use crate::config;
use crate::rules::file_store::{
    O_NOCTTY, O_NOFOLLOW, O_NONBLOCK, open_lock_file, read_regular, sync_dir, write_new,
};
use crate::rules::store::StoreError;
use crate::run::host;

/// The directory of the audit log, in the store directory.
pub(super) const AUDIT_DIR: &str = "audit";
const USERS: &str = "users";
const LOCK: &str = "lock";
const ACTIVATIONS: &str = "activations.log";
/// The most bytes of a user file.
const USER_MAX: u64 = 4096;

/// An admin store in a directory of the file system.
pub struct FileAdminStore {
    dir: PathBuf,
    /// The writes of this process come one at a time, so that they do not meet at the lock of the store.
    writing: Mutex<()>,
}

impl FileAdminStore {
    /// Opens the store in `dir`, which must be an absolute clean path, and makes the directories it needs.
    pub fn open(dir: &Path) -> Result<FileAdminStore, AdminError> {
        if !config::clean_abs(dir) {
            return Err(AdminError(
                "the admin store directory is not an absolute clean path",
            ));
        }
        let uid = host::fs_uid().map_err(AdminError)?;
        host::private_dir(dir, uid).map_err(AdminError)?;
        let store = FileAdminStore {
            dir: dir.to_path_buf(),
            writing: Mutex::new(()),
        };
        store.ensure_dir(USERS)?;
        store.ensure_dir(AUDIT_DIR)?;
        Ok(store)
    }

    /// `<dir>/<name>`, made (0700) when it is not there; whatever else is there is refused.
    fn ensure_dir(&self, name: &str) -> Result<(), AdminError> {
        let path = self.dir.join(name);
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_dir() => Ok(()),
            Ok(_) => Err(AdminError(
                "a directory of the admin store is not a real directory",
            )),
            Err(e) if e.kind() == io::ErrorKind::NotFound => DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .and_then(|()| sync_dir(&self.dir))
                .map_err(|_| AdminError("a directory of the admin store cannot be made")),
            Err(_) => Err(AdminError(
                "a directory of the admin store cannot be looked at",
            )),
        }
    }

    /// Takes the lock without waiting; the file is made when it is not there.
    fn lock(&self) -> Result<File, AdminError> {
        let file = open_lock_file(
            &self.dir.join(LOCK),
            StoreError("the lock of the admin store cannot be opened"),
            StoreError("the lock of the admin store is not a regular file"),
        )
        .map_err(|e| AdminError(e.0))?;
        match file.try_lock() {
            Ok(()) => Ok(file),
            Err(TryLockError::WouldBlock) => Err(BUSY),
            Err(TryLockError::Error(_)) => {
                Err(AdminError("the lock of the admin store cannot be taken"))
            }
        }
    }

    fn user_path(&self, name: &str) -> PathBuf {
        self.dir.join(USERS).join(format!("{name}.json"))
    }

    /// Whether `users/` holds a file that is a user's, by its name; a broken file is one too.
    fn any_user(&self) -> Result<bool, AdminError> {
        const CANNOT: AdminError = AdminError("the users cannot be listed");
        for entry in fs::read_dir(self.dir.join(USERS)).map_err(|_| CANNOT)? {
            let entry = entry.map_err(|_| CANNOT)?;
            if entry.file_name().as_bytes().ends_with(b".json") {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Writes the file of `user` as described above. The lock is held by the caller.
    fn write_user(&self, user: &User) -> Result<(), AdminError> {
        const CANNOT: AdminError = AdminError("the user file cannot be written");
        let bytes = user.encode()?;
        let users = self.dir.join(USERS);
        let new = users.join(format!("{}.json.new", user.name));
        match fs::remove_file(&new) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(CANNOT),
        }
        write_new(&new, &bytes)
            .and_then(|()| fs::rename(&new, self.user_path(&user.name)))
            .and_then(|()| sync_dir(&users))
            .map_err(|_| {
                let _ = fs::remove_file(&new);
                CANNOT
            })
    }
}

impl AdminStore for FileAdminStore {
    /// Reads `users/<name>.json`: a link, a special file or a file over 4 KiB is a refusal, and so is a content
    /// that is not the user of that name.
    fn user(&self, name: &str) -> Result<Option<User>, AdminError> {
        if !valid_name(name) {
            return Ok(None);
        }
        match read_regular(&self.user_path(name), USER_MAX, None) {
            Ok(bytes) => User::decode(&bytes, name).map(Some),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(AdminError("a user file cannot be read")),
        }
    }

    fn create_first(&self, user: &User) -> Result<(), AdminError> {
        let _writing = self.writing.lock().unwrap_or_else(PoisonError::into_inner);
        let _lock = self.lock()?;
        if self.any_user()? {
            return Err(AdminError("the store has a user already"));
        }
        self.write_user(user)
    }

    fn replace(&self, seen: u64, user: &User) -> Result<(), AdminError> {
        let _writing = self.writing.lock().unwrap_or_else(PoisonError::into_inner);
        let _lock = self.lock()?;
        match self.user(&user.name)? {
            Some(stored) if stored.changed == seen => self.write_user(user),
            Some(_) => Err(CONFLICT),
            None => Err(AdminError("the user is not in the store")),
        }
    }

    fn record_activation(&self, activation: &Activation) -> Result<(), AdminError> {
        const CANNOT: AdminError = AdminError("the history cannot be written");
        let mut line = activation.encode().ok_or(CANNOT)?.into_bytes();
        line.push(b'\n');
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(O_NOFOLLOW | O_NONBLOCK | O_NOCTTY)
            .open(self.dir.join(ACTIVATIONS))
            .map_err(|_| CANNOT)?;
        let meta = file.metadata().map_err(|_| CANNOT)?;
        if !meta.is_file() {
            return Err(CANNOT);
        }
        // A file that a crash stopped in the middle of a line gets its line feed first.
        let mut last = [b'\n'];
        if meta.len() > 0 {
            file.read_exact_at(&mut last, meta.len() - 1)
                .map_err(|_| CANNOT)?;
        }
        if last[0] != b'\n' {
            line.insert(0, b'\n');
        }
        let written = file
            .write_all(&line)
            .and_then(|()| file.sync_all())
            .and_then(|()| sync_dir(&self.dir));
        if written.is_err() {
            let _ = file.set_len(meta.len());
            return Err(CANNOT);
        }
        Ok(())
    }

    fn activations(&self, limit: usize) -> Result<Vec<Activation>, AdminError> {
        match tail(&self.dir.join(ACTIVATIONS)) {
            Ok((bytes, _)) => Ok(bytes
                .rsplit(|&b| b == b'\n')
                .filter_map(Activation::decode)
                .take(limit)
                .collect()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(_) => Err(AdminError("the history cannot be read")),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
