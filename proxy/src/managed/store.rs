//! The managed store in its directory: the versions, the files they name, the record of the chosen version and the
//! lock, and the certificates of the sites with `acme` (see `managed` for the form). The writes of the versions, the
//! files and the record are made by the commands of `managed`, by the admin process when it saves a version (the
//! files and the version, through `import::place`, as `managed import` does) and by its order (`apply`), which hold
//! the lock; the certificates of the sites with `acme` are written by the command `acme renew`, which does not take
//! it, for it touches no version and no record. The readings take no lock, for every name they read is replaced whole
//! or not at all.

use std::fs::{self, DirBuilder, File, TryLockError};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::config;
use crate::rules::bundle::{Fingerprint, hex, sha256};
use crate::rules::file_store::{open_lock_file, read_regular, sync_dir, write_new};
use crate::rules::store::StoreError;
use crate::run::host;

/// The largest version and the largest file of the store, in bytes.
pub const MAX_BYTES: u64 = 1 << 20;
/// The size of `current`: 64 hexadecimal digits and a newline.
const CURRENT_LEN: u64 = 65;
const VERSIONS: &str = "versions";
const FILES: &str = "files";
const CURRENT: &str = "current";
const CURRENT_NEW: &str = "current.new";
const LOCK: &str = "lock";
/// What follows the name of a version.
const VERSION_END: &str = ".json";
/// The directory of the certificates of the sites with `acme`, and the names of the two files of a site in it.
const ACME: &str = "acme";
const CHAIN: &str = "chain";
const KEY: &str = "key";

/// The chain and the key of a site with `acme`, as the store has them.
pub type Issued = (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>);

/// The name of the directory of `acme/` for a site with `acme` and these `hosts`: the SHA-256 of the hosts in byte
/// order, each followed by a newline. The same hosts in any order have the same name; the name of the site is no part
/// of it.
pub fn acme_name(hosts: &[String]) -> [u8; 32] {
    let mut sorted: Vec<&str> = hosts.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    let mut bytes = Vec::new();
    for host in sorted {
        bytes.extend_from_slice(host.as_bytes());
        bytes.push(b'\n');
    }
    sha256(&bytes)
}

/// Why the managed store refused: a fixed English sentence, never a path or a value read from the store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManagedError(pub &'static str);

/// Why `lock` refuses a lock that another holds.
pub const IN_USE: ManagedError = ManagedError("the managed store is in use by another command");

/// Why `choose_if_current` refuses when `current` does not name the version that the caller saw as chosen.
pub const NOT_CURRENT: ManagedError =
    ManagedError("the chosen managed version is not the one that was expected");

/// What a write found at its name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placed {
    /// Nothing; the bytes are there now.
    Created,
    /// The same bytes, which are left as they are.
    Existing,
    /// Something else than the bytes its name says, which the bytes replaced.
    Recreated,
}

/// A version of the store, as `versions` lists it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Listed {
    pub name: [u8; 32],
    /// When the version was made, in seconds since the epoch.
    pub made: i64,
}

/// The kinds of the entries of the store that are written by their content: a version and a file.
#[derive(Clone, Copy)]
enum Kind {
    Version,
    File,
}

impl Kind {
    /// The directory of the kind in the store, and what follows the name of an entry.
    fn place(self) -> (&'static str, &'static str) {
        match self {
            Kind::Version => (VERSIONS, VERSION_END),
            Kind::File => (FILES, ""),
        }
    }
}

/// The managed store in a directory of the file system.
#[derive(Clone, Debug)]
pub struct Store {
    dir: PathBuf,
}

impl Store {
    /// Opens the store in `dir`, which must be an absolute clean path: only `dir` is examined, by `lstat`, as
    /// `host::private_dir` does (a real directory without group or other permission bits, owned by the user that the
    /// file system sees for this process).
    pub fn open(dir: &Path) -> Result<Store, ManagedError> {
        if !config::clean_abs(dir) {
            return Err(ManagedError(
                "the managed store directory is not an absolute clean path",
            ));
        }
        let uid = host::fs_uid().map_err(ManagedError)?;
        Store::open_as(dir, uid)
    }

    /// `open` for a directory that must be owned by `uid`. The tests give a user id other than the owner's: a
    /// directory of another owner cannot be made without privilege.
    fn open_as(dir: &Path, uid: u32) -> Result<Store, ManagedError> {
        host::private_dir(dir, uid).map_err(ManagedError)?;
        Ok(Store {
            dir: dir.to_path_buf(),
        })
    }

    /// Takes the lock without waiting; the file is made when it is not there. It is opened like every file that is
    /// read, so a link or a FIFO in its place is refused. The lock lasts as long as the file that is returned.
    pub fn lock(&self) -> Result<File, ManagedError> {
        let file = open_lock_file(
            &self.dir.join(LOCK),
            StoreError("the lock of the managed store cannot be opened"),
            StoreError("the lock of the managed store is not a regular file"),
        )
        .map_err(|e| ManagedError(e.0))?;
        match file.try_lock() {
            Ok(()) => Ok(file),
            Err(TryLockError::WouldBlock) => Err(IN_USE),
            Err(TryLockError::Error(_)) => Err(ManagedError(
                "the lock of the managed store cannot be taken",
            )),
        }
    }

    /// Reads `current`: absent is no choice yet; a link, a special file, a file over 65 bytes or any failure to read
    /// it is a refusal, and so is a content other than 64 lowercase digits and one newline.
    pub fn current(&self) -> Result<Option<[u8; 32]>, ManagedError> {
        const UNREADABLE: ManagedError =
            ManagedError("the current managed version record cannot be read");
        const BROKEN: ManagedError = ManagedError("the current managed version record is broken");
        let record = match read_regular(&self.dir.join(CURRENT), CURRENT_LEN, None) {
            Ok(record) => record,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(UNREADABLE),
        };
        match record.split_last() {
            Some((b'\n', digits)) => Fingerprint::from_hex(digits)
                .map(|name| Some(name.bytes()))
                .ok_or(BROKEN),
            _ => Err(BROKEN),
        }
    }

    /// The bytes of the version `name`, which are what the name says.
    pub fn version(&self, name: [u8; 32]) -> Result<Vec<u8>, ManagedError> {
        self.real_dir(Kind::Version)?;
        let bytes =
            read_regular(&self.path(Kind::Version, name), MAX_BYTES, None).map_err(|e| {
                ManagedError(match e.kind() {
                    io::ErrorKind::NotFound => "the managed version is not in the store",
                    io::ErrorKind::InvalidData => {
                        "the managed version is not a regular file of at most 1 MiB"
                    }
                    _ => "the managed version cannot be read, or is a link",
                })
            })?;
        if sha256(&bytes) != name {
            return Err(ManagedError("the managed version does not match its name"));
        }
        Ok(bytes)
    }

    /// The bytes of the file `name` (a certificate chain, a private key or a file of authorities), which are what the
    /// name says. They are overwritten with zeros when they are dropped.
    pub fn file(&self, name: [u8; 32]) -> Result<Zeroizing<Vec<u8>>, ManagedError> {
        self.real_dir(Kind::File)?;
        let bytes = Zeroizing::new(
            read_regular(&self.path(Kind::File, name), MAX_BYTES, None).map_err(|e| {
                ManagedError(match e.kind() {
                    io::ErrorKind::NotFound => "a managed file is not in the store",
                    io::ErrorKind::InvalidData => {
                        "a managed file is not a regular file of at most 1 MiB"
                    }
                    _ => "a managed file cannot be read, or is a link",
                })
            })?,
        );
        if sha256(&bytes) != name {
            return Err(ManagedError("a managed file does not match its name"));
        }
        Ok(bytes)
    }

    /// Where the file `name` is, for the tests that change what is there.
    #[cfg(test)]
    pub(crate) fn file_path(&self, name: [u8; 32]) -> PathBuf {
        self.path(Kind::File, name)
    }

    /// The chain and the key of the site with `acme` whose hosts have the name `name` (see `acme_name`), each read
    /// without following a link and at most 1 MiB, and overwritten with zeros when they are dropped. `None` when
    /// `acme/`, its directory `name` or one of the two files is not there: the certificate has not been issued yet.
    /// Everything else is a refusal, never `None`: a link or anything but a directory in the place of a directory, a
    /// link or a special file in the place of a file, a file over 1 MiB, and a failure to look at or read one.
    pub fn issued(&self, name: [u8; 32]) -> Result<Option<Issued>, ManagedError> {
        let acme = self.dir.join(ACME);
        let site = acme.join(hex(&name));
        for dir in [&acme, &site] {
            match fs::symlink_metadata(dir) {
                Ok(meta) if meta.file_type().is_dir() => {}
                Ok(_) => {
                    return Err(ManagedError(
                        "a directory of the managed store is not a real directory",
                    ));
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(_) => {
                    return Err(ManagedError(
                        "a directory of the managed store cannot be looked at",
                    ));
                }
            }
        }
        let read = |file: &str| match read_regular(&site.join(file), MAX_BYTES, None) {
            Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) if e.kind() == io::ErrorKind::InvalidData => Err(ManagedError(
                "an issued certificate or key is not a regular file of at most 1 MiB",
            )),
            Err(_) => Err(ManagedError(
                "an issued certificate or key cannot be read, or is a link",
            )),
        };
        match (read(CHAIN)?, read(KEY)?) {
            (Some(chain), Some(key)) => Ok(Some((chain, key))),
            _ => Ok(None),
        }
    }

    /// The versions, oldest first: the regular files of `versions/` whose name is 64 lowercase digits and `.json`.
    pub fn versions(&self) -> Result<Vec<Listed>, ManagedError> {
        const CANNOT: ManagedError = ManagedError("the managed versions cannot be listed");
        let dir = self.dir.join(VERSIONS);
        match fs::symlink_metadata(&dir) {
            Ok(meta) if meta.file_type().is_dir() => {}
            Ok(_) => {
                return Err(ManagedError(
                    "a directory of the managed store is not a real directory",
                ));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => return Err(CANNOT),
        }
        let mut found = Vec::new();
        for entry in fs::read_dir(&dir).map_err(|_| CANNOT)? {
            let entry = entry.map_err(|_| CANNOT)?;
            let file_name = entry.file_name();
            let Some(name) = file_name
                .as_bytes()
                .strip_suffix(VERSION_END.as_bytes())
                .and_then(Fingerprint::from_hex)
            else {
                continue;
            };
            // Not followed: a link is no version.
            let meta = entry.metadata().map_err(|_| CANNOT)?;
            if meta.file_type().is_file() {
                found.push(Listed {
                    name: name.bytes(),
                    made: meta.mtime(),
                });
            }
        }
        found.sort_by_key(|listed| (listed.made, listed.name));
        Ok(found)
    }

    /// Puts `bytes` in `files/` under their SHA-256, which it returns. The caller holds the lock.
    pub fn put_file(&self, bytes: &[u8]) -> Result<([u8; 32], Placed), ManagedError> {
        self.put(Kind::File, bytes)
    }

    /// Puts `bytes` in `versions/` under their SHA-256, which it returns. The caller holds the lock, and has checked
    /// the bytes as a version.
    pub fn put_version(&self, bytes: &[u8]) -> Result<([u8; 32], Placed), ManagedError> {
        self.put(Kind::Version, bytes)
    }

    /// Chooses the version `name`, after it is read as `version` reads it. The caller holds the lock.
    pub fn choose(&self, name: [u8; 32]) -> Result<(), ManagedError> {
        const CANNOT: ManagedError =
            ManagedError("the current managed version record cannot be written");
        self.version(name)?;
        let new = self.dir.join(CURRENT_NEW);
        match fs::remove_file(&new) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(CANNOT),
        }
        let record = format!("{}\n", hex(&name));
        write_new(&new, record.as_bytes())
            .and_then(|()| fs::rename(&new, self.dir.join(CURRENT)))
            .and_then(|()| sync_dir(&self.dir))
            .map_err(|_| {
                let _ = fs::remove_file(&new);
                CANNOT
            })
    }

    /// `choose`, but only if `current` names `expect`: the record is read and the version chosen while the caller holds
    /// the lock, which this does not take (a lock of the store is refused to a second taker in the same process as
    /// well), so nothing that changes the store comes in between. Another version, or none, is refused with
    /// `NOT_CURRENT`.
    pub fn choose_if_current(&self, expect: [u8; 32], name: [u8; 32]) -> Result<(), ManagedError> {
        if self.current()? != Some(expect) {
            return Err(NOT_CURRENT);
        }
        self.choose(name)
    }

    /// The places of the chain and of the key of the site with `acme` whose hosts have the name `name`, for the command
    /// `acme renew` to write the two files there: `acme/` and then its directory `name` are made (0700) when they are
    /// not there, and refused when what is there is not a real directory, for a file that is written beside its place
    /// would be written through a link. The command looks before it orders the certificate.
    pub fn issue_places(&self, name: [u8; 32]) -> Result<(PathBuf, PathBuf), ManagedError> {
        self.ensure_dir(ACME)?;
        let site = self.ensure_dir(&format!("{ACME}/{}", hex(&name)))?;
        Ok((site.join(CHAIN), site.join(KEY)))
    }

    /// Refuses a directory of the kind that is not a real directory: a name is opened without following a link, and so
    /// is the directory it is in. One that is not there is left to the reading of the name, which does not find it.
    fn real_dir(&self, kind: Kind) -> Result<(), ManagedError> {
        let (dir, _) = kind.place();
        match fs::symlink_metadata(self.dir.join(dir)) {
            Ok(meta) if !meta.file_type().is_dir() => Err(ManagedError(
                "a directory of the managed store is not a real directory",
            )),
            _ => Ok(()),
        }
    }

    fn path(&self, kind: Kind, name: [u8; 32]) -> PathBuf {
        let (dir, end) = kind.place();
        self.dir.join(dir).join(format!("{}{end}", hex(&name)))
    }

    /// The order: the size, the directory of the kind (made when it is not there), what is at the name (kept if it is
    /// the bytes), then the bytes written to `<name>.new`, synced and renamed over the name, and the directory synced.
    /// A `.new` that an earlier command left is removed first, and one that is written in part is removed again.
    fn put(&self, kind: Kind, bytes: &[u8]) -> Result<([u8; 32], Placed), ManagedError> {
        const CANNOT: ManagedError =
            ManagedError("an entry of the managed store cannot be written");
        if !u64::try_from(bytes.len()).is_ok_and(|n| n <= MAX_BYTES) {
            return Err(ManagedError(match kind {
                Kind::Version => "the managed version is over 1 MiB",
                Kind::File => "a managed file is over 1 MiB",
            }));
        }
        let name = sha256(bytes);
        let (dir, _) = kind.place();
        let dir = self.ensure_dir(dir)?;
        let target = self.path(kind, name);
        let found = match fs::symlink_metadata(&target) {
            Ok(_) => true,
            Err(e) if e.kind() == io::ErrorKind::NotFound => false,
            Err(_) => return Err(CANNOT),
        };
        if found {
            let sound = match kind {
                Kind::Version => self.version(name).is_ok(),
                Kind::File => self.file(name).is_ok(),
            };
            if sound {
                return Ok((name, Placed::Existing));
            }
        }
        let mut new = target.clone().into_os_string();
        new.push(".new");
        let new = PathBuf::from(new);
        match fs::remove_file(&new) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(CANNOT),
        }
        // A rename puts the new file over a broken one, or over a link, in one step; over a directory it fails.
        write_new(&new, bytes)
            .and_then(|()| fs::rename(&new, &target))
            .and_then(|()| sync_dir(&dir))
            .map_err(|_| {
                let _ = fs::remove_file(&new);
                CANNOT
            })?;
        Ok((
            name,
            if found {
                Placed::Recreated
            } else {
                Placed::Created
            },
        ))
    }

    /// `<dir>/<name>`, made (0700) when it is not there, and the directory it is made in synced; whatever else is there
    /// is refused. Only the last component of `name` is looked at without following a link, so for a `name` of two
    /// components the caller has made sure of the first one before.
    fn ensure_dir(&self, name: &str) -> Result<PathBuf, ManagedError> {
        let path = self.dir.join(name);
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_dir() => Ok(path),
            Ok(_) => Err(ManagedError(
                "a directory of the managed store is not a real directory",
            )),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let parent = path.parent().unwrap_or(self.dir.as_path());
                DirBuilder::new()
                    .mode(0o700)
                    .create(&path)
                    .and_then(|()| sync_dir(parent))
                    .map_err(|_| ManagedError("a directory of the managed store cannot be made"))?;
                Ok(path)
            }
            Err(_) => Err(ManagedError(
                "a directory of the managed store cannot be looked at",
            )),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
