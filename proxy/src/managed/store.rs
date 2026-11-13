//! The managed store in its directory: the versions, the files they name, the record of the chosen version and the
//! lock, and the certificates of the sites with `acme` (see `managed` for the form). The writes of the versions, the
//! files and the record are made by the commands of `managed`, by the admin process when it saves a version (the
//! files and the version, through `import::place`, as `managed import` does) and by its order (`apply`), which hold
//! the lock, and so are the removal of a version and the cleaning that comes with it (`remove`, which `managed remove`
//! and the admin process take). The certificates of the sites with `acme` are written by the command `acme renew`,
//! which does not take it, for it touches no version and no record. A reading takes no lock of the store, for every
//! name it reads is replaced whole or not at all. A version that is read to be served with or used is read with a
//! shared lock on its own file (`hold`), which keeps `remove` from removing it, and `put` from replacing a broken copy
//! of it, while it is held. What the cleaning removes is named by no version that is left, so whatever holds a version
//! loses no file of it. The admin process reads the chain of a site to show it, and of its key it only looks at
//! whether it is there (`look_file`, `issued_key`).

use std::collections::BTreeSet;
use std::fs::{self, DirBuilder, File, TryLockError};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::config;
use crate::rules::bundle::{Fingerprint, hex, sha256};
use crate::rules::file_store::{
    open_lock_file, open_read, read_opened, read_regular, sync_dir, write_new,
};
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
/// What follows the name of an entry that is being written (see `put`).
const NEW_END: &str = ".new";

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

/// Why a file is refused that is not there (see `file` and `look_file`).
pub const FILE_NOT_IN_STORE: ManagedError = ManagedError("a managed file is not in the store");

/// Why a version is refused that is not there, or not any more.
const NOT_IN_STORE: ManagedError = ManagedError("the managed version is not in the store");
/// Why a version is not removed, or not replaced, while another holds the lock of its file (see `Hold`).
const VERSION_IN_USE: ManagedError = ManagedError("the managed version is in use");
/// Why the lock of the file of a version is refused when it is not held by another.
const NO_VERSION_LOCK: ManagedError =
    ManagedError("the lock of the managed version cannot be taken");

/// A version that was read with a shared lock on its file (see `Store::hold`). While it lives, the version is not
/// removed and a broken copy of it is not replaced, for both take the exclusive lock first; dropping it gives the
/// version back.
#[derive(Debug)]
pub struct Hold {
    _file: File,
}

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
        let bytes = read_regular(&self.path(Kind::Version, name), MAX_BYTES, None)
            .map_err(version_fault)?;
        if sha256(&bytes) != name {
            return Err(ManagedError("the managed version does not match its name"));
        }
        Ok(bytes)
    }

    /// The bytes of the version `name`, as `version` reads them, with a shared lock on its file that lasts as long as
    /// the `Hold`: what the proxy and the commands read a version with that they serve with or use, so that it is not
    /// removed from under them. Nothing is made or written. The order: the file is opened to be read, the lock is
    /// taken on it without waiting (one whose file another holds the exclusive lock of, see `claim`, is being removed
    /// or replaced), the bytes are read from the same file and checked against the name, and then the name is looked
    /// at again: a lock on a file that was removed or replaced after it was opened holds nothing, and that version is
    /// not in the store.
    pub fn hold(&self, name: [u8; 32]) -> Result<(Vec<u8>, Hold), ManagedError> {
        let file = self.open_version(name)?;
        self.hold_opened(name, file)
    }

    /// The file of the version `name`, opened to be read without following a link (see `hold`).
    fn open_version(&self, name: [u8; 32]) -> Result<File, ManagedError> {
        self.real_dir(Kind::Version)?;
        open_read(&self.path(Kind::Version, name)).map_err(version_fault)
    }

    /// The rest of `hold`, for the file of the version `name` that `open_version` opened.
    fn hold_opened(&self, name: [u8; 32], file: File) -> Result<(Vec<u8>, Hold), ManagedError> {
        match file.try_lock_shared() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(ManagedError(
                    "the managed version is being removed or replaced",
                ));
            }
            Err(TryLockError::Error(_)) => return Err(NO_VERSION_LOCK),
        }
        let bytes = read_opened(&file, MAX_BYTES, None).map_err(version_fault)?;
        if sha256(&bytes) != name {
            return Err(ManagedError("the managed version does not match its name"));
        }
        let opened = file.metadata().map_err(version_fault)?;
        match fs::symlink_metadata(self.path(Kind::Version, name)) {
            Ok(meta) if (meta.dev(), meta.ino()) == (opened.dev(), opened.ino()) => {
                Ok((bytes, Hold { _file: file }))
            }
            _ => Err(NOT_IN_STORE),
        }
    }

    /// The exclusive lock on the file of the version `name`, taken without waiting, which lasts as long as the file
    /// that is returned: what `remove` holds while it removes the version, and `put` while it replaces a broken one. A
    /// version that is not there is refused, and so is one that is not a regular file, which is not read (a link is
    /// not followed); one whose file another holds the lock of (see `Hold`) is in use.
    pub(super) fn claim(&self, name: [u8; 32]) -> Result<File, ManagedError> {
        self.real_dir(Kind::Version)?;
        let path = self.path(Kind::Version, name);
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_file() => {}
            Ok(_) => return Err(ManagedError("the managed version is not a regular file")),
            Err(e) => return Err(version_fault(e)),
        }
        let file = open_read(&path).map_err(|_| NO_VERSION_LOCK)?;
        match file.try_lock() {
            Ok(()) => Ok(file),
            Err(TryLockError::WouldBlock) => Err(VERSION_IN_USE),
            Err(TryLockError::Error(_)) => Err(NO_VERSION_LOCK),
        }
    }

    /// Removes the version `name` from `versions/`, and syncs the directory. The caller holds the lock of the store
    /// and the exclusive lock of the version (`claim`).
    pub(super) fn remove_version(&self, name: [u8; 32]) -> Result<(), ManagedError> {
        let (dir, _) = Kind::Version.place();
        fs::remove_file(self.path(Kind::Version, name))
            .and_then(|()| sync_dir(&self.dir.join(dir)))
            .map_err(|_| ManagedError("the managed version cannot be removed"))
    }

    /// The bytes of the file `name` (a certificate chain, a private key or a file of authorities), which are what the
    /// name says. They are overwritten with zeros when they are dropped.
    pub fn file(&self, name: [u8; 32]) -> Result<Zeroizing<Vec<u8>>, ManagedError> {
        self.real_dir(Kind::File)?;
        let bytes = Zeroizing::new(
            read_regular(&self.path(Kind::File, name), MAX_BYTES, None).map_err(file_fault)?,
        );
        if sha256(&bytes) != name {
            return Err(ManagedError("a managed file does not match its name"));
        }
        Ok(bytes)
    }

    /// Looks whether the file `name` is there, and at nothing more: a regular file of at most 1 MiB, looked at without
    /// following a link and neither opened nor read, so neither whether it can be read (its permissions) nor its bytes
    /// against its name are looked at. What the admin process looks at for the private key of a site, which it does not
    /// read. The refusals are those of `file`; one that is not there is `FILE_NOT_IN_STORE`.
    pub fn look_file(&self, name: [u8; 32]) -> Result<(), ManagedError> {
        self.real_dir(Kind::File)?;
        look_regular(&self.path(Kind::File, name)).map_err(file_fault)
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
        let Some(site) = self.issued_dir(name)? else {
            return Ok(None);
        };
        let read = |file: &str| {
            issued_fault(read_regular(&site.join(file), MAX_BYTES, None).map(Zeroizing::new))
        };
        match (read(CHAIN)?, read(KEY)?) {
            (Some(chain), Some(key)) => Ok(Some((chain, key))),
            _ => Ok(None),
        }
    }

    /// The chain of the site with `acme` whose hosts have the name `name`, as `issued` reads it, without its key: what
    /// the admin process reads to show the certificate. `None` when `acme/`, its directory `name` or the chain is not
    /// there; the refusals are those of `issued`.
    pub fn issued_chain(&self, name: [u8; 32]) -> Result<Option<Zeroizing<Vec<u8>>>, ManagedError> {
        let Some(site) = self.issued_dir(name)? else {
            return Ok(None);
        };
        issued_fault(read_regular(&site.join(CHAIN), MAX_BYTES, None).map(Zeroizing::new))
    }

    /// Whether the key of the site with `acme` whose hosts have the name `name` is there, as `look_file` looks at a
    /// file: a regular file of at most 1 MiB, neither opened nor read, so whether it can be read (its permissions) is
    /// not looked at. False when `acme/`, its directory `name` or the key is not there; the refusals are those of
    /// `issued`.
    pub fn issued_key(&self, name: [u8; 32]) -> Result<bool, ManagedError> {
        let Some(site) = self.issued_dir(name)? else {
            return Ok(false);
        };
        Ok(issued_fault(look_regular(&site.join(KEY)))?.is_some())
    }

    /// The directory of the site with `acme` whose hosts have the name `name`, for `issued` and the two above, after
    /// `acme/` and then it are looked at without following a link: `None` when either is not there, and a refusal
    /// when either is anything but a real directory or cannot be looked at.
    fn issued_dir(&self, name: [u8; 32]) -> Result<Option<PathBuf>, ManagedError> {
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
        Ok(Some(site))
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

    /// Cleans the store for `remove`, which holds its lock: the files of `files/` whose names no version names
    /// (`files`), the directories of `acme/` whose names no version names (`issued`, see `acme_name`), and what a write
    /// that stopped halfway left in `files/` and `versions/` (`<name>.new`). A name is removed without following a
    /// link; a directory in `files/`, a link in `acme/` and every other name are left. Each directory is synced after
    /// its removals. Whether all of it went: a directory of the store that is not a real one is not cleaned, and a
    /// directory of `acme/` that holds anything else is left.
    pub(super) fn clean(&self, files: &BTreeSet<[u8; 32]>, issued: &BTreeSet<[u8; 32]>) -> bool {
        let files = self.sweep(Kind::File, Some(files));
        let versions = self.sweep(Kind::Version, None);
        let issued = self.clean_issued(issued);
        files && versions && issued
    }

    /// The part of `clean` for the directory of `kind`: the names of a write that stopped halfway, and with `named` the
    /// entries whose names it has not.
    fn sweep(&self, kind: Kind, named: Option<&BTreeSet<[u8; 32]>>) -> bool {
        let (dir, end) = kind.place();
        let dir = self.dir.join(dir);
        match fs::symlink_metadata(&dir) {
            Ok(meta) if meta.file_type().is_dir() => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return true,
            _ => return false,
        }
        let Ok(entries) = fs::read_dir(&dir) else {
            return false;
        };
        let (mut whole, mut removed) = (true, false);
        for entry in entries {
            // An entry that cannot be read stops the look; what went before it is synced all the same.
            let Ok(entry) = entry else {
                whole = false;
                break;
            };
            let file_name = entry.file_name();
            let text = file_name.as_bytes();
            let gone = match text.strip_suffix(NEW_END.as_bytes()) {
                Some(stem) => entry_name(stem, end).is_some(),
                None => named.is_some_and(|named| {
                    entry_name(text, end).is_some_and(|name| !named.contains(&name))
                }),
            };
            if !gone {
                continue;
            }
            // Not followed: a link goes as a name, and a directory stays.
            match entry.file_type() {
                Ok(found) if !found.is_dir() => {}
                Ok(_) => continue,
                Err(_) => {
                    whole = false;
                    continue;
                }
            }
            match fs::remove_file(entry.path()) {
                Ok(()) => removed = true,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(_) => whole = false,
            }
        }
        if removed && sync_dir(&dir).is_err() {
            whole = false;
        }
        whole
    }

    /// The part of `clean` for `acme/`: its real directories whose names `named` has not (see `remove_issued`).
    fn clean_issued(&self, named: &BTreeSet<[u8; 32]>) -> bool {
        let acme = self.dir.join(ACME);
        match fs::symlink_metadata(&acme) {
            Ok(meta) if meta.file_type().is_dir() => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return true,
            _ => return false,
        }
        let Ok(entries) = fs::read_dir(&acme) else {
            return false;
        };
        let (mut whole, mut removed) = (true, false);
        for entry in entries {
            let Ok(entry) = entry else {
                whole = false;
                break;
            };
            let Some(name) = entry_name(entry.file_name().as_bytes(), "") else {
                continue;
            };
            if named.contains(&name) {
                continue;
            }
            // Not followed: a link, and anything but a directory, stays.
            match entry.file_type() {
                Ok(found) if found.is_dir() => {}
                Ok(_) => continue,
                Err(_) => {
                    whole = false;
                    continue;
                }
            }
            if remove_issued(&entry.path()) {
                removed = true;
            } else {
                whole = false;
            }
        }
        if removed && sync_dir(&acme).is_err() {
            whole = false;
        }
        whole
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
            Ok(meta) => Some(meta.file_type()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(_) => return Err(CANNOT),
        };
        if found.is_some() {
            let sound = match kind {
                Kind::Version => self.version(name).is_ok(),
                Kind::File => self.file(name).is_ok(),
            };
            if sound {
                return Ok((name, Placed::Existing));
            }
        }
        // A broken version that is a regular file is held while it is replaced, and is not replaced while another
        // holds it: the holder would go on with the old file, and the new one would be held by nobody. A link, or
        // anything else, is replaced as it is.
        let _claimed = match (kind, found) {
            (Kind::Version, Some(found)) if found.is_file() => Some(self.claim(name)?),
            _ => None,
        };
        let mut new = target.clone().into_os_string();
        new.push(NEW_END);
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
            if found.is_some() {
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

/// The refusal of a version whose file cannot be read: it is not there, it is not a regular file of at most 1 MiB, or
/// any other fault (a link included).
fn version_fault(e: io::Error) -> ManagedError {
    ManagedError(match e.kind() {
        io::ErrorKind::NotFound => NOT_IN_STORE.0,
        io::ErrorKind::InvalidData => "the managed version is not a regular file of at most 1 MiB",
        _ => "the managed version cannot be read, or is a link",
    })
}

/// The refusal of a file of `files/` that cannot be read or looked at: it is not there (`FILE_NOT_IN_STORE`), it is not
/// a regular file of at most 1 MiB, or any other fault (a link included).
fn file_fault(e: io::Error) -> ManagedError {
    match e.kind() {
        io::ErrorKind::NotFound => FILE_NOT_IN_STORE,
        io::ErrorKind::InvalidData => {
            ManagedError("a managed file is not a regular file of at most 1 MiB")
        }
        _ => ManagedError("a managed file cannot be read, or is a link"),
    }
}

/// What the reading or the look of the chain or the key of a site with `acme` comes to: `None` when the file is not
/// there (not issued yet), and a refusal for a file that is not a regular file of at most 1 MiB or any other fault (a
/// link included).
fn issued_fault<T>(found: io::Result<T>) -> Result<Option<T>, ManagedError> {
    match found {
        Ok(found) => Ok(Some(found)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) if e.kind() == io::ErrorKind::InvalidData => Err(ManagedError(
            "an issued certificate or key is not a regular file of at most 1 MiB",
        )),
        Err(_) => Err(ManagedError(
            "an issued certificate or key cannot be read, or is a link",
        )),
    }
}

/// Looks at `path` as `read_regular` reads it, without opening it: a regular file of at most 1 MiB, looked at without
/// following a link. The faults have the kinds of those of `read_regular`: `NotFound` when nothing is there,
/// `InvalidData` for anything but a regular file and for a file over the size, and another kind for a link and for a
/// failure to look.
fn look_regular(path: &Path) -> io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(io::Error::other("a link"));
    }
    if !meta.file_type().is_file() || meta.len() > MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a regular file of at most 1 MiB",
        ));
    }
    Ok(())
}

/// The name of the entry `text` of a directory of the store whose names end with `end`: 64 lowercase hexadecimal digits
/// and `end`, else none.
fn entry_name(text: &[u8], end: &str) -> Option<[u8; 32]> {
    text.strip_suffix(end.as_bytes())
        .and_then(Fingerprint::from_hex)
        .map(|name| name.bytes())
}

/// Removes the directory `dir` of `acme/` that no version names: its chain, its key and the files that `acme renew`
/// writes them to first (`.acme-<16 lowercase hexadecimal digits>.tmp`, see `acme::files`), each as a name, and then
/// the directory, only if all of them went, and if nothing else is in it. A name that cannot be removed does not keep
/// the others from going; an entry that cannot be read stops the look. A directory that stays is synced if something
/// in it went. Whether the directory went.
fn remove_issued(dir: &Path) -> bool {
    let Ok(entries) = fs::read_dir(dir) else {
        return false;
    };
    let (mut whole, mut removed) = (true, false);
    for entry in entries {
        let Ok(entry) = entry else {
            whole = false;
            break;
        };
        let name = entry.file_name();
        let name = name.as_bytes();
        let staged = name
            .strip_prefix(b".acme-")
            .and_then(|rest| rest.strip_suffix(b".tmp"))
            .is_some_and(|digits| {
                digits.len() == 16
                    && digits
                        .iter()
                        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            });
        if !(staged || name == CHAIN.as_bytes() || name == KEY.as_bytes()) {
            continue;
        }
        match fs::remove_file(entry.path()) {
            Ok(()) => removed = true,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(_) => whole = false,
        }
    }
    if whole && fs::remove_dir(dir).is_ok() {
        return true;
    }
    if removed {
        let _ = sync_dir(dir);
    }
    false
}

#[cfg(test)]
pub(crate) mod tests;
