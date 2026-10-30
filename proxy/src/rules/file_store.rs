//! The rules store in a directory of the file system.
//!
//! The directory holds one directory per generation, `generations/<64 lowercase hex digits>/`, which is never
//! changed after it was made, and the file `current`, which names the chosen generation: its 64 digits and a
//! newline. `staging/<32 lowercase hex digits>/` is a bundle between `stage` and `commit` or `discard`, and `lock`
//! is the file that a command holds with `File::try_lock` from `stage` (or `activate` or `remove`) to its end, so that only one
//! command changes the store at a time. `current` is replaced by writing `current.new`, syncing it and renaming it
//! over `current`, and then syncing the directory; a generation becomes visible by one rename from `staging/` after
//! its files and directories were synced.
//!
//! `using/<64 lowercase hex digits>` is an empty file for a generation that a proxy uses or a command removes. A
//! running proxy holds a shared lock on it (`File::try_lock_shared`) for as long as it uses the generation, and
//! `remove` takes the exclusive lock without waiting, so it never removes a generation that a proxy holds. A proxy
//! asks `generation_dir` after it took the lock: a removal that has finished is found there, and one that is
//! going on holds the exclusive lock.
//!
//! Only the store directory itself is examined (a real directory, owned by this process's user, no group or other
//! bits): a user who cannot write there cannot make or replace a name inside it. What is read is opened without
//! following a link and without waiting for a writer. A command that stopped halfway leaves at most a bundle in
//! `staging/` or a `current.new`, which the next `stage` or `activate` removes.

use std::collections::BTreeSet;
use std::fs::{self, DirBuilder, File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use tukuyomi_kernel::Engine;

use crate::config;
use crate::rules::bundle::{
    Bundle, Fingerprint, MANIFEST_NAME, MAX_MANIFEST_BYTES, Manifest, Mode, sha256,
};
use crate::rules::routes::Routes;
use crate::rules::store::{
    Committed, Generation, Hold, NOT_EXPECTED, RuleStore, Staged, StoreError,
};
use crate::run::host;

/// `O_NOFOLLOW` of Linux, which std has no name for. x86_64: the UAPI header `asm-generic/fcntl.h` (and Go's
/// `syscall/zerrors_linux_amd64.go`). aarch64: Go's `syscall/zerrors_linux_arm64.go`, where the value differs.
#[cfg(target_arch = "x86_64")]
pub(crate) const O_NOFOLLOW: i32 = 0o400_000;
#[cfg(target_arch = "aarch64")]
pub(crate) const O_NOFOLLOW: i32 = 0o100_000;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("O_NOFOLLOW is only known for x86_64 and aarch64 Linux");
/// `O_NONBLOCK` of Linux, the same on x86_64 and aarch64 (the same sources as for `O_NOFOLLOW`).
pub(crate) const O_NONBLOCK: i32 = 0o4_000;
/// `O_NOCTTY` of Linux, the same on x86_64 and aarch64 (the same sources as for `O_NOFOLLOW`).
pub(crate) const O_NOCTTY: i32 = 0o400;

/// The size of `current`: 64 hexadecimal digits and a newline.
const CURRENT_LEN: u64 = 65;
/// The length of the name of a bundle in `staging/`.
const STAGE_NAME_LEN: usize = 32;
const GENERATIONS: &str = "generations";
const STAGING: &str = "staging";
const CURRENT: &str = "current";
const CURRENT_NEW: &str = "current.new";
const LOCK: &str = "lock";
const USING: &str = "using";

/// A bundle between `stage` and `commit` or `discard`. The lock lives as long as the descriptor does.
struct Import {
    _lock: File,
    dir: PathBuf,
    fingerprint: Fingerprint,
}

/// A rules store in a directory of the file system.
pub struct FileStore {
    dir: PathBuf,
    import: Option<Import>,
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
            import: None,
        })
    }

    /// Takes the lock without waiting; the file is made when it is not there. It is opened like every file that is
    /// read, so a link or a FIFO in its place is refused.
    fn lock(&self) -> Result<File, StoreError> {
        let file = open_lock_file(
            &self.dir.join(LOCK),
            StoreError("the lock of the rules store cannot be opened"),
            StoreError("the lock of the rules store is not a regular file"),
        )?;
        match file.try_lock() {
            Ok(()) => Ok(file),
            Err(TryLockError::WouldBlock) => {
                Err(StoreError("the rules store is in use by another command"))
            }
            Err(TryLockError::Error(_)) => {
                Err(StoreError("the lock of the rules store cannot be taken"))
            }
        }
    }

    /// The file that marks a generation as used, `using/<digits>`; it and `using/` are made when they are not there.
    fn using_file(&self, generation: Fingerprint) -> Result<File, StoreError> {
        let using = self.ensure_dir(USING)?;
        open_lock_file(
            &using.join(generation.hex()),
            StoreError("the usage lock of the generation cannot be opened"),
            StoreError("the usage lock of the generation is not a regular file"),
        )
    }

    /// `<dir>/<name>`, made (0700) when it is not there; whatever else is there is refused.
    fn ensure_dir(&self, name: &str) -> Result<PathBuf, StoreError> {
        let path = self.dir.join(name);
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_dir() => Ok(path),
            Ok(_) => Err(StoreError(
                "a directory of the rules store is not a real directory",
            )),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                DirBuilder::new()
                    .mode(0o700)
                    .create(&path)
                    .and_then(|()| sync_dir(&self.dir))
                    .map_err(|_| StoreError("a directory of the rules store cannot be made"))?;
                Ok(path)
            }
            Err(_) => Err(StoreError(
                "a directory of the rules store cannot be looked at",
            )),
        }
    }

    /// Chooses `generation`, after `verify`. The lock is held by the caller.
    fn choose(&self, generation: Fingerprint) -> Result<(), StoreError> {
        const CANNOT: StoreError = StoreError("the current generation record cannot be written");
        self.verify(generation)?;
        let new = self.dir.join(CURRENT_NEW);
        match fs::remove_file(&new) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(CANNOT),
        }
        let record = format!("{}\n", generation.hex());
        write_new(&new, record.as_bytes())
            .and_then(|()| fs::rename(&new, self.dir.join(CURRENT)))
            .and_then(|()| sync_dir(&self.dir))
            .map_err(|_| {
                let _ = fs::remove_file(&new);
                CANNOT
            })
    }

    /// Puts the staged bundle at its name in `generations/`, and reports what was there.
    fn place(&self, import: &Import) -> Result<Committed, StoreError> {
        const CANNOT: StoreError = StoreError("the generation cannot be made");
        let generations = self.dir.join(GENERATIONS);
        let target = generations.join(import.fingerprint.hex());
        let found = match fs::symlink_metadata(&target) {
            Ok(_) => true,
            Err(e) if e.kind() == io::ErrorKind::NotFound => false,
            Err(_) => return Err(CANNOT),
        };
        // A generation that is there is kept when it is sound. A broken one is moved out of the way by one rename
        // (a rename onto a directory that holds files would fail), the new one is moved in, and only then the
        // broken one is removed.
        let mut broken = None;
        if found {
            if self.verify(import.fingerprint).is_ok() {
                return Ok(Committed::Existing);
            }
            let away = self.dir.join(STAGING).join(random_name()?);
            fs::rename(&target, &away).map_err(|_| CANNOT)?;
            broken = Some(away);
        }
        fs::rename(&import.dir, &target).map_err(|_| CANNOT)?;
        sync_dir(&generations).map_err(|_| CANNOT)?;
        Ok(match broken {
            Some(away) => {
                // If it cannot be removed now, it stays in `staging` and the next `stage` removes it.
                let _ = remove_entry(&away);
                Committed::Repaired
            }
            None => Committed::Created,
        })
    }
}

impl RuleStore for FileStore {
    /// Reads `current`: absent is no choice yet; a link, a special file, a file over 65 bytes or any failure to
    /// read it is a refusal, and so is a content other than 64 lowercase digits and one newline.
    fn current(&self) -> Result<Option<Fingerprint>, StoreError> {
        const UNREADABLE: StoreError = StoreError("the current generation record cannot be read");
        const BROKEN: StoreError = StoreError("the current generation record is broken");
        let record = match read_regular(&self.dir.join(CURRENT), CURRENT_LEN, None) {
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
        let generations = self.dir.join(GENERATIONS);
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

    /// The order: the lock, the directories of the store (the first `stage` of an empty store makes them), the
    /// removal of the bundles an earlier command left, then the bundle under a name that is chosen at random. A
    /// bundle that was written in part is removed again.
    fn stage(&mut self, bundle: &Bundle) -> Result<Staged, StoreError> {
        if self.import.is_some() {
            return Err(StoreError("a bundle is staged already"));
        }
        let lock = self.lock()?;
        self.ensure_dir(GENERATIONS)?;
        let staging = self.ensure_dir(STAGING)?;
        clear_staging(&staging)?;
        let dir = staging.join(random_name()?);
        if write_stage(&dir, bundle).is_err() {
            // The bundle may be in part there; whatever stays is removed by the next `stage`.
            let _ = remove_entry(&dir);
            return Err(StoreError(
                "the bundle cannot be written to the rules store",
            ));
        }
        let fingerprint = bundle.fingerprint();
        self.import = Some(Import {
            _lock: lock,
            dir: dir.clone(),
            fingerprint,
        });
        Ok(Staged { fingerprint, dir })
    }

    fn commit(&mut self) -> Result<Committed, StoreError> {
        let Some(import) = self.import.take() else {
            return Err(StoreError("no bundle is staged"));
        };
        let committed = self.place(&import);
        // What is left of the staged bundle goes; if it was moved to its name there is nothing at this path.
        let _ = remove_entry(&import.dir);
        committed
    }

    fn discard(&mut self) -> Result<(), StoreError> {
        match self.import.take() {
            Some(import) => remove_entry(&import.dir)
                .map_err(|_| StoreError("the staged bundle cannot be removed")),
            None => Ok(()),
        }
    }

    fn activate(&mut self, generation: Fingerprint) -> Result<(), StoreError> {
        let _lock = self.lock()?;
        self.choose(generation)
    }

    /// The order: the lock, the chosen generation (a record that cannot be read is a refusal, as for `remove`), then
    /// the choice as `activate` makes it.
    fn activate_if_current(
        &mut self,
        expect: Fingerprint,
        generation: Fingerprint,
    ) -> Result<(), StoreError> {
        let _lock = self.lock()?;
        if self.current()? != Some(expect) {
            return Err(NOT_EXPECTED);
        }
        self.choose(generation)
    }

    fn list(&self) -> Result<Vec<Generation>, StoreError> {
        const CANNOT: StoreError = StoreError("the generations cannot be listed");
        let generations = self.dir.join(GENERATIONS);
        match fs::symlink_metadata(&generations) {
            Ok(meta) if meta.file_type().is_dir() => {}
            Ok(_) => {
                return Err(StoreError(
                    "the generations directory is not a real directory",
                ));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => return Err(CANNOT),
        }
        let mut found = Vec::new();
        for entry in fs::read_dir(&generations).map_err(|_| CANNOT)? {
            let entry = entry.map_err(|_| CANNOT)?;
            // Only a real directory under the name of a fingerprint is a generation.
            let Some(fingerprint) = Fingerprint::from_hex(entry.file_name().as_bytes()) else {
                continue;
            };
            let meta = entry.metadata().map_err(|_| CANNOT)?;
            if meta.file_type().is_dir() {
                found.push(Generation {
                    fingerprint,
                    made: meta.mtime(),
                });
            }
        }
        found.sort_by_key(|g| (g.made, g.fingerprint));
        Ok(found)
    }

    fn verify(&self, generation: Fingerprint) -> Result<(), StoreError> {
        let dir = self.generation_dir(generation)?;
        let manifest = read_manifest(&dir, generation)?;
        for entry in manifest.files() {
            let data = read_regular(&dir.join(entry.path.as_str()), entry.size, None)
                .map_err(|_| StoreError("a file of the generation cannot be read"))?;
            if u64::try_from(data.len()).ok() != Some(entry.size) || sha256(&data) != entry.sha256 {
                return Err(StoreError(
                    "a file of the generation differs from its manifest",
                ));
            }
        }
        Ok(())
    }

    fn manifest(&self, generation: Fingerprint) -> Result<Manifest, StoreError> {
        read_manifest(&self.generation_dir(generation)?, generation)
    }

    fn engine(&self, generation: Fingerprint) -> Result<Engine, StoreError> {
        let dir = self.generation_dir(generation)?;
        Ok(read_manifest(&dir, generation)?.engine())
    }

    fn mode(&self, generation: Fingerprint) -> Result<Mode, StoreError> {
        let dir = self.generation_dir(generation)?;
        Ok(read_manifest(&dir, generation)?.mode())
    }

    fn routes(&self, generation: Fingerprint) -> Result<Routes, StoreError> {
        let dir = self.generation_dir(generation)?;
        Ok(read_manifest(&dir, generation)?.routes().clone())
    }

    fn hold(&self, generation: Fingerprint) -> Result<Hold, StoreError> {
        let file = self.using_file(generation)?;
        match file.try_lock_shared() {
            Ok(()) => Ok(Hold::new(file)),
            Err(TryLockError::WouldBlock) => Err(StoreError("the generation is being removed")),
            Err(TryLockError::Error(_)) => Err(StoreError(
                "the usage lock of the generation cannot be taken",
            )),
        }
    }

    /// The order: the lock of the store, the chosen generation (a record that cannot be read leaves it unknown, and
    /// then nothing is removed), the generation, the exclusive lock on its `using` file, then one rename out of
    /// `generations` that is made durable before the files go, as `place` does for a broken generation.
    fn remove(&mut self, generation: Fingerprint) -> Result<(), StoreError> {
        const CANNOT: StoreError = StoreError("the generation cannot be removed");
        let _lock = self.lock()?;
        if self.current()? == Some(generation) {
            return Err(StoreError("the generation is the current one"));
        }
        let dir = self.generation_dir(generation)?;
        let using = self.using_file(generation)?;
        match using.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(StoreError("the generation is used by a running proxy"));
            }
            Err(TryLockError::Error(_)) => {
                return Err(StoreError(
                    "the usage lock of the generation cannot be taken",
                ));
            }
        }
        let away = self.ensure_dir(STAGING)?.join(random_name()?);
        fs::rename(&dir, &away).map_err(|_| CANNOT)?;
        sync_dir(&self.dir.join(GENERATIONS)).map_err(|_| CANNOT)?;
        // If it cannot be removed now, it stays in `staging` and the next `stage` removes it. The `using` file goes
        // while its lock is still held.
        let _ = remove_entry(&away);
        let _ = fs::remove_file(self.dir.join(USING).join(generation.hex()));
        Ok(())
    }
}

/// The manifest of the generation `generation` in `dir`: read as every file is read and at most 64 KiB, the very
/// bytes that the name of the generation says, and in the form of a manifest.
fn read_manifest(dir: &Path, generation: Fingerprint) -> Result<Manifest, StoreError> {
    let bytes = read_regular(&dir.join(MANIFEST_NAME), MAX_MANIFEST_BYTES, None)
        .map_err(|_| StoreError("the manifest of the generation cannot be read"))?;
    if Fingerprint::of(&bytes) != generation {
        return Err(StoreError(
            "the manifest of the generation does not match its name",
        ));
    }
    Manifest::parse(&bytes).map_err(|e| StoreError(e.0))
}

/// Opens the file at `path` that a lock is taken on, and makes it (empty, 0600) when it is not there. It is opened
/// like every file that is read: a link is not followed, a FIFO does not make the open wait, a terminal does not
/// become the controlling terminal, and what is not a regular file is refused. `cannot_open` and `not_regular` are the two sentences of the refusal.
pub(crate) fn open_lock_file(
    path: &Path,
    cannot_open: StoreError,
    not_regular: StoreError,
) -> Result<File, StoreError> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK | O_NOCTTY)
        .open(path)
        .map_err(|_| cannot_open)?;
    if !file.metadata().is_ok_and(|meta| meta.is_file()) {
        return Err(not_regular);
    }
    Ok(file)
}

/// Removes the bundles an earlier command left: the entries of `staging` whose name is 32 lowercase hexadecimal
/// digits and that are real directories (`remove_dir_all` does not follow links either). Other entries are left.
fn clear_staging(staging: &Path) -> Result<(), StoreError> {
    const CANNOT: StoreError =
        StoreError("the staged bundles of the rules store cannot be cleared");
    for entry in fs::read_dir(staging).map_err(|_| CANNOT)? {
        let entry = entry.map_err(|_| CANNOT)?;
        let name = entry.file_name();
        let name = name.as_bytes();
        let ours = name.len() == STAGE_NAME_LEN
            && name.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if ours && entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            fs::remove_dir_all(entry.path()).map_err(|_| CANNOT)?;
        }
    }
    Ok(())
}

/// 16 bytes from `/dev/urandom` as 32 lowercase hexadecimal digits: a name in `staging`.
fn random_name() -> Result<String, StoreError> {
    let mut bytes = [0u8; STAGE_NAME_LEN / 2];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|_| StoreError("no random number is available"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Writes the bundle below `dir`, which must not be there: every directory 0700 and every file 0600, the files
/// and the manifest synced, then the directories.
fn write_stage(dir: &Path, bundle: &Bundle) -> io::Result<()> {
    DirBuilder::new().mode(0o700).create(dir)?;
    let mut made = BTreeSet::new();
    for (path, data) in bundle.files() {
        // The shortest first, so that the parent is there.
        for parent in path.parents() {
            if made.insert(parent.to_owned()) {
                DirBuilder::new().mode(0o700).create(dir.join(parent))?;
            }
        }
        write_new(&dir.join(path.as_str()), data)?;
    }
    write_new(&dir.join(MANIFEST_NAME), bundle.manifest())?;
    for parent in &made {
        sync_dir(&dir.join(parent))?;
    }
    sync_dir(dir)
}

/// A new file of mode 0600 with `data`, synced. It fails if the name is taken, also by a link.
pub(crate) fn write_new(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(data)?;
    file.sync_all()
}

/// Makes the entries of a directory durable.
pub(crate) fn sync_dir(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

/// Removes what is at `path` without following a link: a directory with all it holds, anything else as one name.
fn remove_entry(path: &Path) -> io::Result<()> {
    if fs::symlink_metadata(path)?.file_type().is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    }
}

/// The content of the regular file at `path`, which must not be a link and must be at most `limit` bytes. When
/// `same_as` is the device and inode that an earlier `lstat` of the path gave, the file that was opened must be that
/// one. The kind of fault is `InvalidData` for a file that is not regular, is another one than `same_as`, is over
/// the limit or changed its size while it was read; the faults of the file system keep their own kind (`NotFound`
/// for an absent file).
pub(crate) fn read_regular(
    path: &Path,
    limit: u64,
    same_as: Option<(u64, u64)>,
) -> io::Result<Vec<u8>> {
    // O_NONBLOCK: opening a FIFO must not wait for a writer; the check of the file type below then refuses it.
    // It does not affect reads of a regular file. O_NOCTTY: a terminal that is opened before that check is never
    // made the controlling terminal of the process. std adds close-on-exec.
    let file = OpenOptions::new()
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
    if same_as.is_some_and(|seen| seen != (meta.dev(), meta.ino())) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not the file that was looked at",
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
