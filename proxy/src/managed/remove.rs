//! The removal of a version from the store (`remove`), which the command `managed remove` and the admin process take,
//! with the cleaning of what no version names any more that comes with it.
//!
//! The steps, with the lock of the store held to the end, so that nothing else changes the store meanwhile:
//! 1. The lock: held by another, the store is in use.
//! 2. `current`: the version it names is not removed; a record that cannot be read, or is broken, removes nothing.
//!    None is no hindrance.
//! 3. The version: `versions/` is a real directory, and the name of the version in it is a regular file, which is
//!    looked at without following a link and is not read, so that a broken version can be removed as well.
//! 4. The exclusive lock on its file, without waiting: a version that the proxy serves with or a command reads holds
//!    the shared lock (see `Store::hold`), and is in use.
//! 5. What the other versions name (see `version`), each read as the proxy reads a version, without the main file. A
//!    version that cannot be read leaves that unknown, and the removal goes on without the cleaning.
//! 6. The version is removed and `versions/` synced, while the exclusive lock is held still.
//! 7. If step 5 knows what the other versions name, the store is cleaned (`Store::clean`): the files of `files/` and
//!    the directories of `acme/` that none of them names, and what a write that stopped halfway left. A file or a
//!    directory that two versions name stays when one of them goes.
//!
//! What a removal comes to is that the version is gone, and whether the cleaning went whole (`Removed::cleaned`). A
//! cleaning that did not go whole undoes nothing, the removal included: the next removal cleans again.
//!
//! A version is held, so that it is not removed and what it names is not cleaned up, by the proxy (the version that it
//! serves with, and the one that a reading of its configuration again reads), by `acme renew` to its end, and by
//! `config check` and `managed activate` while they read it (see `load`). The readings of the admin process, which
//! checks a version that is not in the store yet, and those of the cleaning hold no lock. A proxy built before
//! versions were held holds nothing, so the version it serves with can be removed.

use std::collections::BTreeSet;

use super::store::{ManagedError, Store};
use super::version;

/// What versions name outside themselves: the names of the files of the store, and those of the directories of
/// `acme/`.
type Named = (BTreeSet<[u8; 32]>, BTreeSet<[u8; 32]>);

/// A version that `remove` removed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Removed {
    /// Whether the store was cleaned whole as well.
    pub cleaned: bool,
}

/// Removes the version `name` from `store`, in the order of the module documentation.
pub fn remove(store: &Store, name: [u8; 32]) -> Result<Removed, ManagedError> {
    let _lock = store.lock()?;
    if store.current()? == Some(name) {
        return Err(ManagedError("the managed version is the current one"));
    }
    let claimed = store.claim(name)?;
    let named = named(store, name);
    store.remove_version(name)?;
    drop(claimed);
    let cleaned = match named {
        Some((files, issued)) => store.clean(&files, &issued),
        None => false,
    };
    Ok(Removed { cleaned })
}

/// What the versions of `store` but `removed` name: the files and the directories of `acme/` (see
/// `version::RawVersion::names`). None when the versions cannot be listed or one of them cannot be read.
fn named(store: &Store, removed: [u8; 32]) -> Option<Named> {
    let (mut files, mut issued) = (BTreeSet::new(), BTreeSet::new());
    for listed in store.versions().ok()? {
        if listed.name == removed {
            continue;
        }
        let bytes = store.version(listed.name).ok()?;
        version::parse(&bytes).ok()?.names(&mut files, &mut issued);
    }
    Some((files, issued))
}

#[cfg(test)]
mod tests;
