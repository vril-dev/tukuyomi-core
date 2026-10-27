//! Where rule generations are kept.
//!
//! A generation is one rule bundle under the name of its fingerprint. The proxy reads the chosen generation
//! (`current`, `generation_dir`) when it starts and again when it is told to switch, and it holds the generation it
//! uses (`hold`) for as long as it uses it. The commands change the store in this order: `stage` writes a bundle
//! where the inspector can read it and takes the lock of the store, the caller tries the bundle, then `commit`
//! makes it a generation or `discard` throws it away, and either gives the lock back. `activate` chooses a
//! generation, `activate_if_current` does so only if the chosen generation is the one the caller saw, `remove`
//! deletes one that is neither chosen nor held, `list`, `verify`, `mode`, `routes` and `manifest` only read.

use std::any::Any;
use std::path::PathBuf;

use crate::config::StoreConfig;
use crate::rules::bundle::{Bundle, Fingerprint, Manifest, Mode};
use crate::rules::file_store::FileStore;
use crate::rules::routes::Routes;

/// Why the rules store refused: a fixed English sentence, never a path or a value read from the store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreError(pub &'static str);

/// Why `activate_if_current` refuses a generation that is not the one the caller saw as chosen.
pub const NOT_EXPECTED: StoreError =
    StoreError("the chosen generation is not the one that was expected");

/// A bundle written for a trial, not yet a generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Staged {
    pub fingerprint: Fingerprint,
    /// The directory of the bundle for the inspector: absolute and clean.
    pub dir: PathBuf,
}

/// What `commit` made of a staged bundle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Committed {
    /// A new generation.
    Created,
    /// The generation was there, and its files are as its manifest says.
    Existing,
    /// The generation was there with files that are not as its manifest says; it was replaced.
    Repaired,
}

/// One generation of the store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Generation {
    pub fingerprint: Fingerprint,
    /// When the generation was made, in seconds since the epoch.
    pub made: i64,
}

/// A generation that a running proxy uses. While it lives, `remove` refuses the generation; dropping it gives the
/// generation back. What it holds is the business of the store that made it.
pub struct Hold {
    _guard: Box<dyn Any>,
}

impl Hold {
    /// A hold that lasts as long as `guard` does.
    pub(crate) fn new(guard: impl Any) -> Hold {
        Hold {
            _guard: Box::new(guard),
        }
    }
}

/// Where rule generations are kept. `FileStore` is the only implementation; the configuration's `kind` picks it.
pub trait RuleStore {
    /// The chosen generation; `Ok(None)` when none was chosen yet.
    fn current(&self) -> Result<Option<Fingerprint>, StoreError>;
    /// The directory of a generation for the inspector: absolute and clean, checked to be a real directory.
    fn generation_dir(&self, generation: Fingerprint) -> Result<PathBuf, StoreError>;
    /// Writes the bundle for a trial and takes the lock of the store, which is kept until `commit` or `discard`.
    /// Staged bundles that an earlier command left are removed first. Only one bundle is staged at a time.
    fn stage(&mut self, bundle: &Bundle) -> Result<Staged, StoreError>;
    /// Makes the staged bundle a generation, or, when the generation is there and sound, keeps that one. A
    /// generation that is there but broken is replaced. Gives the lock back.
    fn commit(&mut self) -> Result<Committed, StoreError>;
    /// Throws the staged bundle away, if there is one, and gives the lock back.
    fn discard(&mut self) -> Result<(), StoreError>;
    /// Chooses a generation, after `verify`. A proxy that runs does not notice; one that starts later uses it.
    fn activate(&mut self, generation: Fingerprint) -> Result<(), StoreError>;
    /// `activate`, but only if the chosen generation is `expect`: it is read and the generation is chosen under the
    /// same lock, so a choice that another process made in between is not overwritten. Another choice, or none, is
    /// refused with `NOT_EXPECTED`.
    fn activate_if_current(
        &mut self,
        expect: Fingerprint,
        generation: Fingerprint,
    ) -> Result<(), StoreError>;
    /// The generations of the store, the oldest first. The lock is not needed.
    fn list(&self) -> Result<Vec<Generation>, StoreError>;
    /// Checks that the manifest of a generation is as its name says and that every file is as the manifest says.
    fn verify(&self, generation: Fingerprint) -> Result<(), StoreError>;
    /// The mode of a generation, from its manifest, which is read and checked as `verify` checks it. The files are
    /// not read.
    fn mode(&self, generation: Fingerprint) -> Result<Mode, StoreError>;
    /// The manifest of a generation, read and checked as `verify` checks it: the files it lists with their sizes and
    /// digests, the order they are loaded in, the mode and the routes. The files are not read.
    fn manifest(&self, generation: Fingerprint) -> Result<Manifest, StoreError>;
    /// The routes of a generation, from its manifest, which is read and checked as `verify` checks it. The files are
    /// not read. The manifest of a generation is the very bytes its name says, so this and `mode` read the same
    /// manifest.
    fn routes(&self, generation: Fingerprint) -> Result<Routes, StoreError>;
    /// Marks the generation as used by a running proxy until the `Hold` is dropped, without waiting. A generation
    /// that is being removed is refused. The generation itself is not looked at: the caller asks `generation_dir`
    /// after the hold is taken, which is how it learns that a removal has finished.
    fn hold(&self, generation: Fingerprint) -> Result<Hold, StoreError>;
    /// Removes a generation that is neither the chosen one nor held. Takes the lock of the store.
    fn remove(&mut self, generation: Fingerprint) -> Result<(), StoreError>;
}

/// Opens the store that the configuration names.
pub fn open(cfg: &StoreConfig) -> Result<Box<dyn RuleStore>, StoreError> {
    match cfg {
        StoreConfig::File { dir } => Ok(Box::new(FileStore::open(dir)?)),
    }
}
