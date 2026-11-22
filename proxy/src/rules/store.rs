//! Where rule generations are kept.
//!
//! A generation is one rule bundle under the name of its fingerprint, and it is for one engine, which its manifest
//! says. Each engine has its own chosen generation (`current`). The proxy reads the chosen generations
//! (`current`, `generation_dir`) when it starts and again when it is told to switch, and it holds the generations it
//! uses (`hold`) for as long as it uses them. The commands change the store in this order: `stage` writes a bundle
//! where the inspector can read it and takes the lock of the store, the caller tries the bundle, then `commit`
//! makes it a generation or `discard` throws it away, and either gives the lock back. `activate` chooses a
//! generation for its engine, `activate_if_current` does so only if the generation chosen for that engine is the one
//! the caller saw (or none, which the caller saw), `deactivate` leaves an engine with none chosen, `remove` deletes
//! one that is not chosen for any engine and not held, `list`, `verify`, `engine`, `mode`, `routes` and `manifest`
//! only read.

use std::any::Any;
use std::path::PathBuf;

use tukuyomi_kernel::Engine;

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

/// Why a configuration is refused whose upstream group has an engine for which no generation is chosen (see
/// `unchosen`).
pub const UNCHOSEN: &str = "no generation is chosen for the engine of an upstream";

/// The engines, in the order of their names.
pub const ENGINES: [Engine; 2] = [Engine::Coraza, Engine::ModSecurity];

/// The place of `engine` in `ENGINES`, which is its place in every table that has one entry for each engine. The
/// `match` names every engine, so an engine that the kernel gets does not build until it has its place here.
pub fn index(engine: Engine) -> usize {
    match engine {
        Engine::Coraza => 0,
        Engine::ModSecurity => 1,
    }
}

/// The engines with `first` first and the others after it in the order of their names: the order in which the start
/// and SIGUSR1 take them.
pub fn engines_from(first: Engine) -> impl Iterator<Item = Engine> {
    std::iter::once(first).chain(ENGINES.into_iter().filter(move |&engine| engine != first))
}

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
    /// The generation chosen for `engine`; `Ok(None)` when none was chosen yet. The engine in the manifest of the
    /// generation it returns is `engine`: a record that names a generation of another engine is an error.
    fn current(&self, engine: Engine) -> Result<Option<Fingerprint>, StoreError>;
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
    /// Chooses a generation for its engine, after `verify`. A proxy that runs does not notice; one that starts later
    /// uses it.
    fn activate(&mut self, generation: Fingerprint) -> Result<(), StoreError>;
    /// `activate`, but only if the generation chosen for the engine of `generation` is `expect`, where `None` is no
    /// choice: it is read and the generation is chosen under the same lock, so a choice that another process made in
    /// between is not overwritten. Another choice, or one where none was expected, is refused with `NOT_EXPECTED`.
    fn activate_if_current(
        &mut self,
        expect: Option<Fingerprint>,
        generation: Fingerprint,
    ) -> Result<(), StoreError>;
    /// Leaves `engine` with no chosen generation, and gives the one that was chosen for it, `None` if there was none.
    /// A proxy that runs does not notice; one that starts later does not start the engine for want of a generation.
    fn deactivate(&mut self, engine: Engine) -> Result<Option<Fingerprint>, StoreError>;
    /// The generations of the store, the oldest first. The lock is not needed.
    fn list(&self) -> Result<Vec<Generation>, StoreError>;
    /// Checks that the manifest of a generation is as its name says and that every file is as the manifest says.
    fn verify(&self, generation: Fingerprint) -> Result<(), StoreError>;
    /// The engine of a generation, from its manifest, which is read and checked as `verify` checks it. The files are
    /// not read.
    fn engine(&self, generation: Fingerprint) -> Result<Engine, StoreError>;
    /// The mode of a generation, from its manifest, which is read and checked as `verify` checks it. The files are
    /// not read.
    fn mode(&self, generation: Fingerprint) -> Result<Mode, StoreError>;
    /// The manifest of a generation, read and checked as `verify` checks it: the files it lists with their sizes and
    /// digests, the order they are loaded in, the engine, the mode and the routes. The files are not read.
    fn manifest(&self, generation: Fingerprint) -> Result<Manifest, StoreError>;
    /// The routes of a generation, from its manifest, which is read and checked as `verify` checks it. The files are
    /// not read. The manifest of a generation is the very bytes its name says, so this and `mode` read the same
    /// manifest.
    fn routes(&self, generation: Fingerprint) -> Result<Routes, StoreError>;
    /// Marks the generation as used by a running proxy until the `Hold` is dropped, without waiting. A generation
    /// that is being removed is refused. The generation itself is not looked at: the caller asks `generation_dir`
    /// after the hold is taken, which is how it learns that a removal has finished.
    fn hold(&self, generation: Fingerprint) -> Result<Hold, StoreError>;
    /// Removes a generation that is not chosen for any engine and not held. Takes the lock of the store.
    fn remove(&mut self, generation: Fingerprint) -> Result<(), StoreError>;
}

/// The place, among `engines`, of the first one that has no generation chosen in `store`.
pub fn unchosen(
    store: &dyn RuleStore,
    engines: impl IntoIterator<Item = Engine>,
) -> Result<Option<usize>, StoreError> {
    for (at, engine) in engines.into_iter().enumerate() {
        if store.current(engine)?.is_none() {
            return Ok(Some(at));
        }
    }
    Ok(None)
}

/// Opens the store that the configuration names.
pub fn open(cfg: &StoreConfig) -> Result<Box<dyn RuleStore>, StoreError> {
    match cfg {
        StoreConfig::File { dir } => Ok(Box::new(FileStore::open(dir)?)),
    }
}
