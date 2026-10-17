//! Where rule generations are kept, as the proxy reads them.

use std::path::PathBuf;

use crate::config::StoreConfig;
use crate::rules::bundle::Fingerprint;
use crate::rules::file_store::FileStore;

/// Why the rules store refused: a fixed English sentence, never a path or a value read from the store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreError(pub &'static str);

/// Where rule generations are kept. `FileStore` is the only implementation; the configuration's `kind` picks it.
pub trait RuleStore {
    /// The chosen generation; `Ok(None)` when none was chosen yet.
    fn current(&self) -> Result<Option<Fingerprint>, StoreError>;
    /// The directory of a generation for the inspector: absolute and clean, checked to be a real directory.
    fn generation_dir(&self, generation: Fingerprint) -> Result<PathBuf, StoreError>;
}

/// Opens the store that the configuration names.
pub fn open(cfg: &StoreConfig) -> Result<Box<dyn RuleStore>, StoreError> {
    match cfg {
        StoreConfig::File { dir } => Ok(Box::new(FileStore::open(dir)?)),
    }
}
