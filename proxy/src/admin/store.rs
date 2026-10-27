//! Where the state of the admin process is kept. For now that is the users; the tokens and the history of the
//! switches of the rules are to come, and are added here as methods of the trait.
//!
//! A user is read whenever it is needed and is never held in memory by the process, so that a change made by another
//! process (the command `admin bootstrap`) is seen at once. `create_first` and `replace` are the only writes, and
//! each takes the lock of the store without waiting: when another process holds it the answer is `BUSY`.

use std::sync::Arc;

use super::file_store::FileAdminStore;
use super::users::User;
use crate::config::AdminStoreConfig;

/// Why the store refused: a fixed English sentence, never a path or a value read from the store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdminError(pub &'static str);

/// Another process holds the lock of the store.
pub const BUSY: AdminError = AdminError("the admin store is in use by another process");
/// The stored user is not the one that was read.
pub const CONFLICT: AdminError = AdminError("the user was changed since it was read");

/// Where the users are kept. `FileAdminStore` is the only implementation; the configuration's `kind` picks it.
pub trait AdminStore: Send + Sync {
    /// The user of this name; `Ok(None)` when there is none, also for a name that no user can have.
    fn user(&self, name: &str) -> Result<Option<User>, AdminError>;
    /// Stores `user`, only if the store has no user at all.
    fn create_first(&self, user: &User) -> Result<(), AdminError>;
    /// Stores `user` in place of the user of that name, only if the stored one has `changed` equal to `seen`; else
    /// the answer is `CONFLICT`.
    fn replace(&self, seen: u64, user: &User) -> Result<(), AdminError>;
}

/// Opens the store that the configuration names.
pub fn open(cfg: &AdminStoreConfig) -> Result<Arc<dyn AdminStore>, AdminError> {
    match cfg {
        AdminStoreConfig::File { dir } => Ok(Arc::new(FileAdminStore::open(dir)?)),
    }
}
