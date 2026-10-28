//! Where the state of the admin process is kept: the users, the API tokens (see `auth::tokens`) and the history of
//! the switches of the rules (see `waf::history`).
//!
//! A user is read whenever it is needed and is never held in memory by the process, so that a change made by another
//! process (the commands `admin bootstrap` and `admin reset`) is seen at once. `create_first`, `create`, `replace`
//! and the writes of tokens each take the lock of the store without waiting: when another process holds it the
//! answer is `BUSY`. A line of the history is appended without the lock, as a line of the audit log is: it is
//! written whole.
//!
//! One admin process uses a store at a time. `open_exclusive`, with which the admin process opens its store, takes
//! a second lock and keeps it for as long as the store is open; when another admin process holds it the answer is
//! `IN_USE`. Two admin processes would each accept the same step of the second factor or the same recovery code: what
//! prevents it is the lock on the changes of a user, which is held inside one process (see `auth`). The commands do
//! not take the lock of the process: they open the store with `open` and may run while the admin process runs.

use std::sync::Arc;

use super::auth::tokens::Token;
use super::file_store::FileAdminStore;
use super::users::{Role, User};
use super::waf::history::Activation;
use crate::config::AdminStoreConfig;

/// Why the store refused: a fixed English sentence, never a path or a value read from the store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdminError(pub &'static str);

/// Another process holds the lock of the store.
pub const BUSY: AdminError = AdminError("the admin store is in use by another process");
/// The stored user is not the one that was read.
pub const CONFLICT: AdminError = AdminError("the user was changed since it was read");
/// A user or a token of that name is in the store already.
pub const EXISTS: AdminError = AdminError("the entry is in the store already");
/// Another admin process holds the store.
pub const IN_USE: AdminError = AdminError("another admin process runs on this store");

/// Where the users are kept. `FileAdminStore` is the only implementation; the configuration's `kind` picks it.
pub trait AdminStore: Send + Sync {
    /// The user of this name; `Ok(None)` when there is none, also for a name that no user can have.
    fn user(&self, name: &str) -> Result<Option<User>, AdminError>;
    /// Stores `user`, only if the store has no user at all.
    fn create_first(&self, user: &User) -> Result<(), AdminError>;
    /// Stores `user`, only if the store has no user of that name (else the answer is `EXISTS`) and has less than
    /// 1000 users.
    fn create(&self, user: &User) -> Result<(), AdminError>;
    /// Stores `user` in place of the user of that name, only if the stored one has `changed` equal to `seen`; else
    /// the answer is `CONFLICT`.
    fn replace(&self, seen: u64, user: &User) -> Result<(), AdminError>;
    /// Every user, in no order.
    fn users(&self) -> Result<Vec<User>, AdminError>;
    /// The token with this id; `Ok(None)` when there is none, also for an id that no token can have.
    fn token(&self, id: &str) -> Result<Option<Token>, AdminError>;
    /// Every token, in no order. A file that is not a token is left out; it can not be used.
    fn tokens(&self) -> Result<Vec<Token>, AdminError>;
    /// Stores `token`, only if the store has no token with that id (else the answer is `EXISTS`).
    fn create_token(&self, token: &Token) -> Result<(), AdminError>;
    /// Writes `used` as the time of use of the token `id`, only if the token is there and its time is earlier.
    fn touch_token(&self, id: &str, used: u64) -> Result<(), AdminError>;
    /// Removes the token `id`; false: there was none.
    fn remove_token(&self, id: &str) -> Result<bool, AdminError>;
    /// Removes the tokens of `owner` whose role is above `above` (all of them for none); how many were removed.
    fn remove_tokens(&self, owner: &str, above: Option<Role>) -> Result<usize, AdminError>;
    /// Appends `activation` to the history of the switches of the rules; the line is on the disk when this returns.
    fn record_activation(&self, activation: &Activation) -> Result<(), AdminError>;
    /// The newest `limit` lines of the history that can be read, the newest first.
    fn activations(&self, limit: usize) -> Result<Vec<Activation>, AdminError>;
}

/// Opens the store that the configuration names.
pub fn open(cfg: &AdminStoreConfig) -> Result<Arc<dyn AdminStore>, AdminError> {
    match cfg {
        AdminStoreConfig::File { dir } => Ok(Arc::new(FileAdminStore::open(dir)?)),
    }
}

/// Opens the store as `open` does, for the admin process: no other admin process may hold it (the answer is
/// `IN_USE`), and this one holds it until the store is dropped.
pub fn open_exclusive(cfg: &AdminStoreConfig) -> Result<Arc<dyn AdminStore>, AdminError> {
    match cfg {
        AdminStoreConfig::File { dir } => Ok(Arc::new(FileAdminStore::open_exclusive(dir)?)),
    }
}
