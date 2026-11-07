//! The routes of the managed configuration (see `crate::managed`): `routes` (the table, the state of the managed store
//! and of the proxy, and the versions of the store), `import` (the saving of a version, `POST /api/managed/apply`),
//! `job` (the steps of a change, the job that puts a version in force in the proxy, and the changes by name and back)
//! and `history` (the history of the changes and the target of a rollback).

mod history;
mod import;
mod job;
mod routes;

pub use history::{Change, Kind};
pub use routes::{Managed, Op};
pub(super) use routes::{ROUTES, body_limit};
