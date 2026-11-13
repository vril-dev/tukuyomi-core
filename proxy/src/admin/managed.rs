//! The routes of the managed configuration (see `crate::managed`): `routes` (the table, the state of the managed store
//! and of the proxy, and the versions of the store), `import` (the saving of a version, `POST /api/managed/apply`),
//! `job` (the steps of a change, the job that puts a version in force in the proxy, and the changes by name and back),
//! `history` (the history of the changes and the target of a rollback), `check` (the check of a version that saves
//! nothing, `POST /api/managed/check`), `config` (the values of the main file, `GET /api/config`), `remove` (the
//! removal of a version, `DELETE /api/managed/versions/<name>`) and `certificates` (the certificates of the sites of a
//! version as the store has them, `GET /api/managed/certificates/<name>`).

mod certificates;
mod check;
mod config;
mod history;
mod import;
mod job;
mod remove;
mod routes;

pub use history::{Change, Kind};
pub use routes::{Managed, Op};
pub(super) use routes::{ROUTES, body_limit};
