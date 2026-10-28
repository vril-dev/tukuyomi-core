//! The admin process: `tukuyomi-proxy admin <config>` answers the admin API on a loopback address, and
//! `tukuyomi-proxy admin bootstrap <config> <name>` makes the first user, and `tukuyomi-proxy admin reset <config>
//! <name>` sets the password of a user again. The process reads the same configuration
//! file as the proxy and uses its `admin` object (see `config`); it runs apart from the proxy, as a service of its
//! own, and stops and starts without the proxy noticing.
//!
//! The parts, one file each: `server` (the listener, the table of routes and the checks that come before a route
//! runs, and the start and stop of the process), `auth` (the login with its limits, the session or the API token of a
//! request, the change of a password; its parts `auth::totp`, the second factor, and `auth::tokens`, the API tokens),
//! `account` (the routes of the account: the login and its second step, the session, the password, the second factor
//! and the user's own tokens), `session` (the sessions in memory), `password` (the rules for names and passwords, the
//! hash, the random bytes), `users` (the user and the role, and the first user; `users::manage` has the routes with
//! which an owner manages users and everybody's tokens), `store` and `file_store` (where the users, the tokens and
//! the history of the switches are kept: the trait and the directory of files), `audit` (the audit log), and `waf`
//! (the routes of the rules: the generations, their import, the switch of the proxy and the way back, the history and
//! the records; the client of the control socket of the proxy is `waf::control`).
//!
//! The commands: `admin <config>` runs the process and writes its records as JSON, like the proxy. `admin bootstrap
//! <config> <name>` is a short command that writes texts for a person to read: it reads one line from the standard
//! input as the password and makes the user `name` with the role `owner`, but only when the store has no user at all;
//! else it refuses and the exit code is 1. It writes the creation to the audit log first, and makes no user when that
//! cannot be written. `admin reset <config> <name>` is a short command of the same kind (see `users::reset`), for a
//! user who is locked out: it reads one line from the standard input as the new password of the user `name`, who must
//! be in the store, takes the second factor away, makes the user change the password at the next login, ends the
//! sessions of the user and voids its tokens. It writes to the audit log first, as `bootstrap` does, and it may run
//! while the admin process runs. All three refuse a process that runs as root and make the other checks of the host
//! that the proxy makes before it starts (see `run::host`), and all three need the `admin` object in the
//! configuration. The exit codes are those of the other commands: 0 for success, 1 for any other end and 2 for a
//! wrong argument or a refused configuration.
//!
//! One admin process runs on a store: the process takes the lock `process.lock` of the store directory when it starts
//! and keeps it until it ends, and it does not start (exit code 1) when another process holds it. The two commands do
//! not take it.
//!
//! The routes, each with the least role that may use it (`viewer`, then `operator`, then `owner`), the state of a
//! session that may use it, and whether a token may:
//! - `account`: `POST /api/login` (no credential needed), `POST /api/login/mfa`, `POST /api/logout`, `GET
//!   /api/session`, `PUT /api/account/password`, `POST /api/account/mfa/setup`, `POST /api/account/mfa/confirm`,
//!   `DELETE /api/account/mfa`, `GET` and `POST /api/account/tokens`, `DELETE /api/account/tokens/<id>` (viewer, session
//!   only);
//! - `GET /api/audit` (operator, a token may), and the routes of `users::manage` (owner, session only): `GET` and
//!   `POST /api/users`, `PUT /api/users/<name>`, `POST /api/users/<name>/password`, `DELETE /api/users/<name>/mfa`,
//!   `GET /api/tokens`, `DELETE /api/tokens/<id>`;
//! - the routes of the rules, which `waf` lists.
//!
//! A request has a session cookie or an API token (`Authorization: Bearer`), never both. A token may use the routes of
//! a role (the rules and the audit), and none of the account or the management; its role is the one it was made with,
//! not above its owner's. A session is in one of four states: it counts, it waits for the second factor (it ends
//! after 5 minutes and may only give the code or log out), the password must be changed (an owner made the user or
//! set the password), or the second factor must be set up (`admin.mfa` is `required` and the user has none); the last
//! three limit the routes with a 403 and a fixed sentence (see `server`). Every body is JSON of at most 64 KiB, the
//! one of the import of a generation of at most 12 MiB. A path that is not in the table is 404, a path with another
//! method is 405.
//!
//! Sessions are kept in memory only: when the process starts again, everybody logs in again, and the second factor
//! that was being set up is lost. The tokens are kept in the store and stay.

pub mod account;
pub mod audit;
pub mod auth;
pub mod file_store;
pub mod password;
pub mod server;
pub mod session;
pub mod store;
pub mod users;
pub mod waf;

/// How a command of the admin process ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    Done,
    Failed,
    Usage,
}
