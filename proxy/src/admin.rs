//! The admin process: `tukuyomi-proxy admin <config>` answers the admin API on a loopback address, and
//! `tukuyomi-proxy admin bootstrap <config> <name>` makes the first user. The process reads the same configuration
//! file as the proxy and uses its `admin` object (see `config`); it runs apart from the proxy, as a service of its
//! own, and stops and starts without the proxy noticing.
//!
//! The parts, one file each: `server` (the listener, the table of routes and the checks that come before a route
//! runs, and the start and stop of the process), `auth` (the login with its limits, the session of a request, the
//! change of a password), `session` (the sessions in memory), `password` (the rules for names and passwords, the
//! hash, the random bytes), `users` (the user and the role, and the first user), `store` and `file_store` (where the
//! users are kept: the trait and the directory of files), and `audit` (the audit log).
//!
//! The commands: `admin <config>` runs the process and writes its records as JSON, like the proxy; it does not start
//! when `admin.mfa` is `required`, because there is no second factor yet (exit code 1). `admin bootstrap <config>
//! <name>` is a short command that writes texts for a person to read: it reads one line from the standard input as
//! the password and makes the user `name` with the role `owner`, but only when the store has no user at all; else it
//! refuses and the exit code is 1. It writes the creation to the audit log first, and makes no user when that cannot
//! be written. Both refuse a process that runs as root and make the other
//! checks of the host that the proxy makes before it starts (see `run::host`), and both need the `admin` object in the
//! configuration. The exit codes are those of the other commands: 0 for success, 1 for any other end and 2 for a wrong
//! argument or a refused configuration.
//!
//! The routes, each with the least role that may use it (`viewer`, then `operator`, then `owner`): `POST /api/login`
//! (no session needed), `POST /api/logout` (viewer), `GET /api/session` (viewer), `PUT /api/account/password`
//! (viewer) and `GET /api/audit` (operator). Every body is JSON of at most 64 KiB. A path that is not in the table is
//! 404, a path with another method is 405.
//!
//! Sessions are kept in memory only: when the process starts again, everybody logs in again.

pub mod audit;
pub mod auth;
pub mod file_store;
pub mod password;
pub mod server;
pub mod session;
pub mod store;
pub mod users;

/// How a command of the admin process ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    Done,
    Failed,
    Usage,
}
