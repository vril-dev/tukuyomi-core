//! The shipper process: `tukuyomi-records-ship <config>` reads the records from the files the proxy writes and
//! ships them into the database that `records.ship` of the configuration names, until SIGTERM, SIGINT or SIGHUP asks
//! it to stop.
//!
//! It starts in this order: the logger (see `main`), the argument (the absolute clean path of the configuration
//! file), the check that the process does not run as root, the configuration (the same file as the proxy's, read
//! with the proxy's own checks; it needs `records` with `ship`), the driver (only `pgsql` is built; `mysql` is
//! refused), the directory of the records (a real directory of this user without group or other bits, for the
//! position file is written there) and that its file system gives a birth time for the files (a record file is
//! told from another one with the same inode number by it), the file of the connection string (see `dsn`), the
//! runtime and the signal handlers, and `READY=1` to the service manager if the environment has `NOTIFY_SOCKET`
//! (see `notify`). The connection to the database is made in the first turn of the loop, and a database that cannot
//! be reached then is waited for as at any other time (see `ship`), with the signals watched meanwhile. A
//! connection string that cannot be read, or that names `prefer` or `allow` as its `sslmode`, ends the start with
//! exit code 1. So does a database that refuses the login (the user or the password of the connection string, at the
//! first turn or at any later connection), for waiting does not mend it.
//!
//! A signal ends the process after the batch that is under way: it sends `STOPPING=1`, and the exit code is 0. The
//! other codes are those of the proxy: 1 for any other end, 2 for a wrong argument or a refused configuration.
//! The log is the proxy's: one line of JSON for each text on the standard error, with no text from the connection
//! string, from a record or from the server.

mod host;
mod notify;
mod signals;
mod start;

pub use start::{EXIT_FAILED, EXIT_OK, start};
