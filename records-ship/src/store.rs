//! The database side, behind one trait: the connection, the position of the shipping, the batches, and the removal
//! of old rows. A driver is one implementation (`pgsql`).
//!
//! A batch is the rows of some lines and the position they lead to, and the database makes both durable in one
//! transaction. The position is held against the one that the caller expects: if the database has another (another
//! shipper ships into the same table, or the caller is wrong about where it is), nothing of the batch is stored.
//!
//! An error is a fixed sentence and the code the server gave (SQLSTATE), if any. It holds no value from the
//! connection string, from a record or from the server's message, which can repeat them. The refusal of a login is
//! a sentence of its own (`LOGIN`), for it is the one failure that waiting does not mend.

use std::fmt;

use crate::follow::Position;
use crate::row::Row;

pub mod pgsql;

pub const CONNECT: &str = "cannot connect to the database";
pub const CERTIFICATE: &str = "the certificate of the database server is not accepted";
pub const ROOTS: &str = "no certificate authorities can be read for the TLS to the database";
pub const NEWER: &str = "the schema of the database is newer than this program";
pub const MOVED: &str = "the position in the database is not the one that was expected";
pub const FAILED: &str = "the database refused or failed a request";
pub const LOGIN: &str = "the database refused the login of the connection string";
pub const CLOSED: &str = "the connection to the database is closed";
pub const TIMEOUT: &str = "the database did not answer in time";
pub const VALUE: &str = "a value does not fit the database";
pub const DSN: &str = "the connection string of the database is not valid";
pub const SSLMODE: &str = "the sslmode of the connection string is prefer or allow, which fall back to plain text: \
                           write require, or disable for a server on this host";
pub const FILES: &str = "cannot read the record files";

/// Why the database could not be used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub what: &'static str,
    /// The SQLSTATE the server gave.
    pub code: Option<String>,
}

impl Error {
    pub fn new(what: &'static str) -> Error {
        Error { what, code: None }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.code {
            Some(code) => write!(f, "{} (SQLSTATE {code})", self.what),
            None => f.write_str(self.what),
        }
    }
}

/// A database that the records are shipped into. The runtime has one thread, so the futures need not be `Send`.
#[allow(async_fn_in_trait)]
pub trait Store: Sized {
    /// What the connection is made from.
    type Settings;

    /// Connects, makes the tables if they are not there (and only then needs the right to) and refuses a newer
    /// schema.
    async fn connect(settings: &Self::Settings) -> Result<Self, Error>;

    /// The position that the database has: `None` before the first batch.
    async fn position(&mut self) -> Result<Option<Position>, Error>;

    /// Stores `rows` and moves the position from `from` to `to`, in one transaction; a row that is stored already
    /// is not stored twice. Gives the number of rows stored. If the position is not `from`, nothing is stored and
    /// the error is `MOVED`.
    async fn commit(
        &mut self,
        from: Option<Position>,
        to: Position,
        rows: &[Row],
    ) -> Result<u64, Error>;

    /// Removes at most `limit` rows older than `days` days. Gives the number removed.
    async fn purge(&mut self, days: u32, limit: u32) -> Result<u64, Error>;
}
