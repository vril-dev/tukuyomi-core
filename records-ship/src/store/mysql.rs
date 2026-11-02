//! MySQL through `mysql_async`.
//!
//! The tables are looked for when the shipper connects, and made only if they are not there: `tukuyomi_records` (a
//! row for each line), `tukuyomi_records_state` (the position of each source) and `tukuyomi_records_schema` (the
//! version of this layout, now 1; a newer one is refused). When they are there, nothing is created, so the user of
//! the shipper needs no right to create. A table that is missing is made again, also when the version is recorded
//! (an operator may have dropped it); the others stay as they are. They are made in the database of the connection
//! string, which it must name, and every statement names them without a database. `CREATE TABLE` commits at once,
//! so there is no transaction around it: making them takes a lock of the server (`GET_LOCK`), for two processes
//! that make a table at the same moment can fail on each other. The tables are InnoDB tables of `utf8mb4` with the
//! collation `utf8mb4_bin` and the row format `DYNAMIC`, written out, for a row of `tukuyomi_records` and the key
//! of `tukuyomi_records_state` are too long for the older `COMPACT`, which a server can have as its default. A time
//! is a `DATETIME(3)` in UTC.
//!
//! Every connection sets its `sql_mode` to a strict one and its time zone to UTC, so the server refuses a value
//! that does not fit its column and never cuts it. A line must therefore never make a value that does not fit:
//! `row` cuts the texts of the columns that have a length to the length (the columns here are as long as its
//! limits), and the other texts are `TEXT`.
//!
//! A batch is some multi-row `INSERT ... ON DUPLICATE KEY UPDATE id = id` (a row whose line is stored already
//! changes nothing, and is not counted; `INSERT IGNORE` would turn other errors into warnings too), in chunks, for a
//! statement takes at most 65535 parameters, and the move of the position, in one transaction. The position row is
//! read with `FOR UPDATE` and compared with the one the caller expects before anything is stored: if it is another
//! (or is not there although one was expected, or is there although none was), nothing of the batch stays. The
//! position is compared in the program, not by the count of rows that an `UPDATE` reports, for MySQL reports the
//! rows it changed and not the rows it found, so an `UPDATE` that sets what is set already would look like a
//! position that moved. A time is bound as a `DATETIME` value; a line without a good time gets the time of the
//! server. Every value is a bound parameter.
//!
//! TLS follows the connection string, as `mysql_async` reads it. A string without `require_ssl` means TLS with the
//! certificate and the name verified, and so does `require_ssl=true`. `require_ssl=false` speaks plain and is used
//! only when it is written (the form is looked for in the query of the string, and the client must read it the same
//! way). `verify_ca=false` and `verify_identity=false` are refused, for they would leave a connection that anyone on
//! the way to the server can read; the client reads them only with `require_ssl=true`, but a string without it is
//! TLS all the same, so they are refused there too. `verify_ca=true` and `verify_identity=true` are the default and
//! are taken. A server that does not offer TLS is not connected to. The authorities are those of the system, as for
//! PostgreSQL (see `roots`), and `built_in_roots` changes nothing. The connection stays on the address of the
//! string: the client's habit of going over to the unix socket that the server names (`prefer_socket`) is turned
//! off, and a `socket` path, which cannot be secured, is accepted only with `require_ssl=false` written.

use std::time::Duration;

use mysql_async::prelude::Queryable;
use mysql_async::{
    Conn, DriverError, Error as MyError, Opts, OptsBuilder, Params, SslOpts, TxOpts, Value,
};
use tokio::runtime::Handle;
use tokio::time::timeout;
use tukuyomi_proxy::log::record::{HOST_MAX, METHOD_MAX, PATH_MAX};
use tukuyomi_proxy::log::ship::Identity;

use super::roots::{self, refused_certificate};
use super::{
    CERTIFICATE, CLOSED, CONNECT, DSN, Error, FAILED, LOGIN, MOVED, NEWER, ROOTS, Store, TIMEOUT,
    UNVERIFIED, VALUE,
};
use crate::dsn::Dsn;
use crate::follow::Position;
use crate::row::{ID_MAX, Row};

/// The longest the connection to the server may take.
const CONNECT_WAIT: Duration = Duration::from_secs(10);
/// The longest the closing of a connection that is let go may take.
const CLOSE_WAIT: Duration = Duration::from_secs(2);
/// The version of the layout of the tables.
const VERSION: i32 = 1;
/// The name of the lock of the server that setting up takes, and how many seconds to wait for it.
const SETUP_LOCK: &str = "tukuyomi_records_setup";
const SETUP_WAIT: i64 = 20;
/// The longest name of a source in characters: the column of it is that long, and a longer one is refused.
const SOURCE_MAX: usize = 512;
/// The error number of a duplicate key.
const DUPLICATE_ENTRY: u16 = 1062;
/// The columns of a row of `tukuyomi_records` that a batch fills, and the rows of one `INSERT`: far under the 65535
/// parameters that a statement takes, and with rows of the longest lines (a line of 4 KiB of bytes that are not
/// UTF-8 is about 12 KiB in `raw`) under the 4 MiB of the packet of the oldest servers.
const COLUMNS: usize = 22;
const ROWS_PER_INSERT: usize = 100;
/// The first year a `DATETIME` is promised to hold.
const FIRST_YEAR: u16 = 1000;

// The columns that have a length hold what `row` cuts to: a character is at least a byte.
const _: () = assert!(METHOD_MAX <= 32 && HOST_MAX <= 255 && PATH_MAX <= 1024 && ID_MAX <= 128);
const _: () = assert!(ROWS_PER_INSERT * COLUMNS <= 65_535);

/// The settings of every connection: strict, and in UTC.
const SESSION: &str = "SET SESSION sql_mode = 'STRICT_ALL_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,\
                       ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION', SESSION time_zone = '+00:00'";

const SCHEMA_TABLE: &str = "
CREATE TABLE IF NOT EXISTS tukuyomi_records_schema (
    version INT NOT NULL PRIMARY KEY
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC";

const RECORDS_TABLE: &str = "
CREATE TABLE IF NOT EXISTS tukuyomi_records (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ts DATETIME(3) NOT NULL,
    `type` VARCHAR(16) NOT NULL,
    request_id VARCHAR(128) NULL,
    client VARCHAR(45) NULL,
    method VARCHAR(32) NULL,
    host VARCHAR(255) NULL,
    path VARCHAR(1024) NULL,
    class TEXT NULL,
    status INT NULL,
    reason TEXT NULL,
    ms BIGINT NULL,
    upstream TEXT NULL,
    mode TEXT NULL,
    engine TEXT NULL,
    generation TEXT NULL,
    rule BIGINT NULL,
    rules TEXT NULL,
    score INT NULL,
    body BIGINT NULL,
    sent BIGINT NULL,
    raw LONGTEXT NOT NULL,
    line_hash BINARY(32) NOT NULL,
    UNIQUE KEY tukuyomi_records_line_hash (line_hash),
    KEY tukuyomi_records_ts (ts),
    KEY tukuyomi_records_type_ts (`type`, ts),
    KEY tukuyomi_records_request_id (request_id),
    KEY tukuyomi_records_rule (rule)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC";

const STATE_TABLE: &str = "
CREATE TABLE IF NOT EXISTS tukuyomi_records_state (
    source VARCHAR(512) NOT NULL PRIMARY KEY,
    inode VARCHAR(20) NOT NULL,
    born VARCHAR(40) NOT NULL,
    `offset` BIGINT NOT NULL,
    lost_lines BIGINT NOT NULL,
    updated DATETIME(3) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC";

const TABLES_THERE: &str = "
SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE()
    AND table_name IN ('tukuyomi_records', 'tukuyomi_records_state', 'tukuyomi_records_schema')";

const NEWEST: &str = "SELECT MAX(version) FROM tukuyomi_records_schema";

const INSERT_HEAD: &str = "
INSERT INTO tukuyomi_records (ts, `type`, request_id, client, method, host, path, class, status, reason, ms,
    upstream, mode, engine, generation, rule, rules, score, body, sent, raw, line_hash) VALUES ";
/// One row of the values of `INSERT`: the time of the server stands in for a line without a good one.
const INSERT_ROW: &str = "(COALESCE(?, UTC_TIMESTAMP(3)), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, \
                          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
const INSERT_TAIL: &str = " ON DUPLICATE KEY UPDATE id = id";

/// The position row of a source, locked until the transaction ends.
const HELD: &str =
    "SELECT inode, born, `offset` FROM tukuyomi_records_state WHERE source = ? FOR UPDATE";

/// The first position of a source.
const FIRST: &str = "
INSERT INTO tukuyomi_records_state (source, inode, born, `offset`, lost_lines, updated)
VALUES (?, ?, ?, ?, ?, UTC_TIMESTAMP(3))";

/// The move of a position that is held.
const MOVE: &str = "
UPDATE tukuyomi_records_state
SET inode = ?, born = ?, `offset` = ?, lost_lines = ?, updated = UTC_TIMESTAMP(3)
WHERE source = ?";

const PURGE: &str = "
DELETE FROM tukuyomi_records WHERE ts < UTC_TIMESTAMP(3) - INTERVAL ? DAY ORDER BY ts, id LIMIT ?";

/// The `INSERT` of `rows` rows.
fn insert(rows: usize) -> String {
    let mut sql = String::with_capacity(
        INSERT_HEAD.len() + rows * (INSERT_ROW.len() + 2) + INSERT_TAIL.len(),
    );
    sql.push_str(INSERT_HEAD);
    for n in 0..rows {
        if n > 0 {
            sql.push_str(", ");
        }
        sql.push_str(INSERT_ROW);
    }
    sql.push_str(INSERT_TAIL);
    sql
}

/// What a connection is made from. It has no `Debug` form, for the client's form of it shows the password.
pub struct Settings {
    pub opts: Opts,
    /// The name under which the position of the shipping is kept.
    pub source: String,
}

/// Whether the query of the connection string has `pair` (`name=value`) just so. The fragment, which the client does
/// not read, is left out.
fn query_has(text: &str, pair: &str) -> bool {
    let text = text.split('#').next().unwrap_or("");
    text.split_once('?')
        .is_some_and(|(_, query)| query.split('&').any(|one| one == pair))
}

impl Settings {
    /// The settings for the connection string `dsn`. A string without `require_ssl` is read as `require_ssl=true`,
    /// which here verifies the certificate and the name; `require_ssl=false` is taken only when it is written;
    /// the two `false` forms of the verification are refused with TLS (see above).
    pub fn parse(dsn: &Dsn, source: &str) -> Result<Settings, Error> {
        if source.chars().count() > SOURCE_MAX {
            return Err(Error::new(VALUE));
        }
        let text = dsn.text();
        let opts = Opts::from_url(text).map_err(|_| Error::new(DSN))?;
        if opts.db_name().is_none() {
            return Err(Error::new(DSN));
        }
        let (tls, unverified) = match opts.ssl_opts() {
            Some(ssl) => (
                true,
                ssl.accept_invalid_certs() || ssl.skip_domain_validation(),
            ),
            // Without `require_ssl=true` the client drops what it was told about the checks, so the text is looked
            // at for them: the string is TLS unless it says plain.
            None => {
                let tls = !query_has(text, "require_ssl=false");
                let unverified =
                    query_has(text, "verify_ca=false") || query_has(text, "verify_identity=false");
                (tls, tls && unverified)
            }
        };
        if unverified {
            return Err(Error::new(UNVERIFIED));
        }
        if tls && opts.socket().is_some() {
            return Err(Error::new(DSN));
        }
        let opts: Opts = OptsBuilder::from_opts(opts)
            .ssl_opts(tls.then(SslOpts::default))
            .prefer_socket(false)
            .client_found_rows(false)
            .init(vec![SESSION])
            .into();
        Ok(Settings {
            opts,
            source: source.to_owned(),
        })
    }
}

/// The TLS of a connection: the certificate and the name verified, against the authorities of the system only.
fn system_tls() -> Result<SslOpts, Error> {
    let path = roots::bundle().ok_or(Error::new(ROOTS))?;
    let authorities = roots::certificates_from(&path)?
        .iter()
        .map(|certificate| certificate.to_vec().into())
        .collect();
    Ok(SslOpts::default()
        .with_disable_built_in_roots(true)
        .with_root_certs(authorities))
}

/// A connection to the database.
pub struct MyStore {
    /// Gone only while the store is dropped.
    conn: Option<Conn>,
    source: String,
}

impl Drop for MyStore {
    fn drop(&mut self) {
        // A connection that is let go is closed by the client on its own, with no limit to the time it waits for
        // the server. Closed here with a limit, the connections of an outage do not stay open for ever when the
        // server does not answer.
        if let (Some(conn), Ok(handle)) = (self.conn.take(), Handle::try_current()) {
            handle.spawn(async move {
                let _ = timeout(CLOSE_WAIT, conn.disconnect()).await;
            });
        }
    }
}

/// The SQLSTATE the server gave, if it is the five characters of one.
fn sqlstate(state: &str) -> Option<String> {
    (state.len() == 5
        && state
            .bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_uppercase()))
    .then(|| state.to_owned())
}

/// The error of a request: the SQLSTATE if the server answered, else what the kind of the failure says.
fn failed(error: &MyError) -> Error {
    match error {
        MyError::Server(server) => {
            let code = sqlstate(&server.state);
            Error {
                // The class 28 is the refusal of a login: a wrong user or password (1045). The other refusals at a
                // login, such as no right to the database (1044), a host that is not let in (1130) or a locked
                // account (3118), are not in it, and are tried again.
                what: if code.as_deref().is_some_and(|code| code.starts_with("28")) {
                    LOGIN
                } else {
                    FAILED
                },
                code,
            }
        }
        _ if refused_certificate(error) => Error::new(CERTIFICATE),
        MyError::Driver(DriverError::ConnectionClosed) => Error::new(CLOSED),
        _ => Error::new(FAILED),
    }
}

/// The error of the connection: as for a request, but a failure without a kind is a failure to connect.
fn not_connected(error: &MyError) -> Error {
    let error = failed(error);
    if error.what == FAILED && error.code.is_none() {
        Error::new(CONNECT)
    } else {
        error
    }
}

impl MyStore {
    /// The connection and the source, for a statement that needs both.
    fn parts(&mut self) -> Result<(&mut Conn, &str), Error> {
        match self.conn.as_mut() {
            Some(conn) => Ok((conn, &self.source)),
            None => Err(Error::new(CLOSED)),
        }
    }

    /// The newest version of the layout that is recorded, if any is.
    async fn newest(conn: &mut Conn) -> Result<Option<i32>, Error> {
        let newest: Option<Option<i32>> = conn.query_first(NEWEST).await.map_err(|e| failed(&e))?;
        Ok(newest.flatten())
    }

    /// Whether the three tables are there with a layout recorded, so that nothing is to be made; a newer layout is
    /// refused. This asks for no right to create, so a user that may only use the tables gets as far as here.
    async fn laid_out(&mut self) -> Result<bool, Error> {
        let (conn, _) = self.parts()?;
        let there: Option<u64> = conn
            .query_first(TABLES_THERE)
            .await
            .map_err(|e| failed(&e))?;
        if there != Some(3) {
            return Ok(false);
        }
        match Self::newest(conn).await? {
            Some(version) if version > VERSION => Err(Error::new(NEWER)),
            Some(_) => Ok(true),
            None => Ok(false),
        }
    }

    /// Makes the tables that are not there, and refuses a newer layout. The caller holds the lock.
    async fn make_tables(&mut self) -> Result<(), Error> {
        let (conn, _) = self.parts()?;
        conn.query_drop(SCHEMA_TABLE)
            .await
            .map_err(|e| failed(&e))?;
        let newest = Self::newest(conn).await?;
        if newest.is_some_and(|version| version > VERSION) {
            return Err(Error::new(NEWER));
        }
        // Every statement of the tables does nothing for a table that is there.
        for table in [RECORDS_TABLE, STATE_TABLE] {
            conn.query_drop(table).await.map_err(|e| failed(&e))?;
        }
        if newest.is_none() {
            conn.exec_drop(
                "INSERT INTO tukuyomi_records_schema (version) VALUES (?)",
                (VERSION,),
            )
            .await
            .map_err(|e| failed(&e))?;
        }
        Ok(())
    }

    /// Makes the tables if they are not there, under the lock, and refuses a newer layout.
    async fn setup(&mut self) -> Result<(), Error> {
        if self.laid_out().await? {
            return Ok(());
        }
        let (conn, _) = self.parts()?;
        let got: Option<Option<i64>> = conn
            .exec_first("SELECT GET_LOCK(?, ?)", (SETUP_LOCK, SETUP_WAIT))
            .await
            .map_err(|e| failed(&e))?;
        if got.flatten() != Some(1) {
            return Err(Error::new(TIMEOUT));
        }
        let made = self.make_tables().await;
        // The lock is let go now, not when the connection is found closed.
        let (conn, _) = self.parts()?;
        let freed = conn
            .exec_drop("DO RELEASE_LOCK(?)", (SETUP_LOCK,))
            .await
            .map_err(|e| failed(&e));
        made?;
        freed
    }
}

/// A time in the form the proxy writes (`2026-10-25T08:00:00.123Z`, which `row` has made sure of) as the value of
/// a `DATETIME(3)`. None for a year before `FIRST_YEAR`, which that type is not promised to hold: the row gets the
/// time of the server, as a line without a good time does.
fn datetime(ts: &str) -> Option<Value> {
    let number = |from: usize, to: usize| ts.get(from..to)?.parse::<u32>().ok();
    let year = u16::try_from(number(0, 4)?)
        .ok()
        .filter(|year| *year >= FIRST_YEAR)?;
    Some(Value::Date(
        year,
        u8::try_from(number(5, 7)?).ok()?,
        u8::try_from(number(8, 10)?).ok()?,
        u8::try_from(number(11, 13)?).ok()?,
        u8::try_from(number(14, 16)?).ok()?,
        u8::try_from(number(17, 19)?).ok()?,
        number(20, 23)?.checked_mul(1000)?,
    ))
}

/// A text for a column that may be empty.
fn text(value: &Option<String>) -> Value {
    value.as_deref().map_or(Value::NULL, Value::from)
}

/// The parameters of one row of `INSERT`, in the order of its placeholders.
fn values(row: &Row) -> [Value; COLUMNS] {
    [
        row.ts.as_deref().and_then(datetime).unwrap_or(Value::NULL),
        Value::from(row.kind),
        text(&row.request_id),
        text(&row.client),
        text(&row.method),
        text(&row.host),
        text(&row.path),
        text(&row.class),
        Value::from(row.status),
        text(&row.reason),
        Value::from(row.ms),
        text(&row.upstream),
        text(&row.mode),
        text(&row.engine),
        text(&row.generation),
        Value::from(row.rule),
        text(&row.rules),
        Value::from(row.score),
        Value::from(row.body),
        Value::from(row.sent),
        Value::from(row.raw.as_str()),
        Value::from(row.line_hash.as_slice()),
    ]
}

/// A number of a position as the database column holds it.
fn column(value: u64) -> Result<i64, Error> {
    i64::try_from(value).map_err(|_| Error::new(VALUE))
}

impl Store for MyStore {
    type Settings = Settings;

    async fn connect(settings: &Settings) -> Result<MyStore, Error> {
        let mut builder = OptsBuilder::from_opts(settings.opts.clone());
        // Plain text is for a string that says `require_ssl=false` alone; any TLS is the one of the system.
        if settings.opts.ssl_opts().is_some() {
            builder = builder.ssl_opts(Some(system_tls()?));
        }
        let conn = match timeout(CONNECT_WAIT, Conn::new(Opts::from(builder))).await {
            Ok(conn) => conn.map_err(|e| not_connected(&e))?,
            Err(_) => return Err(Error::new(CONNECT)),
        };
        let mut store = MyStore {
            conn: Some(conn),
            source: settings.source.clone(),
        };
        store.setup().await?;
        Ok(store)
    }

    async fn position(&mut self) -> Result<Option<Position>, Error> {
        let (conn, source) = self.parts()?;
        let row: Option<(String, String, i64, i64)> = conn
            .exec_first(
                "SELECT inode, born, `offset`, lost_lines FROM tukuyomi_records_state WHERE source = ?",
                (source,),
            )
            .await
            .map_err(|e| failed(&e))?;
        let Some((inode, born, offset, lost)) = row else {
            return Ok(None);
        };
        Ok(Some(Position {
            identity: Identity {
                inode: inode.parse().map_err(|_| Error::new(VALUE))?,
                born: born.parse().map_err(|_| Error::new(VALUE))?,
            },
            offset: u64::try_from(offset).map_err(|_| Error::new(VALUE))?,
            lost_lines: u64::try_from(lost).map_err(|_| Error::new(VALUE))?,
        }))
    }

    async fn commit(
        &mut self,
        from: Option<Position>,
        to: Position,
        rows: &[Row],
    ) -> Result<u64, Error> {
        let (inode, born, offset, lost) = (
            to.identity.inode.to_string(),
            to.identity.born.to_string(),
            column(to.offset)?,
            column(to.lost_lines)?,
        );
        let expected = from
            .map(|from| {
                Ok::<_, Error>((
                    from.identity.inode.to_string(),
                    from.identity.born.to_string(),
                    column(from.offset)?,
                ))
            })
            .transpose()?;
        let (conn, source) = self.parts()?;
        let mut transaction = conn
            .start_transaction(TxOpts::default())
            .await
            .map_err(|e| failed(&e))?;
        // The position goes first, so that a batch that does not follow it stores nothing.
        match &expected {
            None => {
                let first = (source, inode.as_str(), born.as_str(), offset, lost);
                if let Err(e) = transaction.exec_drop(FIRST, first).await {
                    // A position is there although none was expected.
                    let moved = matches!(&e, MyError::Server(s) if s.code == DUPLICATE_ENTRY);
                    let _ = transaction.rollback().await;
                    return Err(if moved { Error::new(MOVED) } else { failed(&e) });
                }
            }
            Some((from_inode, from_born, from_offset)) => {
                let held: Option<(String, String, i64)> = transaction
                    .exec_first(HELD, (source,))
                    .await
                    .map_err(|e| failed(&e))?;
                let expected = (from_inode.as_str(), from_born.as_str(), *from_offset);
                if held.as_ref().map(|(i, b, o)| (i.as_str(), b.as_str(), *o)) != Some(expected) {
                    let _ = transaction.rollback().await;
                    return Err(Error::new(MOVED));
                }
                let moved = (inode.as_str(), born.as_str(), offset, lost, source);
                transaction
                    .exec_drop(MOVE, moved)
                    .await
                    .map_err(|e| failed(&e))?;
            }
        }
        let mut stored = 0;
        for chunk in rows.chunks(ROWS_PER_INSERT) {
            let parameters: Vec<Value> = chunk.iter().flat_map(values).collect();
            transaction
                .exec_drop(insert(chunk.len()), Params::Positional(parameters))
                .await
                .map_err(|e| failed(&e))?;
            stored += transaction.affected_rows();
        }
        transaction.commit().await.map_err(|e| failed(&e))?;
        Ok(stored)
    }

    async fn purge(&mut self, days: u32, limit: u32) -> Result<u64, Error> {
        let (conn, _) = self.parts()?;
        conn.exec_drop(PURGE, (i64::from(days), i64::from(limit)))
            .await
            .map_err(|e| failed(&e))?;
        Ok(conn.affected_rows())
    }
}

#[cfg(test)]
mod tests;
