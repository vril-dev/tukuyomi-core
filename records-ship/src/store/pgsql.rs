//! PostgreSQL through `tokio-postgres`.
//!
//! The tables are looked for when the shipper connects, and made only if they are not there: `tukuyomi_records` (a
//! row for each line), `tukuyomi_records_state` (the position of each source) and `tukuyomi_records_schema` (the
//! version of this layout, now 1; a newer one is refused). When they are there, nothing is created, so the role of
//! the shipper needs no right to create. A table that is missing is made again, also when the version is recorded
//! (an operator may have dropped it); the others stay as they are. They are made in the first schema of the
//! `search_path` of the connection, and every statement names them without a schema. Making them takes an advisory
//! lock, for two processes that make a table at the same moment can fail on each other.
//!
//! A batch is one `INSERT ... SELECT FROM unnest(...)` with one array for each column (so the number of parameters
//! is the number of columns and does not grow with the batch; the rows keep the order of the lines) and the move of
//! the position, in a transaction. The move changes the row of the source only if it still has the position the
//! caller expects, and it adds the row only when the caller expects none; if it changed nothing (the position is
//! another, or the row is not there although a position was expected), the transaction is rolled back and nothing
//! of the batch stays. The text of a time and of an address is cast by the database from text that `row` has made
//! sure of. Every value is a bound parameter.
//!
//! TLS follows the connection string. A string without `sslmode` means TLS with the certificate and the name
//! verified, and so do `require`, `verify-full` and `verify-ca` (the mode `require` here always verifies, see
//! `tls`; `verify-ca` is read as `verify-full`, which asks for more). `sslmode=disable` speaks plain and is used
//! only when it is written. `prefer` and `allow` are refused, for a server, or someone on the way to it, that
//! answers "no TLS" would make them send the password and the records in the clear; and a connection that is made
//! with a settings object that says `prefer` is made as `require`.

mod tls;

use std::ops::Range;
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio_postgres::config::SslMode;
use tokio_postgres::types::ToSql;
use tokio_postgres::{Client, Config, NoTls};
use tukuyomi_proxy::log::ship::Identity;

use super::{
    CERTIFICATE, CLOSED, CONNECT, DSN, Error, FAILED, LOGIN, MOVED, NEWER, SSLMODE, Store, VALUE,
};
use crate::dsn::Dsn;
use crate::follow::Position;
use crate::row::Row;

/// The longest the connection to the server may take, if the connection string does not say.
const CONNECT_WAIT: Duration = Duration::from_secs(10);
/// The name the server shows for this connection, if the connection string does not say.
const APPLICATION: &str = "tukuyomi-records-ship";
/// The version of the layout of the tables.
const VERSION: i32 = 1;
/// The key of the advisory lock that setting up takes.
const SETUP_LOCK: i64 = 0x7475_6b75_7974_6d69;

const TABLES: &str = "
CREATE TABLE IF NOT EXISTS tukuyomi_records (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts timestamptz NOT NULL,
    \"type\" text NOT NULL,
    request_id text,
    client inet,
    method text,
    host text,
    path text,
    class text,
    status integer,
    reason text,
    ms bigint,
    upstream text,
    mode text,
    engine text,
    generation text,
    rule bigint,
    rules text,
    score integer,
    body bigint,
    sent bigint,
    raw text NOT NULL,
    line_hash bytea NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS tukuyomi_records_ts ON tukuyomi_records (ts);
CREATE INDEX IF NOT EXISTS tukuyomi_records_type_ts ON tukuyomi_records (\"type\", ts);
CREATE INDEX IF NOT EXISTS tukuyomi_records_request_id ON tukuyomi_records (request_id);
CREATE INDEX IF NOT EXISTS tukuyomi_records_rule ON tukuyomi_records (rule);
CREATE TABLE IF NOT EXISTS tukuyomi_records_state (
    source text PRIMARY KEY,
    inode text NOT NULL,
    born text NOT NULL,
    \"offset\" bigint NOT NULL,
    lost_lines bigint NOT NULL,
    updated timestamptz NOT NULL DEFAULT now()
);";

const INSERT: &str = "
INSERT INTO tukuyomi_records (ts, \"type\", request_id, client, method, host, path, class, status, reason, ms,
    upstream, mode, engine, generation, rule, rules, score, body, sent, raw, line_hash)
SELECT COALESCE(t.ts::timestamptz, now()), t.kind, t.request_id, t.client::inet, t.method, t.host, t.path, t.class,
    t.status, t.reason, t.ms, t.upstream, t.mode, t.engine, t.generation, t.rule, t.rules, t.score, t.body, t.sent,
    t.raw, t.line_hash
FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::text[],
    $9::integer[], $10::text[], $11::bigint[], $12::text[], $13::text[], $14::text[], $15::text[], $16::bigint[],
    $17::text[], $18::integer[], $19::bigint[], $20::bigint[], $21::text[], $22::bytea[])
    WITH ORDINALITY AS t(ts, kind, request_id, client, method, host, path, class, status, reason, ms, upstream,
    mode, engine, generation, rule, rules, score, body, sent, raw, line_hash, n)
ORDER BY t.n
ON CONFLICT (line_hash) DO NOTHING";

/// The first position of a source: added only if there is none.
const FIRST: &str = "
INSERT INTO tukuyomi_records_state (source, inode, born, \"offset\", lost_lines, updated)
VALUES ($1, $2, $3, $4, $5, now())
ON CONFLICT (source) DO NOTHING";

/// The move of a position from the one the caller expects: changes nothing if the row has another, or none.
const MOVE: &str = "
UPDATE tukuyomi_records_state
SET inode = $2, born = $3, \"offset\" = $4, lost_lines = $5, updated = now()
WHERE source = $1 AND inode = $6 AND born = $7 AND \"offset\" = $8";

const PURGE: &str = "
DELETE FROM tukuyomi_records WHERE id IN (
    SELECT id FROM tukuyomi_records WHERE ts < now() - make_interval(days => $1::integer) ORDER BY ts LIMIT $2::bigint
)";

/// What a connection is made from.
pub struct Settings {
    pub config: Config,
    /// The name under which the position of the shipping is kept.
    pub source: String,
}

/// Where the connection string gives `sslmode` a value, as the byte ranges of the values in the order they stand, in
/// the key and value form (spaces may surround the `=`) and in the query of a URL: a value runs up to a space, a
/// quote or an `&`. Looking for the text is enough, for it is only used to refuse a mode and to read two names of
/// one mode; the mode that is used is the one the parser of the client reads.
fn sslmode_values(text: &str) -> Vec<Range<usize>> {
    const KEY: &str = "sslmode";
    let mut values = Vec::new();
    for (at, _) in text.match_indices(KEY) {
        let Some(rest) = text[at + KEY.len()..].trim_start().strip_prefix('=') else {
            continue;
        };
        let rest = rest.trim_start().trim_start_matches(['\'', '"']);
        let start = text.len() - rest.len();
        let end = rest
            .find(|c: char| c.is_whitespace() || matches!(c, '\'' | '"' | '&'))
            .unwrap_or(rest.len());
        values.push(start..start + end);
    }
    values
}

/// The value that the connection string gives `sslmode` last, if it names one.
fn named_sslmode(text: &str) -> Option<&str> {
    sslmode_values(text).pop().map(|value| &text[value])
}

/// The string with each `sslmode` value that is `verify-full` or `verify-ca` written as `require`: the client knows
/// `disable`, `prefer` and `require` only, and here `require` verifies the certificate and the name, as both do.
fn verifying_as_require(text: &str) -> String {
    let mut spelled = text.to_owned();
    // From the last value to the first, for the new text is not as long as the old.
    for value in sslmode_values(text).into_iter().rev() {
        if matches!(&text[value.clone()], "verify-full" | "verify-ca") {
            spelled.replace_range(value, "require");
        }
    }
    spelled
}

impl Settings {
    /// The settings for the connection string `dsn`. A string without `sslmode` is read as `require`, which here
    /// verifies the certificate and the name, and so are `verify-full` and `verify-ca`; `prefer` and `allow` are
    /// refused (see above).
    pub fn parse(dsn: &Dsn, source: &str) -> Result<Settings, Error> {
        if matches!(named_sslmode(dsn.text()), Some("prefer" | "allow")) {
            return Err(Error::new(SSLMODE));
        }
        // The client refuses the two verifying names. Only a string that it refused is written again, so that one
        // it takes is used as it stands. In one it refused, the text `sslmode=verify-full` or `verify-ca` inside a
        // quoted value, such as a password, is written again too; the login is then refused and the process ends,
        // so such a password has to be written without that text.
        let mut config: Config = match dsn.text().parse() {
            Ok(config) => config,
            Err(_) => verifying_as_require(dsn.text())
                .parse()
                .map_err(|_| Error::new(DSN))?,
        };
        if config.get_ssl_mode() == SslMode::Prefer {
            config.ssl_mode(SslMode::Require);
        }
        if config.get_connect_timeout().is_none() {
            config.connect_timeout(CONNECT_WAIT);
        }
        if config.get_application_name().is_none() {
            config.application_name(APPLICATION);
        }
        Ok(Settings {
            config,
            source: source.to_owned(),
        })
    }
}

/// A connection to the database.
pub struct PgStore {
    client: Client,
    /// The task that runs the connection; it ends with the store.
    driver: JoinHandle<()>,
    source: String,
}

impl Drop for PgStore {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

/// Whether an error is the refusal of the certificate of the server: the cause is a TLS error of that kind.
fn refused_certificate(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut cause = Some(error);
    while let Some(error) = cause {
        let tls = error.downcast_ref::<rustls::Error>().or_else(|| {
            error
                .downcast_ref::<std::io::Error>()?
                .get_ref()?
                .downcast_ref::<rustls::Error>()
        });
        if let Some(tls) = tls {
            return matches!(tls, rustls::Error::InvalidCertificate(_));
        }
        cause = error.source();
    }
    false
}

/// The error of a request: the SQLSTATE if the server answered, else what the kind of the failure says.
fn failed(error: &tokio_postgres::Error) -> Error {
    if let Some(code) = error.code() {
        let code = code.code();
        return Error {
            // The class 28 is the refusal of a login: a wrong user or password, or no entry that lets this user in.
            what: if code.starts_with("28") {
                LOGIN
            } else {
                FAILED
            },
            code: Some(code.to_owned()),
        };
    }
    if refused_certificate(error) {
        return Error::new(CERTIFICATE);
    }
    if error.is_closed() {
        return Error::new(CLOSED);
    }
    Error::new(FAILED)
}

/// The error of the connection: as for a request, but a failure without a kind is a failure to connect.
fn not_connected(error: &tokio_postgres::Error) -> Error {
    let error = failed(error);
    if error.what == FAILED && error.code.is_none() {
        Error::new(CONNECT)
    } else {
        error
    }
}

impl PgStore {
    /// Whether the three tables are there with a layout recorded, so that nothing is to be made; a newer layout is
    /// refused. This asks for no right to create, so a role that may only use the tables gets as far as here.
    async fn laid_out(&self) -> Result<bool, Error> {
        let tables: bool = self
            .client
            .query_one(
                "SELECT to_regclass('tukuyomi_records') IS NOT NULL \
                     AND to_regclass('tukuyomi_records_state') IS NOT NULL \
                     AND to_regclass('tukuyomi_records_schema') IS NOT NULL",
                &[],
            )
            .await
            .map_err(|e| failed(&e))?
            .get(0);
        if !tables {
            return Ok(false);
        }
        let newest: Option<i32> = self
            .client
            .query_one("SELECT max(version) FROM tukuyomi_records_schema", &[])
            .await
            .map_err(|e| failed(&e))?
            .get(0);
        match newest {
            Some(version) if version > VERSION => Err(Error::new(NEWER)),
            Some(_) => Ok(true),
            None => Ok(false),
        }
    }

    /// Makes the tables if they are not there, under the lock, and refuses a newer layout.
    async fn setup(&mut self) -> Result<(), Error> {
        if self.laid_out().await? {
            return Ok(());
        }
        let transaction = self.client.transaction().await.map_err(|e| failed(&e))?;
        transaction
            .execute("SELECT pg_advisory_xact_lock($1)", &[&SETUP_LOCK])
            .await
            .map_err(|e| failed(&e))?;
        transaction
            .batch_execute(
                "CREATE TABLE IF NOT EXISTS tukuyomi_records_schema (version integer PRIMARY KEY)",
            )
            .await
            .map_err(|e| failed(&e))?;
        let newest: Option<i32> = transaction
            .query_one("SELECT max(version) FROM tukuyomi_records_schema", &[])
            .await
            .map_err(|e| failed(&e))?
            .get(0);
        match newest {
            Some(version) if version > VERSION => {
                // The lock is let go now, not when the connection is found closed.
                let _ = transaction.rollback().await;
                return Err(Error::new(NEWER));
            }
            _ => {
                // Every statement of the tables does nothing for a table that is there.
                transaction
                    .batch_execute(TABLES)
                    .await
                    .map_err(|e| failed(&e))?;
                if newest.is_none() {
                    transaction
                        .execute(
                            "INSERT INTO tukuyomi_records_schema (version) VALUES ($1)",
                            &[&VERSION],
                        )
                        .await
                        .map_err(|e| failed(&e))?;
                }
            }
        }
        transaction.commit().await.map_err(|e| failed(&e))
    }
}

/// The columns of a batch, one array for each.
struct Columns<'a> {
    ts: Vec<Option<&'a str>>,
    kind: Vec<&'a str>,
    request_id: Vec<Option<&'a str>>,
    client: Vec<Option<&'a str>>,
    method: Vec<Option<&'a str>>,
    host: Vec<Option<&'a str>>,
    path: Vec<Option<&'a str>>,
    class: Vec<Option<&'a str>>,
    status: Vec<Option<i32>>,
    reason: Vec<Option<&'a str>>,
    ms: Vec<Option<i64>>,
    upstream: Vec<Option<&'a str>>,
    mode: Vec<Option<&'a str>>,
    engine: Vec<Option<&'a str>>,
    generation: Vec<Option<&'a str>>,
    rule: Vec<Option<i64>>,
    rules: Vec<Option<&'a str>>,
    score: Vec<Option<i32>>,
    body: Vec<Option<i64>>,
    sent: Vec<Option<i64>>,
    raw: Vec<&'a str>,
    line_hash: Vec<&'a [u8]>,
}

impl<'a> Columns<'a> {
    fn of(rows: &'a [Row]) -> Columns<'a> {
        let text = |pick: fn(&Row) -> &Option<String>| -> Vec<Option<&'a str>> {
            rows.iter().map(|row| pick(row).as_deref()).collect()
        };
        Columns {
            ts: text(|row| &row.ts),
            kind: rows.iter().map(|row| row.kind).collect(),
            request_id: text(|row| &row.request_id),
            client: text(|row| &row.client),
            method: text(|row| &row.method),
            host: text(|row| &row.host),
            path: text(|row| &row.path),
            class: text(|row| &row.class),
            status: rows.iter().map(|row| row.status).collect(),
            reason: text(|row| &row.reason),
            ms: rows.iter().map(|row| row.ms).collect(),
            upstream: text(|row| &row.upstream),
            mode: text(|row| &row.mode),
            engine: text(|row| &row.engine),
            generation: text(|row| &row.generation),
            rule: rows.iter().map(|row| row.rule).collect(),
            rules: text(|row| &row.rules),
            score: rows.iter().map(|row| row.score).collect(),
            body: rows.iter().map(|row| row.body).collect(),
            sent: rows.iter().map(|row| row.sent).collect(),
            raw: rows.iter().map(|row| row.raw.as_str()).collect(),
            line_hash: rows.iter().map(|row| row.line_hash.as_slice()).collect(),
        }
    }

    /// The parameters of `INSERT`, in the order of its placeholders.
    fn parameters(&self) -> [&(dyn ToSql + Sync); 22] {
        [
            &self.ts,
            &self.kind,
            &self.request_id,
            &self.client,
            &self.method,
            &self.host,
            &self.path,
            &self.class,
            &self.status,
            &self.reason,
            &self.ms,
            &self.upstream,
            &self.mode,
            &self.engine,
            &self.generation,
            &self.rule,
            &self.rules,
            &self.score,
            &self.body,
            &self.sent,
            &self.raw,
            &self.line_hash,
        ]
    }
}

/// A number of a position as the database column holds it.
fn column(value: u64) -> Result<i64, Error> {
    i64::try_from(value).map_err(|_| Error::new(VALUE))
}

impl Store for PgStore {
    type Settings = Settings;

    async fn connect(settings: &Settings) -> Result<PgStore, Error> {
        let mut config = settings.config.clone();
        // Plain text is for `disable` alone: with `prefer` a server that answers "no TLS" would get the password.
        if config.get_ssl_mode() != SslMode::Disable {
            config.ssl_mode(SslMode::Require);
        }
        let (client, driver) = if config.get_ssl_mode() == SslMode::Disable {
            let (client, connection) =
                config.connect(NoTls).await.map_err(|e| not_connected(&e))?;
            (
                client,
                tokio::spawn(async move {
                    let _ = connection.await;
                }),
            )
        } else {
            let connector = tls::connector()?;
            let (client, connection) = config
                .connect(connector)
                .await
                .map_err(|e| not_connected(&e))?;
            (
                client,
                tokio::spawn(async move {
                    let _ = connection.await;
                }),
            )
        };
        let mut store = PgStore {
            client,
            driver,
            source: settings.source.clone(),
        };
        store.setup().await?;
        Ok(store)
    }

    async fn position(&mut self) -> Result<Option<Position>, Error> {
        let row = self
            .client
            .query_opt(
                "SELECT inode, born, \"offset\", lost_lines FROM tukuyomi_records_state WHERE source = $1",
                &[&self.source],
            )
            .await
            .map_err(|e| failed(&e))?;
        let Some(row) = row else {
            return Ok(None);
        };
        let (inode, born, offset, lost): (String, String, i64, i64) =
            (row.get(0), row.get(1), row.get(2), row.get(3));
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
        let columns = Columns::of(rows);
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
        let transaction = self.client.transaction().await.map_err(|e| failed(&e))?;
        let stored = if rows.is_empty() {
            0
        } else {
            transaction
                .execute(INSERT, &columns.parameters())
                .await
                .map_err(|e| failed(&e))?
        };
        let moved = match &expected {
            None => {
                transaction
                    .execute(FIRST, &[&self.source, &inode, &born, &offset, &lost])
                    .await
            }
            Some((from_inode, from_born, from_offset)) => {
                transaction
                    .execute(
                        MOVE,
                        &[
                            &self.source,
                            &inode,
                            &born,
                            &offset,
                            &lost,
                            from_inode,
                            from_born,
                            from_offset,
                        ],
                    )
                    .await
            }
        }
        .map_err(|e| failed(&e))?;
        if moved != 1 {
            let _ = transaction.rollback().await;
            return Err(Error::new(MOVED));
        }
        transaction.commit().await.map_err(|e| failed(&e))?;
        Ok(stored)
    }

    async fn purge(&mut self, days: u32, limit: u32) -> Result<u64, Error> {
        let days = i32::try_from(days).map_err(|_| Error::new(VALUE))?;
        self.client
            .execute(PURGE, &[&days, &i64::from(limit)])
            .await
            .map_err(|e| failed(&e))
    }
}

#[cfg(test)]
mod tests;
