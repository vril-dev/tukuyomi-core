//! The `records` object of the configuration: where the proxy keeps a copy of its records, how much of them, what it
//! does when it cannot keep them, and where a shipper takes them from (see `log::sink` and `log::ship`).
//!
//! The object may be left out, and then the records go to the standard error only and are kept as well as the
//! standard error keeps them (best effort). When it is there it has the keys `dir` (an absolute clean path of at
//! most 3840 bytes; the directory is looked at when the proxy starts, not here), `file_bytes` (1 MiB to 1 GiB: a
//! line that would take the file in use above it starts the next file) and `files` (2 to 64: the files kept, the one
//! in use included), and it may have these:
//! - `keep`: `best_effort` (the default) or `required`. It is what a route that has no `records` of its own does
//!   with a request whose record cannot be kept: `best_effort` lets the request through and drops the record,
//!   `required` turns the request away with 503 (see `inbound::conn`).
//! - `sync_ms` (1 to 60000): the lines written to the file are made to reach the disk (`fsync`) at least this often.
//!   Left out, the operating system decides, and a power loss can take what it had not written yet.
//! - `ship`: the shipper that takes the records out of the files into a database, which the proxy does not run and
//!   only looks at (see `log::ship`). All its keys are there: `db_driver` (`pgsql` or `mysql`), `db_dsn_file` (an
//!   absolute clean path of at most 3840 bytes; the proxy never opens it, for it holds the password of the
//!   database), `batch` (1 to 10000 records for one transaction), `interval_ms` (100 to 60000) and `retention_days`
//!   (0 to 3650; 0 keeps the records for ever). With `ship` the proxy turns away the requests that need their record
//!   kept before the shipper falls so far behind that a rotation would delete records it has not shipped.
//!
//! A route may have `records` of its own: `best_effort`, `required` or `security` (see `forward`). A route with
//! `required`, and `keep` as `required`, need this object. With a `ship` and anything required there must be 3 files
//! or more, for a request that needs its record kept is turned away when the shipper is `files - 2` files behind (see
//! `log::ship`), and that has to be more than nothing.

use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use serde::Deserialize;

use super::{
    ConfigError, ForwardSettings, GIB, MAX_STORE_DIR, MIB, Object, bytes, clean_abs, ensure, within,
};

/// The most files that `files` can keep.
pub(crate) const MAX_RECORD_FILES: usize = 64;
/// The longest `sync_ms`.
const MAX_SYNC_MS: u64 = 60_000;

/// The `records` object, checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Records {
    pub dir: PathBuf,
    /// The size above which the file in use is not given another line.
    pub file_bytes: u64,
    /// The files kept, the one in use included.
    pub files: usize,
    /// What a route without a value of its own does when a record cannot be kept.
    pub keep: Keep,
    /// How often at least the lines written to the file are made to reach the disk; none: the operating system
    /// decides.
    pub sync_ms: Option<u32>,
    /// The shipper, if the file has one.
    pub ship: Option<Ship>,
}

/// What is done with a request whose record cannot be kept: `records.keep`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Keep {
    /// The request goes through and its record is dropped.
    BestEffort,
    /// The request is turned away with 503.
    Required,
}

/// The `records` of a route: `Keep`, and a third value that keeps the records of some requests only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteKeep {
    BestEffort,
    Required,
    /// Best effort, and only the records of the requests that a rule decided, that could not be inspected or that a
    /// policy turned away are written.
    Security,
}

impl Keep {
    /// What a request of a route does that has `route` as its `records`, when the file's `keep` is `self`.
    pub fn for_route(self, route: Option<RouteKeep>) -> RouteKeep {
        route.unwrap_or(match self {
            Keep::BestEffort => RouteKeep::BestEffort,
            Keep::Required => RouteKeep::Required,
        })
    }
}

/// The database the shipper puts the records into.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Driver {
    Pgsql,
    Mysql,
}

/// The `ship` object, checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ship {
    pub driver: Driver,
    /// The file that holds the connection string. The proxy does not open it.
    pub dsn_file: PathBuf,
    /// The most records one transaction takes.
    pub batch: u32,
    /// The time between two rounds of the shipper.
    pub interval_ms: u32,
    /// The days the shipped records are kept in the database; 0: for ever.
    pub retention_days: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawRecords {
    dir: String,
    file_bytes: u64,
    files: usize,
    #[serde(default, deserialize_with = "super::present")]
    keep: Option<String>,
    #[serde(default, deserialize_with = "super::present")]
    sync_ms: Option<u64>,
    #[serde(default, deserialize_with = "super::present")]
    ship: Option<Object<RawShip>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawShip {
    db_driver: String,
    db_dsn_file: String,
    batch: u64,
    interval_ms: u64,
    retention_days: u64,
}

/// `value` as a `u32` if it is from `low` to `high`, else `text` is the refusal.
fn number(value: u64, low: u64, high: u64, text: &'static str) -> Result<u32, ConfigError> {
    u32::try_from(value)
        .ok()
        .filter(|n| (low..=high).contains(&u64::from(*n)))
        .ok_or(ConfigError(text))
}

/// The `ship` object, checked.
fn ship(raw: RawShip) -> Result<Ship, ConfigError> {
    let driver = match raw.db_driver.as_str() {
        "pgsql" => Driver::Pgsql,
        "mysql" => Driver::Mysql,
        _ => return Err(ConfigError("records ship db_driver is not pgsql or mysql")),
    };
    let dsn_file = PathBuf::from(raw.db_dsn_file);
    ensure(
        clean_abs(&dsn_file) && dsn_file.as_os_str().as_bytes().len() <= MAX_STORE_DIR,
        "records ship db_dsn_file is not an absolute clean path of at most 3840 bytes",
    )?;
    Ok(Ship {
        driver,
        dsn_file,
        batch: number(raw.batch, 1, 10_000, "records ship batch is not 1 to 10000")?,
        interval_ms: number(
            raw.interval_ms,
            100,
            60_000,
            "records ship interval_ms is not 100 to 60000",
        )?,
        retention_days: number(
            raw.retention_days,
            0,
            3650,
            "records ship retention_days is not 0 to 3650",
        )?,
    })
}

/// Checks the object.
pub(super) fn check(raw: Option<Object<RawRecords>>) -> Result<Option<Records>, ConfigError> {
    let Some(Object(raw)) = raw else {
        return Ok(None);
    };
    let dir = PathBuf::from(raw.dir);
    ensure(
        clean_abs(&dir) && dir.as_os_str().as_bytes().len() <= MAX_STORE_DIR,
        "records dir is not an absolute clean path of at most 3840 bytes",
    )?;
    ensure(
        (MIB..=GIB).contains(&raw.file_bytes),
        "records file_bytes is not 1 MiB to 1 GiB",
    )?;
    ensure(
        within(raw.files, 2, bytes(MAX_RECORD_FILES)),
        "records files is not 2 to 64",
    )?;
    let keep = match raw.keep.as_deref() {
        None | Some("best_effort") => Keep::BestEffort,
        Some("required") => Keep::Required,
        Some(_) => return Err(ConfigError("records keep is not best_effort or required")),
    };
    let sync_ms = raw
        .sync_ms
        .map(|ms| number(ms, 1, MAX_SYNC_MS, "records sync_ms is not 1 to 60000"))
        .transpose()?;
    Ok(Some(Records {
        dir,
        file_bytes: raw.file_bytes,
        files: raw.files,
        keep,
        sync_ms,
        ship: raw.ship.map(|Object(raw)| ship(raw)).transpose()?,
    }))
}

/// The `records` of a route.
pub(super) fn route_keep(text: &str) -> Result<RouteKeep, ConfigError> {
    match text {
        "best_effort" => Ok(RouteKeep::BestEffort),
        "required" => Ok(RouteKeep::Required),
        "security" => Ok(RouteKeep::Security),
        _ => Err(ConfigError(
            "a route records is not best_effort, required or security",
        )),
    }
}

/// The `records` object against the routes: a route that needs its records kept needs the object, and with a shipper
/// the object has 3 files or more.
pub(crate) fn consistent(
    records: Option<&Records>,
    forward: &ForwardSettings,
) -> Result<(), ConfigError> {
    let route_required = forward
        .routes
        .targets()
        .any(|route| route.records == Some(RouteKeep::Required));
    match records {
        None => ensure(
            !route_required,
            "a route has records required while the file has no records object",
        ),
        Some(records) => ensure(
            records.ship.is_none()
                || records.files >= 3
                || !(route_required || records.keep == Keep::Required),
            "records files is below 3 while ship is there and some records are required",
        ),
    }
}
