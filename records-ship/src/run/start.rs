//! The arguments, the checks, the configuration and the loop of the shipper process (see `run`).

use std::path::{Path, PathBuf};
use std::time::Duration;

use tukuyomi_proxy::config::{self, Driver};
use tukuyomi_proxy::log::Log;

use super::host;
use super::notify::Notify;
use super::signals::Signals;
use crate::dsn;
use crate::ship::{HEARTBEAT, Settings, Shipper};
use crate::store::Store;
use crate::store::mysql::{self, MyStore};
use crate::store::pgsql::{self, PgStore};

/// The settings of the database that `db_driver` names. The settings of PostgreSQL are the larger, and boxed.
enum Database {
    Pgsql(Box<pgsql::Settings>),
    Mysql(mysql::Settings),
}

pub const EXIT_OK: u8 = 0;
pub const EXIT_FAILED: u8 = 1;
const EXIT_USAGE: u8 = 2;

/// Runs the process: the arguments are those of the process.
pub fn start(log: &Log) -> u8 {
    let mut args = std::env::args_os().skip(1);
    let path = match (args.next(), args.next()) {
        (Some(path), None) if config::clean_abs(Path::new(&path)) => PathBuf::from(path),
        _ => {
            log.line(
                "records-ship: expected one argument, the absolute clean path of the configuration file",
            );
            return EXIT_USAGE;
        }
    };
    run(&path, log)
}

fn run(path: &Path, log: &Log) -> u8 {
    if let Err(text) = host::not_root() {
        log.line(&format!("records-ship: host check refused: {text}"));
        return EXIT_FAILED;
    }
    let loaded = match config::load_main(path) {
        Ok(loaded) => loaded,
        Err(e) => {
            log.line(&format!("records-ship: configuration refused: {}", e.0));
            return EXIT_USAGE;
        }
    };
    let Some((records, ship)) = loaded
        .records
        .as_ref()
        .and_then(|records| records.ship.as_ref().map(|ship| (records, ship)))
    else {
        log.line("records-ship: configuration refused: there is no records.ship object");
        return EXIT_USAGE;
    };
    log.line("records-ship: configuration accepted");
    let uid = match host::fs_uid() {
        Ok(uid) => uid,
        Err(text) => {
            log.line(&format!("records-ship: host check refused: {text}"));
            return EXIT_FAILED;
        }
    };
    if let Err(text) = host::private_dir(&records.dir, uid) {
        log.line(&format!("records-ship: records dir refused: {text}"));
        return EXIT_FAILED;
    }
    if let Err(text) = host::birth_times(&records.dir, records.files) {
        log.line(&format!("records-ship: records dir refused: {text}"));
        return EXIT_FAILED;
    }
    let dsn = match dsn::read(&ship.dsn_file, uid) {
        Ok(dsn) => dsn,
        Err(text) => {
            log.line(&format!("records-ship: {text}"));
            return EXIT_FAILED;
        }
    };
    // The position of the shipping is kept under the directory of the records it follows.
    let source = records.dir.to_string_lossy().into_owned();
    let parsed = match ship.driver {
        Driver::Pgsql => {
            pgsql::Settings::parse(&dsn, &source).map(|s| Database::Pgsql(Box::new(s)))
        }
        Driver::Mysql => mysql::Settings::parse(&dsn, &source).map(Database::Mysql),
    };
    let database = match parsed {
        Ok(database) => database,
        Err(e) => {
            log.line(&format!("records-ship: {e}"));
            return EXIT_FAILED;
        }
    };
    let Ok(batch) = usize::try_from(ship.batch) else {
        log.line("records-ship: configuration refused: batch does not fit");
        return EXIT_USAGE;
    };
    let settings = Settings {
        dir: records.dir.clone(),
        files: records.files,
        batch,
        interval: Duration::from_millis(u64::from(ship.interval_ms)),
        retention_days: ship.retention_days,
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            log.line("records-ship: cannot build the runtime");
            return EXIT_FAILED;
        }
    };
    match database {
        Database::Pgsql(database) => runtime.block_on(serve::<PgStore>(settings, *database, log)),
        Database::Mysql(database) => runtime.block_on(serve::<MyStore>(settings, database, log)),
    }
}

/// Ships until a signal asks for the stop, and stops. The first turn connects; a database that is away is waited
/// for as at any other time. A database that refuses the login ends the shipping with the failure code.
async fn serve<S: Store>(settings: Settings, database: S::Settings, log: &Log) -> u8 {
    let Some(mut signals) = Signals::install() else {
        log.line("records-ship: cannot install the signal handlers");
        return EXIT_FAILED;
    };
    let notify = Notify::from_env(log);
    let mut shipper = Shipper::<S>::new(settings, database, log.clone());
    log.line("records-ship: shipping");
    notify.ready(log);
    let cause = 'run: loop {
        // The wait is in slices of a second at most, so that the position file stays young also while the database
        // is waited for.
        let mut wait = shipper.turn().await;
        if shipper.login_refused() {
            log.line("records-ship: stop: the login is refused, which waiting does not mend");
            notify.stopping(log);
            return EXIT_FAILED;
        }
        loop {
            let slice = wait.min(HEARTBEAT);
            if let Some(name) = signals.sleep(slice).await {
                break 'run name;
            }
            wait = wait.saturating_sub(slice);
            if wait.is_zero() {
                break;
            }
            shipper.keep_alive();
        }
    };
    log.line(&format!("records-ship: stop: {cause}"));
    notify.stopping(log);
    EXIT_OK
}
