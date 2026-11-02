use std::fs;
use std::future::Future;
use std::net::{SocketAddr, ToSocketAddrs};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use mysql_async::prelude::Queryable;
use mysql_async::{Conn, OptsBuilder};
use tokio::runtime::Runtime;
use tokio::sync::Mutex;
use tukuyomi_records_ship::dsn::{self, Dsn};
use tukuyomi_records_ship::ship::Shipper;
use tukuyomi_records_ship::store::Store;
use tukuyomi_records_ship::store::mysql::{MyStore, Settings};

pub use crate::support::{
    INTERVAL, Records, Relay, at, lines, raws, rows, runtime, until_idle, var,
};

/// The name of the lock of the server that a test holds while it runs, and how many seconds another one waits.
const TEST_LOCK: &str = "tukuyomi_records_test_database";
const TEST_LOCK_WAIT: u32 = 600;
/// The tables of the shipper.
const TABLES: &str = "tukuyomi_records, tukuyomi_records_state, tukuyomi_records_schema";

/// A connection string from a file, as `run` makes it.
fn dsn_of(text: &str) -> Dsn {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let path = std::env::temp_dir().join(format!(
        "tukuyomi-ship-mytest-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&path, text).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let uid = fs::metadata(&path).unwrap().uid();
    let dsn = dsn::read(&path, uid).expect("the test connection string is a good file");
    fs::remove_file(&path).unwrap();
    dsn
}

/// A connection to the database of the test.
pub async fn connect(db: &Database) -> MyStore {
    MyStore::connect(&db.settings())
        .await
        .unwrap_or_else(|e| panic!("cannot connect to the test database: {e}"))
}

/// The database of the test, with no table of the shipper in it at the start and at the end. It is the one database
/// that the user of the test has, so a test holds a lock of the server while it runs, and the tests of one run, and
/// of every run, go one after the other.
pub struct Database {
    /// The runtime that the connections of the test run on; the tables are dropped on it, before it ends.
    runtime: Option<Runtime>,
    /// The test connection string, as it is written in the file: TLS is what it means.
    text: String,
    /// The settings of the test connection string with the plain form written, for the server is on this host.
    plain: Settings,
    /// The connection that holds the lock, and with which the test looks into the tables.
    admin: Mutex<Option<Conn>>,
}

impl Database {
    pub fn new() -> Database {
        let runtime = runtime();
        let path = PathBuf::from(var("TUKUYOMI_TEST_MYSQL_DSN_FILE"));
        let uid = fs::metadata(&path).unwrap().uid();
        let text = dsn::read(&path, uid)
            .expect("the test connection string is a good file")
            .text()
            .to_owned();
        let separator = if text.contains('?') { '&' } else { '?' };
        let plain = Settings::parse(
            &dsn_of(&format!("{text}{separator}require_ssl=false")),
            "test",
        )
        .expect("the test connection string parses");
        let admin = runtime.block_on(async {
            let mut admin = Conn::new(plain.opts.clone())
                .await
                .unwrap_or_else(|_| panic!("cannot connect with the test connection string"));
            let got: Option<Option<i64>> = admin
                .exec_first("SELECT GET_LOCK(?, ?)", (TEST_LOCK, TEST_LOCK_WAIT))
                .await
                .unwrap();
            assert_eq!(got.flatten(), Some(1), "the lock of the tests is not free");
            admin
                .query_drop(format!("DROP TABLE IF EXISTS {TABLES}"))
                .await
                .unwrap_or_else(|_| panic!("cannot drop the tables of the shipper"));
            admin
        });
        Database {
            runtime: Some(runtime),
            text,
            plain,
            admin: Mutex::new(Some(admin)),
        }
    }

    /// Runs a test on the runtime of the database.
    pub fn run<F: Future>(&self, future: F) -> F::Output {
        match &self.runtime {
            Some(runtime) => runtime.block_on(future),
            None => unreachable!("the runtime ends in drop"),
        }
    }

    /// The settings of a connection to the database of this test, plain.
    pub fn settings(&self) -> Settings {
        Settings {
            opts: self.plain.opts.clone(),
            source: "test".to_owned(),
        }
    }

    /// The settings of the test connection string as it is written: TLS, which the server of the test cannot give
    /// with a certificate that is accepted.
    pub fn tls_settings(&self) -> Settings {
        Settings::parse(&dsn_of(&self.text), "test").expect("the test connection string parses")
    }

    /// The settings of a connection to the database of this test through the local port `port`, which relays to the
    /// server.
    pub fn settings_through(&self, port: u16) -> Settings {
        Settings {
            opts: OptsBuilder::from_opts(self.plain.opts.clone())
                .ip_or_hostname("127.0.0.1")
                .tcp_port(port)
                .into(),
            source: "test".to_owned(),
        }
    }

    /// The address of the server.
    pub fn server(&self) -> SocketAddr {
        (self.plain.opts.ip_or_hostname(), self.plain.opts.tcp_port())
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap()
    }

    pub async fn exec(&self, sql: &str) {
        let mut admin = self.admin.lock().await;
        admin
            .as_mut()
            .expect("the connection ends in drop")
            .query_drop(sql)
            .await
            .unwrap_or_else(|_| panic!("a statement of the test failed: {sql}"));
    }

    /// The lines of all rows, in the order they were stored.
    pub async fn raws(&self) -> Vec<String> {
        let mut admin = self.admin.lock().await;
        admin
            .as_mut()
            .expect("the connection ends in drop")
            .query("SELECT raw FROM tukuyomi_records ORDER BY id")
            .await
            .unwrap()
    }

    pub async fn count(&self) -> usize {
        self.raws().await.len()
    }

    /// One text value of a query that gives one row.
    pub async fn text(&self, sql: &str) -> String {
        let mut admin = self.admin.lock().await;
        admin
            .as_mut()
            .expect("the connection ends in drop")
            .query_first(sql)
            .await
            .unwrap_or_else(|_| panic!("a query of the test failed: {sql}"))
            .expect("the query of the test gave no row")
    }
}

impl Drop for Database {
    fn drop(&mut self) {
        // The tables are dropped and the connection, which holds the lock, is closed on the runtime it belongs to.
        if let (Some(runtime), Some(mut admin)) = (self.runtime.take(), self.admin.get_mut().take())
        {
            runtime.block_on(async {
                let _ = admin
                    .query_drop(format!("DROP TABLE IF EXISTS {TABLES}"))
                    .await;
                let _ = admin.disconnect().await;
            });
        }
    }
}

/// A shipper of `records` into the database of the test.
pub fn shipper(
    records: &Records,
    batch: usize,
    retention_days: u32,
    settings: Settings,
) -> Shipper<MyStore> {
    crate::support::shipper::<MyStore>(records, batch, retention_days, settings)
}
