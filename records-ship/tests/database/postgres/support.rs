use std::fs;
use std::net::{SocketAddr, ToSocketAddrs};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;
use std::time::Duration;

use std::future::Future;
use tokio::runtime::Runtime;
use tokio_postgres::config::{Host, SslMode};
use tokio_postgres::{Client, Config, NoTls};
use tukuyomi_records_ship::dsn;
use tukuyomi_records_ship::ship::Shipper;
use tukuyomi_records_ship::store::Store;
use tukuyomi_records_ship::store::pgsql::{PgStore, Settings};

pub use crate::support::{
    INTERVAL, Records, Relay, at, lines, raws, rows, runtime, until_idle, var,
};

/// A connection to the schema of the test.
pub async fn connect(db: &Database) -> PgStore {
    PgStore::connect(&db.settings())
        .await
        .unwrap_or_else(|e| panic!("cannot connect to the test database: {e}"))
}

/// A schema of its own in the test database, dropped with everything in it when this is dropped.
pub struct Database {
    /// The runtime that the connections of the test run on; it ends before the schema is dropped, which closes them.
    runtime: Option<Runtime>,
    schema: String,
    /// The settings of the test connection string, plain TCP, in the default schema.
    base: Config,
    admin: Client,
}

impl Database {
    pub fn new() -> Database {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let runtime = runtime();
        let (schema, base, admin) = runtime.block_on(async {
            let path = PathBuf::from(var("TUKUYOMI_TEST_PGSQL_DSN_FILE"));
            let uid = fs::metadata(&path).unwrap().uid();
            let dsn = dsn::read(&path, uid).expect("the test connection string is a good file");
            let mut base = Settings::parse(&dsn, "test")
                .expect("the test connection string parses")
                .config;
            base.ssl_mode(SslMode::Disable);
            let (admin, connection) = base
                .connect(NoTls)
                .await
                .unwrap_or_else(|_| panic!("cannot connect with the test connection string"));
            tokio::spawn(async move {
                let _ = connection.await;
            });
            let schema = format!(
                "tukuyomi_test_{}_{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            );
            admin
                .batch_execute(&format!("CREATE SCHEMA {schema}"))
                .await
                .unwrap_or_else(|_| panic!("cannot make the schema of the test"));
            (schema, base, admin)
        });
        Database {
            runtime: Some(runtime),
            schema,
            base,
            admin,
        }
    }

    /// Runs a test on the runtime of the database.
    pub fn run<F: Future>(&self, future: F) -> F::Output {
        match &self.runtime {
            Some(runtime) => runtime.block_on(future),
            None => unreachable!("the runtime ends in drop"),
        }
    }

    /// The settings of a connection that works in the schema of this test.
    pub fn settings(&self) -> Settings {
        let mut config = self.base.clone();
        config.options(format!("-c search_path={}", self.schema));
        Settings {
            config,
            source: "test".to_owned(),
        }
    }

    /// The settings of a connection to the schema of this test through the local port `port`, which relays to the
    /// server. (The configuration of the test connection string names the server itself, and a host added to it would
    /// only be a second one to try.)
    pub fn settings_through(&self, port: u16) -> Settings {
        let mut config = Config::new();
        if let Some(user) = self.base.get_user() {
            config.user(user);
        }
        if let Some(password) = self.base.get_password() {
            config.password(password);
        }
        if let Some(dbname) = self.base.get_dbname() {
            config.dbname(dbname);
        }
        config
            .host("127.0.0.1")
            .port(port)
            .ssl_mode(SslMode::Disable)
            .options(format!("-c search_path={}", self.schema))
            .connect_timeout(Duration::from_secs(10));
        Settings {
            config,
            source: "test".to_owned(),
        }
    }

    /// The address of the server.
    pub fn server(&self) -> SocketAddr {
        let Host::Tcp(host) = &self.base.get_hosts()[0] else {
            panic!("the test server is reached over TCP");
        };
        let port = self.base.get_ports().first().copied().unwrap_or(5432);
        (host.as_str(), port)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap()
    }

    pub async fn exec(&self, sql: &str) {
        let sql = sql.replace("{s}", &self.schema);
        self.admin
            .batch_execute(&sql)
            .await
            .unwrap_or_else(|_| panic!("a statement of the test failed: {sql}"));
    }

    /// The lines of all rows, in the order they were stored.
    pub async fn raws(&self) -> Vec<String> {
        let sql = format!(
            "SELECT raw FROM {}.tukuyomi_records ORDER BY id",
            self.schema
        );
        let rows = self.admin.query(sql.as_str(), &[]).await.unwrap();
        rows.iter().map(|row| row.get(0)).collect()
    }

    pub async fn count(&self) -> usize {
        self.raws().await.len()
    }

    /// One text value of a query that gives one row.
    pub async fn text(&self, sql: &str) -> String {
        let sql = sql.replace("{s}", &self.schema);
        self.admin
            .query_one(sql.as_str(), &[])
            .await
            .unwrap()
            .get(0)
    }
}

impl Drop for Database {
    fn drop(&mut self) {
        drop(self.runtime.take());
        let (config, schema) = (self.base.clone(), self.schema.clone());
        // The runtime of the test may be gone: a thread of its own drops the schema.
        let _ = thread::spawn(move || {
            runtime().block_on(async move {
                if let Ok((client, connection)) = config.connect(NoTls).await {
                    tokio::spawn(async move {
                        let _ = connection.await;
                    });
                    let _ = client
                        .batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
                        .await;
                }
            });
        })
        .join();
    }
}

/// A shipper of `records` into the database of the test.
pub fn shipper(
    records: &Records,
    batch: usize,
    retention_days: u32,
    settings: Settings,
) -> Shipper<PgStore> {
    crate::support::shipper::<PgStore>(records, batch, retention_days, settings)
}
