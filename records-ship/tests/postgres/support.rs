use std::fs;
use std::io;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use std::future::Future;
use tokio::runtime::{Builder, Runtime};
use tokio_postgres::config::{Host, SslMode};
use tokio_postgres::{Client, Config, NoTls};
use tukuyomi_proxy::log::{Format, start_logger};
use tukuyomi_records_ship::dsn;
use tukuyomi_records_ship::ship::{self, Shipper};
use tukuyomi_records_ship::store::Store;
use tukuyomi_records_ship::store::pgsql::{PgStore, Settings};

pub const INTERVAL: Duration = Duration::from_millis(100);

pub fn var(name: &str) -> String {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => v,
        _ => panic!("{name} is not set: this real-database test needs it and is never skipped"),
    }
}

pub fn runtime() -> Runtime {
    Builder::new_current_thread().enable_all().build().unwrap()
}

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

/// A fresh 0700 directory for record files, removed with everything in it when dropped.
pub struct Records(pub PathBuf);

impl Records {
    pub fn new() -> Records {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "tukuyomi-ship-pg-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        Records(dir)
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    pub fn write(&self, name: &str, text: &str) {
        fs::write(self.path(name), text).unwrap();
    }

    pub fn append(&self, name: &str, text: &str) {
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(self.path(name))
            .unwrap();
        file.write_all(text.as_bytes()).unwrap();
    }

    /// What the proxy does when the file in use is full: the files go up by one name and a new one is made.
    pub fn rotate(&self) {
        for n in (1..3).rev() {
            let from = self.path(&format!("records.{n}.log"));
            if from.exists() {
                fs::rename(&from, self.path(&format!("records.{}.log", n + 1))).unwrap();
            }
        }
        fs::rename(self.path("records.log"), self.path("records.1.log")).unwrap();
        fs::write(self.path("records.log"), "").unwrap();
    }
}

impl Drop for Records {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Lines `from` to `to`, each as a record of the type `line`.
pub fn lines(from: usize, to: usize) -> String {
    (from..to)
        .map(|n| {
            format!("{{\"ts\":\"2026-10-25T08:00:00.123Z\",\"type\":\"line\",\"line\":\"n{n}\"}}\n")
        })
        .collect()
}

/// The text of the lines `from` to `to` as the database keeps them in `raw`.
pub fn raws(from: usize, to: usize) -> Vec<String> {
    lines(from, to).lines().map(str::to_owned).collect()
}

pub fn shipper(
    records: &Records,
    batch: usize,
    retention_days: u32,
    settings: Settings,
) -> Shipper<PgStore> {
    let log = start_logger(Format::Json).unwrap();
    Shipper::new(
        ship::Settings {
            dir: records.0.clone(),
            files: 4,
            batch,
            interval: INTERVAL,
            retention_days,
        },
        settings,
        log,
    )
}

/// Turns until one asks for a wait. An error asks for one as well.
pub async fn until_idle(shipper: &mut Shipper<PgStore>) {
    while shipper.turn().await == Duration::ZERO {}
}

/// A relay of TCP connections to the server, to be stopped and started to take the database away and bring it back.
pub struct Relay {
    pub port: u16,
    stop: Arc<AtomicBool>,
    streams: Arc<Mutex<Vec<TcpStream>>>,
    accept: Option<JoinHandle<()>>,
}

impl Relay {
    /// Listens on 127.0.0.1 at `port` (0: any) and relays to `target`.
    pub fn start(target: SocketAddr, port: u16) -> Relay {
        let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let streams: Arc<Mutex<Vec<TcpStream>>> = Arc::default();
        let accept = {
            let (stop, streams) = (stop.clone(), streams.clone());
            thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((client, _)) => {
                            client.set_nonblocking(false).unwrap();
                            let Ok(server) = TcpStream::connect(target) else {
                                continue;
                            };
                            let mut held = streams.lock().unwrap_or_else(PoisonError::into_inner);
                            held.push(client.try_clone().unwrap());
                            held.push(server.try_clone().unwrap());
                            for (mut from, mut to) in [
                                (client.try_clone().unwrap(), server.try_clone().unwrap()),
                                (server, client),
                            ] {
                                thread::spawn(move || {
                                    let _ = io::copy(&mut from, &mut to);
                                    let _ = to.shutdown(Shutdown::Both);
                                });
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            })
        };
        Relay {
            port,
            stop,
            streams,
            accept: Some(accept),
        }
    }

    /// Closes the listener and every connection through it.
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
        let held = self.streams.lock().unwrap_or_else(PoisonError::into_inner);
        for stream in held.iter() {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}
