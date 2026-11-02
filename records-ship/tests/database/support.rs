//! What the tests of every database share: the record files, the lines, the relay that takes a database away, and
//! the shipper over a store.

use std::fs;
use std::io;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use tokio::runtime::{Builder, Runtime};
use tukuyomi_proxy::log::ship::Identity;
use tukuyomi_proxy::log::{Format, start_logger};
use tukuyomi_records_ship::follow::Position;
use tukuyomi_records_ship::row::Row;
use tukuyomi_records_ship::ship::{self, Shipper};
use tukuyomi_records_ship::store::Store;

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

/// The rows `from` to `to`, as lines of no record type.
pub fn rows(from: usize, to: usize) -> Vec<Row> {
    (from..to)
        .map(|n| Row::of(format!("row {n}").as_bytes()))
        .collect()
}

/// A position in a file with fixed numbers, at `offset`.
pub fn at(offset: u64) -> Position {
    Position {
        identity: Identity { inode: 7, born: 8 },
        offset,
        lost_lines: 0,
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

/// A shipper of `records` into the store `S`.
pub fn shipper<S: Store>(
    records: &Records,
    batch: usize,
    retention_days: u32,
    settings: S::Settings,
) -> Shipper<S> {
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
pub async fn until_idle<S: Store>(shipper: &mut Shipper<S>) {
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
