use std::cell::RefCell;
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicU32, Ordering};

use tukuyomi_proxy::log::ship::{Identity, Position as State};
use tukuyomi_proxy::log::{Format, start_logger};

use super::*;
use crate::follow::Position;
use crate::store::{CONNECT, LOGIN, MOVED};

fn block_on<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}

struct TestDir(PathBuf);

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn scratch() -> TestDir {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "tukuyomi-ship-loop-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    TestDir(dir)
}

/// A database in memory.
#[derive(Default)]
struct Db {
    hashes: Vec<Vec<u8>>,
    position: Option<Position>,
    /// Every call fails.
    down: bool,
    /// The connection is refused for its login.
    refuses_login: bool,
    /// A commit is applied and then reported as failed, as when the connection is lost after the commit.
    lose_answer: bool,
    connects: u32,
}

type Shared = Rc<RefCell<Db>>;

struct Fake(Shared);

impl Store for Fake {
    type Settings = Shared;

    async fn connect(db: &Shared) -> Result<Fake, Error> {
        let mut state = db.borrow_mut();
        if state.refuses_login {
            return Err(Error::new(LOGIN));
        }
        if state.down {
            return Err(Error::new(CONNECT));
        }
        state.connects += 1;
        Ok(Fake(db.clone()))
    }

    async fn position(&mut self) -> Result<Option<Position>, Error> {
        Ok(self.0.borrow().position)
    }

    async fn commit(
        &mut self,
        from: Option<Position>,
        to: Position,
        rows: &[Row],
    ) -> Result<u64, Error> {
        let mut db = self.0.borrow_mut();
        if db.down {
            return Err(Error::new(CLOSED));
        }
        if db.position != from {
            return Err(Error::new(MOVED));
        }
        let mut stored = 0;
        for row in rows {
            if !db.hashes.contains(&row.line_hash) {
                db.hashes.push(row.line_hash.clone());
                stored += 1;
            }
        }
        db.position = Some(to);
        if db.lose_answer {
            return Err(Error::new(CLOSED));
        }
        Ok(stored)
    }

    async fn purge(&mut self, _: u32, _: u32) -> Result<u64, Error> {
        Ok(0)
    }
}

const INTERVAL: Duration = Duration::from_millis(100);

fn shipper(dir: &TestDir, batch: usize, db: &Shared) -> Shipper<Fake> {
    let log = start_logger(Format::Json).unwrap();
    Shipper::new(
        Settings {
            dir: dir.0.clone(),
            files: 4,
            batch,
            interval: INTERVAL,
            retention_days: 0,
        },
        db.clone(),
        log,
    )
}

fn lines(from: usize, to: usize) -> String {
    (from..to).map(|n| format!("line {n}\n")).collect()
}

#[test]
fn the_waits_double_up_to_a_minute_and_start_again() {
    let mut backoff = Backoff::new(INTERVAL);
    let waits: Vec<u128> = (0..12).map(|_| backoff.fail().as_millis()).collect();
    assert_eq!(
        waits,
        [
            100, 200, 400, 800, 1600, 3200, 6400, 12800, 25600, 51200, 60000, 60000
        ]
    );
    backoff.ok();
    assert_eq!(backoff.fail(), INTERVAL);
    // An interval of a minute stays a minute.
    let mut slow = Backoff::new(Duration::from_secs(60));
    assert_eq!(slow.fail(), Duration::from_secs(60));
    assert_eq!(slow.fail(), Duration::from_secs(60));
}

#[test]
fn a_full_batch_asks_for_no_wait_and_the_last_one_for_the_interval() {
    let dir = scratch();
    fs::write(dir.0.join("records.log"), lines(0, 5)).unwrap();
    let db = Shared::default();
    let mut shipper = shipper(&dir, 2, &db);
    let waits: Vec<Duration> = (0..4).map(|_| block_on(shipper.turn())).collect();
    assert_eq!(waits, [Duration::ZERO, Duration::ZERO, INTERVAL, INTERVAL]);
    assert_eq!(db.borrow().hashes.len(), 5);
    let position = db.borrow().position.unwrap();
    assert_eq!(
        position.offset,
        fs::metadata(dir.0.join("records.log")).unwrap().len()
    );
    // The position file is that of the database.
    let state = State::parse(&fs::read(dir.0.join("ship.state")).unwrap()).unwrap();
    assert_eq!(
        (state.identity(), state.offset, state.lost_lines),
        (position.identity, position.offset, 0)
    );
}

#[test]
fn a_database_that_fails_is_waited_for_and_nothing_is_lost() {
    let dir = scratch();
    fs::write(dir.0.join("records.log"), lines(0, 3)).unwrap();
    let db = Shared::default();
    let mut shipper = shipper(&dir, 2, &db);
    assert_eq!(block_on(shipper.turn()), Duration::ZERO);
    assert_eq!(db.borrow().hashes.len(), 2);
    // The database goes away while more lines are written.
    db.borrow_mut().down = true;
    let mut log = fs::OpenOptions::new()
        .append(true)
        .open(dir.0.join("records.log"))
        .unwrap();
    std::io::Write::write_all(&mut log, lines(3, 8).as_bytes()).unwrap();
    let waits: Vec<Duration> = (0..4).map(|_| block_on(shipper.turn())).collect();
    assert_eq!(
        waits,
        [
            Duration::from_millis(100),
            Duration::from_millis(200),
            Duration::from_millis(400),
            Duration::from_millis(800)
        ]
    );
    assert_eq!(db.borrow().hashes.len(), 2);
    // The position file stays alive and shows where the shipping is.
    assert!(State::parse(&fs::read(dir.0.join("ship.state")).unwrap()).is_some());
    // It comes back: the rest is shipped once, and the waits start again.
    db.borrow_mut().down = false;
    while block_on(shipper.turn()) == Duration::ZERO {}
    assert_eq!(db.borrow().hashes.len(), 8);
    // The next failure waits the interval again, not the longer time of the earlier ones.
    std::io::Write::write_all(&mut log, lines(8, 9).as_bytes()).unwrap();
    db.borrow_mut().down = true;
    assert_eq!(block_on(shipper.turn()), INTERVAL);
}

#[test]
fn a_commit_whose_answer_was_lost_is_settled_by_the_database() {
    let dir = scratch();
    fs::write(dir.0.join("records.log"), lines(0, 4)).unwrap();
    let db = Shared::default();
    let mut shipper = shipper(&dir, 2, &db);
    db.borrow_mut().lose_answer = true;
    // The database stored the batch and the position; the shipper heard of an error.
    assert_eq!(block_on(shipper.turn()), INTERVAL);
    assert_eq!(db.borrow().hashes.len(), 2);
    db.borrow_mut().lose_answer = false;
    // It connects again, reads the position, and goes on after the stored lines: no refusal, no second copy.
    while block_on(shipper.turn()) == Duration::ZERO {}
    assert_eq!(db.borrow().hashes.len(), 4);
    assert_eq!(db.borrow().connects, 2);
}

#[test]
fn another_position_in_the_database_stops_the_batch_and_it_is_read_again() {
    let dir = scratch();
    fs::write(dir.0.join("records.log"), lines(0, 2)).unwrap();
    let db = Shared::default();
    let mut shipper = shipper(&dir, 10, &db);
    block_on(shipper.open()).unwrap();
    // Another shipper moved the position after this one read it.
    db.borrow_mut().position = Some(Position {
        identity: Identity { inode: 1, born: 1 },
        offset: 1,
        lost_lines: 0,
    });
    assert_eq!(block_on(shipper.turn()), INTERVAL);
    assert!(db.borrow().hashes.is_empty());
}

#[test]
fn a_file_rotated_away_while_the_database_was_away_is_still_finished() {
    let dir = scratch();
    fs::write(dir.0.join("records.log"), lines(0, 3)).unwrap();
    let db = Shared::default();
    let mut shipper = shipper(&dir, 2, &db);
    assert_eq!(block_on(shipper.turn()), Duration::ZERO);
    assert_eq!(db.borrow().hashes.len(), 2);
    db.borrow_mut().down = true;
    let mut log = fs::OpenOptions::new()
        .append(true)
        .open(dir.0.join("records.log"))
        .unwrap();
    std::io::Write::write_all(&mut log, lines(3, 6).as_bytes()).unwrap();
    assert_eq!(block_on(shipper.turn()), INTERVAL);
    // The proxy rotates the file the shipper is in so far that it is gone from the directory, and starts a new one.
    fs::remove_file(dir.0.join("records.log")).unwrap();
    fs::write(dir.0.join("records.log"), lines(6, 8)).unwrap();
    assert_eq!(block_on(shipper.turn()), 2 * INTERVAL);
    // The database is back: the rest of the file that is gone is shipped, and then the new file; nothing is lost.
    db.borrow_mut().down = false;
    while block_on(shipper.turn()) == Duration::ZERO {}
    assert_eq!(db.borrow().hashes.len(), 8);
    assert_eq!(db.borrow().position.unwrap().lost_lines, 0);
}

#[test]
fn a_database_that_is_down_at_the_start_is_waited_for() {
    let dir = scratch();
    fs::write(dir.0.join("records.log"), lines(0, 3)).unwrap();
    let db = Shared::default();
    db.borrow_mut().down = true;
    let mut shipper = shipper(&dir, 10, &db);
    // The same waits as for a database that goes away later.
    assert_eq!(block_on(shipper.turn()), INTERVAL);
    assert_eq!(block_on(shipper.turn()), 2 * INTERVAL);
    assert!(db.borrow().hashes.is_empty());
    db.borrow_mut().down = false;
    while block_on(shipper.turn()) == Duration::ZERO {}
    assert_eq!(db.borrow().hashes.len(), 3);
}

#[test]
fn a_database_that_refuses_the_login_is_not_waited_for() {
    let dir = scratch();
    fs::write(dir.0.join("records.log"), lines(0, 3)).unwrap();
    let db = Shared::default();
    let mut running = shipper(&dir, 10, &db);
    while block_on(running.turn()) == Duration::ZERO {}
    assert_eq!(db.borrow().hashes.len(), 3);
    // A database that is away is waited for: a line to ship finds the connection closed.
    db.borrow_mut().down = true;
    fs::write(dir.0.join("records.log"), lines(0, 4)).unwrap();
    assert_eq!(block_on(running.turn()), INTERVAL);
    assert!(!running.login_refused());
    // A login that is refused when the connection is made again is told to the caller, which stops.
    db.borrow_mut().down = false;
    db.borrow_mut().refuses_login = true;
    block_on(running.turn());
    assert!(running.login_refused());
    // And at the start.
    let mut starting = shipper(&dir, 10, &db);
    block_on(starting.turn());
    assert!(starting.login_refused());
}
