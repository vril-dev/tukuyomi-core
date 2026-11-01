//! The shipping loop, one turn at a time.
//!
//! A turn makes sure there is a connection (a new one reads the position from the database, which is the truth,
//! and the follower goes on from it, keeping the record files it holds open), takes up to `batch` lines from the
//! follower, has the database store them and the position that they lead to in one transaction, and only then lets
//! the follower and the position file (`ship.state`) move to that position. It returns how long to wait before the
//! next turn: no time when a full batch was shipped, so that a backlog is worked off at once, the interval when
//! there was nothing more, and, after an error, a time that doubles from the interval to one minute and starts
//! again at the interval after a turn that worked. A database that cannot be reached is waited for in the same way
//! at the start. After an error the connection is dropped and the position is read again at the next turn, so a
//! commit whose outcome is not known is settled by what the database has. Every call to the database is bounded in
//! time.
//!
//! A database that refuses the login is not waited for, for waiting does not change the user or the password that
//! the connection string holds: the turn that heard it says so through `login_refused`, and the caller stops.
//!
//! While nothing new comes and while the database cannot be reached, the position file is written again at least
//! once a second with the time of now (the turn does it when it ends without work, `keep_alive` is for the caller
//! while it waits), so that its reader can tell a shipper that is alive and behind from one that is not running.
//!
//! With `retention_days` the turn removes, once a minute (at once again while a removal took its whole batch), up
//! to 1000 rows older than that many days.

use std::future::Future;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

use tokio::time::timeout;
use tukuyomi_proxy::log::Log;

use crate::files;
use crate::follow::{Follower, Note};
use crate::row::Row;
use crate::store::{CLOSED, Error, FILES, LOGIN, Store, TIMEOUT};

/// The longest a call to the database may take.
const DATABASE_WAIT: Duration = Duration::from_secs(30);
/// The longest wait after an error.
const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// The least time between two writes of the position file when the position did not change.
pub const HEARTBEAT: Duration = Duration::from_secs(1);
/// The most rows a removal takes, and the pause after one that took fewer.
const PURGE_ROWS: u32 = 1000;
const PURGE_PAUSE: Duration = Duration::from_secs(60);

/// What the shipping is told by the configuration.
#[derive(Clone, Debug)]
pub struct Settings {
    /// The directory of the record files, which also holds `ship.state`.
    pub dir: PathBuf,
    /// The record files kept (`records.files`).
    pub files: usize,
    /// The most lines of a batch.
    pub batch: usize,
    pub interval: Duration,
    /// Rows older than this many days are removed; 0 keeps them.
    pub retention_days: u32,
}

/// The waits after errors: the interval, then twice that, and so on up to a minute.
#[derive(Clone, Copy, Debug)]
pub struct Backoff {
    base: Duration,
    next: Duration,
}

impl Backoff {
    pub fn new(base: Duration) -> Backoff {
        Backoff { base, next: base }
    }

    /// The wait after an error.
    pub fn fail(&mut self) -> Duration {
        let wait = self.next;
        self.next = self.next.saturating_mul(2).min(BACKOFF_MAX.max(self.base));
        wait
    }

    /// A turn worked.
    pub fn ok(&mut self) {
        self.next = self.base;
    }
}

/// A call to the database, given up after `DATABASE_WAIT`.
async fn within<T>(call: impl Future<Output = Result<T, Error>>) -> Result<T, Error> {
    match timeout(DATABASE_WAIT, call).await {
        Ok(result) => result,
        Err(_) => Err(Error::new(TIMEOUT)),
    }
}

/// The shipper of one directory of record files into one database.
pub struct Shipper<S: Store> {
    settings: Settings,
    database: S::Settings,
    store: Option<S>,
    follower: Follower,
    backoff: Backoff,
    /// When the position file was last written.
    written: Option<Instant>,
    /// The last write of the position file failed.
    state_failed: bool,
    /// The database refused the login.
    login_refused: bool,
    next_purge: Instant,
    log: Log,
}

impl<S: Store> Shipper<S> {
    /// A shipper that has not connected yet.
    pub fn new(settings: Settings, database: S::Settings, log: Log) -> Shipper<S> {
        Shipper {
            follower: Follower::new(&settings.dir, settings.files, None),
            backoff: Backoff::new(settings.interval),
            settings,
            database,
            store: None,
            written: None,
            state_failed: false,
            login_refused: false,
            next_purge: Instant::now(),
            log,
        }
    }

    /// Connects, reads the position from the database and writes the position file for it. Only the side of the
    /// database is made anew: the follower keeps the record files it holds, for one that the proxy has rotated away
    /// since is still read to its end.
    pub async fn open(&mut self) -> Result<(), Error> {
        self.store = None;
        let mut store = within(S::connect(&self.database)).await?;
        let position = within(store.position()).await?;
        self.follower.resume(position);
        self.store = Some(store);
        self.write_state(true);
        Ok(())
    }

    /// The follower.
    pub fn follower(&self) -> &Follower {
        &self.follower
    }

    /// One turn. Gives the time to wait before the next.
    pub async fn turn(&mut self) -> Duration {
        if self.store.is_none()
            && let Err(error) = self.open().await
        {
            self.fail(&error);
            return self.backoff.fail();
        }
        match self.cycle().await {
            Ok(more) => {
                self.backoff.ok();
                self.purge().await;
                if more {
                    return Duration::ZERO;
                }
                self.write_state(false);
                self.settings.interval
            }
            Err(error) => {
                self.fail(&error);
                self.backoff.fail()
            }
        }
    }

    /// Writes the position file again if it is a second old: for the caller that waits between two turns.
    pub fn keep_alive(&mut self) {
        self.write_state(false);
    }

    /// Whether the database has refused the login: the caller stops, for the next turn would be refused as well.
    pub fn login_refused(&self) -> bool {
        self.login_refused
    }

    /// Says what went wrong, drops the connection and keeps the position file alive.
    fn fail(&mut self, error: &Error) {
        self.log.line(&format!("records-ship: {error}"));
        self.login_refused |= error.what == LOGIN;
        self.store = None;
        self.write_state(false);
    }

    /// Ships one batch. True: it was a full one, so there is probably more.
    async fn cycle(&mut self) -> Result<bool, Error> {
        let batch = self.follower.read(self.settings.batch);
        for note in self.follower.take_notes() {
            self.say(note);
        }
        let Some(batch) = batch.map_err(|_| Error::new(FILES))? else {
            return Ok(false);
        };
        let rows: Vec<Row> = batch.lines.iter().map(|line| Row::of(line)).collect();
        let Some(store) = self.store.as_mut() else {
            return Err(Error::new(CLOSED));
        };
        within(store.commit(batch.from, batch.to, &rows)).await?;
        self.follower.accept(&batch);
        self.write_state(true);
        Ok(batch.lines.len() >= self.settings.batch)
    }

    /// Removes old rows when it is time to.
    async fn purge(&mut self) {
        if self.settings.retention_days == 0 || Instant::now() < self.next_purge {
            return;
        }
        let Some(store) = self.store.as_mut() else {
            return;
        };
        match within(store.purge(self.settings.retention_days, PURGE_ROWS)).await {
            Ok(removed) => {
                self.next_purge = if removed >= u64::from(PURGE_ROWS) {
                    Instant::now()
                } else {
                    Instant::now() + PURGE_PAUSE
                };
            }
            Err(error) => {
                self.next_purge = Instant::now() + PURGE_PAUSE;
                self.fail(&error);
            }
        }
    }

    /// Writes the position file for the position the database has: at once if `changed`, else when it is a second
    /// old. A failure is said once, and again when the file can be written again.
    fn write_state(&mut self, changed: bool) {
        let Some(position) = self.follower.position() else {
            return;
        };
        if !changed && self.written.is_some_and(|at| at.elapsed() < HEARTBEAT) {
            return;
        }
        match files::write_state(&self.settings.dir, &position, SystemTime::now()) {
            Ok(()) => {
                self.written = Some(Instant::now());
                if self.state_failed {
                    self.state_failed = false;
                    self.log
                        .line("records-ship: the position file is written again");
                }
            }
            Err(_) => {
                if !self.state_failed {
                    self.state_failed = true;
                    self.log
                        .line("records-ship: the position file cannot be written");
                }
            }
        }
    }

    fn say(&self, note: Note) {
        self.log.line(&match note {
            Note::Lost(lines) => format!(
                "records-ship: a record file was removed before it was shipped, {lines} lines lost"
            ),
            Note::Cut(lines) => {
                format!("records-ship: {lines} lines were over the longest record and were cut")
            }
            Note::Rewound => "records-ship: the saved position does not fit its record file, \
                              shipping the file from its start"
                .to_owned(),
            Note::Gone => "records-ship: the record file of the saved position is gone, shipping \
                           from the oldest record file; lines may be lost"
                .to_owned(),
            Note::Unseen => "records-ship: the newest record file that was held is gone, shipping \
                             the record files that are left; lines may be lost, and lost_lines \
                             does not count them"
                .to_owned(),
            Note::Unsettled => "records-ship: the record files kept changing while they were \
                                listed, trying again at the next turn"
                .to_owned(),
        });
    }
}

#[cfg(test)]
mod tests;
