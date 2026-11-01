//! The bounded record queue and the logger thread, the only writer of stderr.
//!
//! A caller never waits: an item goes into a queue of `LOG_QUEUE` entries with `try_send`, and an item that does
//! not fit is dropped and counted. Only the logger thread writes to stderr, so a stderr that stops taking data
//! stops the logger and nothing else. After items were dropped the logger writes one report with their number as
//! soon as it can write again.
//!
//! The logger writes one of two forms, which it is given when it starts. The proxy writes JSON: every item is one
//! line of JSON (see `record`), a text of the process (`Log::line`) as a record of the type `line`, and a typed
//! record (`Log::record`) as the line of its type. The short commands (`rules`, `acme`, `config`) write their texts
//! as they are, for a person to read, and the report of the dropped items as one text. The time of an item is the
//! time it was queued, except for the report, which has the time it was written. The encoding is done on the
//! logger thread. An encoded record of more than `record::RECORD_MAX` bytes with its line feed is dropped and
//! counted like a full queue. A write that fails loses its line and is counted apart (`Log::write_errors`).
//!
//! In the JSON form the logger can be given a record file (`sink`, `Log::attach`), and then writes every line to it as
//! well, after the standard error. A line that the file does not take is lost for the file only and is counted apart
//! (`Log::file_errors`). What was queued before the file was handed over is not written to it. The text form never
//! has a record file.
//!
//! Every item in the queue takes one of its `LOG_QUEUE` places, and one that finds none is dropped. A request whose
//! record must not be dropped for a full queue takes its place before it is let in (`Log::seat`), holds it as a
//! `Seat` while the request is served, and queues its record with it (`Log::record_in`), which cannot fail for lack
//! of room. The logger gives a place back when it takes the item out of the queue, and a seat that is dropped gives
//! its place back. Seats take at most half of the places, so that the records of the other routes and the lines of
//! the process still find room while many requests that need their record kept are in flight.
//!
//! The logger keeps one fact for the requests that need their record kept: whether the last write to the record
//! file went through (`Log::healthy`). A write that fails makes it false and the next write that goes through makes
//! it true again; the file is opened again a second after a failure, by the first line that comes after that. It is
//! false for good once the logger is gone: its thread has ended, or the queue finds no receiver. With a shipper the
//! logger's handle also knows how far behind the shipper is (`ship`). `Log::admit` lets a request in, with a seat,
//! or says which of the three stops it; `Log::admitting` tells whether it would.
//!
//! If the record file has a sync interval the logger makes the lines written to it reach the disk when the oldest
//! of them has waited that long, also when no line comes after them, and when it is asked to flush. A sync that fails
//! is counted with the lines the file did not take and makes the logger unhealthy like a write that fails.

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use self::record::Record;
use self::sink::RecordFile;
use crate::config::Records;

pub mod counters;
pub mod record;
pub mod ship;
pub mod sink;
pub(crate) mod time;

/// Longest text of a line item in bytes; a longer text is cut.
pub const LOG_LINE: usize = 512;
/// Items the queue holds; an item sent to a full queue is dropped and counted.
pub const LOG_QUEUE: usize = 1024;

/// How the logger writes what it is given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// The text of a line as it is, for a person.
    Text,
    /// One line of JSON for every item.
    Json,
}

/// What the logger takes from the queue.
enum Item {
    Line {
        at: SystemTime,
        text: String,
    },
    Record {
        at: SystemTime,
        record: Record,
    },
    /// The record file, which the logger writes to as well from then on.
    File(Box<RecordFile>),
    /// A marker: the logger answers on the channel once every item queued before it is written.
    Flush(SyncSender<()>),
}

/// The places of the queue, the items that could not be written (counted by the callers and by the logger) and what
/// the logger knows of the record file.
struct Counts {
    /// The places the queue has.
    places: usize,
    /// The places that are taken: by the items in the queue and by the seats that wait for their records.
    taken: AtomicUsize,
    /// The seats that wait for their records; at most `seat_places`.
    seats: AtomicUsize,
    /// The most seats there are: half of the places.
    seat_places: usize,
    /// Items that did not fit into the queue, found no logger, or were too long once encoded.
    dropped: AtomicU64,
    /// Lines that the logger could not write.
    write_errors: AtomicU64,
    /// Lines that the logger could not write to the record file, and syncs of it that failed.
    file_errors: AtomicU64,
    /// The last write to the record file, or the last sync of it, failed, or the logger is gone.
    failing: AtomicBool,
    /// How far behind the shipper is: there if the configuration has a shipper (`Log::watch_ship`).
    lag: OnceLock<ship::Lag>,
}

impl Counts {
    fn new(places: usize) -> Counts {
        Counts {
            places,
            taken: AtomicUsize::new(0),
            seats: AtomicUsize::new(0),
            seat_places: places / 2,
            dropped: AtomicU64::new(0),
            write_errors: AtomicU64::new(0),
            file_errors: AtomicU64::new(0),
            failing: AtomicBool::new(false),
            lag: OnceLock::new(),
        }
    }

    /// Takes one place of the queue if one is free.
    fn take_place(&self) -> bool {
        self.taken
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |taken| {
                (taken < self.places).then_some(taken + 1)
            })
            .is_ok()
    }

    /// Gives one place back.
    fn give_place(&self) {
        let _ = self
            .taken
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |taken| {
                Some(taken.saturating_sub(1))
            });
    }

    /// Takes a seat, and the place that goes with it, if both are free.
    fn take_seat(&self) -> bool {
        let seat = self
            .seats
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |seats| {
                (seats < self.seat_places).then_some(seats + 1)
            });
        if seat.is_err() {
            return false;
        }
        if self.take_place() {
            return true;
        }
        self.give_seat();
        false
    }

    /// Gives one seat back; its place stays taken.
    fn give_seat(&self) {
        let _ = self
            .seats
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |seats| {
                Some(seats.saturating_sub(1))
            });
    }

    /// Whether a seat is free now, with a place for it.
    fn seat_free(&self) -> bool {
        self.seats.load(Ordering::Acquire) < self.seat_places
            && self.taken.load(Ordering::Acquire) < self.places
    }

    /// Notes that the queue did not take an item: its place goes back, and a queue without a receiver means that
    /// the logger is gone, which makes the logger unhealthy for good.
    fn not_taken(&self, why: &TrySendError<Item>) {
        self.give_place();
        if matches!(why, TrySendError::Disconnected(_)) {
            self.failing.store(true, Ordering::Release);
        }
    }
}

/// A place of the queue that is kept for one record, so that the record is not dropped for a full queue. The place
/// and the seat go back when the seat is dropped. When the record is queued with it (`Log::record_in`) the place
/// passes to the item and only the seat goes back.
pub struct Seat(Option<Arc<Counts>>);

impl Drop for Seat {
    fn drop(&mut self) {
        if let Some(counts) = self.0.take() {
            counts.give_seat();
            counts.give_place();
        }
    }
}

/// Why a request that needs its record kept is not let in (`Log::admit`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unkept {
    /// The last write to the record file failed, or the logger is gone.
    Failing,
    /// The shipper is so far behind that records would be deleted before it ships them, or how far it is is not
    /// known.
    Behind,
    /// All the seats are taken, or the queue has no place for one.
    Full,
}

/// A handle to the record queue. Sending never waits.
#[derive(Clone)]
pub struct Log {
    queue: SyncSender<Item>,
    counts: Arc<Counts>,
}

impl Log {
    /// Queues one text, cut to `LOG_LINE` bytes at a character boundary, without waiting. A full or closed queue
    /// drops it and counts it. Control characters, line breaks included, become spaces, so one call is always one
    /// line.
    pub fn line(&self, text: &str) {
        let mut end = text.len().min(LOG_LINE);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        let text = text[..end]
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        self.send(Item::Line {
            at: SystemTime::now(),
            text,
        });
    }

    /// Queues one typed record, which the logger encodes, without waiting. A full or closed queue drops it and
    /// counts it.
    pub fn record(&self, record: Record) {
        self.send(Item::Record {
            at: SystemTime::now(),
            record,
        });
    }

    /// Queues one typed record with the seat that was taken for it. It is not dropped for a full queue; it is when
    /// there is no logger, and then it is counted.
    pub fn record_in(&self, mut seat: Seat, record: Record) {
        // The seat is spent, and its place passes to the item: the logger gives it back when it takes the item out
        // of the queue.
        if let Some(counts) = seat.0.take() {
            counts.give_seat();
        }
        self.put(Item::Record {
            at: SystemTime::now(),
            record,
        });
    }

    /// Takes a place of the queue for a record that is to come, without waiting. None: all the seats are taken, or
    /// the queue is full.
    pub fn seat(&self) -> Option<Seat> {
        self.counts
            .take_seat()
            .then(|| Seat(Some(self.counts.clone())))
    }

    /// Queues the item if a place is free, else drops it and counts it.
    fn send(&self, item: Item) {
        if self.counts.take_place() {
            self.put(item);
        } else {
            self.counts.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Puts an item whose place is taken into the queue. An item that the queue does not take gives its place back
    /// and is counted.
    fn put(&self, item: Item) {
        if let Err(why) = self.queue.try_send(item) {
            self.counts.not_taken(&why);
            self.counts.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Puts an item into the queue if a place is free. False: it is not in the queue, and nothing is counted.
    fn try_put(&self, item: Item) -> bool {
        if !self.counts.take_place() {
            return false;
        }
        if let Err(why) = self.queue.try_send(item) {
            self.counts.not_taken(&why);
            return false;
        }
        true
    }

    /// Items dropped so far.
    pub fn dropped(&self) -> u64 {
        self.counts.dropped.load(Ordering::Relaxed)
    }

    /// Lines that could not be written so far.
    pub fn write_errors(&self) -> u64 {
        self.counts.write_errors.load(Ordering::Relaxed)
    }

    /// Lines that could not be written to the record file so far, and syncs of it that failed.
    pub fn file_errors(&self) -> u64 {
        self.counts.file_errors.load(Ordering::Relaxed)
    }

    /// Whether the last write to the record file went through and the logger is there. True before anything was
    /// written to it and while there is no record file.
    pub fn healthy(&self) -> bool {
        !self.counts.failing.load(Ordering::Acquire)
    }

    /// Whether the shipper, if there is one, is so far behind that records would be deleted before it ships them,
    /// or how far it is is not known.
    fn behind(&self) -> bool {
        self.counts.lag.get().is_some_and(ship::Lag::behind)
    }

    /// Lets in a request that needs its record kept: the record file takes records, the shipper, if there is one,
    /// is not so far behind that records would be deleted before it ships them, and a seat is free. The seat, or
    /// what stops the request, in that order.
    pub fn admit(&self) -> Result<Seat, Unkept> {
        if !self.healthy() {
            return Err(Unkept::Failing);
        }
        if self.behind() {
            return Err(Unkept::Behind);
        }
        self.seat().ok_or(Unkept::Full)
    }

    /// Whether `admit` would let in a request now.
    pub fn admitting(&self) -> bool {
        self.healthy() && !self.behind() && self.counts.seat_free()
    }

    /// How much of the record files the shipper has not shipped; none: the configuration has no shipper.
    pub fn unshipped(&self) -> Option<ship::Unshipped> {
        self.counts.lag.get().map(ship::Lag::unshipped)
    }

    /// Starts to look once a second at where the shipper of the configuration has got to (see `ship`). The first look
    /// is made before this returns.
    pub fn watch_ship(&self, config: &Records) -> Result<(), &'static str> {
        ship::watch(&self.counts, config)
    }

    /// Hands the record file to the logger, which writes every line it writes to the standard error to it from then
    /// on (the items queued before are not). False: the queue did not take the file, and it is closed.
    pub fn attach(&self, file: RecordFile) -> bool {
        self.try_put(Item::File(Box::new(file)))
    }

    /// Asks the logger to write what it has; true if it answered within `wait`. A marker that does not fit into
    /// the queue, a queue without a logger and a `wait` that overflows the clock all give false at once.
    pub fn flush(&self, wait: Duration) -> bool {
        let Some(deadline) = Instant::now().checked_add(wait) else {
            return false;
        };
        let (ack, answer) = sync_channel(1);
        if !self.try_put(Item::Flush(ack)) {
            return false;
        }
        answer
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .is_ok()
    }
}

/// A queue of `places` items and the handle that fills it.
fn open(places: usize) -> (Log, Receiver<Item>) {
    let (queue, items) = sync_channel(places);
    let log = Log {
        queue,
        counts: Arc::new(Counts::new(places)),
    };
    (log, items)
}

/// Writes one line with its line feed in a single write, to `out` and then to the record file if there is one. A
/// write that fails loses the line there and is counted apart.
fn write_line<W: Write>(out: &mut W, counts: &Counts, file: &mut Option<RecordFile>, text: &str) {
    let line = format!("{text}\n");
    if out.write_all(line.as_bytes()).is_err() {
        counts.write_errors.fetch_add(1, Ordering::Relaxed);
    }
    if let Some(file) = file {
        let kept = file.append(line.as_bytes());
        counts.failing.store(!kept, Ordering::Release);
        if kept {
            if let Some(lag) = counts.lag.get() {
                lag.wrote(line.len());
            }
        } else {
            counts.file_errors.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Makes the lines of the record file that are not on the disk yet reach it. A sync that fails is counted with the
/// lines that the file did not take, and makes the logger unhealthy.
fn sync_file(counts: &Counts, file: &mut Option<RecordFile>) {
    if let Some(file) = file
        && !file.sync_pending(Instant::now())
    {
        counts.file_errors.fetch_add(1, Ordering::Relaxed);
        counts.failing.store(true, Ordering::Release);
    }
}

/// The next item of the queue; none when every handle is gone. While the record file has lines that wait to be
/// synced, this waits no longer than they may, and syncs when the time comes.
fn next(items: &Receiver<Item>, counts: &Counts, file: &mut Option<RecordFile>) -> Option<Item> {
    loop {
        let Some(due) = file.as_ref().and_then(RecordFile::sync_due) else {
            return items.recv().ok();
        };
        let now = Instant::now();
        if due <= now {
            sync_file(counts, file);
            continue;
        }
        match items.recv_timeout(due - now) {
            Ok(item) => return Some(item),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                sync_file(counts, file);
                return None;
            }
        }
    }
}

/// Writes an encoded line; one that did not fit the limit is dropped and counted.
fn write_encoded<W: Write>(
    out: &mut W,
    counts: &Counts,
    file: &mut Option<RecordFile>,
    line: Option<String>,
) {
    match line {
        Some(line) => write_line(out, counts, file, &line),
        None => {
            counts.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// The logger loop: writes every item in order, and after each item reports the items dropped since the last
/// report. It returns when every handle is gone. A failed write loses that line and nothing more.
fn run<W: Write>(items: &Receiver<Item>, counts: &Counts, format: Format, out: &mut W) {
    let mut reported = 0;
    let mut file = None;
    while let Some(item) = next(items, counts, &mut file) {
        counts.give_place();
        let mut ack = None;
        match item {
            Item::Line { at, text } => match format {
                Format::Text => write_line(out, counts, &mut file, &text),
                Format::Json => {
                    write_encoded(out, counts, &mut file, record::encode_line(at, &text));
                }
            },
            Item::Record { at, record } => {
                write_encoded(out, counts, &mut file, record::encode(at, &record));
            }
            Item::File(opened) => {
                if format == Format::Json {
                    file = Some(*opened);
                }
            }
            Item::Flush(answer) => {
                sync_file(counts, &mut file);
                ack = Some(answer);
            }
        }
        let total = counts.dropped.load(Ordering::Relaxed);
        if total > reported {
            let count = total - reported;
            match format {
                Format::Text => {
                    write_line(
                        out,
                        counts,
                        &mut file,
                        &format!("log lines dropped: {count}"),
                    );
                }
                Format::Json => write_encoded(
                    out,
                    counts,
                    &mut file,
                    record::encode_dropped(SystemTime::now(), count),
                ),
            }
            reported = total;
        }
        if let Some(answer) = ack {
            let _ = out.flush();
            let _ = answer.try_send(());
        }
    }
}

/// Makes the logger unhealthy when its thread ends, whether `run` returns or panics: nothing is written after that.
struct Ending(Arc<Counts>);

impl Drop for Ending {
    fn drop(&mut self) {
        self.0.failing.store(true, Ordering::Release);
    }
}

/// Starts the logger thread.
pub fn start_logger(format: Format) -> Result<Log, &'static str> {
    let (log, items) = open(LOG_QUEUE);
    let ending = Ending(log.counts.clone());
    thread::Builder::new()
        .name("logger".into())
        .spawn(move || {
            let ending = ending;
            run(&items, &ending.0, format, &mut io::stderr());
        })
        .map_err(|_| "cannot start the logger thread")?;
    Ok(log)
}

/// A handle whose items wait in the queue until a test reads them, and the way to read them.
#[cfg(test)]
pub fn recording() -> (Log, Lines) {
    let (log, items) = open(LOG_QUEUE);
    let counts = log.counts.clone();
    let items = Arc::new(std::sync::Mutex::new(items));
    (log, Lines { items, counts })
}

/// The queue of a handle that `recording` made.
#[cfg(test)]
#[derive(Clone)]
pub struct Lines {
    items: Arc<std::sync::Mutex<Receiver<Item>>>,
    counts: Arc<Counts>,
}

#[cfg(test)]
impl Lines {
    /// The items queued since the last call, as the logger writes them in JSON, parsed. A record that the logger
    /// would drop for its length fails the test.
    pub fn take(&self) -> Vec<serde_json::Value> {
        let items = self
            .items
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        items
            .try_iter()
            .filter_map(|item| {
                self.counts.give_place();
                let line = match item {
                    Item::Line { at, text } => record::encode_line(at, &text),
                    Item::Record { at, record } => record::encode(at, &record),
                    Item::File(_) | Item::Flush(_) => return None,
                };
                let line = line.expect("a record within the limit");
                Some(serde_json::from_str(&line).expect("a record is a line of JSON"))
            })
            .collect()
    }

    /// The texts of the line items queued since the last call.
    pub fn texts(&self) -> Vec<String> {
        self.take()
            .iter()
            .filter(|record| record["type"] == "line")
            .map(|record| record["line"].as_str().unwrap_or_default().to_string())
            .collect()
    }
}

/// Whether `record` is a request record of this class, status and reason.
#[cfg(test)]
pub fn is_answer(record: &serde_json::Value, class: &str, status: u16, reason: &str) -> bool {
    record["type"] == "request"
        && record["class"] == class
        && record["status"] == status
        && record["reason"] == reason
}

/// Sends panic messages to the record queue instead of writing them to stderr.
pub fn install_panic_hook(log: Log) {
    std::panic::set_hook(Box::new(move |info| log.line(&format!("panic: {info}"))));
}

/// Every byte outside 0x20 to 0x7e as `\xNN`, so that what is written cannot move the cursor, change the colours or
/// bend the text (the C1 controls and the controls of the direction of text are bytes of 0x80 and over in UTF-8).
pub fn escaped(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &byte in bytes {
        if (0x20..=0x7e).contains(&byte) {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("\\x{byte:02x}"));
        }
    }
    out
}

#[cfg(test)]
mod tests;
