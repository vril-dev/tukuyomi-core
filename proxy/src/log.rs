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

use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use self::record::Record;

pub mod record;
mod time;

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
    /// A marker: the logger answers on the channel once every item queued before it is written.
    Flush(SyncSender<()>),
}

/// The items that could not be written, counted by the callers and by the logger.
#[derive(Default)]
struct Counts {
    /// Items that did not fit into the queue, found no logger, or were too long once encoded.
    dropped: AtomicU64,
    /// Lines that the logger could not write.
    write_errors: AtomicU64,
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

    fn send(&self, item: Item) {
        match self.queue.try_send(item) {
            Ok(()) => {}
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.counts.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Items dropped so far.
    pub fn dropped(&self) -> u64 {
        self.counts.dropped.load(Ordering::Relaxed)
    }

    /// Lines that could not be written so far.
    pub fn write_errors(&self) -> u64 {
        self.counts.write_errors.load(Ordering::Relaxed)
    }

    /// Asks the logger to write what it has; true if it answered within `wait`. A marker that does not fit into
    /// the queue, a queue without a logger and a `wait` that overflows the clock all give false at once.
    pub fn flush(&self, wait: Duration) -> bool {
        let Some(deadline) = Instant::now().checked_add(wait) else {
            return false;
        };
        let (ack, answer) = sync_channel(1);
        if self.queue.try_send(Item::Flush(ack)).is_err() {
            return false;
        }
        answer
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .is_ok()
    }
}

/// A queue of `capacity` items and the handle that fills it.
fn open(capacity: usize) -> (Log, Receiver<Item>) {
    let (queue, items) = sync_channel(capacity);
    let log = Log {
        queue,
        counts: Arc::new(Counts::default()),
    };
    (log, items)
}

/// Writes one line with its line feed in a single write.
fn write_line<W: Write>(out: &mut W, counts: &Counts, text: &str) {
    if out.write_all(format!("{text}\n").as_bytes()).is_err() {
        counts.write_errors.fetch_add(1, Ordering::Relaxed);
    }
}

/// Writes an encoded line; one that did not fit the limit is dropped and counted.
fn write_encoded<W: Write>(out: &mut W, counts: &Counts, line: Option<String>) {
    match line {
        Some(line) => write_line(out, counts, &line),
        None => {
            counts.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// The logger loop: writes every item in order, and after each item reports the items dropped since the last
/// report. It returns when every handle is gone. A failed write loses that line and nothing more.
fn run<W: Write>(items: &Receiver<Item>, counts: &Counts, format: Format, out: &mut W) {
    let mut reported = 0;
    while let Ok(item) = items.recv() {
        let mut ack = None;
        match item {
            Item::Line { at, text } => match format {
                Format::Text => write_line(out, counts, &text),
                Format::Json => write_encoded(out, counts, record::encode_line(at, &text)),
            },
            Item::Record { at, record } => {
                write_encoded(out, counts, record::encode(at, &record));
            }
            Item::Flush(answer) => ack = Some(answer),
        }
        let total = counts.dropped.load(Ordering::Relaxed);
        if total > reported {
            let count = total - reported;
            match format {
                Format::Text => write_line(out, counts, &format!("log lines dropped: {count}")),
                Format::Json => write_encoded(
                    out,
                    counts,
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

/// Starts the logger thread.
pub fn start_logger(format: Format) -> Result<Log, &'static str> {
    let (log, items) = open(LOG_QUEUE);
    let counts = log.counts.clone();
    thread::Builder::new()
        .name("logger".into())
        .spawn(move || run(&items, &counts, format, &mut io::stderr()))
        .map_err(|_| "cannot start the logger thread")?;
    Ok(log)
}

/// A handle whose items wait in the queue until a test reads them, and the way to read them.
#[cfg(test)]
pub fn recording() -> (Log, Lines) {
    let (log, items) = open(LOG_QUEUE);
    (log, Lines(Arc::new(std::sync::Mutex::new(items))))
}

/// The queue of a handle that `recording` made.
#[cfg(test)]
#[derive(Clone)]
pub struct Lines(Arc<std::sync::Mutex<Receiver<Item>>>);

#[cfg(test)]
impl Lines {
    /// The items queued since the last call, as the logger writes them in JSON, parsed. A record that the logger
    /// would drop for its length fails the test.
    pub fn take(&self) -> Vec<serde_json::Value> {
        let items = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        items
            .try_iter()
            .filter_map(|item| {
                let line = match item {
                    Item::Line { at, text } => record::encode_line(at, &text),
                    Item::Record { at, record } => record::encode(at, &record),
                    Item::Flush(_) => return None,
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
