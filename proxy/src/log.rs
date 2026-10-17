//! The bounded record queue and the logger thread, the only writer of stderr.
//!
//! A caller never waits: a line goes into a queue of `LOG_QUEUE` entries with `try_send`, and a line that does
//! not fit is dropped and counted. Only the logger thread writes to stderr, so a stderr that stops taking data
//! stops the logger and nothing else. After lines were dropped the logger writes one line with their number as
//! soon as it can write again.

use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::thread;
use std::time::{Duration, Instant};

/// Longest record line in bytes; a longer line is cut.
pub const LOG_LINE: usize = 512;
/// Lines the queue holds; a line sent to a full queue is dropped and counted.
pub const LOG_QUEUE: usize = 1024;

/// What the logger takes from the queue.
enum Item {
    Line(String),
    /// A marker: the logger answers on the channel once every line queued before it is written.
    Flush(SyncSender<()>),
}

/// A handle to the record queue. Sending never waits.
#[derive(Clone)]
pub struct Log {
    queue: SyncSender<Item>,
    dropped: Arc<AtomicU64>,
}

impl Log {
    /// Queues one line, cut to `LOG_LINE` bytes at a character boundary, without waiting. A full or closed queue
    /// drops the line and counts it. Control characters, line breaks included, become spaces, so one call is
    /// always one line.
    pub fn line(&self, text: &str) {
        let mut end = text.len().min(LOG_LINE);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        let line = text[..end]
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        match self.queue.try_send(Item::Line(line)) {
            Ok(()) => {}
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Lines dropped so far.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
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
        dropped: Arc::new(AtomicU64::new(0)),
    };
    (log, items)
}

/// Writes one line with its line feed in a single write.
fn write_line<W: Write>(out: &mut W, text: &str) {
    let _ = out.write_all(format!("{text}\n").as_bytes());
}

/// The logger loop: writes every line in order, and after each item reports the lines dropped since the last
/// report. It returns when every handle is gone. A failed write loses that line and nothing more.
fn run<W: Write>(items: &Receiver<Item>, dropped: &AtomicU64, out: &mut W) {
    let mut reported = 0;
    while let Ok(item) = items.recv() {
        let mut ack = None;
        match item {
            Item::Line(text) => write_line(out, &text),
            Item::Flush(answer) => ack = Some(answer),
        }
        let total = dropped.load(Ordering::Relaxed);
        if total > reported {
            write_line(out, &format!("log lines dropped: {}", total - reported));
            reported = total;
        }
        if let Some(answer) = ack {
            let _ = out.flush();
            let _ = answer.try_send(());
        }
    }
}

/// Starts the logger thread.
pub fn start_logger() -> Result<Log, &'static str> {
    let (log, items) = open(LOG_QUEUE);
    let dropped = log.dropped.clone();
    thread::Builder::new()
        .name("logger".into())
        .spawn(move || run(&items, &dropped, &mut io::stderr()))
        .map_err(|_| "cannot start the logger thread")?;
    Ok(log)
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
