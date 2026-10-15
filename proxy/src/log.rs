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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<u8>>>);

    impl Sink {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn queued(items: &Receiver<Item>) -> String {
        match items.try_recv() {
            Ok(Item::Line(text)) => text,
            _ => panic!("no line queued"),
        }
    }

    #[test]
    fn lines_over_the_limit_are_cut_at_a_char_boundary() {
        let (log, items) = open(8);
        let exact = "a".repeat(LOG_LINE);
        log.line(&exact);
        assert_eq!(queued(&items), exact);
        log.line(&format!("{exact}b"));
        assert_eq!(queued(&items), exact);
        // A two-byte character that starts at byte LOG_LINE - 1 does not fit and is cut whole.
        let straddling = format!("{}é", "a".repeat(LOG_LINE - 1));
        log.line(&straddling);
        assert_eq!(queued(&items), "a".repeat(LOG_LINE - 1));
        // Three-byte characters: 170 of them are 510 bytes, the next one would end at 513.
        log.line(&"あ".repeat(171));
        assert_eq!(queued(&items), "あ".repeat(170));
        log.line("");
        assert_eq!(queued(&items), "");
        assert_eq!(log.dropped(), 0);
    }

    #[test]
    fn control_characters_never_split_a_line() {
        let (log, items) = open(2);
        log.line("a\nb\r\x1b[0mc\u{85}d");
        assert_eq!(queued(&items), "a b  [0mc d");
    }

    #[test]
    fn a_full_or_closed_queue_drops_and_counts_without_waiting() {
        let (log, items) = open(2);
        let start = Instant::now();
        for n in 0..5 {
            log.line(&format!("line {n}"));
        }
        assert!(start.elapsed() < Duration::from_secs(2));
        assert_eq!(log.dropped(), 3);
        assert_eq!(queued(&items), "line 0");
        log.line("fits again");
        assert_eq!(log.dropped(), 3);
        drop(items);
        log.line("nobody reads");
        assert_eq!(log.dropped(), 4);
    }

    #[test]
    fn the_logger_writes_the_dropped_count_when_it_can_write_again() {
        let (log, items) = open(2);
        for n in 0..5 {
            log.line(&format!("line {n}"));
        }
        let dropped = log.dropped.clone();
        drop(log);
        let mut sink = Sink::default();
        run(&items, &dropped, &mut sink);
        assert_eq!(sink.text(), "line 0\nlog lines dropped: 3\nline 1\n");
    }

    #[test]
    fn flush_answers_after_the_earlier_lines_are_written() {
        let (log, items) = open(LOG_QUEUE);
        let dropped = log.dropped.clone();
        let sink = Sink::default();
        let mut out = sink.clone();
        thread::spawn(move || run(&items, &dropped, &mut out));
        log.line("first");
        log.line("second");
        assert!(log.flush(Duration::from_secs(10)));
        assert_eq!(sink.text(), "first\nsecond\n");
    }

    #[test]
    fn flush_on_a_stopped_or_stalled_logger_returns_false_within_its_wait() {
        let wait = Duration::from_millis(200);
        let (log, items) = open(4);
        // Nobody reads: the marker is queued and never answered.
        let start = Instant::now();
        assert!(!log.flush(wait));
        let spent = start.elapsed();
        assert!(spent >= wait && spent < wait + Duration::from_secs(2));
        // A full queue has no room for the marker.
        for _ in 0..4 {
            log.line("x");
        }
        let start = Instant::now();
        assert!(!log.flush(wait));
        assert!(start.elapsed() < wait);
        // A stopped logger: the queue is closed.
        drop(items);
        let start = Instant::now();
        assert!(!log.flush(wait));
        assert!(start.elapsed() < wait);
        // A wait that overflows the clock does not block.
        let (log, _items) = open(4);
        let start = Instant::now();
        assert!(!log.flush(Duration::MAX));
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}
