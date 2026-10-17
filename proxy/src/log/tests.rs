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
