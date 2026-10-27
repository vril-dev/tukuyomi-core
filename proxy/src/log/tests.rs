use super::*;
use std::sync::Mutex;

use tukuyomi_kernel::Matched;

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

/// A writer that takes nothing, as a stderr that a closed pipe leaves.
struct Failing;

impl Write for Failing {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::BrokenPipe))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn queued(items: &Receiver<Item>) -> String {
    match items.try_recv() {
        Ok(Item::Line { text, .. }) => text,
        _ => panic!("no line queued"),
    }
}

/// A request record that is as short as a record can be.
fn request(upstream: Option<&str>) -> Record {
    Record::Request(Box::new(record::Request {
        id: "0123456789abcdef-1".to_string(),
        conn: 1,
        listener: 0,
        proto: "h1",
        tls: false,
        client: "203.0.113.9".parse().unwrap(),
        seen: None,
        class: "closed",
        status: 0,
        reason: "no answer",
        ms: 0,
        upstream: upstream.map(Arc::from),
        server: None,
        mode: None,
        generation: None,
        rule: None,
        matched: Matched::NONE,
        body: None,
        inspected: None,
        sent: 0,
    }))
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
    log.record(request(None));
    assert!(start.elapsed() < Duration::from_secs(2));
    assert_eq!(log.dropped(), 4);
    assert_eq!(queued(&items), "line 0");
    drop(items);
    log.line("nobody reads");
    assert_eq!(log.dropped(), 5);
    assert_eq!(log.write_errors(), 0);
}

#[test]
fn the_text_form_writes_lines_as_they_are_and_the_dropped_count_as_a_line() {
    let (log, items) = open(2);
    for n in 0..5 {
        log.line(&format!("line {n}"));
    }
    let counts = log.counts.clone();
    drop(log);
    let mut sink = Sink::default();
    run(&items, &counts, Format::Text, &mut sink);
    assert_eq!(sink.text(), "line 0\nlog lines dropped: 3\nline 1\n");
}

#[test]
fn the_json_form_writes_one_record_per_item_and_a_dropped_record() {
    let (log, items) = open(3);
    log.line("start: \"listening\"");
    log.record(request(None));
    log.line("two");
    log.line("lost");
    log.line("lost");
    let counts = log.counts.clone();
    drop(log);
    let mut sink = Sink::default();
    run(&items, &counts, Format::Json, &mut sink);
    let text = sink.text();
    let lines: Vec<&str> = text.lines().collect();
    // The report comes after the first item that was written, as the text form shows.
    assert_eq!(lines.len(), 4, "{text}");
    // The first two fields are the time and the type; a value that is not there is not written.
    assert!(lines[0].starts_with("{\"ts\":\""), "{}", lines[0]);
    assert!(
        lines[0].ends_with("\",\"type\":\"line\",\"line\":\"start: \\\"listening\\\"\"}"),
        "{}",
        lines[0]
    );
    let dropped: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(dropped["type"], "dropped");
    assert_eq!(dropped["count"], 2);
    assert!(
        lines[2].contains(
            "\"type\":\"request\",\"id\":\"0123456789abcdef-1\",\"conn\":1,\"listener\":0,"
        ),
        "{}",
        lines[2]
    );
    assert!(
        !lines[2].contains("null") && !lines[2].contains("upstream"),
        "{}",
        lines[2]
    );
    assert!(lines[3].ends_with("\"line\":\"two\"}"), "{}", lines[3]);
    assert_eq!(counts.dropped.load(Ordering::Relaxed), 2);
    assert_eq!(counts.write_errors.load(Ordering::Relaxed), 0);
}

#[test]
fn a_failing_writer_counts_write_errors_and_not_dropped() {
    let (log, items) = open(8);
    log.line("one");
    log.record(request(None));
    let counts = log.counts.clone();
    drop(log);
    run(&items, &counts, Format::Json, &mut Failing);
    assert_eq!(counts.write_errors.load(Ordering::Relaxed), 2);
    assert_eq!(counts.dropped.load(Ordering::Relaxed), 0);
}

#[test]
fn a_record_over_the_limit_is_dropped_and_counted() {
    let base = record::encode(SystemTime::UNIX_EPOCH, &request(Some("")))
        .unwrap()
        .len();
    // The longest line written is one byte less than the limit, for its line feed counts.
    for (extra, written) in [
        (record::RECORD_MAX - 1 - base, true),
        (record::RECORD_MAX - base, false),
    ] {
        let (log, items) = open(8);
        log.record(request(Some(&"g".repeat(extra))));
        let counts = log.counts.clone();
        drop(log);
        let mut sink = Sink::default();
        run(&items, &counts, Format::Json, &mut sink);
        let text = sink.text();
        if written {
            assert_eq!(text.len(), record::RECORD_MAX);
            assert_eq!(counts.dropped.load(Ordering::Relaxed), 0);
        } else {
            assert!(text.contains("\"type\":\"dropped\",\"count\":1"), "{text}");
            assert!(!text.contains("\"type\":\"request\""));
            assert_eq!(counts.dropped.load(Ordering::Relaxed), 1);
        }
    }
}

#[test]
fn flush_answers_after_the_earlier_lines_are_written() {
    let (log, items) = open(LOG_QUEUE);
    let counts = log.counts.clone();
    let sink = Sink::default();
    let mut out = sink.clone();
    thread::spawn(move || run(&items, &counts, Format::Text, &mut out));
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
