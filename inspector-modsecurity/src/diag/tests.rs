use super::*;
use crate::owner::Counts;
use std::fs::{self, DirBuilder};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
use std::sync::atomic::{AtomicU32, Ordering};

/// A directory under the temporary directory, removed when it goes out of scope.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Scratch {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "tkv-diag-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        DirBuilder::new().mode(0o700).create(&dir).unwrap();
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A writer that fails every time, and counts the calls.
struct Broken(u32);

impl Write for Broken {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        self.0 += 1;
        Err(io::Error::from(io::ErrorKind::BrokenPipe))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// A line is one line of at most 512 bytes with the prefix; the bytes outside 0x20 to 0x7e and the backslash are
// escaped, and a text that is too long is cut. The cut falls before an escape that does not fit, never inside it.
#[test]
fn a_line_is_bounded_and_escaped() {
    let got = line(format_args!("a\nb\x00c\\{}", "x".repeat(2000)));
    assert_eq!(got.len(), MAX_LINE);
    assert_eq!(got.iter().filter(|&&c| c == b'\n').count(), 1);
    assert!(got.starts_with(b"tkv0-inspector: a\\x0ab\\x00c\\x5cx"));
    assert!(got.ends_with(b"x\n"));

    // 16 bytes of prefix and 493 of text leave room for two bytes before the newline: an escape needs four.
    let got = line(format_args!("{}\x01\x01", "x".repeat(493)));
    assert_eq!(got.len(), 510);
    assert!(got.ends_with(b"x\n"));
    // One byte fewer leaves room for the first escape and not for the second.
    let got = line(format_args!("{}\x01\x01", "x".repeat(488)));
    assert_eq!(got.len(), 509);
    assert!(got.ends_with(b"\\x01\n"));
}

// After the first failed write the writer is not used again, and the lines are counted.
#[test]
fn a_failed_write_stops_the_writing_and_counts_the_lines() {
    let mut d = Diag::new(Broken(0));
    d.print(format_args!("one"));
    d.print(format_args!("two"));
    d.print(format_args!("three"));
    assert_eq!(d.w.0, 1);
    assert!(d.broken);
    assert_eq!(d.dropped, 3);
}

// start-failure is created once, with mode 0600, and a link in its place is not followed.
#[test]
fn start_failure_is_made_once_and_a_link_is_not_followed() {
    let scratch = Scratch::new();
    let text = line(format_args!("start: rules\n"));
    write_start_failure(&scratch.0, &text).unwrap();
    let file = scratch.0.join(START_FAILURE);
    assert_eq!(fs::read(&file).unwrap(), text);
    assert_eq!(
        fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let again = write_start_failure(&scratch.0, &text).unwrap_err();
    assert_eq!(again.kind(), io::ErrorKind::AlreadyExists);

    let other = Scratch::new();
    let victim = scratch.0.join("victim");
    symlink(&victim, other.0.join(START_FAILURE)).unwrap();
    assert!(write_start_failure(&other.0, &text).is_err());
    assert!(!victim.exists());
}

// A failed start writes the same bytes to the standard error and, once TMPDIR was accepted, to start-failure. When
// the file cannot be written, a note follows and the code is the same.
#[test]
fn a_failed_start_leaves_its_line_in_tmpdir_once_it_was_accepted() {
    let scratch = Scratch::new();
    let mut d = Diag::new(Vec::new());
    assert_eq!(d.start_fail(11, format_args!("start: before")), 11);
    assert!(!scratch.0.join(START_FAILURE).exists());

    d.set_tmp(scratch.0.clone());
    assert_eq!(d.start_fail(14, format_args!("start: after")), 14);
    let written = fs::read(scratch.0.join(START_FAILURE)).unwrap();
    assert_eq!(written, line(format_args!("start: after")));
    let shown = String::from_utf8(d.w.clone()).unwrap();
    assert!(shown.ends_with("tkv0-inspector: start: after\n"));

    d.w.clear();
    assert_eq!(d.start_fail(10, format_args!("start: again")), 10);
    let shown = String::from_utf8(d.w.clone()).unwrap();
    let mut lines = shown.lines();
    assert_eq!(lines.next(), Some("tkv0-inspector: start: again"));
    let note = lines.next().unwrap();
    assert!(
        note.starts_with("tkv0-inspector: start: start-failure: "),
        "{note}"
    );
    assert!(!note.contains(scratch.0.to_str().unwrap()));
    assert_eq!(lines.next(), None);
    // The note did not replace the file.
    assert_eq!(fs::read(scratch.0.join(START_FAILURE)).unwrap(), written);
}

// The last line of a session holds the exit code, the counts, the reason and what was not written.
#[test]
fn the_last_line_holds_the_counts_and_the_reason() {
    let mut d = Diag::new(Vec::new());
    d.finish(&Ended {
        code: 12,
        why: "read: PeerClosed".to_owned(),
        counts: Counts {
            started: 5,
            closed: 4,
            close_errors: 1,
            discarded: 2,
            bad_tx_end: 3,
        },
        dup_drains: 6,
    });
    assert_eq!(
        String::from_utf8(d.w).unwrap(),
        "tkv0-inspector: exit=12 started=5 closed=4 close_errors=1 discarded=2 bad_tx_end=3 dup_drain=6 diag_dropped=0 reason=read: PeerClosed\n"
    );
}
