//! The diagnostic lines of the process: bounded, escaped, and never a value of a request.
//!
//! A line is a fixed prefix, a text with every byte outside 0x20 to 0x7e and the backslash written as `\xNN`, and a
//! newline, and it has at most `MAX_LINE` bytes. The lines go to the standard error. A start that fails writes its
//! line also to the file `start-failure` in `TMPDIR`, for the process that started this one, but only once the
//! process has checked `TMPDIR` (`Diag::set_tmp`): a failure before that never writes to a path that was not
//! checked. After the first failed write to the standard error nothing more is written there and the lines are only
//! counted.
#![forbid(unsafe_code)]

use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::link::Ended;

/// The most bytes of one line, the newline included.
const MAX_LINE: usize = 512;

/// The file in `TMPDIR` that holds the line of a failed start, for the process that started this one.
const START_FAILURE: &str = "start-failure";

const PREFIX: &str = "tkv0-inspector: ";
const HEX: &[u8; 16] = b"0123456789abcdef";

/// One line: the prefix, the text with every byte outside 0x20 to 0x7e and the backslash written as `\xNN`, and a
/// newline. The text is cut before an escape that would not fit, so the line has at most `MAX_LINE` bytes and no half
/// of an escape.
fn line(text: fmt::Arguments<'_>) -> Vec<u8> {
    let text = text.to_string();
    let mut out = Vec::with_capacity(MAX_LINE);
    out.extend_from_slice(PREFIX.as_bytes());
    for &c in text.as_bytes() {
        let escape = !(0x20..0x7f).contains(&c) || c == b'\\';
        let width = if escape { 4 } else { 1 };
        if out.len() + width > MAX_LINE - 1 {
            // One byte stays for the newline.
            break;
        }
        if escape {
            out.extend_from_slice(&[
                b'\\',
                b'x',
                HEX[usize::from(c >> 4)],
                HEX[usize::from(c & 0x0f)],
            ]);
        } else {
            out.push(c);
        }
    }
    out.push(b'\n');
    out
}

/// The writer of the diagnostic lines.
pub struct Diag<W: Write> {
    w: W,
    broken: bool,
    dropped: u64,
    /// The `TMPDIR` that the checks accepted; `None` until then.
    tmp: Option<PathBuf>,
}

impl<W: Write> Diag<W> {
    pub fn new(w: W) -> Diag<W> {
        Diag {
            w,
            broken: false,
            dropped: 0,
            tmp: None,
        }
    }

    /// Records the `TMPDIR` that was checked: from now on a failed start also leaves its line there.
    pub fn set_tmp(&mut self, dir: PathBuf) {
        self.tmp = Some(dir);
    }

    fn print(&mut self, text: fmt::Arguments<'_>) {
        let line = line(text);
        self.write(&line);
    }

    fn write(&mut self, line: &[u8]) {
        if self.broken {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        if self.w.write_all(line).is_err() {
            self.broken = true;
            self.dropped = self.dropped.saturating_add(1);
        }
    }

    /// Reports a failure to start and returns `code`. The line goes to the standard error and, once `set_tmp` was
    /// called, the same bytes go to the file `start-failure` there. The file is for the process that started this
    /// one; when it cannot be written the start has failed anyway, so only a note is made.
    pub fn start_fail(&mut self, code: i32, text: fmt::Arguments<'_>) -> i32 {
        let line = line(text);
        self.write(&line);
        let failed = self
            .tmp
            .as_deref()
            .and_then(|dir| write_start_failure(dir, &line).err());
        if let Some(e) = failed {
            self.print(format_args!("start: {START_FAILURE}: {e}"));
        }
        code
    }

    /// The last line of a session: the exit code, what the table dealt with and why the session ended.
    pub fn finish(&mut self, ended: &Ended) {
        let c = &ended.counts;
        let dropped = self.dropped;
        self.print(format_args!(
            "exit={} started={} closed={} close_errors={} discarded={} bad_tx_end={} dup_drain={} diag_dropped={} reason={}",
            ended.code,
            c.started,
            c.closed,
            c.close_errors,
            c.discarded,
            c.bad_tx_end,
            ended.dup_drains,
            dropped,
            ended.why
        ));
    }
}

/// Creates `start-failure` in `dir`, which must be the `TMPDIR` that the checks accepted, and writes `line` to it. The
/// file must not exist and a link in its place is not followed (`O_EXCL`, `O_NOFOLLOW`), and only we can read it
/// (0600).
fn write_start_failure(dir: &Path, line: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(dir.join(START_FAILURE))?;
    file.write_all(line)
}

#[cfg(test)]
mod tests;
