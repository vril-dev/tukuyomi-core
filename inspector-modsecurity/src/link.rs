//! The socket the inspector inherits from the kernel: framed reading and writing with deadlines, and the loop of the
//! session.
//!
//! `recv` waits for the first byte of a frame as long as it takes, then the rest of the frame (header and payload)
//! must arrive within `frame_io` of that byte: an overrun is `Io(TimedOut)`, a connection-wide violation, because part
//! of a frame has moved and the frame boundary can no longer be trusted. `send` writes one whole frame before its
//! deadline. Every read and write recomputes the time left and sets the socket timeout from it, so that partial
//! transfers, `Interrupted` and a timeout that fires early cannot stretch a deadline. The stream must be in blocking
//! mode.
//!
//! `serve` runs the session on the calling thread. HELLO reports a queue depth of 17, the number of frames that the
//! protocol lets wait for one transaction, and the kernel checks it. This inspector has no queue: one thread reads a
//! frame and handles it completely, and writes the answer, before it reads the next. A frame never waits behind
//! another, the depth is never reached, and ERROR 24 (queue overflow) is never sent. What the kernel sends in the
//! meantime waits in the buffer of the socket.
#![forbid(unsafe_code)]

use std::io::{self, ErrorKind, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use crate::codec::{ConnError, Header, KIND_DRAIN, encode_bye, read_frame};
use crate::owner::{Counts, Inspection, Table};

/// The time a frame has to arrive after its first byte, and to be written.
pub const FRAME_TIMEOUT: Duration = Duration::from_secs(3);

// Exit codes: 0 after BYE, 12 when the connection was lost and every transaction was closed in time, 13 when closing
// them took longer.
pub const EXIT_OK: i32 = 0;
pub const EXIT_LOST_CLEAN: i32 = 12;
pub const EXIT_LOST_TIMEOUT: i32 = 13;

/// Time left until `deadline`; `None` when it is reached or over.
fn left(deadline: Instant) -> Option<Duration> {
    let d = deadline.saturating_duration_since(Instant::now());
    if d.is_zero() { None } else { Some(d) }
}

/// A `Read` over the stream whose every call is bounded by the absolute deadline.
struct Timed<'a> {
    stream: &'a UnixStream,
    deadline: Instant,
}

impl Read for Timed<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let Some(d) = left(self.deadline) else {
                return Err(io::Error::from(ErrorKind::TimedOut));
            };
            self.stream.set_read_timeout(Some(d))?;
            match (&*self.stream).read(buf) {
                Ok(n) => return Ok(n),
                // The socket timeout fired, or a signal came: the deadline is checked again above.
                Err(e)
                    if matches!(
                        e.kind(),
                        ErrorKind::Interrupted | ErrorKind::WouldBlock | ErrorKind::TimedOut
                    ) => {}
                Err(e) => return Err(e),
            }
        }
    }
}

/// Reads one frame, validated for `run` and `inc`. EOF before the first byte is `PeerClosed`.
pub fn recv(
    stream: &UnixStream,
    run: u64,
    inc: u32,
    frame_io: Duration,
) -> Result<(Header, Vec<u8>), ConnError> {
    stream
        .set_read_timeout(None)
        .map_err(|e| ConnError::Io(e.kind()))?;
    let mut first = [0u8; 1];
    loop {
        match (&*stream).read(&mut first) {
            Ok(0) => return Err(ConnError::PeerClosed),
            Ok(1) => break,
            Ok(_) => return Err(ConnError::Io(ErrorKind::InvalidData)),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(ConnError::Io(e.kind())),
        }
    }
    let by = Instant::now()
        .checked_add(frame_io)
        .ok_or(ConnError::Io(ErrorKind::InvalidInput))?;
    // `read_frame` reads the byte already taken first, then the rest from the stream.
    let mut r = (&first[..]).chain(Timed {
        stream,
        deadline: by,
    });
    read_frame(&mut r, run, inc)
}

/// Writes one whole frame within `timeout`.
pub fn send(stream: &UnixStream, frame: &[u8], timeout: Duration) -> Result<(), ConnError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(ConnError::Io(ErrorKind::InvalidInput))?;
    let mut off = 0;
    while off < frame.len() {
        let Some(d) = left(deadline) else {
            return Err(ConnError::Io(ErrorKind::TimedOut));
        };
        stream
            .set_write_timeout(Some(d))
            .map_err(|e| ConnError::Io(e.kind()))?;
        match (&*stream).write(&frame[off..]) {
            Ok(0) => return Err(ConnError::Io(ErrorKind::WriteZero)),
            Ok(n) if n > frame.len() - off => return Err(ConnError::Io(ErrorKind::InvalidData)),
            Ok(n) => off += n,
            // The socket timeout fired, or a signal came: the deadline is checked again above.
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::Interrupted | ErrorKind::WouldBlock | ErrorKind::TimedOut
                ) => {}
            Err(e) => return Err(ConnError::Io(e.kind())),
        }
    }
    Ok(())
}

/// How a session ended and what it dealt with, for the last line of the diagnostics.
#[derive(Debug)]
pub struct Ended {
    /// The exit code: `EXIT_OK`, `EXIT_LOST_CLEAN` or `EXIT_LOST_TIMEOUT`.
    pub code: i32,
    /// Why the session ended, in a fixed form that holds no request value.
    pub why: String,
    pub counts: Counts,
    /// DRAIN frames after the first.
    pub dup_drains: u64,
}

enum Over {
    /// BYE was written.
    Drained,
    /// The connection failed or the kernel broke the protocol on the connection.
    Lost(String),
}

/// Runs the session on `stream` until BYE is written or the connection is lost. `hello` is the encoded HELLO, sent
/// first. After a loss every open transaction is closed without CLOSED; the exit code is `EXIT_LOST_TIMEOUT` when that
/// took longer than `close_deadline`. The closing runs on this thread, so a call into the inspection that never returns
/// is not cut off here.
pub fn serve<I: Inspection>(
    stream: UnixStream,
    run: u64,
    inc: u32,
    hello: &[u8],
    mut table: Table<I>,
    close_deadline: Duration,
) -> Ended {
    let mut dup_drains = 0;
    let over = session(&stream, run, inc, hello, &mut table, &mut dup_drains);
    // The kernel sees the end of the connection at once, whichever way the session ended.
    let _ = stream.shutdown(Shutdown::Both);
    let (code, why) = match over {
        Over::Drained => (EXIT_OK, "drained".to_string()),
        Over::Lost(why) => {
            let start = Instant::now();
            table.connection_lost();
            let in_time = start.elapsed() <= close_deadline;
            (
                if in_time {
                    EXIT_LOST_CLEAN
                } else {
                    EXIT_LOST_TIMEOUT
                },
                why,
            )
        }
    };
    Ended {
        code,
        why,
        counts: table.counts(),
        dup_drains,
    }
}

fn session<I: Inspection>(
    stream: &UnixStream,
    run: u64,
    inc: u32,
    hello: &[u8],
    table: &mut Table<I>,
    dup_drains: &mut u64,
) -> Over {
    if let Err(e) = send(stream, hello, FRAME_TIMEOUT) {
        return Over::Lost(format!("hello not written: {e:?}"));
    }
    loop {
        if table.is_drained() {
            let c = table.counts();
            let bye = encode_bye(run, inc, c.started, c.closed, c.close_errors);
            return match send(stream, &bye, FRAME_TIMEOUT) {
                Ok(()) => Over::Drained,
                Err(e) => Over::Lost(format!("write: {e:?}")),
            };
        }
        let (h, p) = match recv(stream, run, inc, FRAME_TIMEOUT) {
            Ok(frame) => frame,
            Err(e) => return Over::Lost(format!("read: {e:?}")),
        };
        if h.kind == KIND_DRAIN {
            if !table.start_drain() {
                *dup_drains = dup_drains.saturating_add(1);
            }
            continue;
        }
        if let Some(answer) = table.dispatch(&h, &p)
            && let Err(e) = send(stream, &answer, FRAME_TIMEOUT)
        {
            return Over::Lost(format!("write: {e:?}"));
        }
    }
}

#[cfg(test)]
mod tests;
