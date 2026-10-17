//! Deadline-bound frame transport over a `UnixStream`.
//!
//! `send` writes one frame built by `codec::encode_frame`; `recv` reads one frame with `codec::read_frame`, so the
//! header is checked (`codec::check_header`: magic, kind, length limit, run, incarnation, ids) before any payload
//! buffer is allocated. Both take absolute `Instant` deadlines from the caller. Every `read` and `write` recomputes
//! the time left and sets the socket timeout from it, so partial transfers, `Interrupted` and a timeout that fires early
//! cannot stretch a deadline. A deadline that is already over, or has just been reached, fails before the next
//! system call (`set_*_timeout(Some(0))` would be an error, not "no timeout").
//!
//! `recv` has two kinds of expiry. Before the first byte of a frame (`idle`, or `hard` if that is earlier) nothing has
//! been consumed: it is `Io(WouldBlock)`, the normal result of a polling reader, and the stream is sound for the next
//! `recv`. Once the first byte has arrived, the rest of the frame must arrive within `frame_io` of that byte (and
//! before `hard`); an overrun is `Io(TimedOut)`, like any other timeout of a read or write (a connection-wide
//! violation). Part of a frame has moved, so the frame boundary can no longer be trusted: the caller drops the
//! connection. `send` has one deadline and reports its overrun as `Io(TimedOut)`.
//!
//! The stream must be in blocking mode. The socket timeouts are left set after a call (read and write timeouts are
//! independent). The run and incarnation that `recv` checks come from the caller, who owns the trusted local
//! connection generation; nothing on the wire is a generation.
#![forbid(unsafe_code)]

use std::io::{self, ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use crate::protocol::codec::{ConnError, HEADER_LEN, Header, MAX_BODY, read_frame};

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

/// Reads one frame, validated for `run` and `inc`. The first byte is awaited until `min(idle, hard)`: if it does not
/// come, nothing was consumed and the result is `Io(WouldBlock)`. The rest of the frame is due `frame_io` after the
/// first byte, but not after `hard` (a sum that overflows is `hard`): an overrun is `Io(TimedOut)`. Other errors are
/// those of `codec::read_frame`; EOF before the first byte is `PeerClosed`.
pub(crate) fn recv(
    stream: &UnixStream,
    run: u64,
    inc: u32,
    idle: Instant,
    frame_io: Duration,
    hard: Instant,
) -> Result<(Header, Vec<u8>), ConnError> {
    let mut first = [0u8; 1];
    let mut w = Timed {
        stream,
        deadline: idle.min(hard),
    };
    match w.read(&mut first) {
        Ok(0) => return Err(ConnError::PeerClosed),
        Ok(1) => {}
        Ok(_) => return Err(ConnError::Io(ErrorKind::InvalidData)),
        // `Timed` reports only its own deadline as TimedOut. No byte was read: the stream is still sound.
        Err(e) if e.kind() == ErrorKind::TimedOut => {
            return Err(ConnError::Io(ErrorKind::WouldBlock));
        }
        Err(e) => return Err(ConnError::Io(e.kind())),
    }
    let by = Instant::now()
        .checked_add(frame_io)
        .map_or(hard, |t| t.min(hard));
    // `read_frame` reads the byte already taken first, then the rest from the stream.
    let mut r = (&first[..]).chain(Timed {
        stream,
        deadline: by,
    });
    read_frame(&mut r, run, inc)
}

/// Writes one whole frame (as built by `codec::encode_frame`) before `deadline`. The frame must be a header and a
/// payload of at most `MAX_BODY` bytes whose length field matches; anything else is `Io(InvalidInput)` and nothing is
/// written.
pub(crate) fn send(stream: &UnixStream, frame: &[u8], deadline: Instant) -> Result<(), ConnError> {
    let declared = match frame.get(8..12) {
        Some(b) if frame.len() >= HEADER_LEN => u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        _ => return Err(ConnError::Io(ErrorKind::InvalidInput)),
    };
    if declared as usize > MAX_BODY || frame.len() - HEADER_LEN != declared as usize {
        return Err(ConnError::Io(ErrorKind::InvalidInput));
    }
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

#[cfg(test)]
mod tests;
