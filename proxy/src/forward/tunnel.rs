//! A connection that the upstream has switched to another protocol (a WebSocket), which the proxy from then on only
//! copies.
//!
//! `origin` sends the handshake of a WebSocket and, when the upstream answers it with 101, hands over what it holds
//! of the upstream connection (`Switch`). `conn` adds the share of the byte budget, the route's times and the words
//! of the record line (`Tunnel`), and the session runs it once the 101 has been written to the client. The client
//! side of the copy is the stream of the client itself with the bytes that the gate had already read behind the
//! handshake in front, so they reach the upstream first and in order; the upstream side is the connection that hyper
//! gives back after the upgrade. The frames are not looked at: the handshake was inspected like any request, and what
//! follows it is copied. Each direction flushes its writer whenever its reader has nothing ready (see `pump`), so that
//! the end of a message does not wait for the next one in a stream that holds written bytes back, as a TLS stream
//! does.
//!
//! Each direction is copied through a buffer of 8 KiB, and the tunnel holds the share of the byte budget that these
//! two buffers take for as long as it lives. It ends when:
//! - both directions have ended, each by the end of the stream it reads (`closed`);
//! - the upstream sends nothing for `idle` (`idle`), or a write to either side makes no progress for
//!   `response_idle` (`idle` as well): the client may be silent for as long as it wants, as a subscriber is, but
//!   only while both directions are open;
//! - one direction has ended and the other has not within `idle` of it, however much it still moves (`idle`): a
//!   client that stays silent, or sends a little now and then, cannot keep the tunnel and its share of the budget
//!   after the upstream has gone, and the upstream cannot after the client has;
//! - `total` has passed since the 101 (`total`);
//! - a read or a write fails otherwise, or the upstream connection cannot be taken over (`error`);
//! - the proxy is stopped: the stop does not end a tunnel, the end of the time that the connections get to finish
//!   aborts it like any other (`stop`).
//!
//! The end is one line in the record, written when the tunnel is dropped, whatever became of it: it has the record
//! from the moment it is made, so a tunnel that is dropped before it ran (the 101 could not be given: `error`) or
//! aborted has its line like one that ran. The line has the connection, the reason as one of those words, the seconds
//! it lasted, who it was for and the bytes read from each side after the handshake. Only numbers, fixed words and
//! the words that `answer::who` makes.

use std::future::{Future, poll_fn};
use std::io;
use std::pin::{Pin, pin};
use std::task::{Poll, ready};
use std::time::Duration;

use bytes::Bytes;
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, split};
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::{Instant, Sleep, sleep, timeout, timeout_at};

use crate::config::{ProxyConfig, Stream};
use crate::forward::pool::Lease;
use crate::inbound::transport::io::{Gauge, Guarded};
use crate::log::Log;

/// The buffer of each of the two directions.
const BUFFER: usize = 8 * 1024;
/// The share of the byte budget that a tunnel holds: its two buffers.
pub const HOLD: usize = 2 * BUFFER;

/// The upstream side of a connection whose handshake was answered with 101: the way to the upgraded connection, and
/// the connection, which is kept until it has been taken over.
pub struct Switch {
    on: OnUpgrade,
    lease: Lease,
}

impl Switch {
    pub(super) fn new(on: OnUpgrade, lease: Lease) -> Switch {
        Switch { on, lease }
    }
}

/// What the line for the end of a tunnel says besides how it ended.
pub struct Record {
    pub log: Log,
    /// The number of the connection.
    pub id: u64,
    /// For whom the line is (see `answer::who`).
    pub who: String,
}

/// A tunnel that has not been run yet.
pub struct Tunnel {
    switch: Switch,
    stream: Stream,
    /// The end of the tunnel, from the 101.
    until: Instant,
    /// Writes the line for the end of the tunnel when the tunnel is dropped.
    report: Report,
    _hold: OwnedSemaphorePermit,
}

/// Why a tunnel ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reason {
    Idle,
    Total,
    Closed,
    Error,
    Stop,
}

impl Reason {
    fn word(self) -> &'static str {
        match self {
            Reason::Idle => "idle",
            Reason::Total => "total",
            Reason::Closed => "closed",
            Reason::Error => "error",
            Reason::Stop => "stop",
        }
    }
}

/// Writes the line for the end of a tunnel when it is dropped. The reason is `stop` until something sets another.
struct Report {
    record: Record,
    began: Instant,
    reason: Reason,
    /// The bytes read from the client stream, once the copy has it, and those that the gate had read before.
    client: Option<Gauge>,
    kept: u64,
    /// The bytes read from the upstream, and those that had been read when the tunnel was made.
    upstream: Gauge,
    base: u64,
}

impl Drop for Report {
    fn drop(&mut self) {
        let read = self.client.as_ref().map_or(0, Gauge::read);
        let sent = read.saturating_add(self.kept);
        let got = self.upstream.read().saturating_sub(self.base);
        self.record.log.line(&format!(
            "conn {}: tunnel {} {} s {} to-upstream {sent} from-upstream {got}",
            self.record.id,
            self.reason.word(),
            self.began.elapsed().as_secs(),
            self.record.who,
        ));
    }
}

impl Tunnel {
    /// `hold` is the share of the byte budget of `HOLD` bytes, and `record` the words of the line for the end. The
    /// time of the tunnel runs from now.
    pub fn new(
        switch: Switch,
        stream: Stream,
        hold: OwnedSemaphorePermit,
        record: Record,
    ) -> Tunnel {
        let now = Instant::now();
        let upstream = switch.lease.gauge.clone();
        Tunnel {
            report: Report {
                record,
                began: now,
                reason: Reason::Stop,
                client: None,
                kept: 0,
                base: upstream.read(),
                upstream,
            },
            switch,
            stream,
            until: now.checked_add(stream.total).unwrap_or(now),
            _hold: hold,
        }
    }

    /// The tunnel is given up before it ran: the 101 did not get to the client. Its line says `error`.
    pub fn failed(mut self) {
        self.report.reason = Reason::Error;
    }

    /// Copies between the client and the upstream until the tunnel ends. `rest` is what the client sent behind the
    /// handshake and the gate had read; `client` is the stream of the client from there on. The writing direction of
    /// the client is ended when the direction from the upstream ends (see `copy_both`).
    pub async fn run<C>(self, client: &mut C, rest: Bytes, cfg: &ProxyConfig)
    where
        C: AsyncRead + AsyncWrite + Unpin,
    {
        let Tunnel {
            switch: Switch { on, lease },
            stream,
            until,
            mut report,
            _hold,
        } = self;
        // From the 101 on, the upstream may be silent for `idle`; the client for as long as it wants, as long as
        // both directions are open (see `copy_both`).
        report.upstream.restart(stream.idle);
        report.kept = u64::try_from(rest.len()).unwrap_or(u64::MAX);
        let (mut client, seen) =
            Guarded::new(client, rest, Duration::MAX, cfg.response_idle, u64::MAX);
        report.client = Some(seen);
        report.reason = relay(
            on,
            lease,
            &mut client,
            until,
            cfg.response_idle,
            stream.idle,
        )
        .await;
    }
}

/// Takes the upstream connection over, which `wait` bounds, and copies until `until` or the end of the streams.
async fn relay<C>(
    on: OnUpgrade,
    lease: Lease,
    client: &mut Guarded<&mut C>,
    until: Instant,
    wait: Duration,
    idle: Duration,
) -> Reason
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let Ok(Ok(upgraded)) = timeout(wait, on).await else {
        return Reason::Error;
    };
    // The task that drove the connection has handed it over and ended; the lease only held it until then.
    drop(lease);
    match timeout_at(until, copy_both(client, TokioIo::new(upgraded), idle)).await {
        Err(_) => Reason::Total,
        Ok(Ok(())) => Reason::Closed,
        Ok(Err(e)) if e.kind() == io::ErrorKind::TimedOut => Reason::Idle,
        Ok(Err(_)) => Reason::Error,
    }
}

/// Copies both ways until both directions have ended, or one has failed. When one direction has ended, the other
/// gets `idle` from that end, which the bytes it still moves do not renew; if it has not ended by then the copy
/// fails with `TimedOut`. Until one has ended, only the read and write limits of the two streams bound the copy.
async fn copy_both<C, U>(client: C, upstream: U, idle: Duration) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let (from_client, to_client) = split(client);
    let (from_upstream, to_upstream) = split(upstream);
    let mut up = pin!(pump(from_client, to_upstream));
    let mut down = pin!(pump(from_upstream, to_client));
    let (mut up_ended, mut down_ended) = (false, false);
    let mut limit: Option<Pin<Box<Sleep>>> = None;
    poll_fn(|cx| -> Poll<io::Result<()>> {
        // The bound is looked at before the copies, while the task still has its budget: a direction that keeps
        // moving bytes could use the budget up, and a timer polled after that does not read the clock.
        if let Some(end) = limit.as_mut()
            && end.as_mut().poll(cx).is_ready()
        {
            return Poll::Ready(Err(late()));
        }
        if !up_ended && let Poll::Ready(done) = up.as_mut().poll(cx) {
            done?;
            up_ended = true;
        }
        if !down_ended && let Poll::Ready(done) = down.as_mut().poll(cx) {
            done?;
            down_ended = true;
        }
        if up_ended && down_ended {
            return Poll::Ready(Ok(()));
        }
        if up_ended || down_ended {
            let end = limit.get_or_insert_with(|| Box::pin(sleep(idle)));
            if end.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(late()));
            }
        }
        Poll::Pending
    })
    .await
}

/// The error of a direction that did not end in time after the other one had.
fn late() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "the other direction did not end in time",
    )
}

/// Copies `from` to `to` through a buffer of `BUFFER` bytes and ends the writing direction of `to`. `to` is flushed
/// whenever `from` has nothing ready to read, and at the end of `from`: a stream may keep what it was given until it
/// is flushed (a TLS stream does when its socket cannot take more), and what was written must not wait for a reader
/// that stays quiet.
async fn pump<R, W>(from: R, mut to: W) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut from = BufReader::with_capacity(BUFFER, from);
    // Something was written since the last flush.
    let mut unflushed = false;
    poll_fn(|cx| -> Poll<io::Result<()>> {
        loop {
            let chunk = match Pin::new(&mut from).poll_fill_buf(cx) {
                Poll::Ready(read) => read?,
                Poll::Pending => {
                    if unflushed {
                        ready!(Pin::new(&mut to).poll_flush(cx))?;
                        unflushed = false;
                    }
                    return Poll::Pending;
                }
            };
            if chunk.is_empty() {
                ready!(Pin::new(&mut to).poll_flush(cx))?;
                return Poll::Ready(Ok(()));
            }
            let n = ready!(Pin::new(&mut to).poll_write(cx, chunk))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            unflushed = true;
            Pin::new(&mut from).consume(n);
        }
    })
    .await?;
    to.shutdown().await
}

#[cfg(test)]
mod tests;
