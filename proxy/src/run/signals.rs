//! What the running process waits for, behind one poll: the signals, the answers of the driver, the end of a
//! connection and the accept side.

use std::future::{Future, poll_fn};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::oneshot;
use tokio::task::{JoinError, JoinSet};
use tokio::time::{Instant, timeout_at};
use tukuyomi_kernel::Failure;

use crate::inbound::transport::accept::{Accepted, Acceptor, Arrival};
use crate::inspect::driver::{End, Switched};

/// The five signal streams. They are created before the driver starts.
pub(super) struct Signals {
    term: Signal,
    int: Signal,
    hup: Signal,
    usr1: Signal,
    usr2: Signal,
}

impl Signals {
    pub(super) fn install() -> io::Result<Signals> {
        Ok(Signals {
            term: signal(SignalKind::terminate())?,
            int: signal(SignalKind::interrupt())?,
            hup: signal(SignalKind::hangup())?,
            usr1: signal(SignalKind::user_defined1())?,
            usr2: signal(SignalKind::user_defined2())?,
        })
    }
}

/// The channel an answer did not come through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Source {
    Ready,
    Failed,
    End,
    Permits,
    Switch,
}

impl Source {
    pub(super) fn name(self) -> &'static str {
        match self {
            Source::Ready => "ready",
            Source::Failed => "failed",
            Source::End => "end",
            Source::Permits => "connection permit",
            Source::Switch => "switch",
        }
    }
}

/// What ended one wait.
pub(super) enum Event {
    Ready(Result<(), Failure>),
    Signal(&'static str),
    /// SIGUSR1.
    Reload,
    /// SIGUSR2.
    Certificates,
    /// The driver answered a switch: whether the new generation serves.
    Switched(bool),
    Failed(Failure),
    Ended(End),
    Lost(Source),
    /// The deadline of the wait passed.
    Late,
    Conn(Arrival),
    AcceptErr(Option<i32>),
    Joined(Result<(), JoinError>),
}

/// Everything the main thread waits for, behind one poll. The order of the polls is the order of precedence: the
/// driver's answers and the signals before the connections that ended, those before the next accept.
pub(super) struct Waits {
    term: Signal,
    int: Signal,
    hup: Signal,
    usr1: Signal,
    usr2: Signal,
    ready: Option<oneshot::Receiver<Result<(), Failure>>>,
    failed: Option<oneshot::Receiver<Failure>>,
    /// The answer to the switch that is under way, if there is one.
    pub(super) switch: Option<oneshot::Receiver<Switched>>,
    end: Option<oneshot::Receiver<End>>,
    pub(super) accept: Option<Acceptor>,
    pub(super) conns: JoinSet<()>,
}

impl Waits {
    pub(super) fn new(
        signals: Signals,
        ready: oneshot::Receiver<Result<(), Failure>>,
        failed: oneshot::Receiver<Failure>,
        end: oneshot::Receiver<End>,
    ) -> Waits {
        Waits {
            term: signals.term,
            int: signals.int,
            hup: signals.hup,
            usr1: signals.usr1,
            usr2: signals.usr2,
            ready: Some(ready),
            failed: Some(failed),
            switch: None,
            end: Some(end),
            accept: None,
            conns: JoinSet::new(),
        }
    }

    /// The next event, or `Event::Late` at `by`. A channel that answered or closed is not polled again.
    pub(super) async fn wait(&mut self, by: Option<Instant>) -> Event {
        let next = poll_fn(|cx| self.poll(cx));
        match by {
            Some(by) => timeout_at(by, next).await.unwrap_or(Event::Late),
            None => next.await,
        }
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Event> {
        if let Some(ready) = self.ready.as_mut()
            && let Poll::Ready(answer) = Pin::new(ready).poll(cx)
        {
            self.ready = None;
            return Poll::Ready(answer.map_or(Event::Lost(Source::Ready), Event::Ready));
        }
        for (name, stream) in [
            ("SIGTERM", &mut self.term),
            ("SIGINT", &mut self.int),
            ("SIGHUP", &mut self.hup),
        ] {
            if stream.poll_recv(cx).is_ready() {
                return Poll::Ready(Event::Signal(name));
            }
        }
        if self.usr1.poll_recv(cx).is_ready() {
            return Poll::Ready(Event::Reload);
        }
        if self.usr2.poll_recv(cx).is_ready() {
            return Poll::Ready(Event::Certificates);
        }
        if let Some(failed) = self.failed.as_mut()
            && let Poll::Ready(answer) = Pin::new(failed).poll(cx)
        {
            self.failed = None;
            return Poll::Ready(answer.map_or(Event::Lost(Source::Failed), Event::Failed));
        }
        if let Some(switch) = self.switch.as_mut()
            && let Poll::Ready(answer) = Pin::new(switch).poll(cx)
        {
            self.switch = None;
            return Poll::Ready(answer.map_or(Event::Lost(Source::Switch), |switched| {
                Event::Switched(switched == Switched::Yes)
            }));
        }
        if let Some(end) = self.end.as_mut()
            && let Poll::Ready(answer) = Pin::new(end).poll(cx)
        {
            self.end = None;
            return Poll::Ready(answer.map_or(Event::Lost(Source::End), Event::Ended));
        }
        if let Poll::Ready(Some(done)) = self.conns.poll_join_next(cx) {
            return Poll::Ready(Event::Joined(done));
        }
        match self.accept.as_mut().map(|accept| accept.poll(cx)) {
            Some(Poll::Ready(Accepted::Conn(arrival))) => Poll::Ready(Event::Conn(arrival)),
            Some(Poll::Ready(Accepted::Failed(errno))) => Poll::Ready(Event::AcceptErr(errno)),
            Some(Poll::Ready(Accepted::PermitsGone)) => Poll::Ready(Event::Lost(Source::Permits)),
            Some(Poll::Pending) | None => Poll::Pending,
        }
    }
}

#[cfg(test)]
pub(super) mod tests;
