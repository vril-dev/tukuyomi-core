//! What the running process waits for, behind one poll: the signals, the answers of the driver, the end of a
//! connection and the accept side.

use std::collections::VecDeque;
use std::future::{Future, poll_fn};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinError, JoinSet};
use tokio::time::{Instant, timeout_at};
use tukuyomi_kernel::{Engine, Failure};

use super::control::{Control, Order};
use super::start::{Parts, Refusal};
use super::status::Status;
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
    Ready(Result<(), (Engine, Failure)>),
    Signal(&'static str),
    /// SIGHUP.
    Configuration,
    /// SIGUSR1.
    Reload,
    /// SIGUSR2.
    Certificates,
    /// The driver answered the switch of `engine`: whether the new generation serves.
    Switched {
        engine: Engine,
        switched: bool,
    },
    /// The thread that reads the configuration file again answered: the parts it made, or why it refused the file (it
    /// wrote the line that says so).
    Configured(Result<Box<Parts>, Refusal>),
    /// The thread that reads the configuration file again ended without an answer. This is no cause of a stop: the
    /// thread has nothing to do with the requests that are served.
    ConfigurationLost,
    /// An order from the control socket.
    Control(Order),
    /// The kernel of `engine`, which served, failed.
    Failed {
        engine: Engine,
        failure: Failure,
    },
    Ended(End),
    Lost(Source),
    /// The deadline of the wait passed.
    Late,
    Conn(Arrival),
    AcceptErr(Option<i32>),
    Joined(Result<(), JoinError>),
}

/// Everything the main thread waits for, behind one poll. The order of the polls is the order of precedence: the
/// driver's answers and the signals before the connections that ended, those before the next accept. The status
/// listener answers on its own and is held here only so that the stop can close it; the control socket gives its
/// orders to the main loop, which carries them out.
pub(super) struct Waits {
    term: Signal,
    int: Signal,
    hup: Signal,
    usr1: Signal,
    usr2: Signal,
    ready: Option<oneshot::Receiver<Result<(), (Engine, Failure)>>>,
    failed: Option<mpsc::Receiver<(Engine, Failure)>>,
    /// The engine and the answer of the switch that is under way, if there is one. There is one at a time.
    pub(super) switch: Option<(Engine, oneshot::Receiver<Switched>)>,
    /// The engines that SIGUSR1 has still to switch, after the one under way.
    pub(super) queue: VecDeque<Engine>,
    /// The answer of the thread that reads the configuration file again, if one is under way.
    pub(super) config: Option<oneshot::Receiver<Result<Box<Parts>, Refusal>>>,
    end: Option<oneshot::Receiver<End>>,
    pub(super) accept: Option<Acceptor>,
    pub(super) status: Option<Status>,
    pub(super) control: Option<Control>,
    pub(super) conns: JoinSet<()>,
}

impl Waits {
    pub(super) fn new(
        signals: Signals,
        ready: oneshot::Receiver<Result<(), (Engine, Failure)>>,
        failed: mpsc::Receiver<(Engine, Failure)>,
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
            queue: VecDeque::new(),
            config: None,
            end: Some(end),
            accept: None,
            status: None,
            control: None,
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
        for (name, stream) in [("SIGTERM", &mut self.term), ("SIGINT", &mut self.int)] {
            if stream.poll_recv(cx).is_ready() {
                return Poll::Ready(Event::Signal(name));
            }
        }
        if self.hup.poll_recv(cx).is_ready() {
            return Poll::Ready(Event::Configuration);
        }
        if self.usr1.poll_recv(cx).is_ready() {
            return Poll::Ready(Event::Reload);
        }
        if self.usr2.poll_recv(cx).is_ready() {
            return Poll::Ready(Event::Certificates);
        }
        if let Some(failed) = self.failed.as_mut()
            && let Poll::Ready(answer) = failed.poll_recv(cx)
        {
            // The channel closes only when the driver is gone: a kernel that failed is the answer, and later ones
            // are heard too.
            if answer.is_none() {
                self.failed = None;
            }
            return Poll::Ready(
                answer.map_or(Event::Lost(Source::Failed), |(engine, failure)| {
                    Event::Failed { engine, failure }
                }),
            );
        }
        if let Some((engine, switch)) = self.switch.as_mut()
            && let Poll::Ready(answer) = Pin::new(switch).poll(cx)
        {
            let engine = *engine;
            self.switch = None;
            return Poll::Ready(answer.map_or(Event::Lost(Source::Switch), |switched| {
                Event::Switched {
                    engine,
                    switched: switched == Switched::Yes,
                }
            }));
        }
        if let Some(config) = self.config.as_mut()
            && let Poll::Ready(answer) = Pin::new(config).poll(cx)
        {
            self.config = None;
            return Poll::Ready(answer.map_or(Event::ConfigurationLost, Event::Configured));
        }
        if let Some(control) = self.control.as_mut()
            && let Poll::Ready(order) = control.poll_order(cx)
        {
            match order {
                Some(order) => return Poll::Ready(Event::Control(order)),
                // The task of the socket is gone: no order will come.
                None => self.control = None,
            }
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
