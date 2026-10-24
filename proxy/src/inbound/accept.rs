//! The accept side: every listener is bound once, and a connection permit is taken before each accept.
//!
//! One `Acceptor` serves all the listeners and holds the one `Semaphore` of `max_conns`, so the connections of all
//! the listeners together are counted against it. It takes a permit first, then looks for a connection at the
//! listeners, and the permit goes with the connection. A permit that is held while no connection is there is the
//! only one held without a connection, however many listeners there are. The look starts at the listener after the
//! one that gave the last connection, so a listener with a long backlog cannot keep the others from being served.
//!
//! While every permit is in use and a connection arrives at a listener, that connection is taken from the backlog to
//! wait for a permit, and the connections that wait for their next request are told to close (`Ingress::drain`), so
//! that the permits of idle connections come back. One connection waits for each listener, so at most as many as
//! there are listeners; the next one of a listener stays in its backlog until the one that waits has its permit. The
//! permits go to the waiting connections in turn, the listener after the last one served first. When the system runs
//! out of descriptors, memory or buffers, the accepts pause for a while.
//!
//! The listeners are bound in the order of the configuration, and the first one that cannot be bound ends the
//! start: the ones bound before it are closed.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{AcquireError, OwnedSemaphorePermit, Semaphore};
use tokio::time::{Sleep, sleep};

use crate::inspect::driver::Ingress;

/// The pause of the accept loop after the system ran out of a resource.
const ACCEPT_PAUSE: Duration = Duration::from_millis(100);
/// Linux errno values (the same on x86_64 and aarch64).
const ENOMEM: i32 = 12;
const ENFILE: i32 = 23;
const EMFILE: i32 = 24;
const ENOBUFS: i32 = 105;

/// A connection that was accepted, the permit it lives under, and the position of the listener it came in on.
pub struct Arrival {
    pub sock: TcpStream,
    pub peer: SocketAddr,
    pub permit: OwnedSemaphorePermit,
    pub listener: usize,
}

/// What one wait of the acceptor ended with.
pub enum Accepted {
    Conn(Arrival),
    /// An accept failed; the number is the error of the system, if there is one.
    Failed(Option<i32>),
    /// The semaphore of the permits was closed.
    PermitsGone,
}

type Acquire = Pin<Box<dyn Future<Output = Result<OwnedSemaphorePermit, AcquireError>>>>;

/// A connection that was accepted, and the position of the listener it came in on.
type Taken = (TcpStream, SocketAddr, usize);

/// The accept side.
pub struct Acceptor {
    listeners: Vec<TcpListener>,
    /// Where the next look starts.
    start: usize,
    permits: Arc<Semaphore>,
    ingress: Arc<Ingress>,
    acquire: Option<Acquire>,
    permit: Option<OwnedSemaphorePermit>,
    /// The connection of each listener that was accepted without a permit, if there is one.
    waiting: Vec<Option<(TcpStream, SocketAddr)>>,
    pause: Option<Pin<Box<Sleep>>>,
}

impl Acceptor {
    pub fn new(
        listeners: Vec<TcpListener>,
        permits: Arc<Semaphore>,
        ingress: Arc<Ingress>,
    ) -> Acceptor {
        Acceptor {
            waiting: listeners.iter().map(|_| None).collect(),
            listeners,
            start: 0,
            permits,
            ingress,
            acquire: None,
            permit: None,
            pause: None,
        }
    }

    /// Binds every address in order. The first failure is the result, and the listeners bound before it are closed.
    pub async fn bind(
        addresses: &[SocketAddr],
        permits: Arc<Semaphore>,
        ingress: Arc<Ingress>,
    ) -> io::Result<Acceptor> {
        let mut listeners = Vec::with_capacity(addresses.len());
        for address in addresses {
            listeners.push(TcpListener::bind(address).await?);
        }
        Ok(Acceptor::new(listeners, permits, ingress))
    }

    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Accepted> {
        if let Some(pause) = self.pause.as_mut() {
            if pause.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            self.pause = None;
        }
        let permit = match self.permit.take() {
            Some(permit) => permit,
            None => {
                let permits = &self.permits;
                let acquire = self
                    .acquire
                    .get_or_insert_with(|| Box::pin(permits.clone().acquire_owned()));
                match acquire.as_mut().poll(cx) {
                    Poll::Pending => return self.crowded(cx),
                    Poll::Ready(Ok(permit)) => {
                        self.acquire = None;
                        permit
                    }
                    Poll::Ready(Err(_)) => return Poll::Ready(Accepted::PermitsGone),
                }
            }
        };
        if let Some(taken) = self.next_waiting() {
            return Poll::Ready(Accepted::Conn(arrival(taken, permit)));
        }
        match self.look(cx) {
            Poll::Pending => {
                self.permit = Some(permit);
                Poll::Pending
            }
            Poll::Ready(Ok(taken)) => Poll::Ready(Accepted::Conn(arrival(taken, permit))),
            Poll::Ready(Err(e)) => {
                self.permit = Some(permit);
                Poll::Ready(self.failed(&e))
            }
        }
    }

    /// Asks the listeners for a connection, starting after the one that gave the last. A listener that answers, with
    /// a connection or with an error, is the last one asked, so the next look starts after it.
    fn look(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Taken>> {
        let count = self.listeners.len();
        for step in 0..count {
            let at = (self.start + step) % count;
            if let Poll::Ready(done) = self.listeners[at].poll_accept(cx) {
                self.start = (at + 1) % count;
                return Poll::Ready(done.map(|(sock, peer)| (sock, peer, at)));
            }
        }
        Poll::Pending
    }

    /// The connection that waits for a permit at the first listener, from the one after the last served, that has
    /// one.
    fn next_waiting(&mut self) -> Option<Taken> {
        let count = self.waiting.len();
        for step in 0..count {
            let at = (self.start + step) % count;
            if let Some((sock, peer)) = self.waiting[at].take() {
                self.start = (at + 1) % count;
                return Some((sock, peer, at));
            }
        }
        None
    }

    /// Every permit is in use. At each listener that has no connection waiting, the first connection that arrives is
    /// accepted to wait for a permit, and the idle connections are told to close; the next one stays in the backlog
    /// until that one has its permit.
    fn crowded(&mut self, cx: &mut Context<'_>) -> Poll<Accepted> {
        let count = self.listeners.len();
        for step in 0..count {
            let at = (self.start + step) % count;
            if self.waiting[at].is_some() {
                continue;
            }
            match self.listeners[at].poll_accept(cx) {
                Poll::Ready(Ok(arrived)) => {
                    self.waiting[at] = Some(arrived);
                    self.ingress.drain();
                }
                Poll::Ready(Err(e)) => return Poll::Ready(self.failed(&e)),
                Poll::Pending => {}
            }
        }
        Poll::Pending
    }

    /// What an accept that failed is. Running out of a resource pauses the accepts for a while.
    fn failed(&mut self, e: &io::Error) -> Accepted {
        let errno = e.raw_os_error();
        if errno.is_some_and(is_resource_error) {
            self.pause = Some(Box::pin(sleep(ACCEPT_PAUSE)));
        }
        Accepted::Failed(errno)
    }
}

fn arrival((sock, peer, listener): Taken, permit: OwnedSemaphorePermit) -> Arrival {
    Arrival {
        sock,
        peer,
        permit,
        listener,
    }
}

/// Whether the accept error means the system is out of descriptors, memory or buffers.
fn is_resource_error(errno: i32) -> bool {
    matches!(errno, ENOMEM | ENFILE | EMFILE | ENOBUFS)
}

#[cfg(test)]
mod tests;
