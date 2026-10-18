//! The connections to the upstream that wait to be used again.
//!
//! A connection that has carried a whole answer, and that neither side has ended, goes back here instead of being
//! closed. At most `upstream_keepalive` of them wait; when one more comes, the one that has waited longest is
//! closed. A connection waits for at most `upstream_keepalive_timeout` and carries at most
//! `upstream_keepalive_requests` requests. The newest waiting connection is taken first, so the others age out
//! when the load is low.
//!
//! A connection ends by itself at the end of its wait: when it goes back, the idle limit of its reads becomes
//! `upstream_keepalive_timeout`, and when it is taken the caller puts the limit of the request back (see
//! `origin`). A connection that ends this way is closed with no word from the pool; its place in the list is
//! freed when it is next looked at. A connection goes back only if it can carry a request right then: one that
//! is closed, or whose request is still being written because the upstream does not read it, does not.
//!
//! A connection is checked when it is taken: one that the upstream has closed in the meantime is dropped, and so
//! is one that does not become ready to carry a request in time. The upstream can still close a connection in the
//! moment it is taken; the caller handles that (see `origin`). A connection that is dropped is closed: its task
//! is aborted, which drops the socket. The lock on the list is never held across a wait.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use hyper::client::conn::http1::SendRequest;
use tokio::task::AbortHandle;
use tokio::time::{Instant, timeout_at};

use crate::config::ProxyConfig;
use crate::forward::origin::Sent;
use crate::inbound::io::Gauge;

/// Aborts the spawned future that drives the connection to the upstream when it is dropped.
struct Abort(AbortHandle);

impl Drop for Abort {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A connection to the upstream: the way to send a request on it, the counts of its socket, and its task.
/// Dropping it closes the connection.
pub(super) struct Lease {
    pub(super) sender: SendRequest<Sent>,
    pub(super) gauge: Gauge,
    /// The requests sent on the connection, the one under way included.
    pub(super) used: usize,
    _task: Abort,
}

impl Lease {
    /// A new connection, driven by the task that `task` belongs to.
    pub(super) fn new(sender: SendRequest<Sent>, gauge: Gauge, task: AbortHandle) -> Lease {
        Lease {
            sender,
            gauge,
            used: 0,
            _task: Abort(task),
        }
    }
}

struct Idle {
    lease: Lease,
    /// When it went back into the pool.
    since: Instant,
}

struct Shared {
    /// The longest waiting connection first.
    idle: Mutex<VecDeque<Idle>>,
    most: usize,
    timeout: Duration,
    requests: usize,
}

/// The waiting connections to the upstream. A handle: a clone is the same pool.
#[derive(Clone)]
pub struct Pool {
    shared: Arc<Shared>,
}

fn lock(idle: &Mutex<VecDeque<Idle>>) -> MutexGuard<'_, VecDeque<Idle>> {
    idle.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Pool {
    /// A pool as `upstream_keepalive`, `upstream_keepalive_timeout` and `upstream_keepalive_requests` say. With
    /// `upstream_keepalive` 0 nothing waits.
    pub fn new(cfg: &ProxyConfig) -> Pool {
        Pool {
            shared: Arc::new(Shared {
                idle: Mutex::new(VecDeque::new()),
                most: cfg.upstream_keepalive,
                timeout: cfg.upstream_keepalive_timeout,
                requests: cfg.upstream_keepalive_requests,
            }),
        }
    }

    /// Drops the connections that have waited for the whole time, and returns what is left, to be changed by `f`.
    /// They are the first ones, for the connections are in the order they came back in.
    fn with<R>(&self, f: impl FnOnce(&mut VecDeque<Idle>) -> R) -> R {
        let mut idle = lock(&self.shared.idle);
        let now = Instant::now();
        while idle
            .front()
            .is_some_and(|front| now.saturating_duration_since(front.since) >= self.shared.timeout)
        {
            idle.pop_front();
        }
        f(&mut idle)
    }

    /// The newest waiting connection that can carry a request, or `None` if there is none (the caller connects).
    /// A connection that is closed, or not ready by `by`, is dropped. The cap of its socket and the idle limit of
    /// its reads are those of the wait, and the caller gives it those of the request (`Gauge::rearm`).
    pub(super) async fn take(&self, by: Instant) -> Option<Lease> {
        loop {
            let mut lease = self.with(VecDeque::pop_back)?.lease;
            if lease.sender.is_closed() {
                continue;
            }
            if let Ok(Ok(())) = timeout_at(by, lease.sender.ready()).await {
                return Some(lease);
            }
        }
    }

    /// Takes a connection back after a whole answer. It is closed instead if it has carried its requests, if
    /// its socket was cut off, if it is not ready to carry a request now (it is closed), if the bytes of the
    /// request are still waiting to be written (the upstream answered without reading them, and a request sent
    /// on this connection would wait behind them), or if the pool keeps none. A connection that stays has the
    /// idle limit of its reads set to the time it may wait, so it closes by itself at the end of that time.
    pub(super) fn put(&self, lease: Lease) {
        let shared = &self.shared;
        if shared.most == 0
            || lease.used >= shared.requests
            || lease.gauge.over()
            || !lease.sender.is_ready()
            || lease.gauge.write_blocked()
        {
            return;
        }
        lease.gauge.restart(shared.timeout);
        self.with(|idle| {
            while idle.len() >= shared.most {
                idle.pop_front();
            }
            idle.push_back(Idle {
                lease,
                since: Instant::now(),
            });
        });
    }

    /// The number of waiting connections, for the tests.
    #[cfg(test)]
    pub(super) fn waiting(&self) -> usize {
        lock(&self.shared.idle).len()
    }
}

#[cfg(test)]
mod tests;
