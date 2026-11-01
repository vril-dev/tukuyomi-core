//! The signals that stop the shipper: SIGTERM, SIGINT and SIGHUP, as for the admin process of the proxy.

use std::future::poll_fn;
use std::task::Poll;
use std::time::Duration;

use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::time::timeout;

/// The three streams of signals. They must be made inside the runtime.
pub(super) struct Signals {
    term: Signal,
    int: Signal,
    hup: Signal,
}

impl Signals {
    /// Installs the handlers. `None`: one could not be installed.
    pub(super) fn install() -> Option<Signals> {
        Some(Signals {
            term: signal(SignalKind::terminate()).ok()?,
            int: signal(SignalKind::interrupt()).ok()?,
            hup: signal(SignalKind::hangup()).ok()?,
        })
    }

    /// Waits for a signal and gives its name.
    async fn wait(&mut self) -> &'static str {
        poll_fn(|cx| {
            for (name, stream) in [
                ("SIGTERM", &mut self.term),
                ("SIGINT", &mut self.int),
                ("SIGHUP", &mut self.hup),
            ] {
                if stream.poll_recv(cx).is_ready() {
                    return Poll::Ready(name);
                }
            }
            Poll::Pending
        })
        .await
    }

    /// Waits `wait` for a signal: its name if one came first. A signal that came before is seen at once, also when
    /// `wait` is zero.
    pub(super) async fn sleep(&mut self, wait: Duration) -> Option<&'static str> {
        timeout(wait, self.wait()).await.ok()
    }
}
