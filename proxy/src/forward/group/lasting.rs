//! What a server keeps through every reading of the configuration: the number of requests that it has at the moment.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// What a server keeps whatever else changes between two readings of the configuration. The server of a group and the
/// server of the group that replaces it have the same one (see `Server::follow`), so a request that began under the
/// old configuration and ends under the new one is counted down where it was counted up.
#[derive(Default)]
pub(super) struct Lasting {
    /// The requests that the server has, from when it was chosen for them until their answers are over.
    in_use: AtomicU64,
}

impl Lasting {
    pub(super) fn in_use(&self) -> u64 {
        self.in_use.load(Ordering::Relaxed)
    }
}

/// A request that a server has: counted up when this is made, and counted down when it is dropped, however that comes
/// about. Each is made once and dropped once, so the count is the number of those that are alive and cannot go below
/// 0.
pub(in crate::forward) struct InUse(Arc<Lasting>);

impl InUse {
    pub(super) fn new(lasting: &Arc<Lasting>) -> InUse {
        lasting.in_use.fetch_add(1, Ordering::Relaxed);
        InUse(Arc::clone(lasting))
    }
}

impl Drop for InUse {
    fn drop(&mut self) {
        self.0.in_use.fetch_sub(1, Ordering::Relaxed);
    }
}
