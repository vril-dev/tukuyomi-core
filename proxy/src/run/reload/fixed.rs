//! The values of the configuration that a running proxy does not change when it reads the file again.
//!
//! They are the sizes and the times that the main loop, the byte budget and the driver took at the start
//! (`proxy.max_conns`, `max_buffered_bytes`, `drive_slice_ms`, `ready_wait_ms`, `stop_inspect_ms` and
//! `stop_wait_ms`), and the objects that the other processes read from the same file when they start: `records`
//! (everything but its `keep`, which each setup has of its own), `status`, `admin`, `rules.store` and `kernel`. A file
//! that has another value for one of them is refused whole, and the refusal names the first of them, in this order, by
//! its place in the file. It never shows a value. The listeners are not among them: a file may add, remove and reorder
//! them (see `config`).

use std::time::Duration;

use crate::config::{
    AdminConfig, Keep, KernelSettings, Loaded, Records, StatusConfig, StoreConfig,
};

/// The values of one configuration file that a reading of the file again may not change.
pub(in crate::run) struct Fixed {
    max_conns: usize,
    max_buffered_bytes: usize,
    drive_slice: Duration,
    ready_wait: Duration,
    stop_inspect: Duration,
    stop_wait: Duration,
    /// With `keep` made the same in every file, so that a file that differs in nothing else is the same.
    records: Option<Records>,
    status: Option<StatusConfig>,
    admin: Option<AdminConfig>,
    store: StoreConfig,
    kernel: KernelSettings,
}

impl Fixed {
    /// The values of `loaded`.
    pub(in crate::run) fn of(loaded: &Loaded) -> Fixed {
        let proxy = &loaded.proxy;
        Fixed {
            max_conns: proxy.max_conns,
            max_buffered_bytes: proxy.max_buffered_bytes,
            drive_slice: proxy.drive_slice,
            ready_wait: proxy.ready_wait,
            stop_inspect: proxy.stop_inspect,
            stop_wait: proxy.stop_wait,
            records: loaded.records.clone().map(|records| Records {
                keep: Keep::BestEffort,
                ..records
            }),
            status: loaded.status,
            admin: loaded.admin.clone(),
            store: loaded.store.clone(),
            kernel: loaded.kernel.clone(),
        }
    }

    /// The first key, in the order of the module comment, that has another value in `other` than here.
    pub(in crate::run) fn first_difference(&self, other: &Fixed) -> Option<&'static str> {
        [
            ("proxy.max_conns", self.max_conns == other.max_conns),
            (
                "proxy.max_buffered_bytes",
                self.max_buffered_bytes == other.max_buffered_bytes,
            ),
            (
                "proxy.drive_slice_ms",
                self.drive_slice == other.drive_slice,
            ),
            ("proxy.ready_wait_ms", self.ready_wait == other.ready_wait),
            (
                "proxy.stop_inspect_ms",
                self.stop_inspect == other.stop_inspect,
            ),
            ("proxy.stop_wait_ms", self.stop_wait == other.stop_wait),
            ("records", self.records == other.records),
            ("status", self.status == other.status),
            ("admin", self.admin == other.admin),
            ("rules.store", self.store == other.store),
            ("kernel", self.kernel == other.kernel),
        ]
        .into_iter()
        .find_map(|(key, same)| (!same).then_some(key))
    }
}

#[cfg(test)]
mod tests;
