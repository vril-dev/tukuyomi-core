//! The TLS of all the listeners together: what is read when the proxy starts and each time it reads the configuration
//! file again, what is looked up for a connection, and what SIGUSR2 replaces.
//!
//! `Tls::load` reads and checks every certificate of every TLS listener and makes the handshake of each; one that
//! fails refuses the start, except a certificate with `acme` whose files do not exist yet, which waits (`waiting`):
//! of a listener, and with `managed` that of the way to the admin process and those of the sites with `acme`.
//! `Tls::load_sites` does the same for a file with `managed`, whose TLS listeners all choose from the certificate of
//! the way to the admin process and those of the sites (see `table`). `Tls::reload` reads and checks them all again,
//! and puts the new certificates in use only if every one passes; the hosts of the certificates are those of the
//! settings and do not change, so a connection keeps what it has and only the handshakes that start afterwards use the
//! new ones.

use std::sync::Arc;

use super::certs::{Place, Refusal, Store};
use super::handshake::Handshake;
use super::keys::KeySource;
use super::table::Table;
use crate::config::{CertificateConfig, ListenerConfig, ListenerKind};
use crate::managed::{self, Site};

/// The TLS state of the proxy: a handshake for each TLS listener, the certificates they use, and the table that says
/// where those come from.
pub struct Tls {
    /// By the position of the listener; `None` for a listener that does not end TLS.
    listeners: Vec<Option<Handshake>>,
    store: Arc<Store>,
    table: Table,
}

impl Tls {
    /// No TLS listener at all, for the tests of a proxy that has none.
    #[cfg(test)]
    pub fn none() -> Tls {
        Tls {
            listeners: Vec::new(),
            store: Arc::new(Store::new(Vec::new())),
            table: Table::default(),
        }
    }

    /// Reads and checks the certificates of the TLS listeners among `listeners`, and makes their handshakes.
    pub fn load(listeners: &[ListenerConfig], source: &dyn KeySource) -> Result<Tls, Refusal> {
        Tls::of(Table::listeners(listeners), listeners, source)
    }

    /// `load` for a file with `managed`: every TLS listener among `listeners`, which have no certificate of their own,
    /// chooses from the certificate `route` of the way to the admin process, read through `source`, and the
    /// certificates of `sites`, read from `store`.
    pub fn load_sites(
        listeners: &[ListenerConfig],
        route: Option<&CertificateConfig>,
        sites: &[Site],
        store: &managed::Store,
        source: &dyn KeySource,
    ) -> Result<Tls, Refusal> {
        Tls::of(
            Table::sites(listeners, route, sites, store),
            listeners,
            source,
        )
    }

    fn of(
        table: Table,
        listeners: &[ListenerConfig],
        source: &dyn KeySource,
    ) -> Result<Tls, Refusal> {
        let store = Arc::new(Store::new(table.read(source)?));
        let mut built = Vec::with_capacity(listeners.len());
        for (at, listener) in listeners.iter().enumerate() {
            built.push(match (&listener.kind, table.list_of(at)) {
                (ListenerKind::Tls(tls), Some((list, entries))) => Some(
                    Handshake::new(list, entries, tls, store.clone()).map_err(|fault| Refusal {
                        why: fault.text(),
                        place: Place::Listener(at + 1),
                    })?,
                ),
                _ => None,
            });
        }
        Ok(Tls {
            listeners: built,
            store,
            table,
        })
    }

    /// Reads and checks the certificates again. If all of them pass, they are used for the handshakes that start
    /// from now on; if one does not, none is, and the refusal says which. `listeners` are those of `load`. A TLS of
    /// `load_sites`, whose listeners have no certificates, reads its own sources again instead: the files of the way to
    /// the admin process, and the managed store.
    pub fn reload(
        &self,
        listeners: &[ListenerConfig],
        source: &dyn KeySource,
    ) -> Result<(), Refusal> {
        let material = if self.table.shared() {
            self.table.read(source)?
        } else {
            Table::listeners(listeners).read(source)?
        };
        self.store.replace(material);
        Ok(())
    }

    /// The certificates with `acme` whose files did not exist when the certificates were last read: they are not in
    /// use, and the handshakes for their hosts are refused.
    pub fn waiting(&self) -> Vec<Place> {
        self.table.waiting(&self.store.current())
    }

    /// The handshake of the listener at `listener`, if it ends TLS.
    pub fn handshake(&self, listener: usize) -> Option<&Handshake> {
        self.listeners.get(listener)?.as_ref()
    }

    /// Whether a certificate of some TLS listener has `name`, a lowercase name, among its hosts.
    pub fn serves(&self, name: &str) -> bool {
        self.listeners
            .iter()
            .flatten()
            .any(|handshake| handshake.names().find(name).is_some())
    }
}
