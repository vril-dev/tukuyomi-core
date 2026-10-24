//! The TLS of all the listeners together: what is read when the proxy starts, what is looked up for a connection,
//! and what SIGUSR2 replaces.
//!
//! `Tls::load` reads and checks every certificate of every TLS listener and makes the handshake of each; one that
//! fails refuses the start, except a certificate with `acme` whose files do not exist yet, which waits (`waiting`).
//! `Tls::reload` reads and checks them all again, and puts the new certificates in use only
//! if every one passes; the hosts of the certificates are those of the settings and do not change, so a connection
//! keeps what it has and only the handshakes that start afterwards use the new ones.

use std::sync::Arc;

use super::certs::{Fault, Place, Refusal, Store, read_all};
use super::handshake::Handshake;
use super::keys::KeySource;
use crate::config::{ListenerConfig, ListenerKind};

/// The TLS state of the proxy: a handshake for each TLS listener, and the certificates they use.
pub struct Tls {
    /// By the position of the listener; `None` for a listener that does not end TLS.
    listeners: Vec<Option<Handshake>>,
    store: Arc<Store>,
}

impl Tls {
    /// No TLS listener at all, for the tests of a proxy that has none.
    #[cfg(test)]
    pub fn none() -> Tls {
        Tls {
            listeners: Vec::new(),
            store: Arc::new(Store::new(Vec::new())),
        }
    }

    /// Reads and checks the certificates of the TLS listeners among `listeners`, and makes their handshakes.
    pub fn load(listeners: &[ListenerConfig], source: &dyn KeySource) -> Result<Tls, Refusal> {
        let store = Arc::new(Store::new(read_all(listeners, source)?));
        let mut built = Vec::with_capacity(listeners.len());
        for (at, listener) in listeners.iter().enumerate() {
            built.push(match &listener.kind {
                ListenerKind::Tls(tls) => Some(Handshake::new(at, tls, store.clone()).map_err(
                    |fault: Fault| Refusal {
                        why: fault.text(),
                        listener: at + 1,
                        certificate: None,
                    },
                )?),
                ListenerKind::Plain | ListenerKind::Redirect { .. } => None,
            });
        }
        Ok(Tls {
            listeners: built,
            store,
        })
    }

    /// Reads and checks the certificates again. If all of them pass, they are used for the handshakes that start
    /// from now on; if one does not, none is, and the refusal says which. `listeners` are those of `load`.
    pub fn reload(
        &self,
        listeners: &[ListenerConfig],
        source: &dyn KeySource,
    ) -> Result<(), Refusal> {
        self.store.replace(read_all(listeners, source)?);
        Ok(())
    }

    /// The certificates with `acme` whose files did not exist when the certificates were last read: they are not in
    /// use, and the handshakes for their hosts are refused.
    pub fn waiting(&self) -> Vec<Place> {
        let material = self.store.current();
        let mut places = Vec::new();
        for (listener, keys) in material.iter().enumerate() {
            for (certificate, key) in keys.iter().enumerate() {
                if key.is_none() {
                    places.push(Place {
                        listener: listener + 1,
                        certificate: certificate + 1,
                    });
                }
            }
        }
        places
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
