//! The certificates that the TLS listeners choose from, in one form for both kinds of configuration.
//!
//! A file without `managed` gives each TLS listener the certificates of its own `tls`: the table has one list for
//! each listener, at the position of the listener, and a line names a certificate by the number of its listener and
//! its place there. A file with `managed` gives every TLS listener the same list: the certificate of the way to the
//! admin process and those of the sites of the version, named `admin route` and `site <name>`. The certificate of
//! the way is read from its files as the certificate of a listener is (`KeySource`); the chain and the key of a site
//! are files of the managed store, which are read through the store only, so they are checked against their names
//! each time (see `managed`). The material that is read has the same lists in the same order.

use std::sync::Arc;

use super::certs::{Fault, Material, Place, Refusal, check};
use super::keys::{KeySource, certified};
use crate::config::{CertificateConfig, ListenerConfig, ListenerKind};
use crate::managed::{Site, Store};

/// Where the chain and the key of a certificate are.
#[derive(Clone, Debug)]
enum Source {
    /// Files of the operator, read through a `KeySource`.
    Files(CertificateConfig),
    /// Files of the managed store, by their SHA-256.
    Stored { chain: [u8; 32], key: [u8; 32] },
}

/// One certificate of a list: its hosts, where it is in the configuration, and where its files are.
#[derive(Clone, Debug)]
pub(super) struct Entry {
    /// In the form the settings write them: a lowercase name, or `*.` and a name.
    pub(super) hosts: Vec<String>,
    /// `Place::AdminRoute` for the certificate of the way to the admin process.
    pub(super) place: Place,
    source: Source,
}

/// The lists of certificates, and the list of each listener.
#[derive(Clone, Debug, Default)]
pub(super) struct Table {
    lists: Vec<Vec<Entry>>,
    /// By the position of the listener: the list its handshake chooses from, `None` for one that does not end TLS.
    of: Vec<Option<usize>>,
    /// The store of the sites, for a table of a file with `managed`.
    store: Option<Store>,
}

impl Table {
    /// The certificates of each TLS listener among `listeners`, a list for each listener.
    pub(super) fn listeners(listeners: &[ListenerConfig]) -> Table {
        let mut table = Table::default();
        for (at, listener) in listeners.iter().enumerate() {
            let mut list = Vec::new();
            if let ListenerKind::Tls(tls) = &listener.kind {
                for (place, certificate) in tls.certificates.iter().enumerate() {
                    list.push(Entry {
                        hosts: certificate.hosts.clone(),
                        place: Place::Certificate {
                            listener: at + 1,
                            certificate: place + 1,
                        },
                        source: Source::Files(certificate.clone()),
                    });
                }
                table.of.push(Some(at));
            } else {
                table.of.push(None);
            }
            table.lists.push(list);
        }
        table
    }

    /// One list for every TLS listener among `listeners`: the certificate of the way to the admin process, if there is
    /// one, and the certificates of the sites, whose files are in `store`.
    pub(super) fn sites(
        listeners: &[ListenerConfig],
        route: Option<&CertificateConfig>,
        sites: &[Site],
        store: &Store,
    ) -> Table {
        let route = route.map(|certificate| Entry {
            hosts: certificate.hosts.clone(),
            place: Place::AdminRoute,
            source: Source::Files(certificate.clone()),
        });
        let sites = sites.iter().map(|site| Entry {
            hosts: site.hosts.clone(),
            place: Place::Site(site.name.clone()),
            source: Source::Stored {
                chain: site.chain,
                key: site.key,
            },
        });
        Table {
            lists: vec![route.into_iter().chain(sites).collect()],
            of: listeners
                .iter()
                .map(|listener| matches!(listener.kind, ListenerKind::Tls(_)).then_some(0))
                .collect(),
            store: Some(store.clone()),
        }
    }

    /// Whether the table is the one list of a file with `managed`.
    pub(super) fn shared(&self) -> bool {
        self.store.is_some()
    }

    /// The list that the listener at `listener` chooses from, by its position in the material, and its entries.
    pub(super) fn list_of(&self, listener: usize) -> Option<(usize, &[Entry])> {
        let list = (*self.of.get(listener)?)?;
        Some((list, self.lists.get(list)?))
    }

    /// Reads and checks every certificate (see `certs`). The first that fails ends the reading, and the refusal names
    /// it. A certificate of a listener with `acme` whose file does not exist yet is left empty.
    pub(super) fn read(&self, files: &dyn KeySource) -> Result<Material, Refusal> {
        let mut material = Vec::with_capacity(self.lists.len());
        for list in &self.lists {
            let mut keys = Vec::with_capacity(list.len());
            for entry in list {
                let refuse = |fault: Fault| Refusal {
                    why: fault.text(),
                    place: entry.place.clone(),
                };
                let read = match &entry.source {
                    Source::Files(certificate) => {
                        files.load(&certificate.cert_file, &certificate.key_file)
                    }
                    Source::Stored { chain, key } => self.stored(*chain, *key),
                };
                let key = match read {
                    Ok(key) => key,
                    Err(Fault::Missing) if matches!(&entry.source, Source::Files(c) if c.acme.is_some()) =>
                    {
                        keys.push(None);
                        continue;
                    }
                    Err(fault) => return Err(refuse(fault)),
                };
                check(&key, &entry.hosts).map_err(refuse)?;
                keys.push(Some(Arc::new(key)));
            }
            material.push(keys);
        }
        Ok(material)
    }

    /// The chain and the key of a site, read through the store, which checks them against their names.
    fn stored(&self, chain: [u8; 32], key: [u8; 32]) -> Result<rustls::sign::CertifiedKey, Fault> {
        let store = self.store.as_ref().ok_or(Fault::Unreadable)?;
        let chain = store.file(chain).map_err(|_| Fault::Unreadable)?;
        let key = store.file(key).map_err(|_| Fault::Unreadable)?;
        certified(&chain, &key)
    }

    /// The certificates with `acme` that `material`, read from this table, has empty: only a certificate of a listener
    /// may have `acme`.
    pub(super) fn waiting(&self, material: &Material) -> Vec<Place> {
        let mut places = Vec::new();
        for (list, keys) in self.lists.iter().zip(material) {
            for (entry, key) in list.iter().zip(keys) {
                if key.is_none() {
                    places.push(entry.place.clone());
                }
            }
        }
        places
    }
}
