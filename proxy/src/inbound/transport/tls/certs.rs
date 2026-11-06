//! The certificates and keys in use, and the checks every one of them passes before it is.
//!
//! All the certificates of all the TLS listeners are read in one pass (`Table::read`), each from where the table says,
//! and each is checked: the private key is the key of the first certificate of the chain, and that certificate covers
//! every host that the settings give it (a `*.` host is checked with one fixed label in front of its name). The first
//! one that fails ends the pass and is named by its `Place`: the number of its listener and its place in the listener,
//! or, in the table of a file with `managed`, `admin route` or `site <name>`. The time of validity is not looked at.
//! Nothing is in use until the whole pass has succeeded: the result is one `Material`, and `Store` replaces the one in
//! use with it in a single step. A certificate with `acme` whose certificate file or key file does not exist (for a
//! site with `acme`, whose files are in the managed store, also its directory there) is not a failure: it has not
//! been issued yet, so its place in the material is empty and a handshake for its hosts is refused like one for a name
//! that nobody has (`Tls::waiting` lists such certificates). Any other fault of such a certificate, a link in the place
//! of a directory of the store included, and a missing file of any other certificate, fails the pass as before.

use std::fmt;
use std::sync::{Arc, PoisonError, RwLock};

use rustls::client::verify_server_name;
use rustls::pki_types::ServerName;
use rustls::server::ParsedCertificate;
use rustls::sign::CertifiedKey;

/// The label that stands in front of the name of a `*.` host when the certificate is checked for it.
const WILDCARD_PROBE: &str = "wildcard-check";

/// Why a certificate or a key was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// A file does not exist.
    Missing,
    /// A file is not a regular file, or cannot be read.
    Unreadable,
    TooLarge,
    NotCertificates,
    NotOneKey,
    KeyType,
    NotPair,
    NotCovered,
    /// The settings of a listener cannot be made into a TLS configuration.
    Build,
}

impl Fault {
    /// A fixed sentence: it names no file and no value from a file.
    pub fn text(self) -> &'static str {
        match self {
            Fault::Missing => "a certificate or key file does not exist",
            Fault::Unreadable => "a certificate or key file cannot be read",
            Fault::TooLarge => "a certificate or key file is over 1 MiB",
            Fault::NotCertificates => {
                "a certificate file does not hold 1 to 10 certificates in PEM"
            }
            Fault::NotOneKey => "a key file does not hold exactly one private key in PEM",
            Fault::KeyType => "a private key is not of a type that can be loaded",
            Fault::NotPair => "a certificate and a private key are not a pair",
            Fault::NotCovered => "a certificate does not cover a host of its settings",
            Fault::Build => "the TLS settings of a listener cannot be made",
        }
    }
}

/// What a fault is about, and its fixed sentence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub why: &'static str,
    pub place: Place,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.why, self.place)
    }
}

/// Where a certificate is, in the words of a line of the record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Place {
    /// A certificate of a listener, by the number of the listener and its place in the listener (both from 1).
    Certificate { listener: usize, certificate: usize },
    /// A listener as a whole, by its number (from 1).
    Listener(usize),
    /// The certificate of the way to the admin process, of a file with `managed`.
    AdminRoute,
    /// The certificate of a site of a managed version, by the name of the site.
    Site(String),
}

impl fmt::Display for Place {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Place::Certificate {
                listener,
                certificate,
            } => write!(f, "listener {listener}, certificate {certificate}"),
            Place::Listener(listener) => write!(f, "listener {listener}"),
            Place::AdminRoute => f.write_str("admin route"),
            Place::Site(name) => write!(f, "site {name}"),
        }
    }
}

/// The certified keys, by the list of the table (see `table`; for a file without `managed`, the position of the
/// listener) and then by the place of the certificate; `None` for a certificate with `acme` that has not been issued
/// yet. A listener that does not end TLS has none.
pub(super) type Material = Vec<Vec<Option<Arc<CertifiedKey>>>>;

/// The material in use. A handshake takes it once and keeps that one, whatever replaces it afterwards.
#[derive(Debug)]
pub(super) struct Store(RwLock<Arc<Material>>);

impl Store {
    pub(super) fn new(material: Material) -> Store {
        Store(RwLock::new(Arc::new(material)))
    }

    pub(super) fn current(&self) -> Arc<Material> {
        Arc::clone(&self.0.read().unwrap_or_else(PoisonError::into_inner))
    }

    pub(super) fn replace(&self, material: Material) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(material);
    }
}

/// The key goes with the first certificate, and that certificate covers every host. The `acme` command makes the same
/// check of the chain it gets and of the files it finds.
pub(crate) fn check(key: &CertifiedKey, hosts: &[String]) -> Result<(), Fault> {
    key.keys_match().map_err(|_| Fault::NotPair)?;
    let leaf = key.end_entity_cert().map_err(|_| Fault::NotPair)?;
    let leaf = ParsedCertificate::try_from(leaf).map_err(|_| Fault::NotPair)?;
    for host in hosts {
        let name = match host.strip_prefix("*.") {
            Some(rest) => format!("{WILDCARD_PROBE}.{rest}"),
            None => host.clone(),
        };
        let covered =
            ServerName::try_from(name).is_ok_and(|name| verify_server_name(&leaf, &name).is_ok());
        if !covered {
            return Err(Fault::NotCovered);
        }
    }
    Ok(())
}
