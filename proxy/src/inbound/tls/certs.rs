//! The certificates and keys in use, and the checks every one of them passes before it is.
//!
//! All the certificates of all the TLS listeners are read in one pass (`read_all`), each through the key source, and
//! each is checked: the private key is the key of the first certificate of the chain, and that certificate covers
//! every host that the settings give it (a `*.` host is checked with one fixed label in front of its name). The
//! first one that fails ends the pass and is named by the number of its listener and its place in the listener. The
//! time of validity is not looked at. Nothing is in use until the whole pass has succeeded: the result is one
//! `Material`, and `Store` replaces the one in use with it in a single step.

use std::fmt;
use std::sync::{Arc, PoisonError, RwLock};

use rustls::client::verify_server_name;
use rustls::pki_types::ServerName;
use rustls::server::ParsedCertificate;
use rustls::sign::CertifiedKey;

use super::keys::KeySource;
use crate::config::{ListenerConfig, ListenerKind};

/// The label that stands in front of the name of a `*.` host when the certificate is checked for it.
const WILDCARD_PROBE: &str = "wildcard-check";

/// Why a certificate or a key was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// A file is missing, not a regular file, or cannot be read.
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

/// Which listener and which certificate (both from 1) a fault is about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub why: &'static str,
    pub listener: usize,
    pub certificate: Option<usize>,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (listener {}", self.why, self.listener)?;
        match self.certificate {
            Some(certificate) => write!(f, ", certificate {certificate})"),
            None => f.write_str(")"),
        }
    }
}

/// The certified keys, by the position of the listener and then of the certificate. A listener that does not end TLS
/// has none.
pub(super) type Material = Vec<Vec<Arc<CertifiedKey>>>;

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

/// Reads and checks every certificate of every TLS listener.
pub(super) fn read_all(
    listeners: &[ListenerConfig],
    source: &dyn KeySource,
) -> Result<Material, Refusal> {
    let mut material = Vec::with_capacity(listeners.len());
    for (at, listener) in listeners.iter().enumerate() {
        let mut keys = Vec::new();
        if let ListenerKind::Tls(tls) = &listener.kind {
            for (place, certificate) in tls.certificates.iter().enumerate() {
                let refuse = |fault: Fault| Refusal {
                    why: fault.text(),
                    listener: at + 1,
                    certificate: Some(place + 1),
                };
                let key = source
                    .load(&certificate.cert_file, &certificate.key_file)
                    .map_err(refuse)?;
                check(&key, &certificate.hosts).map_err(refuse)?;
                keys.push(Arc::new(key));
            }
        }
        material.push(keys);
    }
    Ok(material)
}

/// The key goes with the first certificate, and that certificate covers every host.
fn check(key: &CertifiedKey, hosts: &[String]) -> Result<(), Fault> {
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
