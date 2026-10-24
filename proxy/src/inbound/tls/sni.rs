//! Which certificate serves a name, and which names a certificate covers.
//!
//! A host of a certificate is a lowercase name, or `*.` and a name, which stands for exactly one label in front of
//! the name (`*.a.example` holds for `www.a.example`, not for `a.example` and not for `x.y.a.example`). Names are
//! compared without regard to the case of ASCII letters. The same rules decide the certificate for the name in a
//! handshake, whether the `Host` of a request is covered by the certificate that was chosen, and whether the redirect
//! listener serves a `Host` at all.

use std::sync::Arc;

use crate::config::CertificateConfig;
use crate::route::RequestHost;

/// The hosts of one certificate.
#[derive(Debug)]
pub struct Hosts {
    exact: Vec<String>,
    /// The name of each wildcard host, without its `*.`.
    wildcard: Vec<String>,
}

impl Hosts {
    fn new(hosts: &[String]) -> Hosts {
        let mut found = Hosts {
            exact: Vec::new(),
            wildcard: Vec::new(),
        };
        for host in hosts {
            match host.strip_prefix("*.") {
                Some(name) => found.wildcard.push(name.to_owned()),
                None => found.exact.push(host.clone()),
            }
        }
        found
    }

    fn has_exact(&self, name: &str) -> bool {
        self.exact.iter().any(|host| host == name)
    }

    fn has_wildcard(&self, name: &str) -> bool {
        one_label_below(name).is_some_and(|rest| self.wildcard.iter().any(|host| host == rest))
    }

    /// Whether `name`, in lowercase, is one of the hosts, or one label in front of a wildcard host.
    pub fn covers(&self, name: &str) -> bool {
        self.has_exact(name) || self.has_wildcard(name)
    }

    /// Whether the value of a `Host` field names a covered host. A value that cannot be read as a name and an
    /// optional port, or that is an IP literal, names none.
    pub fn covers_host(&self, host: Option<&[u8]>) -> bool {
        host_name(host).is_some_and(|name| self.covers(&name))
    }
}

/// The name that a `Host` value holds, without port and trailing dot, in lowercase.
pub fn host_name(host: Option<&[u8]>) -> Option<String> {
    let host = RequestHost::parse(host?)?;
    String::from_utf8(host.name().to_ascii_lowercase()).ok()
}

/// What is left of `name` after its first label, if that label is not empty.
fn one_label_below(name: &str) -> Option<&str> {
    let (label, rest) = name.split_once('.')?;
    (!label.is_empty()).then_some(rest)
}

/// The hosts of the certificates of one TLS listener, in the order of the configuration.
#[derive(Debug)]
pub struct Names {
    certificates: Vec<Arc<Hosts>>,
}

impl Names {
    pub fn new(certificates: &[CertificateConfig]) -> Names {
        Names {
            certificates: certificates
                .iter()
                .map(|certificate| Arc::new(Hosts::new(&certificate.hosts)))
                .collect(),
        }
    }

    /// The position of the certificate for `name`: the one that has it as a host, or else the one that has a
    /// wildcard host for it. A host is written once in a listener, so there is at most one of each.
    pub fn find(&self, name: &str) -> Option<usize> {
        let name = name.to_ascii_lowercase();
        self.certificates
            .iter()
            .position(|hosts| hosts.has_exact(&name))
            .or_else(|| {
                self.certificates
                    .iter()
                    .position(|hosts| hosts.has_wildcard(&name))
            })
    }

    /// The hosts of the certificate at `index`.
    pub fn hosts(&self, index: usize) -> Option<&Arc<Hosts>> {
        self.certificates.get(index)
    }
}
