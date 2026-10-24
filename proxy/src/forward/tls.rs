//! TLS to the servers of an upstream group.
//!
//! A group may have `tls`, `{"ca_file", "server_name"?}` (see `config`). Every server of such a group is reached
//! over TLS, and the certificate of the server is always checked: there is no way to turn that off. The only roots
//! of trust are the certificates of `ca_file`, a regular file of at most 1 MiB that holds 1 to 100 certificates in
//! PEM, each of which must be usable as a trust anchor. The file is read once, when the proxy starts (see
//! `resolve`), and never again. A server is checked for `server_name` if the group has one, else for the name it is
//! written with, else, if it is written as an IP literal, for that address. The name is also what the server is told
//! to be reached by (the server name of TLS), unless it is an address. TLS 1.2 and 1.3 are spoken, `http/1.1` is the
//! only protocol of ALPN, no certificate is sent, and the resuming of sessions is what rustls does by default: the
//! servers of a group share one configuration and so their sessions.
//!
//! The settings are made into a `Client` when the names of the servers are looked up: the configuration of TLS, and
//! the name of each server in the order of the group. The handshake belongs to the server (`Secure`); the caller
//! bounds its time.

use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::crypto::aws_lc_rs::default_provider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, DnsName, ServerName};
use rustls::{ClientConfig, RootCertStore, version};
use tokio::net::TcpStream;
use tokio_rustls::{Connect, TlsConnector};

use crate::config::Address;
use crate::rules::file_store::{O_NOCTTY, O_NONBLOCK};

/// The longest file of authorities in bytes.
const MAX_FILE: u64 = 1 << 20;
/// The most certificates in a file of authorities.
const MAX_CERTIFICATES: usize = 100;
const ALPN: &[u8] = b"http/1.1";

/// The `tls` of a group, as the configuration writes it: the file of the authorities, and the name to check the
/// servers for if it is not the name of each.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    pub ca_file: PathBuf,
    pub server_name: Option<String>,
}

/// Why the TLS of a group could not be made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// The file is missing, not a regular file, or cannot be read.
    Unreadable,
    TooLarge,
    NotCertificates,
    /// A certificate of the file cannot be a trust anchor.
    NotAnchor,
    /// A name that a server is checked for is not a name that TLS can use.
    Name,
    /// The settings cannot be made into a TLS configuration.
    Build,
}

impl Fault {
    /// A fixed sentence: it names no file and no value from a file.
    pub fn text(self) -> &'static str {
        match self {
            Fault::Unreadable => "an upstream ca_file cannot be read",
            Fault::TooLarge => "an upstream ca_file is over 1 MiB",
            Fault::NotCertificates => {
                "an upstream ca_file does not hold 1 to 100 certificates in PEM"
            }
            Fault::NotAnchor => {
                "an upstream ca_file has a certificate that cannot be a trust anchor"
            }
            Fault::Name => {
                "a name that a server of an upstream with tls is checked for cannot be used"
            }
            Fault::Build => "the TLS settings of an upstream cannot be made",
        }
    }
}

/// A whole file, which is at most `MAX_FILE` bytes.
fn read(path: &Path) -> Result<Vec<u8>, Fault> {
    // O_NONBLOCK: opening a FIFO must not wait for a writer; the check of the file type below then refuses it. It
    // does not affect reads of a regular file. O_NOCTTY: a terminal that is opened before that check is never made
    // the controlling terminal of the process. A link is followed (there is no O_NOFOLLOW): the path of a file of
    // authorities is often a link. The type and the size are those of the file that was opened, so a path that is
    // changed after the open does not change what is read.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK | O_NOCTTY)
        .open(path)
        .map_err(|_| Fault::Unreadable)?;
    let meta = file.metadata().map_err(|_| Fault::Unreadable)?;
    if !meta.is_file() {
        return Err(Fault::Unreadable);
    }
    if meta.len() > MAX_FILE {
        return Err(Fault::TooLarge);
    }
    // Room for the byte that shows the end, so that the bytes already read are not moved to a new place.
    let room = usize::try_from(meta.len()).map_or(0, |n| n.saturating_add(1));
    let mut bytes = Vec::with_capacity(room);
    file.take(MAX_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Fault::Unreadable)?;
    if u64::try_from(bytes.len()).is_ok_and(|n| n > MAX_FILE) {
        return Err(Fault::TooLarge);
    }
    Ok(bytes)
}

/// The authorities of the file at `path`.
fn roots(path: &Path) -> Result<RootCertStore, Fault> {
    let bytes = read(path)?;
    let chain = CertificateDer::pem_slice_iter(&bytes)
        .take(MAX_CERTIFICATES + 1)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Fault::NotCertificates)?;
    if chain.is_empty() || chain.len() > MAX_CERTIFICATES {
        return Err(Fault::NotCertificates);
    }
    let mut roots = RootCertStore::empty();
    for certificate in chain {
        roots.add(certificate).map_err(|_| Fault::NotAnchor)?;
    }
    Ok(roots)
}

/// The configuration of TLS that the servers of a group share: the authorities of `settings`, versions 1.3 and 1.2,
/// ALPN `http/1.1`, no certificate of our own. Reads the file.
pub fn config(settings: &Settings) -> Result<Arc<ClientConfig>, Fault> {
    let roots = roots(&settings.ca_file)?;
    let mut config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&version::TLS13, &version::TLS12])
        .map_err(|_| Fault::Build)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok(Arc::new(config))
}

/// `text` as a name that a server is checked for, or `None` if TLS cannot use it (a label that starts or ends with
/// `-`, for one).
pub fn dns_name(text: &str) -> Option<ServerName<'static>> {
    DnsName::try_from(text.to_owned())
        .ok()
        .map(ServerName::DnsName)
}

/// What a server written as `address` is checked for: the `server_name` of `settings`, else its own name, else, for
/// an IP literal, the address (a mapped IPv4 address as the IPv4 address). `None` if the name cannot be used.
pub fn name_of(settings: &Settings, address: &Address) -> Option<ServerName<'static>> {
    match (&settings.server_name, address) {
        (Some(name), _) | (None, Address::Name { name, .. }) => dns_name(name),
        (None, Address::Literal(literal)) => {
            Some(ServerName::IpAddress(literal.ip().to_canonical().into()))
        }
    }
}

/// The TLS of a group once its names are looked up: the configuration its servers share, and the name each of them
/// is checked for, one for each server and in the order of the group.
#[derive(Clone, Debug)]
pub struct Client {
    config: Arc<ClientConfig>,
    names: Vec<ServerName<'static>>,
}

impl Client {
    /// `names` has one entry for each server of the group.
    pub fn new(config: Arc<ClientConfig>, names: Vec<ServerName<'static>>) -> Client {
        Client { config, names }
    }

    /// The name each server is checked for.
    #[cfg(test)]
    pub(super) fn names(&self) -> &[ServerName<'static>] {
        &self.names
    }

    /// The way to the server at `index` of the group.
    pub(super) fn secure(&self, index: usize) -> Secure {
        Secure {
            connector: TlsConnector::from(self.config.clone()),
            name: self.names[index].clone(),
        }
    }
}

/// How to speak TLS to one server: the handshake, which checks the certificate of the server for its name.
#[derive(Clone)]
pub(super) struct Secure {
    connector: TlsConnector,
    name: ServerName<'static>,
}

impl Secure {
    /// The handshake on `stream`.
    pub(super) fn handshake(&self, stream: TcpStream) -> Connect<TcpStream> {
        self.connector.connect(self.name.clone(), stream)
    }
}

#[cfg(test)]
pub(super) mod tests;
