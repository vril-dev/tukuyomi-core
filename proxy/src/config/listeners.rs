//! The `listeners` of the `proxy` object: where the proxy takes connections, and what each listener does with them.
//!
//! There are 1 to 8 listeners, in no order that matters. A listener is `{"address", "tls"?, "redirect"?}`: the
//! address is an IP literal and a port (`[..]:port` for IPv6, port 0 is refused). With neither key the listener is
//! plain: it speaks HTTP and the requests go to the upstream groups. With `tls` it ends TLS first and then does the
//! same. With `redirect` it answers every request it serves with a redirect to https, or 404, and forwards nothing.
//! The two keys exclude each other. At least one listener is plain or has `tls`, and a `redirect` needs a listener
//! with `tls` to point at. Two listeners may not have the same address, nor may one be an unspecified address
//! (`0.0.0.0`, `::`) at the port of another: the second bind would fail.
//!
//! `tls` is `{"min_version", "certificates"}`: `min_version` is `"1.2"` or `"1.3"`, and there are 1 to 16
//! certificates `{"cert_file", "key_file", "hosts"}`. Each file is an absolute clean path of at most 3840 bytes. A
//! certificate has 1 to 64 hosts, each a name (lowercase letters, digits, `-` and `.`, in labels of 1 to 63 bytes of
//! which the last starts with a letter, 253 bytes at most, so no IP literal) or `*.` and a name, which stands for any
//! one label in front of the name. A host is written once in a listener. The files are not read here: `inbound::tls`
//! reads them when the proxy starts. `redirect` is `{"https_port"}`, from 1 to 65535.

use std::net::SocketAddr;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use serde::Deserialize;

use super::forward::host_ok;
use super::{ConfigError, MAX_STORE_DIR, Object, address, clean_abs, ensure};

/// The most listeners.
const MAX_LISTENERS: usize = 8;
/// The most certificates of one TLS listener, and the most hosts of one certificate.
const MAX_CERTIFICATES: usize = 16;
const MAX_HOSTS: usize = 64;

/// One listener, checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListenerConfig {
    pub address: SocketAddr,
    pub kind: ListenerKind,
}

/// What a listener does with the connections it takes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ListenerKind {
    /// HTTP; the requests go to the upstream groups.
    Plain,
    /// TLS is ended here; the requests go to the upstream groups.
    Tls(TlsConfig),
    /// Every request is answered with a redirect to https at this port, or with 404.
    Redirect { https_port: u16 },
}

/// The `tls` object of a listener.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsConfig {
    pub min_version: MinVersion,
    pub certificates: Vec<CertificateConfig>,
}

/// The oldest TLS version a listener speaks. TLS 1.3 is always spoken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MinVersion {
    Tls12,
    Tls13,
}

/// A certificate chain file, its private key file, and the hosts that the certificate serves, in the form the file
/// writes them: a lowercase name, or `*.` and a name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateConfig {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    pub hosts: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawListener {
    address: String,
    #[serde(default, deserialize_with = "super::present")]
    tls: Option<Object<RawTls>>,
    #[serde(default, deserialize_with = "super::present")]
    redirect: Option<Object<RawRedirect>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTls {
    min_version: String,
    certificates: Vec<Object<RawCertificate>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCertificate {
    cert_file: String,
    key_file: String,
    hosts: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRedirect {
    https_port: u64,
}

/// The addresses of the listeners, in order.
pub fn addresses(listeners: &[ListenerConfig]) -> Vec<SocketAddr> {
    listeners.iter().map(|listener| listener.address).collect()
}

/// Whether a bind at `b` fails when `a` is bound: the same port, and the same address or one of them unspecified.
fn clash(a: SocketAddr, b: SocketAddr) -> bool {
    let (x, y) = (a.ip().to_canonical(), b.ip().to_canonical());
    a.port() == b.port() && (x == y || x.is_unspecified() || y.is_unspecified())
}

/// A path of a certificate or key file.
fn file(text: String) -> Result<PathBuf, ConfigError> {
    let path = PathBuf::from(text);
    ensure(
        clean_abs(&path) && path.as_os_str().as_bytes().len() <= MAX_STORE_DIR,
        "a tls cert_file or key_file is not an absolute clean path of at most 3840 bytes",
    )?;
    Ok(path)
}

/// A host: a name, or `*.` and a name. The name has the form of a server name, without `_`.
fn host_ok_for_tls(host: &str) -> bool {
    let name = host.strip_prefix("*.").unwrap_or(host);
    host_ok(name) && !name.contains('_')
}

fn tls(raw: RawTls) -> Result<TlsConfig, ConfigError> {
    let min_version = match raw.min_version.as_str() {
        "1.2" => MinVersion::Tls12,
        "1.3" => MinVersion::Tls13,
        _ => return Err(ConfigError("tls min_version is not 1.2 or 1.3")),
    };
    ensure(
        (1..=MAX_CERTIFICATES).contains(&raw.certificates.len()),
        "tls has no certificate or more than 16",
    )?;
    let mut certificates: Vec<CertificateConfig> = Vec::with_capacity(raw.certificates.len());
    for Object(raw) in raw.certificates {
        ensure(
            (1..=MAX_HOSTS).contains(&raw.hosts.len()),
            "a certificate has no host or more than 64",
        )?;
        for host in &raw.hosts {
            ensure(
                host_ok_for_tls(host),
                "a tls host is not a name, or * and a name",
            )?;
        }
        certificates.push(CertificateConfig {
            cert_file: file(raw.cert_file)?,
            key_file: file(raw.key_file)?,
            hosts: raw.hosts,
        });
    }
    let mut seen: Vec<&String> = certificates.iter().flat_map(|c| &c.hosts).collect();
    seen.sort();
    ensure(
        seen.windows(2).all(|pair| pair[0] != pair[1]),
        "a tls host is written twice in a listener",
    )?;
    Ok(TlsConfig {
        min_version,
        certificates,
    })
}

fn listener(raw: RawListener) -> Result<ListenerConfig, ConfigError> {
    let address = address(
        &raw.address,
        "a listener address is not an IP address and port",
        "a listener port is 0",
    )?;
    let kind = match (raw.tls, raw.redirect) {
        (Some(_), Some(_)) => return Err(ConfigError("a listener has both tls and redirect")),
        (Some(Object(raw)), None) => ListenerKind::Tls(tls(raw)?),
        (None, Some(Object(raw))) => {
            ensure(
                (1..=65535).contains(&raw.https_port),
                "a redirect https_port is not 1 to 65535",
            )?;
            ListenerKind::Redirect {
                https_port: u16::try_from(raw.https_port).unwrap_or(u16::MAX),
            }
        }
        (None, None) => ListenerKind::Plain,
    };
    Ok(ListenerConfig { address, kind })
}

/// Checks the `listeners` array.
pub(super) fn check(raw: Vec<Object<RawListener>>) -> Result<Vec<ListenerConfig>, ConfigError> {
    ensure(
        (1..=MAX_LISTENERS).contains(&raw.len()),
        "listeners has no listener or more than 8",
    )?;
    let listeners = raw
        .into_iter()
        .map(|Object(raw)| listener(raw))
        .collect::<Result<Vec<_>, _>>()?;
    for (at, first) in listeners.iter().enumerate() {
        ensure(
            listeners[at + 1..]
                .iter()
                .all(|second| !clash(first.address, second.address)),
            "two listeners have the same address, or one is an unspecified address at the port of the other",
        )?;
    }
    ensure(
        listeners
            .iter()
            .any(|l| matches!(l.kind, ListenerKind::Plain | ListenerKind::Tls(_))),
        "no listener is plain or has tls",
    )?;
    ensure(
        listeners
            .iter()
            .all(|l| !matches!(l.kind, ListenerKind::Redirect { .. }))
            || listeners
                .iter()
                .any(|l| matches!(l.kind, ListenerKind::Tls(_))),
        "a redirect listener needs a listener with tls",
    )?;
    Ok(listeners)
}
