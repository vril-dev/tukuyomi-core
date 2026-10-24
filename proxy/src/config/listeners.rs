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
//! one label in front of the name. A host is written once in a listener. The files are not read here:
//! `inbound::transport::tls` reads them when the proxy starts. `tls` may also have `http2`, an object that turns
//! HTTP/2 on for the listener and has five keys, all of them required: `max_streams` (1 to 256, the streams a client
//! may have open at once), `stream_window` (65535 to 1 MiB, the receive window of a stream), `connection_window`
//! (65535 to 4 MiB, the receive window of the connection), `max_header_list` (1 KiB to four times `max_head_bytes`,
//! the size of the fields of a request once they are decoded) and `send_buffer` (1 KiB to 1 MiB, the bytes of a
//! response that wait to be sent, for each stream). What a connection can hold in these, that is
//! `connection_window` and `max_streams` times `send_buffer` plus 32 KiB, is at most 16 MiB. Each open stream can also
//! hold the fields of its request (up to `max_header_list`) and one chunk of its response as large as the proxy reads
//! from an upstream at once (`upstream_max_head_bytes`), and with them the total is at most 16 MiB too (checked with
//! the values of `proxy`). The windows and the
//! buffers are not part of `max_buffered_bytes`, and every connection can hold that much: with `max_conns`
//! connections the proxy can hold `max_conns` times as much. `redirect` is `{"https_port"}`, from 1 to 65535.

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
/// The bounds of the keys of `http2`.
const MAX_STREAMS: u64 = 256;
const WINDOW_LOW: u64 = 65535;
const STREAM_WINDOW_HIGH: u64 = 1 << 20;
const CONNECTION_WINDOW_HIGH: u64 = 4 << 20;
const HEADER_LIST_LOW: u64 = 1024;
/// The most `max_header_list` is, in units of `max_head_bytes`.
const HEADER_LIST_TIMES: usize = 4;
const SEND_BUFFER_LOW: u64 = 1024;
const SEND_BUFFER_HIGH: u64 = 1 << 20;
/// What each open stream holds besides its send buffer: its data in the frame that is being written, and the like.
const STREAM_OVERHEAD: u64 = 32 * 1024;
/// The most that the windows and the buffers of a connection may hold.
const HTTP2_HOLD_HIGH: u64 = 16 << 20;

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
    /// HTTP/2 is spoken on the listener, with these settings; without them only HTTP/1.1 is.
    pub http2: Option<Http2Config>,
}

/// The `http2` object of a TLS listener.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Http2Config {
    /// The streams that a client may have open at once.
    pub max_streams: u32,
    /// The receive window of a stream, and of the connection, in bytes.
    pub stream_window: u32,
    pub connection_window: u32,
    /// The size of the fields of a request once they are decoded, in bytes.
    pub max_header_list: u32,
    /// The bytes of a response that wait to be sent, for each stream.
    pub send_buffer: usize,
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
    #[serde(default, deserialize_with = "super::present")]
    http2: Option<Object<RawHttp2>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHttp2 {
    max_streams: u64,
    stream_window: u64,
    connection_window: u64,
    max_header_list: u64,
    send_buffer: u64,
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

/// The `http2` object. `max_header_list` is checked against `max_head_bytes` by `header_lists_fit`, once that is
/// known to be in range.
fn http2(raw: RawHttp2) -> Result<Http2Config, ConfigError> {
    let within = |value: u64, low: u64, high: u64| (low..=high).contains(&value);
    ensure(
        within(raw.max_streams, 1, MAX_STREAMS),
        "http2 max_streams is not 1 to 256",
    )?;
    ensure(
        within(raw.stream_window, WINDOW_LOW, STREAM_WINDOW_HIGH),
        "http2 stream_window is not 65535 to 1 MiB",
    )?;
    ensure(
        within(raw.connection_window, WINDOW_LOW, CONNECTION_WINDOW_HIGH),
        "http2 connection_window is not 65535 to 4 MiB",
    )?;
    ensure(
        raw.max_header_list >= HEADER_LIST_LOW,
        "http2 max_header_list is below 1 KiB",
    )?;
    ensure(
        within(raw.send_buffer, SEND_BUFFER_LOW, SEND_BUFFER_HIGH),
        "http2 send_buffer is not 1 KiB to 1 MiB",
    )?;
    let hold = raw
        .send_buffer
        .checked_add(STREAM_OVERHEAD)
        .and_then(|per_stream| per_stream.checked_mul(raw.max_streams))
        .and_then(|streams| streams.checked_add(raw.connection_window));
    ensure(
        hold.is_some_and(|hold| hold <= HTTP2_HOLD_HIGH),
        "http2 windows and buffers can hold more than 16 MiB",
    )?;
    let too_big = ConfigError("http2 max_header_list is above four times max_head_bytes");
    Ok(Http2Config {
        max_streams: u32::try_from(raw.max_streams).map_err(|_| too_big)?,
        stream_window: u32::try_from(raw.stream_window).map_err(|_| too_big)?,
        connection_window: u32::try_from(raw.connection_window).map_err(|_| too_big)?,
        max_header_list: u32::try_from(raw.max_header_list).map_err(|_| too_big)?,
        send_buffer: usize::try_from(raw.send_buffer).map_err(|_| too_big)?,
    })
}

/// Whether the `max_header_list` of every listener that has one is at most four times `max_head_bytes`.
pub(super) fn header_lists_fit(listeners: &[ListenerConfig], max_head_bytes: usize) -> bool {
    let Some(high) = max_head_bytes.checked_mul(HEADER_LIST_TIMES) else {
        return false;
    };
    listeners.iter().all(|listener| match &listener.kind {
        ListenerKind::Tls(TlsConfig {
            http2: Some(http2), ..
        }) => usize::try_from(http2.max_header_list).is_ok_and(|list| list <= high),
        _ => true,
    })
}

/// Whether what each listener with `http2` can hold stays at most 16 MiB when every open stream also holds the fields
/// of its request and one chunk of its response as large as an upstream read (`upstream_max_head_bytes`, at least
/// 8 KiB, the size the connections to the upstreams read at once).
pub(super) fn holds_fit(listeners: &[ListenerConfig], upstream_max_head_bytes: usize) -> bool {
    let Ok(chunk) = u64::try_from(upstream_max_head_bytes.max(8192)) else {
        return false;
    };
    listeners.iter().all(|listener| match &listener.kind {
        ListenerKind::Tls(TlsConfig {
            http2: Some(http2), ..
        }) => u64::try_from(http2.send_buffer)
            .ok()
            .and_then(|buffer| buffer.checked_add(STREAM_OVERHEAD))
            .and_then(|stream| stream.checked_add(chunk))
            .and_then(|stream| stream.checked_add(u64::from(http2.max_header_list)))
            .and_then(|stream| stream.checked_mul(u64::from(http2.max_streams)))
            .and_then(|streams| streams.checked_add(u64::from(http2.connection_window)))
            .is_some_and(|hold| hold <= HTTP2_HOLD_HIGH),
        _ => true,
    })
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
        http2: raw.http2.map(|Object(raw)| http2(raw)).transpose()?,
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

#[cfg(test)]
mod tests;
