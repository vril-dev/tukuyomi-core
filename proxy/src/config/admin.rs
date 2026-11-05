//! The `admin` object of the configuration: the settings of the admin process, which reads this file as well. The
//! proxy uses two of the keys, `listen` (the address the admin process answers on, which no listener of the proxy
//! may have) and `control` (the socket on which the proxy takes orders from it, see `run::control`); the others it
//! only checks, so that the proxy and the admin process accept or refuse one file together.
//!
//! The object may be left out, and then there is no admin process and no control socket. When it is there it has
//! these keys, all required but the last: `listen` (an IP literal and a port, `[..]:port` for IPv6, port 0 refused;
//! only a loopback address, `127.0.0.0/8` or `::1`, is accepted), `control` (an absolute clean path of at most 107
//! bytes, which a socket address holds), `store` (`{"kind": "file", "dir": ..}`, the directory an absolute clean path
//! of at most 3840 bytes), `origin` (`https://` and a host and an optional port as the host of a route is written,
//! without a wildcard, a path, a query or a trailing `/`), `trusted_proxies` (as the key of the `proxy` object, with
//! its own limit of 256 entries), `mfa` (`optional` or `required`), `session_idle_ms` (1 minute to 24 hours),
//! `session_total_ms` (from `session_idle_ms` to 7 days) and `crs_dir` (may be left out; an absolute clean path of at
//! most 3840 bytes).
//!
//! `listen` may not clash with the address of a listener or of the status listener (the rule for two listeners: the
//! second bind would fail). A server of an upstream may be at `listen`, unlike at the address of a listener or of
//! the status listener: the proxy reaches the admin process by a route to it, which is meant to be the way in.
//!
//! A file with `managed` writes that way in the object itself, and only such a file: `route`, which it then must have,
//! is `{"host", "certificate": {"cert_file", "key_file"}, "access"}`. `host` is one name as a host of a certificate of
//! a listener is written, without `*.`; the certificate is checked and read as the certificate of a listener with that
//! one host is; `access` is written as the `access` of a route is (see `rewrite`) and has `allow_cidrs`, which is not
//! empty, so that the way to the admin process is never open to every address. The proxy makes the route itself (see
//! `forward::group`): a request whose `Host` is the host goes to `listen`, over a connection of that certificate, and
//! the `access` and `rate_limit` of the configuration do not apply to it. `route` is the proxy's alone: it is not one
//! of the values the admin process takes, and a reading of the file again may change it.

use std::net::SocketAddr;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

use super::listeners::{self, clash, host_ok_for_tls};
use super::rewrite::{self, RawAccess};
use super::{
    CertificateConfig, ConfigError, ListenerConfig, MAX_STORE_DIR, Object, RawStore, StatusConfig,
    address, clean_abs, ensure, networks,
};
use crate::forward::client_ip::{Access, Cidr};
use crate::route::Rule;

/// The longest `control` in bytes: the path of a socket address, without its end byte, fits `sun_path`.
const MAX_CONTROL: usize = 107;
const MIN_IDLE_MS: u64 = 60_000;
const MAX_IDLE_MS: u64 = 86_400_000;
const MAX_TOTAL_MS: u64 = 7 * 86_400_000;

/// Whether a user needs a second factor to log in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mfa {
    Optional,
    Required,
}

/// Where the admin process keeps its state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdminStoreConfig {
    File { dir: PathBuf },
}

/// The `admin` object, checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminConfig {
    pub listen: SocketAddr,
    pub control: PathBuf,
    pub store: AdminStoreConfig,
    pub origin: String,
    pub trusted_proxies: Vec<Cidr>,
    pub mfa: Mfa,
    pub session_idle: Duration,
    pub session_total: Duration,
    pub crs_dir: Option<PathBuf>,
}

/// The `route` of the `admin` object, checked: the way to the admin process of a file with `managed`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminRoute {
    /// A lowercase name.
    pub host: String,
    /// Its `hosts` are `[host]`, and it has no `acme`.
    pub certificate: CertificateConfig,
    pub access: Access,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawAdmin {
    listen: String,
    control: String,
    store: Object<RawStore>,
    origin: String,
    trusted_proxies: Vec<String>,
    mfa: String,
    session_idle_ms: u64,
    session_total_ms: u64,
    #[serde(default, deserialize_with = "super::present")]
    crs_dir: Option<String>,
    #[serde(default, deserialize_with = "super::present")]
    route: Option<Object<RawRoute>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRoute {
    host: String,
    certificate: Object<RawCertificate>,
    access: Object<RawAccess>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCertificate {
    cert_file: String,
    key_file: String,
}

/// A path of at most `longest` bytes that is absolute and clean.
fn path(text: String, longest: usize, bad: &'static str) -> Result<PathBuf, ConfigError> {
    let path = PathBuf::from(text);
    ensure(
        clean_abs(&path) && path.as_os_str().as_bytes().len() <= longest,
        bad,
    )?;
    Ok(path)
}

/// `https://` and a host with an optional port, as the host of a route is written: a name of lowercase letters,
/// digits, `-` and `.`, and no wildcard.
fn origin_ok(text: &str) -> bool {
    text.strip_prefix("https://")
        .is_some_and(|host| !host.starts_with('*') && Rule::forward(Some(host), None).is_ok())
}

/// Checks the object against the listeners and the status listener. `managed` tells that the file has `managed`.
pub(super) fn check(
    raw: Option<Object<RawAdmin>>,
    listeners: &[ListenerConfig],
    status: Option<StatusConfig>,
    managed: bool,
) -> Result<(Option<AdminConfig>, Option<AdminRoute>), ConfigError> {
    let Some(Object(raw)) = raw else {
        return Ok((None, None));
    };
    let listen = address(
        &raw.listen,
        "admin listen is not an IP address and port",
        "admin listen port is 0",
    )?;
    ensure(
        listen.ip().is_loopback(),
        "admin listen is not a loopback address",
    )?;
    ensure(
        listeners
            .iter()
            .map(|listener| listener.address)
            .chain(status.map(|status| status.listen))
            .all(|bound| !clash(bound, listen)),
        "admin listen is the address of a listener or of the status listener, or one is an unspecified address at the port of the other",
    )?;
    let control = path(
        raw.control,
        MAX_CONTROL,
        "admin control is not an absolute clean path of at most 107 bytes",
    )?;
    let Object(store) = raw.store;
    ensure(store.kind == "file", "admin store kind is not supported")?;
    let dir = path(
        store.dir,
        MAX_STORE_DIR,
        "admin store dir is not an absolute clean path of at most 3840 bytes",
    )?;
    ensure(
        origin_ok(&raw.origin),
        "admin origin is not https:// and a host with an optional port",
    )?;
    let trusted_proxies = networks(
        &raw.trusted_proxies,
        "admin trusted_proxies has more than 256 entries",
        "admin trusted_proxies has an entry that is not a network",
    )?;
    let mfa = match raw.mfa.as_str() {
        "optional" => Mfa::Optional,
        "required" => Mfa::Required,
        _ => return Err(ConfigError("admin mfa is not optional or required")),
    };
    ensure(
        (MIN_IDLE_MS..=MAX_IDLE_MS).contains(&raw.session_idle_ms),
        "admin session_idle_ms is not 1 minute to 24 hours",
    )?;
    ensure(
        (raw.session_idle_ms..=MAX_TOTAL_MS).contains(&raw.session_total_ms),
        "admin session_total_ms is not session_idle_ms to 7 days",
    )?;
    let crs_dir = raw
        .crs_dir
        .map(|text| {
            path(
                text,
                MAX_STORE_DIR,
                "admin crs_dir is not an absolute clean path of at most 3840 bytes",
            )
        })
        .transpose()?;
    let route = match (raw.route, managed) {
        (Some(Object(raw)), true) => Some(route(raw)?),
        (None, false) => None,
        (Some(_), false) => {
            return Err(ConfigError(
                "admin route is only for a configuration with managed",
            ));
        }
        (None, true) => {
            return Err(ConfigError(
                "admin has no route while the configuration has managed",
            ));
        }
    };
    let admin = AdminConfig {
        listen,
        control,
        store: AdminStoreConfig::File { dir },
        origin: raw.origin,
        trusted_proxies,
        mfa,
        session_idle: Duration::from_millis(raw.session_idle_ms),
        session_total: Duration::from_millis(raw.session_total_ms),
        crs_dir,
    };
    Ok((Some(admin), route))
}

/// The `route` of the object.
fn route(raw: RawRoute) -> Result<AdminRoute, ConfigError> {
    ensure(
        !raw.host.starts_with("*.") && host_ok_for_tls(&raw.host),
        "admin route host is not a name",
    )?;
    let Object(files) = raw.certificate;
    let certificate = CertificateConfig {
        cert_file: listeners::file(files.cert_file)?,
        key_file: listeners::file(files.key_file)?,
        hosts: vec![raw.host.clone()],
        acme: None,
    };
    let access = rewrite::access(Some(raw.access))?;
    ensure(
        access.has_allowed_networks(),
        "admin route access has no allow_cidrs",
    )?;
    Ok(AdminRoute {
        host: raw.host,
        certificate,
        access,
    })
}
