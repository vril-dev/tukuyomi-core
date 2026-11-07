//! The configuration file: one JSON object `{"proxy": {..}, "forward": {..}, "kernel": {..}, "rules": {"store":
//! {..}}, "acme": {..}, "status": {..}, "records": {..}, "access": {..}, "rate_limit": {..}, "geo": {..}, "admin":
//! {..}, "managed": {..}}`; every value is chosen by the operator and checked here.
//!
//! The file is read whole (at most 256 KiB, UTF-8) and deserialized into plain structs; the result keeps the
//! SHA-256 of the bytes that were read. Every key must be present (a route may leave out its `host`, its `path`,
//! its `access`, its `rewrite`, its `stream` and its `max_body`; `access` and `rewrite` have no key that must be
//! present, see `rewrite`, and a `stream` has all three; an upstream group may leave out its
//! `tls`, which may leave out its `server_name`; a listener may leave out its `tls` and its `redirect`, and the `tls`
//! of a listener may leave out its `http2`, and a certificate of a listener may leave out its `acme`; the file
//! may leave out `acme`, which it must have when a certificate has one, see `acme`, and `status`, which
//! has the one key `listen`, see `status`, and `records`, `access`, `rate_limit`, `geo` and `admin`, see their files
//! (`access`, `rate_limit` and `geo` are in `policy`); an unknown or repeated
//! key is refused, and so is a value of the wrong
//! type, an array in place of an object and `null` for a key that may be left out included (such a key is either left
//! out or has a value). A refusal is one fixed sentence per kind of fault and never carries a key or a value from the
//! file. Then the values are checked in a fixed order and the first broken rule is returned: the `proxy` bounds, the
//! `status` object against the listeners (before `forward`, for no server may be at its address), the `forward`
//! values (see `forward`; the names of the servers are not looked up here, `forward::resolve` does that when the proxy
//! starts), the `rules.store` values, the `records` object (and that the `records` of the routes suit it), the
//! `access`, `rate_limit` and `geo` objects (see `policy`) and that `geo` is there if a list of countries is, the
//! `admin` object against the listeners and the status listener, the `acme` object with the certificates that have
//! `acme` (that of `admin.route` included), the directories, the control socket and the files of `acme` against each
//! other (see `places`), the conversion of the `kernel` object into `tukuyomi_kernel::Config` with that type's
//! own check, and last the relations between the `proxy` and `kernel` objects.
//!
//! `managed` may be left out. When it is there it is `{"dir"}`, the directory of the managed store (see `managed`),
//! an absolute clean path of at most 3840 bytes, and the file does not write how the proxy routes: `forward` has
//! `resolve_timeout_ms` only, the `tls` of a listener has no `certificates`, and the file has no `access` and no
//! `rate_limit`. The upstream groups, the routes, the default group, the `access`, the `rate_limit` and the sites with
//! their certificates come from a version of the store, which is checked after the values of this file and against
//! them, by the same rules and with the same sentences (see `managed::version`). Its `admin`, if it has one, writes
//! the way to the admin process (`admin.route`, see `admin`). A file without `managed` is read as it always was.
//!
//! There are two readings of the file. `load` reads the whole configuration, which the proxy serves with: the file,
//! with `managed` the version that the store chooses and the files it names (see `managed::load`), and the country
//! database. `load_main` reads the file alone and gives a `MainFile`, which has no routing: the readers that serve no
//! request use it (the shipper, the commands `rules`, `admin bootstrap` and `admin reset`, and the admin process). A
//! file without `managed` gets the same checks from both, but `load_main` does not read the country database.
//!
//! `max_body` (1 KiB to 4 GiB) is the most bytes a request body may have once decoded (a gzip body under a route
//! that skips the inspection is not decoded, so the limit counts its coded bytes), and `inspect_body` (1 KiB up to
//! the body limit of the kernel, 1 MiB, and not above `max_body`) is how many of its first bytes are inspected: a
//! longer body is passed on without being inspected behind those bytes. `max_body_wire` runs from `max_body` to twice
//! `max_body` and 4 MiB, for the framing of a chunked body is on the wire too, and `max_buffered_bytes` from twice
//! `inspect_body`, the most bytes of the fields of a request and the piece that a request holds while the rest of its
//! body is passed on (`STREAM_HOLD`, 32 KiB), up to 4 GiB: that is what one request whose body goes on past the
//! inspected bytes holds at most. Every request that is under way at once holds its share, so the budget is to be
//! sized for the most of them that are expected. The budget does not count the buffer of the connection to the
//! upstream, which is sized by `upstream_max_head_bytes` and holds bytes of a body that goes on as well: that is up
//! to `upstream_max_head_bytes` more for each request under way whose body goes on, whatever the length of the body.
//!
//! Times are whole milliseconds under keys that end in `_ms`; the `proxy` times run from 1 ms to 3600 s, except
//! `keepalive_timeout_ms`, which also takes 0 (a connection is not kept after its response), and `conn_total_ms`,
//! which runs up to 24 h.
//! `trusted_proxies` is a list of networks, `address/prefix` in the form `Cidr::parse` takes, and may be empty.
//! `listeners` is a list of 1 to 8 listeners (see `listeners`). `rules.store.kind` is `file`, the
//! only kind there is, and `dir` is an absolute clean path of at most 3840 bytes. The `kernel` object has no
//! rules path and no rules fingerprint: the directory and the fingerprint of the chosen generation come from the
//! rules store when the proxy starts (`KernelSettings::for_generation`). Its `inspector` is the one of the engine
//! Coraza; the inspectors of the other engines are in its `engines` object, which may be left out (see `kernel`).

use std::fmt;
use std::fs::{self, File};
use std::io::Read;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use serde::de::value::MapAccessDeserializer;
use serde::de::{Deserializer, MapAccess, Visitor};
use serde_json::error::Category;
use tukuyomi_kernel::limits::{BODY, HEADER_TOTAL};

use crate::forward::client_ip::Cidr;
use crate::managed::{self, Choice, Version};
use crate::rules::bundle::sha256;

mod acme;
mod admin;
mod forward;
mod kernel;
mod listeners;
mod places;
mod policy;
mod records;
mod rewrite;
mod status;

pub use acme::AcmeConfig;
pub use admin::{AdminConfig, AdminRoute, AdminStoreConfig, Mfa};
pub use forward::{
    Address, AdminWay, ForwardConfig, ForwardSettings, GroupConfig, RouteConfig, ServerConfig,
    Stream,
};
pub(crate) use forward::{Groups, MAX_SERVERS, RawRoute, RawTls, StoredTls, name_ok, routing};
pub use kernel::KernelSettings;
pub use listeners::{
    CertificateAcme, CertificateConfig, Http2Config, ListenerConfig, ListenerKind, MinVersion,
    TlsConfig, addresses,
};
pub(crate) use listeners::{RawCertificateAcme, certificate_acme, host_ok_for_tls};
pub use policy::{GeoConfig, PolicyConfig, RateLimitConfig};
pub(crate) use policy::{RawRateLimit, routed};
pub use records::{Driver, Keep, Records, RouteKeep, Ship};
pub(crate) use records::{MAX_RECORD_FILES, consistent};
pub(crate) use rewrite::RawAccess;
pub use status::StatusConfig;

const MAX_FILE: u64 = 256 * 1024;
/// Longest accepted `rules.store.dir` in bytes: the paths below it must stay inside the Linux `PATH_MAX`. A guard
/// against a wrong setting, not a recommendation.
const MAX_STORE_DIR: usize = 3840;
pub(crate) const MAX_MS: u64 = 3_600_000;
/// The longest `conn_total_ms`: the connection time has room for `keepalive_time_ms` and one request after it.
const MAX_CONN_MS: u64 = 86_400_000;
/// The most networks in `trusted_proxies`.
const MAX_TRUSTED: usize = 256;
const KIB: u64 = 1 << 10;
const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;

/// The share of the byte budget that a request holds while the rest of its body is passed on: one piece of it as it
/// is handed from the client to the upstream. A piece is no longer than the read buffer of the connection, which
/// is at most 32 KiB (`max_head_bytes` is no more than that).
pub(crate) const STREAM_HOLD: usize = 32 * 1024;

/// The HTTP side of the configuration. No `Default`: every value comes from the file.
#[derive(Clone, Debug)]
pub struct ProxyConfig {
    pub listeners: Vec<ListenerConfig>,
    pub max_conns: usize,
    pub max_head_bytes: usize,
    /// The most bytes a request body may have, once decoded. A longer one is refused with 413. A gzip body under a
    /// route that skips the inspection is not decoded, and counts as it is sent.
    pub max_body: usize,
    /// The first bytes of a request body that are inspected. The bytes behind them are passed on without being
    /// inspected.
    pub inspect_body: usize,
    pub max_body_wire: usize,
    pub max_buffered_bytes: usize,
    pub upstream_max_headers: usize,
    pub upstream_max_head_bytes: usize,
    pub upstream_head_wire: usize,
    /// How long the driver steps the kernel in one round. It takes in new requests between the rounds, so this is
    /// the longest a new request waits for it while others are in flight.
    pub drive_slice: Duration,
    pub ready_wait: Duration,
    pub head_read: Duration,
    pub body_read: Duration,
    pub inspect_wait: Duration,
    pub upstream_connect: Duration,
    pub upstream_header: Duration,
    pub request_total: Duration,
    pub response_idle: Duration,
    pub conn_total: Duration,
    pub stop_inspect: Duration,
    pub stop_wait: Duration,
    /// How long a connection waits for its next request after a response. Zero: the connection closes after
    /// every response.
    pub keepalive_timeout: Duration,
    /// The most requests one connection serves. The answer to the last one closes it.
    pub keepalive_requests: usize,
    /// How long a connection may be kept, counted from the accept. A request that is answered after this time
    /// gets the last answer of the connection. A request that starts before it gets its answer or the head of
    /// the upstream's response before `conn_total`; a response body that streams longer is still cut there, unless
    /// the route has a `stream`, which says how long the response may last.
    pub keepalive_time: Duration,
    /// Before the proxy closes a connection after a response: the longest it reads and discards what the client
    /// still sends, the longest it waits for one more read, and the most bytes it discards.
    pub lingering_time: Duration,
    pub lingering_timeout: Duration,
    pub lingering_bytes: usize,
    /// The peers that are believed when they say who the client is, by the `X-Forwarded-For` of a request. Empty:
    /// the client is always the peer.
    pub trusted_proxies: Vec<Cidr>,
    /// The most connections that wait to be used again in each upstream group, to all its servers together. Zero: a
    /// connection is closed after its answer.
    pub upstream_keepalive: usize,
    /// How long a connection to a server waits to be used again.
    pub upstream_keepalive_timeout: Duration,
    /// The most requests one connection to a server carries.
    pub upstream_keepalive_requests: usize,
}

/// A whole configuration that passed every check: the main file, and for a file with `managed` the version of the
/// managed store it was read with. The proxy serves with it.
#[derive(Clone, Debug)]
pub struct Loaded {
    pub proxy: ProxyConfig,
    /// From the main file, or from the version for a file with `managed` (`resolve_timeout` is the main file's).
    pub forward: ForwardSettings,
    pub kernel: KernelSettings,
    pub store: StoreConfig,
    /// There if the file has the `acme` object (see `acme` for when it must).
    pub acme: Option<AcmeConfig>,
    /// There if the file has the `status` object.
    pub status: Option<StatusConfig>,
    /// There if the file has the `records` object.
    pub records: Option<Records>,
    /// What turns a request away before its route is looked for: the `access`, `rate_limit` and `geo` objects. For a
    /// file with `managed` the first two are the version's and `geo` is the main file's.
    pub policy: PolicyConfig,
    /// There if the file has the `admin` object.
    pub admin: Option<AdminConfig>,
    /// The `route` of `admin`, there if the file has `managed` and `admin`.
    pub admin_route: Option<AdminRoute>,
    /// There if the file has the `managed` object.
    pub managed: Option<ManagedConfig>,
    /// The version that was read, there if and only if `managed` is.
    pub version: Option<Version>,
    /// The SHA-256 of the bytes of the main file that were read: what the running proxy shows of the file it follows.
    pub sha256: [u8; 32],
}

/// The main file that passed every check, without its routing: see the module documentation.
#[derive(Clone, Debug)]
pub struct MainFile {
    pub proxy: ProxyConfig,
    pub kernel: KernelSettings,
    pub store: StoreConfig,
    pub acme: Option<AcmeConfig>,
    pub status: Option<StatusConfig>,
    pub records: Option<Records>,
    pub admin: Option<AdminConfig>,
    pub admin_route: Option<AdminRoute>,
    pub managed: Option<ManagedConfig>,
    pub sha256: [u8; 32],
}

/// The main file, checked, with its policy and its routing.
pub(crate) struct Built {
    pub(crate) main: MainFile,
    /// The `access`, the `rate_limit` and the `geo` of the file; with `managed`, its `geo` only.
    pub(crate) policy: PolicyConfig,
    pub(crate) routing: Routing,
}

pub(crate) enum Routing {
    /// The groups, the routes and the default group of a file without `managed`, checked.
    Own(ForwardSettings),
    /// A file with `managed`: the time to look up the names of the servers of its version.
    Managed { resolve_timeout: Duration },
}

/// Where the rule generations are kept, as the file names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreConfig {
    File { dir: PathBuf },
}

/// Where the managed store is, as the file names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedConfig {
    pub dir: PathBuf,
}

/// Why the file was refused: a fixed English sentence, never a value taken from the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigError(pub &'static str);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    proxy: Object<RawProxy>,
    forward: Object<forward::RawForward>,
    kernel: Object<kernel::RawKernel>,
    rules: Object<RawRules>,
    #[serde(default, deserialize_with = "present")]
    acme: Option<Object<acme::RawAcme>>,
    #[serde(default, deserialize_with = "present")]
    status: Option<Object<status::RawStatus>>,
    #[serde(default, deserialize_with = "present")]
    records: Option<Object<records::RawRecords>>,
    #[serde(default, deserialize_with = "present")]
    access: Option<Object<rewrite::RawAccess>>,
    #[serde(default, deserialize_with = "present")]
    rate_limit: Option<Object<policy::RawRateLimit>>,
    #[serde(default, deserialize_with = "present")]
    geo: Option<Object<policy::RawGeo>>,
    #[serde(default, deserialize_with = "present")]
    admin: Option<Object<admin::RawAdmin>>,
    #[serde(default, deserialize_with = "present")]
    managed: Option<Object<RawManaged>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProxy {
    listeners: Vec<Object<listeners::RawListener>>,
    max_conns: usize,
    max_head_bytes: usize,
    max_body: usize,
    inspect_body: usize,
    max_body_wire: usize,
    max_buffered_bytes: usize,
    upstream_max_headers: usize,
    upstream_max_head_bytes: usize,
    upstream_head_wire: usize,
    drive_slice_ms: u64,
    ready_wait_ms: u64,
    head_read_ms: u64,
    body_read_ms: u64,
    inspect_wait_ms: u64,
    upstream_connect_ms: u64,
    upstream_header_ms: u64,
    request_total_ms: u64,
    response_idle_ms: u64,
    conn_total_ms: u64,
    stop_inspect_ms: u64,
    stop_wait_ms: u64,
    keepalive_timeout_ms: u64,
    keepalive_requests: usize,
    keepalive_time_ms: u64,
    lingering_time_ms: u64,
    lingering_timeout_ms: u64,
    lingering_bytes: usize,
    trusted_proxies: Vec<String>,
    upstream_keepalive: usize,
    upstream_keepalive_timeout_ms: u64,
    upstream_keepalive_requests: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRules {
    store: Object<RawStore>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStore {
    kind: String,
    dir: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManaged {
    dir: String,
}

/// For a key that may be left out: the value when the key is there, and never `null`. serde reads `null` as a key
/// that is left out, which would turn TLS off, or drop an access list or a host, without a word. Used as
/// `#[serde(default, deserialize_with = "super::present")]`, where `default` is what a key that is left out gives.
pub(crate) fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(deserializer).map(Some)
}

/// Accepts only a JSON object. A derived struct alone would also take an array of its values in field order,
/// which would skip the key names.
pub(crate) struct Object<T>(pub(crate) T);

struct ObjectVisitor<T>(PhantomData<T>);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Object<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(ObjectVisitor(PhantomData))
    }
}

impl<'de, T: Deserialize<'de>> Visitor<'de> for ObjectVisitor<T> {
    type Value = Object<T>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an object")
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Object<T>, A::Error> {
        T::deserialize(MapAccessDeserializer::new(map)).map(Object)
    }
}

/// Reads and checks the whole configuration (see the module documentation): the reading of `managed::load` with the
/// version that the store chooses, every refusal as its sentence.
pub fn load(path: &Path) -> Result<Loaded, ConfigError> {
    managed::load(path, &Choice::Current).map_err(|e| e.sentence())
}

/// Reads and checks the main file alone (see the module documentation).
pub fn load_main(path: &Path) -> Result<MainFile, ConfigError> {
    Ok(main_file(&read(path)?)?.main)
}

/// The bytes of the main file: a regular file of at most 256 KiB, which is checked by `main_file`.
pub(crate) fn read(path: &Path) -> Result<Vec<u8>, ConfigError> {
    const UNREADABLE: ConfigError = ConfigError("configuration file cannot be read");
    let meta = fs::metadata(path).map_err(|_| UNREADABLE)?;
    if !meta.is_file() {
        return Err(ConfigError("configuration file is not a regular file"));
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| UNREADABLE)?
        .take(MAX_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| UNREADABLE)?;
    Ok(bytes)
}

/// Reads the country database that the `geo` of a whole configuration names (see `policy`). The database is read and
/// checked whether or not a list uses it, so that a bad one is found at once; it is kept only if one does.
pub(crate) fn read_countries(loaded: &mut Loaded) -> Result<(), ConfigError> {
    if let Some(geo) = &loaded.policy.geo {
        let country = geo.open()?;
        let route = loaded.admin_route.as_ref();
        if uses_countries(&loaded.policy, &loaded.forward)
            || route.is_some_and(|route| route.access.has_countries())
        {
            loaded.policy.country = Some(country);
        }
    }
    Ok(())
}

/// The bytes of a main file, checked.
pub(crate) fn main_file(bytes: &[u8]) -> Result<Built, ConfigError> {
    if !u64::try_from(bytes.len()).is_ok_and(|n| n <= MAX_FILE) {
        return Err(ConfigError("configuration file is over 256 KiB"));
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| ConfigError("configuration file is not UTF-8"))?;
    let Object(file): Object<RawFile> = serde_json::from_str(text).map_err(|e| refusal(&e))?;
    build(file, sha256(bytes))
}

/// A file without `managed`, from its bytes, as `load` reads it but for the country database.
#[cfg(test)]
fn parse(bytes: &[u8]) -> Result<Loaded, ConfigError> {
    match main_file(bytes)? {
        Built {
            main,
            policy,
            routing: Routing::Own(forward),
        } => Ok(managed::whole(main, forward, policy, None)),
        Built {
            routing: Routing::Managed { .. },
            ..
        } => Err(ConfigError("a file with managed is read with its store")),
    }
}

/// The fixed sentence for a deserialization fault. The text of the fault is only used to tell the kinds apart.
pub(crate) fn refusal(e: &serde_json::Error) -> ConfigError {
    ConfigError(match e.classify() {
        Category::Io | Category::Syntax | Category::Eof => "configuration is not valid JSON",
        Category::Data => {
            let text = e.to_string();
            if text.starts_with("missing field") {
                "configuration has a missing key"
            } else if text.starts_with("unknown field") {
                "configuration has an unknown key"
            } else if text.starts_with("duplicate field") {
                "configuration has a repeated key"
            } else {
                "configuration has a value of the wrong type"
            }
        }
    })
}

pub(crate) fn ensure(ok: bool, text: &'static str) -> Result<(), ConfigError> {
    if ok { Ok(()) } else { Err(ConfigError(text)) }
}

/// Whether the `access` of the configuration or of some route has a list of countries.
pub(crate) fn uses_countries(policy: &PolicyConfig, forward: &ForwardSettings) -> bool {
    policy.access.has_countries()
        || forward
            .routes
            .targets()
            .any(|route| route.access.has_countries())
}

/// A list of networks for a `trusted_proxies`: at most `MAX_TRUSTED`, each in the form `Cidr::parse` takes. `many` and
/// `bad` are the two sentences of the refusal.
fn networks(
    list: &[String],
    many: &'static str,
    bad: &'static str,
) -> Result<Vec<Cidr>, ConfigError> {
    ensure(list.len() <= MAX_TRUSTED, many)?;
    list.iter()
        .map(|text| Cidr::parse(text))
        .collect::<Option<Vec<Cidr>>>()
        .ok_or(ConfigError(bad))
}

fn bytes(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn within(value: usize, low: u64, high: u64) -> bool {
    (low..=high).contains(&bytes(value))
}

fn millis(ms: u64, text: &'static str) -> Result<Duration, ConfigError> {
    ensure((1..=MAX_MS).contains(&ms), text)?;
    Ok(Duration::from_millis(ms))
}

fn address(text: &str, bad: &'static str, port0: &'static str) -> Result<SocketAddr, ConfigError> {
    let addr: SocketAddr = text.parse().map_err(|_| ConfigError(bad))?;
    ensure(addr.port() != 0, port0)?;
    Ok(addr)
}

/// Whether a server at `b` is the proxy itself when a listener is at `a`: the same address and port, or, when `a` is
/// an unspecified address (the proxy listens at every address of the host), a loopback address at the port.
pub(crate) fn same(a: SocketAddr, b: SocketAddr) -> bool {
    let (own, server) = (a.ip().to_canonical(), b.ip().to_canonical());
    a.port() == b.port() && (own == server || (own.is_unspecified() && server.is_loopback()))
}

/// A path argument or a configured path must be absolute and already clean: no empty, `.` or `..` component, no
/// trailing slash, no NUL, and shorter than the Linux `PATH_MAX`.
pub fn clean_abs(p: &Path) -> bool {
    let b = p.as_os_str().as_bytes();
    b.len() > 1
        && b.len() < 4096
        && b[0] == b'/'
        && !b.contains(&0)
        && b[1..]
            .split(|&c| c == b'/')
            .all(|s| !s.is_empty() && s != b"." && s != b"..")
}

fn build(file: RawFile, sha256: [u8; 32]) -> Result<Built, ConfigError> {
    let RawFile {
        proxy: Object(p),
        forward: Object(f),
        kernel: Object(k),
        rules: Object(RawRules { store: Object(s) }),
        acme: a,
        status: st,
        records: rec,
        access: ac,
        rate_limit: rl,
        geo: ge,
        admin: ad,
        managed: m,
    } = file;
    // The routing of a file with `managed` is in its version. Without `managed`, the three keys of the routing are
    // required, and a missing one is found before any value is checked, as serde finds a missing key that is not
    // optional.
    let versioned = m.is_some();
    ensure(
        versioned || f.routes_written() == Some(true),
        "configuration has a missing key",
    )?;
    let listeners = if versioned {
        listeners::check_managed(p.listeners)?
    } else {
        listeners::check(p.listeners)?
    };
    ensure(within(p.max_conns, 1, 65536), "max_conns is out of range")?;
    ensure(
        within(p.max_head_bytes, 1024, 32768),
        "max_head_bytes is out of range",
    )?;
    ensure(
        listeners::header_lists_fit(&listeners, p.max_head_bytes),
        "http2 max_header_list is above four times max_head_bytes",
    )?;
    ensure(within(p.max_body, KIB, 4 * GIB), "max_body is out of range")?;
    ensure(
        within(p.inspect_body, KIB, BODY),
        "inspect_body is out of range",
    )?;
    ensure(
        p.inspect_body <= p.max_body,
        "inspect_body is above max_body",
    )?;
    // The wire holds the framing of a chunked body besides the body.
    let wire_high = bytes(p.max_body)
        .checked_mul(2)
        .and_then(|n| n.checked_add(4 * MIB));
    ensure(
        wire_high.is_some_and(|high| within(p.max_body_wire, bytes(p.max_body), high)),
        "max_body_wire is out of range",
    )?;
    // One request holds the inspected bytes, the kernel's copy of them with the fields, and the piece of the rest of
    // the body that is on its way.
    let one_request = bytes(p.inspect_body)
        .checked_mul(2)
        .and_then(|n| n.checked_add(bytes(HEADER_TOTAL)))
        .and_then(|n| n.checked_add(bytes(STREAM_HOLD)));
    ensure(
        one_request.is_some_and(|low| within(p.max_buffered_bytes, low, 4 * GIB)),
        "max_buffered_bytes is out of range",
    )?;
    ensure(
        within(p.upstream_max_headers, 1, 1024),
        "upstream_max_headers is out of range",
    )?;
    ensure(
        within(p.upstream_max_head_bytes, 8192, MIB),
        "upstream_max_head_bytes is out of range",
    )?;
    ensure(
        listeners::holds_fit(&listeners, p.upstream_max_head_bytes),
        "http2 streams with their fields and a response chunk can hold more than 16 MiB",
    )?;
    let head_wire_low = bytes(p.upstream_max_head_bytes.max(8192)).checked_mul(2);
    ensure(
        head_wire_low.is_some_and(|low| within(p.upstream_head_wire, low, 4 * MIB)),
        "upstream_head_wire is out of range",
    )?;
    let drive_slice = millis(p.drive_slice_ms, "drive_slice_ms is out of range")?;
    let ready_wait = millis(p.ready_wait_ms, "ready_wait_ms is out of range")?;
    let head_read = millis(p.head_read_ms, "head_read_ms is out of range")?;
    let body_read = millis(p.body_read_ms, "body_read_ms is out of range")?;
    let inspect_wait = millis(p.inspect_wait_ms, "inspect_wait_ms is out of range")?;
    let upstream_connect = millis(p.upstream_connect_ms, "upstream_connect_ms is out of range")?;
    let upstream_header = millis(p.upstream_header_ms, "upstream_header_ms is out of range")?;
    let request_total = millis(p.request_total_ms, "request_total_ms is out of range")?;
    let response_idle = millis(p.response_idle_ms, "response_idle_ms is out of range")?;
    ensure(
        (1..=MAX_CONN_MS).contains(&p.conn_total_ms),
        "conn_total_ms is out of range",
    )?;
    let conn_total = Duration::from_millis(p.conn_total_ms);
    let stop_inspect = millis(p.stop_inspect_ms, "stop_inspect_ms is out of range")?;
    let stop_wait = millis(p.stop_wait_ms, "stop_wait_ms is out of range")?;
    ensure(
        p.keepalive_timeout_ms <= MAX_MS,
        "keepalive_timeout_ms is out of range",
    )?;
    let keepalive_timeout = Duration::from_millis(p.keepalive_timeout_ms);
    ensure(
        within(p.keepalive_requests, 1, 1_000_000),
        "keepalive_requests is out of range",
    )?;
    let keepalive_time = millis(p.keepalive_time_ms, "keepalive_time_ms is out of range")?;
    let lingering_time = millis(p.lingering_time_ms, "lingering_time_ms is out of range")?;
    let lingering_timeout = millis(
        p.lingering_timeout_ms,
        "lingering_timeout_ms is out of range",
    )?;
    ensure(
        within(p.lingering_bytes, 1, 4 * MIB),
        "lingering_bytes is out of range",
    )?;
    let trusted_proxies = networks(
        &p.trusted_proxies,
        "trusted_proxies has more than 256 entries",
        "trusted_proxies has an entry that is not a network",
    )?;
    ensure(
        within(p.upstream_keepalive, 0, 1024),
        "upstream_keepalive is out of range",
    )?;
    let upstream_keepalive_timeout = millis(
        p.upstream_keepalive_timeout_ms,
        "upstream_keepalive_timeout_ms is out of range",
    )?;
    ensure(
        within(p.upstream_keepalive_requests, 1, 1_000_000),
        "upstream_keepalive_requests is out of range",
    )?;

    let status = status::check(st, &listeners)?;
    // A server may not be at an address the proxy listens on, the one of the status listener included.
    let mut bound = addresses(&listeners);
    bound.extend(status.map(|status| status.listen));
    // With `managed`, the routing is checked with the version (see `managed::version`).
    let (forward, resolve_timeout) = if versioned {
        (None, forward::timeout_only(f)?)
    } else {
        let forward = forward::check(f, &bound, p.max_body)?;
        let timeout = forward.resolve_timeout;
        (Some(forward), timeout)
    };

    ensure(s.kind == "file", "rules store kind is not supported")?;
    let dir = PathBuf::from(s.dir);
    ensure(
        clean_abs(&dir),
        "rules store dir is not an absolute clean path",
    )?;
    ensure(
        dir.as_os_str().as_bytes().len() <= MAX_STORE_DIR,
        "rules store dir is over 3840 bytes",
    )?;
    let managed = m.map(|Object(raw)| managed_dir(raw)).transpose()?;

    let records = records::check(rec)?;
    if let Some(forward) = &forward {
        records::consistent(records.as_ref(), forward)?;
    }
    ensure(
        managed.is_none() || (ac.is_none() && rl.is_none()),
        "the configuration has access or rate_limit while it has managed",
    )?;
    let policy = policy::check(ac, rl, ge)?;
    if let Some(forward) = &forward {
        ensure(
            policy.geo.is_some() || !uses_countries(&policy, forward),
            "access has a list of countries while geo is left out",
        )?;
    }
    // Unlike the status listener, the admin process may be the server of an upstream: `bound` above does not hold
    // its address.
    let (admin, admin_route) = admin::check(ad, &listeners, status, versioned)?;
    ensure(
        policy.geo.is_some()
            || !admin_route
                .as_ref()
                .is_some_and(|r| r.access.has_countries()),
        "access has a list of countries while geo is left out",
    )?;
    let acme = acme::check(a, &listeners, admin_route.as_ref(), versioned)?;
    places::separate(
        &dir,
        records.as_ref(),
        admin.as_ref(),
        managed.as_ref(),
        acme.as_ref(),
        admin_route.as_ref(),
    )?;

    let kernel = kernel::settings(k, &dir)?;
    let proxy = ProxyConfig {
        listeners,
        max_conns: p.max_conns,
        max_head_bytes: p.max_head_bytes,
        max_body: p.max_body,
        inspect_body: p.inspect_body,
        max_body_wire: p.max_body_wire,
        max_buffered_bytes: p.max_buffered_bytes,
        upstream_max_headers: p.upstream_max_headers,
        upstream_max_head_bytes: p.upstream_max_head_bytes,
        upstream_head_wire: p.upstream_head_wire,
        drive_slice,
        ready_wait,
        head_read,
        body_read,
        inspect_wait,
        upstream_connect,
        upstream_header,
        request_total,
        response_idle,
        conn_total,
        stop_inspect,
        stop_wait,
        keepalive_timeout,
        keepalive_requests: p.keepalive_requests,
        keepalive_time,
        lingering_time,
        lingering_timeout,
        lingering_bytes: p.lingering_bytes,
        trusted_proxies,
        upstream_keepalive: p.upstream_keepalive,
        upstream_keepalive_timeout,
        upstream_keepalive_requests: p.upstream_keepalive_requests,
    };
    kernel::relations(&proxy, &kernel)?;

    let main = MainFile {
        proxy,
        kernel,
        store: StoreConfig::File { dir },
        acme,
        status,
        records,
        admin,
        admin_route,
        managed,
        sha256,
    };
    let routing = match forward {
        Some(forward) => Routing::Own(forward),
        None => Routing::Managed { resolve_timeout },
    };
    Ok(Built {
        main,
        policy,
        routing,
    })
}

/// The `managed` object: the directory as the rules store `dir` is written.
fn managed_dir(raw: RawManaged) -> Result<ManagedConfig, ConfigError> {
    let dir = PathBuf::from(raw.dir);
    ensure(clean_abs(&dir), "managed dir is not an absolute clean path")?;
    ensure(
        dir.as_os_str().as_bytes().len() <= MAX_STORE_DIR,
        "managed dir is over 3840 bytes",
    )?;
    Ok(ManagedConfig { dir })
}

#[cfg(test)]
mod tests;
