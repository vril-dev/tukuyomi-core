//! The configuration file: one JSON object `{"proxy": {..}, "forward": {..}, "kernel": {..}, "rules": {"store":
//! {..}}}`; every value is chosen by the operator and checked here.
//!
//! The file is read whole (at most 256 KiB, UTF-8) and deserialized into plain structs. Every key must be present (a
//! route may leave out its `host`, its `path`, its `access`, its `rewrite` and its `stream`; `access` and `rewrite`
//! have no key that must be present, see `rewrite`, and a `stream` has all three; an upstream group may leave out its
//! `tls`, which may leave out its `server_name`; a listener may leave out its `tls` and its `redirect`, and the `tls`
//! of a listener may leave out its `http2`); an unknown or repeated key is refused, and so is a value of the wrong
//! type, an array in place of an object and `null` for a key that may be left out included (such a key is either left
//! out or has a value). A refusal is one fixed sentence per kind of fault and never carries a key or a value from the
//! file. Then the values are checked in a fixed order and the first broken rule is returned: the `proxy` bounds, the
//! `forward` values (see `forward`; the names of the servers are not looked up here, `forward::resolve` does that when
//! the proxy starts), the `rules.store` values, the conversion of the `kernel` object into `tukuyomi_kernel::Config`
//! with that type's own check, and last the relations between the `proxy` and `kernel` objects.
//!
//! Times are whole milliseconds under keys that end in `_ms`; the `proxy` times run from 1 ms to 3600 s, except
//! `keepalive_timeout_ms`, which also takes 0 (a connection is not kept after its response), and `conn_total_ms`,
//! which runs up to 24 h.
//! `trusted_proxies` is a list of networks, `address/prefix` in the form `Cidr::parse` takes, and may be empty.
//! `listeners` is a list of 1 to 8 listeners (see `listeners`). `rules.store.kind` is `file`, the
//! only kind there is, and `dir` is an absolute clean path of at most 3840 bytes. The `kernel` object has no
//! rules path and no rules fingerprint: the directory and the fingerprint of the chosen generation come from the
//! rules store when the proxy starts (`KernelSettings::for_generation`).

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
use crate::rules::bundle::Fingerprint;

mod forward;
mod listeners;
mod rewrite;

pub(crate) use forward::MAX_SERVERS;
pub use forward::{
    Address, ForwardConfig, ForwardSettings, GroupConfig, RouteConfig, ServerConfig, Stream,
};
pub use listeners::{
    CertificateConfig, Http2Config, ListenerConfig, ListenerKind, MinVersion, TlsConfig, addresses,
};

const MAX_FILE: u64 = 256 * 1024;
/// Longest accepted `rules.store.dir` in bytes: the paths below it must stay inside the Linux `PATH_MAX`. A guard
/// against a wrong setting, not a recommendation.
const MAX_STORE_DIR: usize = 3840;
const MAX_MS: u64 = 3_600_000;
/// The longest `conn_total_ms`: the connection time has room for `keepalive_time_ms` and one request after it.
const MAX_CONN_MS: u64 = 86_400_000;
/// The most networks in `trusted_proxies`.
const MAX_TRUSTED: usize = 256;
const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;

/// The HTTP side of the configuration. No `Default`: every value comes from the file.
#[derive(Clone, Debug)]
pub struct ProxyConfig {
    pub listeners: Vec<ListenerConfig>,
    pub max_conns: usize,
    pub max_head_bytes: usize,
    pub max_body: usize,
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

/// A configuration that passed every check.
#[derive(Clone, Debug)]
pub struct Loaded {
    pub proxy: ProxyConfig,
    pub forward: ForwardSettings,
    pub kernel: KernelSettings,
    pub store: StoreConfig,
}

/// Where the rule generations are kept, as the file names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreConfig {
    File { dir: PathBuf },
}

/// The kernel values of the file, checked. The rules directory and fingerprint come from the rules store at
/// start-up.
#[derive(Clone, Debug)]
pub struct KernelSettings(tukuyomi_kernel::Config);

impl KernelSettings {
    /// The kernel configuration for one generation, checked again.
    pub fn for_generation(
        &self,
        dir: PathBuf,
        generation: Fingerprint,
    ) -> Result<tukuyomi_kernel::Config, ConfigError> {
        let kernel = tukuyomi_kernel::Config {
            rules: dir,
            rules_sha256: generation.bytes(),
            ..self.0.clone()
        };
        kernel.check().map_err(|e| ConfigError(e.0))?;
        Ok(kernel)
    }
}

/// Why the file was refused: a fixed English sentence, never a value taken from the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigError(pub &'static str);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    proxy: Object<RawProxy>,
    forward: Object<forward::RawForward>,
    kernel: Object<RawKernel>,
    rules: Object<RawRules>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProxy {
    listeners: Vec<Object<listeners::RawListener>>,
    max_conns: usize,
    max_head_bytes: usize,
    max_body: usize,
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
struct RawKernel {
    inspector: String,
    tmp_root: String,
    gomaxprocs: u16,
    gomemlimit: u64,
    slots: usize,
    wait_queue: usize,
    records: usize,
    discard_limit: u32,
    tick_ms: u64,
    hello_wait_ms: u64,
    frame_io_ms: u64,
    verdict_wait_ms: u64,
    wait_deadline_ms: u64,
    closed_wait_ms: u64,
    stop_after_ms: u64,
    drain_wait_ms: u64,
    exit_wait_ms: u64,
    kill_grace_ms: u64,
    restarts: u32,
    restart_window_ms: u64,
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
struct Object<T>(T);

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

/// Reads and checks the configuration file.
pub fn load(path: &Path) -> Result<Loaded, ConfigError> {
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
    parse(&bytes)
}

fn parse(bytes: &[u8]) -> Result<Loaded, ConfigError> {
    if !u64::try_from(bytes.len()).is_ok_and(|n| n <= MAX_FILE) {
        return Err(ConfigError("configuration file is over 256 KiB"));
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| ConfigError("configuration file is not UTF-8"))?;
    let Object(file): Object<RawFile> = serde_json::from_str(text).map_err(|e| refusal(&e))?;
    build(
        file.proxy.0,
        file.forward.0,
        file.rules.0.store.0,
        file.kernel.0,
    )
}

/// The fixed sentence for a deserialization fault. The text of the fault is only used to tell the kinds apart.
fn refusal(e: &serde_json::Error) -> ConfigError {
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

fn ensure(ok: bool, text: &'static str) -> Result<(), ConfigError> {
    if ok { Ok(()) } else { Err(ConfigError(text)) }
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

/// The least time the HTTP side must allow for an inspection: the kernel's wait for the first frame, two
/// verdicts, and 18 driver steps of one slice and one frame write each. `None` if the sum overflows.
fn inspect_floor(kernel: &tukuyomi_kernel::Config, slice: Duration) -> Option<Duration> {
    let steps = slice.checked_add(kernel.frame_io)?.checked_mul(18)?;
    kernel
        .wait_deadline
        .checked_add(kernel.verdict_wait.checked_mul(2)?)?
        .checked_add(steps)
}

fn build(
    p: RawProxy,
    f: forward::RawForward,
    s: RawStore,
    k: RawKernel,
) -> Result<Loaded, ConfigError> {
    let listeners = listeners::check(p.listeners)?;
    ensure(within(p.max_conns, 1, 65536), "max_conns is out of range")?;
    ensure(
        within(p.max_head_bytes, 1024, 32768),
        "max_head_bytes is out of range",
    )?;
    ensure(
        listeners::header_lists_fit(&listeners, p.max_head_bytes),
        "http2 max_header_list is above four times max_head_bytes",
    )?;
    ensure(
        bytes(p.max_body) <= BODY,
        "max_body is above the body limit",
    )?;
    ensure(
        within(p.max_body_wire, bytes(p.max_body), 4 * MIB),
        "max_body_wire is out of range",
    )?;
    let one_request = bytes(p.max_body)
        .checked_mul(2)
        .and_then(|n| n.checked_add(bytes(HEADER_TOTAL)));
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
    ensure(
        p.trusted_proxies.len() <= MAX_TRUSTED,
        "trusted_proxies has more than 256 entries",
    )?;
    let trusted_proxies = p
        .trusted_proxies
        .iter()
        .map(|text| Cidr::parse(text))
        .collect::<Option<Vec<Cidr>>>()
        .ok_or(ConfigError(
            "trusted_proxies has an entry that is not a network",
        ))?;
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

    let forward = forward::check(f, &addresses(&listeners))?;

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

    let kernel = tukuyomi_kernel::Config {
        inspector: PathBuf::from(k.inspector),
        // The check looks at the form of the path only, so the directory of a generation, which is below this
        // one, gets the same answer. The fingerprint is any value of its type.
        rules: dir.join("generations"),
        rules_sha256: [0; 32],
        tmp_root: PathBuf::from(k.tmp_root),
        gomaxprocs: k.gomaxprocs,
        gomemlimit: k.gomemlimit,
        slots: k.slots,
        wait_queue: k.wait_queue,
        records: k.records,
        discard_limit: k.discard_limit,
        tick: Duration::from_millis(k.tick_ms),
        hello_wait: Duration::from_millis(k.hello_wait_ms),
        frame_io: Duration::from_millis(k.frame_io_ms),
        verdict_wait: Duration::from_millis(k.verdict_wait_ms),
        wait_deadline: Duration::from_millis(k.wait_deadline_ms),
        closed_wait: Duration::from_millis(k.closed_wait_ms),
        stop_after: Duration::from_millis(k.stop_after_ms),
        drain_wait: Duration::from_millis(k.drain_wait_ms),
        exit_wait: Duration::from_millis(k.exit_wait_ms),
        kill_grace: Duration::from_millis(k.kill_grace_ms),
        restarts: k.restarts,
        restart_window: Duration::from_millis(k.restart_window_ms),
    };
    kernel.check().map_err(|e| ConfigError(e.0))?;

    ensure(
        drive_slice <= kernel.tick,
        "drive_slice_ms is above the kernel tick",
    )?;
    ensure(
        ready_wait >= kernel.hello_wait,
        "ready_wait_ms is below the kernel hello_wait",
    )?;
    ensure(
        head_read <= request_total,
        "head_read_ms is above request_total_ms",
    )?;
    ensure(
        body_read <= request_total,
        "body_read_ms is above request_total_ms",
    )?;
    ensure(
        inspect_floor(&kernel, drive_slice).is_some_and(|low| inspect_wait >= low),
        "inspect_wait_ms is below the kernel inspection time",
    )?;
    ensure(
        inspect_wait <= request_total,
        "inspect_wait_ms is above request_total_ms",
    )?;
    // The two stages of the exchange with the upstream follow each other, and both must end before the request time
    // does. A server that holds a stage up is counted against only if the limit of the stage comes first; if the end
    // of the request time comes first, the request ends there and no server is at fault. A slow client or a long
    // inspection can still use up the time that is left, and the request then ends the same way.
    ensure(
        upstream_connect
            .checked_add(upstream_header)
            .is_some_and(|n| n < request_total),
        "upstream_connect_ms plus upstream_header_ms is not below request_total_ms",
    )?;
    ensure(
        request_total <= conn_total,
        "request_total_ms is above conn_total_ms",
    )?;
    ensure(
        response_idle <= conn_total,
        "response_idle_ms is above conn_total_ms",
    )?;
    ensure(
        keepalive_timeout <= conn_total,
        "keepalive_timeout_ms is above conn_total_ms",
    )?;
    // A connection that waits in the pool is read from the whole time, and a read that waits for longer than
    // `response_idle` fails.
    ensure(
        upstream_keepalive_timeout <= response_idle,
        "upstream_keepalive_timeout_ms is above response_idle_ms",
    )?;
    // A request that starts before `keepalive_time` gets its answer, or the upstream's response head, before
    // the connection time is over (`request_total` bounds that part of a request, not a streamed body).
    ensure(
        keepalive_time
            .checked_add(request_total)
            .is_some_and(|n| n <= conn_total),
        "keepalive_time_ms plus request_total_ms is above conn_total_ms",
    )?;
    ensure(
        lingering_timeout <= lingering_time,
        "lingering_timeout_ms is above lingering_time_ms",
    )?;
    ensure(
        stop_inspect < stop_wait,
        "stop_inspect_ms is not below stop_wait_ms",
    )?;
    ensure(
        stop_inspect
            .checked_add(kernel.kill_grace)
            .is_some_and(|n| stop_wait > n),
        "stop_wait_ms is not above stop_inspect_ms plus kill_grace",
    )?;
    // A connection holds at most one inspection, so a longer queue would never fill. The bound also keeps the
    // queue and its permits small.
    ensure(
        kernel.wait_queue <= p.max_conns,
        "wait_queue is above max_conns",
    )?;

    Ok(Loaded {
        proxy: ProxyConfig {
            listeners,
            max_conns: p.max_conns,
            max_head_bytes: p.max_head_bytes,
            max_body: p.max_body,
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
        },
        forward,
        kernel: KernelSettings(kernel),
        store: StoreConfig::File { dir },
    })
}

#[cfg(test)]
mod tests;
