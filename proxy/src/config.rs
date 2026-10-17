//! The configuration file: one JSON object `{"proxy": {..}, "kernel": {..}}`; every value is chosen by the
//! operator and checked here.
//!
//! The file is read whole (at most 64 KiB, UTF-8) and deserialized into plain structs. Every key must be present;
//! an unknown or repeated key is refused, and so is a value of the wrong type, an array in place of an object
//! included. A refusal is one fixed sentence per kind of fault and never carries a key or a value from the file.
//! Then the values are checked in a fixed order and the first broken rule is returned: the `proxy` bounds, the
//! conversion of the `kernel` object into `tukuyomi_kernel::Config` with that type's own check, and last the
//! relations between the two objects.
//!
//! Times are whole milliseconds under keys that end in `_ms`; the `proxy` times run from 1 ms to 3600 s.
//! `listen` and `upstream` are an IP literal and a port (`[..]:port` for IPv6). `rules_sha256` is exactly 64
//! lowercase hexadecimal digits.

use std::fmt;
use std::fs::{self, File};
use std::io::Read;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use serde::de::value::MapAccessDeserializer;
use serde::de::{Deserializer, MapAccess, Visitor};
use serde_json::error::Category;
use tukuyomi_kernel::limits::{BODY, HEADER_TOTAL};

const MAX_FILE: u64 = 64 * 1024;
const MAX_MS: u64 = 3_600_000;
const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;

/// The HTTP side of the configuration. No `Default`: every value comes from the file.
#[derive(Clone, Debug)]
pub struct ProxyConfig {
    pub listen: SocketAddr,
    pub upstream: SocketAddr,
    pub max_conns: usize,
    pub max_head_bytes: usize,
    pub max_body: usize,
    pub max_body_wire: usize,
    pub max_buffered_bytes: usize,
    pub upstream_max_headers: usize,
    pub upstream_max_head_bytes: usize,
    pub upstream_head_wire: usize,
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
}

/// A configuration that passed every check.
#[derive(Clone, Debug)]
pub struct Loaded {
    pub proxy: ProxyConfig,
    pub kernel: tukuyomi_kernel::Config,
}

/// Why the file was refused: a fixed English sentence, never a value taken from the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigError(pub &'static str);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    proxy: Object<RawProxy>,
    kernel: Object<RawKernel>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProxy {
    listen: String,
    upstream: String,
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
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawKernel {
    inspector: String,
    rules: String,
    rules_sha256: String,
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
        return Err(ConfigError("configuration file is over 64 KiB"));
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| ConfigError("configuration file is not UTF-8"))?;
    let Object(file): Object<RawFile> = serde_json::from_str(text).map_err(|e| refusal(&e))?;
    build(file.proxy.0, file.kernel.0)
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

fn same(a: SocketAddr, b: SocketAddr) -> bool {
    a.port() == b.port() && a.ip().to_canonical() == b.ip().to_canonical()
}

fn digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

fn sha256(hex: &str) -> Result<[u8; 32], ConfigError> {
    const BAD: ConfigError = ConfigError("rules_sha256 is not 64 lowercase hex digits");
    let text = hex.as_bytes();
    if text.len() != 64 {
        return Err(BAD);
    }
    let mut out = [0; 32];
    for (byte, pair) in out.iter_mut().zip(text.chunks_exact(2)) {
        *byte = digit(pair[0]).ok_or(BAD)? << 4 | digit(pair[1]).ok_or(BAD)?;
    }
    Ok(out)
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

fn build(p: RawProxy, k: RawKernel) -> Result<Loaded, ConfigError> {
    let listen = address(
        &p.listen,
        "listen is not an IP address and port",
        "listen port is 0",
    )?;
    let upstream = address(
        &p.upstream,
        "upstream is not an IP address and port",
        "upstream port is 0",
    )?;
    ensure(
        !same(listen, upstream),
        "listen and upstream are the same address",
    )?;
    ensure(within(p.max_conns, 1, 65536), "max_conns is out of range")?;
    ensure(
        within(p.max_head_bytes, 1024, 32768),
        "max_head_bytes is out of range",
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
    let conn_total = millis(p.conn_total_ms, "conn_total_ms is out of range")?;
    let stop_inspect = millis(p.stop_inspect_ms, "stop_inspect_ms is out of range")?;
    let stop_wait = millis(p.stop_wait_ms, "stop_wait_ms is out of range")?;

    let kernel = tukuyomi_kernel::Config {
        inspector: PathBuf::from(k.inspector),
        rules: PathBuf::from(k.rules),
        rules_sha256: sha256(&k.rules_sha256)?,
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
    ensure(
        upstream_connect <= request_total,
        "upstream_connect_ms is above request_total_ms",
    )?;
    ensure(
        upstream_header <= request_total,
        "upstream_header_ms is above request_total_ms",
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
            listen,
            upstream,
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
        },
        kernel,
    })
}

#[cfg(test)]
mod tests;
