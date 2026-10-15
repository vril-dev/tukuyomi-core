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
mod tests {
    use super::*;
    use serde_json::Value;
    use std::sync::atomic::{AtomicU32, Ordering};

    const BASE: &str = r#"{"proxy":{"listen":"127.0.0.1:8080","upstream":"127.0.0.1:9000","max_conns":1024,"max_head_bytes":8192,"max_body":1048576,"max_body_wire":2097152,"max_buffered_bytes":8388608,"upstream_max_headers":100,"upstream_max_head_bytes":16384,"upstream_head_wire":65536,"drive_slice_ms":50,"ready_wait_ms":10000,"head_read_ms":10000,"body_read_ms":30000,"inspect_wait_ms":30000,"upstream_connect_ms":5000,"upstream_header_ms":30000,"request_total_ms":60000,"response_idle_ms":30000,"conn_total_ms":120000,"stop_inspect_ms":5000,"stop_wait_ms":10000},"kernel":{"inspector":"/opt/tukuyomi/inspector","rules":"/etc/tukuyomi/rules.conf","rules_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","tmp_root":"/var/lib/tukuyomi/tmp","gomaxprocs":2,"gomemlimit":1073741824,"slots":4,"wait_queue":16,"records":20,"discard_limit":4,"tick_ms":100,"hello_wait_ms":5000,"frame_io_ms":1000,"verdict_wait_ms":2000,"wait_deadline_ms":3000,"closed_wait_ms":2000,"stop_after_ms":2000,"drain_wait_ms":1000,"exit_wait_ms":1000,"kill_grace_ms":1000,"restarts":3}}"#;

    /// Marks a value that must never appear in an error sentence.
    const MARK: &str = "qqmark";

    type Edit = (&'static str, &'static str, Value);

    fn p(key: &'static str, value: impl Into<Value>) -> Edit {
        ("proxy", key, value.into())
    }

    fn k(key: &'static str, value: impl Into<Value>) -> Edit {
        ("kernel", key, value.into())
    }

    fn base() -> Value {
        serde_json::from_str(BASE).unwrap()
    }

    fn doc(edits: &[Edit]) -> Vec<u8> {
        let mut value = base();
        for (object, key, new) in edits {
            value[*object][*key] = new.clone();
        }
        value.to_string().into_bytes()
    }

    fn pass(edits: &[Edit]) {
        let result = parse(&doc(edits));
        assert!(result.is_ok(), "{edits:?}: {:?}", result.err());
    }

    fn refuse(edits: &[Edit], sentence: &str) {
        let result = parse(&doc(edits));
        assert_eq!(
            result.as_ref().err().map(|e| e.0),
            Some(sentence),
            "{edits:?}"
        );
    }

    fn refuse_text(text: &str, sentence: &str) {
        assert_eq!(
            parse(text.as_bytes()).err().map(|e| e.0),
            Some(sentence),
            "{text:.60}"
        );
    }

    #[test]
    fn the_base_document_loads_with_every_value_converted() {
        let loaded = parse(BASE.as_bytes()).unwrap();
        let (proxy, kernel) = (&loaded.proxy, &loaded.kernel);
        assert_eq!(proxy.listen, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(proxy.upstream, "127.0.0.1:9000".parse().unwrap());
        assert_eq!(proxy.max_conns, 1024);
        assert_eq!(proxy.max_body, 1 << 20);
        assert_eq!(proxy.max_buffered_bytes, 8 << 20);
        assert_eq!(proxy.upstream_head_wire, 65536);
        assert_eq!(proxy.drive_slice, Duration::from_millis(50));
        assert_eq!(proxy.conn_total, Duration::from_millis(120_000));
        assert_eq!(proxy.stop_wait, Duration::from_millis(10_000));
        assert_eq!(kernel.inspector, PathBuf::from("/opt/tukuyomi/inspector"));
        assert_eq!(kernel.tmp_root, PathBuf::from("/var/lib/tukuyomi/tmp"));
        assert_eq!(kernel.rules_sha256[..2], [0x01, 0x23]);
        assert_eq!(kernel.rules_sha256[30..], [0xcd, 0xef]);
        assert_eq!(kernel.gomaxprocs, 2);
        assert_eq!(kernel.gomemlimit, 1 << 30);
        assert_eq!(
            (kernel.slots, kernel.wait_queue, kernel.records),
            (4, 16, 20)
        );
        assert_eq!(kernel.tick, Duration::from_millis(100));
        assert_eq!(kernel.kill_grace, Duration::from_millis(1000));
        assert_eq!((kernel.discard_limit, kernel.restarts), (4, 3));
    }

    #[test]
    fn the_file_is_at_most_64_kib_and_utf8() {
        let at_limit = format!("{BASE}{}", " ".repeat(65536 - BASE.len()));
        assert_eq!(at_limit.len(), 65536);
        assert!(parse(at_limit.as_bytes()).is_ok());
        let over = format!("{at_limit} ");
        refuse_text(&over, "configuration file is over 64 KiB");
        // The size comes first: a file over the limit is not looked at for anything else.
        let junk = vec![0xff; 65537];
        assert_eq!(
            parse(&junk).err(),
            Some(ConfigError("configuration file is over 64 KiB"))
        );

        pass(&[k("inspector", "/opt/é")]);
        let mut bytes = BASE
            .replace("/opt/tukuyomi/inspector", "/opt/qqmark")
            .into_bytes();
        let at = bytes.windows(6).position(|w| w == MARK.as_bytes()).unwrap();
        bytes[at] = 0xff;
        let sentence = "configuration file is not UTF-8";
        assert_eq!(parse(&bytes).err(), Some(ConfigError(sentence)));
        // A character cut in the middle at the end of the file.
        let mut cut = BASE.as_bytes().to_vec();
        cut.push(0xc3);
        assert_eq!(parse(&cut).err(), Some(ConfigError(sentence)));
    }

    #[test]
    fn broken_json_is_refused_with_one_sentence() {
        let sentence = "configuration is not valid JSON";
        for text in [
            "",
            "{",
            "{\"proxy\":",
            "nul",
            "{'proxy':{}}",
            "{,}",
            "{\"proxy\" 1}",
        ] {
            refuse_text(text, sentence);
        }
        refuse_text(&format!("{BASE} x"), sentence);
        refuse_text(&format!("{BASE}{BASE}"), sentence);
        refuse_text(&BASE[..BASE.len() - 1], sentence);
    }

    #[test]
    fn a_missing_key_is_refused_in_all_three_objects() {
        let sentence = "configuration has a missing key";
        refuse_text("{}", sentence);
        for top in ["proxy", "kernel"] {
            let mut value = base();
            value.as_object_mut().unwrap().remove(top);
            refuse_text(&value.to_string(), sentence);
            let keys: Vec<String> = base()[top].as_object().unwrap().keys().cloned().collect();
            for key in keys {
                let mut value = base();
                value[top].as_object_mut().unwrap().remove(&key);
                refuse_text(&value.to_string(), sentence);
            }
        }
    }

    #[test]
    fn an_unknown_key_is_refused_in_all_three_objects() {
        let sentence = "configuration has an unknown key";
        let mut value = base();
        value["qqmark"] = Value::from(1);
        refuse_text(&value.to_string(), sentence);
        refuse(&[p("qqmark", 1)], sentence);
        refuse(&[k("qqmark", 1)], sentence);
        // Near misses of real keys: the unit suffix, the case.
        refuse(&[p("max_conns_ms", 1)], sentence);
        refuse(&[k("Tick_ms", 1)], sentence);
    }

    #[test]
    fn a_repeated_key_is_refused_even_with_the_same_value() {
        let sentence = "configuration has a repeated key";
        refuse_text(
            &BASE.replacen("\"proxy\":{", "\"proxy\":{\"max_conns\":1024,", 1),
            sentence,
        );
        refuse_text(
            &BASE.replacen("\"kernel\":{", "\"kernel\":{\"restarts\":9,", 1),
            sentence,
        );
        refuse_text(
            &format!("{},\"proxy\":{{}}}}", &BASE[..BASE.len() - 1]),
            sentence,
        );
    }

    #[test]
    fn a_value_of_the_wrong_type_is_refused_for_every_key() {
        let sentence = "configuration has a value of the wrong type";
        for object in ["proxy", "kernel"] {
            let keys: Vec<String> = base()[object]
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect();
            for key in keys {
                let wrong = if base()[object][&key].is_string() {
                    Value::from(5)
                } else {
                    Value::from("5")
                };
                for new in [wrong, Value::Null, Value::from(true), Value::Array(vec![])] {
                    let mut value = base();
                    value[object][&key] = new;
                    refuse_text(&value.to_string(), sentence);
                }
            }
        }
        // A number of the right kind but outside the type, a fraction, a negative count.
        refuse(&[k("gomaxprocs", 65536)], sentence);
        refuse(&[k("gomaxprocs", -1)], sentence);
        refuse(&[p("max_conns", 5.0)], sentence);
        refuse(&[p("max_conns", -1)], sentence);
        refuse(&[p("max_conns", u64::MAX)], "max_conns is out of range");
        refuse(&[k("discard_limit", u64::from(u32::MAX) + 1)], sentence);
        pass(&[k("gomaxprocs", 65535)]);
        pass(&[k("discard_limit", u32::MAX - 1)]);
    }

    #[test]
    fn an_array_never_stands_in_for_an_object() {
        let sentence = "configuration has a value of the wrong type";
        let values = |object: &str| -> Value {
            Value::Array(
                base()[object]
                    .as_object()
                    .unwrap()
                    .values()
                    .cloned()
                    .collect(),
            )
        };
        let mut positional = base();
        positional["proxy"] = values("proxy");
        refuse_text(&positional.to_string(), sentence);
        let mut positional = base();
        positional["kernel"] = values("kernel");
        refuse_text(&positional.to_string(), sentence);
        refuse_text(
            &Value::Array(vec![base()["proxy"].clone(), base()["kernel"].clone()]).to_string(),
            sentence,
        );
        refuse_text("null", sentence);
        refuse_text("5", sentence);
        refuse_text("\"proxy\"", sentence);
    }

    #[test]
    fn errors_never_carry_a_value_or_a_key_from_the_file() {
        let mut cases: Vec<Vec<u8>> = vec![
            doc(&[p("listen", MARK)]),
            doc(&[p("upstream", format!("{MARK}:80"))]),
            doc(&[p("max_conns", MARK)]),
            doc(&[p(MARK, 1)]),
            doc(&[k(MARK, 1)]),
            doc(&[k("inspector", MARK)]),
            doc(&[k("rules", format!("/{MARK}/../x"))]),
            doc(&[k("rules_sha256", MARK)]),
            doc(&[k("tmp_root", MARK)]),
            format!("{BASE}{MARK}").into_bytes(),
            format!("{{\"{MARK}\":1,\"{MARK}\":2}}").into_bytes(),
            BASE.replacen(
                "\"proxy\":{",
                &format!("\"proxy\":{{\"{MARK}\":1,\"{MARK}\":2,"),
                1,
            )
            .into_bytes(),
            format!("{BASE}{}", MARK.repeat(20000)).into_bytes(),
        ];
        let mut not_utf8 = MARK.as_bytes().to_vec();
        not_utf8.push(0xff);
        cases.push(not_utf8);
        let mut sentences = Vec::new();
        for case in &cases {
            let e = parse(case).expect_err("every case is refused");
            assert!(!e.0.contains(MARK), "{}", e.0);
            assert!(e.0.is_ascii() && e.0.len() < 80, "{}", e.0);
            sentences.push(e.0);
        }
        // Each kind of fault has its own sentence.
        assert_eq!(
            [
                refusal_of("{}"),
                refusal_of(&format!("{{\"{MARK}\":1}}")),
                refusal_of(&format!("{},\"proxy\":{{}}}}", &BASE[..BASE.len() - 1])),
                refusal_of("{\"proxy\":1}"),
                refusal_of("{"),
            ]
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
            5
        );
    }

    fn refusal_of(text: &str) -> &'static str {
        parse(text.as_bytes()).err().unwrap().0
    }

    #[test]
    fn addresses_are_ip_literals_with_a_port_and_differ() {
        let bad = "listen is not an IP address and port";
        for text in [
            "localhost:8080",
            "127.0.0.1",
            "",
            "127.0.0.1:65536",
            ":80",
            "[::1]",
        ] {
            refuse(&[p("listen", text)], bad);
        }
        pass(&[p("listen", "127.0.0.1:65535")]);
        pass(&[p("listen", "[::1]:8080")]);
        refuse(&[p("listen", "127.0.0.1:0")], "listen port is 0");
        pass(&[p("listen", "127.0.0.1:1")]);

        let bad = "upstream is not an IP address and port";
        for text in ["example.com:80", "127.0.0.1", "", "127.0.0.1:65536"] {
            refuse(&[p("upstream", text)], bad);
        }
        pass(&[p("upstream", "[2001:db8::1]:65535")]);
        refuse(&[p("upstream", "127.0.0.1:0")], "upstream port is 0");
        pass(&[p("upstream", "127.0.0.1:1")]);

        let same = "listen and upstream are the same address";
        refuse(&[p("upstream", "127.0.0.1:8080")], same);
        refuse(&[p("upstream", "[::ffff:127.0.0.1]:8080")], same);
        refuse(&[p("listen", "[::1]:80"), p("upstream", "[::1]:80")], same);
        pass(&[p("upstream", "127.0.0.1:8081")]);
        pass(&[p("upstream", "127.0.0.2:8080")]);
        pass(&[p("listen", "[::1]:9000"), p("upstream", "127.0.0.1:9000")]);
    }

    #[test]
    fn counts_and_sizes_are_inside_their_bounds() {
        let out = |key: &str| format!("{key} is out of range");
        // key, lowest passing value, highest passing value
        for (key, low, high) in [
            ("max_head_bytes", 1024, 32768),
            ("upstream_max_headers", 1, 1024),
        ] {
            pass(&[p(key, low)]);
            pass(&[p(key, high)]);
            refuse(&[p(key, low - 1)], &out(key));
            refuse(&[p(key, high + 1)], &out(key));
        }

        // max_conns: 1 to 65536. The lowest value needs a wait_queue of 1 (checked as a relation below).
        let key = "max_conns";
        refuse(&[p(key, 0)], &out(key));
        pass(&[p(key, 1), k("wait_queue", 1)]);
        pass(&[p(key, 65536)]);
        refuse(&[p(key, 65537)], &out(key));

        let key = "max_body";
        refuse(
            &[p(key, (1u64 << 20) + 1)],
            "max_body is above the body limit",
        );
        pass(&[p(key, 1u64 << 20)]);
        pass(&[p(key, 0)]);

        // max_body_wire: from max_body (1 MiB here) to 4 MiB.
        let key = "max_body_wire";
        refuse(&[p(key, (1u64 << 20) - 1)], &out(key));
        pass(&[p(key, 1u64 << 20)]);
        pass(&[p(key, 4u64 << 20)]);
        refuse(&[p(key, (4u64 << 20) + 1)], &out(key));
        pass(&[p("max_body", 100), p(key, 100)]);
        refuse(&[p("max_body", 100), p(key, 99)], &out(key));

        // max_buffered_bytes: from 2 * max_body + 24 KiB to 4 GiB.
        let key = "max_buffered_bytes";
        let least = 2 * (1u64 << 20) + 24 * 1024;
        refuse(&[p(key, least - 1)], &out(key));
        pass(&[p(key, least)]);
        pass(&[p(key, 4u64 << 30)]);
        refuse(&[p(key, (4u64 << 30) + 1)], &out(key));
        pass(&[
            p("max_body", 1000),
            p("max_body_wire", 1000),
            p(key, 2000 + 24 * 1024),
        ]);
        refuse(
            &[
                p("max_body", 1000),
                p("max_body_wire", 1000),
                p(key, 2000 + 24 * 1024 - 1),
            ],
            &out(key),
        );

        let key = "upstream_max_head_bytes";
        refuse(&[p(key, 8191)], &out(key));
        pass(&[p(key, 8192)]);
        pass(&[p(key, 1u64 << 20), p("upstream_head_wire", 2u64 << 20)]);
        refuse(&[p(key, (1u64 << 20) + 1)], &out(key));

        // upstream_head_wire: from 2 * max(8192, upstream_max_head_bytes) to 4 MiB.
        let key = "upstream_head_wire";
        refuse(&[p(key, 32767)], &out(key));
        pass(&[p(key, 32768)]);
        pass(&[p(key, 4u64 << 20)]);
        refuse(&[p(key, (4u64 << 20) + 1)], &out(key));
        pass(&[p("upstream_max_head_bytes", 8192), p(key, 16384)]);
        refuse(
            &[p("upstream_max_head_bytes", 8192), p(key, 16383)],
            &out(key),
        );
    }

    #[test]
    fn every_proxy_time_is_between_1_ms_and_3600_s() {
        for key in [
            "drive_slice_ms",
            "ready_wait_ms",
            "head_read_ms",
            "body_read_ms",
            "inspect_wait_ms",
            "upstream_connect_ms",
            "upstream_header_ms",
            "request_total_ms",
            "response_idle_ms",
            "conn_total_ms",
            "stop_inspect_ms",
            "stop_wait_ms",
        ] {
            let sentence = format!("{key} is out of range");
            refuse(&[p(key, 0)], &sentence);
            refuse(&[p(key, 3_600_001)], &sentence);
            refuse(&[p(key, -1)], "configuration has a value of the wrong type");
        }
        pass(&[
            p("drive_slice_ms", 1),
            p("head_read_ms", 1),
            p("body_read_ms", 1),
            p("upstream_connect_ms", 1),
            p("upstream_header_ms", 1),
            p("response_idle_ms", 1),
            p("stop_inspect_ms", 1),
        ]);
        pass(&[
            p("ready_wait_ms", 3_600_000),
            p("head_read_ms", 3_600_000),
            p("body_read_ms", 3_600_000),
            p("inspect_wait_ms", 3_600_000),
            p("upstream_connect_ms", 3_600_000),
            p("upstream_header_ms", 3_600_000),
            p("request_total_ms", 3_600_000),
            p("response_idle_ms", 3_600_000),
            p("conn_total_ms", 3_600_000),
            p("stop_inspect_ms", 3_598_000),
            p("stop_wait_ms", 3_600_000),
        ]);
    }

    #[test]
    fn the_kernel_object_is_converted_and_checked_by_the_kernel() {
        let bad = "rules_sha256 is not 64 lowercase hex digits";
        let hex = "0123456789abcdef".repeat(4);
        pass(&[k("rules_sha256", hex.as_str())]);
        refuse(&[k("rules_sha256", &hex[..63])], bad);
        refuse(&[k("rules_sha256", format!("{hex}0"))], bad);
        refuse(&[k("rules_sha256", hex.to_uppercase())], bad);
        refuse(&[k("rules_sha256", format!("{}g", &hex[..63]))], bad);
        refuse(&[k("rules_sha256", "")], bad);
        refuse(&[k("rules_sha256", "é".repeat(32))], bad);

        // The kernel's own sentences come through unchanged.
        refuse(
            &[k("inspector", "inspector")],
            "inspector path is not an absolute clean path",
        );
        refuse(
            &[k("rules", "/a/../b")],
            "rules path is not an absolute clean path",
        );
        refuse(
            &[k("tmp_root", "/tmp/")],
            "tmp_root is not an absolute clean UTF-8 path",
        );
        refuse(&[k("gomaxprocs", 0)], "gomaxprocs is 0");
        refuse(&[k("gomemlimit", 0)], "gomemlimit is out of range");
        pass(&[k("gomemlimit", i64::MAX)]);
        refuse(&[k("gomemlimit", u64::MAX)], "gomemlimit is out of range");
        refuse(&[k("slots", 0)], "slots is out of range");
        refuse(&[k("slots", 5)], "slots is out of range");
        refuse(&[k("wait_queue", 0)], "wait_queue is 0");
        refuse(
            &[k("records", 19)],
            "records is below slots plus wait_queue",
        );
        pass(&[k("records", 20)]);
        refuse(
            &[k("discard_limit", u32::MAX)],
            "discard_limit must be below u32::MAX",
        );
        refuse(&[k("tick_ms", 0)], "tick is out of range");
        refuse(&[k("tick_ms", 3_600_001)], "tick is out of range");
        refuse(&[k("hello_wait_ms", 0)], "hello_wait is out of range");
        refuse(
            &[k("kill_grace_ms", 3_600_001)],
            "kill_grace is out of range",
        );
        // A kernel fault is reported before a relation that the same value would also break.
        refuse(
            &[k("tick_ms", 1001), p("drive_slice_ms", 2000)],
            "tick is above the longest tick",
        );
    }

    #[test]
    fn each_relation_between_the_two_objects_has_a_boundary() {
        // drive_slice <= tick (100 ms)
        refuse(
            &[p("drive_slice_ms", 101)],
            "drive_slice_ms is above the kernel tick",
        );
        pass(&[p("drive_slice_ms", 100)]);
        // ready_wait >= hello_wait (5000 ms)
        refuse(
            &[p("ready_wait_ms", 4999)],
            "ready_wait_ms is below the kernel hello_wait",
        );
        pass(&[p("ready_wait_ms", 5000)]);
        // head_read, body_read, upstream_connect, upstream_header <= request_total (60000 ms)
        for key in [
            "head_read_ms",
            "body_read_ms",
            "upstream_connect_ms",
            "upstream_header_ms",
        ] {
            let sentence = format!("{key} is above request_total_ms");
            refuse(&[p(key, 60001)], &sentence);
            pass(&[p(key, 60000)]);
        }
        // request_total, response_idle <= conn_total (120000 ms)
        refuse(
            &[p("request_total_ms", 120_001)],
            "request_total_ms is above conn_total_ms",
        );
        pass(&[p("request_total_ms", 120_000)]);
        refuse(
            &[p("response_idle_ms", 120_001)],
            "response_idle_ms is above conn_total_ms",
        );
        pass(&[p("response_idle_ms", 120_000)]);
        // stop_inspect < stop_wait, stop_wait > stop_inspect + kill_grace (5000 + 1000 ms)
        let below = "stop_inspect_ms is not below stop_wait_ms";
        let plus = "stop_wait_ms is not above stop_inspect_ms plus kill_grace";
        refuse(&[p("stop_wait_ms", 4999)], below);
        refuse(&[p("stop_wait_ms", 5000)], below);
        refuse(&[p("stop_wait_ms", 5001)], plus);
        refuse(&[p("stop_wait_ms", 6000)], plus);
        pass(&[p("stop_wait_ms", 6001)]);
        refuse(&[k("kill_grace_ms", 5000)], plus);
        pass(&[k("kill_grace_ms", 4999)]);
        // wait_queue (16) <= max_conns
        let queue = "wait_queue is above max_conns";
        refuse(&[p("max_conns", 15)], queue);
        pass(&[p("max_conns", 16)]);
        refuse(
            &[p("max_conns", 16), k("wait_queue", 17), k("records", 21)],
            queue,
        );
        pass(&[p("max_conns", 1), k("wait_queue", 1)]);
        refuse(&[p("max_conns", 1), k("wait_queue", 2)], queue);
        // At the top of max_conns (65536) the queue is held to the same value.
        let top = |wait_queue: u64| {
            [
                p("max_conns", 65536),
                k("wait_queue", wait_queue),
                k("records", 65541),
            ]
        };
        pass(&top(65536));
        refuse(&top(65537), queue);
        // The kernel's own checks come first: a queue of 0 and a short records are not this relation.
        refuse(&[p("max_conns", 16), k("wait_queue", 0)], "wait_queue is 0");
        refuse(
            &[p("max_conns", 16), k("wait_queue", 17)],
            "records is below slots plus wait_queue",
        );
    }

    #[test]
    fn inspect_wait_covers_the_kernel_time_for_one_inspection() {
        // wait_deadline + 2 * verdict_wait + 18 * (drive_slice + frame_io)
        // = 3000 + 2 * 2000 + 18 * (50 + 1000) = 25900 ms
        let low = "inspect_wait_ms is below the kernel inspection time";
        refuse(&[p("inspect_wait_ms", 25899)], low);
        pass(&[p("inspect_wait_ms", 25900)]);
        let at = p("inspect_wait_ms", 25900);
        refuse(&[at.clone(), k("wait_deadline_ms", 3001)], low);
        refuse(&[at.clone(), k("verdict_wait_ms", 2001)], low);
        refuse(&[at.clone(), k("frame_io_ms", 1001)], low);
        refuse(&[at.clone(), p("drive_slice_ms", 51)], low);
        pass(&[at.clone(), k("wait_deadline_ms", 3000)]);
        pass(&[at, k("wait_deadline_ms", 2999)]);
        // The same value cannot also exceed request_total (60000 ms).
        refuse(
            &[p("inspect_wait_ms", 60001)],
            "inspect_wait_ms is above request_total_ms",
        );
        pass(&[p("inspect_wait_ms", 60000)]);

        let kernel = parse(BASE.as_bytes()).unwrap().kernel;
        let slice = Duration::from_millis(50);
        assert_eq!(
            inspect_floor(&kernel, slice),
            Some(Duration::from_millis(25900))
        );
        assert_eq!(inspect_floor(&kernel, Duration::MAX), None);
        let mut huge = kernel.clone();
        huge.verdict_wait = Duration::MAX;
        assert_eq!(inspect_floor(&huge, slice), None);
        let mut huge = kernel;
        huge.wait_deadline = Duration::MAX;
        assert_eq!(inspect_floor(&huge, slice), None);
    }

    fn scratch() -> PathBuf {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "tukuyomi-proxy-config-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        dir
    }

    #[test]
    fn load_reads_a_regular_file_of_at_most_64_kib() {
        let dir = scratch();
        let file = dir.join("config.json");
        fs::write(&file, BASE).unwrap();
        assert!(load(&file).is_ok());

        fs::write(&file, format!("{BASE}{}", " ".repeat(65536 - BASE.len()))).unwrap();
        assert!(load(&file).is_ok());
        fs::write(&file, format!("{BASE}{}", " ".repeat(65537 - BASE.len()))).unwrap();
        assert_eq!(
            load(&file).err(),
            Some(ConfigError("configuration file is over 64 KiB"))
        );

        assert_eq!(
            load(&dir.join("absent.json")).err(),
            Some(ConfigError("configuration file cannot be read"))
        );
        assert_eq!(
            load(&dir).err(),
            Some(ConfigError("configuration file is not a regular file"))
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
