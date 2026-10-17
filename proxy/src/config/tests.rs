use super::*;
use serde_json::Value;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::sync::atomic::{AtomicU32, Ordering};

const BASE: &str = r#"{"proxy":{"listen":"127.0.0.1:8080","upstream":"127.0.0.1:9000","max_conns":1024,"max_head_bytes":8192,"max_body":1048576,"max_body_wire":2097152,"max_buffered_bytes":8388608,"upstream_max_headers":100,"upstream_max_head_bytes":16384,"upstream_head_wire":65536,"drive_slice_ms":50,"ready_wait_ms":10000,"head_read_ms":10000,"body_read_ms":30000,"inspect_wait_ms":30000,"upstream_connect_ms":5000,"upstream_header_ms":30000,"request_total_ms":60000,"response_idle_ms":30000,"conn_total_ms":120000,"stop_inspect_ms":5000,"stop_wait_ms":10000},"kernel":{"inspector":"/opt/tukuyomi/inspector","tmp_root":"/var/lib/tukuyomi/tmp","gomaxprocs":2,"gomemlimit":1073741824,"slots":4,"wait_queue":16,"records":20,"discard_limit":4,"tick_ms":100,"hello_wait_ms":5000,"frame_io_ms":1000,"verdict_wait_ms":2000,"wait_deadline_ms":3000,"closed_wait_ms":2000,"stop_after_ms":2000,"drain_wait_ms":1000,"exit_wait_ms":1000,"kill_grace_ms":1000,"restarts":3,"restart_window_ms":60000},"rules":{"store":{"kind":"file","dir":"/var/lib/tukuyomi/rules"}}}"#;

/// Marks a value that must never appear in an error sentence.
const MARK: &str = "qqmark";

/// Where in the document (a JSON pointer to an object), the key, and the new value.
type Edit = (&'static str, &'static str, Value);

fn p(key: &'static str, value: impl Into<Value>) -> Edit {
    ("/proxy", key, value.into())
}

fn k(key: &'static str, value: impl Into<Value>) -> Edit {
    ("/kernel", key, value.into())
}

fn s(key: &'static str, value: impl Into<Value>) -> Edit {
    ("/rules/store", key, value.into())
}

fn base() -> Value {
    serde_json::from_str(BASE).unwrap()
}

fn doc(edits: &[Edit]) -> Vec<u8> {
    let mut value = base();
    for (at, key, new) in edits {
        value.pointer_mut(at).unwrap()[*key] = new.clone();
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
    let (proxy, kernel) = (&loaded.proxy, &loaded.kernel.0);
    assert_eq!(proxy.listen, "127.0.0.1:8080".parse().unwrap());
    assert_eq!(proxy.upstream, "127.0.0.1:9000".parse().unwrap());
    assert_eq!(proxy.max_buffered_bytes, 8 << 20);
    assert_eq!(proxy.drive_slice, Duration::from_millis(50));
    assert_eq!(proxy.stop_wait, Duration::from_millis(10_000));
    assert_eq!(kernel.inspector, PathBuf::from("/opt/tukuyomi/inspector"));
    // The directory and the fingerprint of a generation are not in the file: the check ran with placeholders.
    assert_eq!(
        kernel.rules,
        PathBuf::from("/var/lib/tukuyomi/rules/generations")
    );
    assert_eq!(kernel.rules_sha256, [0; 32]);
    assert_eq!(kernel.tick, Duration::from_millis(100));
    assert_eq!((kernel.discard_limit, kernel.restarts), (4, 3));
    assert_eq!(
        loaded.store,
        StoreConfig::File {
            dir: PathBuf::from("/var/lib/tukuyomi/rules")
        }
    );
}

#[test]
fn the_file_is_at_most_64_kib_and_utf8() {
    let at_limit = format!("{BASE}{}", " ".repeat(65536 - BASE.len()));
    assert!(parse(at_limit.as_bytes()).is_ok());
    refuse_text(&format!("{at_limit} "), "configuration file is over 64 KiB");

    let mut bytes = BASE
        .replace("/opt/tukuyomi/inspector", "/opt/qqmark")
        .into_bytes();
    let at = bytes.windows(6).position(|w| w == MARK.as_bytes()).unwrap();
    bytes[at] = 0xff;
    assert_eq!(
        parse(&bytes).err(),
        Some(ConfigError("configuration file is not UTF-8"))
    );
}

#[test]
fn broken_json_is_refused_with_one_sentence() {
    let sentence = "configuration is not valid JSON";
    for text in ["", "{", "{'proxy':{}}"] {
        refuse_text(text, sentence);
    }
    refuse_text(&format!("{BASE} x"), sentence);
    refuse_text(&BASE[..BASE.len() - 1], sentence);
}

#[test]
fn a_missing_key_is_refused_in_every_object() {
    let sentence = "configuration has a missing key";
    refuse_text("{}", sentence);
    for (parent, name) in [
        ("", "rules"),
        ("/rules", "store"),
        ("/proxy", "max_conns"),
        ("/kernel", "tick_ms"),
        ("/rules/store", "dir"),
    ] {
        let mut value = base();
        let object = if parent.is_empty() {
            &mut value
        } else {
            value.pointer_mut(parent).unwrap()
        };
        object.as_object_mut().unwrap().remove(name);
        refuse_text(&value.to_string(), sentence);
    }
}

#[test]
fn an_unknown_key_is_refused_in_every_object() {
    let sentence = "configuration has an unknown key";
    let mut value = base();
    value["qqmark"] = Value::from(1);
    refuse_text(&value.to_string(), sentence);
    refuse(&[p("qqmark", 1)], sentence);
    refuse(&[k("qqmark", 1)], sentence);
    // The kernel object has no rules path and no fingerprint: they come from the rules store.
    refuse(&[k("rules", "/etc/tukuyomi/rules")], sentence);
    refuse(&[k("rules_sha256", "0123456789abcdef".repeat(4))], sentence);
}

#[test]
fn a_repeated_key_is_refused_even_with_the_same_value() {
    refuse_text(
        &BASE.replacen("\"proxy\":{", "\"proxy\":{\"max_conns\":1024,", 1),
        "configuration has a repeated key",
    );
}

#[test]
fn a_value_of_the_wrong_type_is_refused_for_every_key() {
    let sentence = "configuration has a value of the wrong type";
    for (path, key, wrong) in [
        ("/proxy", "listen", Value::from(5)),
        ("/proxy", "max_conns", Value::from("5")),
        ("/kernel", "tick_ms", Value::Null),
        ("/rules/store", "dir", Value::from(true)),
    ] {
        let mut value = base();
        value.pointer_mut(path).unwrap()[key] = wrong;
        refuse_text(&value.to_string(), sentence);
    }
    // A number of the right kind but outside the type, a fraction, a negative count.
    refuse(&[k("gomaxprocs", 65536)], sentence);
    refuse(&[p("max_conns", 5.0)], sentence);
    refuse(&[p("max_conns", -1)], sentence);
    pass(&[k("gomaxprocs", 65535)]);
}

#[test]
fn an_array_never_stands_in_for_an_object() {
    let sentence = "configuration has a value of the wrong type";
    for path in ["/proxy", "/rules/store"] {
        let mut positional = base();
        let values: Vec<Value> = base()
            .pointer(path)
            .unwrap()
            .as_object()
            .unwrap()
            .values()
            .cloned()
            .collect();
        *positional.pointer_mut(path).unwrap() = Value::Array(values);
        refuse_text(&positional.to_string(), sentence);
    }
    refuse_text("null", sentence);
}

#[test]
fn errors_never_carry_a_value_or_a_key_from_the_file() {
    let mut cases: Vec<Vec<u8>> = vec![
        doc(&[p("listen", MARK)]),
        doc(&[p("max_conns", MARK)]),
        doc(&[p(MARK, 1)]),
        doc(&[k("inspector", MARK)]),
        doc(&[k("tmp_root", MARK)]),
        format!("{BASE}{MARK}").into_bytes(),
        format!("{{\"{MARK}\":1,\"{MARK}\":2}}").into_bytes(),
    ];
    let mut not_utf8 = MARK.as_bytes().to_vec();
    not_utf8.push(0xff);
    cases.push(not_utf8);
    for case in &cases {
        let e = parse(case).expect_err("every case is refused");
        assert!(!e.0.contains(MARK), "{}", e.0);
        assert!(e.0.is_ascii() && e.0.len() < 80, "{}", e.0);
    }
}

#[test]
fn addresses_are_ip_literals_with_a_port_and_differ() {
    let bad = "listen is not an IP address and port";
    for text in ["localhost:8080", "127.0.0.1", "127.0.0.1:65536"] {
        refuse(&[p("listen", text)], bad);
    }
    pass(&[p("listen", "127.0.0.1:65535")]);
    pass(&[p("listen", "[::1]:8080")]);
    refuse(&[p("listen", "127.0.0.1:0")], "listen port is 0");
    refuse(
        &[p("upstream", "example.com:80")],
        "upstream is not an IP address and port",
    );
    refuse(&[p("upstream", "127.0.0.1:0")], "upstream port is 0");

    let same = "listen and upstream are the same address";
    refuse(&[p("upstream", "127.0.0.1:8080")], same);
    refuse(&[p("upstream", "[::ffff:127.0.0.1]:8080")], same);
    pass(&[p("upstream", "127.0.0.1:8081")]);
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

    refuse(
        &[p("max_body", (1u64 << 20) + 1)],
        "max_body is above the body limit",
    );
    pass(&[p("max_body", 1u64 << 20)]);

    // max_body_wire: from max_body (1 MiB here) to 4 MiB.
    let key = "max_body_wire";
    refuse(&[p(key, (1u64 << 20) - 1)], &out(key));
    pass(&[p(key, 1u64 << 20)]);
    pass(&[p(key, 4u64 << 20)]);
    refuse(&[p(key, (4u64 << 20) + 1)], &out(key));

    // max_buffered_bytes: from 2 * max_body + 24 KiB to 4 GiB.
    let key = "max_buffered_bytes";
    let least = 2 * (1u64 << 20) + 24 * 1024;
    refuse(&[p(key, least - 1)], &out(key));
    pass(&[p(key, least)]);
    pass(&[p(key, 4u64 << 30)]);
    refuse(&[p(key, (4u64 << 30) + 1)], &out(key));

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
    }
    pass(&[p("drive_slice_ms", 1), p("response_idle_ms", 1)]);
    pass(&[
        p("ready_wait_ms", 3_600_000),
        p("inspect_wait_ms", 3_600_000),
        p("request_total_ms", 3_600_000),
        p("conn_total_ms", 3_600_000),
        p("stop_wait_ms", 3_600_000),
    ]);
}

#[test]
fn the_kernel_object_is_converted_and_checked_by_the_kernel() {
    // The kernel's own sentences come through unchanged.
    refuse(
        &[k("inspector", "inspector")],
        "inspector path is not an absolute clean path",
    );
    refuse(&[k("slots", 5)], "slots is out of range");
    refuse(
        &[k("records", 19)],
        "records is below slots plus wait_queue",
    );
    pass(&[k("records", 20)]);
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
        refuse(
            &[p(key, 60001)],
            &format!("{key} is above request_total_ms"),
        );
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
    // stop_inspect < stop_wait, stop_wait > stop_inspect + kill_grace (5000 + 1000 ms)
    let below = "stop_inspect_ms is not below stop_wait_ms";
    let plus = "stop_wait_ms is not above stop_inspect_ms plus kill_grace";
    refuse(&[p("stop_wait_ms", 5000)], below);
    refuse(&[p("stop_wait_ms", 6000)], plus);
    pass(&[p("stop_wait_ms", 6001)]);
    // wait_queue (16) <= max_conns
    let queue = "wait_queue is above max_conns";
    refuse(&[p("max_conns", 15)], queue);
    pass(&[p("max_conns", 16)]);
    // The kernel's own checks come first: a queue of 0 is not this relation.
    refuse(&[p("max_conns", 16), k("wait_queue", 0)], "wait_queue is 0");
}

#[test]
fn inspect_wait_covers_the_kernel_time_for_one_inspection() {
    // wait_deadline + 2 * verdict_wait + 18 * (drive_slice + frame_io)
    // = 3000 + 2 * 2000 + 18 * (50 + 1000) = 25900 ms
    let low = "inspect_wait_ms is below the kernel inspection time";
    refuse(&[p("inspect_wait_ms", 25899)], low);
    pass(&[p("inspect_wait_ms", 25900)]);
    refuse(
        &[p("inspect_wait_ms", 25900), k("wait_deadline_ms", 3001)],
        low,
    );
    // The same value cannot also exceed request_total (60000 ms).
    refuse(
        &[p("inspect_wait_ms", 60001)],
        "inspect_wait_ms is above request_total_ms",
    );
    pass(&[p("inspect_wait_ms", 60000)]);

    let kernel = parse(BASE.as_bytes()).unwrap().kernel.0;
    assert_eq!(inspect_floor(&kernel, Duration::MAX), None);
}

/// A fresh 0700 directory under the temp directory (`TMPDIR`), removed with everything in it when dropped.
struct TestDir(PathBuf);

impl TestDir {
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn scratch() -> TestDir {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "tukuyomi-proxy-config-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    // A umask can only remove bits; make the mode exactly 0700.
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    TestDir(dir)
}

#[test]
fn load_reads_a_regular_file_of_at_most_64_kib() {
    let dir = scratch();
    let file = dir.path().join("config.json");
    fs::write(&file, format!("{BASE}{}", " ".repeat(65536 - BASE.len()))).unwrap();
    assert!(load(&file).is_ok());
    fs::write(&file, format!("{BASE}{}", " ".repeat(65537 - BASE.len()))).unwrap();
    assert_eq!(
        load(&file).err(),
        Some(ConfigError("configuration file is over 64 KiB"))
    );

    assert_eq!(
        load(&dir.path().join("absent.json")).err(),
        Some(ConfigError("configuration file cannot be read"))
    );
    assert_eq!(
        load(dir.path()).err(),
        Some(ConfigError("configuration file is not a regular file"))
    );
}

#[test]
fn the_rules_store_kind_is_file_and_nothing_else() {
    pass(&[s("kind", "file")]);
    refuse(&[s("kind", "db")], "rules store kind is not supported");
}

#[test]
fn the_rules_store_dir_is_an_absolute_clean_path() {
    pass(&[s("dir", "/a")]);
    refuse(
        &[s("dir", "rules")],
        "rules store dir is not an absolute clean path",
    );
}

#[test]
fn the_rules_store_dir_is_at_most_3840_bytes() {
    let at = format!("/{}", "a".repeat(3839));
    pass(&[s("dir", at.as_str())]);
    refuse(
        &[s("dir", format!("{at}a"))],
        "rules store dir is over 3840 bytes",
    );
}

#[test]
fn a_generation_completes_the_kernel_values_and_is_checked_again() {
    let loaded = parse(BASE.as_bytes()).unwrap();
    let generation = Fingerprint::from_hex("0123456789abcdef".repeat(4).as_bytes()).unwrap();
    let dir = PathBuf::from(format!(
        "/var/lib/tukuyomi/rules/generations/{}",
        generation.hex()
    ));
    let kernel = loaded
        .kernel
        .for_generation(dir.clone(), generation)
        .unwrap();
    assert_eq!(kernel.rules, dir);
    assert_eq!(kernel.rules_sha256, generation.bytes());
    // The kernel checks the directory again: a relative one is refused.
    let result = loaded
        .kernel
        .for_generation(PathBuf::from("rules"), generation);
    assert_eq!(
        result.err(),
        Some(ConfigError("rules path is not an absolute clean path"))
    );
}
