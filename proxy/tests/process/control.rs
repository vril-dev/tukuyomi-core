//! The control socket in a real process: the `admin` object is added to the configuration of the test with the socket
//! in a directory of its own in the root of the test (the directory of the socket may hold no other place of the
//! configuration), and the `status` object, so that `/metrics` can be read.

use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use serde_json::{Value, json};

use crate::rules::rules;
use crate::support::*;

/// The control socket of the proxy in `root`.
fn socket(root: &Path) -> PathBuf {
    root.join("ctl").join("c.sock")
}

/// Adds the `status` object at `status_port`, if there is one, and the `admin` object to the configuration in `root`.
/// The directory of the socket is made.
fn add_admin(root: &Path, status_port: Option<u16>) {
    if let Some(port) = status_port {
        add_object(
            root,
            "status",
            json!({ "listen": format!("127.0.0.1:{port}") }),
        );
    }
    fs::DirBuilder::new()
        .mode(0o700)
        .create(root.join("ctl"))
        .expect("make the directory of the socket");
    add_object(
        root,
        "admin",
        json!({
            "listen": format!("127.0.0.1:{}", free_port()),
            "control": socket(root).to_string_lossy(),
            "store": {"kind": "file", "dir": root.join("admin").to_string_lossy()},
            "origin": "https://admin.example.test",
            "trusted_proxies": [],
            "mfa": "optional",
            "session_idle_ms": 1_800_000,
            "session_total_ms": 43_200_000,
        }),
    );
}

/// Sends `request` to the control socket in `root` and reads the one line of the answer, until the proxy closes.
fn ask(root: &Path, request: &str) -> Value {
    let mut sock = UnixStream::connect(socket(root)).expect("connect to the control socket");
    sock.set_read_timeout(Some(MARGIN * 6))
        .expect("set the read time");
    sock.write_all(request.as_bytes())
        .expect("send the request");
    let mut out = String::new();
    sock.read_to_string(&mut out).expect("read the answer");
    assert_eq!(out.matches('\n').count(), 1, "answer: {out:?}");
    serde_json::from_str(&out).expect("the answer is a line of JSON")
}

fn switch(root: &Path, expect: &str) -> Value {
    ask(
        root,
        &format!("{{\"op\":\"switch\",\"expect\":\"{expect}\"}}\n"),
    )
}

/// The page of `/metrics`.
fn metrics(port: u16) -> String {
    let reply = exchange(port, &get("/metrics"));
    String::from_utf8(reply.message().body.clone()).expect("the page is text")
}

fn has_line(text: &str, line: &str) -> bool {
    text.lines().any(|have| have == line)
}

/// Imports a second generation (the test rules and one more, which blocks `/reload-probe`) and chooses it. Returns
/// its fingerprint.
fn choose_second(root: &Path) -> String {
    let extra = root.join("extra.conf");
    fs::write(
        &extra,
        "SecRule REQUEST_URI \"@beginsWith /reload-probe\" \"id:9204,phase:1,deny,status:403,log,msg:'reload probe'\"\n",
    )
    .expect("write the rule file");
    let basic = rules_file();
    let imported = rules(
        root,
        "import",
        &[
            OsStr::new("--rules"),
            basic.as_os_str(),
            OsStr::new("--rules"),
            extra.as_os_str(),
        ],
    );
    assert_eq!(imported.code, Some(0), "{}", imported.err);
    let second = imported
        .out
        .strip_suffix(" created\n")
        .unwrap_or_else(|| panic!("unexpected output {:?}", imported.out))
        .to_owned();
    assert_ne!(second, generation());
    fs::remove_file(&extra).expect("remove the rule file");
    let chosen = rules(root, "activate", &[OsStr::new(&second)]);
    assert_eq!(chosen.code, Some(0), "{}", chosen.err);
    second
}

/// Ends the test of a proxy that has a control socket: SIGTERM, and the file of the socket is gone before the proxy has
/// exited. The directory of the socket is empty then and is removed, so that the root holds what `finish` wants.
fn finish(proxy: Proxy, upstream_connections: usize) {
    let root = proxy.root().to_path_buf();
    let since = proxy.term();
    let deadline = Instant::now() + MARGIN;
    while fs::symlink_metadata(socket(&root)).is_ok() {
        assert!(Instant::now() < deadline, "the socket is still there");
        std::thread::sleep(10 * MS);
    }
    fs::remove_dir(root.join("ctl")).expect("the directory of the socket is empty");
    let counts = proxy.finish_after_term(since, upstream_connections);
    assert_eq!(counts, [0, 0, 0], "the kernel held something at the stop");
}

#[test]
#[ignore = "needs a built inspector"]
fn the_control_socket_has_mode_0600_and_switches_only_to_the_generation_that_is_expected() {
    let status_port = free_port();
    let mut proxy = Proxy::start_with("ctl_switch", Knobs::quick(), |root| {
        add_admin(root, Some(status_port));
    });
    let root = proxy.root().to_path_buf();
    let meta = fs::symlink_metadata(socket(&root)).expect("the socket is there");
    assert!(meta.file_type().is_socket());
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);

    let first = generation();
    let status = |generation: &str| json!({"generation": generation, "mode": "block", "engine": "coraza", "phase": "ready", "switching": false, "ready": true});
    assert_eq!(ask(&root, "{\"op\":\"status\"}\n"), status(&first));
    assert_eq!(exchange(proxy.port, &get("/reload-probe")).status(), 200);

    // The store chooses the second generation; the one that runs does not change by that.
    let second = choose_second(&root);
    assert_eq!(ask(&root, "{\"op\":\"status\"}\n"), status(&first));

    // An order that expects another generation than the one the store chooses changes nothing.
    let changed = |serving: &str| json!({"result": "refused", "reason": "current changed", "generation": serving});
    assert_eq!(switch(&root, &first), changed(&first));
    let page = metrics(status_port);
    for result in ["switched", "refused", "failed"] {
        let line = format!("tukuyomi_rules_switches_total{{result=\"{result}\"}} 0");
        assert!(has_line(&page, &line), "{line} in {page}");
    }
    assert_eq!(exchange(proxy.port, &get("/reload-probe")).status(), 200);

    // The order that expects it switches, and is answered when the switch has ended.
    let before = proxy.inspector();
    assert_eq!(
        switch(&root, &second),
        json!({"result": "switched", "generation": second})
    );
    proxy.wait_inspector(Some(before));
    assert_eq!(ask(&root, "{\"op\":\"status\"}\n"), status(&second));
    let page = metrics(status_port);
    for line in [
        "tukuyomi_rules_switches_total{result=\"switched\"} 1".to_string(),
        "tukuyomi_rules_switches_total{result=\"refused\"} 0".to_string(),
        format!(
            "tukuyomi_rules_generation_info{{generation=\"{}\",mode=\"block\",engine=\"coraza\"}} 1",
            &second[..16]
        ),
        "tukuyomi_record_file_errors_total 0".to_string(),
    ] {
        assert!(has_line(&page, &line), "{line} in {page}");
    }
    assert_eq!(exchange(proxy.port, &get("/reload-probe")).status(), 403);
    assert_eq!(exchange(proxy.port, &get("/ok")).status(), 200);
    let line = format!("control: switch expect {second}: switched, serving {second}");
    proxy
        .records
        .wait_lines("the record of the switch", 1, |l| l == line);

    // The store chooses what runs: nothing is switched. Another expectation is not met.
    assert_eq!(
        switch(&root, &second),
        json!({"result": "unchanged", "reason": "already serving", "generation": second})
    );
    assert_eq!(switch(&root, &first), changed(&second));
    assert_eq!(
        ask(&root, "{\"op\":\"nothing\"}\n"),
        json!({"result": "error", "reason": "unknown op"})
    );
    // The socket goes with the proxy, and nothing but the configuration and the store is left in the root.
    finish(proxy, 3);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_second_proxy_on_the_same_configuration_does_not_take_the_socket_of_a_running_one() {
    // No `status` object: the second proxy would end at its address before it came to the socket.
    let proxy = Proxy::start_with("ctl_second", Knobs::quick(), |root| {
        add_admin(root, None);
    });
    let root = proxy.root().to_path_buf();
    let before = fs::symlink_metadata(socket(&root)).expect("the socket is there");
    let second = Command::new(env!("CARGO_BIN_EXE_tukuyomi-proxy"))
        .arg(root.join("config.json"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .env_remove("NOTIFY_SOCKET")
        .output()
        .expect("run the second proxy");
    let text = String::from_utf8_lossy(&second.stderr).into_owned();
    assert_eq!(second.status.code(), Some(1), "its records: {text}");
    assert!(
        text.contains(
            "start: control socket refused: the control socket is in use by another process"
        ),
        "its records: {text}"
    );
    assert!(!text.contains("kernel"), "its records: {text}");
    // The running proxy has its socket still, the same file, and answers on it.
    let after = fs::symlink_metadata(socket(&root)).expect("the socket is still there");
    assert_eq!(
        (after.dev(), after.ino()),
        (before.dev(), before.ino()),
        "the socket was replaced"
    );
    assert_eq!(
        ask(&root, "{\"op\":\"status\"}\n"),
        json!({"generation": generation(), "mode": "block", "engine": "coraza", "phase": "ready", "switching": false, "ready": true})
    );
    finish(proxy, 0);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_control_socket_path_that_holds_a_file_ends_the_start_before_the_inspector_runs() {
    let mut proxy = Proxy::spawn_with("ctl_taken", Knobs::quick(), |root| {
        add_admin(root, Some(free_port()));
        fs::write(socket(root), b"not a socket").expect("put a file in the place of the socket");
    });
    let started = proxy.started;
    let (status, _) = proxy.wait_exit(started, MARGIN);
    let lines = proxy.records.lines();
    assert_eq!(
        status.code(),
        Some(1),
        "exit status {status}; records: {lines:#?}"
    );
    assert_eq!(
        lines.last().map(String::as_str),
        Some(
            "start: control socket refused: something other than a socket of this user is at the path"
        ),
        "records: {lines:#?}"
    );
    assert!(
        !lines
            .iter()
            .any(|l| l.contains("kernel") || l.starts_with("stop")),
        "records: {lines:#?}"
    );
    // No inspector was started, and the file was not touched.
    assert_turned_away(proxy.port);
    assert_eq!(
        fs::read(socket(proxy.root())).expect("the file is still there"),
        b"not a socket"
    );
    proxy.clear_root(&["config.json", STORE, "ctl"]);
    proxy.upstream.stop();
    assert_eq!(proxy.upstream.connections(), 0);
}
