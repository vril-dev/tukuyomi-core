//! The status listener and the notices to the service manager in a real process.
//!
//! The `status` object is added to the configuration of the test before the proxy starts, at a free loopback port.
//! The notices are received by a datagram socket of the test that `NOTIFY_SOCKET` names.

use std::fs;
use std::net::TcpListener;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::thread;

use serde_json::{Value, json};

use crate::support::*;

/// Adds the `status` object to the configuration in `root`.
fn add_status(root: &Path, listen: &str) {
    let path = root.join("config.json");
    let mut config: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    config["status"] = json!({ "listen": listen });
    fs::write(&path, config.to_string()).unwrap();
}

/// A proxy that is listening, its inspector there, and its status listener at the port that is returned.
fn status_proxy(test: &str, knobs: Knobs) -> (Proxy, u16) {
    let port = free_port();
    let proxy = Proxy::start_with(test, knobs, |root| {
        add_status(root, &format!("127.0.0.1:{port}"));
    });
    (proxy, port)
}

/// The status and the body of a GET of `target` from the status listener.
fn page(port: u16, target: &str) -> (u16, String) {
    let message = exchange(port, &get(target)).message();
    (
        message.status(),
        String::from_utf8_lossy(&message.body).into_owned(),
    )
}

#[test]
#[ignore = "needs a built inspector"]
fn readyz_is_ready_while_the_proxy_serves_and_says_stopping_from_the_signal_while_healthz_goes_on()
{
    let (proxy, port) = status_proxy("status_stopping", Knobs::slow());
    assert_eq!(page(port, "/healthz"), (200, "ok".to_string()));
    assert_eq!(page(port, "/readyz"), (200, "ready".to_string()));

    // An inspection that takes seconds keeps the stop going, so the listener can be asked during it.
    let mut sock = proxy.start_slow(&post_form("/submit", &padded_form("ok", MAX_BODY)));
    let since = proxy.term();
    let mut said = None;
    for _ in 0..200 {
        let seen = page(port, "/readyz");
        if seen.0 == 503 {
            said = Some(seen);
            break;
        }
        thread::sleep(50 * MS);
    }
    assert_eq!(said, Some((503, "stopping".to_string())));
    assert_eq!(page(port, "/healthz"), (200, "ok".to_string()));
    assert_eq!(page(port, "/nothing").0, 404);

    let answer = collect(&mut sock, since);
    assert_eq!(answer.status(), 200, "answer: {:?}", answer.text());
    let counts = proxy.finish_after_term(since, 1);
    assert!(counts[0] >= 1, "the request was in flight: {counts:?}");
}

#[test]
#[ignore = "needs a built inspector"]
fn metrics_count_a_forwarded_and_a_blocked_request_and_a_scrape_is_no_request() {
    let (proxy, port) = status_proxy("status_metrics", Knobs::quick());
    let forwarded = exchange(proxy.port, &get("/ok"));
    assert_eq!(forwarded.status(), 200, "answer: {:?}", forwarded.text());
    let blocked = exchange(proxy.port, &get("/block-probe/x"));
    assert_empty_answer(&blocked, 403);
    proxy.records.conn("the forwarded record", |l| {
        is_answer(l, "forwarded", 200, "forwarded")
    });
    proxy
        .records
        .conn("the blocked record", |l| blocked_by(l, 9201));

    let reply = exchange(port, &get("/metrics"));
    let message = reply.message();
    assert_eq!(message.status(), 200, "answer: {:?}", reply.text());
    assert_eq!(
        message.values("content-type"),
        ["text/plain; version=0.0.4; charset=utf-8"]
    );
    assert_eq!(message.values("connection"), ["close"]);
    let text = String::from_utf8(message.body.clone()).expect("the page is text");

    for line in [
        "tukuyomi_requests_total{class=\"forwarded\"} 1",
        "tukuyomi_requests_total{class=\"blocked\"} 1",
        "tukuyomi_requests_total{class=\"rejected\"} 0",
        "tukuyomi_waf_rule_hits_total{decision=\"block\"} 1",
        "tukuyomi_waf_rule_hits_total{decision=\"detect\"} 0",
        "tukuyomi_connections_accepted_total 2",
        "tukuyomi_inspector_up 1",
        "tukuyomi_inspector_restarts_total 0",
        "tukuyomi_upstream_failures_total{group=\"main\"} 0",
        "tukuyomi_records_dropped_total 0",
        "tukuyomi_record_write_errors_total 0",
    ] {
        assert!(text.lines().any(|have| have == line), "{line} in {text}");
    }
    // The two connections are done or end at once: nothing is open, though the accept side waits for the next one.
    let mut open = text.clone();
    for _ in 0..200 {
        if open
            .lines()
            .any(|have| have == "tukuyomi_connections_open 0")
        {
            break;
        }
        thread::sleep(50 * MS);
        open = page(port, "/metrics").1;
    }
    assert!(
        open.lines()
            .any(|have| have == "tukuyomi_connections_open 0"),
        "{open}"
    );
    let info = format!(
        "tukuyomi_rules_generation_info{{generation=\"{}\",mode=\"block\"}} 1",
        &generation()[..16]
    );
    assert!(text.lines().any(|have| have == info), "{info} in {text}");

    // Each family has its HELP and its TYPE once.
    let names = |prefix: &str| -> Vec<String> {
        text.lines()
            .filter_map(|l| l.strip_prefix(prefix))
            .map(|rest| rest.split(' ').next().unwrap_or_default().to_string())
            .collect()
    };
    let (helped, typed) = (names("# HELP "), names("# TYPE "));
    let mut unique = helped.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(helped.len(), 18, "{helped:?}");
    assert_eq!((unique.len(), &typed), (18, &helped));

    // The scrape and the other pages were not requests: the two records are the only ones.
    assert_eq!(page(port, "/healthz").0, 200);
    let requests = proxy.records.all();
    let requests = requests.iter().filter(|r| r["type"] == "request").count();
    assert_eq!(requests, 2);
    proxy.finish(1);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_status_address_that_cannot_be_bound_ends_the_start_before_the_inspector_runs() {
    // Something else holds the address.
    let taken = TcpListener::bind("127.0.0.1:0").expect("bind a port");
    let listen = taken.local_addr().expect("the address").to_string();
    let mut proxy = Proxy::spawn_with("status_taken", Knobs::quick(), |root| {
        add_status(root, &listen);
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
        Some("start: the status address cannot be bound"),
        "records: {lines:#?}"
    );
    assert!(
        !lines
            .iter()
            .any(|l| l.contains("kernel") || l.starts_with("stop")),
        "records: {lines:#?}"
    );
    // No inspector was started: the root holds what the test put there and no directory of a kernel.
    assert_turned_away(proxy.port);
    proxy.clear_root(&["config.json", STORE]);
    proxy.upstream.stop();
    assert_eq!(proxy.upstream.connections(), 0);
}

/// Runs `tukuyomi-proxy config check` on the configuration of `idle` and waits for it.
fn config_check(idle: &Idle) -> Output {
    Command::new(env!("CARGO_BIN_EXE_tukuyomi-proxy"))
        .args(["config", "check"])
        .arg(idle.root().join("config.json"))
        .stdin(Stdio::null())
        .output()
        .expect("run the command")
}

#[test]
#[ignore = "needs a built inspector"]
fn config_check_refuses_a_status_address_that_is_not_a_loopback_address() {
    let idle = Idle::new("status_check", &Knobs::quick(), |root| {
        add_status(root, "192.0.2.1:9180");
    });
    let output = config_check(&idle);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "config check: configuration refused: status listen is not a loopback address\n"
    );
}

#[test]
#[ignore = "needs a built inspector"]
fn config_check_refuses_a_server_name_that_comes_to_the_status_address() {
    let port = free_port();
    let idle = Idle::new("status_server", &Knobs::quick(), |root| {
        add_status(root, &format!("127.0.0.1:{port}"));
        // The one server of the group `main` is `localhost` at the port of the status listener.
        let path = root.join("config.json");
        let mut config: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        config["forward"]["upstreams"]["main"]["servers"][0]["address"] =
            json!(format!("localhost:{port}"));
        fs::write(&path, config.to_string()).unwrap();
    });
    let output = config_check(&idle);
    let err = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{err}");
    assert!(
        err.ends_with(
            "config check: upstream refused: a server name has the address of a listener (upstream main, server 1)\n"
        ),
        "{err}"
    );
}

#[test]
#[ignore = "needs a built inspector"]
fn ready_is_sent_when_the_listeners_are_bound_and_stopping_at_the_signal() {
    // A name in the abstract namespace, so that no path (and no limit on its length) is in the test root.
    let name = format!("tukuyomi-proxy-test-{}-{}", std::process::id(), free_port());
    let socket =
        UnixDatagram::bind_addr(&SocketAddr::from_abstract_name(&name).unwrap()).expect("bind");
    socket.set_read_timeout(Some(30 * SEC)).unwrap();
    let knobs = Knobs {
        notify_socket: Some(format!("@{name}")),
        ..Knobs::quick()
    };
    let proxy = Proxy::start("status_notify", knobs);
    let receive = || {
        let mut buf = [0u8; 64];
        let got = socket.recv(&mut buf).expect("a notice");
        String::from_utf8_lossy(&buf[..got]).into_owned()
    };
    assert_eq!(receive(), "READY=1");
    let since = proxy.term();
    assert_eq!(receive(), "STOPPING=1");
    proxy.finish_after_term(since, 0);
}
