//! SIGHUP in a real process: the proxy reads the configuration file again.
//!
//! The configuration file of a test is written again before the signal: the second upstream of the test stands for the
//! new target of the route, the first for the old one. The status listener is added so that `/readyz` and `/metrics`
//! can be asked. The connections that wait are kept (`keepalive_timeout_ms`), and a request that is under way is a slow
//! inspection (see `main`). The tests of the listeners change the listeners of the file instead.

use std::fs;
use std::io::Write;
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::sync::mpsc::TryRecvError;
use std::thread;
use std::time::Instant;

use bytes::Bytes;
use http::Request;
use http_body_util::{BodyExt, Full};
use serde_json::{Value, json};
use tokio::time::{sleep, timeout};
use tukuyomi_proxy::rules::bundle::{hex, sha256};

use crate::http2::{Client, add_listener};
use crate::keepalive::read_response;
use crate::support::*;
use crate::tls::Pki;

/// Knobs for a proxy with a second upstream, whose connections are kept after a response.
fn kept() -> Knobs {
    Knobs {
        upstreams: 2,
        keepalive_timeout_ms: 60_000,
        ..Knobs::quick()
    }
}

/// Changes the configuration file in `root` as `change` says.
fn rewrite(root: &Path, change: impl FnOnce(&mut Value)) {
    let path = root.join("config.json");
    let mut config: Value =
        serde_json::from_str(&fs::read_to_string(&path).expect("read the configuration"))
            .expect("parse the configuration");
    change(&mut config);
    fs::write(&path, config.to_string()).expect("write the configuration");
}

/// Makes the one server of the group `main` the one at `address`.
fn point_at(config: &mut Value, address: SocketAddr) {
    config["forward"]["upstreams"]["main"]["servers"] = json!([server(address)]);
}

/// The status and the body of a GET of `target` from the status listener at `port`.
fn page(port: u16, target: &str) -> (u16, String) {
    let message = exchange(port, &get(target)).message();
    (
        message.status(),
        String::from_utf8_lossy(&message.body).into_owned(),
    )
}

/// The readings of the configuration file that ended with `result`, from `/metrics`.
fn reloads(port: u16, result: &str) -> String {
    let line = format!("tukuyomi_config_reloads_total{{result=\"{result}\"}} ");
    page(port, "/metrics")
        .1
        .lines()
        .find_map(|have| have.strip_prefix(&line))
        .unwrap_or_else(|| panic!("no {line} in the page"))
        .to_string()
}

/// Waits until `reloads` says `count`. A refusal by the thread that reads the file is counted when the main loop has
/// its answer, which is just after the line that says why.
fn wait_reloads(port: u16, result: &str, count: &str) {
    for _ in 0..200 {
        if reloads(port, result) == count {
            return;
        }
        thread::sleep(50 * MS);
    }
    assert_eq!(reloads(port, result), count);
}

/// The process has not ended.
fn alive(proxy: &Proxy) -> bool {
    matches!(proxy.exit.try_recv(), Err(TryRecvError::Empty))
}

/// A proxy with the status listener, and the port of that listener.
fn start(test: &str, knobs: Knobs) -> (Proxy, u16) {
    let status = free_port();
    let proxy = Proxy::start_with(test, knobs, |root| {
        add_object(
            root,
            "status",
            json!({ "listen": format!("127.0.0.1:{status}") }),
        );
    });
    (proxy, status)
}

/// Adds a plain listener at `port` to the listeners of the configuration.
fn add_plain(config: &mut Value, port: u16) {
    config["proxy"]["listeners"]
        .as_array_mut()
        .expect("the listeners")
        .push(json!({ "address": format!("127.0.0.1:{port}") }));
}

/// A proxy with the status listener and a second plain listener, and the ports of the two.
fn start_two(test: &str, knobs: Knobs) -> (Proxy, u16, u16) {
    let (status, second) = (free_port(), free_port());
    let proxy = Proxy::start_with(test, knobs, |root| {
        add_object(
            root,
            "status",
            json!({ "listen": format!("127.0.0.1:{status}") }),
        );
        rewrite(root, |config| add_plain(config, second));
    });
    (proxy, status, second)
}

#[test]
#[ignore = "needs a built inspector"]
fn sighup_replaces_the_configuration_for_the_connections_that_begin_and_closes_the_one_that_waits()
{
    let (proxy, status) = start("reload_replace", kept());
    // A connection that has had its answer from the first upstream and waits for the next request.
    let mut waiting = connect(proxy.port);
    waiting.write_all(&get("/one")).expect("send a request");
    assert_eq!(read_response(&mut waiting).status(), 200);
    assert_eq!(proxy.upstream.requests().len(), 1);

    let other = proxy.others[0].addr();
    rewrite(proxy.root(), |config| point_at(config, other));
    let file = fs::read(proxy.root().join("config.json")).expect("read the configuration");
    proxy.signal("HUP");
    let digest = hex(&sha256(&file));
    proxy.records.wait_lines("the replacement", 1, |l| {
        l == format!("reload: configuration replaced {digest}")
    });
    let lines = proxy.records.lines();
    for line in ["reload: SIGHUP", "reload: configuration accepted"] {
        assert!(lines.iter().any(|l| l == line), "{line} in {lines:#?}");
    }

    // The process goes on and says it is ready.
    assert!(alive(&proxy));
    assert_eq!(page(status, "/readyz"), (200, "ready".to_string()));
    // The connection that waited is closed, long before its wait for the next request would end.
    let closing = Instant::now();
    assert!(read_to_close(&mut waiting).is_empty());
    assert!(closing.elapsed() < 30 * SEC);
    // A new connection reaches the new target.
    let mut fresh = connect(proxy.port);
    fresh.write_all(&get("/two")).expect("send a request");
    let answer = read_response(&mut fresh);
    assert_eq!(answer.status(), 200);
    assert_eq!(answer.body, UPSTREAM_BODY.as_bytes());
    assert_eq!(proxy.upstream.requests().len(), 1);
    assert_eq!(proxy.others[0].requests().len(), 1);
    assert_eq!(reloads(status, "replaced"), "1");
    assert_eq!(reloads(status, "refused"), "0");
    drop(fresh);
    proxy.finish(1);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_file_that_is_not_valid_is_refused_and_the_old_configuration_goes_on() {
    let (proxy, status) = start("reload_broken", kept());
    fs::write(proxy.root().join("config.json"), b"{\"proxy\": ").expect("write the configuration");
    proxy.signal("HUP");
    proxy.records.wait_lines("the refusal", 1, |l| {
        l == "reload: configuration refused: configuration is not valid JSON"
    });

    assert!(alive(&proxy));
    wait_reloads(status, "refused", "1");
    assert_eq!(reloads(status, "replaced"), "0");
    // The old target answers, and the connection stays open for a second request.
    let mut sock = connect(proxy.port);
    sock.write_all(&get("/still")).expect("send a request");
    assert_eq!(read_response(&mut sock).status(), 200);
    sock.write_all(&get("/again")).expect("send a request");
    assert_eq!(read_response(&mut sock).status(), 200);
    assert_eq!(proxy.upstream.requests().len(), 2);
    assert!(proxy.others[0].requests().is_empty());
    drop(sock);
    proxy.finish(2);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_file_with_another_value_that_cannot_change_is_refused_by_its_key_and_the_old_target_answers() {
    let (proxy, status) = start("reload_fixed", kept());
    let other = proxy.others[0].addr();
    // The file names the second upstream, but also another number of connections.
    rewrite(proxy.root(), |config| {
        point_at(config, other);
        config["proxy"]["max_conns"] = json!(65);
    });
    proxy.signal("HUP");
    proxy.records.wait_lines("the refusal", 1, |l| {
        l == "reload: configuration refused: proxy.max_conns cannot change while running"
    });

    assert!(alive(&proxy));
    assert_eq!(reloads(status, "refused"), "1");
    assert_eq!(reloads(status, "replaced"), "0");
    let mut sock = connect(proxy.port);
    sock.write_all(&get("/still")).expect("send a request");
    assert_eq!(read_response(&mut sock).status(), 200);
    assert_eq!(proxy.upstream.requests().len(), 1);
    assert!(proxy.others[0].requests().is_empty());
    drop(sock);
    proxy.finish(1);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_request_under_way_is_answered_by_the_old_target_and_then_the_connection_is_closed() {
    let knobs = Knobs {
        upstreams: 2,
        keepalive_timeout_ms: 60_000,
        ..Knobs::slow()
    };
    let (proxy, status) = start("reload_busy", knobs);
    // The request is being inspected, which takes seconds; the route is looked up after that.
    let mut sock = proxy.start_slow(&post_form("/submit", &padded_form("ok", MAX_BODY)));
    let other = proxy.others[0].addr();
    rewrite(proxy.root(), |config| point_at(config, other));
    proxy.signal("HUP");
    proxy.records.wait_lines("the replacement", 1, |l| {
        l.starts_with("reload: configuration replaced ")
    });
    assert_eq!(reloads(status, "replaced"), "1");

    let answer = read_response(&mut sock);
    assert_eq!(answer.status(), 200, "answer: {:?}", answer.start);
    assert_eq!(answer.body, UPSTREAM_BODY.as_bytes());
    assert_eq!(answer.values("connection"), ["close"]);
    assert!(read_to_close(&mut sock).is_empty());
    assert_eq!(proxy.upstream.requests().len(), 1);
    assert!(proxy.others[0].requests().is_empty());
    proxy.finish(1);
}

#[test]
#[ignore = "needs a built inspector"]
fn an_h2_connection_gets_a_goaway_at_sighup_and_a_stream_that_is_open_still_gets_its_answer() {
    let mut pki = Pki::new("reload_h2");
    let files = pki.issue("a", &["a.example", "*.a.example"]);
    let port = free_port();
    let knobs = Knobs {
        upstreams: 2,
        keepalive_timeout_ms: 60_000,
        ..Knobs::slow()
    };
    let proxy = Proxy::start_with("reload_h2", knobs, |root| add_listener(root, port, &files));
    let mut client = Client::connect(&pki, port);
    let other = proxy.others[0].addr();
    rewrite(proxy.root(), |config| point_at(config, other));

    let request = Request::post("https://www.a.example/submit")
        .header("content-type", URLENCODED)
        .body(Full::new(Bytes::from(padded_form("ok", MAX_BODY))))
        .unwrap();
    let inspector = proxy.inspector();
    let Client { runtime, send } = &mut client;
    let (status, body) = runtime.block_on(async {
        // The stream is open once the inspector has read the first frame of its body.
        let base = read_chars(inspector).expect("read the inspector's counter");
        let stream = tokio::spawn({
            let mut send = send.clone();
            async move {
                send.ready().await.expect("the connection takes a request");
                let response = send.send_request(request).await.expect("a response");
                let status = response.status().as_u16();
                let body = response.into_body().collect().await.expect("the body");
                (status, body.to_bytes().to_vec())
            }
        });
        timeout(MARGIN, async {
            while read_chars(inspector).is_none_or(|now| now < base + FRAME) {
                sleep(5 * MS).await;
            }
        })
        .await
        .expect("the inspector to read the body");
        proxy.signal("HUP");
        proxy.records.wait_lines("the replacement", 1, |l| {
            l.starts_with("reload: configuration replaced ")
        });
        // The connection takes no new stream from now on.
        timeout(MARGIN, async {
            while send.ready().await.is_ok() {
                sleep(20 * MS).await;
            }
        })
        .await
        .expect("the GOAWAY");
        stream.await.expect("the stream was not cut")
    });
    assert_eq!((status, body.as_slice()), (200, UPSTREAM_BODY.as_bytes()));
    assert_eq!(proxy.upstream.requests().len(), 1);
    assert!(proxy.others[0].requests().is_empty());

    // A new connection takes the new configuration.
    let mut fresh = Client::connect(&pki, port);
    assert_eq!(fresh.get_fields("/two").0, 200);
    assert_eq!(proxy.others[0].requests().len(), 1);
    drop(fresh);
    drop(client);
    assert!(alive(&proxy));
    proxy.finish(1);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_listener_that_is_added_answers_and_the_one_before_it_goes_on_answering() {
    let (proxy, status) = start("reload_add_listener", Knobs::quick());
    let added = free_port();
    rewrite(proxy.root(), |config| add_plain(config, added));
    proxy.signal("HUP");
    proxy.records.wait_lines("the replacement", 1, |l| {
        l.starts_with("reload: configuration replaced ")
    });

    assert_eq!(exchange(added, &get("/added")).status(), 200);
    assert_eq!(exchange(proxy.port, &get("/before")).status(), 200);
    assert_eq!(proxy.upstream.requests().len(), 2);
    assert_eq!(reloads(status, "replaced"), "1");
    assert_eq!(reloads(status, "refused"), "0");
    proxy.finish(2);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_listener_that_is_removed_turns_new_connections_away_and_answers_the_request_begun_on_it() {
    let (proxy, status, second) = start_two("reload_remove_listener", Knobs::slow());
    // The request is being inspected, which takes seconds, on the first listener, which the file leaves out.
    let mut sock = proxy.start_slow(&post_form("/submit", &padded_form("ok", MAX_BODY)));
    rewrite(proxy.root(), |config| {
        config["proxy"]["listeners"] = json!([{ "address": format!("127.0.0.1:{second}") }]);
    });
    proxy.signal("HUP");
    proxy.records.wait_lines("the replacement", 1, |l| {
        l.starts_with("reload: configuration replaced ")
    });
    assert_eq!(reloads(status, "replaced"), "1");

    // The address that is gone turns new connections away, and the one that stays answers, now as the first.
    assert_turned_away(proxy.port);
    assert_eq!(exchange(second, &get("/still")).status(), 200);
    // The request that began before gets its answer on its connection, which is closed after it.
    let answer = read_response(&mut sock);
    assert_eq!(answer.status(), 200, "answer: {:?}", answer.start);
    assert_eq!(answer.body, UPSTREAM_BODY.as_bytes());
    assert!(read_to_close(&mut sock).is_empty());
    proxy.finish(2);
}

#[test]
#[ignore = "needs a built inspector"]
fn an_address_that_cannot_be_bound_refuses_the_whole_file_and_nothing_is_replaced() {
    let knobs = Knobs {
        upstreams: 2,
        ..Knobs::quick()
    };
    let (proxy, status, second) = start_two("reload_unbindable", knobs);
    // Something else holds the last address of the file; the address before it can be bound.
    let held = TcpListener::bind("127.0.0.1:0").expect("bind the address to hold");
    let held_port = held.local_addr().expect("the held address").port();
    let (free, other) = (free_port(), proxy.others[0].addr());
    rewrite(proxy.root(), |config| {
        point_at(config, other);
        add_plain(config, free);
        add_plain(config, held_port);
    });
    proxy.signal("HUP");
    proxy.records.wait_lines("the refusal", 1, |l| {
        l == "reload: configuration refused: listener 4 cannot be bound"
    });

    assert!(alive(&proxy));
    assert_eq!(reloads(status, "refused"), "1");
    assert_eq!(reloads(status, "replaced"), "0");
    // The address that was bound before the one that failed is closed again.
    TcpListener::bind(("127.0.0.1", free)).expect("the address is free again");
    // The addresses of the file that runs answer, and the old target serves.
    assert_eq!(exchange(proxy.port, &get("/first")).status(), 200);
    assert_eq!(exchange(second, &get("/second")).status(), 200);
    assert_eq!(proxy.upstream.requests().len(), 2);
    assert!(proxy.others[0].requests().is_empty());
    drop(held);
    proxy.finish(2);
}

#[test]
#[ignore = "needs a built inspector"]
fn listeners_in_another_order_answer_each_as_its_own_plain_or_tls_listener() {
    let mut pki = Pki::new("reload_swap_listeners");
    let files = pki.issue("a", &["a.example", "*.a.example"]);
    let (tls, status) = (free_port(), free_port());
    let proxy = Proxy::start_with("reload_swap_listeners", Knobs::quick(), |root| {
        add_object(
            root,
            "status",
            json!({ "listen": format!("127.0.0.1:{status}") }),
        );
        add_listener(root, tls, &files);
    });
    // The plain listener is the first of the file and the one that ends TLS the second; the file turns them round.
    rewrite(proxy.root(), |config| {
        config["proxy"]["listeners"]
            .as_array_mut()
            .expect("the listeners")
            .reverse();
    });
    proxy.signal("HUP");
    proxy.records.wait_lines("the replacement", 1, |l| {
        l.starts_with("reload: configuration replaced ")
    });

    assert_eq!(exchange(proxy.port, &get("/plain")).status(), 200);
    let mut client = Client::connect(&pki, tls);
    assert_eq!(client.get_fields("/tls").0, 200);
    drop(client);
    assert_eq!(reloads(status, "replaced"), "1");
    assert_eq!(reloads(status, "refused"), "0");
    proxy.finish(2);
}
