//! The records of requests in a real process: the number of a request is the same in its record, in the response
//! to the client and in the request that the upstream gets, and what the record shows of the request.

use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::time::Instant;

use serde_json::{Value, json};

use crate::http2::{Client, add_listener};
use crate::support::*;
use crate::tls::Pki;

/// Whether `id` is a number of a request: 16 lower-case hexadecimal digits, a `-` and a count in lower-case
/// hexadecimal.
fn is_number(id: &str) -> bool {
    id.split_once('-').is_some_and(|(random, count)| {
        let hex = |text: &str| {
            !text.is_empty()
                && text
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        random.len() == 16 && hex(random) && hex(count)
    })
}

/// The one `X-Request-ID` of a response.
fn response_number(reply: &Reply) -> String {
    let message = reply.message();
    let ids = message.values("x-request-id");
    assert_eq!(ids.len(), 1, "answer: {:?}", reply.text());
    assert!(is_number(ids[0]), "{}", ids[0]);
    ids[0].to_string()
}

#[test]
#[ignore = "needs a built inspector"]
fn a_forwarded_request_has_one_number_in_its_record_its_response_and_the_upstream_request() {
    let proxy = Proxy::start("records_forwarded", Knobs::quick());
    // The client's own numbers, two lines, are not passed on; the query is not recorded.
    let request = format!(
        "POST /ok?q=secret HTTP/1.1\r\nHost: Example.test\r\nX-Request-ID: from-the-client\r\n\
         X-Request-ID: second\r\nContent-Type: {URLENCODED}\r\nContent-Length: 5\r\n\r\na=1&b"
    );
    let reply = exchange(proxy.port, request.as_bytes());
    assert_eq!(reply.status(), 200, "answer: {:?}", reply.text());
    assert_eq!(reply.message().body, UPSTREAM_BODY.as_bytes());
    // The upstream sent a number of its own, which the number of the record replaces.
    let id = response_number(&reply);

    let record = proxy.records.conn("the forwarded record", |l| {
        is_answer(l, "forwarded", 200, "forwarded")
    });
    assert_eq!(record["id"], id.as_str());
    assert_eq!(record["proto"], "h1");
    assert_eq!(record["tls"], false);
    assert_eq!(record["listener"], 0);
    assert_eq!(record["client"], "127.0.0.1");
    assert_eq!(
        (&record["method"], &record["host"], &record["path"]),
        (&json!("POST"), &json!("Example.test"), &json!("/ok"))
    );
    assert!(no(&record, "cut") && no(&record, "rule"));
    assert!(!record.to_string().contains("secret"), "{record}");
    assert_eq!(
        (&record["body"], no(&record, "inspected")),
        (&json!(5), true)
    );
    assert_eq!(record["sent"], UPSTREAM_BODY.len());
    // The rules that gave the verdict: the generation of the store, its mode and its engine.
    assert_eq!(record["mode"], "block");
    assert_eq!(record["engine"], "coraza");
    assert_eq!(record["generation"], generation()[..16]);
    assert_eq!(record["upstream"], "main");
    assert_eq!(record["server"], proxy.upstream.addr().to_string().as_str());

    // The upstream got the number of the record, once, and not the numbers of the client.
    let requests = proxy.upstream.requests();
    assert_eq!(requests.len(), 1);
    let seen = Message::parse(&requests[0]);
    assert_eq!(seen.values("x-request-id"), [id.as_str()]);
    proxy.finish(1);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_blocked_request_is_answered_with_the_number_of_its_record_which_names_the_rule() {
    let proxy = Proxy::start("records_blocked", Knobs::quick());
    let reply = exchange(proxy.port, &get("/block-probe/x"));
    assert_empty_answer(&reply, 403);
    let id = response_number(&reply);
    let record = proxy
        .records
        .conn("the blocked record", |l| blocked_by(l, 9201));
    assert_eq!(record["id"], id.as_str());
    assert_eq!(record["mode"], "block");
    assert_eq!(record["engine"], "coraza");
    assert_eq!(record["generation"], generation()[..16]);
    assert!(no(&record, "upstream") && no(&record, "server"), "{record}");
    assert_eq!(record["sent"], 0);
    assert_eq!(proxy.upstream.connections(), 0);
    proxy.finish(0);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_refused_first_head_is_answered_with_a_number_and_its_record_has_no_text_of_the_head() {
    let proxy = Proxy::start("records_refused", Knobs::quick());
    // Two `Host` lines: the head check refuses it, and nothing of it is written to the record.
    let reply = exchange(
        proxy.port,
        b"GET /secret-path HTTP/1.1\r\nHost: a.test\r\nHost: b.test\r\n\r\n",
    );
    assert_empty_answer(&reply, 400);
    let id = response_number(&reply);
    let record = proxy.records.conn("the refused head", |l| {
        is_answer(l, "rejected", 400, "malformed request head")
    });
    assert_eq!(record["id"], id.as_str());
    for key in [
        "method",
        "host",
        "path",
        "mode",
        "engine",
        "generation",
        "rule",
    ] {
        assert!(no(&record, key), "{key} in {record}");
    }
    assert_eq!(record["sent"], 0);
    assert_eq!(proxy.upstream.connections(), 0);
    proxy.finish(0);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_request_over_h2_has_a_number_in_its_record_and_its_response() {
    let mut pki = Pki::new("records_h2");
    let files = pki.issue("a", &["a.example", "*.a.example"]);
    let port = free_port();
    let knobs = Knobs {
        keepalive_timeout_ms: 5_000,
        ..Knobs::quick()
    };
    let proxy = Proxy::start_with("records_h2", knobs, |root| add_listener(root, port, &files));
    let mut client = Client::connect(&pki, port);
    let (status, fields) = client.get_fields("/ok?q=1");
    assert_eq!(status, 200);
    let ids: Vec<_> = fields.get_all("x-request-id").iter().collect();
    assert_eq!(ids.len(), 1, "{fields:?}");
    let id = ids[0].to_str().unwrap().to_string();
    assert!(is_number(&id), "{id}");
    drop(client);
    let record = proxy.records.conn("the h2 record", |l| {
        is_answer(l, "forwarded", 200, "forwarded") && l["proto"] == "h2"
    });
    assert_eq!(record["id"], id.as_str());
    assert_eq!(record["tls"], true);
    assert_eq!(
        (&record["method"], &record["host"], &record["path"]),
        (&json!("GET"), &json!("www.a.example"), &json!("/ok"))
    );
    let seen = Message::parse(&proxy.upstream.requests()[0]);
    assert_eq!(seen.values("x-request-id"), [id.as_str()]);
    proxy.finish(1);
}

#[test]
#[ignore = "needs a built inspector"]
fn the_text_of_a_request_has_every_byte_that_could_hurt_a_reader_as_a_percent_code() {
    let proxy = Proxy::start("records_bytes", Knobs::quick());
    // A quote, a backslash and a received `%41` in the path, which the head check lets through, and in the `Host`
    // the bytes of a control of the direction of text.
    let reply = exchange(
        proxy.port,
        b"GET /a\"b\\c%41?q=1 HTTP/1.1\r\nHost: x\xe2\x80\xaey.test\r\n\r\n",
    );
    let id = response_number(&reply);
    let record = proxy.records.conn("the record", |l| {
        l["type"] == "request" && l["id"] == id.as_str()
    });
    assert_eq!(record["path"], "/a%22b%5Cc%41");
    assert_eq!(record["host"], "x%E2%80%AEy.test");
    assert!(no(&record, "cut"), "{record}");
    // Where the request went does not matter here.
    let upstream = proxy.upstream.connections();
    proxy.finish(upstream);
}

#[test]
#[ignore = "needs a built inspector"]
fn the_records_are_kept_in_a_file_of_mode_0600_with_the_lines_the_standard_error_has() {
    let proxy = Proxy::start_with("records_file", Knobs::quick(), |root| {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(root.join("rec"))
            .expect("make the directory of the records");
        add_object(
            root,
            "records",
            json!({ "dir": root.join("rec").to_string_lossy(), "file_bytes": 1 << 20, "files": 2 }),
        );
    });
    let reply = exchange(proxy.port, &get("/ok"));
    assert_eq!(reply.status(), 200, "answer: {:?}", reply.text());
    let id = response_number(&reply);
    proxy.records.conn("the forwarded record", |l| {
        is_answer(l, "forwarded", 200, "forwarded")
    });

    let file = proxy.root().join("rec").join("records.log");
    let meta = fs::symlink_metadata(&file).expect("the record file is there");
    assert!(meta.is_file());
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    // The inspector does not inherit the file.
    for entry in
        fs::read_dir(format!("/proc/{}/fd", proxy.inspector())).expect("list the descriptors")
    {
        let target = fs::read_link(entry.expect("an entry").path()).expect("read a descriptor");
        assert!(
            !target.to_string_lossy().ends_with("records.log"),
            "{target:?}"
        );
    }
    // The file gets a line a moment after the standard error does.
    let deadline = Instant::now() + 30 * SEC;
    let text = loop {
        let text = fs::read_to_string(&file).expect("read the record file");
        if text.contains(&id) {
            break text;
        }
        assert!(Instant::now() < deadline, "the record is not in the file");
        std::thread::sleep(20 * MS);
    };
    let kept: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).expect("a line of the file is a record"))
        .collect();
    assert!(
        kept.iter()
            .any(|r| r["type"] == "request" && r["id"] == id.as_str()),
        "{text}"
    );
    // Every line is one that the standard error has too. The lines of the start before the file was opened are not
    // in it, the ones after are.
    let all = proxy.records.all();
    assert!(kept.iter().all(|r| all.contains(r)), "{text}");
    assert!(!text.contains("configuration accepted"), "{text}");
    assert!(text.contains("start: listening"), "{text}");
    // The root holds only the configuration and the store at the end.
    fs::remove_dir_all(proxy.root().join("rec")).expect("remove the records");
    proxy.finish(1);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_records_directory_that_others_can_reach_ends_the_start_before_the_inspector_runs() {
    let mut proxy = Proxy::spawn_with("records_open", Knobs::quick(), |root| {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(root.join("rec"))
            .expect("make the directory of the records");
        fs::set_permissions(root.join("rec"), fs::Permissions::from_mode(0o755))
            .expect("open the directory to others");
        add_object(
            root,
            "records",
            json!({ "dir": root.join("rec").to_string_lossy(), "file_bytes": 1 << 20, "files": 2 }),
        );
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
        Some("start: record file refused: the directory has group or other permission bits"),
        "records: {lines:#?}"
    );
    assert!(
        !lines
            .iter()
            .any(|l| l.contains("kernel") || l.starts_with("stop")),
        "records: {lines:#?}"
    );
    // No inspector was started, and no file was made in the directory.
    assert_turned_away(proxy.port);
    assert_eq!(
        fs::read_dir(proxy.root().join("rec"))
            .expect("list the directory")
            .count(),
        0
    );
    proxy.clear_root(&["config.json", STORE, "rec"]);
    proxy.upstream.stop();
    assert_eq!(proxy.upstream.connections(), 0);
}
