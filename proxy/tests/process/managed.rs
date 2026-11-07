//! A configuration with `managed` in a real process. The routing of a test is a version of the managed store in its
//! root, made from a document with `managed import` and chosen with `managed activate` (see `support::manage`). The
//! second upstream of a test stands for the admin process, at `admin.listen`, and the third is the server of a group
//! of its own. The certificates are made like those of `tls`. The client is a trusted proxy (`trusted_proxies`), so
//! that a request can come from another address by its `X-Forwarded-For`.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::Request;
use http_body_util::Full;
use serde_json::{Value, json};
use tukuyomi_proxy::admin::waf::control::Control;
use tukuyomi_proxy::managed::Store;
use tukuyomi_proxy::managed::apply::{Outcome, apply};
use tukuyomi_proxy::rules::bundle::{Fingerprint, hex, sha256};

use crate::http2::Client;
use crate::support::*;
use crate::tls::Pki;

/// The groups of a test: `main` for every request but those for `b.example/b/`, which go to `other`; and `admin`, which
/// is the way to the admin process and leaves the document for `admin.listen` (see `with_admin`).
fn forward(addresses: &[SocketAddr]) -> Value {
    json!({
        "resolve_timeout_ms": RESOLVE_TIMEOUT_MS,
        "upstreams": {
            "main": {"servers": [server(addresses[0])]},
            "admin": {"servers": [server(addresses[1])]},
            "other": {"servers": [server(addresses[2])]},
        },
        "routes": [{"host": "b.example", "path": "/b/", "upstream": "other"}],
        "default_upstream": "main",
    })
}

fn knobs() -> Knobs {
    Knobs {
        upstreams: 3,
        forward,
        trusted_proxies: vec!["127.0.0.1/32".to_owned()],
        ..Knobs::quick()
    }
}

/// The control socket in the root.
fn socket(root: &Path) -> PathBuf {
    root.join("ctl").join("c.sock")
}

/// A TLS listener at `port` without certificates of its own, which speaks HTTP/2 if `http2` says so.
fn tls_listener(port: u16, http2: bool) -> Value {
    let mut listener =
        json!({"address": format!("127.0.0.1:{port}"), "tls": {"min_version": "1.2"}});
    if http2 {
        listener["tls"]["http2"] = json!({
            "max_streams": 128, "stream_window": 65535, "connection_window": 262_144,
            "max_header_list": 32768, "send_buffer": 16384,
        });
    }
    listener
}

/// The `admin` object of `root` with the way to the admin process for `admin.a.example`, whose certificate is
/// `files`, to the server of the group `admin` of `document`, which leaves the document. It lets in the network that
/// the `access` of the version turns away, and the client itself.
fn with_admin(root: &Path, main: &mut Value, document: &mut Value, files: &(PathBuf, PathBuf)) {
    let groups = document["upstreams"].as_object_mut().unwrap();
    let listen = groups.remove("admin").unwrap()["servers"][0]["address"].clone();
    fs::DirBuilder::new()
        .mode(0o700)
        .create(root.join("ctl"))
        .expect("make the directory of the socket");
    main["admin"] = json!({
        "listen": listen,
        "control": socket(root),
        "store": {"kind": "file", "dir": root.join("admin")},
        "origin": "https://admin.a.example",
        "trusted_proxies": [],
        "mfa": "optional",
        "session_idle_ms": 1_800_000,
        "session_total_ms": 43_200_000,
        "route": {
            "host": "admin.a.example",
            "certificate": {"cert_file": files.0, "key_file": files.1},
            "access": {"allow_cidrs": ["198.51.100.0/24", "127.0.0.1/32"]},
        },
    });
}

/// One request over TLS to `port` with `name` as the server name, and the answer until the proxy ends the connection,
/// with the certificate that the server showed.
fn over_tls(pki: &Pki, port: u16, name: &str, request: &str) -> (Message, Vec<u8>) {
    let mut stream = pki.client(name, port);
    stream
        .write_all(request.as_bytes())
        .expect("send the request");
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .expect("the proxy ended the connection with the closing alert");
    let shown = stream.conn.peer_certificates().expect("a certificate")[0].to_vec();
    (Message::parse(&raw), shown)
}

/// A GET of `/` for `host`, from the client `from` as a trusted proxy says.
fn request(host: &str, from: &str) -> String {
    format!("GET / HTTP/1.1\r\nHost: {host}\r\nX-Forwarded-For: {from}\r\n\r\n")
}

/// The first certificate of the chain file `path`, as the server shows it.
fn shown(path: &Path) -> Vec<u8> {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;
    CertificateDer::from_pem_file(path).unwrap().to_vec()
}

/// Sends `request` to the control socket in `root` and reads the one line of the answer, until the proxy closes. A
/// reading of the configuration may take the time of the lookup of the names and a margin.
fn ask(root: &Path, request: &str) -> Value {
    let mut sock = std::os::unix::net::UnixStream::connect(socket(root))
        .expect("connect to the control socket");
    sock.set_read_timeout(Some(MARGIN * 6)).unwrap();
    sock.write_all(request.as_bytes()).unwrap();
    let mut out = String::new();
    sock.read_to_string(&mut out).unwrap();
    assert_eq!(out.matches('\n').count(), 1, "answer: {out:?}");
    serde_json::from_str(&out).expect("a line of JSON")
}

/// The answer of the control socket in `root` to a status question.
fn status(root: &Path) -> Value {
    ask(root, "{\"op\":\"status\"}\n")
}

/// The answer of the control socket in `root` to a reload order for the version `name`.
fn reload(root: &Path, name: &str) -> Value {
    ask(
        root,
        &format!("{{\"op\":\"reload\",\"managed\":\"{name}\"}}\n"),
    )
}

/// The document that the version of the test root `root` was last imported from.
fn document(root: &Path) -> Value {
    serde_json::from_str(&fs::read_to_string(root.join(DOCUMENT)).unwrap()).unwrap()
}

/// Stops the proxy and leaves its root as `finish` wants it: the store of the version and the document go, and so
/// does the directory of the control socket once the proxy has removed the socket.
fn finish(proxy: Proxy, upstream_connections: usize) {
    let root = proxy.root().to_path_buf();
    let since = proxy.term();
    let deadline = Instant::now() + MARGIN;
    while fs::symlink_metadata(socket(&root)).is_ok() {
        assert!(Instant::now() < deadline, "the socket is still there");
        std::thread::sleep(10 * MS);
    }
    let _ = fs::remove_dir(root.join("ctl"));
    fs::remove_dir_all(root.join(MANAGED)).unwrap();
    fs::remove_file(root.join(DOCUMENT)).unwrap();
    let counts = proxy.finish_after_term(since, upstream_connections);
    assert_eq!(counts, [0, 0, 0], "the kernel held something at the stop");
}

#[test]
#[ignore = "needs a built inspector"]
fn the_sites_serve_on_every_tls_listener_and_the_way_to_the_admin_process_is_taken_by_its_host_alone()
 {
    let mut pki = Pki::new("managed_sites");
    let site_a = pki.issue("a", &["a.example", "*.a.example"]);
    let site_b = pki.issue("b", &["b.example"]);
    let admin = pki.issue("admin", &["admin.a.example"]);
    let (h2_port, tls_port, redirect_port) = (free_port(), free_port(), free_port());
    let mut name = String::new();
    let proxy = Proxy::start_with("mng_sites", knobs(), |root| {
        name = manage(root, |main, document| {
            let listeners = main["proxy"]["listeners"].as_array_mut().unwrap();
            listeners.push(tls_listener(h2_port, true));
            listeners.push(tls_listener(tls_port, false));
            listeners.push(json!({
                "address": format!("127.0.0.1:{redirect_port}"),
                "redirect": {"https_port": tls_port},
            }));
            document["sites"] = json!([
                {"name": "a", "hosts": ["a.example", "*.a.example"], "certificate": {"chain_file": site_a.0, "key_file": site_a.1}},
                {"name": "b", "hosts": ["b.example"], "certificate": {"chain_file": site_b.0, "key_file": site_b.1}},
            ]);
            // Every client of this network is turned away, but on the way to the admin process.
            document["access"] = json!({"deny_cidrs": ["198.51.100.0/24"]});
            with_admin(root, main, document, &admin);
        });
    });
    let (standin, other) = (&proxy.others[0], &proxy.others[1]);
    let line = format!("start: managed version {name}");
    proxy.records.wait_lines("the version", 1, |l| l == line);

    // Each TLS listener chooses the certificate of each site by the server name, and the routes of the version hold.
    let (answer, cert) = over_tls(
        &pki,
        tls_port,
        "www.a.example",
        &request("www.a.example", "192.0.2.1"),
    );
    assert_eq!((answer.status(), cert), (200, shown(&site_a.0)));
    assert_eq!(proxy.upstream.requests().len(), 1);
    let (answer, cert) = over_tls(
        &pki,
        h2_port,
        "b.example",
        "GET /b/x HTTP/1.1\r\nHost: b.example\r\n\r\n",
    );
    assert_eq!((answer.status(), cert), (200, shown(&site_b.0)));
    assert_eq!(other.requests().len(), 1);

    // The access of the version turns the network away, but not on the way to the admin process, which has its own
    // certificate; its own access list turns another network away.
    let (answer, _) = over_tls(
        &pki,
        tls_port,
        "www.a.example",
        &request("www.a.example", "198.51.100.9"),
    );
    assert_eq!(answer.status(), 403);
    let (answer, cert) = over_tls(
        &pki,
        tls_port,
        "admin.a.example",
        &request("admin.a.example", "198.51.100.9"),
    );
    assert_eq!((answer.status(), cert), (200, shown(&admin.0)));
    assert_eq!(standin.requests().len(), 1);
    let (answer, _) = over_tls(
        &pki,
        h2_port,
        "admin.a.example",
        &request("admin.a.example", "203.0.113.5"),
    );
    assert_eq!(answer.status(), 403);

    // A connection of HTTP/2 that the site of `*.a.example` took is not used for the way: 421, and nothing is sent.
    let mut client = Client::connect(&pki, h2_port);
    let send = &mut client.send;
    let code = client.runtime.block_on(async {
        send.ready().await.expect("the connection takes a request");
        let request = Request::get("https://admin.a.example/")
            .body(Full::new(Bytes::new()))
            .unwrap();
        send.send_request(request)
            .await
            .expect("a response")
            .status()
            .as_u16()
    });
    assert_eq!(code, 421);
    drop(client);
    // The listener that redirects sends the host of the way to https, also for a client that the access of the version
    // turns away, which it turns away for another host.
    let reply = exchange(
        redirect_port,
        &request("admin.a.example", "198.51.100.9").into_bytes(),
    );
    let message = reply.message();
    assert_eq!(message.status(), 308);
    assert_eq!(
        message.values("location"),
        [format!("https://admin.a.example:{tls_port}/").as_str()]
    );
    let reply = exchange(
        redirect_port,
        &request("www.a.example", "198.51.100.9").into_bytes(),
    );
    assert_eq!(reply.status(), 403);
    // Nor is a plain listener: 404, and the default group gets nothing.
    let reply = exchange(
        proxy.port,
        &request("admin.a.example", "192.0.2.1").into_bytes(),
    );
    assert_empty_answer(&reply, 404);
    assert_eq!(
        (standin.requests().len(), proxy.upstream.requests().len()),
        (1, 1)
    );

    // The control socket names the version in force.
    assert_eq!(status(proxy.root())["managed"], json!(name));
    finish(proxy, 1);
}

#[test]
#[ignore = "needs a built inspector"]
fn sighup_takes_the_chosen_version_and_a_version_that_activate_refuses_is_not_chosen() {
    let proxy = Proxy::start_with("mng_reload", knobs(), |root| {
        manage(root, |_, document| {
            document["upstreams"]
                .as_object_mut()
                .unwrap()
                .remove("admin");
        });
    });
    let root = proxy.root().to_path_buf();
    assert_eq!(exchange(proxy.port, &get("/x")).status(), 200);
    assert_eq!(proxy.upstream.requests().len(), 1);

    // A second version sends every request to `other`; it is chosen, and SIGHUP takes it.
    let document: Value =
        serde_json::from_str(&fs::read_to_string(root.join(DOCUMENT)).unwrap()).unwrap();
    let mut second = document.clone();
    second["default_upstream"] = json!("other");
    let name = import_and_activate(&root, &second);
    proxy.signal("HUP");
    let config = sha256(&fs::read(root.join("config.json")).unwrap());
    let line = format!(
        "reload: configuration replaced {} managed {name}",
        hex(&config)
    );
    proxy
        .records
        .wait_lines("the replacement", 1, |l| l == line);
    assert_eq!(exchange(proxy.port, &get("/x")).status(), 200);
    assert_eq!(proxy.others[1].requests().len(), 1);

    // A version whose server has a name that cannot be looked up is made, and is not chosen.
    let mut third = second.clone();
    third["upstreams"]["other"]["servers"] = json!([server("nowhere.invalid:80")]);
    let path = root.join(DOCUMENT);
    fs::write(&path, third.to_string()).unwrap();
    let (code, out, err) = managed(&root, "import", &[&path.to_string_lossy()]);
    assert_eq!(code, Some(0), "{err}");
    let refused = out.split_whitespace().next().unwrap().to_owned();
    let (code, _, err) = managed(&root, "activate", &[&refused]);
    assert_eq!(code, Some(1));
    assert!(
        err.contains("managed activate: upstream refused: "),
        "{err}"
    );
    let (_, listed, _) = managed(&root, "list", &[]);
    let current: Vec<&str> = listed
        .lines()
        .filter(|line| line.ends_with(" current"))
        .collect();
    assert_eq!(current.len(), 1);
    assert!(current[0].starts_with(&name), "{listed}");
    finish(proxy, 1);
}

// ---- the reload order of the control socket ----

#[test]
#[ignore = "needs a built inspector"]
fn a_reload_order_replaces_the_configuration_with_the_version_it_names_and_leaves_current_as_it_is()
{
    let mut pki = Pki::new("managed_order");
    let admin = pki.issue("admin", &["admin.a.example"]);
    let mut first = String::new();
    let proxy = Proxy::start_with("mng_order", knobs(), |root| {
        first = manage(root, |main, document| {
            with_admin(root, main, document, &admin);
        });
    });
    let root = proxy.root().to_path_buf();
    assert_eq!(exchange(proxy.port, &get("/x")).status(), 200);
    assert_eq!(proxy.upstream.requests().len(), 1);

    // A second version sends every request to `other`. It is made and not chosen; the order names it.
    let mut second = document(&root);
    second["default_upstream"] = json!("other");
    let name = import(&root, &second);
    let config = hex(&sha256(&fs::read(root.join("config.json")).unwrap()));
    assert_eq!(
        reload(&root, &name),
        json!({"result": "replaced", "config": config, "managed": name})
    );
    for line in [
        format!("reload: control reload {name}"),
        format!("reload: configuration replaced {config} managed {name}"),
        format!("control: reload {name}: replaced"),
    ] {
        proxy.records.wait_lines(&line, 1, |l| l == line);
    }
    // The next connection takes it, and the status names it.
    assert_eq!(exchange(proxy.port, &get("/x")).status(), 200);
    assert_eq!(proxy.others[1].requests().len(), 1);
    let answer = status(&root);
    assert_eq!(
        [
            &answer["managed"],
            &answer["config_reloads"],
            &answer["reloading"],
            &answer["resolve_timeout_ms"]
        ],
        [
            &json!(name),
            &json!({"replaced": 1, "refused": 0}),
            &json!(false),
            &json!(RESOLVE_TIMEOUT_MS)
        ]
    );
    // The proxy does not write the store: `current` names the first version still.
    let (_, listed, _) = managed(&root, "list", &[]);
    let current: Vec<&str> = listed
        .lines()
        .filter(|line| line.ends_with(" current"))
        .collect();
    assert_eq!(current.len(), 1, "{listed}");
    assert!(current[0].starts_with(&first), "{listed}");
    finish(proxy, 1);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_version_that_the_reading_refuses_is_answered_with_the_part_and_its_sentence_and_nothing_is_replaced()
 {
    let mut pki = Pki::new("managed_refused");
    let site_a = pki.issue("a", &["a.example"]);
    let site_b = pki.issue("b", &["b.example"]);
    let site_c = pki.issue("c", &["c.example"]);
    let admin = pki.issue("admin", &["admin.a.example"]);
    let tls_port = free_port();
    let mut first = String::new();
    let proxy = Proxy::start_with("mng_refused", knobs(), |root| {
        first = manage(root, |main, document| {
            let listeners = main["proxy"]["listeners"].as_array_mut().unwrap();
            listeners.push(tls_listener(tls_port, false));
            document["sites"] = json!([
                {"name": "a", "hosts": ["a.example"], "certificate": {"chain_file": site_a.0, "key_file": site_a.1}},
                {"name": "b", "hosts": ["b.example"], "certificate": {"chain_file": site_b.0, "key_file": site_b.1}},
            ]);
            with_admin(root, main, document, &admin);
        });
    });
    let root = proxy.root().to_path_buf();
    let store = root.join(MANAGED);
    let refused = |reason: &str, detail: &str| json!({"result": "refused", "reason": reason, "detail": detail, "managed": first});

    // A version whose site has the key of the other site: the sentence names the site, as the line does.
    let path = store.join("versions").join(format!("{first}.json"));
    let mut swapped: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    swapped["sites"][0]["certificate"]["key"] = swapped["sites"][1]["certificate"]["key"].clone();
    let bytes = serde_json::to_vec(&swapped).unwrap();
    let name = hex(&sha256(&bytes));
    fs::write(store.join("versions").join(format!("{name}.json")), &bytes).unwrap();
    let detail = "a certificate and a private key are not a pair (site a)";
    assert_eq!(reload(&root, &name), refused("tls", detail));
    let line = format!("reload: tls refused: {detail}");
    proxy.records.wait_lines(&line, 1, |l| l == line);

    // A version that names a file whose bytes are not what its name says.
    let mut third = document(&root);
    third["sites"].as_array_mut().unwrap().push(json!(
        {"name": "c", "hosts": ["c.example"], "certificate": {"chain_file": site_c.0, "key_file": site_c.1}}
    ));
    let name = import(&root, &third);
    let chain = hex(&sha256(&fs::read(&site_c.0).unwrap()));
    fs::write(
        store.join("files").join(chain),
        fs::read(&site_b.0).unwrap(),
    )
    .unwrap();
    assert_eq!(
        reload(&root, &name),
        refused("store", "a managed file does not match its name")
    );

    // A main file with another value that cannot change while the proxy runs, with the version in force.
    let config = root.join("config.json");
    let original = fs::read(&config).unwrap();
    let mut main: Value = serde_json::from_slice(&original).unwrap();
    main["proxy"]["max_conns"] = json!(main["proxy"]["max_conns"].as_u64().unwrap() + 1);
    fs::write(&config, main.to_string()).unwrap();
    assert_eq!(
        reload(&root, &first),
        refused("fixed", "proxy.max_conns cannot change while running")
    );
    fs::write(&config, &original).unwrap();

    // Nothing was replaced: the first version serves, and each reading is counted as refused.
    let answer = status(&root);
    assert_eq!(
        [&answer["managed"], &answer["config_reloads"]],
        [&json!(first), &json!({"replaced": 0, "refused": 3})]
    );
    let (answer, cert) = over_tls(
        &pki,
        tls_port,
        "a.example",
        &request("a.example", "192.0.2.1"),
    );
    assert_eq!((answer.status(), cert), (200, shown(&site_a.0)));
    finish(proxy, 1);
}

// ---- the order of the admin process ----

/// Starts the proxy of the test root `root` again with its configuration, as the service manager does after a stop,
/// asks `/x` at `port` once it listens, and stops it: the texts of its records, the status of the answer (`None` if it
/// did not listen in time or did not answer) and its exit code. It is killed if it does not listen in time.
fn start_again(root: &Path, port: u16) -> (Vec<String>, Option<u16>, Option<i32>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_tukuyomi-proxy"))
        .arg(root.join("config.json"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .env_remove("NOTIFY_SOCKET")
        .spawn()
        .expect("start the proxy again");
    let stderr = child.stderr.take().expect("the stderr is piped");
    let (send, texts) = mpsc::channel();
    let reader = thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            let record: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
            let text = record["line"].as_str().map_or(line.clone(), str::to_owned);
            if send.send(text).is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + 3 * MARGIN;
    let mut lines = Vec::new();
    let listening = loop {
        match texts.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(text) => {
                let done = text == "start: listening";
                lines.push(text);
                if done {
                    break true;
                }
            }
            Err(_) => break false,
        }
    };
    let answered = listening
        .then(|| std::panic::catch_unwind(|| exchange(port, &get("/x")).status()).ok())
        .flatten();
    if listening {
        run_kill("TERM", child.id());
    } else {
        // It may have ended by itself already.
        let _ = child.kill();
    }
    let code = child.wait().expect("wait for the proxy").code();
    reader.join().expect("the reader ends");
    lines.extend(texts.try_iter());
    (lines, answered, code)
}

#[test]
#[ignore = "needs a built inspector"]
fn the_order_of_the_admin_process_chooses_a_version_only_once_the_proxy_has_taken_it() {
    let mut pki = Pki::new("managed_apply");
    let admin = pki.issue("admin", &["admin.a.example"]);
    let mut first = String::new();
    let mut proxy = Proxy::start_with("mng_apply", knobs(), |root| {
        first = manage(root, |main, document| {
            with_admin(root, main, document, &admin);
        });
    });
    let root = proxy.root().to_path_buf();
    let original = document(&root);
    let digits = |text: &str| Fingerprint::from_hex(text.as_bytes()).unwrap().bytes();
    let store = Store::open(&root.join(MANAGED)).expect("open the store");
    let control = Control::new(&socket(&root), Duration::from_secs(20));
    let lookup = Duration::from_millis(RESOLVE_TIMEOUT_MS);
    let config = sha256(&fs::read(root.join("config.json")).unwrap());

    // A version whose server has a name that cannot be looked up: the proxy refuses it, and the store goes on choosing
    // the first.
    let mut refused = original.clone();
    refused["upstreams"]["other"]["servers"] = json!([server("nowhere.invalid:80")]);
    let name = import(&root, &refused);
    let ended = apply(
        &store,
        &control,
        digits(&first),
        digits(&name),
        lookup,
        |_| Ok::<(), ()>(()),
    );
    assert!(
        matches!(
            &ended,
            Outcome::Refused {
                reason: "upstream",
                ..
            }
        ),
        "{ended:?}"
    );
    assert_eq!(store.current(), Ok(Some(digits(&first))));
    assert_eq!(exchange(proxy.port, &get("/x")).status(), 200);
    assert_eq!(proxy.upstream.requests().len(), 1);

    // A version that sends every request to `other`: the proxy takes it, and then the store chooses it.
    let mut second = original;
    second["default_upstream"] = json!("other");
    let to = import(&root, &second);
    assert_eq!(
        apply(
            &store,
            &control,
            digits(&first),
            digits(&to),
            lookup,
            |_| Ok::<(), ()>(())
        ),
        Outcome::Applied {
            before: Some(config),
            after: Some(config)
        }
    );
    assert_eq!(store.current(), Ok(Some(digits(&to))));
    assert_eq!(exchange(proxy.port, &get("/x")).status(), 200);
    assert_eq!(proxy.others[1].requests().len(), 1);

    // Stopped and started again, the proxy comes up with the version that the store chooses.
    let since = proxy.term();
    let (status, _) = proxy.wait_exit(since, 3 * MARGIN);
    assert_eq!(status.code(), Some(0));
    let (lines, answered, code) = start_again(&root, proxy.port);
    let line = format!("start: managed version {to}");
    assert!(lines.contains(&line), "{lines:#?}");
    assert_eq!((answered, code), (Some(200), Some(0)), "{lines:#?}");
    assert_eq!(proxy.others[1].requests().len(), 2);
}

// ---- the certificates with `acme` ----

/// The `acme` object with its files in the directory of `pki` and a CA at a port where nothing listens.
fn acme_object(pki: &Pki) -> Value {
    json!({
        "directory_url": format!("https://127.0.0.1:{}/dir", free_port()),
        "contact_email": "ops@example.test",
        "account_key_file": pki.path("account.key"),
        "challenge_dir": pki.path("challenges"),
        "ca_file": pki.path("ca.pem"),
        "timeout_ms": 20_000,
    })
}

/// A site with `acme` for `hosts`.
fn acme_site(name: &str, hosts: &[&str]) -> Value {
    json!({"name": name, "hosts": hosts, "certificate": {"acme": {"renew_before_days": 30}}})
}

/// A request for the challenge of the token `Tok_-1` for `host`, from a client that `admin.route.access` turns away.
fn challenge(host: &str) -> Vec<u8> {
    format!(
        "GET /.well-known/acme-challenge/Tok_-1 HTTP/1.1\r\nHost: {host}\r\nX-Forwarded-For: 203.0.113.5\r\n\r\n"
    )
    .into_bytes()
}

/// Whether the handshake with the server name `name` at `port` is refused.
fn refused(pki: &Pki, port: u16, name: &str) -> bool {
    let mut stream = pki.client(name, port);
    stream.conn.complete_io(&mut stream.sock).is_err()
}

fn acme_renew(root: &Path) -> (Option<i32>, String, String) {
    let config = root.join("config.json");
    crate::acme::command(&[Path::new("acme"), Path::new("renew"), &config])
}

#[test]
#[ignore = "needs a built inspector"]
fn a_site_and_the_way_with_acme_wait_for_their_files_and_their_hosts_are_answered_the_challenge_of_the_version()
 {
    let mut pki = Pki::new("managed_acme");
    fs::create_dir(pki.path("challenges")).unwrap();
    let given = pki.issue("given", &["g.example"]);
    let way = (pki.path("admin.pem"), pki.path("admin.key"));
    let tls_port = free_port();
    let mut first = String::new();
    let proxy = Proxy::start_with("mng_acme", knobs(), |root| {
        first = manage(root, |main, document| {
            let listeners = main["proxy"]["listeners"].as_array_mut().unwrap();
            listeners.push(tls_listener(tls_port, false));
            main["acme"] = acme_object(&pki);
            document["sites"] = json!([
                acme_site("issued", &["s.example"]),
                acme_site("gone", &["x.example"]),
                {"name": "given", "hosts": ["g.example"], "certificate": {"chain_file": given.0, "key_file": given.1}},
            ]);
            with_admin(root, main, document, &way);
            main["admin"]["route"]["certificate"]["acme"] = json!({"renew_before_days": 30});
        });
    });
    let root = proxy.root().to_path_buf();
    // The start is not refused for the files that are not there: they are named, and their hosts get no handshake.
    for place in ["admin route", "site issued", "site gone"] {
        let line = format!("start: tls certificate not issued yet ({place})");
        proxy
            .records
            .wait_lines("a waiting certificate", 1, |l| l == line);
    }
    assert!(refused(&pki, tls_port, "s.example"));
    assert!(refused(&pki, tls_port, "admin.a.example"));
    let (answer, cert) = over_tls(
        &pki,
        tls_port,
        "g.example",
        &request("g.example", "192.0.2.1"),
    );
    assert_eq!((answer.status(), cert), (200, shown(&given.0)));

    // The plain listener answers the challenge for the hosts with acme, also to a client that the way to the admin
    // process turns away; for the host of the site without acme the request goes on to the upstream.
    fs::write(pki.path("challenges/Tok_-1"), b"abc.def").unwrap();
    for host in ["s.example", "admin.a.example", "x.example"] {
        let reply = exchange(proxy.port, &challenge(host));
        assert_eq!(
            (reply.status(), reply.message().body),
            (200, b"abc.def".to_vec()),
            "{host}"
        );
    }
    let reply = exchange(proxy.port, &challenge("g.example"));
    assert_eq!(reply.message().body, UPSTREAM_BODY.as_bytes());
    fs::remove_file(pki.path("challenges/Tok_-1")).unwrap();

    // The command cannot reach the CA: the way first, then the sites in the order of the version, all failed.
    let (code, out, err) = acme_renew(&root);
    assert_eq!(
        (code, out.as_str()),
        (
            Some(1),
            "admin route failed\nsite issued failed\nsite gone failed\n"
        ),
        "{err}"
    );
    assert_eq!(
        err,
        "acme renew: admin route: the CA cannot be reached\nacme renew: site issued: the CA cannot be reached\nacme renew: site gone: the CA cannot be reached\n"
    );

    // The files appear where the command writes them, and SIGUSR2 takes them.
    let issued = pki.issue("s", &["s.example"]);
    put_issued(&root, &["s.example"], &issued);
    let admin = pki.issue("admin", &["admin.a.example"]);
    assert_eq!(admin, way);
    proxy.signal("USR2");
    proxy.records.wait_lines("the certificates", 1, |l| {
        l == "reload: certificates replaced"
    });
    let (answer, cert) = over_tls(
        &pki,
        tls_port,
        "s.example",
        &request("s.example", "192.0.2.1"),
    );
    assert_eq!((answer.status(), cert), (200, shown(&issued.0)));
    let (answer, cert) = over_tls(
        &pki,
        tls_port,
        "admin.a.example",
        &request("admin.a.example", "198.51.100.9"),
    );
    assert_eq!((answer.status(), cert), (200, shown(&admin.0)));

    // A version whose site has one more host waits for a certificate of those hosts, and the site that it leaves out
    // is answered no challenge.
    let document: Value =
        serde_json::from_str(&fs::read_to_string(root.join(DOCUMENT)).unwrap()).unwrap();
    let mut second = document.clone();
    second["sites"] = json!([
        acme_site("issued", &["s.example", "t.example"]),
        document["sites"][2]
    ]);
    let name = import_and_activate(&root, &second);
    let config = hex(&sha256(&fs::read(root.join("config.json")).unwrap()));
    proxy.signal("HUP");
    let line = format!("reload: configuration replaced {config} managed {name}");
    proxy
        .records
        .wait_lines("the second version", 1, |l| l == line);
    proxy.records.wait_lines("the site of more hosts", 1, |l| {
        l == "reload: tls certificate not issued yet (site issued)"
    });
    assert!(refused(&pki, tls_port, "s.example"));
    fs::write(pki.path("challenges/Tok_-1"), b"abc.def").unwrap();
    let reply = exchange(proxy.port, &challenge("t.example"));
    assert_eq!(reply.message().body, b"abc.def");
    let reply = exchange(proxy.port, &challenge("x.example"));
    assert_eq!(reply.message().body, UPSTREAM_BODY.as_bytes());
    fs::remove_file(pki.path("challenges/Tok_-1")).unwrap();

    // Back to the first version: the certificate of its hosts is still there, and serves.
    let (code, _, err) = managed(&root, "activate", &[&first]);
    assert_eq!(code, Some(0), "{err}");
    proxy.signal("HUP");
    let line = format!("reload: configuration replaced {config} managed {first}");
    proxy
        .records
        .wait_lines("the first version again", 1, |l| l == line);
    let (answer, cert) = over_tls(
        &pki,
        tls_port,
        "s.example",
        &request("s.example", "192.0.2.1"),
    );
    assert_eq!((answer.status(), cert), (200, shown(&issued.0)));
    // The group `main` had the requests for g.example (two), s.example (two) and the challenge of x.example.
    finish(proxy, 5);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_link_in_the_place_of_the_directory_of_a_site_with_acme_refuses_the_start_and_the_command_orders_nothing()
 {
    let pki = Pki::new("managed_acme_link");
    fs::create_dir(pki.path("challenges")).unwrap();
    let idle = Idle::new("mng_acme_link", &Knobs::quick(), |_| {});
    let root = idle.root();
    manage(root, |main, document| {
        main["acme"] = acme_object(&pki);
        document["sites"] = json!([acme_site("issued", &["s.example"])]);
    });
    let elsewhere = pki.path("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    fs::write(elsewhere.join("chain"), b"the chain").unwrap();
    fs::write(elsewhere.join("key"), b"the key").unwrap();
    let place = root
        .join(MANAGED)
        .join("acme")
        .join(hex(&sha256(b"s.example\n")));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(place.parent().unwrap())
        .unwrap();
    std::os::unix::fs::symlink(&elsewhere, &place).unwrap();

    // The steps of the start refuse the link, and do not take it for a certificate that is not issued yet.
    let ran = crate::config_check::config_check(&idle);
    assert_eq!(ran.code, Some(1), "{}", ran.err);
    assert!(
        ran.err.contains(
            "config check: tls refused: a certificate or key file cannot be read (site issued)"
        ),
        "{}",
        ran.err
    );
    assert!(!ran.err.contains("not issued yet"), "{}", ran.err);

    // The command does not order the certificate: the store refused before the CA was asked, so the account key was
    // never made, and nothing was written through the link.
    let (code, out, err) = acme_renew(root);
    assert_eq!(
        (code, out.as_str()),
        (Some(1), "site issued failed\n"),
        "{err}"
    );
    assert_eq!(
        err,
        "acme renew: site issued: a directory of the managed store is not a real directory\n"
    );
    assert!(!pki.path("account.key").exists());
    let mut entries: Vec<String> = fs::read_dir(&elsewhere)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    entries.sort();
    assert_eq!(entries, ["chain", "key"]);
    assert_eq!(fs::read(elsewhere.join("chain")).unwrap(), b"the chain");
    assert_eq!(fs::read(elsewhere.join("key")).unwrap(), b"the key");

    // A version with no site with acme, and no way to the admin process: nothing to renew, and the exit code is 0.
    fs::remove_file(&place).unwrap();
    let document: Value =
        serde_json::from_str(&fs::read_to_string(root.join(DOCUMENT)).unwrap()).unwrap();
    let mut second = document;
    second["sites"] = json!([]);
    import_and_activate(root, &second);
    let (code, out, err) = acme_renew(root);
    assert_eq!((code, out.as_str()), (Some(0), ""), "{err}");
    assert_eq!(
        err,
        "acme renew: no certificate has acme, neither that of admin route nor a site of the managed version\n"
    );
}
