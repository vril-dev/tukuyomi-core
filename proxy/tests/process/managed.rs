//! A configuration with `managed` in a real process. The routing of a test is a version of the managed store in its
//! root, made from a document with `managed import` and chosen with `managed activate` (see `support::manage`). The
//! second upstream of a test stands for the admin process, at `admin.listen`, and the third is the server of a group
//! of its own. The certificates are made like those of `tls`. The client is a trusted proxy (`trusted_proxies`), so
//! that a request can come from another address by its `X-Forwarded-For`.

use std::fs;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

use bytes::Bytes;
use http::Request;
use http_body_util::Full;
use serde_json::{Value, json};
use tukuyomi_proxy::rules::bundle::{hex, sha256};

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

/// The one line of the answer of the control socket in `root` to a status question.
fn status(root: &Path) -> Value {
    let mut sock = std::os::unix::net::UnixStream::connect(socket(root))
        .expect("connect to the control socket");
    sock.set_read_timeout(Some(MARGIN)).unwrap();
    sock.write_all(b"{\"op\":\"status\"}\n").unwrap();
    let mut out = String::new();
    sock.read_to_string(&mut out).unwrap();
    serde_json::from_str(&out).expect("a line of JSON")
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
