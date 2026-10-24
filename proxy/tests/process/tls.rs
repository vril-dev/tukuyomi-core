//! The listeners that end TLS and the listeners that redirect, in a real process.
//!
//! The certificates are made by the `openssl` command into a directory of their own under `TUKUYOMI_TEST_TMP` (the
//! test root holds nothing but the configuration and the store when a test ends), and that directory is removed when
//! the test is over. The client is a TLS client of rustls on a plain socket; its name for the server is what the
//! test says.

use std::fs::{self, DirBuilder};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use rustls::crypto::aws_lc_rs::default_provider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde_json::{Value, json};

use crate::support::*;
use crate::websocket::open_route;

/// A certificate authority and what it issued, in a directory that is removed when it is dropped.
struct Pki {
    dir: PathBuf,
    serial: u32,
}

fn openssl(dir: &Path, args: &[&str]) {
    let out = Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("run the openssl command");
    assert!(
        out.status.success(),
        "openssl {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

impl Pki {
    fn new(test: &str) -> Pki {
        let parent = std::env::var("TUKUYOMI_TEST_TMP").expect("TUKUYOMI_TEST_TMP is set");
        let dir = PathBuf::from(parent).join(format!("{test}-pki-{}", std::process::id()));
        DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .expect("make the directory of the certificates");
        openssl(
            &dir,
            &[
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-nodes",
                "-keyout",
                "ca.key",
                "-out",
                "ca.pem",
                "-subj",
                "/CN=test-ca",
                "-days",
                "2",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign",
            ],
        );
        Pki { dir, serial: 100 }
    }

    /// A certificate for the names, and its key, as `a.pem` and `a.key` for the stem `a`. Issuing again with the
    /// same stem replaces the files.
    fn issue(&mut self, stem: &str, names: &[&str]) -> (PathBuf, PathBuf) {
        self.serial += 1;
        let serial = self.serial.to_string();
        let (key, csr, ext, cert) = (
            format!("{stem}.key"),
            format!("{stem}.csr"),
            format!("{stem}.ext"),
            format!("{stem}.pem"),
        );
        let list: Vec<String> = names.iter().map(|name| format!("DNS:{name}")).collect();
        fs::write(
            self.dir.join(&ext),
            format!(
                "basicConstraints=CA:FALSE\nsubjectAltName={}\n",
                list.join(",")
            ),
        )
        .unwrap();
        openssl(
            &self.dir,
            &[
                "req",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-nodes",
                "-keyout",
                &key,
                "-out",
                &csr,
                "-subj",
                &format!("/CN={stem}"),
            ],
        );
        openssl(
            &self.dir,
            &[
                "x509",
                "-req",
                "-in",
                &csr,
                "-CA",
                "ca.pem",
                "-CAkey",
                "ca.key",
                "-set_serial",
                &serial,
                "-out",
                &cert,
                "-days",
                "2",
                "-extfile",
                &ext,
            ],
        );
        (self.dir.join(cert), self.dir.join(key))
    }

    /// A client that trusts the authority, for the server named `name`.
    fn client(&self, name: &str, port: u16) -> StreamOwned<ClientConnection, TcpStream> {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_file(self.dir.join("ca.pem")).unwrap())
            .unwrap();
        let config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = ServerName::try_from(name.to_owned()).unwrap();
        let conn = ClientConnection::new(Arc::new(config), name).unwrap();
        let sock = connect(port);
        sock.set_read_timeout(Some(30 * SEC)).unwrap();
        StreamOwned::new(conn, sock)
    }
}

impl Drop for Pki {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// The ports of a test, besides the plain one.
struct Ports {
    tls: u16,
    redirect: u16,
}

impl Ports {
    fn new() -> Ports {
        Ports {
            tls: free_port(),
            redirect: free_port(),
        }
    }

    /// Adds to the configuration in `root`, besides the plain listener, one that ends TLS with the certificate
    /// `files` for the names `a.example` and `*.a.example` and one that redirects to https at the port of the first.
    fn add_to(&self, root: &Path, files: &(PathBuf, PathBuf)) {
        let (cert, key) = files;
        let path = root.join("config.json");
        let mut config: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let listeners = config["proxy"]["listeners"].as_array_mut().unwrap();
        listeners.push(json!({
            "address": format!("127.0.0.1:{}", self.tls),
            "tls": {
                "min_version": "1.2",
                "certificates": [{
                    "cert_file": cert,
                    "key_file": key,
                    "hosts": ["a.example", "*.a.example"],
                }],
            },
        }));
        listeners.push(json!({
            "address": format!("127.0.0.1:{}", self.redirect),
            "redirect": {"https_port": self.tls},
        }));
        fs::write(&path, config.to_string()).unwrap();
    }
}

/// Starts a proxy with those listeners (see `Ports::add_to`).
fn start(test: &str, files: &(PathBuf, PathBuf)) -> (Proxy, Ports) {
    let ports = Ports::new();
    let proxy = Proxy::start_with(test, Knobs::quick(), |root| ports.add_to(root, files));
    (proxy, ports)
}

/// One request over TLS on a new connection, and everything the proxy answers until it ends the connection with the
/// closing alert of TLS. Also the certificate the server showed.
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

fn request(target: &str, host: &str) -> String {
    format!("GET {target} HTTP/1.1\r\nHost: {host}\r\n\r\n")
}

#[test]
#[ignore = "needs a built inspector"]
fn a_request_over_tls_is_inspected_and_forwarded_and_sigusr2_replaces_the_certificate() {
    let mut pki = Pki::new("tls_forward");
    let files = pki.issue("a", &["a.example", "*.a.example"]);
    let (proxy, ports) = start("tls_forward", &files);

    let (answer, first) = over_tls(
        &pki,
        ports.tls,
        "www.a.example",
        &request("/ok?q=1", "www.a.example"),
    );
    assert_eq!(answer.status(), 200, "{:?}", answer.start);
    assert_eq!(answer.body, UPSTREAM_BODY.as_bytes());
    let requests = proxy.upstream.requests();
    assert_eq!(requests.len(), 1);
    let seen = Message::parse(&requests[0]);
    assert_eq!(seen.values("x-forwarded-proto"), ["https"]);
    assert_eq!(seen.values("x-forwarded-host"), ["www.a.example"]);

    // The rules see a request over TLS as any other.
    let (answer, _) = over_tls(
        &pki,
        ports.tls,
        "a.example",
        &request("/block-probe", "a.example"),
    );
    assert_eq!(answer.status(), 403);
    // A name that no host has gets no certificate.
    let mut refused = pki.client("b.example", ports.tls);
    assert!(refused.conn.complete_io(&mut refused.sock).is_err());

    // A broken file leaves the certificate as it is; a good one replaces it.
    fs::write(&files.1, b"not a key").unwrap();
    proxy.signal("USR2");
    proxy.records.wait_lines("the refusal", 1, |l| {
        l.starts_with("reload: certificates refused")
    });
    let (_, shown) = over_tls(
        &pki,
        ports.tls,
        "a.example",
        &request("/block-probe", "a.example"),
    );
    assert_eq!(shown, first);
    pki.issue("a", &["a.example", "*.a.example"]);
    proxy.signal("USR2");
    proxy.records.wait_lines("the replacement", 1, |l| {
        l == "reload: certificates replaced"
    });
    let (_, shown) = over_tls(
        &pki,
        ports.tls,
        "a.example",
        &request("/block-probe", "a.example"),
    );
    assert_ne!(shown, first);

    proxy.records.conn("the forwarded record", |l| {
        l.contains(": forwarded 200 forwarded rule - ")
    });
    proxy.finish(1);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_host_the_certificate_does_not_cover_gets_421_and_nothing_reaches_the_upstream() {
    let mut pki = Pki::new("tls_421");
    let files = pki.issue("a", &["a.example", "*.a.example"]);
    let (proxy, ports) = start("tls_421", &files);
    for host in ["other.example", "192.0.2.1", "a.example.net"] {
        let (answer, _) = over_tls(&pki, ports.tls, "a.example", &request("/ok", host));
        assert_eq!(answer.status(), 421, "{host}");
        assert_eq!(answer.values("content-length"), ["0"]);
    }
    proxy.records.conns("the 421 records", 3, |l| {
        l.contains(": rejected 421 host not covered by the certificate rule - ")
    });
    assert_eq!(proxy.upstream.connections(), 0);
    proxy.finish(0);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_redirect_listener_sends_a_served_host_to_https_and_answers_any_other_with_404() {
    let mut pki = Pki::new("tls_redirect");
    let files = pki.issue("a", &["a.example", "*.a.example"]);
    let (proxy, ports) = start("tls_redirect", &files);
    let reply = exchange(
        ports.redirect,
        request("/p/q?x=1&y=%41", "Www.A.Example:80").as_bytes(),
    );
    let answer = reply.message();
    assert_eq!(answer.status(), 308, "{:?}", reply.text());
    let want = format!("https://www.a.example:{}/p/q?x=1&y=%41", ports.tls);
    assert_eq!(answer.values("location"), [want.as_str()]);
    assert_eq!(answer.values("content-length"), ["0"]);
    assert_eq!(answer.values("connection"), ["close"]);
    for host in ["other.example", "192.0.2.1", "[::1]"] {
        let reply = exchange(ports.redirect, request("/p", host).as_bytes());
        assert_empty_answer(&reply, 404);
    }
    proxy.records.conns("the redirect records", 1, |l| {
        l.contains(": redirected 308 redirected rule - ")
    });
    assert_eq!(proxy.upstream.connections(), 0);
    proxy.finish(0);
}

/// The handshake of a WebSocket for the host `host`.
fn upgrade(host: &str) -> String {
    format!(
        "GET /chat HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
}

#[test]
#[ignore = "needs a built inspector"]
fn a_websocket_echoes_over_tls_in_pieces_of_several_records_and_ends_with_the_closing_alert() {
    let mut pki = Pki::new("tls_websocket");
    let files = pki.issue("a", &["a.example", "*.a.example"]);
    let knobs = Knobs {
        forward: open_route,
        ..Knobs::quick()
    };
    let ports = Ports::new();
    let proxy = Proxy::start_with("tls_websocket", knobs, |root| ports.add_to(root, &files));

    let mut stream = pki.client("a.example", ports.tls);
    stream
        .write_all(upgrade("a.example").as_bytes())
        .expect("send the handshake");
    let mut head = Vec::new();
    let mut chunk = [0u8; 4096];
    while find(&head, b"\r\n\r\n").is_none() {
        let n = stream.read(&mut chunk).expect("read the answer");
        assert_ne!(n, 0, "the proxy closed; got {head:?}");
        head.extend_from_slice(&chunk[..n]);
    }
    assert_eq!(
        Message::parse(&head).status(),
        101,
        "{:?}",
        String::from_utf8_lossy(&head)
    );

    // Each piece is longer than two records of TLS, and the upstream sends it back and then has nothing more to
    // say: the end of the piece has to reach the client without anything behind it to push it.
    let mut total = 0;
    for round in 0..8u8 {
        let piece: Vec<u8> = (0..40_000u32)
            .map(|i| u8::try_from(i % 251).unwrap() ^ round)
            .collect();
        stream.write_all(&piece).expect("send a piece");
        let mut back = vec![0u8; piece.len()];
        stream
            .read_exact(&mut back)
            .expect("the whole piece comes back");
        assert!(back == piece, "piece {round} came back changed");
        total += piece.len();
    }

    // The client ends its side with the closing alert; the upstream ends its own, and the proxy ends the connection
    // with its closing alert and writes a line for the tunnel.
    stream.conn.send_close_notify();
    stream.flush().expect("send the closing alert");
    let mut rest = Vec::new();
    stream
        .read_to_end(&mut rest)
        .expect("the proxy ended the connection with the closing alert");
    assert!(rest.is_empty());
    proxy.records.conn("the record of the tunnel", |l| {
        l.contains(": tunnel closed ")
            && l.ends_with(&format!(" to-upstream {total} from-upstream {total}"))
    });
    proxy.finish(1);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_key_that_is_not_the_key_of_the_certificate_ends_the_start_with_exit_code_1_and_no_listener() {
    let mut pki = Pki::new("tls_pair");
    let a = pki.issue("a", &["a.example", "*.a.example"]);
    let b = pki.issue("b", &["b.example"]);
    let ports = Ports::new();
    let mut proxy = Proxy::spawn_with("tls_pair", Knobs::quick(), |root| {
        ports.add_to(root, &(a.0.clone(), b.1.clone()));
    });
    let started = proxy.started;
    let (status, _) = proxy.wait_exit(started, MARGIN);
    let lines = proxy.records.lines();
    assert_eq!(
        status.code(),
        Some(1),
        "exit status {status}; records: {lines:#?}"
    );
    assert_eq!(lines.len(), 2, "records: {lines:#?}");
    assert_eq!(lines[0], "start: configuration accepted");
    assert_eq!(
        lines[1],
        "start: tls refused: a certificate and a private key are not a pair (listener 2, certificate 1)"
    );
    assert_turned_away(ports.tls);
    proxy.clear_root(&["config.json", STORE]);
}
