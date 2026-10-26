//! The proxy in front of an upstream that speaks TLS, in a real process.
//!
//! The upstream is made here: a listener on a loopback port that ends TLS (rustls, on a thread for each connection)
//! with a certificate that the `openssl` command made into a directory of its own under `TUKUYOMI_TEST_TMP`, which
//! is removed when the test is over. It answers a request, or, to the handshake of a WebSocket, says 101 and sends
//! back what it reads. It records the server name and the protocol of ALPN that the proxy used, and the requests.
//! The configuration that the harness wrote is changed before the proxy starts: the group `main` gets the server
//! and the `tls`.

use std::fs::{self, DirBuilder};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use rustls::crypto::aws_lc_rs::default_provider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use serde_json::{Value, json};

use crate::support::*;
use crate::websocket::open_route;

/// The name in the certificate of the upstream, and the `server_name` of the group.
const NAME: &str = "up.example";

/// The answer to a request, and to the handshake of a WebSocket.
const REPLY: &str =
    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 19\r\n\r\nhello-from-upstream";
const SWITCHING: &str = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";

/// A certificate authority and the certificate it issued, in a directory that is removed when it is dropped.
struct Pki {
    dir: PathBuf,
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
        let pki = Pki { dir };
        openssl(
            &pki.dir,
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
        pki
    }

    /// The file of the authority.
    fn ca(&self) -> PathBuf {
        self.dir.join("ca.pem")
    }

    /// A file of the directory with these bytes.
    fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.dir.join(name);
        fs::write(&path, bytes).expect("write a file of the directory");
        path
    }

    /// The certificate for `NAME`, signed by the authority, and its key.
    fn issue(&self) -> (PathBuf, PathBuf) {
        self.file(
            "up.ext",
            format!("basicConstraints=CA:FALSE\nsubjectAltName=DNS:{NAME}\n").as_bytes(),
        );
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
                "up.key",
                "-out",
                "up.csr",
                "-subj",
                "/CN=up",
            ],
        );
        openssl(
            &self.dir,
            &[
                "x509",
                "-req",
                "-in",
                "up.csr",
                "-CA",
                "ca.pem",
                "-CAkey",
                "ca.key",
                "-set_serial",
                "101",
                "-out",
                "up.pem",
                "-days",
                "2",
                "-extfile",
                "up.ext",
            ],
        );
        (self.dir.join("up.pem"), self.dir.join("up.key"))
    }
}

impl Drop for Pki {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// The server name and the protocol of ALPN of a connection.
type Hello = (Option<String>, Option<Vec<u8>>);

/// What an upstream took.
#[derive(Default)]
struct Took {
    connections: AtomicUsize,
    /// One for each connection.
    hellos: Mutex<Vec<Hello>>,
    /// Each request, head and nothing else.
    requests: Mutex<Vec<Vec<u8>>>,
}

/// A listener that ends TLS and answers like the upstream of the harness does, without keeping its tests apart from
/// the harness: the harness upstream sees nothing.
struct TlsUpstream {
    addr: SocketAddr,
    took: Arc<Took>,
    stopping: Arc<AtomicBool>,
    accepter: Option<JoinHandle<Vec<JoinHandle<()>>>>,
}

impl TlsUpstream {
    fn start(cert: &Path, key: &Path) -> TlsUpstream {
        let chain = CertificateDer::pem_file_iter(cert)
            .expect("open the certificate")
            .collect::<Result<Vec<_>, _>>()
            .expect("read the certificate");
        let key = PrivateKeyDer::from_pem_file(key).expect("read the key");
        let mut config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .expect("the versions of TLS")
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .expect("the certificate and the key");
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let config = Arc::new(config);

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind the upstream");
        listener
            .set_nonblocking(true)
            .expect("make the upstream non-blocking");
        let addr = listener.local_addr().expect("the upstream address");
        let took = Arc::new(Took::default());
        let stopping = Arc::new(AtomicBool::new(false));
        let accepter = {
            let (took, stopping) = (took.clone(), stopping.clone());
            thread::spawn(move || accept_loop(&listener, &config, &took, &stopping))
        };
        TlsUpstream {
            addr,
            took,
            stopping,
            accepter: Some(accepter),
        }
    }

    fn connections(&self) -> usize {
        self.took.connections.load(Ordering::SeqCst)
    }

    fn requests(&self) -> Vec<Vec<u8>> {
        self.took.requests.lock().unwrap().clone()
    }

    /// Closes the listener and waits for the connection threads. The proxy has to be gone, or has to close its
    /// connections, for they end.
    fn stop(&mut self) {
        self.stopping.store(true, Ordering::SeqCst);
        if let Some(accepter) = self.accepter.take() {
            for handler in accepter.join().expect("the accept loop panicked") {
                handler.join().expect("a connection panicked");
            }
        }
    }
}

impl Drop for TlsUpstream {
    fn drop(&mut self) {
        // After a failed test the loop still has to end.
        self.stopping.store(true, Ordering::SeqCst);
    }
}

fn accept_loop(
    listener: &TcpListener,
    config: &Arc<ServerConfig>,
    took: &Arc<Took>,
    stopping: &AtomicBool,
) -> Vec<JoinHandle<()>> {
    let mut handlers = Vec::new();
    loop {
        match listener.accept() {
            Ok((sock, _)) => {
                took.connections.fetch_add(1, Ordering::SeqCst);
                let (config, took) = (config.clone(), took.clone());
                handlers.push(thread::spawn(move || serve(sock, config, &took)));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if stopping.load(Ordering::SeqCst) {
                    break;
                }
                thread::sleep(2 * MS);
            }
            Err(_) => break,
        }
    }
    handlers
}

/// One connection: a request after another until the other side ends, or an echo after the handshake of a
/// WebSocket.
fn serve(sock: TcpStream, config: Arc<ServerConfig>, took: &Took) {
    sock.set_nonblocking(false)
        .expect("make the connection blocking");
    sock.set_read_timeout(Some(60 * SEC))
        .expect("set the read timeout");
    sock.set_write_timeout(Some(60 * SEC))
        .expect("set the write timeout");
    let Ok(conn) = ServerConnection::new(config) else {
        return;
    };
    let mut stream = StreamOwned::new(conn, sock);
    let mut greeted = false;
    while let Some(request) = read_request(&mut stream) {
        if !greeted {
            greeted = true;
            let hello = (
                stream.conn.server_name().map(str::to_string),
                stream.conn.alpn_protocol().map(<[u8]>::to_vec),
            );
            took.hellos.lock().unwrap().push(hello);
        }
        took.requests.lock().unwrap().push(request.clone());
        if Message::parse(&request).values("upgrade") == ["websocket"] {
            echo(&mut stream, &request);
            return;
        }
        if stream.write_all(REPLY.as_bytes()).is_err() {
            return;
        }
    }
    close(&mut stream);
}

/// The closing alert of TLS, as the end of what this side has to say.
fn close(stream: &mut StreamOwned<ServerConnection, TcpStream>) {
    stream.conn.send_close_notify();
    let _ = stream.flush();
}

/// The head of the next request, or `None` if the other side ends first.
fn read_request(stream: &mut StreamOwned<ServerConnection, TcpStream>) -> Option<Vec<u8>> {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    while find(&raw, b"\r\n\r\n").is_none() {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return None,
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
        }
    }
    Some(raw)
}

/// Says 101 and sends back every byte it reads, until the other side ends its own.
fn echo(stream: &mut StreamOwned<ServerConnection, TcpStream>, request: &[u8]) {
    let mut behind = request[find(request, b"\r\n\r\n").map_or(0, |end| end + 4)..].to_vec();
    if stream.write_all(SWITCHING.as_bytes()).is_err() {
        return;
    }
    let mut chunk = [0u8; 16 * 1024];
    loop {
        if !behind.is_empty() && stream.write_all(&std::mem::take(&mut behind)).is_err() {
            return;
        }
        match stream.read(&mut chunk) {
            Ok(0) => return close(stream),
            Err(_) => return,
            Ok(n) => behind.extend_from_slice(&chunk[..n]),
        }
    }
}

/// The `forward` object of a proxy whose default group `main` has no server yet, and no route.
fn plain_forward() -> Value {
    json!({
        "resolve_timeout_ms": RESOLVE_TIMEOUT_MS,
        "upstreams": {},
        "routes": [],
        "default_upstream": "main",
    })
}

/// Changes the configuration in `root`: the group `main` of `forward` has the server at `upstream` and this `tls`.
fn point_at(root: &Path, mut forward: Value, upstream: SocketAddr, tls: Value) {
    let path = root.join("config.json");
    let mut config: Value =
        serde_json::from_str(&fs::read_to_string(&path).expect("read the configuration"))
            .expect("the configuration is JSON");
    forward["upstreams"]["main"] = json!({"servers": [server(upstream)], "tls": tls});
    config["forward"] = forward;
    fs::write(&path, config.to_string()).expect("write the configuration");
}

#[test]
#[ignore = "needs a built inspector"]
fn a_request_goes_to_an_upstream_that_speaks_tls_and_its_connection_is_used_again() {
    let pki = Pki::new("upstream_tls");
    let (cert, key) = pki.issue();
    let mut upstream = TlsUpstream::start(&cert, &key);
    let knobs = Knobs {
        upstream_keepalive: 4,
        ..Knobs::quick()
    };
    let tls = json!({"ca_file": pki.ca(), "server_name": NAME});
    let proxy = Proxy::start_with("upstream_tls", knobs, |root| {
        point_at(root, plain_forward(), upstream.addr, tls);
    });
    for _ in 0..2 {
        let reply = exchange(proxy.port, &get("/ok?q=1"));
        assert_eq!(reply.status(), 200, "{:?}", reply.text());
        assert_eq!(reply.message().body, UPSTREAM_BODY.as_bytes());
    }
    // One connection carried both requests, and it was TLS with the name and the protocol the group says.
    assert_eq!(upstream.connections(), 1);
    assert_eq!(
        *upstream.took.hellos.lock().unwrap(),
        [(Some(NAME.to_string()), Some(b"http/1.1".to_vec()))]
    );
    let requests = upstream.requests();
    assert_eq!(requests.len(), 2);
    let seen = Message::parse(&requests[0]);
    assert_eq!(seen.start, "GET /ok?q=1 HTTP/1.1");
    assert_eq!(seen.values("x-forwarded-proto"), ["http"]);
    proxy.records.conns("the forwarded records", 2, |l| {
        is_answer(l, "forwarded", 200, "forwarded")
            && no(l, "rule")
            && l["upstream"] == "main"
            && l["server"]
                .as_str()
                .is_some_and(|s| s.starts_with("127.0.0.1:"))
    });
    proxy.finish(0);
    upstream.stop();
}

#[test]
#[ignore = "needs a built inspector"]
fn a_websocket_echoes_through_an_upstream_that_speaks_tls_in_pieces_of_several_records() {
    let pki = Pki::new("upstream_tls_ws");
    let (cert, key) = pki.issue();
    let mut upstream = TlsUpstream::start(&cert, &key);
    let tls = json!({"ca_file": pki.ca(), "server_name": NAME});
    let proxy = Proxy::start_with("upstream_tls_ws", Knobs::quick(), |root| {
        point_at(root, open_route(&[upstream.addr]), upstream.addr, tls);
    });
    let mut sock = connect(proxy.port);
    sock.set_read_timeout(Some(30 * SEC))
        .expect("set the read timeout");
    sock.write_all(
        b"GET /chat HTTP/1.1\r\nHost: example.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
    )
    .expect("send the handshake");
    let mut head = Vec::new();
    let mut chunk = [0u8; 4096];
    while find(&head, b"\r\n\r\n").is_none() {
        let n = sock.read(&mut chunk).expect("read the answer");
        assert_ne!(n, 0, "the proxy closed; got {head:?}");
        head.extend_from_slice(&chunk[..n]);
    }
    let reply = Message::parse(&head);
    assert_eq!(reply.status(), 101, "{:?}", String::from_utf8_lossy(&head));
    assert_eq!(reply.values("upgrade"), ["websocket"]);

    // Each piece is longer than two records of TLS on the way to the upstream and on the way back, and the upstream
    // has nothing more to say after it: the end of the piece has to reach the client by itself.
    let mut total = 0;
    for round in 0..4u8 {
        let piece: Vec<u8> = (0..40_000u32)
            .map(|i| u8::try_from(i % 251).unwrap() ^ round)
            .collect();
        sock.write_all(&piece).expect("send a piece");
        let mut back = vec![0u8; piece.len()];
        sock.read_exact(&mut back)
            .expect("the whole piece comes back");
        assert!(back == piece, "piece {round} came back changed");
        total += piece.len();
    }

    // The client ends its side; the upstream ends its own with the closing alert, and the proxy writes a line.
    sock.shutdown(Shutdown::Write)
        .expect("end the writing side");
    assert!(read_to_close(&mut sock).is_empty());
    proxy.records.conn("the record of the tunnel", |l| {
        l["type"] == "tunnel"
            && l["end"] == "closed"
            && l["upstream"] == "main"
            && l["to_upstream"] == total
            && l["from_upstream"] == total
    });
    let requests = upstream.requests();
    assert_eq!(requests.len(), 1);
    let seen = Message::parse(&requests[0]);
    assert_eq!(seen.values("upgrade"), ["websocket"]);
    assert_eq!(seen.values("connection"), ["upgrade"]);
    proxy.finish(0);
    upstream.stop();
}

#[test]
#[ignore = "needs a built inspector"]
fn a_file_of_authorities_that_cannot_be_used_ends_the_start_with_exit_code_1_and_no_listener() {
    let pki = Pki::new("upstream_tls_ca");
    let missing = pki.dir.join("missing.pem");
    let empty = pki.file("empty.pem", b"");
    // Nothing is connected to: the address is one that is reserved for documents.
    let upstream: SocketAddr = "192.0.2.1:443".parse().unwrap();
    for (n, (ca_file, sentence)) in [
        (missing, "an upstream ca_file cannot be read"),
        (
            empty,
            "an upstream ca_file does not hold 1 to 100 certificates in PEM",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let mut proxy = Proxy::spawn_with(&format!("upstream_tls_ca{n}"), Knobs::quick(), |root| {
            let tls = json!({"ca_file": ca_file});
            point_at(root, plain_forward(), upstream, tls);
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
            format!("start: upstream refused: {sentence} (upstream main)")
        );
        assert_turned_away(proxy.port);
        proxy.clear_root(&["config.json", STORE]);
    }
}
