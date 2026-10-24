//! HTTP/2 on a listener that ends TLS, in a real process.
//!
//! The certificates are made like those of `tls`. The client is the HTTP/2 client of hyper on a TLS connection that
//! offers `h2`, in a runtime of the test's own.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use http::Request;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http2::{self, SendRequest};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::ClientConfig;
use rustls::crypto::aws_lc_rs::default_provider;
use rustls::pki_types::ServerName;
use serde_json::{Value, json};
use tokio::net::TcpStream;
use tokio::runtime::{Builder, Runtime};
use tokio_rustls::TlsConnector;

use crate::support::*;
use crate::tls::Pki;

/// Adds to the configuration in `root` a listener at `port` that ends TLS with the certificate `files` for `a.example`
/// and its subdomains, and speaks HTTP/2.
fn add_listener(root: &Path, port: u16, files: &(PathBuf, PathBuf)) {
    let (cert, key) = files;
    let path = root.join("config.json");
    let mut config: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    let listeners = config["proxy"]["listeners"].as_array_mut().unwrap();
    listeners.push(json!({
        "address": format!("127.0.0.1:{port}"),
        "tls": {
            "min_version": "1.2",
            "certificates": [{
                "cert_file": cert,
                "key_file": key,
                "hosts": ["a.example", "*.a.example"],
            }],
            "http2": {
                "max_streams": 128,
                "stream_window": 65535,
                "connection_window": 262_144,
                "max_header_list": 32768,
                "send_buffer": 16384,
            },
        },
    }));
    fs::write(&path, config.to_string()).unwrap();
}

/// One connection of an HTTP/2 client, with the runtime that drives it.
struct Client {
    runtime: Runtime,
    send: SendRequest<Full<Bytes>>,
}

impl Client {
    fn connect(pki: &Pki, port: u16) -> Client {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        let mut config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(pki.roots())
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let send = runtime.block_on(async {
            let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            let name = ServerName::try_from("www.a.example".to_owned()).unwrap();
            let tls = TlsConnector::from(Arc::new(config))
                .connect(name, tcp)
                .await
                .expect("the handshake");
            assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
            let (send, conn) = http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
                .await
                .expect("the HTTP/2 handshake");
            tokio::spawn(async move {
                let _ = conn.await;
            });
            send
        });
        Client { runtime, send }
    }

    /// The status and the body of the response to `request`.
    fn fetch(&mut self, request: Request<Full<Bytes>>) -> (u16, Vec<u8>) {
        let send = &mut self.send;
        self.runtime.block_on(async {
            send.ready().await.expect("the connection takes a request");
            let response = send.send_request(request).await.expect("a response");
            let status = response.status().as_u16();
            let body = response.into_body().collect().await.expect("the body");
            (status, body.to_bytes().to_vec())
        })
    }

    fn get(&mut self, path: &str) -> (u16, Vec<u8>) {
        let request = Request::get(format!("https://www.a.example{path}"))
            .body(Full::new(Bytes::new()))
            .unwrap();
        self.fetch(request)
    }

    fn post_form(&mut self, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
        let request = Request::post(format!("https://www.a.example{path}"))
            .header("content-type", URLENCODED)
            .body(Full::new(Bytes::copy_from_slice(body)))
            .unwrap();
        self.fetch(request)
    }
}

#[test]
#[ignore = "needs a built inspector"]
fn a_request_over_h2_is_inspected_and_reaches_the_upstream_as_http_1_1() {
    let mut pki = Pki::new("h2_forward");
    let files = pki.issue("a", &["a.example", "*.a.example"]);
    let port = free_port();
    let knobs = Knobs {
        keepalive_timeout_ms: 5_000,
        ..Knobs::quick()
    };
    let proxy = Proxy::start_with("h2_forward", knobs, |root| add_listener(root, port, &files));
    let mut client = Client::connect(&pki, port);

    // A request that nothing blocks goes to the upstream, as a request of HTTP/1.1 with its target alone.
    let (status, body) = client.get("/ok?q=1");
    assert_eq!((status, body.as_slice()), (200, UPSTREAM_BODY.as_bytes()));
    let requests = proxy.upstream.requests();
    assert_eq!(requests.len(), 1);
    let seen = Message::parse(&requests[0]);
    assert_eq!(seen.start, "GET /ok?q=1 HTTP/1.1");
    assert_eq!(seen.values("host"), ["www.a.example"]);
    assert_eq!(seen.values("x-forwarded-proto"), ["https"]);

    // The rules see a request over h2 as any other: the one on the target, and the one on the body.
    assert_eq!(client.get("/block-probe").0, 403);
    assert_eq!(client.post_form("/p", b"probe=block").0, 403);

    // A body of half a MiB crosses the windows of the connection and reaches the upstream whole.
    let big = padded_form("fine", 512 * 1024);
    assert_eq!(client.post_form("/ok", &big).0, 200);
    let requests = proxy.upstream.requests();
    assert_eq!(requests.len(), 2);
    let seen = Message::parse(&requests[1]);
    let length = big.len().to_string();
    assert_eq!(seen.values("content-length"), [length.as_str()]);
    assert!(seen.body == big);

    drop(client);
    proxy.records.conns("the forwarded records", 2, |l| {
        l.contains(": forwarded 200 forwarded rule - ")
    });
    proxy
        .records
        .conn("the block by the target", |l| l.contains(&blocked_by(9201)));
    proxy
        .records
        .conn("the block by the body", |l| l.contains(&blocked_by(9202)));
    proxy.finish(2);
}
