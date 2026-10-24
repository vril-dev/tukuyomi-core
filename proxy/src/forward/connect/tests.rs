//! The upstreams of these tests are made here: a listener that speaks TLS with a certificate made by the `openssl`
//! command (see `tls`), and one that speaks plain HTTP.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::crypto::aws_lc_rs::default_provider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, SupportedProtocolVersion, version};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use super::*;
use crate::config::{Address, ForwardConfig, GroupConfig};
use crate::forward::origin::tests::{bare, collect, config, ctx_of, far, run, send};
use crate::forward::origin::{OriginBody, forward};
use crate::forward::rewrite::Rewrite;
use crate::forward::tls::tests::{Pair, Pki};
use crate::forward::tls::{self, Client, Settings};
use crate::inbound::conn::Ctx;

const OK_REPLY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

/// The server name and the protocol of ALPN of a handshake.
type Hello = (Option<String>, Option<Vec<u8>>);

/// What an upstream took.
#[derive(Default)]
struct Took {
    /// The connections it accepted, the requests it answered, and the handshakes that did not end well.
    accepted: AtomicUsize,
    served: AtomicUsize,
    failed: AtomicUsize,
    /// One for each handshake that ended well.
    hellos: Mutex<Vec<Hello>>,
    /// The first bytes of each connection of a plain upstream.
    first: Mutex<Vec<Vec<u8>>>,
}

fn acceptor(pair: &Pair, versions: &[&'static SupportedProtocolVersion]) -> TlsAcceptor {
    let chain = CertificateDer::pem_file_iter(&pair.cert)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_file(&pair.key).unwrap();
    let mut config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(versions)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    TlsAcceptor::from(Arc::new(config))
}

/// Answers each request of a connection with `OK_REPLY`, over TLS.
async fn serve_tls(sock: TcpStream, acceptor: TlsAcceptor, took: Arc<Took>) {
    took.accepted.fetch_add(1, Ordering::SeqCst);
    let Ok(mut stream) = acceptor.accept(sock).await else {
        took.failed.fetch_add(1, Ordering::SeqCst);
        return;
    };
    let hello = {
        let (_, session) = stream.get_ref();
        (
            session.server_name().map(str::to_string),
            session.alpn_protocol().map(<[u8]>::to_vec),
        )
    };
    took.hellos.lock().unwrap().push(hello);
    let mut head = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => head.extend_from_slice(&chunk[..n]),
            }
        }
        head.clear();
        took.served.fetch_add(1, Ordering::SeqCst);
        if stream.write_all(OK_REPLY).await.is_err() || stream.flush().await.is_err() {
            return;
        }
    }
}

/// An upstream that speaks TLS with this certificate and these versions.
async fn tls_upstream_of(
    pair: &Pair,
    versions: &[&'static SupportedProtocolVersion],
) -> (SocketAddr, Arc<Took>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (took, acceptor) = (Arc::new(Took::default()), acceptor(pair, versions));
    let seen = took.clone();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            tokio::spawn(serve_tls(sock, acceptor.clone(), seen.clone()));
        }
    });
    (addr, took)
}

async fn tls_upstream(pair: &Pair) -> (SocketAddr, Arc<Took>) {
    tls_upstream_of(pair, &[&version::TLS13, &version::TLS12]).await
}

/// An upstream that speaks plain HTTP: it reads once from each connection, answers it, and closes it.
async fn plain_upstream() -> (SocketAddr, Arc<Took>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let took = Arc::new(Took::default());
    let seen = took.clone();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            seen.accepted.fetch_add(1, Ordering::SeqCst);
            let mut chunk = [0u8; 4096];
            let n = sock.read(&mut chunk).await.unwrap_or(0);
            let reply: &[u8] = if chunk[..n].starts_with(b"GET ") {
                OK_REPLY
            } else {
                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
            };
            seen.first.lock().unwrap().push(chunk[..n].to_vec());
            let _ = sock.write_all(reply).await;
        }
    });
    (addr, took)
}

fn named(name: &str, at: SocketAddr) -> Address {
    Address::Name {
        name: name.to_string(),
        port: at.port(),
    }
}

/// The settings of a group: the authority of `pki`, and a `server_name` or none.
fn trusting(pki: &Pki, server_name: Option<&str>) -> Settings {
    Settings {
        ca_file: pki.ca(),
        server_name: server_name.map(str::to_string),
    }
}

/// One group whose servers are at `addresses` and are written as `written`, reached over TLS as `settings` say.
fn secured(addresses: &[SocketAddr], written: &[Address], settings: &Settings) -> ForwardConfig {
    let mut forward = ForwardConfig::of(addresses);
    let names = written
        .iter()
        .map(|address| tls::name_of(settings, address).unwrap())
        .collect();
    forward.groups[0].tls = Some(Client::new(tls::config(settings).unwrap(), names));
    forward
}

/// Connections wait to be used again.
fn keeping() -> ProxyConfig {
    ProxyConfig {
        upstream_keepalive: 4,
        ..config()
    }
}

/// A GET to the first group: the status and the body, or why there is no answer.
async fn get(ctx: &Ctx) -> Result<(u16, Vec<u8>), OriginError> {
    let response = send(bare(ctx, "GET"), ctx, far()).await?;
    let status = response.status().as_u16();
    Ok((status, collect(response.into_body()).await.0))
}

#[test]
fn a_server_with_a_certificate_for_its_name_answers_over_tls_and_its_connection_is_used_again() {
    run(async {
        let pki = Pki::new();
        let pair = pki.issue("app", &["DNS:app.test"]);
        // Each version of TLS that is spoken, one at a time.
        for versions in [&[&version::TLS13][..], &[&version::TLS12]] {
            let (addr, took) = tls_upstream_of(&pair, versions).await;
            let forward = secured(&[addr], &[named("app.test", addr)], &trusting(&pki, None));
            let ctx = ctx_of(&forward, keeping());
            for _ in 0..2 {
                assert_eq!(get(&ctx).await.unwrap(), (200, b"ok".to_vec()));
            }
            assert_eq!(took.accepted.load(Ordering::SeqCst), 1);
            assert_eq!(took.served.load(Ordering::SeqCst), 2);
            // The name of the server goes to the server, and the one protocol of ALPN is `http/1.1`.
            assert_eq!(
                *took.hellos.lock().unwrap(),
                [(Some("app.test".to_string()), Some(b"http/1.1".to_vec()))]
            );
        }
    });
}

#[test]
fn a_server_is_checked_for_the_server_name_of_the_group_else_its_own_name_else_its_address() {
    enum Want {
        Sni(&'static str),
        NoSni,
        Refused,
    }
    run(async {
        let pki = Pki::new();
        // The names of the certificate, the `server_name` of the group, how the server is written (a name, or
        // `None` for the IP literal), and what comes of it.
        let cases = [
            (
                &["DNS:api.test"][..],
                Some("api.test"),
                Some("other.test"),
                Want::Sni("api.test"),
            ),
            (
                &["DNS:api.test"],
                Some("api.test"),
                None,
                Want::Sni("api.test"),
            ),
            (
                &["DNS:app.test"],
                None,
                Some("app.test"),
                Want::Sni("app.test"),
            ),
            (&["IP:127.0.0.1"], None, None, Want::NoSni),
            (
                &["DNS:other.test"],
                Some("api.test"),
                Some("other.test"),
                Want::Refused,
            ),
            (&["DNS:app.test"], None, None, Want::Refused),
            (&["DNS:app.test"], None, Some("other.test"), Want::Refused),
        ];
        for (n, (sans, server_name, written, want)) in cases.into_iter().enumerate() {
            let (addr, took) = tls_upstream(&pki.issue("c", sans)).await;
            let written = written.map_or(Address::Literal(addr), |name| named(name, addr));
            let forward = secured(&[addr], &[written], &trusting(&pki, server_name));
            let got = get(&ctx_of(&forward, config())).await;
            let hellos = took.hellos.lock().unwrap().clone();
            match want {
                Want::Sni(name) => {
                    assert_eq!(got.unwrap().0, 200, "case {n}");
                    assert_eq!(hellos[0].0.as_deref(), Some(name), "case {n}");
                }
                Want::NoSni => {
                    assert_eq!(got.unwrap().0, 200, "case {n}");
                    assert_eq!(hellos[0].0, None, "case {n}");
                }
                Want::Refused => {
                    assert_eq!(got.unwrap_err(), OriginError::Connect, "case {n}");
                    assert_eq!(took.served.load(Ordering::SeqCst), 0, "case {n}");
                }
            }
        }
    });
}

#[test]
fn a_server_whose_handshake_fails_is_a_failed_server_that_is_counted_and_the_request_goes_on() {
    run(async {
        let pki = Pki::new();
        let rogue = Pki::new();
        let good = pki.issue("good", &["DNS:app.test"]);
        // A certificate of an authority that is not trusted, one for another name, and a server that does not
        // speak TLS.
        for kind in ["rogue", "name", "plain"] {
            let (bad, took) = match kind {
                "rogue" => tls_upstream(&rogue.issue("bad", &["DNS:app.test"])).await,
                "name" => tls_upstream(&pki.issue("bad", &["DNS:other.test"])).await,
                _ => plain_upstream().await,
            };
            let (live, up) = tls_upstream(&good).await;
            let by = trusting(&pki, None);

            let alone = secured(&[bad], &[named("app.test", bad)], &by);
            let ctx = ctx_of(&alone, config());
            assert_eq!(get(&ctx).await.unwrap_err(), OriginError::Connect, "{kind}");
            assert_eq!(took.served.load(Ordering::SeqCst), 0, "{kind}");

            let both = secured(
                &[bad, live],
                &[named("app.test", bad), named("app.test", live)],
                &by,
            );
            let ctx = ctx_of(&both, config());
            let sent = forward(
                bare(&ctx, "GET"),
                ctx.upstreams.group(0),
                &Rewrite::default(),
                &ctx,
                far(),
            )
            .await;
            assert_eq!(sent.server, Some(live), "{kind}");
            assert_eq!(sent.result.unwrap().status(), 200, "{kind}");
            let tried = took.accepted.load(Ordering::SeqCst);
            assert_eq!(tried, 2, "{kind}: once alone, once with the live one");
            // One failure leaves a server out: the next request does not ask it.
            assert_eq!(get(&ctx).await.unwrap().0, 200, "{kind}");
            assert_eq!(took.accepted.load(Ordering::SeqCst), tried, "{kind}");
            assert_eq!(up.served.load(Ordering::SeqCst), 2, "{kind}");
        }
    });
}

#[test]
fn the_connection_and_the_handshake_together_end_by_upstream_connect() {
    run(async {
        let pki = Pki::new();
        // It takes the connection and never says a word.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let held = tokio::spawn(async move {
            let mut socks = Vec::new();
            while let Ok((sock, _)) = listener.accept().await {
                socks.push(sock);
            }
        });
        let forward = secured(&[addr], &[named("app.test", addr)], &trusting(&pki, None));
        let cfg = ProxyConfig {
            upstream_connect: Duration::from_millis(300),
            ..config()
        };
        let began = Instant::now();
        let ctx = ctx_of(&forward, cfg);
        assert_eq!(get(&ctx).await.unwrap_err(), OriginError::Connect);
        let took = began.elapsed();
        assert!(took >= Duration::from_millis(300), "{took:?}");
        assert!(took < Duration::from_secs(3), "{took:?}");
        held.abort();
    });
}

#[test]
fn a_group_without_tls_speaks_plain_and_a_group_with_it_speaks_tls() {
    run(async {
        let pki = Pki::new();
        let (secure, took) = tls_upstream(&pki.issue("app", &["DNS:app.test"])).await;
        let (plain, seen) = plain_upstream().await;
        let mut forward = secured(
            &[secure],
            &[named("app.test", secure)],
            &trusting(&pki, None),
        );
        forward.groups.push(GroupConfig {
            name: "plain".to_string(),
            servers: ForwardConfig::of(&[plain]).groups.remove(0).servers,
            tls: None,
        });
        let ctx = ctx_of(&forward, keeping());
        for group in [0, 1, 0, 1] {
            let sent = forward_to(&ctx, group).await;
            assert_eq!(sent.status(), 200, "group {group}");
            collect(sent.into_body()).await;
        }
        // The plain upstream got HTTP as it is, twice, each time on a connection of its own: a connection that
        // waited for the group with TLS is not used for the other, and the other way round.
        let first = seen.first.lock().unwrap().clone();
        assert_eq!(first.len(), 2);
        assert!(
            first
                .iter()
                .all(|bytes| bytes.starts_with(b"GET /p?q=1 HTTP/1.1\r\n"))
        );
        assert_eq!(took.accepted.load(Ordering::SeqCst), 1);
        assert_eq!(took.served.load(Ordering::SeqCst), 2);
    });
}

async fn forward_to(ctx: &Ctx, group: usize) -> http::Response<OriginBody> {
    let sent = forward(
        bare(ctx, "GET"),
        ctx.upstreams.group(group),
        &Rewrite::default(),
        ctx,
        far(),
    )
    .await;
    sent.result.unwrap()
}
