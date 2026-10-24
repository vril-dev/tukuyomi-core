//! The connection is made over real sockets and TLS, with the keys and certificates of `transport::tls::tests`. The
//! requests that a client library sends are sent with the HTTP/2 client of hyper; what none would send (a crowd of
//! streams, resets, the frames themselves) is written as frames, with the fields in the plain form of HPACK.

use std::time::{Duration, Instant as StdInstant};

use bytes::Bytes;
use http::Request;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http2::{self, SendRequest};
use rustls::pki_types::ServerName;
use rustls::version;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::runtime::Builder;
use tokio::time::{sleep, timeout};

use super::*;
use crate::config::{ForwardConfig, ListenerConfig, MinVersion, RouteConfig, Stream};
use crate::inbound::conn::tests::{BLOCK, FORM, Mode, Rig, routed_to_h_test, run};
use crate::inbound::session::tests::{ALLOW, OK, Raw, kept, reply};
use crate::inbound::transport::tls::tests::{Pki, listener as tls_listener, with_http2};
use crate::inbound::transport::tls::{Files, Tls};
use crate::log::recording;
use crate::route::{Rule, Table};

const SEC: Duration = Duration::from_secs(1);

type TlsClient = tokio_rustls::client::TlsStream<TcpStream>;

/// A rig whose one listener ends TLS with a certificate for `a.example` and its subdomains, and speaks HTTP/2.
async fn h2_rig(pki: &Pki, cfg: ProxyConfig, mode: Mode, forward: &ForwardConfig) -> Rig {
    let pair = pki.issue("a", &["a.example", "*.a.example"]);
    let listeners: Vec<ListenerConfig> = vec![with_http2(tls_listener(
        MinVersion::Tls12,
        &[(&pair, &["a.example", "*.a.example"])],
    ))];
    let tls = Tls::load(&listeners, &Files).unwrap();
    Rig::with_tls(ProxyConfig { listeners, ..cfg }, mode, forward, tls).await
}

/// The client side of the handshake, offering `h2`.
async fn shake(pki: &Pki, tcp: TcpStream) -> TlsClient {
    let name = ServerName::try_from("a.example".to_owned()).unwrap();
    let client = pki.client(&[&version::TLS13, &version::TLS12], &[b"h2", b"http/1.1"]);
    let stream = client.connect(name, tcp).await.unwrap();
    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    stream
}

/// An HTTP/2 client of hyper on the stream.
async fn client(stream: TlsClient) -> SendRequest<Full<Bytes>> {
    let (send, conn) = http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    send
}

/// The status of the response, and its body.
async fn fetch(
    send: &mut SendRequest<Full<Bytes>>,
    request: Request<Full<Bytes>>,
) -> (u16, Vec<u8>) {
    let response = timeout(30 * SEC, async {
        send.ready().await.unwrap();
        send.send_request(request).await
    })
    .await
    .expect("a response came")
    .expect("the request was sent");
    let status = response.status().as_u16();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, body.to_vec())
}

fn get(uri: &str) -> http::request::Builder {
    Request::get(uri)
}

fn empty(builder: http::request::Builder) -> Request<Full<Bytes>> {
    builder.body(Full::new(Bytes::new())).unwrap()
}

#[test]
fn a_request_over_h2_reaches_the_upstream_as_http_1_1_with_its_target_alone_and_is_inspected_as_http_2()
 {
    run(async {
        let pki = Pki::new();
        let up = Raw::start(|sock, seen| reply(sock, seen, OK)).await;
        let forward = ForwardConfig::of(&[up.addr]);
        let rig = h2_rig(&pki, kept(), Mode::Answer(ALLOW), &forward).await;
        let (tcp, task) = rig.connect_on(0).await;
        let mut send = client(shake(&pki, tcp).await).await;
        let request = get("https://www.a.example/x?q=1")
            .header("cookie", "a=1")
            .header("cookie", "b=2");
        let (status, body) = fetch(&mut send, empty(request)).await;
        assert_eq!((status, body.as_slice()), (200, &b"ok"[..]));
        drop(send);
        let seen = rig.finish(task).await;
        assert_eq!(seen.len(), 1);
        assert_eq!(
            (
                seen[0].method.as_str(),
                seen[0].uri.as_str(),
                seen[0].proto.as_str()
            ),
            ("GET", "/x?q=1", "HTTP/2.0")
        );
        let sent = up.seen().to_ascii_lowercase();
        assert!(sent.starts_with("get /x?q=1 http/1.1\r\n"), "{sent}");
        assert!(sent.contains("\r\nhost: www.a.example\r\n"), "{sent}");
        assert!(sent.contains("\r\ncookie: a=1; b=2\r\n"), "{sent}");
        assert_eq!(
            sent.matches("x-forwarded-proto: https\r\n").count(),
            1,
            "{sent}"
        );
    });
}

#[test]
fn a_request_that_a_rule_blocks_is_answered_with_403_over_h2_and_its_body_was_inspected() {
    run(async {
        let pki = Pki::new();
        let forward = ForwardConfig::of(&["127.0.0.1:2".parse().unwrap()]);
        let rig = h2_rig(&pki, kept(), Mode::Answer(BLOCK), &forward).await;
        let (tcp, task) = rig.connect_on(0).await;
        let mut send = client(shake(&pki, tcp).await).await;
        let post = Request::post("https://www.a.example/p?q=1").header("content-type", FORM);
        let (status, _) = fetch(&mut send, post.body(Full::new(Bytes::from("a=b"))).unwrap()).await;
        assert_eq!(status, 403);
        drop(send);
        let seen = rig.finish(task).await;
        assert_eq!(seen.len(), 1);
        assert_eq!(
            (
                seen[0].method.as_str(),
                seen[0].uri.as_str(),
                seen[0].proto.as_str()
            ),
            ("POST", "/p?q=1", "HTTP/2.0")
        );
    });
}

#[test]
fn every_request_of_a_connection_has_its_name_checked_against_the_certificate_and_its_host_field() {
    run(async {
        let pki = Pki::new();
        let rig = h2_rig(&pki, kept(), Mode::Answer(BLOCK), &routed_to_h_test()).await;
        let (tcp, task) = rig.connect_on(0).await;
        let mut send = client(shake(&pki, tcp).await).await;
        // The certificate stands for `a.example` and its subdomains, so a name outside them is 421 although the
        // handshake was for `a.example`; the names of the certificate have no route here and are 404; a `host`
        // field that is not the authority is 400. The connection goes on after each of them.
        for (uri, host, want) in [
            ("https://www.a.example/", None, 404),
            ("https://other.example/", None, 421),
            ("https://a.example/", Some("other.example"), 400),
            ("https://192.0.2.1/", None, 421),
            ("https://x.a.example/", Some("X.A.example"), 404),
        ] {
            let mut request = get(uri);
            if let Some(host) = host {
                request = request.header("host", host);
            }
            let (status, _) = fetch(&mut send, empty(request)).await;
            assert_eq!(status, want, "{uri} {host:?}");
        }
        drop(send);
        let lines = rig.lines.clone();
        assert!(rig.finish(task).await.is_empty());
        let lines = lines.take();
        let count = |text: &str| lines.iter().filter(|l| l.contains(text)).count();
        assert_eq!(
            count("rejected 421 host not covered by the certificate"),
            2,
            "{lines:?}"
        );
        assert_eq!(count("rejected 400 malformed request head"), 1, "{lines:?}");
        // The one line of the end of the connection says how many streams it carried.
        assert_eq!(count(" streams 5"), 1, "{lines:?}");
    });
}

// ---- frames ----

#[derive(Clone)]
struct Frame {
    kind: u8,
    stream: u32,
    payload: Vec<u8>,
}

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const RST_STREAM: u8 = 0x3;
const SETTINGS: u8 = 0x4;
const GOAWAY: u8 = 0x7;
const END_STREAM: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const REFUSED_STREAM: u32 = 0x7;
const ENHANCE_YOUR_CALM: u32 = 0xb;

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).unwrap().to_be_bytes();
    let mut out = vec![len[1], len[2], len[3], kind, flags];
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// A string of HPACK without Huffman coding.
fn hpack_string(out: &mut Vec<u8>, text: &str) {
    let mut len = text.len();
    if len < 127 {
        out.push(u8::try_from(len).unwrap());
    } else {
        out.push(127);
        len -= 127;
        while len >= 128 {
            out.push(u8::try_from(len % 128).unwrap() | 128);
            len /= 128;
        }
        out.push(u8::try_from(len).unwrap());
    }
    out.extend_from_slice(text.as_bytes());
}

/// The frame of a request for `/` of `authority` on `stream`.
fn request(stream: u32, authority: &str, flags: u8) -> Vec<u8> {
    request_for(stream, authority, "/", flags)
}

/// The frame of a request for `path` of `authority` on `stream`. Every field is a literal without indexing, with its
/// name written out.
fn request_for(stream: u32, authority: &str, path: &str, flags: u8) -> Vec<u8> {
    let mut fields = Vec::new();
    for (name, value) in [
        (":method", "GET"),
        (":scheme", "https"),
        (":path", path),
        (":authority", authority),
    ] {
        fields.push(0);
        hpack_string(&mut fields, name);
        hpack_string(&mut fields, value);
    }
    frame(HEADERS, flags, stream, &fields)
}

/// A client that speaks frames.
struct Wire {
    stream: TlsClient,
    held: Vec<u8>,
    /// Every frame read so far.
    seen: Vec<Frame>,
}

impl Wire {
    /// The handshake, the preface and an empty `SETTINGS`.
    async fn open(pki: &Pki, tcp: TcpStream) -> Wire {
        let mut wire = Wire {
            stream: shake(pki, tcp).await,
            held: Vec::new(),
            seen: Vec::new(),
        };
        wire.send(PREFACE).await;
        wire.send(&frame(SETTINGS, 0, 0, &[])).await;
        wire
    }

    async fn send(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).await.unwrap();
        self.stream.flush().await.unwrap();
    }

    /// The next frame; `None` at the end of the stream.
    async fn next(&mut self) -> Option<Frame> {
        loop {
            if self.held.len() >= 9 {
                let len = usize::try_from(u32::from_be_bytes([
                    0,
                    self.held[0],
                    self.held[1],
                    self.held[2],
                ]))
                .unwrap();
                if self.held.len() >= 9 + len {
                    let rest = self.held.split_off(9 + len);
                    let whole = std::mem::replace(&mut self.held, rest);
                    let frame = Frame {
                        kind: whole[3],
                        stream: u32::from_be_bytes([whole[5] & 0x7f, whole[6], whole[7], whole[8]]),
                        payload: whole[9..].to_vec(),
                    };
                    self.seen.push(frame.clone());
                    return Some(frame);
                }
            }
            let mut buf = [0u8; 8192];
            match timeout(30 * SEC, self.stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => self.held.extend_from_slice(&buf[..n]),
                Ok(Ok(_) | Err(_)) => return None,
                Err(_) => panic!("nothing came"),
            }
        }
    }

    /// Reads until a frame is one `wanted` takes; `None` if the stream ends first.
    async fn until(&mut self, wanted: impl Fn(&Frame) -> bool) -> Option<Frame> {
        loop {
            let frame = self.next().await?;
            if wanted(&frame) {
                return Some(frame);
            }
        }
    }

    fn goaways(&self) -> usize {
        self.seen.iter().filter(|f| f.kind == GOAWAY).count()
    }
}

fn error_code(frame: &Frame) -> u32 {
    let at = if frame.kind == GOAWAY { 4 } else { 0 };
    u32::from_be_bytes(frame.payload[at..at + 4].try_into().unwrap())
}

#[test]
fn a_stream_over_the_limit_is_refused_and_the_streams_under_it_are_not() {
    run(async {
        let pki = Pki::new();
        let forward = ForwardConfig::of(&["127.0.0.1:2".parse().unwrap()]);
        let rig = h2_rig(&pki, kept(), Mode::Answer(BLOCK), &forward).await;
        let (tcp, task) = rig.connect_on(0).await;
        let mut wire = Wire::open(&pki, tcp).await;
        // 129 streams in one write, none of them ended: 128 are taken and wait for their bodies.
        let mut burst = Vec::new();
        for n in 0..129u32 {
            burst.extend(request(2 * n + 1, "www.a.example", END_HEADERS));
        }
        wire.send(&burst).await;
        let refused = wire
            .until(|f| f.kind == RST_STREAM)
            .await
            .expect("a reset came");
        assert_eq!(
            (refused.stream, error_code(&refused)),
            (257, REFUSED_STREAM)
        );
        assert_eq!(wire.goaways(), 0);
        drop(wire);
        rig.finish(task).await;
    });
}

#[test]
fn the_connection_is_wound_down_by_the_number_of_streams_and_by_idleness() {
    run(async {
        let pki = Pki::new();
        let cfg = ProxyConfig {
            keepalive_requests: 2,
            ..kept()
        };
        let rig = h2_rig(&pki, cfg, Mode::Answer(BLOCK), &routed_to_h_test()).await;
        let (tcp, task) = rig.connect_on(0).await;
        let mut wire = Wire::open(&pki, tcp).await;
        // One stream is answered and the connection goes on.
        wire.send(&request(1, "www.a.example", END_HEADERS | END_STREAM))
            .await;
        wire.until(|f| f.kind == HEADERS && f.stream == 1)
            .await
            .expect("an answer");
        assert_eq!(wire.goaways(), 0);
        // The second one is the last: the `GOAWAY` that tells so is for the streams to come, and the second is
        // answered.
        let waited = StdInstant::now();
        wire.send(&request(3, "www.a.example", END_HEADERS | END_STREAM))
            .await;
        let goaway = wire.until(|f| f.kind == GOAWAY).await.expect("a goaway");
        assert_eq!(error_code(&goaway), 0);
        wire.until(|f| f.kind == HEADERS && f.stream == 3)
            .await
            .expect("an answer");
        // The client never answers the `PING` that goes with the `GOAWAY`: hyper would wait for it for ever, and
        // the connection is dropped `lingering_timeout` after the client was told, as nothing is open.
        assert!(wire.until(|_| false).await.is_none());
        assert!(waited.elapsed() >= Duration::from_millis(250) && waited.elapsed() < 10 * SEC);
        let lines = rig.lines.clone();
        rig.finish(task).await;
        let lines = lines.take();
        let ended: Vec<&String> = lines.iter().filter(|l| l.contains(" streams ")).collect();
        assert_eq!(ended.len(), 1, "{lines:?}");
        assert!(
            ended[0].contains("h2 goaway not answered") && ended[0].ends_with(" streams 2"),
            "{ended:?}"
        );

        // A connection with nothing open for `keepalive_timeout` is wound down; so is one that answered a request
        // and has none after it.
        let cfg = ProxyConfig {
            keepalive_requests: 100,
            keepalive_timeout: Duration::from_millis(400),
            ..kept()
        };
        let rig = h2_rig(&pki, cfg, Mode::Answer(BLOCK), &routed_to_h_test()).await;
        let (tcp, task) = rig.connect_on(0).await;
        let mut wire = Wire::open(&pki, tcp).await;
        wire.send(&request(1, "www.a.example", END_HEADERS | END_STREAM))
            .await;
        wire.until(|f| f.kind == HEADERS && f.stream == 1)
            .await
            .expect("an answer");
        let waited = StdInstant::now();
        let goaway = wire.until(|f| f.kind == GOAWAY).await.expect("a goaway");
        assert_eq!(error_code(&goaway), 0);
        assert!(waited.elapsed() >= Duration::from_millis(350) && waited.elapsed() < 10 * SEC);
        drop(wire);
        rig.finish(task).await;
    });
}

#[test]
fn the_age_of_the_connection_winds_it_down_when_the_next_stream_begins() {
    run(async {
        let pki = Pki::new();
        let cfg = ProxyConfig {
            keepalive_time: Duration::from_millis(300),
            ..kept()
        };
        let rig = h2_rig(&pki, cfg, Mode::Answer(BLOCK), &routed_to_h_test()).await;
        let (tcp, task) = rig.connect_on(0).await;
        let mut wire = Wire::open(&pki, tcp).await;
        wire.send(&request(1, "www.a.example", END_HEADERS | END_STREAM))
            .await;
        wire.until(|f| f.kind == HEADERS && f.stream == 1)
            .await
            .expect("an answer");
        assert_eq!(wire.goaways(), 0);
        tokio::time::sleep(Duration::from_millis(400)).await;
        wire.send(&request(3, "www.a.example", END_HEADERS | END_STREAM))
            .await;
        let goaway = wire.until(|f| f.kind == GOAWAY).await.expect("a goaway");
        assert_eq!(error_code(&goaway), 0);
        drop(wire);
        rig.finish(task).await;
    });
}

#[test]
fn without_a_wait_for_the_next_request_the_connection_is_wound_down_by_its_first_stream() {
    run(async {
        let pki = Pki::new();
        let cfg = ProxyConfig {
            keepalive_timeout: Duration::ZERO,
            ..kept()
        };
        let rig = h2_rig(&pki, cfg, Mode::Answer(BLOCK), &routed_to_h_test()).await;
        let (tcp, task) = rig.connect_on(0).await;
        let mut wire = Wire::open(&pki, tcp).await;
        wire.send(&request(1, "www.a.example", END_HEADERS | END_STREAM))
            .await;
        // The stream is answered, and the client is told that there is no other one.
        let goaway = wire.until(|f| f.kind == GOAWAY).await.expect("a goaway");
        assert_eq!(error_code(&goaway), 0);
        if !wire.seen.iter().any(|f| f.kind == HEADERS && f.stream == 1) {
            wire.until(|f| f.kind == HEADERS && f.stream == 1)
                .await
                .expect("an answer");
        }
        drop(wire);
        rig.finish(task).await;
    });
}

#[test]
fn a_flood_of_resets_ends_the_connection_with_a_goaway() {
    run(async {
        let pki = Pki::new();
        let forward = ForwardConfig::of(&["127.0.0.1:2".parse().unwrap()]);
        let rig = h2_rig(&pki, kept(), Mode::Answer(BLOCK), &forward).await;
        let (tcp, task) = rig.connect_on(0).await;
        let mut wire = Wire::open(&pki, tcp).await;
        let mut burst = Vec::new();
        for n in 0..400u32 {
            burst.extend(request(2 * n + 1, "www.a.example", END_HEADERS));
            burst.extend(frame(RST_STREAM, 0, 2 * n + 1, &8u32.to_be_bytes()));
        }
        wire.send(&burst).await;
        let goaway = wire.until(|f| f.kind == GOAWAY).await.expect("a goaway");
        assert_eq!(error_code(&goaway), ENHANCE_YOUR_CALM);
        drop(wire);
        let lines = rig.lines.clone();
        rig.finish(task).await;
        let lines = lines.take();
        assert_eq!(
            lines.iter().filter(|l| l.contains(" streams ")).count(),
            1,
            "{lines:?}"
        );
    });
}

#[test]
fn the_stop_winds_the_connection_down() {
    run(async {
        let pki = Pki::new();
        let rig = h2_rig(&pki, kept(), Mode::Answer(BLOCK), &routed_to_h_test()).await;
        let (tcp, task) = rig.connect_on(0).await;
        let mut wire = Wire::open(&pki, tcp).await;
        wire.send(&request(1, "www.a.example", END_HEADERS | END_STREAM))
            .await;
        wire.until(|f| f.kind == HEADERS && f.stream == 1)
            .await
            .expect("an answer");
        rig.ctx.ingress.close();
        let goaway = wire.until(|f| f.kind == GOAWAY).await.expect("a goaway");
        assert_eq!(error_code(&goaway), 0);
        assert!(wire.until(|_| false).await.is_none());
        rig.finish(task).await;
    });
}

#[test]
fn a_preface_or_a_header_block_that_does_not_come_in_time_closes_the_connection_with_one_line() {
    run(async {
        let pki = Pki::new();
        let cfg = ProxyConfig {
            head_read: Duration::from_millis(400),
            ..kept()
        };
        for trickle in [false, true] {
            let rig = h2_rig(&pki, cfg.clone(), Mode::Answer(BLOCK), &routed_to_h_test()).await;
            let began = StdInstant::now();
            let (tcp, task) = rig.connect_on(0).await;
            let mut stream = shake(&pki, tcp).await;
            if trickle {
                // The preface is in time, and the header block comes one byte in 80 ms.
                stream.write_all(PREFACE).await.unwrap();
                stream.write_all(&frame(SETTINGS, 0, 0, &[])).await.unwrap();
                for byte in request(1, "www.a.example", END_HEADERS | END_STREAM) {
                    if stream.write_all(&[byte]).await.is_err() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(80)).await;
                }
            }
            let mut rest = Vec::new();
            let _ = stream.read_to_end(&mut rest).await;
            assert!(began.elapsed() >= Duration::from_millis(350) && began.elapsed() < 5 * SEC);
            let lines = rig.lines.clone();
            rig.finish(task).await;
            let lines = lines.take();
            let ours: Vec<&String> = lines
                .iter()
                .filter(|l| l.contains("head not received in time"))
                .collect();
            assert_eq!(ours.len(), 1, "{lines:?}");
            assert!(ours[0].ends_with(" streams 0"), "{ours:?}");
        }
    });
}

#[test]
fn a_client_that_ignores_the_ping_of_a_goaway_takes_no_stream_after_the_linger_time_and_is_dropped_a_linger_time_after_its_last_stream()
 {
    run(async {
        let pki = Pki::new();
        let forward = ForwardConfig::of(&["127.0.0.1:2".parse().unwrap()]);
        let linger = Duration::from_millis(600);
        let cfg = ProxyConfig {
            keepalive_requests: 1,
            lingering_timeout: linger,
            ..kept()
        };
        let rig = h2_rig(&pki, cfg, Mode::Answer(BLOCK), &forward).await;
        let (tcp, task) = rig.connect_on(0).await;
        let mut wire = Wire::open(&pki, tcp).await;
        // The first stream is the last the connection serves, and it waits for its body: it is open when the
        // client has been told for `lingering_timeout`. The client never answers the `PING` of the `GOAWAY`.
        wire.send(&request(1, "www.a.example", END_HEADERS)).await;
        wire.until(|f| f.kind == GOAWAY).await.expect("a goaway");
        // A stream within that time is taken; one after it is reset, and the open one is not touched.
        wire.send(&request(3, "www.a.example", END_HEADERS | END_STREAM))
            .await;
        wire.until(|f| f.kind == HEADERS && f.stream == 3)
            .await
            .expect("an answer");
        sleep(Duration::from_millis(800)).await;
        wire.send(&request(5, "www.a.example", END_HEADERS | END_STREAM))
            .await;
        let reset = wire.until(|f| f.kind == RST_STREAM).await.expect("a reset");
        assert_eq!(reset.stream, 5);
        // The open stream ends, and the connection goes `lingering_timeout` after that: not at once.
        wire.send(&frame(DATA, END_STREAM, 1, &[])).await;
        let ended = StdInstant::now();
        wire.until(|f| f.kind == HEADERS && f.stream == 1)
            .await
            .expect("an answer");
        assert!(wire.until(|_| false).await.is_none());
        assert!(
            ended.elapsed() >= linger - Duration::from_millis(100)
                && ended.elapsed() < linger + SEC,
            "{:?}",
            ended.elapsed()
        );
        assert!(!wire.seen.iter().any(|f| f.kind == HEADERS && f.stream == 5));
        let lines = rig.lines.clone();
        rig.finish(task).await;
        let lines = lines.take();
        let ended: Vec<&String> = lines.iter().filter(|l| l.contains(" streams ")).collect();
        assert_eq!(ended.len(), 1, "{lines:?}");
        // The stream that was turned away is not counted.
        assert!(
            ended[0].contains("h2 goaway not answered") && ended[0].ends_with(" streams 2"),
            "{ended:?}"
        );
    });
}

#[test]
fn more_late_streams_than_max_streams_drop_the_connection_at_once() {
    run(async {
        let pki = Pki::new();
        let forward = ForwardConfig::of(&["127.0.0.1:2".parse().unwrap()]);
        let cfg = ProxyConfig {
            keepalive_requests: 1,
            ..kept()
        };
        let linger = cfg.lingering_timeout;
        let rig = h2_rig(&pki, cfg, Mode::Answer(BLOCK), &forward).await;
        let (tcp, task) = rig.connect_on(0).await;
        let mut wire = Wire::open(&pki, tcp).await;
        // The first stream is the last the connection serves, and it waits for its body, so the connection is not
        // idle. The client never answers the `PING` of the `GOAWAY`, and the streams that follow come late.
        wire.send(&request(1, "www.a.example", END_HEADERS)).await;
        wire.until(|f| f.kind == GOAWAY).await.expect("a goaway");
        sleep(2 * linger).await;
        // `max_streams` (128) of them are turned away, one at a time, and the connection stays.
        for n in 1..=128u32 {
            let id = 2 * n + 1;
            wire.send(&request(id, "www.a.example", END_HEADERS | END_STREAM))
                .await;
            let reset = wire.until(|f| f.kind == RST_STREAM).await.expect("a reset");
            assert_eq!(reset.stream, id);
        }
        // The next one ends it, with the first stream still open.
        let past = StdInstant::now();
        wire.send(&request(259, "www.a.example", END_HEADERS | END_STREAM))
            .await;
        assert!(wire.until(|_| false).await.is_none());
        assert!(past.elapsed() < SEC, "{:?}", past.elapsed());
        let lines = rig.lines.clone();
        rig.finish(task).await;
        let lines = lines.take();
        let ended: Vec<&String> = lines.iter().filter(|l| l.contains(" streams ")).collect();
        assert_eq!(ended.len(), 1, "{lines:?}");
        assert!(
            ended[0].contains("h2 goaway not answered") && ended[0].ends_with(" streams 1"),
            "{ended:?}"
        );
    });
}

/// Reads from `sock` up to the end of the head of a request; `None` if the connection ends first.
async fn read_head(sock: &mut TcpStream) -> Option<Vec<u8>> {
    let mut asked = Vec::new();
    let mut buf = [0u8; 4096];
    while !asked.windows(4).any(|w| w == b"\r\n\r\n") {
        match sock.read(&mut buf).await {
            Ok(n) if n > 0 => asked.extend_from_slice(&buf[..n]),
            _ => return None,
        }
    }
    Some(asked)
}

/// An upstream that answers every request with `len` bytes.
async fn long_reply(mut sock: TcpStream, len: usize) {
    if read_head(&mut sock).await.is_none() {
        return;
    }
    let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {len}\r\n\r\n");
    if sock.write_all(head.as_bytes()).await.is_err() {
        return;
    }
    let _ = sock.write_all(&vec![b'x'; len]).await;
    let mut buf = [0u8; 4096];
    while matches!(sock.read(&mut buf).await, Ok(n) if n > 0) {}
}

/// An upstream that answers `/silent` with its head and the start of its body and then says nothing, and every other
/// path in full. It waits for the proxy to end the connection.
async fn half_silent(mut sock: TcpStream) {
    let Some(asked) = read_head(&mut sock).await else {
        return;
    };
    let answer: &[u8] = if asked.starts_with(b"GET /silent ") {
        b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc"
    } else {
        OK
    };
    if sock.write_all(answer).await.is_err() {
        return;
    }
    let mut buf = [0u8; 4096];
    while matches!(sock.read(&mut buf).await, Ok(n) if n > 0) {}
}

#[test]
fn a_response_that_the_client_takes_no_more_of_ends_the_connection_at_the_time_it_may_stand_still()
{
    run(async {
        let pki = Pki::new();
        let up = Raw::start(|sock, seen| reply(sock, seen, OK)).await;
        // The route `/s/` has a `stream` whose upstream may be silent for longer than `response_idle`.
        let mut forward = ForwardConfig::of(&[up.addr]);
        let route = RouteConfig {
            stream: Some(Stream {
                idle: 2 * SEC,
                total: 10 * SEC,
                websocket: false,
            }),
            ..RouteConfig::plain(0)
        };
        let rule = Rule::forward(None, Some("/s/")).unwrap();
        forward.routes = Table::new(vec![(rule, route)]).unwrap();
        let response_idle = Duration::from_millis(500);
        for (path, limit) in [("/", response_idle), ("/s/", 2 * SEC)] {
            let cfg = ProxyConfig {
                response_idle,
                ..kept()
            };
            let rig = h2_rig(&pki, cfg, Mode::Answer(ALLOW), &forward).await;
            let (tcp, task) = rig.connect_on(0).await;
            let mut wire = Wire::open(&pki, tcp).await;
            // The client has no window for a byte of the response, and reads all the rest that comes.
            wire.send(&frame(SETTINGS, 0, 0, &[0, 4, 0, 0, 0, 0])).await;
            wire.send(&request_for(
                1,
                "www.a.example",
                path,
                END_HEADERS | END_STREAM,
            ))
            .await;
            wire.until(|f| f.kind == HEADERS && f.stream == 1)
                .await
                .expect("the head of the response");
            let waited = StdInstant::now();
            assert!(wire.until(|f| f.kind == DATA).await.is_none(), "{path}");
            assert!(
                waited.elapsed() >= limit - Duration::from_millis(100)
                    && waited.elapsed() < limit + SEC,
                "{path} {:?}",
                waited.elapsed()
            );
            let lines = rig.lines.clone();
            rig.finish(task).await;
            let lines = lines.take();
            let ended: Vec<&String> = lines.iter().filter(|l| l.contains(" streams ")).collect();
            assert_eq!(ended.len(), 1, "{lines:?}");
            assert!(
                ended[0].contains("closed while the response was sent")
                    && ended[0].ends_with(" streams 1"),
                "{ended:?}"
            );
        }
    });
}

#[test]
fn a_client_that_reads_slowly_but_goes_on_is_not_cut_for_standing_still() {
    run(async {
        let pki = Pki::new();
        let len = 400_000;
        let up = Raw::start(move |sock, _| long_reply(sock, len)).await;
        let forward = ForwardConfig::of(&[up.addr]);
        let response_idle = SEC;
        let cfg = ProxyConfig {
            response_idle,
            ..kept()
        };
        let rig = h2_rig(&pki, cfg, Mode::Answer(ALLOW), &forward).await;
        let (tcp, task) = rig.connect_on(0).await;
        let mut send = client(shake(&pki, tcp).await).await;
        let began = StdInstant::now();
        send.ready().await.unwrap();
        let response = send
            .send_request(empty(get("https://www.a.example/long")))
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 200);
        // Each frame is taken within the time, and the whole body takes longer than that.
        let mut body = response.into_body();
        let mut got = 0;
        while let Some(frame) = timeout(30 * SEC, body.frame()).await.expect("a frame came") {
            got += frame.unwrap().into_data().map_or(0, |data| data.len());
            sleep(Duration::from_millis(30)).await;
        }
        assert_eq!(got, len);
        assert!(began.elapsed() > response_idle);
        drop(send);
        rig.finish(task).await;
    });
}

#[test]
fn a_response_that_began_before_a_goaway_and_outlasts_the_linger_time_reaches_a_client_that_answers_the_ping_whole()
 {
    run(async {
        let pki = Pki::new();
        let len = 400_000;
        let up = Raw::start(move |sock, _| long_reply(sock, len)).await;
        let forward = ForwardConfig::of(&[up.addr]);
        let linger = Duration::from_millis(600);
        let cfg = ProxyConfig {
            keepalive_requests: 1,
            lingering_timeout: linger,
            ..kept()
        };
        let rig = h2_rig(&pki, cfg, Mode::Answer(ALLOW), &forward).await;
        let (tcp, task) = rig.connect_on(0).await;
        let mut send = client(shake(&pki, tcp).await).await;
        let began = StdInstant::now();
        send.ready().await.unwrap();
        let response = send
            .send_request(empty(get("https://www.a.example/long")))
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 200);
        // The stream is the first, so the `GOAWAY` goes out with it. The client answers the `PING`, reads slowly
        // until well after the linger time, so that the last chunk is handed to h2 after it, and then takes what is
        // left at once.
        let mut body = response.into_body();
        let mut got = 0;
        while let Some(frame) = timeout(30 * SEC, body.frame()).await.expect("a frame came") {
            got += frame
                .expect("the body goes on")
                .into_data()
                .map_or(0, |data| data.len());
            if began.elapsed() < 2 * linger {
                sleep(Duration::from_millis(30)).await;
            }
        }
        assert_eq!(got, len);
        // The connection ends by itself, in the linger time after the end of the response.
        let read = StdInstant::now();
        let lines = rig.lines.clone();
        rig.finish(task).await;
        assert!(read.elapsed() < linger, "{:?}", read.elapsed());
        drop(send);
        let lines = lines.take();
        let ended: Vec<&String> = lines.iter().filter(|l| l.contains(" streams ")).collect();
        assert_eq!(ended.len(), 1, "{lines:?}");
        assert!(
            ended[0].contains("h2 connection ended") && ended[0].ends_with(" streams 1"),
            "{ended:?}"
        );
    });
}

#[test]
fn an_upstream_that_is_silent_in_the_middle_of_a_body_fails_that_stream_and_not_the_connection() {
    run(async {
        let pki = Pki::new();
        let up = Raw::start(|sock, _| half_silent(sock)).await;
        let forward = ForwardConfig::of(&[up.addr]);
        let cfg = ProxyConfig {
            response_idle: Duration::from_millis(500),
            ..kept()
        };
        let rig = h2_rig(&pki, cfg, Mode::Answer(ALLOW), &forward).await;
        let (tcp, task) = rig.connect_on(0).await;
        let mut send = client(shake(&pki, tcp).await).await;
        send.ready().await.unwrap();
        let silent = send
            .send_request(empty(get("https://www.a.example/silent")))
            .await
            .unwrap();
        assert_eq!(silent.status().as_u16(), 200);
        // Another stream of the connection is answered while the first waits for the rest of its body.
        let (status, body) = fetch(&mut send, empty(get("https://www.a.example/ok"))).await;
        assert_eq!((status, body.as_slice()), (200, &b"ok"[..]));
        // The read of the upstream fails the first stream when it has been silent for `response_idle`. The
        // connection goes on.
        let mut body = silent.into_body();
        let mut failed = false;
        while let Some(frame) = timeout(30 * SEC, body.frame()).await.expect("a frame came") {
            if frame.is_err() {
                failed = true;
                break;
            }
        }
        assert!(failed);
        let (status, body) = fetch(&mut send, empty(get("https://www.a.example/ok"))).await;
        assert_eq!((status, body.as_slice()), (200, &b"ok"[..]));
        let lines = rig.lines.clone();
        drop(send);
        rig.finish(task).await;
        let lines = lines.take();
        let ended: Vec<&String> = lines.iter().filter(|l| l.contains(" streams ")).collect();
        assert_eq!(ended.len(), 1, "{lines:?}");
        assert!(
            !ended[0].contains("closed while the response was sent")
                && ended[0].ends_with(" streams 3"),
            "{ended:?}"
        );
    });
}

#[test]
fn a_panic_of_a_stream_has_a_line_in_the_record_and_goes_on() {
    let (log, lines) = recording();
    let watched = Watched {
        inner: Box::pin(async {
            // A process never has the number 0.
            assert!(std::process::id() == 0, "a stream fails");
        }),
        log,
        id: 7,
    };
    let runtime = Builder::new_current_thread().enable_all().build().unwrap();
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| runtime.block_on(watched)));
    assert!(outcome.is_err());
    assert_eq!(lines.take(), ["conn 7: h2 stream panicked"]);
}
