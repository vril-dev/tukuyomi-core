use std::fs;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex as StdMutex;
use std::sync::atomic::AtomicUsize;
use std::time::{Duration, Instant as StdInstant};

use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tukuyomi_kernel::Verdict;

use super::*;
use crate::config::{
    AcmeConfig, CertificateAcme, CertificateConfig, ForwardConfig, ListenerConfig, MinVersion,
    RateLimitConfig, RouteConfig, TlsConfig,
};
use crate::forward::client_ip::{Access, Cidr};
use crate::inbound::challenge::Challenge;
use crate::inbound::challenge::tests::Dir;
use crate::inbound::conn::tests::{
    BLOCK, FORM, Mode, Parsed, Rig, config, finish_sending, form_post, guarded, parse_response,
    put, read_all, routed_to_h_test, run,
};
use crate::inbound::transport::tls::tests::{Pki, listener as tls_listener};
use crate::inbound::transport::tls::{Files, Tls};
use crate::inspect::driver::Outcome;
use crate::log::Lines;
use crate::log::is_answer;
use crate::policy::RateLimit;
use crate::route::{Rule, Table};

const SEC: Duration = Duration::from_secs(1);

/// A configuration that keeps a connection for a while after a response.
pub(in crate::inbound) fn kept() -> ProxyConfig {
    ProxyConfig {
        keepalive_timeout: 10 * SEC,
        lingering_timeout: Duration::from_millis(300),
        ..config()
    }
}

pub(in crate::inbound) fn get(target: &str) -> Vec<u8> {
    format!("GET {target} HTTP/1.1\r\nHost: h\r\n\r\n").into_bytes()
}

/// Reads until `n` responses have come (the answers of the proxy have no body), or the server closes the
/// connection; and whether it did.
async fn responses(sock: &TcpStream, n: usize) -> (Vec<Parsed>, bool) {
    let mut raw = Vec::new();
    let mut found = Vec::new();
    let mut buf = [0u8; 4096];
    let closed = timeout(30 * SEC, async {
        while found.len() < n {
            while let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                let head: Vec<u8> = raw.drain(..end + 4).collect();
                found.push(parse_response(&head));
            }
            if found.len() >= n {
                break;
            }
            sock.readable().await.unwrap();
            match sock.try_read(&mut buf) {
                Ok(0) => return true,
                Ok(k) => raw.extend_from_slice(&buf[..k]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => return true,
            }
        }
        false
    })
    .await
    .expect("the responses came");
    (found, closed)
}

/// Everything the server sends until it closes the connection; a reset is a failure.
async fn read_clean(sock: &TcpStream) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    timeout(30 * SEC, async {
        loop {
            sock.readable().await.unwrap();
            match sock.try_read(&mut buf) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("the connection was reset: {e}"),
            }
        }
    })
    .await
    .expect("the server closed the connection");
    out
}

#[test]
fn requests_on_one_connection_are_inspected_and_answered_in_order() {
    run(async {
        let rig = Rig::new(kept(), Mode::Answer(BLOCK)).await;
        let (mut client, task) = rig.connect().await;
        // Two requests in one write, the second with a body; then a third on the same connection.
        let mut both = get("/a");
        both.extend_from_slice(&form_post("Content-Length: 3\r\n\r\na=b"));
        put(&client, &both).await;
        let (answers, closed) = responses(&client, 2).await;
        assert!(!closed);
        for answer in &answers {
            assert_eq!(answer.status, 403);
            assert!(answer.all("connection").is_empty());
        }
        put(&client, &get("/c")).await;
        let (answers, closed) = responses(&client, 1).await;
        assert!(!closed && answers[0].status == 403);
        finish_sending(&mut client).await;
        assert!(read_all(&client).await.is_empty());
        let seen = rig.finish(task).await;
        let order: Vec<(&str, &str)> = seen
            .iter()
            .map(|s| (s.method.as_str(), s.uri.as_str()))
            .collect();
        assert_eq!(order, [("GET", "/a"), ("POST", "/p?q=1"), ("GET", "/c")]);
        assert!(seen.iter().all(|s| s.proto == "HTTP/1.1"));
    });
}

#[test]
fn a_404_keeps_the_connection_if_the_request_had_no_body_and_ends_it_otherwise() {
    run(async {
        // The host `h` has no route here.
        let rig = Rig::with(kept(), Mode::Answer(BLOCK), &routed_to_h_test()).await;
        let (client, task) = rig.connect().await;
        for target in ["/a", "/b"] {
            put(&client, &get(target)).await;
            let (answers, closed) = responses(&client, 1).await;
            assert!(!closed && answers[0].status == 404);
            assert!(answers[0].all("connection").is_empty());
        }
        put(&client, &form_post("Content-Length: 3\r\n\r\na=b")).await;
        let last = parse_response(&read_all(&client).await);
        assert_eq!(last.status, 404);
        assert_eq!(last.all("connection"), ["close"]);
        assert!(rig.finish(task).await.is_empty());
    });
}

#[test]
fn a_bad_second_head_closes_the_connection_without_breaking_the_first_answer() {
    run(async {
        let bad = b"GET /b HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n";
        // Pipelined behind the first request.
        let rig = Rig::new(kept(), Mode::Answer(BLOCK)).await;
        let (client, task) = rig.connect().await;
        let mut both = get("/a");
        both.extend_from_slice(bad);
        put(&client, &both).await;
        let raw = read_all(&client).await;
        let first = parse_response(&raw);
        assert_eq!(first.status, 403);
        // The answer is whole and nothing follows it: no answer to the bad head.
        assert_eq!(
            raw.len(),
            raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4
        );
        let seen = rig.finish(task).await;
        assert_eq!(seen.len(), 1);
        // Sent after the first answer.
        let rig = Rig::new(kept(), Mode::Answer(BLOCK)).await;
        let (client, task) = rig.connect().await;
        put(&client, &get("/a")).await;
        let (answers, closed) = responses(&client, 1).await;
        assert!(!closed && answers[0].status == 403);
        put(&client, bad).await;
        assert!(read_all(&client).await.is_empty());
        assert_eq!(rig.finish(task).await.len(), 1);
    });
}

#[test]
fn a_response_that_ends_the_connection_says_so_and_nothing_after_it_is_served() {
    run(async {
        let chunked = form_post("Transfer-Encoding: chunked\r\n\r\n3\r\na=b\r\n0\r\n\r\n");
        let old = b"GET /old HTTP/1.0\r\nHost: h\r\nConnection: keep-alive\r\n\r\n".to_vec();
        let closing = b"GET /close HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n".to_vec();
        for (name, first) in [("chunked", chunked), ("http/1.0", old), ("close", closing)] {
            let rig = Rig::new(kept(), Mode::Answer(BLOCK)).await;
            let (client, task) = rig.connect().await;
            let mut input = first.clone();
            input.extend_from_slice(&get("/after"));
            put(&client, &input).await;
            let raw = read_all(&client).await;
            let answer = parse_response(&raw);
            assert_eq!(answer.status, 403, "{name}");
            assert_eq!(answer.all("connection"), ["close"], "{name}");
            let seen = rig.finish(task).await;
            assert_eq!(seen.len(), 1, "{name}");
            if name == "http/1.0" {
                assert_eq!(seen[0].proto, "HTTP/1.0");
                assert!(
                    raw.starts_with(b"HTTP/1.0 403"),
                    "{:?}",
                    raw.escape_ascii().to_string()
                );
            }
        }
    });
}

#[test]
fn the_number_of_requests_and_the_age_of_the_connection_end_it() {
    run(async {
        // The second request is the last one.
        let few = ProxyConfig {
            keepalive_requests: 2,
            ..kept()
        };
        let rig = Rig::new(few, Mode::Answer(BLOCK)).await;
        let (client, task) = rig.connect().await;
        put(&client, &get("/1")).await;
        let (first, closed) = responses(&client, 1).await;
        assert!(!closed && first[0].all("connection").is_empty());
        put(&client, &get("/2")).await;
        let (second, _) = responses(&client, 1).await;
        assert_eq!(second[0].all("connection"), ["close"]);
        assert!(read_all(&client).await.is_empty());
        assert_eq!(rig.finish(task).await.len(), 2);

        // The age of the connection: the request that is answered after it has the last answer.
        let old = ProxyConfig {
            keepalive_time: Duration::from_millis(400),
            ..kept()
        };
        let rig = Rig::new(old, Mode::Answer(BLOCK)).await;
        let (client, task) = rig.connect().await;
        put(&client, &get("/1")).await;
        let (first, _) = responses(&client, 1).await;
        assert!(first[0].all("connection").is_empty());
        sleep(Duration::from_millis(500)).await;
        put(&client, &get("/2")).await;
        let (second, _) = responses(&client, 1).await;
        assert_eq!(second[0].all("connection"), ["close"]);
        assert!(read_all(&client).await.is_empty());
        assert_eq!(rig.finish(task).await.len(), 2);
    });
}

#[test]
fn the_time_of_a_request_and_of_a_head_start_again_with_each_request() {
    run(async {
        // Neither the request time nor the head time is as long as the connection lives.
        let cfg = ProxyConfig {
            request_total: Duration::from_millis(1500),
            head_read: Duration::from_millis(1500),
            keepalive_timeout: 10 * SEC,
            ..config()
        };
        let rig = Rig::new(cfg, Mode::Answer(BLOCK)).await;
        let (mut client, task) = rig.connect().await;
        put(&client, &get("/1")).await;
        assert_eq!(responses(&client, 1).await.0[0].status, 403);
        sleep(Duration::from_millis(1800)).await;
        put(&client, &get("/2")).await;
        assert_eq!(responses(&client, 1).await.0[0].status, 403);
        // A head that takes longer than the connection has lived, in two pieces within its own time.
        let third = get("/3");
        put(&client, &third[..10]).await;
        sleep(Duration::from_millis(1000)).await;
        put(&client, &third[10..]).await;
        assert_eq!(responses(&client, 1).await.0[0].status, 403);
        finish_sending(&mut client).await;
        assert!(read_all(&client).await.is_empty());
        assert_eq!(rig.finish(task).await.len(), 3);
    });
}

#[test]
fn an_idle_connection_closes_after_the_wait_and_at_once_when_the_stop_begins() {
    run(async {
        let wait = ProxyConfig {
            keepalive_timeout: Duration::from_millis(400),
            ..config()
        };
        let rig = Rig::new(wait, Mode::Answer(BLOCK)).await;
        let (client, task) = rig.connect().await;
        put(&client, &get("/1")).await;
        assert_eq!(responses(&client, 1).await.0[0].status, 403);
        let answered = StdInstant::now();
        assert!(read_all(&client).await.is_empty());
        assert!(answered.elapsed() >= Duration::from_millis(300));
        assert!(answered.elapsed() < 10 * SEC);
        assert_eq!(rig.finish(task).await.len(), 1);

        let rig = Rig::new(kept(), Mode::Answer(BLOCK)).await;
        let (client, task) = rig.connect().await;
        put(&client, &get("/1")).await;
        assert_eq!(responses(&client, 1).await.0[0].status, 403);
        sleep(Duration::from_millis(100)).await;
        let began = StdInstant::now();
        rig.ctx.ingress.close();
        assert!(read_all(&client).await.is_empty());
        assert!(began.elapsed() < 5 * SEC);
        assert_eq!(rig.finish(task).await.len(), 1);

        // A request that starts after the stop has no way to the driver, and its answer ends the connection.
        let rig = Rig::new(kept(), Mode::Answer(BLOCK)).await;
        let (client, task) = rig.connect().await;
        rig.ctx.ingress.close();
        put(&client, &get("/late")).await;
        let answer = parse_response(&read_all(&client).await);
        assert_eq!(answer.status, 503);
        assert_eq!(answer.all("connection"), ["close"]);
        assert!(rig.finish(task).await.is_empty());
    });
}

#[test]
fn an_answer_before_the_body_was_read_closes_the_connection_but_the_client_still_reads_it() {
    run(async {
        // A chunked body that is over the limit answers 413 half way. The client goes on sending, and its bytes
        // are read and thrown away, so that the close does not reset the connection under it.
        let patient = ProxyConfig {
            lingering_timeout: 5 * SEC,
            ..kept()
        };
        let rig = Rig::new(patient, Mode::Answer(BLOCK)).await;
        let (mut client, task) = rig.connect().await;
        let mut head = form_post("Transfer-Encoding: chunked\r\n\r\n800\r\n");
        head.extend_from_slice(&[b'a'; 2048]);
        put(&client, &head).await;
        let (answers, _) = responses(&client, 1).await;
        assert_eq!(answers[0].status, 413);
        assert_eq!(answers[0].all("connection"), ["close"]);
        put(&client, &[b'b'; 100_000]).await;
        finish_sending(&mut client).await;
        assert!(read_clean(&client).await.is_empty());
        assert!(rig.finish(task).await.is_empty());

        // The reading is bounded: by the time a read waits, and by the bytes.
        let cfg = ProxyConfig {
            lingering_timeout: Duration::from_millis(300),
            lingering_time: 5 * SEC,
            lingering_bytes: 10_000,
            ..kept()
        };
        let rig = Rig::new(cfg.clone(), Mode::Answer(BLOCK)).await;
        let (client, task) = rig.connect().await;
        put(&client, &head).await;
        let _ = responses(&client, 1).await;
        let began = StdInstant::now();
        assert!(rig.finish(task).await.is_empty());
        assert!(began.elapsed() >= Duration::from_millis(250) && began.elapsed() < 4 * SEC);
        let rig = Rig::new(
            ProxyConfig {
                lingering_timeout: 5 * SEC,
                ..cfg
            },
            Mode::Answer(BLOCK),
        )
        .await;
        let (client, task) = rig.connect().await;
        put(&client, &head).await;
        let _ = responses(&client, 1).await;
        put(&client, &[b'b'; 20_000]).await;
        let began = StdInstant::now();
        assert!(rig.finish(task).await.is_empty());
        assert!(began.elapsed() < 4 * SEC);
        drop(client);
    });
}

#[test]
fn a_response_that_closes_the_connection_is_read_whole_although_the_client_went_on_sending() {
    run(async {
        let old = b"GET /old HTTP/1.0\r\nHost: h\r\n\r\n".to_vec();
        let closing = b"GET /close HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n".to_vec();
        for (name, first) in [("http/1.0", old), ("close", closing)] {
            let rig = Rig::new(kept(), Mode::Answer(BLOCK)).await;
            let (mut client, task) = rig.connect().await;
            // The requests behind the first one are more than the gate reads, and no head of them is refused,
            // so only the lingering keeps the close from resetting the connection under the client.
            let mut input = first.clone();
            for _ in 0..2000 {
                input.extend_from_slice(&get("/next"));
            }
            put(&client, &input).await;
            let (answers, _) = responses(&client, 1).await;
            assert_eq!(answers[0].status, 403, "{name}");
            assert_eq!(answers[0].all("connection"), ["close"], "{name}");
            // The client has not seen the end of the response yet, and goes on.
            put(&client, &[b'b'; 100_000]).await;
            finish_sending(&mut client).await;
            assert!(read_clean(&client).await.is_empty(), "{name}");
            assert_eq!(rig.finish(task).await.len(), 1, "{name}");
        }
    });
}

#[test]
fn a_drain_closes_the_connection_that_waits_for_a_request_and_leaves_one_that_is_in_a_request() {
    run(async {
        let rig = Rig::new(kept(), Mode::Answer(BLOCK)).await;
        let (client, task) = rig.connect().await;
        put(&client, &get("/1")).await;
        assert_eq!(responses(&client, 1).await.0[0].status, 403);
        sleep(Duration::from_millis(100)).await;
        let began = StdInstant::now();
        rig.ctx.ingress.drain();
        assert!(read_all(&client).await.is_empty());
        assert!(began.elapsed() < 5 * SEC);
        assert_eq!(rig.finish(task).await.len(), 1);

        // A connection that has begun its next request is not told: half of the head is there.
        let rig = Rig::new(kept(), Mode::Answer(BLOCK)).await;
        let (mut client, task) = rig.connect().await;
        put(&client, &get("/1")).await;
        assert_eq!(responses(&client, 1).await.0[0].status, 403);
        let second = get("/2");
        put(&client, &second[..10]).await;
        sleep(Duration::from_millis(100)).await;
        rig.ctx.ingress.drain();
        sleep(Duration::from_millis(100)).await;
        put(&client, &second[10..]).await;
        let (answers, closed) = responses(&client, 1).await;
        assert!(!closed && answers[0].status == 403 && answers[0].all("connection").is_empty());
        finish_sending(&mut client).await;
        assert!(read_all(&client).await.is_empty());
        assert_eq!(rig.finish(task).await.len(), 2);
    });
}

#[test]
fn a_403_of_the_route_keeps_the_connection_if_the_request_had_no_body_and_ends_it_otherwise() {
    run(async {
        // The route turns the loopback address away.
        let forward = guarded(&["127.0.0.0/8"], &[]);
        let rig = Rig::with(kept(), Mode::Answer(BLOCK), &forward).await;
        let (client, task) = rig.connect().await;
        for target in ["/a", "/b"] {
            put(&client, &get(target)).await;
            let (answers, closed) = responses(&client, 1).await;
            assert!(!closed && answers[0].status == 403);
            assert!(answers[0].all("connection").is_empty());
        }
        put(&client, &form_post("Content-Length: 3\r\n\r\na=b")).await;
        let last = parse_response(&read_all(&client).await);
        assert_eq!(last.status, 403);
        assert_eq!(last.all("connection"), ["close"]);
        assert!(rig.finish(task).await.is_empty());
    });
}

// ---- a stream on a route: a WebSocket through it, and the responses that take long ----

pub(in crate::inbound) const ALLOW: Outcome = Outcome::Verdict(Verdict::Allow);

fn stream(idle_ms: u64, total_ms: u64, websocket: bool) -> Stream {
    Stream {
        idle: Duration::from_millis(idle_ms),
        total: Duration::from_millis(total_ms),
        websocket,
    }
}

/// One group with the server at `upstream`. The route `/ws/` has the `stream`; the default route has none.
fn streaming(upstream: SocketAddr, stream: Stream) -> ForwardConfig {
    let mut forward = ForwardConfig::of(&[upstream]);
    let route = RouteConfig {
        stream: Some(stream),
        ..RouteConfig::plain(0)
    };
    let rule = Rule::forward(None, Some("/ws/")).unwrap();
    forward.routes = Table::new(vec![(rule, route)]).unwrap();
    forward
}

/// The handshake of a WebSocket for `target`, with `upgrade` as the protocol.
fn handshake(target: &str, upgrade: &str) -> Vec<u8> {
    format!(
        "GET {target} HTTP/1.1\r\nHost: h\r\nUpgrade: {upgrade}\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
    .into_bytes()
}

/// A client with the bytes it has read and not used yet.
struct Peer {
    sock: TcpStream,
    held: Vec<u8>,
}

impl Peer {
    fn new(sock: TcpStream) -> Peer {
        Peer {
            sock,
            held: Vec::new(),
        }
    }

    async fn send(&mut self, bytes: &[u8]) {
        self.sock.write_all(bytes).await.unwrap();
    }

    /// Reads more into `held`; false at the end of the stream (or a reset).
    async fn more(&mut self) -> bool {
        let mut buf = [0u8; 8192];
        match timeout(30 * SEC, self.sock.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                self.held.extend_from_slice(&buf[..n]);
                true
            }
            Ok(Ok(_) | Err(_)) => false,
            Err(_) => panic!("nothing came"),
        }
    }

    /// The head of a response: everything up to and including the blank line.
    async fn head(&mut self) -> Vec<u8> {
        loop {
            if let Some(end) = self.held.windows(4).position(|w| w == b"\r\n\r\n") {
                return self.held.drain(..end + 4).collect();
            }
            assert!(self.more().await, "the head did not come");
        }
    }

    /// The next `n` bytes.
    async fn take(&mut self, n: usize) -> Vec<u8> {
        while self.held.len() < n {
            assert!(self.more().await, "the stream ended");
        }
        self.held.drain(..n).collect()
    }

    /// Everything up to the end of the stream.
    async fn rest(&mut self) -> Vec<u8> {
        while self.more().await {}
        std::mem::take(&mut self.held)
    }
}

/// A raw upstream: it serves each connection it takes with `serve`, which is also given the place where the bytes
/// that the upstream read are kept.
pub(in crate::inbound) struct Raw {
    pub(in crate::inbound) addr: SocketAddr,
    taken: Arc<AtomicUsize>,
    seen: Arc<StdMutex<Vec<u8>>>,
    accepting: JoinHandle<()>,
}

impl Raw {
    pub(in crate::inbound) async fn start<F, Fut>(serve: F) -> Raw
    where
        F: Fn(TcpStream, Arc<StdMutex<Vec<u8>>>) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let taken = Arc::new(AtomicUsize::new(0));
        let seen: Arc<StdMutex<Vec<u8>>> = Arc::default();
        let accepting = {
            let (taken, seen) = (taken.clone(), seen.clone());
            tokio::spawn(async move {
                while let Ok((sock, _)) = listener.accept().await {
                    taken.fetch_add(1, Ordering::SeqCst);
                    tokio::spawn(serve(sock, seen.clone()));
                }
            })
        };
        Raw {
            addr,
            taken,
            seen,
            accepting,
        }
    }

    fn taken(&self) -> usize {
        self.taken.load(Ordering::SeqCst)
    }

    /// The bytes read from the clients so far, as text.
    pub(in crate::inbound) fn seen(&self) -> String {
        String::from_utf8_lossy(&self.seen.lock().unwrap()).into_owned()
    }
}

impl Drop for Raw {
    fn drop(&mut self) {
        self.accepting.abort();
    }
}

/// Reads the head of a request from `sock`; the bytes behind it are returned too.
async fn read_request(sock: &mut TcpStream) -> (Vec<u8>, Vec<u8>) {
    let mut held = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        if let Some(end) = held.windows(4).position(|w| w == b"\r\n\r\n") {
            let behind = held.split_off(end + 4);
            return (held, behind);
        }
        match sock.read(&mut buf).await {
            Ok(n) if n > 0 => held.extend_from_slice(&buf[..n]),
            _ => return (held, Vec::new()),
        }
    }
}

const SWITCHING: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: accepted\r\nSec-WebSocket-Protocol: chat\r\n\r\n";

/// Answers the handshake with 101 and then sends back every byte it reads.
async fn echo(sock: TcpStream, seen: Arc<StdMutex<Vec<u8>>>) {
    echo_after(sock, seen, Duration::ZERO).await;
}

/// The same, `wait` after the handshake was read.
async fn echo_after(mut sock: TcpStream, seen: Arc<StdMutex<Vec<u8>>>, wait: Duration) {
    let (head, mut behind) = read_request(&mut sock).await;
    seen.lock().unwrap().extend_from_slice(&head);
    sleep(wait).await;
    if sock.write_all(SWITCHING).await.is_err() {
        return;
    }
    let mut buf = [0u8; 4096];
    loop {
        if !behind.is_empty() && sock.write_all(&std::mem::take(&mut behind)).await.is_err() {
            return;
        }
        match sock.read(&mut buf).await {
            Ok(n) if n > 0 => behind.extend_from_slice(&buf[..n]),
            _ => return,
        }
    }
}

/// Answers the handshake with 101 and then says nothing.
async fn silent(mut sock: TcpStream, seen: Arc<StdMutex<Vec<u8>>>) {
    let (head, _) = read_request(&mut sock).await;
    seen.lock().unwrap().extend_from_slice(&head);
    let _ = sock.write_all(SWITCHING).await;
    let mut buf = [0u8; 64];
    while matches!(sock.read(&mut buf).await, Ok(n) if n > 0) {}
}

/// Answers the handshake with 101 and then says nothing, and keeps the connection open whatever the peer does.
async fn mute(mut sock: TcpStream, seen: Arc<StdMutex<Vec<u8>>>) {
    let (head, _) = read_request(&mut sock).await;
    seen.lock().unwrap().extend_from_slice(&head);
    let _ = sock.write_all(SWITCHING).await;
    sleep(30 * SEC).await;
}

/// Answers the handshake with 101 and ends its side of the connection at once.
async fn closing(mut sock: TcpStream, seen: Arc<StdMutex<Vec<u8>>>) {
    let (head, _) = read_request(&mut sock).await;
    seen.lock().unwrap().extend_from_slice(&head);
    let _ = sock.write_all(SWITCHING).await;
}

/// Answers the handshake with 101, then sends a byte every 100 ms, `n` times, and reads on to the end of the stream.
async fn talk(mut sock: TcpStream, seen: Arc<StdMutex<Vec<u8>>>, n: usize) {
    let (head, _) = read_request(&mut sock).await;
    seen.lock().unwrap().extend_from_slice(&head);
    if sock.write_all(SWITCHING).await.is_err() {
        return;
    }
    for _ in 0..n {
        sleep(Duration::from_millis(100)).await;
        if sock.write_all(b"x").await.is_err() {
            return;
        }
    }
    let mut buf = [0u8; 64];
    while matches!(sock.read(&mut buf).await, Ok(k) if k > 0) {}
}

/// Answers a request with `answer`, then reads on and keeps what it reads.
pub(in crate::inbound) async fn reply(
    mut sock: TcpStream,
    seen: Arc<StdMutex<Vec<u8>>>,
    answer: &'static [u8],
) {
    let (head, behind) = read_request(&mut sock).await;
    seen.lock().unwrap().extend_from_slice(&head);
    seen.lock().unwrap().extend_from_slice(&behind);
    let _ = sock.write_all(answer).await;
    let mut buf = [0u8; 4096];
    while let Ok(n) = sock.read(&mut buf).await {
        if n == 0 {
            return;
        }
        seen.lock().unwrap().extend_from_slice(&buf[..n]);
    }
}

pub(in crate::inbound) const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

#[test]
fn a_handshake_gets_its_101_and_the_bytes_go_both_ways_in_order_also_after_the_stop_began() {
    run(async {
        let up = Raw::start(echo).await;
        let forward = streaming(up.addr, stream(5_000, 20_000, true));
        let rig = Rig::with(kept(), Mode::Answer(ALLOW), &forward).await;
        let (client, task) = rig.connect().await;
        let mut peer = Peer::new(client);
        // The first bytes of the tunnel are in the write of the handshake.
        let mut first = handshake("/ws/chat", "WebSocket");
        first.extend_from_slice(b"first");
        peer.send(&first).await;
        let head = parse_response(&peer.head().await);
        assert_eq!(head.status, 101);
        assert_eq!(head.all("connection"), ["upgrade"]);
        assert_eq!(head.all("upgrade"), ["websocket"]);
        assert!(head.all("content-length").is_empty() && head.all("transfer-encoding").is_empty());
        assert_eq!(head.all("sec-websocket-accept"), ["accepted"]);
        assert_eq!(head.all("sec-websocket-protocol"), ["chat"]);
        assert_eq!(peer.take(5).await, b"first");
        peer.send(b"second").await;
        assert_eq!(peer.take(6).await, b"second");
        // The stop does not end a tunnel.
        rig.ctx.ingress.close();
        let big: Vec<u8> = (0..40_000u32).map(|n| (n % 251) as u8).collect();
        peer.send(&big).await;
        assert_eq!(peer.take(big.len()).await, big);
        // The client ends its side, the upstream ends its own, and the tunnel is over.
        peer.sock.shutdown().await.unwrap();
        assert!(peer.rest().await.is_empty());
        let seen = rig.finish(task).await;
        // The handshake was inspected, like any request.
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].uri, "/ws/chat");
        // The upstream was asked with fixed fields, once each, and nothing of the client's own.
        let asked = up.seen();
        assert!(asked.starts_with("GET /ws/chat HTTP/1.1\r\n"), "{asked}");
        assert!(
            asked.contains("Connection: upgrade\r\n") && asked.contains("Upgrade: websocket\r\n")
        );
        assert_eq!(asked.matches("Connection:").count(), 1);
        assert!(asked.contains("Sec-Websocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"));
        assert!(!asked.contains("keep-alive") && !asked.contains("WebSocket"));
    });
}

#[test]
fn a_stop_while_the_handshake_waits_for_the_upstream_does_not_change_its_101() {
    run(async {
        let up = Raw::start(|sock, seen| echo_after(sock, seen, Duration::from_millis(400))).await;
        let forward = streaming(up.addr, stream(5_000, 20_000, true));
        let rig = Rig::with(kept(), Mode::Answer(ALLOW), &forward).await;
        let (client, task) = rig.connect().await;
        let mut peer = Peer::new(client);
        peer.send(&handshake("/ws/chat", "websocket")).await;
        sleep(Duration::from_millis(100)).await;
        // The request is under way: hyper is not told to wind the connection down, or it would add its own
        // `Connection: close` to the 101.
        rig.ctx.ingress.close();
        let head = parse_response(&peer.head().await);
        assert_eq!(head.status, 101);
        assert_eq!(head.all("connection"), ["upgrade"]);
        peer.send(b"ping").await;
        assert_eq!(peer.take(4).await, b"ping");
        peer.sock.shutdown().await.unwrap();
        assert!(peer.rest().await.is_empty());
        assert_eq!(rig.finish(task).await.len(), 1);
    });
}

#[test]
fn an_upgrade_that_is_not_a_websocket_goes_on_without_it_and_the_connection_ends_after_the_response()
 {
    run(async {
        // A route that does not let a WebSocket through, and a protocol other than a WebSocket on a route that does.
        for (allowed, upgrade) in [(false, "websocket"), (true, "h2c")] {
            let up = Raw::start(|sock, seen| reply(sock, seen, OK)).await;
            let forward = streaming(up.addr, stream(5_000, 20_000, allowed));
            let rig = Rig::with(kept(), Mode::Answer(ALLOW), &forward).await;
            let (client, task) = rig.connect().await;
            let mut peer = Peer::new(client);
            // A second request is in the same write: it is neither inspected nor sent on.
            let mut input = handshake("/ws/x", upgrade);
            input.extend_from_slice(&get("/ws/smuggled"));
            peer.send(&input).await;
            let raw = peer.rest().await;
            let answer = parse_response(&raw);
            assert_eq!(answer.status, 200, "{upgrade}");
            assert_eq!(answer.all("connection"), ["close"], "{upgrade}");
            assert!(raw.ends_with(b"\r\n\r\nok"), "{upgrade}");
            assert_eq!(rig.finish(task).await.len(), 1, "{upgrade}");
            let asked = up.seen();
            assert!(asked.starts_with("GET /ws/x HTTP/1.1\r\n"), "{asked}");
            let lower = asked.to_ascii_lowercase();
            assert!(
                !lower.contains("upgrade") && !lower.contains("smuggled"),
                "{asked}"
            );
        }
    });
}

#[test]
fn what_the_upstream_answers_to_a_handshake_other_than_a_proper_101_is_no_tunnel() {
    run(async {
        // 200: an answer like any other, and the connection ends after it.
        let up = Raw::start(|sock, seen| reply(sock, seen, OK)).await;
        let forward = streaming(up.addr, stream(5_000, 20_000, true));
        let rig = Rig::with(kept(), Mode::Answer(ALLOW), &forward).await;
        let (client, task) = rig.connect().await;
        let mut peer = Peer::new(client);
        let mut input = handshake("/ws/x", "websocket");
        input.extend_from_slice(&get("/ws/smuggled"));
        peer.send(&input).await;
        let raw = peer.rest().await;
        let answer = parse_response(&raw);
        assert_eq!(answer.status, 200);
        assert_eq!(answer.all("connection"), ["close"]);
        assert!(raw.ends_with(b"\r\n\r\nok"));
        assert_eq!(rig.finish(task).await.len(), 1);
        assert!(up.seen().contains("Upgrade: websocket\r\n") && !up.seen().contains("smuggled"));

        // A 101 that was not asked for, and a 101 for another protocol, are 502.
        const OTHER: &[u8] =
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n";
        const NO_CONNECTION: &[u8] =
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n";
        for (allowed, answer) in [(false, SWITCHING), (true, OTHER), (true, NO_CONNECTION)] {
            let up = Raw::start(move |sock, seen| reply(sock, seen, answer)).await;
            let forward = streaming(up.addr, stream(5_000, 20_000, allowed));
            let rig = Rig::with(kept(), Mode::Answer(ALLOW), &forward).await;
            let (client, task) = rig.connect().await;
            let mut peer = Peer::new(client);
            peer.send(&handshake("/ws/x", "websocket")).await;
            let raw = peer.rest().await;
            assert_eq!(parse_response(&raw).status, 502, "{allowed} {answer:?}");
            assert_eq!(rig.finish(task).await.len(), 1);
        }
    });
}

#[test]
fn a_handshake_that_a_rule_blocks_or_that_has_no_budget_for_a_tunnel_sends_nothing_upstream() {
    run(async {
        let up = Raw::start(echo).await;
        let forward = streaming(up.addr, stream(5_000, 20_000, true));
        let rig = Rig::with(kept(), Mode::Answer(BLOCK), &forward).await;
        let (client, task) = rig.connect().await;
        let mut peer = Peer::new(client);
        let mut input = handshake("/ws/x", "websocket");
        input.extend_from_slice(&get("/ws/smuggled"));
        peer.send(&input).await;
        let raw = peer.rest().await;
        assert_eq!(parse_response(&raw).status, 403);
        // Only the handshake was inspected.
        assert_eq!(rig.finish(task).await.len(), 1);
        assert_eq!(up.taken(), 0);

        // The budget has the handshake but not the 16 KiB of a tunnel.
        let small = ProxyConfig {
            max_buffered_bytes: 8192,
            ..kept()
        };
        let rig = Rig::with(small, Mode::Answer(ALLOW), &forward).await;
        let (client, task) = rig.connect().await;
        let mut peer = Peer::new(client);
        peer.send(&handshake("/ws/x", "websocket")).await;
        assert_eq!(parse_response(&peer.rest().await).status, 503);
        assert_eq!(rig.finish(task).await.len(), 1);
        assert_eq!(up.taken(), 0);
    });
}

#[test]
fn a_tunnel_ends_when_the_upstream_is_silent_for_idle_and_when_total_has_passed() {
    run(async {
        // The upstream says nothing after the 101: idle ends it, long before total.
        let up = Raw::start(silent).await;
        let forward = streaming(up.addr, stream(300, 20_000, true));
        let rig = Rig::with(kept(), Mode::Answer(ALLOW), &forward).await;
        let (client, task) = rig.connect().await;
        let mut peer = Peer::new(client);
        peer.send(&handshake("/ws/x", "websocket")).await;
        assert_eq!(parse_response(&peer.head().await).status, 101);
        let began = StdInstant::now();
        assert!(peer.rest().await.is_empty());
        assert!(began.elapsed() >= Duration::from_millis(250) && began.elapsed() < 5 * SEC);
        assert_eq!(rig.finish(task).await.len(), 1);

        // The client sends all the time, so the upstream is not silent for idle; total ends it.
        let up = Raw::start(echo).await;
        let forward = streaming(up.addr, stream(5_000, 700, true));
        let rig = Rig::with(kept(), Mode::Answer(ALLOW), &forward).await;
        let (client, task) = rig.connect().await;
        let mut peer = Peer::new(client);
        peer.send(&handshake("/ws/x", "websocket")).await;
        assert_eq!(parse_response(&peer.head().await).status, 101);
        let began = StdInstant::now();
        let (mut read, mut write) = peer.sock.into_split();
        let talker = tokio::spawn(async move {
            while write.write_all(b"x").await.is_ok() {
                sleep(Duration::from_millis(50)).await;
            }
        });
        let mut buf = [0u8; 64];
        while matches!(read.read(&mut buf).await, Ok(n) if n > 0) {}
        talker.abort();
        assert!(began.elapsed() >= Duration::from_millis(650) && began.elapsed() < 4 * SEC);
        assert_eq!(rig.finish(task).await.len(), 1);
    });
}

/// The records that tell how a tunnel ended.
fn tunnel_lines(lines: &Lines) -> Vec<serde_json::Value> {
    lines
        .take()
        .into_iter()
        .filter(|record| record["type"] == "tunnel")
        .collect()
}

#[test]
fn a_client_that_says_nothing_does_not_keep_a_tunnel_after_the_upstream_has_ended() {
    run(async {
        // The upstream ends its side right after the 101; the client keeps its own open and sends nothing.
        let up = Raw::start(closing).await;
        let forward = streaming(up.addr, stream(300, 20_000, true));
        let rig = Rig::with(kept(), Mode::Answer(ALLOW), &forward).await;
        let lines = rig.lines.clone();
        let (client, task) = rig.connect().await;
        let mut peer = Peer::new(client);
        peer.send(&handshake("/ws/x", "websocket")).await;
        assert_eq!(parse_response(&peer.head().await).status, 101);
        let began = StdInstant::now();
        assert_eq!(rig.finish(task).await.len(), 1);
        // `idle` after the end of the upstream, not `total`.
        assert!(began.elapsed() >= Duration::from_millis(250) && began.elapsed() < 5 * SEC);
        let ended = tunnel_lines(&lines);
        assert_eq!(ended.len(), 1, "{ended:?}");
        assert!(ended[0]["end"] == "idle", "{ended:?}");
    });
}

#[test]
fn an_upstream_does_not_keep_a_tunnel_after_the_client_has_ended_silent_or_not() {
    run(async {
        for talking in [false, true] {
            // The upstream keeps its side open: it says nothing, or sends a byte every 100 ms (less than `idle`).
            let up = Raw::start(move |sock, seen| async move {
                if talking {
                    talk(sock, seen, 1_000).await;
                } else {
                    mute(sock, seen).await;
                }
            })
            .await;
            let forward = streaming(up.addr, stream(300, 20_000, true));
            let rig = Rig::with(kept(), Mode::Answer(ALLOW), &forward).await;
            let lines = rig.lines.clone();
            let (client, task) = rig.connect().await;
            let mut peer = Peer::new(client);
            peer.send(&handshake("/ws/x", "websocket")).await;
            assert_eq!(parse_response(&peer.head().await).status, 101);
            peer.sock.shutdown().await.unwrap();
            let began = StdInstant::now();
            assert_eq!(rig.finish(task).await.len(), 1, "{talking}");
            assert!(
                began.elapsed() >= Duration::from_millis(250) && began.elapsed() < 5 * SEC,
                "{talking}: {:?}",
                began.elapsed()
            );
            let ended = tunnel_lines(&lines);
            assert_eq!(ended.len(), 1, "{talking}: {ended:?}");
            assert!(ended[0]["end"] == "idle", "{talking}: {ended:?}");
        }
    });
}

#[test]
fn a_client_that_says_nothing_is_not_cut_while_the_upstream_is_alive() {
    run(async {
        // The upstream sends for 1.2 s, four times `idle`, and the client sends nothing until it has them all.
        let up = Raw::start(|sock, seen| talk(sock, seen, 12)).await;
        let forward = streaming(up.addr, stream(300, 20_000, true));
        let rig = Rig::with(kept(), Mode::Answer(ALLOW), &forward).await;
        let lines = rig.lines.clone();
        let (client, task) = rig.connect().await;
        let mut peer = Peer::new(client);
        peer.send(&handshake("/ws/x", "websocket")).await;
        assert_eq!(parse_response(&peer.head().await).status, 101);
        assert_eq!(peer.take(12).await, b"xxxxxxxxxxxx");
        // Both sides end in turn: the client, and then the upstream, which reads on to the end of the stream.
        peer.sock.shutdown().await.unwrap();
        assert!(peer.rest().await.is_empty());
        assert_eq!(rig.finish(task).await.len(), 1);
        let ended = tunnel_lines(&lines);
        assert_eq!(ended.len(), 1, "{ended:?}");
        assert!(
            ended[0]["end"] == "closed"
                && ended[0]["to_upstream"] == 0
                && ended[0]["from_upstream"] == 12,
            "{ended:?}"
        );
    });
}

#[test]
fn a_tunnel_that_the_client_does_not_get_has_its_one_line_for_the_end() {
    run(async {
        // The upstream answers the handshake after 400 ms; the client has reset the connection by then, so the
        // 101 cannot be written.
        let up = Raw::start(|sock, seen| echo_after(sock, seen, Duration::from_millis(400))).await;
        let forward = streaming(up.addr, stream(5_000, 20_000, true));
        let rig = Rig::with(kept(), Mode::Answer(ALLOW), &forward).await;
        let lines = rig.lines.clone();
        let (client, task) = rig.connect().await;
        let mut peer = Peer::new(client);
        peer.send(&handshake("/ws/x", "websocket")).await;
        while !up.seen().contains("\r\n\r\n") {
            sleep(Duration::from_millis(10)).await;
        }
        peer.sock.set_zero_linger().unwrap();
        drop(peer);
        // Nothing is held after the end (`finish` checks the byte budget).
        rig.finish(task).await;
        let ended = tunnel_lines(&lines);
        assert_eq!(ended.len(), 1, "{ended:?}");
        assert!(ended[0]["end"] == "error", "{ended:?}");
    });
}

/// Answers a request with the head of a chunked response and a first chunk, and the rest once `release` is told.
async fn events(mut sock: TcpStream, seen: Arc<StdMutex<Vec<u8>>>, release: Arc<Notify>) {
    let (head, _) = read_request(&mut sock).await;
    seen.lock().unwrap().extend_from_slice(&head);
    let first = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n";
    if sock.write_all(first).await.is_err() {
        return;
    }
    release.notified().await;
    let _ = sock.write_all(b"5\r\nworld\r\n0\r\n\r\n").await;
}

#[test]
fn only_a_route_with_a_stream_outlives_the_connection_time_and_its_first_chunk_comes_at_once() {
    run(async {
        let short = ProxyConfig {
            conn_total: Duration::from_millis(700),
            ..kept()
        };
        for (target, long) in [("/ws/events", true), ("/plain", false)] {
            let release = Arc::new(Notify::new());
            let up = Raw::start({
                let release = release.clone();
                move |sock, seen| events(sock, seen, release.clone())
            })
            .await;
            let forward = streaming(up.addr, stream(5_000, 20_000, false));
            let rig = Rig::with(short.clone(), Mode::Answer(ALLOW), &forward).await;
            let (client, task) = rig.connect().await;
            let mut peer = Peer::new(client);
            peer.send(&get(target)).await;
            // The first chunk is here while the upstream has not finished.
            let head = parse_response(&peer.head().await);
            assert_eq!(head.status, 200);
            assert_eq!(head.all("connection") == ["close"], long, "{target}");
            assert_eq!(peer.take(10).await, b"5\r\nhello\r\n");
            // Longer than the connection time.
            sleep(Duration::from_millis(1200)).await;
            release.notify_one();
            let rest = peer.rest().await;
            assert_eq!(rest.ends_with(b"0\r\n\r\n"), long, "{target}: {rest:?}");
            assert_eq!(
                rest.windows(5).any(|w| w == b"world"),
                long,
                "{target}: {rest:?}"
            );
            assert_eq!(rig.finish(task).await.len(), 1);
        }
    });
}

#[test]
fn a_response_on_a_route_with_a_stream_ends_when_the_upstream_is_silent_for_idle() {
    run(async {
        let release = Arc::new(Notify::new());
        let up = Raw::start({
            let release = release.clone();
            move |sock, seen| events(sock, seen, release.clone())
        })
        .await;
        let forward = streaming(up.addr, stream(300, 20_000, false));
        let rig = Rig::with(kept(), Mode::Answer(ALLOW), &forward).await;
        let (client, task) = rig.connect().await;
        let mut peer = Peer::new(client);
        peer.send(&get("/ws/events")).await;
        assert_eq!(parse_response(&peer.head().await).status, 200);
        assert_eq!(peer.take(10).await, b"5\r\nhello\r\n");
        let began = StdInstant::now();
        let rest = peer.rest().await;
        assert!(!rest.windows(5).any(|w| w == b"world") && !rest.ends_with(b"0\r\n\r\n"));
        assert!(began.elapsed() >= Duration::from_millis(250) && began.elapsed() < 5 * SEC);
        assert_eq!(rig.finish(task).await.len(), 1);
        release.notify_one();
    });
}

// ---- listeners that end TLS and listeners that redirect ----

type TlsClient = tokio_rustls::client::TlsStream<TcpStream>;

/// A rig whose listeners are, in this order: one that ends TLS with a certificate for `a.example` and its
/// subdomains, a plain one, and one that redirects to https at `https_port`.
async fn over_tls(
    pki: &Pki,
    cfg: ProxyConfig,
    mode: Mode,
    forward: &ForwardConfig,
    https_port: u16,
) -> Rig {
    let pair = pki.issue("a", &["a.example", "*.a.example"]);
    let listeners = vec![
        tls_listener(MinVersion::Tls12, &[(&pair, &["a.example", "*.a.example"])]),
        ListenerConfig {
            address: "127.0.0.1:2".parse().unwrap(),
            kind: ListenerKind::Plain,
        },
        ListenerConfig {
            address: "127.0.0.1:3".parse().unwrap(),
            kind: ListenerKind::Redirect { https_port },
        },
    ];
    let tls = Tls::load(&listeners, &Files).unwrap();
    Rig::with_tls(ProxyConfig { listeners, ..cfg }, mode, forward, tls).await
}

/// The client side of the handshake with the name `a.example`.
async fn shake(pki: &Pki, tcp: TcpStream) -> TlsClient {
    let name = ServerName::try_from("a.example".to_owned()).unwrap();
    pki.any_client().connect(name, tcp).await.unwrap()
}

/// One response on a TLS connection: its head, and the body its length says.
async fn tls_response(stream: &mut TlsClient) -> Option<(Parsed, Vec<u8>)> {
    let mut raw = Vec::new();
    let mut byte = [0u8; 1];
    while !raw.ends_with(b"\r\n\r\n") {
        let n = timeout(30 * SEC, stream.read(&mut byte))
            .await
            .unwrap()
            .ok()?;
        if n == 0 {
            return None;
        }
        raw.push(byte[0]);
    }
    let head = parse_response(&raw);
    let length: usize = head.all("content-length")[0].parse().unwrap();
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).await.unwrap();
    Some((head, body))
}

fn get_for(target: &str, host: &str) -> Vec<u8> {
    format!("GET {target} HTTP/1.1\r\nHost: {host}\r\n\r\n").into_bytes()
}

#[test]
fn a_request_over_tls_is_forwarded_with_https_as_its_scheme_and_a_plain_one_with_http() {
    run(async {
        let pki = Pki::new();
        let up = Raw::start(|sock, seen| reply(sock, seen, OK)).await;
        let forward = ForwardConfig::of(&[up.addr]);
        let rig = over_tls(&pki, kept(), Mode::Answer(ALLOW), &forward, 443).await;
        let (client, task) = rig.connect_on(0).await;
        let mut stream = shake(&pki, client).await;
        stream
            .write_all(&get_for("/x", "www.a.example"))
            .await
            .unwrap();
        let (head, body) = tls_response(&mut stream).await.unwrap();
        assert_eq!((head.status, body.as_slice()), (200, &b"ok"[..]));
        // The end of the connection is the closing alert of TLS.
        stream.shutdown().await.unwrap();
        let mut rest = Vec::new();
        assert_eq!(stream.read_to_end(&mut rest).await.unwrap(), 0);
        let seen = up.seen().to_ascii_lowercase();
        assert_eq!(
            seen.matches("x-forwarded-proto: https\r\n").count(),
            1,
            "{seen}"
        );
        timeout(30 * SEC, task).await.unwrap().unwrap();

        let (client, task) = rig.connect_on(1).await;
        put(&client, &get_for("/y", "h.test")).await;
        assert_eq!(parse_response(&read_all(&client).await).status, 200);
        timeout(30 * SEC, task).await.unwrap().unwrap();
        let seen = up.seen().to_ascii_lowercase();
        assert_eq!(
            seen.matches("x-forwarded-proto: http\r\n").count(),
            1,
            "{seen}"
        );
        assert_eq!(rig.finish(tokio::spawn(async {})).await.len(), 2);
    });
}

#[test]
fn a_host_the_certificate_does_not_cover_is_answered_with_421_before_the_inspection() {
    run(async {
        let pki = Pki::new();
        let rig = over_tls(&pki, kept(), Mode::Answer(BLOCK), &routed_to_h_test(), 443).await;
        let (client, task) = rig.connect_on(0).await;
        let mut stream = shake(&pki, client).await;
        // A request whose Host the certificate does not stand for, or that has none that can be read, is answered
        // with 421 and the connection goes on (there is no body to be read).
        for host in [
            "other.example",
            "a.example.net",
            "192.0.2.1",
            "[::1]",
            "a..example",
            "a.example:0",
        ] {
            stream.write_all(&get_for("/", host)).await.unwrap();
            let (head, _) = tls_response(&mut stream).await.expect(host);
            assert_eq!(head.status, 421, "{host}");
            assert!(head.all("connection").is_empty(), "{host}");
        }
        // The hosts of the certificate go to the route and the inspection (which blocks all in this rig), in any
        // case, with a port or a dot at the end.
        for host in ["a.example", "WWW.A.example:8443", "x.a.example."] {
            stream.write_all(&get_for("/", host)).await.unwrap();
            let (head, _) = tls_response(&mut stream).await.expect(host);
            assert_eq!(head.status, 404, "{host}");
        }
        // A request with a body ends the connection after the 421, like a 404.
        let post = format!(
            "POST /p HTTP/1.1\r\nHost: other.example\r\nContent-Type: {FORM}\r\nContent-Length: 3\r\n\r\na=b"
        );
        stream.write_all(post.as_bytes()).await.unwrap();
        let (head, _) = tls_response(&mut stream).await.unwrap();
        assert_eq!((head.status, head.all("connection")), (421, vec!["close"]));
        let mut rest = Vec::new();
        assert_eq!(stream.read_to_end(&mut rest).await.unwrap(), 0);
        // Nothing of this was inspected; the lines in the record say what was answered.
        let lines = rig.lines.clone();
        assert!(rig.finish(task).await.is_empty());
        let lines = lines.take();
        assert_eq!(
            lines
                .iter()
                .filter(|l| is_answer(l, "rejected", 421, "host not covered by the certificate"))
                .count(),
            7,
            "{lines:?}"
        );
    });
}

#[test]
fn a_request_that_is_inspected_over_tls_is_blocked_like_any_other() {
    run(async {
        let pki = Pki::new();
        let rig = over_tls(
            &pki,
            kept(),
            Mode::Answer(BLOCK),
            &ForwardConfig::of(&["127.0.0.1:2".parse().unwrap()]),
            443,
        )
        .await;
        let (client, task) = rig.connect_on(0).await;
        let mut stream = shake(&pki, client).await;
        let post = form_post("Content-Length: 3\r\n\r\na=b");
        let post = String::from_utf8(post)
            .unwrap()
            .replace("example.test", "a.example");
        stream.write_all(post.as_bytes()).await.unwrap();
        let (head, _) = tls_response(&mut stream).await.unwrap();
        assert_eq!(head.status, 403);
        let mut rest = Vec::new();
        assert_eq!(stream.read_to_end(&mut rest).await.unwrap(), 0);
        assert_eq!(rig.finish(task).await.len(), 1);
    });
}

#[test]
fn a_client_that_is_silent_or_does_not_speak_tls_is_closed_with_one_line_in_the_record() {
    run(async {
        let pki = Pki::new();
        let cfg = ProxyConfig {
            head_read: Duration::from_millis(300),
            ..kept()
        };
        for (sent, reason) in [
            (&b""[..], "tls handshake not finished in time"),
            (
                &b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n"[..],
                "tls handshake failed",
            ),
        ] {
            let rig = over_tls(
                &pki,
                cfg.clone(),
                Mode::Answer(BLOCK),
                &routed_to_h_test(),
                443,
            )
            .await;
            let (client, task) = rig.connect_on(0).await;
            put(&client, sent).await;
            let began = StdInstant::now();
            let _ = read_all(&client).await;
            assert!(began.elapsed() < 10 * SEC);
            let lines = rig.lines.clone();
            assert!(rig.finish(task).await.is_empty());
            let lines = lines.take();
            let ours: Vec<&serde_json::Value> =
                lines.iter().filter(|l| l["reason"] == reason).collect();
            assert_eq!(ours.len(), 1, "{lines:?}");
            assert!(
                ours[0]["type"] == "connection"
                    && ours[0]["class"] == "closed"
                    && ours[0]["status"] == 0,
                "{ours:?}"
            );
            if sent.is_empty() {
                assert!(began.elapsed() >= Duration::from_millis(250));
            }
        }
    });
}

/// The routes of a redirect test: only the subdomains of `a.example` have a route.
fn subdomains_only() -> ForwardConfig {
    let mut forward = ForwardConfig::of(&["127.0.0.1:2".parse().unwrap()]);
    let rule = Rule::forward(Some("*.a.example"), None).unwrap();
    forward.routes = Table::new(vec![(rule, RouteConfig::plain(0))]).unwrap();
    forward.default = None;
    forward
}

/// Sends `request` to the redirect listener of the rig on a new connection, and gives the answer.
async fn redirected(rig: &Rig, request: &str) -> Parsed {
    let (client, task) = rig.connect_on(2).await;
    put(&client, request.as_bytes()).await;
    let raw = read_all(&client).await;
    timeout(30 * SEC, task).await.unwrap().unwrap();
    parse_response(&raw)
}

#[test]
fn a_redirect_listener_sends_a_served_host_with_a_route_to_https_and_answers_any_other_with_404() {
    run(async {
        let pki = Pki::new();
        for (port, at) in [(443, ""), (8443, ":8443")] {
            let rig = over_tls(&pki, kept(), Mode::Answer(BLOCK), &subdomains_only(), port).await;
            // The number of each redirect that was written, which its record has too.
            let mut numbers = Vec::new();
            for (request, location) in [
                (
                    "GET /a/b?x=1&y=%41 HTTP/1.1\r\nHost: www.a.example\r\n\r\n",
                    format!("https://www.a.example{at}/a/b?x=1&y=%41"),
                ),
                (
                    "GET //evil.example/x HTTP/1.1\r\nHost: WWW.A.Example.:80\r\n\r\n",
                    format!("https://www.a.example{at}//evil.example/x"),
                ),
                (
                    "GET / HTTP/1.0\r\nHost: x.a.example\r\n\r\n",
                    format!("https://x.a.example{at}/"),
                ),
            ] {
                let answer = redirected(&rig, request).await;
                assert_eq!(answer.status, 308, "{request}");
                assert_eq!(answer.all("location"), vec![location.as_str()], "{request}");
                assert_eq!(answer.all("content-length"), ["0"]);
                assert_eq!(answer.all("connection"), ["close"]);
                numbers.extend(answer.all("x-request-id").iter().map(ToString::to_string));
            }
            // A host that a certificate has but no route holds for, a host no certificate has, a literal, and a
            // host that cannot be read.
            for host in [
                "a.example",
                "www.other.example",
                "192.0.2.1",
                "[::1]:80",
                "a..example",
                "x.a.example:0",
            ] {
                let answer =
                    redirected(&rig, &format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n")).await;
                assert_eq!(answer.status, 404, "{host}");
                assert!(answer.all("location").is_empty(), "{host}");
                assert_eq!(answer.all("connection"), ["close"]);
                assert_eq!(answer.all("x-request-id").len(), 1, "{host}");
            }
            // The body is not read, and nothing is inspected.
            let post = format!(
                "POST /p HTTP/1.1\r\nHost: x.a.example\r\nContent-Type: {FORM}\r\nContent-Length: 1000\r\n\r\n0123456789"
            );
            let answer = redirected(&rig, &post).await;
            assert_eq!(answer.status, 308);
            numbers.extend(answer.all("x-request-id").iter().map(ToString::to_string));
            let lines = rig.lines.take();
            let mut recorded: Vec<String> = lines
                .iter()
                .filter(|l| is_answer(l, "redirected", 308, "redirected"))
                .map(|l| l["id"].as_str().unwrap_or_default().to_string())
                .collect();
            recorded.sort();
            numbers.sort();
            assert_eq!(numbers, recorded, "{lines:?}");
            let count = |class: &str, status: u16, reason: &str| {
                lines
                    .iter()
                    .filter(|l| is_answer(l, class, status, reason) && l.get("rule").is_none())
                    .count()
            };
            assert_eq!(count("redirected", 308, "redirected"), 4, "{lines:?}");
            assert_eq!(
                count("rejected", 404, "no redirect for the host"),
                6,
                "{lines:?}"
            );
            assert!(rig.finish(tokio::spawn(async {})).await.is_empty());
        }
    });
}

// ---- the challenge of the CA that issues the certificates with acme ----

/// The challenge for the host `a.example` with its files in `dir`.
fn challenge_in(dir: &Path) -> Challenge {
    let acme = AcmeConfig {
        directory_url: "https://ca.example/dir".to_owned(),
        contact_email: "ops@example.test".to_owned(),
        account_key_file: PathBuf::from("/a"),
        challenge_dir: dir.to_path_buf(),
        ca_file: PathBuf::from("/ca"),
        timeout: SEC,
    };
    let listeners = [ListenerConfig {
        address: "127.0.0.1:1".parse().unwrap(),
        kind: ListenerKind::Tls(TlsConfig {
            min_version: MinVersion::Tls12,
            certificates: vec![CertificateConfig {
                cert_file: PathBuf::from("/c"),
                key_file: PathBuf::from("/k"),
                hosts: vec!["a.example".to_owned()],
                acme: Some(CertificateAcme {
                    renew_before_days: 30,
                }),
            }],
            http2: None,
        }),
    }];
    Challenge::new(Some(&acme), &listeners).unwrap()
}

/// One request on a new connection to the listener at `listener`, and the answer, whole: its head and its body.
async fn answered(rig: &Rig, listener: usize, request: &str) -> (Parsed, Vec<u8>) {
    let (client, task) = rig.connect_on(listener).await;
    put(&client, request.as_bytes()).await;
    let raw = read_all(&client).await;
    timeout(30 * SEC, task).await.unwrap().unwrap();
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    (parse_response(&raw[..end]), raw[end..].to_vec())
}

#[test]
fn the_challenge_is_answered_before_all_else_on_a_plain_and_a_redirect_listener_and_never_on_tls() {
    run(async {
        let pki = Pki::new();
        let proofs = Dir::new();
        fs::write(proofs.0.join("Tok_-1"), b"abc.def").unwrap();
        let rig = over_tls(&pki, kept(), Mode::Answer(BLOCK), &subdomains_only(), 443)
            .await
            .with_challenge(challenge_in(&proofs.0));
        let path = "/.well-known/acme-challenge/Tok_-1";
        let request = |method: &str, target: &str, host: &str| {
            format!("{method} {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
        };
        // Listener 1 is plain and listener 2 redirects; neither has a route for `a.example`.
        for listener in [1, 2] {
            let (head, body) =
                answered(&rig, listener, &request("GET", path, "A.Example:80")).await;
            assert_eq!(head.status, 200, "{listener}");
            assert_eq!(head.all("content-type"), ["text/plain"]);
            assert_eq!(head.all("content-length"), ["7"]);
            assert_eq!(body, b"abc.def");
            // A HEAD has the length and no body.
            let (head, body) = answered(&rig, listener, &request("HEAD", path, "a.example")).await;
            assert_eq!((head.status, head.all("content-length")), (200, vec!["7"]));
            assert!(body.is_empty());
            // A token with no file is 404.
            let missing = "/.well-known/acme-challenge/Tok_-2";
            let (head, body) =
                answered(&rig, listener, &request("GET", missing, "a.example")).await;
            assert_eq!((head.status, head.all("content-length")), (404, vec!["0"]));
            assert!(body.is_empty());
            // A host that is no acme host, a query and an escape are not the challenge.
            let query = format!("{path}?x=1");
            for (target, host) in [
                (path, "x.a.example"),
                (query.as_str(), "a.example"),
                ("/.well-known/acme-challenge/%54ok_-1", "a.example"),
            ] {
                let (head, body) = answered(&rig, listener, &request("GET", target, host)).await;
                assert_ne!(head.status, 200, "{listener} {target} {host}");
                assert_ne!(body, b"abc.def");
            }
        }
        // A connection goes on after the answer, and the next request is served as any other.
        let (client, task) = rig.connect_on(1).await;
        let pipelined = [
            get_for(path, "a.example"),
            request("GET", "/other", "x.a.example").into_bytes(),
        ]
        .concat();
        put(&client, &pipelined).await;
        let raw = read_all(&client).await;
        timeout(30 * SEC, task).await.unwrap().unwrap();
        let text = String::from_utf8_lossy(&raw);
        assert!(
            text.starts_with("HTTP/1.1 200 OK\r\n")
                && text.contains("\r\n\r\nabc.defHTTP/1.1 403 "),
            "{text}"
        );

        // A TLS listener does not answer it: the request is routed (and has no route), whatever the file says.
        let (client, task) = rig.connect_on(0).await;
        let mut stream = shake(&pki, client).await;
        stream.write_all(&get_for(path, "a.example")).await.unwrap();
        let (head, body) = tls_response(&mut stream).await.unwrap();
        assert_eq!(head.status, 404);
        assert!(body.is_empty());
        stream.shutdown().await.unwrap();
        let mut rest = Vec::new();
        assert_eq!(stream.read_to_end(&mut rest).await.unwrap(), 0);
        timeout(30 * SEC, task).await.unwrap().unwrap();

        let lines = rig.lines.clone();
        // Only the two requests of the plain listener for `x.a.example` were inspected; no challenge ever was.
        assert_eq!(rig.finish(tokio::spawn(async {})).await.len(), 2);
        let lines = lines.take();
        let count = |status: u16| {
            lines
                .iter()
                .filter(|l| {
                    is_answer(l, "answered", status, "acme challenge") && l.get("rule").is_none()
                })
                .count()
        };
        assert_eq!(count(200), 5, "{lines:?}");
        assert_eq!(count(404), 2, "{lines:?}");
    });
}

// ---- the policy of the configuration on the listener that redirects ----

/// A rig with a listener that redirects, with the challenge of the CA for `a.example` and this `access` and this
/// `rate_limit` in force, and these `trusted_proxies`. The rig closes a connection soon after its answer.
async fn policed_redirects(
    pki: &Pki,
    proofs: &Dir,
    access: Access,
    rate_limit: Option<RateLimit>,
    trusted: &[&str],
) -> Rig {
    let cfg = ProxyConfig {
        lingering_timeout: Duration::from_millis(50),
        trusted_proxies: trusted
            .iter()
            .map(|net| Cidr::parse(net).unwrap())
            .collect(),
        ..kept()
    };
    over_tls(pki, cfg, Mode::Answer(BLOCK), &subdomains_only(), 443)
        .await
        .with_challenge(challenge_in(&proofs.0))
        .with_policy(access, rate_limit)
}

#[test]
fn a_redirect_listener_turns_away_what_the_policy_turns_away_instead_of_redirecting() {
    run(async {
        let pki = Pki::new();
        let proofs = Dir::new();
        fs::write(proofs.0.join("Tok_-1"), b"abc.def").unwrap();
        let served = "GET /p HTTP/1.1\r\nHost: www.a.example\r\n\r\n";
        let unserved = "GET / HTTP/1.1\r\nHost: www.other.example\r\n\r\n";
        let proof = "GET /.well-known/acme-challenge/Tok_-1 HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n";

        // The access turns away the client, which is on the loopback address: 403 where there would be the redirect
        // and where there would be the 404; the challenge is answered all the same.
        let access = Access::new(vec![Cidr::parse("127.0.0.0/8").unwrap()], Vec::new());
        let rig = policed_redirects(&pki, &proofs, access, None, &[]).await;
        for request in [served, unserved] {
            let answer = redirected(&rig, request).await;
            assert_eq!(answer.status, 403, "{request}");
            assert!(answer.all("location").is_empty(), "{request}");
            assert!(answer.all("retry-after").is_empty(), "{request}");
            assert_eq!(answer.all("content-length"), ["0"]);
            assert_eq!(answer.all("connection"), ["close"]);
            assert_eq!(answer.all("x-request-id").len(), 1);
        }
        let (head, body) = answered(&rig, 2, proof).await;
        assert_eq!((head.status, body), (200, b"abc.def".to_vec()));
        assert_eq!(
            rig.ctx.counters.policy_refusals.samples(),
            [("access", 2), ("rate_limit", 0)]
        );
        let lines = rig.lines.take();
        let count = |class: &str, status: u16, reason: &str| {
            lines
                .iter()
                .filter(|l| is_answer(l, class, status, reason))
                .count()
        };
        assert_eq!(count("rejected", 403, "denied by access"), 2, "{lines:?}");
        assert_eq!(count("answered", 200, "acme challenge"), 1, "{lines:?}");
        assert!(rig.finish(tokio::spawn(async {})).await.is_empty());

        // One request a second and none beyond it: the first request is redirected, the next one is 429 with the
        // seconds to wait, and the challenge is neither refused nor counted.
        let limit = RateLimit::new(&RateLimitConfig {
            rate: 1,
            burst: 0,
            keys: 1024,
            exempt: Vec::new(),
        });
        let rig = policed_redirects(&pki, &proofs, Access::default(), Some(limit), &[]).await;
        assert_eq!(redirected(&rig, served).await.status, 308);
        let answer = redirected(&rig, served).await;
        assert_eq!(answer.status, 429);
        assert!(answer.all("location").is_empty());
        assert_eq!(answer.all("retry-after"), ["1"]);
        assert_eq!(answer.all("content-length"), ["0"]);
        assert_eq!(answer.all("connection"), ["close"]);
        let (head, _) = answered(&rig, 2, proof).await;
        assert_eq!(head.status, 200);
        assert_eq!(
            rig.ctx.counters.policy_refusals.samples(),
            [("access", 0), ("rate_limit", 1)]
        );
        let lines = rig.lines.take();
        let count = |class: &str, status: u16, reason: &str| {
            lines
                .iter()
                .filter(|l| is_answer(l, class, status, reason))
                .count()
        };
        assert_eq!(count("redirected", 308, "redirected"), 1, "{lines:?}");
        assert_eq!(count("rejected", 429, "too many requests"), 1, "{lines:?}");
        assert!(rig.finish(tokio::spawn(async {})).await.is_empty());
    });
}

#[test]
fn a_redirect_listener_judges_and_records_the_client_that_a_trusted_peer_names() {
    run(async {
        let pki = Pki::new();
        let proofs = Dir::new();
        // The client is on the loopback address and says in `X-Forwarded-For` that it is 10.1.2.3. The access turns
        // away one of the two addresses. The address that a trusted peer names decides, and the one that a peer that
        // is not trusted names does not. The one record of the request names the address that was judged, also when
        // the answer is the redirect.
        let request = "GET /p HTTP/1.1\r\nHost: www.a.example\r\nX-Forwarded-For: 10.1.2.3\r\n\r\n";
        for (peer_trusted, denied, status, client) in [
            (true, "10.0.0.0/8", 403, "10.1.2.3"),
            (true, "127.0.0.0/8", 308, "10.1.2.3"),
            (false, "10.0.0.0/8", 308, "127.0.0.1"),
            (false, "127.0.0.0/8", 403, "127.0.0.1"),
        ] {
            let access = Access::new(vec![Cidr::parse(denied).unwrap()], Vec::new());
            let trusted: &[&str] = if peer_trusted { &["127.0.0.0/8"] } else { &[] };
            let rig = policed_redirects(&pki, &proofs, access, None, trusted).await;
            let answer = redirected(&rig, request).await;
            assert_eq!(answer.status, status, "{trusted:?} {denied}");
            let lines = rig.lines.take();
            let records: Vec<&serde_json::Value> =
                lines.iter().filter(|l| l["type"] == "request").collect();
            assert_eq!(records.len(), 1, "{lines:?}");
            assert_eq!(records[0]["client"], client, "{trusted:?} {denied}");
            assert!(rig.finish(tokio::spawn(async {})).await.is_empty());
        }
    });
}

use crate::inbound::conn::tests::{countries, in_countries};

#[test]
fn a_redirect_listener_judges_the_country_of_the_client_that_a_trusted_peer_names() {
    run(async {
        let pki = Pki::new();
        let proofs = Dir::new();
        // The client is on the loopback address and says in `X-Forwarded-For` that it is 203.0.113.9, which the
        // database puts in JP. The list that names JP turns it away with 403, and the one that does not lets the
        // redirect through.
        let request =
            "GET /p HTTP/1.1\r\nHost: www.a.example\r\nX-Forwarded-For: 203.0.113.9\r\n\r\n";
        for (deny, allow, status) in [
            (&["JP"][..], &[][..], 403),
            (&["US"], &[], 308),
            (&[], &["US"], 403),
            (&[], &["JP"], 308),
        ] {
            let access = in_countries(deny, allow);
            let rig = policed_redirects(&pki, &proofs, access, None, &["127.0.0.0/8"])
                .await
                .with_countries(countries());
            let answer = redirected(&rig, request).await;
            assert_eq!(answer.status, status, "{deny:?} {allow:?}");
            assert!(rig.finish(tokio::spawn(async {})).await.is_empty());
        }
    });
}
