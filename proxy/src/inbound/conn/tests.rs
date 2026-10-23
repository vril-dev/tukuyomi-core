use std::future::poll_fn;
use std::io::Write;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::mpsc::{Receiver, sync_channel};
use std::thread::{self, JoinHandle};

use flate2::Compression;
use flate2::write::GzEncoder;
use tokio::io::AsyncWrite;
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::{Builder, Runtime};
use tokio::task::JoinHandle as Served;
use tokio::time::{sleep, timeout};
use tukuyomi_kernel::Verdict;

use super::*;
use crate::config::{ForwardConfig, RouteConfig};
use crate::inbound::session::{run as run_session, serve};
use crate::inspect::driver::Outcome;
use crate::log::{Lines, recording};
use crate::route::{Rule, Table};
use crate::rules::routes::{Route, Routes};

pub(in crate::inbound) const FORM: &str = "application/x-www-form-urlencoded";
const BUDGET: usize = 1 << 20;
const PERMITS: usize = 4;

pub(in crate::inbound) fn pair(name: &str, value: &str) -> (String, String) {
    (name.to_string(), value.to_string())
}

/// One gzip member of `data`.
pub(in crate::inbound) fn gz(data: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}
#[test]
fn a_stage_ends_at_the_earlier_of_its_own_end_and_the_request_time() {
    let start = Instant::now();
    let request_by = start + Duration::from_secs(10);
    assert_eq!(
        stage(start, Duration::from_secs(11), request_by),
        start + Duration::from_secs(10)
    );
    assert_eq!(
        stage(start, Duration::from_secs(3), request_by),
        start + Duration::from_secs(3)
    );
    assert_eq!(after(start, Duration::MAX), start);
}

// ---- the connection, over real sockets, with a driver that is a thread in this test ----

pub(in crate::inbound) fn config() -> ProxyConfig {
    let secs = Duration::from_secs;
    ProxyConfig {
        listen: "127.0.0.1:1".parse().unwrap(),
        max_conns: 16,
        max_head_bytes: 8192,
        max_body: 1024,
        max_body_wire: 4096,
        max_buffered_bytes: BUDGET,
        upstream_max_headers: 64,
        upstream_max_head_bytes: 8192,
        upstream_head_wire: 65536,
        drive_slice: Duration::from_millis(10),
        ready_wait: secs(5),
        head_read: secs(5),
        body_read: secs(5),
        inspect_wait: secs(5),
        upstream_connect: secs(5),
        upstream_header: secs(5),
        request_total: secs(10),
        response_idle: secs(5),
        conn_total: secs(20),
        stop_inspect: secs(1),
        stop_wait: secs(5),
        // A connection is not kept, unless a test turns it on.
        keepalive_timeout: Duration::ZERO,
        keepalive_requests: 1000,
        keepalive_time: secs(10),
        lingering_time: secs(1),
        lingering_timeout: Duration::from_millis(100),
        lingering_bytes: 1 << 20,
        trusted_proxies: Vec::new(),
        upstream_keepalive: 0,
        upstream_keepalive_timeout: secs(5),
        upstream_keepalive_requests: 1000,
    }
}

/// What the driver of a test does with a ticket.
#[derive(Clone, Copy)]
pub(in crate::inbound) enum Mode {
    /// Answers every ticket with this.
    Answer(Outcome),
    /// Keeps every ticket and never answers.
    Hold,
    /// The driver is gone: the way to it is closed.
    Gone,
    /// The way to the driver is full.
    Full,
}

#[derive(Debug)]
pub(in crate::inbound) struct Seen {
    pub(in crate::inbound) method: String,
    pub(in crate::inbound) uri: String,
    pub(in crate::inbound) proto: String,
    /// The address the inspection was told is the client's.
    pub(in crate::inbound) client: SocketAddr,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    /// For a ticket that was kept: the connection had dropped its end when the driver stopped.
    abandoned: bool,
}

fn driver(rx: Receiver<Msg>, answer: Option<Outcome>) -> JoinHandle<Vec<Seen>> {
    thread::spawn(move || {
        let mut kept = Vec::new();
        while let Ok(msg) = rx.recv() {
            let Msg::Ticket(ticket) = msg else { continue };
            let req = &ticket.req;
            let seen = Seen {
                method: String::from_utf8_lossy(&req.method).into_owned(),
                uri: String::from_utf8_lossy(&req.uri).into_owned(),
                proto: String::from_utf8_lossy(req.proto).into_owned(),
                client: req.client,
                headers: req
                    .headers
                    .iter()
                    .map(|(n, v)| {
                        (
                            String::from_utf8_lossy(n).into_owned(),
                            String::from_utf8_lossy(v).into_owned(),
                        )
                    })
                    .collect(),
                body: req.body.bytes.to_vec(),
                abandoned: false,
            };
            match answer {
                Some(outcome) => {
                    let _ = ticket.reply.send(outcome);
                    kept.push((seen, None));
                }
                None => kept.push((seen, Some(ticket))),
            }
        }
        kept.into_iter()
            .map(|(seen, ticket)| Seen {
                abandoned: ticket.is_some_and(|t| t.reply.is_closed()),
                ..seen
            })
            .collect()
    })
}

pub(in crate::inbound) struct Rig {
    pub(in crate::inbound) ctx: Arc<Ctx>,
    listener: TcpListener,
    tx: Option<SyncSender<Msg>>,
    driver: Option<JoinHandle<Vec<Seen>>>,
    /// The receiving end of a way that is full, kept so that it stays open.
    _full: Option<Receiver<Msg>>,
    /// The lines that the connections wrote to the record.
    pub(in crate::inbound) lines: Lines,
}

fn runtime() -> Runtime {
    Builder::new_current_thread().enable_all().build().unwrap()
}

/// Runs a test body; a body that hangs fails the test instead of the run.
pub(in crate::inbound) fn run<F: std::future::Future>(body: F) -> F::Output {
    runtime().block_on(async {
        timeout(Duration::from_secs(60), body)
            .await
            .expect("the test hung")
    })
}

impl Rig {
    /// A rig whose one group has one server, at an address where nothing listens, so a request that goes on ends
    /// in 502.
    pub(in crate::inbound) async fn new(cfg: ProxyConfig, mode: Mode) -> Rig {
        let server = "127.0.0.1:2".parse().unwrap();
        Rig::with(cfg, mode, &ForwardConfig::of(&[server])).await
    }

    pub(in crate::inbound) async fn with(
        cfg: ProxyConfig,
        mode: Mode,
        forward: &ForwardConfig,
    ) -> Rig {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let budget = Arc::new(Semaphore::new(cfg.max_buffered_bytes));
        let (tx, rx) = sync_channel(if matches!(mode, Mode::Full) {
            1
        } else {
            PERMITS + 1
        });
        let (log, lines) = recording();
        let ctx = Arc::new(Ctx {
            upstreams: Upstreams::new(forward, &cfg),
            cfg,
            budget,
            inspect: Arc::new(Semaphore::new(PERMITS)),
            routes: SharedRoutes::new(Routes::default()),
            log,
            ingress: Arc::new(Ingress::new(tx.clone())),
        });
        let (driver, full) = match mode {
            Mode::Answer(outcome) => (Some(driver(rx, Some(outcome))), None),
            Mode::Hold => (Some(driver(rx, None)), None),
            Mode::Gone => (None, None),
            Mode::Full => {
                tx.try_send(Msg::Stop {
                    inspect_by: std::time::Instant::now(),
                })
                .unwrap();
                (None, Some(rx))
            }
        };
        Rig {
            ctx,
            listener,
            tx: Some(tx),
            driver,
            _full: full,
            lines,
        }
    }

    /// A client connects and the connection is served in the background.
    pub(in crate::inbound) async fn connect(&self) -> (TcpStream, Served<()>) {
        let client = TcpStream::connect(self.listener.local_addr().unwrap())
            .await
            .unwrap();
        let (sock, peer) = self.listener.accept().await.unwrap();
        let local = sock.local_addr().unwrap();
        let task = tokio::spawn(serve(sock, peer, local, self.ctx.clone()));
        (client, task)
    }

    /// Waits for the connection to end and the driver to stop; checks that nothing is held any more.
    pub(in crate::inbound) async fn finish(mut self, served: Served<()>) -> Vec<Seen> {
        timeout(Duration::from_secs(30), served)
            .await
            .expect("the connection ended")
            .unwrap();
        self.ctx.ingress.close();
        drop(self.tx.take());
        let seen = self
            .driver
            .take()
            .map(|d| d.join().unwrap())
            .unwrap_or_default();
        assert_eq!(
            self.ctx.budget.available_permits(),
            self.ctx.cfg.max_buffered_bytes
        );
        assert_eq!(self.ctx.inspect.available_permits(), PERMITS);
        seen
    }
}

pub(in crate::inbound) async fn put(sock: &TcpStream, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        sock.writable().await.unwrap();
        match sock.try_write(bytes) {
            Ok(n) => bytes = &bytes[n..],
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => panic!("write failed: {e}"),
        }
    }
}

/// Ends the sending direction of a client.
pub(in crate::inbound) async fn finish_sending(sock: &mut TcpStream) {
    poll_fn(|cx| Pin::new(&mut *sock).poll_shutdown(cx))
        .await
        .unwrap();
}

/// Everything the server sends until it closes.
pub(in crate::inbound) async fn read_all(sock: &TcpStream) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    timeout(Duration::from_secs(30), async {
        loop {
            sock.readable().await.unwrap();
            match sock.try_read(&mut buf) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => break,
            }
        }
    })
    .await
    .expect("the server closed the connection");
    out
}

pub(in crate::inbound) struct Parsed {
    pub(in crate::inbound) status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Parsed {
    pub(in crate::inbound) fn all(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

pub(in crate::inbound) fn parse_response(raw: &[u8]) -> Parsed {
    let mut storage = [httparse::EMPTY_HEADER; 32];
    let mut response = httparse::Response::new(&mut storage);
    let httparse::Status::Complete(n) = response.parse(raw).expect("a response") else {
        panic!("an incomplete response: {:?}", String::from_utf8_lossy(raw));
    };
    Parsed {
        status: response.code.unwrap(),
        headers: response
            .headers
            .iter()
            .map(|h| {
                (
                    h.name.to_string(),
                    String::from_utf8_lossy(h.value).into_owned(),
                )
            })
            .collect(),
        body: raw[n..].to_vec(),
    }
}

/// One request, one connection, and what came back and what the driver saw.
async fn exchange(cfg: ProxyConfig, mode: Mode, request: &[u8]) -> (Vec<u8>, Vec<Seen>) {
    let rig = Rig::new(cfg, mode).await;
    let (client, task) = rig.connect().await;
    put(&client, request).await;
    let response = read_all(&client).await;
    // A client that has closed does not keep the connection in its last wait.
    drop(client);
    let seen = rig.finish(task).await;
    (response, seen)
}

/// Like `exchange`, but the connection is run as `serve` runs it, and the reply that its record line is made
/// of comes back as well.
async fn exchange_with_reply(
    cfg: ProxyConfig,
    mode: Mode,
    request: &[u8],
) -> (Vec<u8>, Vec<Seen>, Reply) {
    let rig = Rig::new(cfg, mode).await;
    let client = TcpStream::connect(rig.listener.local_addr().unwrap())
        .await
        .unwrap();
    let (sock, peer) = rig.listener.accept().await.unwrap();
    let local = sock.local_addr().unwrap();
    let ctx = rig.ctx.clone();
    let (sent, reply) = oneshot::channel();
    let task = tokio::spawn(async move {
        let summary = run_session(sock, peer, local, &ctx, Instant::now()).await;
        let _ = sent.send(summary.last);
    });
    put(&client, request).await;
    let response = read_all(&client).await;
    drop(client);
    let seen = rig.finish(task).await;
    (response, seen, reply.await.unwrap())
}

pub(in crate::inbound) fn form_post(body_lines: &str) -> Vec<u8> {
    format!("POST /p?q=1 HTTP/1.1\r\nHost: example.test\r\nContent-Type: {FORM}\r\n{body_lines}")
        .into_bytes()
}

pub(in crate::inbound) const BLOCK: Outcome = Outcome::Verdict(Verdict::Block {
    phase: 2,
    rule_id: 9202,
    status: 403,
});

#[test]
fn a_blocked_request_is_answered_with_the_status_of_the_rule() {
    run(async {
        let (raw, seen) = exchange(
            config(),
            Mode::Answer(BLOCK),
            b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n",
        )
        .await;
        let response = parse_response(&raw);
        assert_eq!(response.status, 403);
        assert_eq!(response.all("content-length"), ["0"]);
        assert_eq!(response.all("connection"), ["close"]);
        assert!(response.body.is_empty());
        assert_eq!(seen.len(), 1);
        assert_eq!(
            (seen[0].method.as_str(), seen[0].uri.as_str()),
            ("GET", "/a")
        );
        assert_eq!(seen[0].headers, [pair("Host", "h")]);
    });
}

/// The address that the inspection is told is the client's, for a request from the loopback address with
/// the given `X-Forwarded-For` lines, when `trusted` are the networks of `trusted_proxies`.
async fn told_client(trusted: &[&str], lines: &[&str]) -> SocketAddr {
    let cfg = ProxyConfig {
        trusted_proxies: trusted
            .iter()
            .map(|net| crate::forward::client_ip::Cidr::parse(net).unwrap())
            .collect(),
        ..config()
    };
    let mut request = String::from("GET /a HTTP/1.1\r\nHost: h\r\n");
    for line in lines {
        request.push_str(&format!("X-Forwarded-For: {line}\r\n"));
    }
    request.push_str("\r\n");
    let (_, seen) = exchange(cfg, Mode::Answer(BLOCK), request.as_bytes()).await;
    assert_eq!(seen.len(), 1);
    seen[0].client
}

#[test]
fn the_inspection_is_told_the_client_that_a_trusted_peer_names_and_the_peer_otherwise() {
    run(async {
        let lines = ["203.0.113.1, 198.51.100.7", "127.0.0.9"];
        // A peer that is not trusted is the client: the lines are not read.
        for trusted in [&[][..], &["10.0.0.0/8"][..]] {
            let client = told_client(trusted, &lines).await;
            assert_eq!(client.ip(), "127.0.0.1".parse::<IpAddr>().unwrap());
            assert_ne!(client.port(), 0);
        }
        // A trusted peer: the first address from the right that is not trusted, and no port.
        let named = told_client(&["127.0.0.0/8"], &lines).await;
        assert_eq!(named, "198.51.100.7:0".parse().unwrap());
        // An entry that is not an address leaves the peer.
        let client = told_client(&["127.0.0.0/8"], &["198.51.100.7, nonsense"]).await;
        assert_eq!(client.ip(), "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_ne!(client.port(), 0);
    });
}

/// A request for `path` on a rig where the table has the route `/static/`: the status of the answer, and what the
/// driver saw. `used_up` takes every inspection permit first.
async fn routed(mode: Mode, used_up: bool, path: &str) -> (u16, Vec<Seen>) {
    let rig = Rig::new(config(), mode).await;
    let table = Routes::new(vec![Route::new(None, "/static/").unwrap()]).unwrap();
    rig.ctx.routes.replace(table);
    let permits = u32::try_from(PERMITS).unwrap();
    let held = used_up.then(|| {
        rig.ctx
            .inspect
            .clone()
            .try_acquire_many_owned(permits)
            .unwrap()
    });
    let (client, task) = rig.connect().await;
    put(
        &client,
        format!("GET {path} HTTP/1.1\r\nHost: h\r\n\r\n").as_bytes(),
    )
    .await;
    let status = parse_response(&read_all(&client).await).status;
    drop(held);
    (status, rig.finish(task).await)
}

#[test]
fn a_request_under_a_route_goes_on_to_the_upstream_when_the_inspection_cannot_take_it() {
    run(async {
        // Nothing listens at the address of the upstream, so a request that goes on ends in 502 here. Under a
        // route it takes no permit, no budget and no place in the way to the driver, so it makes no ticket and
        // goes on whether the driver is gone, the way to it is full or every permit is taken. A request that is
        // not under a route is refused with 503.
        for (mode, used_up) in [
            (Mode::Gone, false),
            (Mode::Full, false),
            (Mode::Answer(BLOCK), true),
        ] {
            let (status, seen) = routed(mode, used_up, "/static/a").await;
            assert_eq!(status, 502, "under the route");
            assert!(seen.is_empty());
            let (status, seen) = routed(mode, used_up, "/dynamic").await;
            assert_eq!(status, 503, "not under the route");
            assert!(seen.is_empty());
        }
    });
}

/// A forwarding configuration with one group at an address where nothing listens, which only a request for the
/// host `h.test` is routed to.
pub(in crate::inbound) fn routed_to_h_test() -> ForwardConfig {
    let mut forward = ForwardConfig::of(&["127.0.0.1:2".parse().unwrap()]);
    let rule = Rule::forward(Some("h.test"), None).unwrap();
    forward.routes = Table::new(vec![(rule, RouteConfig::plain(0))]).unwrap();
    forward.default = None;
    forward
}

#[test]
fn a_request_that_no_route_holds_for_is_answered_with_404_and_is_not_inspected() {
    run(async {
        // The inspection answers every ticket with a block. A request for the routed host (in any case, with
        // any port) is inspected and blocked; one for another host is answered with 404 and makes no ticket.
        for (host, status, inspected) in [
            ("h.test", 403, 1),
            ("H.TEST:8080", 403, 1),
            ("other.test", 404, 0),
        ] {
            let rig = Rig::with(config(), Mode::Answer(BLOCK), &routed_to_h_test()).await;
            let (client, task) = rig.connect().await;
            let request = format!(
                "POST /a HTTP/1.1\r\nHost: {host}\r\nContent-Type: {FORM}\r\nContent-Length: 3\r\n\r\na=b"
            );
            put(&client, request.as_bytes()).await;
            let response = parse_response(&read_all(&client).await);
            drop(client);
            let seen = rig.finish(task).await;
            assert_eq!((response.status, seen.len()), (status, inspected), "{host}");
        }
    });
}

/// Names and values of the fields `form_post` makes, with the `Content-Length` of a 3 byte body.
fn form_post_field_bytes() -> usize {
    (4 + 12) + (12 + FORM.len()) + (14 + 1)
}

#[test]
fn the_byte_budget_covers_the_body_and_the_kernels_copy_of_it() {
    run(async {
        let request = form_post("Content-Length: 3\r\n\r\na=b");
        let needed = 3 + (3 + form_post_field_bytes());
        let mut cfg = config();
        cfg.max_buffered_bytes = needed;
        let (raw, seen) = exchange(cfg, Mode::Answer(BLOCK), &request).await;
        assert_eq!(parse_response(&raw).status, 403);
        assert_eq!(seen[0].body, b"a=b");
        // One byte less: the body is held and the copy is not.
        let mut cfg = config();
        cfg.max_buffered_bytes = needed - 1;
        let (raw, seen) = exchange(cfg, Mode::Answer(BLOCK), &request).await;
        assert_eq!(parse_response(&raw).status, 503);
        assert!(seen.is_empty());
    });
}

#[test]
fn the_wire_limit_is_exact_and_hypers_reads_after_the_body_do_not_trip_it() {
    run(async {
        // One chunk of 1024 bytes with an extension as long as it takes to bring the bytes after the head
        // to `max_body_wire` (4096): 4 + 3059 + 2 + 1024 + 2 + 5.
        let wire = |padding: usize| {
            let mut request = form_post("Transfer-Encoding: chunked\r\n\r\n");
            request.extend_from_slice(format!("400;{}\r\n", "e".repeat(padding)).as_bytes());
            request.extend_from_slice("a".repeat(1024).as_bytes());
            request.extend_from_slice(b"\r\n0\r\n\r\n");
            request
        };
        let head_len = form_post("Transfer-Encoding: chunked\r\n\r\n").len();
        assert_eq!(wire(3059).len() - head_len, 4096);
        for pause in [false, true] {
            for (padding, status) in [(3059, 403), (3060, 413)] {
                let rig = Rig::new(config(), Mode::Answer(BLOCK)).await;
                let (client, served) = rig.connect().await;
                let request = wire(padding);
                if pause {
                    // The head is served first and the rest of the bytes come afterwards.
                    put(&client, &request[..head_len]).await;
                    sleep(Duration::from_millis(100)).await;
                    put(&client, &request[head_len..]).await;
                } else {
                    put(&client, &request).await;
                }
                let response = parse_response(&read_all(&client).await);
                assert_eq!(response.status, status, "padding {padding}, pause {pause}");
                let seen = rig.finish(served).await;
                assert_eq!(seen.len(), usize::from(status == 403));
            }
        }
    });
}

#[test]
fn a_chunked_form_body_is_decoded_and_inspected_with_its_length() {
    run(async {
        let request =
            form_post("Transfer-Encoding: chunked\r\n\r\n3;ext=1\r\na=b\r\n2\r\n&c\r\n0\r\n\r\n");
        let (raw, seen) = exchange(config(), Mode::Answer(BLOCK), &request).await;
        assert_eq!(parse_response(&raw).status, 403);
        assert_eq!(seen[0].body, b"a=b&c");
        assert_eq!(
            seen[0].headers,
            [
                pair("Host", "example.test"),
                pair("Content-Type", FORM),
                pair("Content-Length", "5")
            ]
        );
    });
}

#[test]
fn a_chunked_body_of_another_type_is_415_but_an_empty_one_is_not() {
    run(async {
        let request = b"POST / HTTP/1.1\r\nHost: h\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n";
        let (raw, seen) = exchange(config(), Mode::Answer(BLOCK), request).await;
        assert_eq!(parse_response(&raw).status, 415);
        assert!(seen.is_empty());
        let request = b"POST / HTTP/1.1\r\nHost: h\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        let (raw, seen) = exchange(config(), Mode::Answer(BLOCK), request).await;
        assert_eq!(parse_response(&raw).status, 403);
        assert_eq!(seen.len(), 1);
    });
}

#[test]
fn a_trailer_or_a_broken_chunk_is_400_and_nothing_is_inspected() {
    run(async {
        let trailer = form_post("Transfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\nX-T: 1\r\n\r\n");
        let broken = form_post("Transfer-Encoding: chunked\r\n\r\nzz\r\na\r\n0\r\n\r\n");
        for request in [trailer, broken] {
            let (raw, seen) = exchange(config(), Mode::Answer(BLOCK), &request).await;
            let response = parse_response(&raw);
            assert_eq!(response.status, 400);
            assert_eq!(response.all("content-length"), ["0"]);
            assert!(seen.is_empty());
        }
    });
}

#[test]
fn a_decoded_body_over_the_limit_is_413_and_one_at_the_limit_is_inspected() {
    run(async {
        let chunk = |len: usize| format!("{len:x}\r\n{}\r\n0\r\n\r\n", "a".repeat(len));
        let at = form_post(&format!(
            "Transfer-Encoding: chunked\r\n\r\n{}",
            chunk(1024)
        ));
        let (_, seen) = exchange(config(), Mode::Answer(BLOCK), &at).await;
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].body.len(), 1024);
        let over = form_post(&format!(
            "Transfer-Encoding: chunked\r\n\r\n{}",
            chunk(1025)
        ));
        let (raw, seen) = exchange(config(), Mode::Answer(BLOCK), &over).await;
        assert_eq!(parse_response(&raw).status, 413);
        assert!(seen.is_empty());
        // Two chunks that are each within the limit and together over it.
        let two = form_post("Transfer-Encoding: chunked\r\n\r\n400\r\n");
        let mut two = two;
        two.extend_from_slice("a".repeat(1024).as_bytes());
        two.extend_from_slice(b"\r\n1\r\nb\r\n0\r\n\r\n");
        let (raw, seen) = exchange(config(), Mode::Answer(BLOCK), &two).await;
        assert_eq!(parse_response(&raw).status, 413);
        assert!(seen.is_empty());
    });
}

#[test]
fn a_length_over_the_limit_is_refused_with_the_fixed_answer_before_any_body() {
    run(async {
        let (raw, seen) = exchange(
            config(),
            Mode::Answer(BLOCK),
            &form_post("Content-Length: 1025\r\n\r\n"),
        )
        .await;
        assert_eq!(raw, Reject::ContentTooLarge.response().unwrap());
        assert!(seen.is_empty());
    });
}

#[test]
fn a_refusal_reaches_a_client_that_is_still_sending() {
    run(async {
        let rig = Rig::new(config(), Mode::Answer(BLOCK)).await;
        let (client, task) = rig.connect().await;
        let mut request = form_post("Content-Length: 2000000\r\n\r\n");
        request.extend_from_slice(&vec![b'a'; 200_000]);
        put(&client, &request).await;
        let raw = read_all(&client).await;
        assert_eq!(raw, Reject::ContentTooLarge.response().unwrap());
        assert!(rig.finish(task).await.is_empty());
    });
}

#[test]
fn a_peer_that_goes_away_during_the_body_gets_no_answer_and_leaves_nothing_held() {
    run(async {
        let rig = Rig::new(config(), Mode::Answer(BLOCK)).await;
        let (mut client, task) = rig.connect().await;
        put(&client, &form_post("Content-Length: 10\r\n\r\nabc")).await;
        sleep(Duration::from_millis(100)).await;
        finish_sending(&mut client).await;
        assert!(read_all(&client).await.is_empty());
        assert!(rig.finish(task).await.is_empty());
    });
}

#[test]
fn an_inspection_that_does_not_answer_is_503_and_the_ticket_is_abandoned() {
    run(async {
        let mut cfg = config();
        cfg.inspect_wait = Duration::from_millis(200);
        let rig = Rig::new(cfg, Mode::Hold).await;
        let (client, task) = rig.connect().await;
        put(&client, b"GET / HTTP/1.1\r\nHost: h\r\n\r\n").await;
        let start = std::time::Instant::now();
        let response = parse_response(&read_all(&client).await);
        assert_eq!(response.status, 503);
        assert!(start.elapsed() >= Duration::from_millis(190));
        let seen = rig.finish(task).await;
        assert_eq!(seen.len(), 1);
        assert!(seen[0].abandoned);
    });
}

#[test]
fn a_driver_that_is_gone_or_a_way_to_it_that_is_full_gives_503() {
    run(async {
        for mode in [Mode::Gone, Mode::Full] {
            let (raw, seen) = exchange(config(), mode, b"GET / HTTP/1.1\r\nHost: h\r\n\r\n").await;
            let response = parse_response(&raw);
            assert_eq!(response.status, 503);
            assert_eq!(response.all("content-length"), ["0"]);
            assert!(seen.is_empty());
        }
    });
}

/// A POST of the given type with the gzip coding whose body is `coded`, with its length.
fn gzip_post(content_type: &str, coded: &[u8]) -> Vec<u8> {
    let mut request = format!(
        "POST /p?q=1 HTTP/1.1\r\nHost: example.test\r\nContent-Type: {content_type}\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
        coded.len()
    )
    .into_bytes();
    request.extend_from_slice(coded);
    request
}

/// The same request chunked: `coded` is cut in two chunks.
fn gzip_chunked_post(content_type: &str, coded: &[u8]) -> Vec<u8> {
    let mut request = format!(
        "POST /p?q=1 HTTP/1.1\r\nHost: example.test\r\nContent-Type: {content_type}\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n"
    )
    .into_bytes();
    let (first, second) = coded.split_at(coded.len() / 2);
    for chunk in [first, second] {
        if !chunk.is_empty() {
            request.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            request.extend_from_slice(chunk);
            request.extend_from_slice(b"\r\n");
        }
    }
    request.extend_from_slice(b"0\r\n\r\n");
    request
}

#[test]
fn a_gzip_body_is_decoded_before_the_inspection() {
    run(async {
        let coded = gz(b"probe=block");
        for request in [gzip_post(FORM, &coded), gzip_chunked_post(FORM, &coded)] {
            let (raw, seen) = exchange(config(), Mode::Answer(BLOCK), &request).await;
            assert_eq!(parse_response(&raw).status, 403);
            assert_eq!(seen.len(), 1);
            assert_eq!(seen[0].body, b"probe=block");
            assert_eq!(
                seen[0].headers,
                [
                    pair("Host", "example.test"),
                    pair("Content-Type", FORM),
                    pair("Content-Length", "11")
                ]
            );
        }
    });
}

#[test]
fn a_decoded_gzip_body_over_the_limit_is_413_and_one_at_the_limit_is_inspected() {
    run(async {
        // `max_body` is 1024 here.
        let at = gz(&vec![b'a'; 1024]);
        let over = gz(&vec![b'a'; 1025]);
        let bomb = gz(&vec![0u8; 100_000]);
        assert!(over.len() < 1024 && bomb.len() < 1024);
        let (raw, seen) = exchange(config(), Mode::Answer(BLOCK), &gzip_post(FORM, &at)).await;
        assert_eq!(parse_response(&raw).status, 403);
        assert_eq!(seen[0].body.len(), 1024);
        for coded in [&over, &bomb] {
            let (raw, seen, reply) =
                exchange_with_reply(config(), Mode::Answer(BLOCK), &gzip_post(FORM, coded)).await;
            assert_eq!(parse_response(&raw).status, 413);
            assert!(seen.is_empty());
            assert_eq!(reply, Reply::rejected(413, "decoded body over the limit"));
        }
    });
}

#[test]
fn a_gzip_body_that_cannot_be_decoded_is_400_and_nothing_is_inspected() {
    run(async {
        let good = gz(b"probe=block");
        let mut flipped = good.clone();
        let last = flipped.len() - 8;
        flipped[last] ^= 0x01;
        let mut after = good.clone();
        after.push(0);
        let malformed = "malformed gzip body";
        let cases = [
            // The CRC of the trailer, cut after the header, not gzip at all.
            (flipped, malformed),
            // A byte after the member.
            (after, "data after the gzip member"),
        ];
        for (coded, reason) in &cases {
            for request in [gzip_post(FORM, coded), gzip_chunked_post(FORM, coded)] {
                let (raw, seen, reply) =
                    exchange_with_reply(config(), Mode::Answer(BLOCK), &request).await;
                assert_eq!(parse_response(&raw).status, 400, "{reason}: {coded:?}");
                assert!(seen.is_empty(), "{reason}: {coded:?}");
                assert_eq!(reply, Reply::rejected(400, reason), "{coded:?}");
            }
        }
    });
}

#[test]
fn an_empty_gzip_body_is_400_whatever_its_framing() {
    run(async {
        // A length of 0 is decided by the head check: the fixed answer.
        let (raw, seen) = exchange(
            config(),
            Mode::Answer(BLOCK),
            &form_post("Content-Encoding: gzip\r\nContent-Length: 0\r\n\r\n"),
        )
        .await;
        assert_eq!(raw, Reject::BadRequest.response().unwrap());
        assert!(seen.is_empty());
        // A chunked body is empty only once it has been read.
        let (raw, seen, reply) = exchange_with_reply(
            config(),
            Mode::Answer(BLOCK),
            &form_post("Content-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"),
        )
        .await;
        assert_eq!(parse_response(&raw).status, 400);
        assert!(seen.is_empty());
        assert_eq!(reply, Reply::rejected(400, "empty gzip body"));
    });
}

use crate::forward::client_ip::{Access, Cidr};

/// A forwarding configuration whose one route holds for every request and has these access lists.
pub(in crate::inbound) fn guarded(deny: &[&str], allow: &[&str]) -> ForwardConfig {
    let nets = |list: &[&str]| list.iter().map(|net| Cidr::parse(net).unwrap()).collect();
    let route = RouteConfig {
        access: Access::new(nets(deny), nets(allow)),
        ..RouteConfig::plain(0)
    };
    let mut forward = ForwardConfig::of(&["127.0.0.1:2".parse().unwrap()]);
    forward.routes = Table::new(vec![(Rule::forward(None, None).unwrap(), route)]).unwrap();
    forward.default = None;
    forward
}

/// A POST from the loopback address to the route of `guarded(deny, allow)`, when `trusted` are the networks of
/// `trusted_proxies` and the request has the extra fields `extra`: the status of the answer, and the number of
/// tickets the driver got. The driver blocks every ticket with 403, so a request that is inspected is told from
/// one that is turned away by its ticket.
async fn guarded_post(
    deny: &[&str],
    allow: &[&str],
    trusted: &[&str],
    extra: &str,
) -> (u16, usize) {
    let cfg = ProxyConfig {
        trusted_proxies: trusted
            .iter()
            .map(|net| Cidr::parse(net).unwrap())
            .collect(),
        ..config()
    };
    let rig = Rig::with(cfg, Mode::Answer(BLOCK), &guarded(deny, allow)).await;
    let (client, task) = rig.connect().await;
    let request = form_post(&format!("{extra}Content-Length: 3\r\n\r\na=b"));
    put(&client, &request).await;
    let response = parse_response(&read_all(&client).await);
    drop(client);
    let seen = rig.finish(task).await;
    (response.status, seen.len())
}

#[test]
fn a_client_that_the_route_turns_away_gets_403_before_the_body_is_read_and_is_not_inspected() {
    run(async {
        assert_eq!(guarded_post(&["127.0.0.0/8"], &[], &[], "").await, (403, 0));
        assert_eq!(guarded_post(&[], &["10.0.0.0/8"], &[], "").await, (403, 0));
        // A client that is not turned away is inspected, and the driver blocks it (403 as well, with a ticket).
        assert_eq!(guarded_post(&["10.0.0.0/8"], &[], &[], "").await, (403, 1));
        assert_eq!(guarded_post(&[], &["127.0.0.0/8"], &[], "").await, (403, 1));
        // The address that a trusted peer names decides; one that a peer that is not trusted names does not.
        let named = "X-Forwarded-For: 10.1.2.3\r\n";
        let trusted = ["127.0.0.0/8"];
        assert_eq!(
            guarded_post(&["10.0.0.0/8"], &[], &trusted, named).await,
            (403, 0)
        );
        assert_eq!(
            guarded_post(&[], &["10.0.0.0/8"], &trusted, named).await,
            (403, 1)
        );
        assert_eq!(
            guarded_post(&["10.0.0.0/8"], &[], &[], named).await,
            (403, 1)
        );
    });
}

/// A forwarding configuration with a default route and these routes, each `(host, path, allow)` with the networks of
/// `allow` as its only access list.
fn with_access(routes: &[(Option<&str>, Option<&str>, &[&str])]) -> ForwardConfig {
    let entries = routes
        .iter()
        .map(|&(host, path, allow)| {
            let allow = allow.iter().map(|net| Cidr::parse(net).unwrap()).collect();
            let route = RouteConfig {
                access: Access::new(Vec::new(), allow),
                ..RouteConfig::plain(0)
            };
            (Rule::forward(host, path).unwrap(), route)
        })
        .collect();
    let mut forward = ForwardConfig::of(&["127.0.0.1:2".parse().unwrap()]);
    forward.routes = Table::new(entries).unwrap();
    forward
}

/// A GET from the loopback address with this `Host` for this target: the status of the answer, and the number of
/// tickets the driver got. The driver blocks every ticket with 403, so a request that is inspected is told from one
/// that is turned away by its ticket.
async fn spelled(forward: &ForwardConfig, host: &str, target: &str) -> (u16, usize) {
    let rig = Rig::with(config(), Mode::Answer(BLOCK), forward).await;
    let (client, task) = rig.connect().await;
    let request = format!("GET {target} HTTP/1.1\r\nHost: {host}\r\n\r\n");
    put(&client, request.as_bytes()).await;
    let status = parse_response(&read_all(&client).await).status;
    drop(client);
    (status, rig.finish(task).await.len())
}

/// The status and the number of tickets of a GET for each target, in order.
async fn spelled_all(forward: &ForwardConfig, host: &str, targets: &[&str]) -> Vec<(u16, usize)> {
    let mut got = Vec::new();
    for target in targets {
        got.push(spelled(forward, host, target).await);
    }
    got
}

#[test]
fn a_request_has_to_pass_the_access_of_every_route_its_path_could_be_taken_for() {
    run(async {
        // The loopback client is outside the only network the route for `/private/` allows.
        let forward = with_access(&[
            (None, Some("/private/"), &["10.0.0.0/8"]),
            (None, Some("/public/"), &[]),
        ]);
        // Other ways to write the path of the route, the path just before it (an application may answer for
        // `/private` with what it has for `/private/`), and paths that cannot be told apart from any path.
        for target in [
            "/private/x",
            "/priv%61te/x",
            "/private/./x",
            "//private/x",
            "/private/%2e%2e/private/x",
            "/private",
            "/private?a=1",
            "/priv%61te",
            "/x/%2%65",
        ] {
            let got = spelled(&forward, "app.test", target).await;
            assert_eq!(got, (403, 0), "{target}");
        }
        // The paths of the other route, and the escapes that clients send (`%40`, `%20`, a Japanese letter), pass
        // the lists of their own route only: they are inspected. So is a path that the lists do not hold for in
        // another case of letters, which is another path.
        for target in [
            "/public/x",
            "/public/a%20b",
            "/public/%E3%81%82",
            "/public/%e3%81%82",
            "/api/users/a%40b.com",
            "/%E3%81%82/%20",
            "/other",
            "/PRIV%61TE/x",
        ] {
            let got = spelled(&forward, "app.test", target).await;
            assert_eq!(got, (403, 1), "{target}");
        }
    });
}

#[test]
fn a_client_inside_the_allow_list_is_not_turned_away_however_the_path_is_written() {
    run(async {
        let forward = with_access(&[
            (None, Some("/private/"), &["127.0.0.0/8"]),
            (None, Some("/public/"), &[]),
        ]);
        let targets = [
            "/private/x",
            "/priv%61te/x",
            "/private/./x",
            "//private/x",
            "/private",
            "/private?a=1",
            "/public/x",
            "/other",
        ];
        let got = spelled_all(&forward, "app.test", &targets).await;
        assert_eq!(got, vec![(403, 1); targets.len()]);
    });
}

#[test]
fn a_path_is_judged_by_the_most_exact_route_of_each_way_it_is_written() {
    run(async {
        // The route for `/` has an allow list that the loopback client is outside of, and the route for `/public/`
        // has none: `/public/x` is the business of the second only, and `/public` and every spelling of a path
        // that leaves `/public/` is the business of the first.
        let forward = with_access(&[
            (None, Some("/"), &["10.0.0.0/8"]),
            (None, Some("/public/"), &[]),
        ]);
        let got = spelled_all(&forward, "app.test", &["/public/x", "/public/%E3%81%82"]).await;
        assert_eq!(got, [(403, 1), (403, 1)]);
        let targets = ["/public", "/other", "/pub%6Cic/x", "/public/../x"];
        let got = spelled_all(&forward, "app.test", &targets).await;
        assert_eq!(got, vec![(403, 0); targets.len()]);
    });
}

#[test]
fn a_byte_that_a_route_path_writes_as_an_escape_meets_the_route_however_the_request_writes_it() {
    run(async {
        // A request may hold `[` as it is, and the path of a route can only hold its escape. The loopback client is
        // outside the only network the route allows.
        let targets = ["/a%5Bb/x", "/a[b/x", "/a%5bb/x"];
        let forward = with_access(&[(None, Some("/a%5Bb/"), &["10.0.0.0/8"])]);
        let got = spelled_all(&forward, "app.test", &targets).await;
        assert_eq!(got, vec![(403, 0); targets.len()]);
        // The same client inside the network is inspected, however the byte is written.
        let forward = with_access(&[(None, Some("/a%5Bb/"), &["127.0.0.0/8"])]);
        let got = spelled_all(&forward, "app.test", &targets).await;
        assert_eq!(got, vec![(403, 1); targets.len()]);
    });
}

#[test]
fn a_route_for_a_path_itself_is_not_judged_by_the_route_of_the_path_with_a_slash_after_it() {
    run(async {
        // The loopback client is outside the network that the route for `/` allows. The route for `/health` has no
        // list, so the path itself is open, and the paths next to it are the business of the route for `/`.
        let forward = with_access(&[
            (None, Some("/"), &["10.0.0.0/8"]),
            (None, Some("/health"), &[]),
        ]);
        for target in ["/health", "/health?a=1"] {
            let got = spelled(&forward, "app.test", target).await;
            assert_eq!(got, (403, 1), "{target}");
        }
        for target in ["/health/", "/health/x", "/healthz", "/he%61lth"] {
            let got = spelled(&forward, "app.test", target).await;
            assert_eq!(got, (403, 0), "{target}");
        }
        // The path just before a prefix is still judged by the route of the prefix when the route that the path goes
        // to as received is not for that path itself.
        let forward = with_access(&[
            (None, Some("/private/"), &["10.0.0.0/8"]),
            (None, Some("/health"), &[]),
        ]);
        assert_eq!(spelled(&forward, "app.test", "/private").await, (403, 0));
        assert_eq!(spelled(&forward, "app.test", "/health").await, (403, 1));
    });
}

#[test]
fn only_the_routes_the_host_could_mean_count_and_a_host_that_cannot_be_read_could_mean_any() {
    run(async {
        let forward = with_access(&[
            (Some("secure.test"), Some("/private/"), &["10.0.0.0/8"]),
            (Some("open.test"), None, &[]),
        ]);
        // A request for a host whose routes have no access list is not turned away, however its target is written.
        for target in ["//x", "/priv%61te/x", "/private/x"] {
            let got = spelled(&forward, "open.test", target).await;
            assert_eq!(got, (403, 1), "{target}");
        }
        for target in ["//x", "/private/x", "/priv%61te/x", "/private"] {
            let got = spelled(&forward, "secure.test", target).await;
            assert_eq!(got, (403, 0), "{target}");
        }
        // A `Host` with an empty label cannot be read: any route could be meant, whatever the path.
        for target in ["//x", "/private/x", "/x"] {
            let got = spelled(&forward, "open..test", target).await;
            assert_eq!(got, (403, 0), "{target}");
        }
    });
}

#[test]
fn a_request_is_not_judged_by_the_other_routes_when_no_route_has_an_access_list() {
    run(async {
        // The routes have lists that turn nobody away, so the loopback client is inspected whatever it writes.
        let forward = with_access(&[
            (None, Some("/private/"), &[]),
            (None, Some("/public/"), &[]),
        ]);
        let targets = ["/private/x", "//private/x", "/priv%61te/x", "/private"];
        let got = spelled_all(&forward, "app.test", &targets).await;
        assert_eq!(got, vec![(403, 1); targets.len()]);
        assert_eq!(spelled(&forward, "open..test", "/x").await, (403, 1));
    });
}
