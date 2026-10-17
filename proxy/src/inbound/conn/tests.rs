use std::io::Write;
use std::sync::mpsc::{Receiver, sync_channel};
use std::thread::{self, JoinHandle};

use flate2::write::GzEncoder;
use flate2::{Compression, GzBuilder};
use tokio::net::TcpListener;
use tokio::runtime::{Builder, Runtime};
use tokio::task::JoinHandle as Served;
use tokio::time::{sleep, timeout};
use tukuyomi_kernel::{Reason, Refused, Verdict};

use super::*;
use crate::inbound::represent::tests::{head_of, noise, numbered};
use crate::inspect::driver::Outcome;
use crate::log::start_logger;

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

/// One gzip member of `data` whose header carries a comment of `len` bytes.
fn gz_with_comment(data: &[u8], len: usize) -> Vec<u8> {
    let mut encoder = GzBuilder::new()
        .comment(vec![b'c'; len])
        .write(Vec::new(), Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn parts(request: Request<()>) -> http::request::Parts {
    request.into_parts().0
}

#[test]
fn hyper_and_the_head_check_must_see_the_same_request() {
    let head = head_of("POST /a?b=%41 HTTP/1.1\r\nHost: h\r\nX-A: 1\r\nx-a: 2 \r\nX-B:\tv\r\n\r\n");
    let base = || {
        Request::builder()
            .method("POST")
            .uri("/a?b=%41")
            .version(Version::HTTP_11)
            .header("host", "h")
            .header("x-a", "1")
            .header("x-a", "2")
            .header("x-b", "v")
    };
    assert!(same_head(&head, &parts(base().body(()).unwrap())));
    // A value with blanks around it is the same value; the trim is the same on both sides.
    assert!(same_head(
        &head,
        &parts(
            Request::builder()
                .method("POST")
                .uri("/a?b=%41")
                .header("host", " h")
                .header("x-a", "1")
                .header("x-a", " 2 \t")
                .header("x-b", "v")
                .body(())
                .unwrap()
        )
    ));
    let different = [
        base().method("PUT").body(()).unwrap(),
        base().method("post").body(()).unwrap(),
        base().uri("/a?b=%42").body(()).unwrap(),
        base().uri("/a").body(()).unwrap(),
        base().uri("http://h/a?b=%41").body(()).unwrap(),
        base().version(Version::HTTP_10).body(()).unwrap(),
        base().header("x-c", "3").body(()).unwrap(),
        Request::builder()
            .method("POST")
            .uri("/a?b=%41")
            .header("host", "h")
            .header("x-a", "1")
            .header("x-a", "2")
            .body(())
            .unwrap(),
        // The same fields with the values of one name swapped, or changed.
        Request::builder()
            .method("POST")
            .uri("/a?b=%41")
            .header("host", "h")
            .header("x-a", "2")
            .header("x-a", "1")
            .header("x-b", "v")
            .body(())
            .unwrap(),
        Request::builder()
            .method("POST")
            .uri("/a?b=%41")
            .header("host", "h")
            .header("x-a", "1")
            .header("x-a", "2")
            .header("x-b", "w")
            .body(())
            .unwrap(),
        // One field counted twice and another missing: the count is right and the names are not.
        Request::builder()
            .method("POST")
            .uri("/a?b=%41")
            .header("host", "h")
            .header("x-a", "1")
            .header("x-a", "2")
            .header("x-c", "v")
            .body(())
            .unwrap(),
    ];
    for (n, request) in different.into_iter().enumerate() {
        assert!(!same_head(&head, &parts(request)), "case {n}");
    }
}

#[test]
fn what_the_record_says_when_the_connection_has_ended() {
    let sent = Reply {
        status: 200,
        class: Class::Forwarded,
        reason: "forwarded",
        rule: None,
        internal: false,
    };
    assert_eq!(ended(sent, End::Done), sent);
    assert_eq!(
        ended(sent, End::Error).reason,
        "closed while the response was sent"
    );
    assert_eq!(
        ended(sent, End::Limit).reason,
        "closed while the response was sent"
    );
    assert_eq!(ended(sent, End::Limit).status, 200);
    assert_eq!(ended(Reply::NONE, End::Done), Reply::NONE);
    assert_eq!(ended(Reply::NONE, End::Error).reason, "connection error");
    assert_eq!(
        ended(Reply::NONE, End::Limit).reason,
        "connection time limit"
    );
    let refused = Reply::rejected(400, "malformed body");
    assert_eq!(ended(refused, End::Error), refused);
    assert_eq!(ended(refused, End::Limit), refused);
}

#[test]
fn a_stage_ends_at_the_earlier_of_its_own_end_and_the_request_time() {
    let start = Instant::now();
    let times = Times {
        accept: start,
        request_by: start + Duration::from_secs(10),
        conn_by: start + Duration::from_secs(20),
    };
    assert_eq!(
        stage(start, Duration::from_secs(3), &times),
        start + Duration::from_secs(3)
    );
    assert_eq!(
        stage(start, Duration::from_secs(10), &times),
        start + Duration::from_secs(10)
    );
    assert_eq!(
        stage(start, Duration::from_secs(11), &times),
        start + Duration::from_secs(10)
    );
    // A stage that starts late still ends with the request time.
    let late = start + Duration::from_secs(8);
    assert_eq!(
        stage(late, Duration::from_secs(5), &times),
        start + Duration::from_secs(10)
    );
    // A sum that does not fit into the clock has passed.
    assert_eq!(after(start, Duration::MAX), start);
    assert_eq!(stage(start, Duration::MAX, &times), start);
}

// ---- the connection, over real sockets, with a driver that is a thread in this test ----

fn config() -> ProxyConfig {
    let secs = Duration::from_secs;
    ProxyConfig {
        listen: "127.0.0.1:1".parse().unwrap(),
        upstream: "127.0.0.1:2".parse().unwrap(),
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
    }
}

/// What the driver of a test does with a ticket.
#[derive(Clone, Copy)]
enum Mode {
    /// Answers every ticket with this.
    Answer(Outcome),
    /// Keeps every ticket and never answers.
    Hold,
    /// The driver is gone: the way to it is closed.
    Gone,
    /// The way to the driver is full.
    Full,
    /// Takes every ticket and drops it without an answer.
    Drop,
}

#[derive(Debug)]
struct Seen {
    client: SocketAddr,
    server: SocketAddr,
    method: String,
    uri: String,
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
                client: req.client,
                server: req.server,
                method: String::from_utf8_lossy(&req.method).into_owned(),
                uri: String::from_utf8_lossy(&req.uri).into_owned(),
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

/// A driver that receives every ticket and drops it.
fn dropper(rx: Receiver<Msg>) -> JoinHandle<Vec<Seen>> {
    thread::spawn(move || {
        while let Ok(msg) = rx.recv() {
            drop(msg);
        }
        Vec::new()
    })
}

struct Rig {
    ctx: Arc<Ctx>,
    listener: TcpListener,
    tx: Option<SyncSender<Msg>>,
    driver: Option<JoinHandle<Vec<Seen>>>,
    /// The receiving end of a way that is full, kept so that it stays open.
    _full: Option<Receiver<Msg>>,
}

fn runtime() -> Runtime {
    Builder::new_current_thread().enable_all().build().unwrap()
}

/// Runs a test body; a body that hangs fails the test instead of the run.
fn run<F: std::future::Future>(body: F) -> F::Output {
    runtime().block_on(async {
        timeout(Duration::from_secs(60), body)
            .await
            .expect("the test hung")
    })
}

impl Rig {
    async fn new(cfg: ProxyConfig, mode: Mode) -> Rig {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let budget = Arc::new(Semaphore::new(cfg.max_buffered_bytes));
        let ctx = Arc::new(Ctx {
            cfg,
            budget,
            inspect: Arc::new(Semaphore::new(PERMITS)),
            log: start_logger().unwrap(),
        });
        let (tx, rx) = sync_channel(if matches!(mode, Mode::Full) {
            1
        } else {
            PERMITS + 1
        });
        let (driver, full) = match mode {
            Mode::Answer(outcome) => (Some(driver(rx, Some(outcome))), None),
            Mode::Hold => (Some(driver(rx, None)), None),
            Mode::Drop => (Some(dropper(rx)), None),
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
        }
    }

    /// A client connects and the connection is served in the background.
    async fn connect(&self) -> (TcpStream, Served<()>) {
        let client = TcpStream::connect(self.listener.local_addr().unwrap())
            .await
            .unwrap();
        let (sock, peer) = self.listener.accept().await.unwrap();
        let local = sock.local_addr().unwrap();
        let task = tokio::spawn(serve(
            sock,
            peer,
            local,
            self.ctx.clone(),
            self.tx.clone().unwrap(),
        ));
        (client, task)
    }

    /// Waits for the connection to end and the driver to stop; checks that nothing is held any more.
    async fn finish(mut self, served: Served<()>) -> Vec<Seen> {
        timeout(Duration::from_secs(30), served)
            .await
            .expect("the connection ended")
            .unwrap();
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

async fn put(sock: &TcpStream, mut bytes: &[u8]) {
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
async fn finish_sending(sock: &mut TcpStream) {
    poll_fn(|cx| Pin::new(&mut *sock).poll_shutdown(cx))
        .await
        .unwrap();
}

/// Everything the server sends until it closes.
async fn read_all(sock: &TcpStream) -> Vec<u8> {
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

struct Parsed {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Parsed {
    fn all(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

fn parse_response(raw: &[u8]) -> Parsed {
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
    let accept = Instant::now();
    let times = Times {
        accept,
        request_by: after(accept, rig.ctx.cfg.request_total),
        conn_by: after(accept, rig.ctx.cfg.conn_total),
    };
    let (ctx, ingress) = (rig.ctx.clone(), rig.tx.clone().unwrap());
    let (sent, reply) = oneshot::channel();
    let task = tokio::spawn(async move {
        let _ = sent.send(super::run(sock, peer, local, &ctx, ingress, times).await);
    });
    put(&client, request).await;
    let response = read_all(&client).await;
    let seen = rig.finish(task).await;
    (response, seen, reply.await.unwrap())
}

fn form_post(body_lines: &str) -> Vec<u8> {
    format!("POST /p?q=1 HTTP/1.1\r\nHost: example.test\r\nContent-Type: {FORM}\r\n{body_lines}")
        .into_bytes()
}

const BLOCK: Outcome = Outcome::Verdict(Verdict::Block {
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

#[test]
fn a_block_with_204_or_304_has_no_content_length() {
    run(async {
        for status in [204u16, 304] {
            let outcome = Outcome::Verdict(Verdict::Block {
                phase: 1,
                rule_id: 1,
                status,
            });
            let (raw, _) = exchange(
                config(),
                Mode::Answer(outcome),
                b"GET / HTTP/1.1\r\nHost: h\r\n\r\n",
            )
            .await;
            let response = parse_response(&raw);
            assert_eq!(response.status, status);
            assert!(response.all("content-length").is_empty(), "{status}");
            assert_eq!(response.all("connection"), ["close"]);
            assert!(response.body.is_empty());
        }
    });
}

#[test]
fn the_other_outcomes_are_answered_as_the_table_says() {
    run(async {
        let cases = [
            (
                Outcome::Verdict(Verdict::Block {
                    phase: 1,
                    rule_id: 5,
                    status: 700,
                }),
                500,
            ),
            (
                Outcome::Verdict(Verdict::Block {
                    phase: 1,
                    rule_id: 5,
                    status: 0,
                }),
                500,
            ),
            (
                Outcome::Verdict(Verdict::Uninspectable(Reason::InspectorLost)),
                503,
            ),
            (
                Outcome::Verdict(Verdict::Uninspectable(Reason::Invalid)),
                500,
            ),
            (Outcome::Refused(Refused::Unsupported("content-type")), 500),
            (Outcome::Refused(Refused::Full), 503),
            (Outcome::Unavailable, 503),
        ];
        for (outcome, status) in cases {
            let (raw, seen) = exchange(
                config(),
                Mode::Answer(outcome),
                b"GET / HTTP/1.1\r\nHost: h\r\n\r\n",
            )
            .await;
            let response = parse_response(&raw);
            assert_eq!(response.status, status, "{outcome:?}");
            assert_eq!(response.all("content-length"), ["0"], "{outcome:?}");
            assert_eq!(response.all("connection"), ["close"], "{outcome:?}");
            assert_eq!(seen.len(), 1);
        }
    });
}

/// A GET head whose names and values add up to exactly 24 KiB.
fn total_24_kib() -> String {
    let mut raw = String::from("GET / HTTP/1.1\r\nHost: example.test\r\n");
    for n in 1..=5 {
        raw.push_str(&format!("F00{n}: {}\r\n", "a".repeat(4096)));
    }
    raw.push_str(&format!("F006: {}\r\n\r\n", "a".repeat(4056)));
    raw
}

#[test]
fn heads_at_every_limit_are_served_by_hyper_as_well() {
    run(async {
        let target = format!("GET /{} HTTP/1.1\r\nHost: h\r\n\r\n", "a".repeat(4095));
        let name = format!(
            "GET / HTTP/1.1\r\nHost: h\r\n{}: {}\r\n\r\n",
            "N".repeat(256),
            "v".repeat(4096)
        );
        let exact = {
            let fixed = "GET / HTTP/1.1\r\nHost: a\r\nX-Pad: \r\n\r\n".len();
            format!(
                "GET / HTTP/1.1\r\nHost: a\r\nX-Pad: {}\r\n\r\n",
                "p".repeat(1024 - fixed)
            )
        };
        assert_eq!(exact.len(), 1024);
        let cases = [
            (numbered(64, "GET"), 8192),
            (target, 8192),
            (name, 8192),
            (total_24_kib(), 32 * 1024),
            (exact, 1024),
        ];
        for (n, (request, max_head_bytes)) in cases.into_iter().enumerate() {
            let mut cfg = config();
            cfg.max_head_bytes = max_head_bytes;
            let (raw, seen) = exchange(cfg, Mode::Answer(BLOCK), request.as_bytes()).await;
            assert_eq!(parse_response(&raw).status, 403, "case {n}");
            assert_eq!(seen.len(), 1, "case {n}");
        }
    });
}

#[test]
fn a_request_target_that_hyper_does_not_accept_is_a_400_and_nothing_is_inspected() {
    run(async {
        // The head check refuses these bytes itself: the answer is its fixed one (hyper's own 400 would carry a
        // `Date`), the record says why, and hyper never sees the request.
        for target in ["/a<b", "/a>b", "/a`b", "/?q=\"x\"", "/?q=<x>", "/?q=>"] {
            let request = format!("GET {target} HTTP/1.1\r\nHost: h\r\n\r\n");
            let (raw, seen, reply) =
                exchange_with_reply(config(), Mode::Answer(BLOCK), request.as_bytes()).await;
            assert_eq!(raw, Reject::BadRequest.response().unwrap(), "{target}");
            assert!(seen.is_empty(), "{target}");
            assert_eq!(reply, Reply::of(Reject::BadRequest), "{target}");
            assert_eq!(
                record(1, &reply, Duration::ZERO),
                "conn 1: rejected 400 malformed request head rule - 0 ms",
                "{target}"
            );
        }
    });
}

#[test]
fn a_request_target_that_hyper_accepts_in_one_part_only_is_inspected() {
    run(async {
        // `"` is taken in the path and not in the query; the backtick is taken in the query and not in the path.
        for target in ["/a\"b", "/{\"k\":1}", "/?q=`x`"] {
            let request = format!("GET {target} HTTP/1.1\r\nHost: h\r\n\r\n");
            let (raw, seen) = exchange(config(), Mode::Answer(BLOCK), request.as_bytes()).await;
            assert_eq!(parse_response(&raw).status, 403, "{target}");
            assert_eq!(seen.len(), 1, "{target}");
            assert_eq!(seen[0].uri, target);
        }
    });
}

#[test]
fn no_inspection_permit_or_a_driver_that_drops_the_ticket_is_503() {
    run(async {
        let rig = Rig::new(config(), Mode::Answer(BLOCK)).await;
        let all = rig
            .ctx
            .inspect
            .clone()
            .try_acquire_many_owned(PERMITS as u32)
            .unwrap();
        let (client, served) = rig.connect().await;
        put(&client, b"GET / HTTP/1.1\r\nHost: h\r\n\r\n").await;
        let response = parse_response(&read_all(&client).await);
        assert_eq!(response.status, 503);
        assert_eq!(response.all("content-length"), ["0"]);
        drop(all);
        assert!(rig.finish(served).await.is_empty());
        // One permit left is enough.
        let rig = Rig::new(config(), Mode::Answer(BLOCK)).await;
        let most = rig
            .ctx
            .inspect
            .clone()
            .try_acquire_many_owned(PERMITS as u32 - 1)
            .unwrap();
        let (client, served) = rig.connect().await;
        put(&client, b"GET / HTTP/1.1\r\nHost: h\r\n\r\n").await;
        assert_eq!(parse_response(&read_all(&client).await).status, 403);
        drop(most);
        assert_eq!(rig.finish(served).await.len(), 1);
        // The reply end is dropped without a verdict: the wait ends at once, not at its deadline.
        let start = std::time::Instant::now();
        let (raw, _) = exchange(config(), Mode::Drop, b"GET / HTTP/1.1\r\nHost: h\r\n\r\n").await;
        assert_eq!(parse_response(&raw).status, 503);
        assert!(start.elapsed() < Duration::from_secs(4));
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
        // Only the body fits.
        let mut cfg = config();
        cfg.max_buffered_bytes = 3;
        let (raw, seen) = exchange(cfg, Mode::Answer(BLOCK), &request).await;
        assert_eq!(parse_response(&raw).status, 503);
        assert!(seen.is_empty());
    });
}

#[test]
fn the_budget_of_a_chunked_body_is_taken_frame_by_frame() {
    run(async {
        let request =
            form_post("Transfer-Encoding: chunked\r\n\r\n3\r\na=b\r\n4\r\n&c=d\r\n0\r\n\r\n");
        // 7 bytes of body, held once and copied once, and the fields with `Content-Length: 7`.
        let needed = 7 + (7 + form_post_field_bytes());
        let mut cfg = config();
        cfg.max_buffered_bytes = needed;
        let (raw, seen) = exchange(cfg, Mode::Answer(BLOCK), &request).await;
        assert_eq!(parse_response(&raw).status, 403);
        assert_eq!(seen[0].body, b"a=b&c=d");
        // The second frame does not fit.
        let mut cfg = config();
        cfg.max_buffered_bytes = 6;
        let (raw, seen) = exchange(cfg, Mode::Answer(BLOCK), &request).await;
        assert_eq!(parse_response(&raw).status, 503);
        assert!(seen.is_empty());
        // The copy does not fit.
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
fn a_form_body_with_a_length_is_inspected_as_received() {
    run(async {
        let (_, seen) = exchange(
            config(),
            Mode::Answer(BLOCK),
            &form_post("Content-Length: 3\r\n\r\na=b"),
        )
        .await;
        assert_eq!(seen.len(), 1);
        let seen = &seen[0];
        assert_eq!(seen.body, b"a=b");
        assert_eq!(
            seen.headers,
            [
                pair("Host", "example.test"),
                pair("Content-Type", FORM),
                pair("Content-Length", "3")
            ]
        );
        assert_eq!(
            (seen.method.as_str(), seen.uri.as_str()),
            ("POST", "/p?q=1")
        );
        assert_eq!(seen.server.ip().to_string(), "127.0.0.1");
        assert_ne!(seen.client.port(), seen.server.port());
    });
}

#[test]
fn a_post_without_a_length_is_inspected_with_content_length_0() {
    run(async {
        let (_, seen) = exchange(
            config(),
            Mode::Answer(BLOCK),
            b"POST /e HTTP/1.1\r\nHost: h\r\n\r\n",
        )
        .await;
        assert_eq!(
            seen[0].headers,
            [pair("Host", "h"), pair("Content-Length", "0")]
        );
        assert!(seen[0].body.is_empty());
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
fn a_chunked_json_body_is_decoded_and_inspected_with_its_length() {
    run(async {
        let request = b"POST /j HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n5\r\n:\"b\"}\r\n0\r\n\r\n";
        let (raw, seen) = exchange(config(), Mode::Answer(BLOCK), request).await;
        assert_eq!(parse_response(&raw).status, 403);
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].body, b"{\"a\":\"b\"}");
        assert_eq!(
            seen[0].headers,
            [
                pair("Host", "h"),
                pair("Content-Type", "application/json"),
                pair("Content-Length", "9")
            ]
        );
    });
}

#[test]
fn a_chunked_json_suffix_body_is_decoded_and_inspected_with_its_length() {
    run(async {
        let request = b"POST /j HTTP/1.1\r\nHost: h\r\nContent-Type: application/vnd.api+json\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n5\r\n:\"b\"}\r\n0\r\n\r\n";
        let (raw, seen) = exchange(config(), Mode::Answer(BLOCK), request).await;
        assert_eq!(parse_response(&raw).status, 403);
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].body, b"{\"a\":\"b\"}");
        assert_eq!(
            seen[0].headers,
            [
                pair("Host", "h"),
                pair("Content-Type", "application/vnd.api+json"),
                pair("Content-Length", "9")
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
        // A `+json` type outside `application/` is not JSON.
        let request = b"POST / HTTP/1.1\r\nHost: h\r\nContent-Type: text/x+json\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n";
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
        let (raw, _) = exchange(config(), Mode::Answer(BLOCK), b"GET / HTTP/1.0\r\n\r\n").await;
        assert_eq!(raw, Reject::VersionNotSupported.response().unwrap());
        let (raw, _) = exchange(config(), Mode::Answer(BLOCK), b"GET /\n\n").await;
        assert_eq!(raw, Reject::BadRequest.response().unwrap());
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
fn the_bytes_on_the_wire_after_the_head_are_limited() {
    run(async {
        let rig = Rig::new(config(), Mode::Answer(BLOCK)).await;
        let (client, task) = rig.connect().await;
        put(&client, &form_post("Transfer-Encoding: chunked\r\n\r\n")).await;
        // The head is read and served by now; a chunk header with a long extension is what follows.
        sleep(Duration::from_millis(100)).await;
        let mut more = b"1;".to_vec();
        more.extend_from_slice(&vec![b'e'; 6000]);
        put(&client, &more).await;
        let raw = read_all(&client).await;
        assert_eq!(parse_response(&raw).status, 413);
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
fn the_head_and_the_body_have_their_own_time() {
    run(async {
        let mut cfg = config();
        cfg.head_read = Duration::from_millis(200);
        let rig = Rig::new(cfg, Mode::Answer(BLOCK)).await;
        let (client, task) = rig.connect().await;
        put(&client, b"GET / HT").await;
        let start = std::time::Instant::now();
        assert_eq!(read_all(&client).await, Reject::Timeout.response().unwrap());
        assert!(start.elapsed() >= Duration::from_millis(190));
        assert!(rig.finish(task).await.is_empty());

        let mut cfg = config();
        cfg.body_read = Duration::from_millis(200);
        let rig = Rig::new(cfg, Mode::Answer(BLOCK)).await;
        let (client, task) = rig.connect().await;
        put(&client, &form_post("Content-Length: 10\r\n\r\nabc")).await;
        let start = std::time::Instant::now();
        let response = parse_response(&read_all(&client).await);
        assert_eq!(response.status, 408);
        assert_eq!(response.all("content-length"), ["0"]);
        assert!(start.elapsed() >= Duration::from_millis(190));
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

#[test]
fn a_body_that_does_not_fit_the_budget_is_503_before_any_100_continue() {
    run(async {
        let mut cfg = config();
        cfg.max_buffered_bytes = 2;
        let request = form_post("Content-Length: 3\r\nExpect: 100-continue\r\n\r\n");
        let (raw, seen) = exchange(cfg, Mode::Answer(BLOCK), &request).await;
        assert!(
            raw.starts_with(b"HTTP/1.1 503 "),
            "{:?}",
            String::from_utf8_lossy(&raw)
        );
        assert!(!String::from_utf8_lossy(&raw).contains("100 Continue"));
        assert!(seen.is_empty());
    });
}

#[test]
fn a_request_that_expects_100_continue_gets_it_once_the_body_can_be_held() {
    run(async {
        let rig = Rig::new(config(), Mode::Answer(BLOCK)).await;
        let (client, task) = rig.connect().await;
        put(
            &client,
            &form_post("Content-Length: 3\r\nExpect: 100-continue\r\n\r\n"),
        )
        .await;
        let mut got = Vec::new();
        let mut buf = [0u8; 256];
        while !got.windows(4).any(|w| w == b"\r\n\r\n") {
            client.readable().await.unwrap();
            if let Ok(n) = client.try_read(&mut buf) {
                got.extend_from_slice(&buf[..n]);
            }
        }
        assert_eq!(got, b"HTTP/1.1 100 Continue\r\n\r\n");
        put(&client, b"a=b").await;
        let response = parse_response(&read_all(&client).await);
        assert_eq!(response.status, 403);
        assert_eq!(rig.finish(task).await[0].body, b"a=b");
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
            assert_eq!(
                (seen[0].method.as_str(), seen[0].uri.as_str()),
                ("POST", "/p?q=1")
            );
        }
        // The other inspected types are decoded the same way.
        let json = br#"{"probe":"block"}"#;
        let multipart =
            b"--x\r\nContent-Disposition: form-data; name=\"probe\"\r\n\r\nblock\r\n--x--\r\n";
        for (content_type, body) in [
            ("application/json", &json[..]),
            ("application/vnd.api+json; charset=utf-8", &json[..]),
            ("multipart/form-data; boundary=x", &multipart[..]),
        ] {
            let coded = gz(body);
            for request in [
                gzip_post(content_type, &coded),
                gzip_chunked_post(content_type, &coded),
            ] {
                let (raw, seen) = exchange(config(), Mode::Answer(BLOCK), &request).await;
                assert_eq!(parse_response(&raw).status, 403, "{content_type}");
                assert_eq!(seen[0].body, body, "{content_type}");
                assert_eq!(
                    seen[0].headers,
                    [
                        pair("Host", "example.test"),
                        pair("Content-Type", content_type),
                        pair("Content-Length", &body.len().to_string())
                    ]
                );
            }
        }
        // The coding in any case and with blanks, and a length with zeros in front, are the same request.
        let mut request = format!(
            "POST /p HTTP/1.1\r\nHost: h\r\ncontent-encoding:  GZIP \t\r\nContent-Type: {FORM}\r\nContent-Length: 00{}\r\n\r\n",
            coded.len()
        )
        .into_bytes();
        request.extend_from_slice(&coded);
        let (raw, seen) = exchange(config(), Mode::Answer(BLOCK), &request).await;
        assert_eq!(parse_response(&raw).status, 403);
        assert_eq!(seen[0].body, b"probe=block");
        assert_eq!(
            seen[0].headers,
            [
                pair("Host", "h"),
                pair("Content-Type", FORM),
                pair("Content-Length", "11")
            ]
        );
    });
}

#[test]
fn a_gzip_body_that_decodes_to_nothing_is_inspected_as_an_empty_body() {
    run(async {
        let coded = gz(b"");
        assert!(!coded.is_empty());
        for request in [gzip_post(FORM, &coded), gzip_chunked_post(FORM, &coded)] {
            let (raw, seen) = exchange(config(), Mode::Answer(BLOCK), &request).await;
            assert_eq!(parse_response(&raw).status, 403);
            assert!(seen[0].body.is_empty());
            assert_eq!(
                seen[0].headers,
                [
                    pair("Host", "example.test"),
                    pair("Content-Type", FORM),
                    pair("Content-Length", "0")
                ]
            );
        }
        // A chunked body needs an inspected type only when the decoded body is not empty, as without the
        // coding; a body with a length needs it in any case, which the head check decides.
        let (raw, seen) = exchange(
            config(),
            Mode::Answer(BLOCK),
            &gzip_chunked_post("text/plain", &coded),
        )
        .await;
        assert_eq!(parse_response(&raw).status, 403);
        assert!(seen[0].body.is_empty());
        let (raw, seen) = exchange(
            config(),
            Mode::Answer(BLOCK),
            &gzip_chunked_post("text/plain", &gz(b"x")),
        )
        .await;
        assert_eq!(parse_response(&raw).status, 415);
        assert!(seen.is_empty());
        let (raw, seen) = exchange(
            config(),
            Mode::Answer(BLOCK),
            &gzip_post("text/plain", &coded),
        )
        .await;
        assert_eq!(raw, Reject::UnsupportedMedia.response().unwrap());
        assert!(seen.is_empty());
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
        for post in [gzip_post, gzip_chunked_post] {
            let (raw, seen) = exchange(config(), Mode::Answer(BLOCK), &post(FORM, &at)).await;
            assert_eq!(parse_response(&raw).status, 403);
            assert_eq!(seen[0].body.len(), 1024);
            assert_eq!(
                seen[0].headers.last().unwrap(),
                &pair("Content-Length", "1024")
            );
            for coded in [&over, &bomb] {
                let (raw, seen, reply) =
                    exchange_with_reply(config(), Mode::Answer(BLOCK), &post(FORM, coded)).await;
                let response = parse_response(&raw);
                assert_eq!(response.status, 413);
                assert_eq!(response.all("content-length"), ["0"]);
                assert!(seen.is_empty());
                assert_eq!(reply, Reply::rejected(413, "decoded body over the limit"));
            }
        }
        // The coded body is held to the limit as well, whatever it decodes to: by its length, and when it
        // is chunked as it is read.
        let big = gz(&noise(1100));
        assert!(big.len() > 1024);
        let (raw, seen) = exchange(
            config(),
            Mode::Answer(BLOCK),
            &form_post("Content-Encoding: gzip\r\nContent-Length: 1025\r\n\r\n"),
        )
        .await;
        assert_eq!(raw, Reject::ContentTooLarge.response().unwrap());
        assert!(seen.is_empty());
        let (raw, seen, reply) = exchange_with_reply(
            config(),
            Mode::Answer(BLOCK),
            &gzip_chunked_post(FORM, &big),
        )
        .await;
        assert_eq!(parse_response(&raw).status, 413);
        assert!(seen.is_empty());
        assert_eq!(reply, Reply::rejected(413, "body over the limit"));
    });
}

#[test]
fn a_gzip_body_that_cannot_be_decoded_is_400_and_nothing_is_inspected() {
    run(async {
        let good = gz(b"probe=block");
        let with = |extra: &[u8]| {
            let mut coded = good.clone();
            coded.extend_from_slice(extra);
            coded
        };
        let flipped = |from_end: usize| {
            let mut coded = good.clone();
            let at = coded.len() - from_end;
            coded[at] ^= 0x01;
            coded
        };
        let malformed = "malformed gzip body";
        let after = "data after the gzip member";
        let cases = [
            // The CRC and the length of the trailer.
            (flipped(8), malformed),
            (flipped(1), malformed),
            // Cut in the trailer, cut after the header, not gzip at all.
            (good[..good.len() - 1].to_vec(), malformed),
            (good[..10].to_vec(), malformed),
            (b"probe=block".to_vec(), malformed),
            // A byte after the member, and a second member.
            (with(b"\0"), after),
            (with(&good), after),
        ];
        for (coded, reason) in &cases {
            for request in [gzip_post(FORM, coded), gzip_chunked_post(FORM, coded)] {
                let (raw, seen, reply) =
                    exchange_with_reply(config(), Mode::Answer(BLOCK), &request).await;
                let response = parse_response(&raw);
                assert_eq!(response.status, 400, "{reason}: {coded:?}");
                assert_eq!(response.all("content-length"), ["0"]);
                assert!(seen.is_empty(), "{reason}: {coded:?}");
                assert_eq!(reply, Reply::rejected(400, reason), "{coded:?}");
            }
        }
        // The one good member passes through the same requests.
        for request in [gzip_post(FORM, &good), gzip_chunked_post(FORM, &good)] {
            let (raw, seen) = exchange(config(), Mode::Answer(BLOCK), &request).await;
            assert_eq!(parse_response(&raw).status, 403);
            assert_eq!(seen.len(), 1);
        }
    });
}

#[test]
fn an_empty_gzip_body_is_400_whatever_its_framing() {
    run(async {
        // A length of 0 and no framing are decided by the head check: the fixed answer.
        for lines in [
            "Content-Encoding: gzip\r\nContent-Length: 0\r\n\r\n",
            "Content-Encoding: gzip\r\n\r\n",
        ] {
            let (raw, seen) = exchange(config(), Mode::Answer(BLOCK), &form_post(lines)).await;
            assert_eq!(raw, Reject::BadRequest.response().unwrap(), "{lines:?}");
            assert!(seen.is_empty());
        }
        // A chunked body is empty only once it has been read.
        let (raw, seen, reply) = exchange_with_reply(
            config(),
            Mode::Answer(BLOCK),
            &form_post("Content-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"),
        )
        .await;
        let response = parse_response(&raw);
        assert_eq!(response.status, 400);
        assert_eq!(response.all("content-length"), ["0"]);
        assert!(seen.is_empty());
        assert_eq!(reply, Reply::rejected(400, "empty gzip body"));
        // The same requests without the coding are inspected as empty bodies.
        for lines in [
            "Content-Length: 0\r\n\r\n",
            "\r\n",
            "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        ] {
            let (raw, seen) = exchange(config(), Mode::Answer(BLOCK), &form_post(lines)).await;
            assert_eq!(parse_response(&raw).status, 403, "{lines:?}");
            assert_eq!(seen.len(), 1);
        }
    });
}

#[test]
fn a_body_with_any_other_coding_is_415_and_never_decoded() {
    run(async {
        for coding in [
            "br",
            "deflate",
            "x-gzip",
            "zstd",
            "identity",
            "gzip, gzip",
            "gzip, identity",
            "",
        ] {
            let lines = format!("Content-Encoding: {coding}\r\nContent-Length: 3\r\n\r\na=b");
            let (raw, seen) = exchange(config(), Mode::Answer(BLOCK), &form_post(&lines)).await;
            assert_eq!(
                raw,
                Reject::UnsupportedMedia.response().unwrap(),
                "{coding:?}"
            );
            assert!(seen.is_empty());
        }
        let coded = gz(b"a=b");
        let mut request = format!(
            "POST /p HTTP/1.1\r\nHost: h\r\nContent-Type: {FORM}\r\nContent-Encoding: gzip\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
            coded.len()
        )
        .into_bytes();
        request.extend_from_slice(&coded);
        let (raw, seen) = exchange(config(), Mode::Answer(BLOCK), &request).await;
        assert_eq!(raw, Reject::UnsupportedMedia.response().unwrap());
        assert!(seen.is_empty());
    });
}

#[test]
fn the_budget_of_a_gzip_body_is_the_decoded_length_taken_while_the_coded_body_is_held() {
    run(async {
        let plain = b"a=b";
        // The kernel's copy binds: the body, and the copy of the body with the fields. The coded body is
        // given back before the copy is taken, or the whole would be larger.
        let coded = gz(plain);
        let copy_bound = 3 + (3 + form_post_field_bytes());
        assert!(coded.len() + 3 < copy_bound);
        for post in [gzip_post, gzip_chunked_post] {
            let request = post(FORM, &coded);
            let mut cfg = config();
            cfg.max_buffered_bytes = copy_bound;
            let (raw, seen) = exchange(cfg, Mode::Answer(BLOCK), &request).await;
            assert_eq!(parse_response(&raw).status, 403);
            assert_eq!(seen[0].body, plain);
            let mut cfg = config();
            cfg.max_buffered_bytes = copy_bound - 1;
            let (raw, seen) = exchange(cfg, Mode::Answer(BLOCK), &request).await;
            assert_eq!(parse_response(&raw).status, 503);
            assert!(seen.is_empty());
        }
        // The decoding binds: a coded body with a long header holds more than the copy needs, and the decoded
        // body is taken while it is still held.
        let padded = gz_with_comment(plain, 100);
        let decoding_bound = padded.len() + 3;
        assert!(decoding_bound > copy_bound);
        for post in [gzip_post, gzip_chunked_post] {
            let request = post(FORM, &padded);
            let mut cfg = config();
            cfg.max_buffered_bytes = decoding_bound;
            let (raw, seen) = exchange(cfg, Mode::Answer(BLOCK), &request).await;
            assert_eq!(parse_response(&raw).status, 403);
            assert_eq!(seen[0].body, plain);
            for short in [decoding_bound - 1, padded.len()] {
                let mut cfg = config();
                cfg.max_buffered_bytes = short;
                let (raw, seen, reply) =
                    exchange_with_reply(cfg, Mode::Answer(BLOCK), &request).await;
                let response = parse_response(&raw);
                assert_eq!(response.status, 503, "budget {short}");
                assert_eq!(response.all("content-length"), ["0"]);
                assert!(seen.is_empty());
                assert_eq!(reply, Reply::failed(503, "byte budget exhausted"));
            }
        }
        // The coded body that does not fit is refused before it is read, as without the coding.
        let mut cfg = config();
        cfg.max_buffered_bytes = padded.len() - 1;
        let (raw, seen) = exchange(cfg, Mode::Answer(BLOCK), &gzip_post(FORM, &padded)).await;
        assert_eq!(parse_response(&raw).status, 503);
        assert!(seen.is_empty());
    });
}
