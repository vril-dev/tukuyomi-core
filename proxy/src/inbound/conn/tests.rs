use std::io::Write;
use std::sync::mpsc::{Receiver, sync_channel};
use std::thread::{self, JoinHandle};

use flate2::Compression;
use flate2::write::GzEncoder;
use tokio::net::TcpListener;
use tokio::runtime::{Builder, Runtime};
use tokio::task::JoinHandle as Served;
use tokio::time::{sleep, timeout};
use tukuyomi_kernel::Verdict;

use super::*;
use crate::inbound::represent::tests::head_of;
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
    let swapped = Request::builder()
        .method("POST")
        .uri("/a?b=%41")
        .header("host", "h")
        .header("x-a", "2")
        .header("x-a", "1")
        .header("x-b", "v")
        .body(())
        .unwrap();
    let different = [
        base().method("PUT").body(()).unwrap(),
        base().uri("/a?b=%42").body(()).unwrap(),
        base().uri("http://h/a?b=%41").body(()).unwrap(),
        base().version(Version::HTTP_10).body(()).unwrap(),
        base().header("x-c", "3").body(()).unwrap(),
        swapped,
    ];
    for (n, request) in different.into_iter().enumerate() {
        assert!(!same_head(&head, &parts(request)), "case {n}");
    }
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
        stage(start, Duration::from_secs(11), &times),
        start + Duration::from_secs(10)
    );
    assert_eq!(after(start, Duration::MAX), start);
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
}

#[derive(Debug)]
struct Seen {
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
