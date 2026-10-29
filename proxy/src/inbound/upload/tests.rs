use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tukuyomi_kernel::Verdict;

use crate::config::{ForwardConfig, ProxyConfig, RouteConfig};
use crate::inbound::conn::tests::{
    BLOCK, FORM, Mode, Rig, config, finish_sending, gz, pair, parse_response, put, read_all, run,
};
use crate::inspect::driver::Outcome;
use crate::log::is_answer;
use crate::route::{Rule, Table};
use crate::rules::routes::{Route, Routes};

const ALLOW: Mode = Mode::Answer(Outcome::Verdict(Verdict::Allow));
const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
const INSPECT: usize = 1024;

/// A proxy that inspects the first 1024 bytes of a body and takes 1 MiB of it, with a budget that is far below
/// the size of the bodies of these tests.
fn streaming() -> ProxyConfig {
    ProxyConfig {
        max_body: 1 << 20,
        inspect_body: INSPECT,
        max_body_wire: 4 << 20,
        max_buffered_bytes: 80 * 1024,
        ..config()
    }
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| b'a' + u8::try_from(i % 26).unwrap())
        .collect()
}

/// Bytes that a gzip coding does not make shorter.
fn noise(len: usize) -> Vec<u8> {
    let mut state = 12345u32;
    (0..len)
        .map(|_| {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            u8::try_from(state >> 24).unwrap()
        })
        .collect()
}

fn post_with_length(path: &str, body: &[u8]) -> Vec<u8> {
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: example.test\r\nContent-Type: {FORM}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(body);
    request
}

fn chunked_head(method: &str, path: &str) -> Vec<u8> {
    format!(
        "{method} {path} HTTP/1.1\r\nHost: example.test\r\nContent-Type: {FORM}\r\nTransfer-Encoding: chunked\r\n\r\n"
    )
    .into_bytes()
}

fn chunks(body: &[u8], piece: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for part in body.chunks(piece) {
        out.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
        out.extend_from_slice(part);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"0\r\n\r\n");
    out
}

fn post_chunked(path: &str, body: &[u8], piece: usize) -> Vec<u8> {
    let mut request = chunked_head("POST", path);
    request.extend_from_slice(&chunks(body, piece));
    request
}

/// What the stand-in for an upstream read: the head, the bytes behind it as they came, and whether the request was
/// whole.
struct Got {
    head: String,
    wire: Vec<u8>,
    complete: bool,
}

impl Got {
    fn field(&self, name: &str) -> Option<&str> {
        field_of(&self.head, name)
    }

    /// The body, with the chunked framing taken off.
    fn body(&self) -> Vec<u8> {
        if self.field("transfer-encoding").is_none() {
            return self.wire.clone();
        }
        let mut out = Vec::new();
        let mut rest = &self.wire[..];
        while let Some(end) = rest.windows(2).position(|pair| pair == b"\r\n") {
            let size = usize::from_str_radix(std::str::from_utf8(&rest[..end]).unwrap().trim(), 16)
                .unwrap();
            rest = &rest[end + 2..];
            if size == 0 {
                break;
            }
            if rest.len() < size + 2 {
                out.extend_from_slice(rest);
                break;
            }
            out.extend_from_slice(&rest[..size]);
            rest = &rest[size + 2..];
        }
        out
    }
}

/// An upstream that reads one request. It answers 200 once the request is whole; with `drop_after` it closes the
/// connection, with no answer, as soon as it has that many bytes of the body.
async fn upstream(drop_after: Option<usize>) -> (SocketAddr, JoinHandle<Got>) {
    serve(drop_after, true).await
}

/// An upstream that reads the whole request and never answers: it holds the connection until the other side
/// closes it.
async fn silent_upstream() -> (SocketAddr, JoinHandle<Got>) {
    serve(None, false).await
}

async fn serve(drop_after: Option<usize>, answers: bool) -> (SocketAddr, JoinHandle<Got>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut raw = Vec::new();
        let mut buf = vec![0u8; 16 * 1024];
        let mut head = String::new();
        let mut body_at = None;
        let mut complete = false;
        loop {
            if let Some(at) = body_at {
                let wire = &raw[at..];
                let whole = match field_of(&head, "content-length") {
                    Some(length) => wire.len() >= length.parse::<usize>().unwrap(),
                    None => {
                        field_of(&head, "transfer-encoding").is_none()
                            || wire.ends_with(b"\r\n0\r\n\r\n")
                    }
                };
                if whole {
                    complete = true;
                    break;
                }
                if drop_after.is_some_and(|n| wire.len() >= n) {
                    break;
                }
            }
            let n = match timeout(Duration::from_secs(20), sock.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => n,
                _ => break,
            };
            raw.extend_from_slice(&buf[..n]);
            if body_at.is_none()
                && let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n")
            {
                head = String::from_utf8_lossy(&raw[..end]).into_owned();
                body_at = Some(end + 4);
            }
        }
        if complete && answers {
            let _ = sock.write_all(OK).await;
            let _ = sock.shutdown().await;
        } else if complete {
            while let Ok(Ok(n)) = timeout(Duration::from_secs(20), sock.read(&mut buf)).await
                && n > 0
            {}
        }
        let at = body_at.unwrap_or(raw.len());
        Got {
            head,
            wire: raw[at..].to_vec(),
            complete,
        }
    });
    (addr, task)
}

fn field_of<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .find(|(field, _)| field.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim())
}

/// What a client got back and what the record said, after the connection is over.
struct Done {
    status: Option<u16>,
    lines: Vec<serde_json::Value>,
    seen: Vec<crate::inbound::conn::tests::Seen>,
}

/// Sends `request` through a proxy with `cfg` and `forward`, in front of an inspection that says `mode`.
async fn through(
    cfg: ProxyConfig,
    mode: Mode,
    forward: &ForwardConfig,
    routes: Option<Routes>,
    request: &[u8],
) -> Done {
    let rig = Rig::with(cfg, mode, forward).await;
    if let Some(routes) = routes {
        rig.ctx.routes.replace(routes);
    }
    let (client, task) = rig.connect().await;
    put(&client, request).await;
    let raw = read_all(&client).await;
    drop(client);
    let lines = rig.lines.clone();
    let seen = rig.finish(task).await;
    Done {
        status: (!raw.is_empty()).then(|| parse_response(&raw).status),
        lines: lines.take(),
        seen,
    }
}

fn record_with<'a>(
    lines: &'a [serde_json::Value],
    class: &str,
    status: u16,
    reason: &str,
) -> Option<&'a serde_json::Value> {
    lines
        .iter()
        .find(|line| is_answer(line, class, status, reason))
}

#[test]
fn a_body_longer_than_the_inspected_bytes_is_inspected_cut_and_forwarded_whole_with_its_length() {
    run(async {
        let body = pattern(200_000);
        let (addr, got) = upstream(None).await;
        let forward = ForwardConfig::of(&[addr]);
        let out = through(
            streaming(),
            ALLOW,
            &forward,
            None,
            &post_with_length("/p", &body),
        )
        .await;
        assert_eq!(out.status, Some(200));
        assert_eq!(out.seen.len(), 1);
        assert!(out.seen[0].cut);
        assert_eq!(out.seen[0].body, body[..INSPECT]);
        let got = got.await.unwrap();
        assert!(got.complete);
        assert_eq!(got.field("content-length"), Some("200000"));
        assert_eq!(got.field("transfer-encoding"), None);
        assert_eq!(got.body(), body);
        let line = record_with(&out.lines, "forwarded", 200, "forwarded").expect("the record");
        assert_eq!(
            (&line["body"], &line["inspected"]),
            (&serde_json::json!(200000), &serde_json::json!(1024)),
            "{line}"
        );
    });
}

#[test]
fn a_long_chunked_body_is_inspected_cut_and_forwarded_chunked_and_whole() {
    run(async {
        let body = pattern(200_000);
        let (addr, got) = upstream(None).await;
        let forward = ForwardConfig::of(&[addr]);
        // Pieces that do not meet the end of the inspected bytes.
        let out = through(
            streaming(),
            ALLOW,
            &forward,
            None,
            &post_chunked("/p", &body, 3000),
        )
        .await;
        assert_eq!(out.status, Some(200));
        assert_eq!(out.seen.len(), 1);
        assert!(out.seen[0].cut);
        assert_eq!(out.seen[0].body, body[..INSPECT]);
        // The body has no length to name, so the inspection gets the framing the client used and makes up no length.
        let fields = &out.seen[0].headers;
        assert!(
            fields.contains(&pair("Transfer-Encoding", "chunked")),
            "{fields:?}"
        );
        assert!(
            fields.iter().all(|(name, _)| name != "Content-Length"),
            "{fields:?}"
        );
        let got = got.await.unwrap();
        assert!(got.complete);
        assert_eq!(got.field("transfer-encoding"), Some("chunked"));
        assert_eq!(got.field("content-length"), None);
        assert_eq!(got.body(), body);
        let line = record_with(&out.lines, "forwarded", 200, "forwarded").expect("the record");
        assert_eq!(
            (&line["body"], &line["inspected"]),
            (&serde_json::json!(200000), &serde_json::json!(1024)),
            "{line}"
        );
    });
}

#[test]
fn a_body_of_the_inspected_length_is_whole_and_one_byte_more_is_cut() {
    run(async {
        for len in [INSPECT, INSPECT + 1] {
            let body = pattern(len);
            for request in [
                post_with_length("/p", &body),
                post_chunked("/p", &body, INSPECT),
            ] {
                let (addr, got) = upstream(None).await;
                let forward = ForwardConfig::of(&[addr]);
                let out = through(streaming(), ALLOW, &forward, None, &request).await;
                assert_eq!(out.status, Some(200), "{len}");
                assert_eq!(out.seen.len(), 1);
                assert_eq!(out.seen[0].cut, len > INSPECT, "{len}");
                assert_eq!(out.seen[0].body, body[..INSPECT]);
                let got = got.await.unwrap();
                assert!(got.complete);
                assert_eq!(got.body(), body, "{len}");
            }
        }
    });
}

#[test]
fn a_chunked_body_that_passes_the_limit_while_it_is_passed_on_ends_the_request_and_the_connection()
{
    run(async {
        let cfg = ProxyConfig {
            max_body: 4096,
            ..streaming()
        };
        let (addr, got) = upstream(None).await;
        let forward = ForwardConfig::of(&[addr]);
        let out = through(
            cfg,
            ALLOW,
            &forward,
            None,
            &post_chunked("/p", &pattern(10_000), 1000),
        )
        .await;
        // No answer: the connection is closed, with one reason in the record.
        assert_eq!(out.status, None);
        assert!(
            record_with(
                &out.lines,
                "closed",
                0,
                "body over the limit while it was sent on"
            )
            .is_some(),
            "{:?}",
            out.lines
        );
        assert!(!got.await.unwrap().complete);
    });
}

#[test]
fn a_request_whose_body_was_passed_on_is_not_sent_again() {
    run(async {
        // The first server closes the connection with no answer while the body is on its way; the other one is
        // a backup, which a request that could be sent again would reach.
        let (first, first_got) = upstream(Some(5000)).await;
        let spare = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut forward = ForwardConfig::of(&[first, spare.local_addr().unwrap()]);
        forward.groups[0].servers[1].backup = true;
        // PUT does no harm when it is sent twice, so only the body keeps it from being sent again.
        let mut request = chunked_head("PUT", "/p");
        request.extend_from_slice(&chunks(&pattern(100_000), 2000));
        let out = through(streaming(), ALLOW, &forward, None, &request).await;
        assert_eq!(out.status, Some(502));
        assert!(
            record_with(
                &out.lines,
                "failed",
                502,
                "upstream failed while the body was sent on"
            )
            .is_some(),
            "{:?}",
            out.lines
        );
        assert!(!first_got.await.unwrap().complete);
        assert!(
            timeout(Duration::from_millis(300), spare.accept())
                .await
                .is_err(),
            "the request was sent to the other server"
        );
    });
}

#[test]
fn a_trailer_after_the_rest_of_the_body_is_400_and_the_request_to_the_upstream_is_cut() {
    run(async {
        let (addr, got) = upstream(None).await;
        let forward = ForwardConfig::of(&[addr]);
        // The body is on its way when the trailer comes: the last chunk of `chunks` is swapped for one with a field.
        let mut request = chunked_head("POST", "/p");
        let body = chunks(&pattern(10_000), 1000);
        request.extend_from_slice(&body[..body.len() - b"0\r\n\r\n".len()]);
        request.extend_from_slice(b"0\r\nX-T: 1\r\n\r\n");
        let out = through(streaming(), ALLOW, &forward, None, &request).await;
        assert_eq!(out.status, Some(400));
        assert!(
            record_with(
                &out.lines,
                "rejected",
                400,
                "request trailers not supported"
            )
            .is_some(),
            "{:?}",
            out.lines
        );
        assert!(!got.await.unwrap().complete);
    });
}

#[test]
fn an_upstream_that_reads_the_whole_body_and_never_answers_fails_the_request_after_upstream_header()
{
    run(async {
        // The request time (10 s) is far longer than the time the upstream has to answer once it has the body.
        let cfg = ProxyConfig {
            upstream_header: Duration::from_millis(400),
            ..streaming()
        };
        // A body that is held and one that is passed on get the same answer.
        for body in [pattern(INSPECT), pattern(50_000)] {
            let (addr, got) = silent_upstream().await;
            let forward = ForwardConfig::of(&[addr]);
            let rig = Rig::with(cfg.clone(), ALLOW, &forward).await;
            let (client, task) = rig.connect().await;
            let start = Instant::now();
            put(&client, &post_with_length("/p", &body)).await;
            let raw = read_all(&client).await;
            let waited = start.elapsed();
            assert_eq!(parse_response(&raw).status, 502, "{}", body.len());
            assert!(waited >= cfg.upstream_header, "{waited:?}");
            assert!(waited < cfg.request_total / 2, "{waited:?}");
            drop(client);
            let lines = rig.lines.clone();
            // The server is blamed, as for a request whose body is held.
            assert!(rig.ctx.upstreams.group(0).left_out(0));
            let _ = rig.finish(task).await;
            assert!(
                record_with(
                    &lines.take(),
                    "failed",
                    502,
                    "upstream response head failed"
                )
                .is_some(),
                "{}",
                body.len()
            );
            assert!(got.await.unwrap().complete);
        }
    });
}

/// The head of a POST that announces `length` bytes, and the first `sent` of them.
fn announced(length: usize, sent: usize) -> Vec<u8> {
    let mut request = format!(
        "POST /p HTTP/1.1\r\nHost: example.test\r\nContent-Type: {FORM}\r\nContent-Length: {length}\r\n\r\n"
    )
    .into_bytes();
    request.extend_from_slice(&pattern(sent));
    request
}

#[test]
fn a_client_that_is_silent_for_longer_than_the_body_time_between_two_reads_is_cut_and_the_server_is_not_blamed()
 {
    run(async {
        // The silence of the upstream connection (300 ms) is shorter than the body time (600 ms): the client is
        // cut at the body time, and not as a failure of the upstream.
        let cfg = ProxyConfig {
            body_read: Duration::from_millis(600),
            response_idle: Duration::from_millis(300),
            ..streaming()
        };
        let (addr, got) = upstream(None).await;
        let forward = ForwardConfig::of(&[addr]);
        // The head says 50000 bytes and 2000 come; the client keeps the connection open and sends no more.
        let rig = Rig::with(cfg, ALLOW, &forward).await;
        let (client, task) = rig.connect().await;
        put(&client, &announced(50_000, 2000)).await;
        let raw = read_all(&client).await;
        assert_eq!(parse_response(&raw).status, 408);
        drop(client);
        let lines = rig.lines.clone();
        assert!(!rig.ctx.upstreams.group(0).left_out(0));
        let _ = rig.finish(task).await;
        assert!(record_with(&lines.take(), "rejected", 408, "body not received in time").is_some());
        assert!(!got.await.unwrap().complete);
    });
}

#[test]
fn a_client_that_pauses_for_longer_than_the_silence_of_the_upstream_connection_but_not_the_body_time_gets_through()
 {
    run(async {
        let cfg = ProxyConfig {
            body_read: Duration::from_secs(3),
            response_idle: Duration::from_millis(300),
            ..streaming()
        };
        let body = pattern(50_000);
        let (addr, got) = upstream(None).await;
        let forward = ForwardConfig::of(&[addr]);
        let request = post_with_length("/p", &body);
        // The client pauses for 800 ms after the inspected bytes, which the upstream connection would not wait for.
        let (first, rest) = request.split_at(request.len() - 48_000);
        let rig = Rig::with(cfg, ALLOW, &forward).await;
        let (client, task) = rig.connect().await;
        put(&client, first).await;
        sleep(Duration::from_millis(800)).await;
        put(&client, rest).await;
        let raw = read_all(&client).await;
        assert_eq!(parse_response(&raw).status, 200);
        drop(client);
        assert!(!rig.ctx.upstreams.group(0).left_out(0));
        let _ = rig.finish(task).await;
        let got = got.await.unwrap();
        assert!(got.complete);
        assert_eq!(got.body(), body);
    });
}

#[test]
fn a_client_that_goes_away_in_the_middle_of_the_rest_of_the_body_ends_the_request_to_the_upstream()
{
    run(async {
        let (addr, got) = upstream(None).await;
        let forward = ForwardConfig::of(&[addr]);
        let rig = Rig::with(streaming(), ALLOW, &forward).await;
        let (mut client, task) = rig.connect().await;
        put(&client, &announced(50_000, 5000)).await;
        // The upstream has the first of it when the client stops sending.
        sleep(Duration::from_millis(200)).await;
        finish_sending(&mut client).await;
        assert!(read_all(&client).await.is_empty());
        drop(client);
        let lines = rig.lines.clone();
        assert!(!rig.ctx.upstreams.group(0).left_out(0));
        let _ = rig.finish(task).await;
        let lines = lines.take();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(record_with(&lines, "closed", 0, "peer closed during the body").is_some());
        let got = got.await.unwrap();
        assert!(!got.complete);
        assert!(!got.wire.is_empty() && got.wire.len() < 50_000);
    });
}

#[test]
fn a_chunked_body_that_passes_the_wire_limit_while_it_is_passed_on_is_413_and_the_upstream_request_is_cut()
 {
    run(async {
        let cfg = ProxyConfig {
            max_body_wire: 8192,
            ..streaming()
        };
        let (addr, got) = upstream(None).await;
        let forward = ForwardConfig::of(&[addr]);
        let request = post_chunked("/p", &pattern(20_000), 1000);
        let out = through(cfg, ALLOW, &forward, None, &request).await;
        assert_eq!(out.status, Some(413));
        assert!(
            record_with(
                &out.lines,
                "rejected",
                413,
                "body over the limit on the wire"
            )
            .is_some(),
            "{:?}",
            out.lines
        );
        assert!(!got.await.unwrap().complete);
    });
}

#[test]
fn the_end_of_the_request_time_during_the_rest_of_the_body_is_503_and_the_server_is_not_blamed() {
    run(async {
        // The body time (5 s) is longer than the request time.
        let cfg = ProxyConfig {
            request_total: Duration::from_millis(800),
            ..streaming()
        };
        let (addr, got) = upstream(None).await;
        let forward = ForwardConfig::of(&[addr]);
        let rig = Rig::with(cfg, ALLOW, &forward).await;
        let (client, task) = rig.connect().await;
        put(&client, &announced(50_000, 2000)).await;
        let raw = read_all(&client).await;
        assert_eq!(parse_response(&raw).status, 503);
        drop(client);
        let lines = rig.lines.clone();
        assert!(!rig.ctx.upstreams.group(0).left_out(0));
        let _ = rig.finish(task).await;
        assert!(record_with(&lines.take(), "failed", 503, "request time used up").is_some());
        assert!(!got.await.unwrap().complete);
    });
}

#[test]
fn the_record_gives_the_announced_length_when_the_request_is_stopped_before_the_rest_is_read() {
    run(async {
        let forward = ForwardConfig::of(&["127.0.0.1:2".parse().unwrap()]);
        let rig = Rig::with(streaming(), Mode::Answer(BLOCK), &forward).await;
        let (client, task) = rig.connect().await;
        // 2000 of the 200000 bytes come, and the inspection blocks the request on the first 1024.
        put(&client, &announced(200_000, 2000)).await;
        let raw = read_all(&client).await;
        assert_eq!(parse_response(&raw).status, 403);
        drop(client);
        let lines = rig.lines.clone();
        let _ = rig.finish(task).await;
        let lines = lines.take();
        let line = record_with(&lines, "blocked", 403, "blocked by a rule").expect("the record");
        assert_eq!(
            (&line["body"], &line["inspected"]),
            (&serde_json::json!(200000), &serde_json::json!(1024)),
            "{line}"
        );
    });
}

#[test]
fn a_gzip_body_is_held_and_decoded_whole_and_neither_form_may_pass_the_inspected_bytes() {
    run(async {
        let post = |coded: &[u8]| {
            let mut request = format!(
                "POST /p HTTP/1.1\r\nHost: example.test\r\nContent-Type: {FORM}\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
                coded.len()
            )
            .into_bytes();
            request.extend_from_slice(coded);
            request
        };
        let forward = ForwardConfig::of(&["127.0.0.1:2".parse().unwrap()]);
        // Decoded: the limit itself is inspected (and gets through to the upstream, which is not there: 502), and
        // one byte more is refused with 413 and inspected by no one.
        let at = through(
            streaming(),
            ALLOW,
            &forward,
            None,
            &post(&gz(&pattern(INSPECT))),
        )
        .await;
        assert_eq!((at.status, at.seen.len()), (Some(502), 1));
        assert!(!at.seen[0].cut);
        let over = through(
            streaming(),
            ALLOW,
            &forward,
            None,
            &post(&gz(&pattern(INSPECT + 1))),
        )
        .await;
        assert_eq!((over.status, over.seen.len()), (Some(413), 0));
        assert!(record_with(&over.lines, "rejected", 413, "decoded body over the limit").is_some());
        // Coded: a body that is stored, so that it is longer than what it decodes to, is refused by its own length.
        let mut stored = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::none());
        std::io::Write::write_all(&mut stored, &pattern(INSPECT - 4)).unwrap();
        let stored = stored.finish().unwrap();
        assert!(stored.len() > INSPECT);
        let long = through(streaming(), ALLOW, &forward, None, &post(&stored)).await;
        assert_eq!((long.status, long.seen.len()), (Some(413), 0));
    });
}

#[test]
fn a_body_of_a_type_that_is_not_read_goes_on_under_a_route_that_skips_the_inspection_and_is_415_elsewhere()
 {
    run(async {
        let routes = || Routes::new(vec![Route::new(None, "/up/").unwrap()]).unwrap();
        let xml = b"<a>1</a>";
        let post = |path: &str, type_line: &str, chunked: bool| {
            let mut request =
                format!("POST {path} HTTP/1.1\r\nHost: example.test\r\n{type_line}").into_bytes();
            if chunked {
                request.extend_from_slice(b"Transfer-Encoding: chunked\r\n\r\n");
                request.extend_from_slice(&chunks(xml, 4));
            } else {
                request
                    .extend_from_slice(format!("Content-Length: {}\r\n\r\n", xml.len()).as_bytes());
                request.extend_from_slice(xml);
            }
            request
        };
        let nowhere = ForwardConfig::of(&["127.0.0.1:2".parse().unwrap()]);
        // A type that is not read, and none at all, with a length and chunked.
        for type_line in ["Content-Type: application/xml\r\n", ""] {
            for chunked in [false, true] {
                let (addr, got) = upstream(None).await;
                let forward = ForwardConfig::of(&[addr]);
                let request = post("/up/x", type_line, chunked);
                let out = through(streaming(), ALLOW, &forward, Some(routes()), &request).await;
                assert_eq!(
                    (out.status, out.seen.len()),
                    (Some(200), 0),
                    "{type_line:?} {chunked}"
                );
                let got = got.await.unwrap();
                assert!(got.complete);
                assert_eq!(got.body(), xml);
                // Another path, and two spellings of the path of the route that the matching does not take for
                // it (an escape of a letter, and a `.` segment): inspected, so refused before the upstream.
                for path in ["/dynamic", "/u%70/x", "/up/./x"] {
                    let request = post(path, type_line, chunked);
                    let out = through(streaming(), ALLOW, &nowhere, Some(routes()), &request).await;
                    let case = format!("{path} {type_line:?} {chunked}");
                    assert_eq!((out.status, out.seen.len()), (Some(415), 0), "{case}");
                }
            }
        }
        // The rule on the coding of the body is kept under the route.
        let coded = b"POST /up/x HTTP/1.1\r\nHost: example.test\r\nContent-Encoding: br\r\nContent-Length: 1\r\n\r\nx";
        let out = through(streaming(), ALLOW, &nowhere, Some(routes()), coded).await;
        assert_eq!((out.status, out.seen.len()), (Some(415), 0));
    });
}

#[test]
fn a_body_with_two_content_type_lines_is_415_also_under_a_route_that_skips_the_inspection() {
    run(async {
        let routes = || Routes::new(vec![Route::new(None, "/up/").unwrap()]).unwrap();
        let nowhere = ForwardConfig::of(&["127.0.0.1:2".parse().unwrap()]);
        let post = |path: &str, chunked: bool, body: &[u8]| {
            let mut request = format!(
                "POST {path} HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\nContent-Type: text/plain\r\n"
            )
            .into_bytes();
            if chunked {
                request.extend_from_slice(b"Transfer-Encoding: chunked\r\n\r\n");
                request.extend_from_slice(&chunks(body, 4));
            } else {
                request.extend_from_slice(
                    format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes(),
                );
                request.extend_from_slice(body);
            }
            request
        };
        // With a length (the head check) and chunked (once the body has been read), under the route and off it:
        // refused, and nothing reaches the upstream (a request that was forwarded would be 502).
        for path in ["/up/x", "/dynamic"] {
            for chunked in [false, true] {
                let request = post(path, chunked, b"<a>1</a>");
                let out = through(streaming(), ALLOW, &nowhere, Some(routes()), &request).await;
                assert_eq!(
                    (out.status, out.seen.len()),
                    (Some(415), 0),
                    "{path} {chunked}"
                );
            }
        }
        // A chunked body with no bytes has nothing to give a type to: it goes on.
        let (addr, got) = upstream(None).await;
        let forward = ForwardConfig::of(&[addr]);
        let request = post("/up/x", true, b"");
        let out = through(streaming(), ALLOW, &forward, Some(routes()), &request).await;
        assert_eq!((out.status, out.seen.len()), (Some(200), 0));
        assert!(got.await.unwrap().complete);
    });
}

#[test]
fn a_body_with_a_length_that_the_inspection_does_not_read_is_415_before_it_is_read() {
    run(async {
        let nowhere = ForwardConfig::of(&["127.0.0.1:2".parse().unwrap()]);
        // Only the head is sent. If the type were looked at once the body has been read, the proxy would wait for
        // the body and answer something else when the time for it ran out.
        for type_line in ["Content-Type: text/plain\r\n", ""] {
            let head = format!(
                "POST /dynamic HTTP/1.1\r\nHost: example.test\r\n{type_line}Content-Length: 8\r\n\r\n"
            );
            let out = through(streaming(), ALLOW, &nowhere, None, head.as_bytes()).await;
            assert_eq!(
                (out.status, out.seen.len()),
                (Some(415), 0),
                "{type_line:?}"
            );
        }
    });
}

#[test]
fn a_request_under_a_route_that_skips_the_inspection_streams_a_long_body_and_does_not_hold_it_whole()
 {
    run(async {
        let routes = || Routes::new(vec![Route::new(None, "/up/").unwrap()]).unwrap();
        let body = pattern(200_000);
        for request in [
            post_with_length("/up/x", &body),
            post_chunked("/up/x", &body, 5000),
        ] {
            let (addr, got) = upstream(None).await;
            let forward = ForwardConfig::of(&[addr]);
            let out = through(streaming(), ALLOW, &forward, Some(routes()), &request).await;
            assert_eq!(out.status, Some(200));
            // No ticket: nothing was inspected, and the budget (80 KiB) never held the body whole.
            assert!(out.seen.is_empty());
            let got = got.await.unwrap();
            assert!(got.complete);
            assert_eq!(got.body(), body);
            let line =
                record_with(&out.lines, "forwarded", 200, "bypassed by a route").expect("record");
            assert!(
                line["body"] == 200000 && line.get("inspected").is_none(),
                "{line}"
            );
        }
    });
}

#[test]
fn a_body_under_a_route_that_skips_the_inspection_is_held_if_it_ends_within_the_inspected_bytes() {
    run(async {
        let routes = || Routes::new(vec![Route::new(None, "/up/").unwrap()]).unwrap();
        let gzip_post = |coded: &[u8]| {
            let mut request = format!(
                "POST /up/x HTTP/1.1\r\nHost: example.test\r\nContent-Type: {FORM}\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
                coded.len()
            )
            .into_bytes();
            request.extend_from_slice(coded);
            request
        };
        let gzip_chunked = |coded: &[u8]| {
            let mut request = format!(
                "POST /up/x HTTP/1.1\r\nHost: example.test\r\nContent-Type: {FORM}\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n"
            )
            .into_bytes();
            request.extend_from_slice(&chunks(coded, 20));
            request
        };
        let short = pattern(INSPECT);
        let long = pattern(INSPECT + 1);
        let coded = noise(3000);
        let packed = gz(&coded);
        assert!(packed.len() > INSPECT);
        // A body that is short coded and long decoded: it is not decoded on this route, so it is held as it came.
        let wide = gz(&pattern(200_000));
        assert!(wide.len() <= INSPECT);
        let small = gz(&short);
        // The request, the body the upstream gets, and the fields it gets: the length, whether it is chunked, and
        // whether it is gzip.
        let cases = [
            (
                post_with_length("/up/x", &short),
                short.clone(),
                Some(INSPECT),
                false,
                false,
            ),
            // Held: the length is known, so the upstream gets it and not the chunks.
            (
                post_chunked("/up/x", &short, 300),
                short.clone(),
                Some(INSPECT),
                false,
                false,
            ),
            // A gzip body is held as it came, with its coding and the length of the coded bytes, chunked or not.
            (
                gzip_post(&small),
                small.clone(),
                Some(small.len()),
                false,
                true,
            ),
            (
                gzip_chunked(&small),
                small.clone(),
                Some(small.len()),
                false,
                true,
            ),
            (
                gzip_post(&wide),
                wide.clone(),
                Some(wide.len()),
                false,
                true,
            ),
            // One byte more is not held: it goes on in the form the client sent it.
            (
                post_chunked("/up/x", &long, 300),
                long.clone(),
                None,
                true,
                false,
            ),
            (
                gzip_post(&packed),
                packed.clone(),
                Some(packed.len()),
                false,
                true,
            ),
        ];
        for (request, want, length, chunked, gzip) in cases {
            let (addr, got) = upstream(None).await;
            let forward = ForwardConfig::of(&[addr]);
            let out = through(streaming(), ALLOW, &forward, Some(routes()), &request).await;
            assert_eq!(out.status, Some(200));
            assert!(out.seen.is_empty());
            let got = got.await.unwrap();
            assert!(got.complete);
            assert_eq!(
                got.field("content-length").map(str::to_string),
                length.map(|n| n.to_string())
            );
            assert_eq!(got.field("transfer-encoding").is_some(), chunked);
            assert_eq!(got.field("content-encoding").is_some(), gzip);
            assert_eq!(got.body(), want);
        }
    });
}

#[test]
fn a_route_may_lower_the_limit_on_the_body_and_it_is_looked_at_before_the_body_is_read() {
    run(async {
        let (addr, _got) = upstream(None).await;
        let mut forward = ForwardConfig::of(&[addr]);
        let small = RouteConfig {
            max_body: Some(100),
            ..RouteConfig::plain(0)
        };
        let rule = Rule::forward(None, Some("/small/")).unwrap();
        forward.routes = Table::new(vec![(rule, small)]).unwrap();
        // The length is over the limit of the route: 413 with no body sent, and nothing inspected.
        let head = b"POST /small/x HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 101\r\n\r\n";
        let out = through(streaming(), ALLOW, &forward, None, head).await;
        assert_eq!((out.status, out.seen.len()), (Some(413), 0));
        assert!(
            record_with(
                &out.lines,
                "rejected",
                413,
                "body over the limit of the route"
            )
            .is_some()
        );
        // A chunked body has no length to look at: it is counted as it comes.
        let out = through(
            streaming(),
            ALLOW,
            &forward,
            None,
            &post_chunked("/small/x", &pattern(101), 50),
        )
        .await;
        assert_eq!((out.status, out.seen.len()), (Some(413), 0));
        assert!(record_with(&out.lines, "rejected", 413, "body over the limit").is_some());
        // The limit itself goes through.
        let out = through(
            streaming(),
            ALLOW,
            &forward,
            None,
            &post_with_length("/small/x", &pattern(100)),
        )
        .await;
        assert_eq!((out.status, out.seen.len()), (Some(200), 1));
    });
}
