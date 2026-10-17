use std::future::Future;
use std::io;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant as StdInstant;

use http_body_util::BodyExt;
use hyper::server::conn::http1 as server;
use hyper::service::service_fn;
use tokio::net::TcpListener;
use tokio::runtime::Builder;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

use super::*;
use crate::config::ProxyConfig;
use crate::log::start_logger;

const BUDGET: usize = 4 << 20;
const PEER: &str = "203.0.113.9:5555";

type Outcome = Result<Response<OriginBody>, OriginError>;
/// A method, an answer, and the length the answer should have after the check, on the wire and as a size.
type LengthCase<'a> = (&'a str, &'a [u8], Option<&'a str>, Option<u64>);

fn config(upstream: SocketAddr) -> ProxyConfig {
    let secs = Duration::from_secs;
    ProxyConfig {
        listen: "127.0.0.1:1".parse().unwrap(),
        upstream,
        max_conns: 16,
        max_head_bytes: 8192,
        max_body: 1 << 20,
        max_body_wire: 2 << 20,
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

fn ctx(cfg: ProxyConfig) -> Ctx {
    Ctx {
        budget: Arc::new(Semaphore::new(cfg.max_buffered_bytes)),
        inspect: Arc::new(Semaphore::new(1)),
        log: start_logger().unwrap(),
        cfg,
    }
}

/// Runs a test body; a body that hangs fails the test instead of the run.
fn run<F: Future>(body: F) -> F::Output {
    Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            timeout(Duration::from_secs(60), body)
                .await
                .expect("the test hung")
        })
}

/// Far enough away to play no part.
fn far() -> Instant {
    Instant::now() + Duration::from_secs(30)
}

fn fields(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        map.append(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_bytes(value.as_bytes()).unwrap(),
        );
    }
    map
}

fn hold(ctx: &Ctx, bytes: &[u8]) -> Arc<BodyHold> {
    let permit = ctx
        .budget
        .clone()
        .try_acquire_many_owned(u32::try_from(bytes.len()).unwrap())
        .unwrap();
    Arc::new(BodyHold::new(Bytes::copy_from_slice(bytes), permit))
}

fn request(ctx: &Ctx, method: &str, pairs: &[(&str, &str)], body: &[u8]) -> Forward {
    Forward {
        method: method.parse().unwrap(),
        uri: "/p?q=1".parse().unwrap(),
        fields: fields(pairs),
        body: hold(ctx, body),
        peer: PEER.parse().unwrap(),
    }
}

/// A request with a Host field and nothing else.
fn bare(ctx: &Ctx, method: &str) -> Forward {
    request(ctx, method, &[("Host", "h.test")], b"")
}

// ---- a raw upstream: a listener on 127.0.0.1 that serves one connection ----

async fn pull(sock: &TcpStream, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        sock.readable().await?;
        match sock.try_read(buf) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            other => return other,
        }
    }
}

async fn put(sock: &TcpStream, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        sock.writable().await?;
        match sock.try_write(bytes) {
            Ok(n) => bytes = &bytes[n..],
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Everything the peer sends until it closes.
async fn read_to_end(sock: &TcpStream) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    timeout(Duration::from_secs(10), async {
        loop {
            match pull(sock, &mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => out.extend_from_slice(&buf[..n]),
            }
        }
    })
    .await
    .expect("the peer closed the connection");
    out
}

/// True when the peer closes within a few seconds.
async fn closed(sock: &TcpStream) -> bool {
    let mut buf = [0u8; 4096];
    timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(0) | Err(_) = pull(sock, &mut buf).await {
                return;
            }
        }
    })
    .await
    .is_ok()
}

async fn upstream<T, F, Fut>(serve: F) -> (SocketAddr, JoinHandle<T>)
where
    F: FnOnce(TcpStream) -> Fut + Send + 'static,
    Fut: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serving = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        serve(sock).await
    });
    (addr, serving)
}

/// The request as the upstream read it.
struct Seen {
    line: String,
    fields: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Seen {
    fn all(&self, name: &str) -> Vec<&str> {
        self.fields
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }

    fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .fields
            .iter()
            .map(|(n, _)| n.to_ascii_lowercase())
            .collect();
        names.sort();
        names.dedup();
        names
    }
}

async fn read_request(sock: &TcpStream) -> Seen {
    let mut raw = Vec::new();
    let mut buf = [0u8; 16384];
    let end = loop {
        if let Some(at) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        let n = pull(sock, &mut buf).await.unwrap();
        assert!(n > 0, "the request ended before its head did");
        raw.extend_from_slice(&buf[..n]);
    };
    let mut storage = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Request::new(&mut storage);
    assert_eq!(
        parsed.parse(&raw[..end]).unwrap(),
        httparse::Status::Complete(end)
    );
    let line = format!(
        "{} {} HTTP/1.{}",
        parsed.method.unwrap(),
        parsed.path.unwrap(),
        parsed.version.unwrap()
    );
    let fields: Vec<(String, String)> = parsed
        .headers
        .iter()
        .map(|h| {
            (
                h.name.to_string(),
                String::from_utf8_lossy(h.value).into_owned(),
            )
        })
        .collect();
    let length: usize = fields
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
        .map_or(0, |(_, v)| v.parse().unwrap());
    let mut body = raw[end..].to_vec();
    while body.len() < length {
        let n = pull(sock, &mut buf).await.unwrap();
        assert!(n > 0, "the body ended early");
        body.extend_from_slice(&buf[..n]);
    }
    Seen { line, fields, body }
}

/// Reads up to the end of the request head and no further.
async fn read_request_head(sock: &TcpStream) {
    let mut raw = Vec::new();
    let mut buf = [0u8; 1024];
    while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = pull(sock, &mut buf).await.unwrap();
        assert!(n > 0, "the request ended before its head did");
        raw.extend_from_slice(&buf[..n]);
    }
}

/// Reads the request, sends `reply`, then (with `linger`) waits for the proxy to close the connection and
/// tells whether it did; without `linger` it closes at once.
async fn answering(sock: TcpStream, reply: Vec<u8>, linger: bool) -> bool {
    read_request(&sock).await;
    put(&sock, &reply).await.unwrap();
    !linger || closed(&sock).await
}

/// Forwards a request with no body to an upstream that answers with `reply`.
async fn ask(method: &str, reply: &[u8], linger: bool) -> (Outcome, JoinHandle<bool>) {
    let reply = reply.to_vec();
    let (addr, up) = upstream(move |sock| answering(sock, reply, linger)).await;
    let ctx = ctx(config(addr));
    let out = forward(bare(&ctx, method), &ctx, far()).await;
    (out, up)
}

fn refused(out: Outcome) -> OriginError {
    match out {
        Ok(response) => panic!("passed on with status {}", response.status()),
        Err(e) => e,
    }
}

/// The data of a body and the number of trailer frames it gave.
async fn collect(mut body: OriginBody) -> (Vec<u8>, usize) {
    let mut data = Vec::new();
    let mut trailers = 0;
    while let Some(frame) = body.frame().await {
        match frame.unwrap().into_data() {
            Ok(chunk) => data.extend_from_slice(&chunk),
            Err(_) => trailers += 1,
        }
    }
    (data, trailers)
}

async fn budget_back(ctx: &Ctx) {
    timeout(Duration::from_secs(5), async {
        while ctx.budget.available_permits() != ctx.cfg.max_buffered_bytes {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the byte budget came back");
}

fn only<'a>(map: &'a HeaderMap, name: &str) -> Vec<&'a [u8]> {
    map.get_all(name)
        .iter()
        .map(HeaderValue::as_bytes)
        .collect()
}

// ---- the request that leaves ----

#[test]
fn a_stage_ends_at_its_own_length_or_at_the_end_of_the_exchange() {
    let start = Instant::now();
    let second = Duration::from_secs(1);
    assert_eq!(stage(start, second, start + 2 * second), start + second);
    assert_eq!(
        stage(start, 3 * second, start + 2 * second),
        start + 2 * second
    );
    assert_eq!(stage(start, second, start + second), start + second);
    // A sum that does not fit into the clock counts as passed, and `by` is never passed over.
    assert_eq!(stage(start, Duration::MAX, start + 2 * second), start);
    assert_eq!(
        stage(start + 2 * second, second, start + second),
        start + second
    );
}

#[test]
fn every_hop_by_hop_field_is_removed_from_the_request() {
    let peer: IpAddr = "203.0.113.9".parse().unwrap();
    for name in REQUEST_HOP {
        let sent = fields(&[("Host", "h.test"), (name, "x"), ("X-Keep", "1")]);
        let out = forwarded_fields(sent, peer).unwrap();
        if name == "connection" {
            assert_eq!(only(&out, name), [b"close"], "{name}");
        } else {
            assert!(out.get(name).is_none(), "{name}");
        }
        assert_eq!(only(&out, "x-keep"), [b"1"], "{name}");
        assert_eq!(only(&out, "host"), [b"h.test"], "{name}");
    }
}

#[test]
fn the_names_are_collected_before_the_removal_and_the_additions_come_after_it() {
    let peer: IpAddr = "203.0.113.9".parse().unwrap();
    let sent = fields(&[
        ("Host", "h.test"),
        ("Connection", "X-Forwarded-For, x-forwarded-host"),
        ("Connection", " x-forwarded-proto ,\tX-Hop, Connection"),
        ("X-Forwarded-For", "198.51.100.1"),
        ("X-Forwarded-Host", "evil.test"),
        ("X-Forwarded-Proto", "https"),
        ("X-Hop", "1"),
        ("X-Keep", "k"),
    ]);
    let out = forwarded_fields(sent, peer).unwrap();
    // The client's own lines are gone with the names it listed; ours come after, and listing a name does not
    // take ours away, not even for `Connection` itself.
    assert_eq!(only(&out, "x-forwarded-for"), [b"203.0.113.9"]);
    assert_eq!(only(&out, "x-forwarded-host"), [b"h.test"]);
    assert_eq!(only(&out, "x-forwarded-proto"), [b"http"]);
    assert_eq!(only(&out, "connection"), [b"close"]);
    assert!(out.get("x-hop").is_none());
    assert_eq!(only(&out, "x-keep"), [b"k"]);
    assert_eq!(only(&out, "host"), [b"h.test"]);
    assert_eq!(out.len(), 6);
}

#[test]
fn names_that_are_not_listed_stay_and_are_replaced_only_by_the_forwarding_fields() {
    let peer: IpAddr = "203.0.113.9".parse().unwrap();
    let sent = fields(&[
        ("Host", "h.test"),
        ("X-Forwarded-Host", "evil.test"),
        ("X-Forwarded-Host", "worse.test"),
        ("X-Forwarded-Proto", "https"),
        ("X-Keep", "a"),
        ("Content-Length", "3"),
        ("X-Keep", "b"),
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("X-Keep", "a"),
    ]);
    let out = forwarded_fields(sent, peer).unwrap();
    assert_eq!(only(&out, "x-forwarded-host"), [b"h.test"]);
    assert_eq!(only(&out, "x-forwarded-proto"), [b"http"]);
    assert_eq!(only(&out, "x-keep"), [b"a", b"b", b"a"]);
    assert_eq!(only(&out, "content-length"), [b"3"]);
    assert_eq!(
        only(&out, "content-type"),
        [b"application/x-www-form-urlencoded"]
    );
    // Without a Host there is nothing to put in, and the client's value does not stay.
    let out = forwarded_fields(fields(&[("X-Forwarded-Host", "evil.test")]), peer).unwrap();
    assert!(out.get("x-forwarded-host").is_none());
}

#[test]
fn x_forwarded_for_joins_the_lines_in_order_and_ends_with_the_peer() {
    let v4: IpAddr = "203.0.113.9".parse().unwrap();
    let cases: [(&[&str], IpAddr, &[u8]); 6] = [
        (&[], v4, b"203.0.113.9"),
        (&["198.51.100.1"], v4, b"198.51.100.1, 203.0.113.9"),
        (
            &["198.51.100.1", "198.51.100.2, 198.51.100.3"],
            v4,
            b"198.51.100.1, 198.51.100.2, 198.51.100.3, 203.0.113.9",
        ),
        (&["a\u{e9}"], v4, "a\u{e9}, 203.0.113.9".as_bytes()),
        // The address of the peer is written in its canonical form.
        (&[], "::ffff:203.0.113.9".parse().unwrap(), b"203.0.113.9"),
        (&["x"], "2001:db8::1".parse().unwrap(), b"x, 2001:db8::1"),
    ];
    for (lines, peer, expected) in cases {
        let mut pairs = vec![("Host", "h.test")];
        pairs.extend(lines.iter().map(|line| ("X-Forwarded-For", *line)));
        let out = forwarded_fields(fields(&pairs), peer).unwrap();
        assert_eq!(only(&out, "x-forwarded-for"), [expected], "{lines:?}");
    }
    // A line that is not text is joined as it is.
    let mut sent = fields(&[("Host", "h.test")]);
    sent.append(
        X_FORWARDED_FOR.clone(),
        HeaderValue::from_bytes(b"\xff\xfe").unwrap(),
    );
    let out = forwarded_fields(sent, v4).unwrap();
    assert_eq!(only(&out, "x-forwarded-for"), [b"\xff\xfe, 203.0.113.9"]);
}

#[test]
fn the_upstream_gets_the_inspected_request_with_the_listed_changes() {
    run(async {
        let (addr, up) = upstream(|sock| async move {
            let seen = read_request(&sock).await;
            put(&sock, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
            seen
        })
        .await;
        let ctx = ctx(config(addr));
        let f = request(
            &ctx,
            "POST",
            &[
                ("Host", "h.test"),
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Content-Length", "9"),
                ("Connection", "X-Forwarded-For, X-Hop, Keep-Alive"),
                ("Connection", "close"),
                ("X-Forwarded-For", "198.51.100.1"),
                ("X-Forwarded-Host", "evil.test"),
                ("X-Forwarded-Proto", "https"),
                ("X-Hop", "1"),
                ("X-Keep", "a"),
                ("X-Keep", "b"),
                ("Keep-Alive", "timeout=5"),
                ("Proxy-Connection", "keep-alive"),
                ("Proxy-Authenticate", "x"),
                ("Proxy-Authorization", "y"),
                ("TE", "trailers"),
                ("Trailer", "Expires"),
                ("Transfer-Encoding", "chunked"),
                ("Upgrade", "websocket"),
                ("Expect", "100-continue"),
            ],
            b"a=1&b=%00",
        );
        let response = forward(f, &ctx, far()).await.unwrap();
        let (data, trailers) = collect(response.into_body()).await;
        assert_eq!((data.as_slice(), trailers), (&b"ok"[..], 0));
        let seen = up.await.unwrap();
        assert_eq!(seen.line, "POST /p?q=1 HTTP/1.1");
        assert_eq!(seen.body, b"a=1&b=%00");
        assert_eq!(
            seen.names(),
            [
                "connection",
                "content-length",
                "content-type",
                "host",
                "x-forwarded-for",
                "x-forwarded-host",
                "x-forwarded-proto",
                "x-keep",
            ]
        );
        assert_eq!(seen.all("connection"), ["close"]);
        assert_eq!(seen.all("x-forwarded-for"), ["203.0.113.9"]);
        assert_eq!(seen.all("x-forwarded-host"), ["h.test"]);
        assert_eq!(seen.all("x-forwarded-proto"), ["http"]);
        assert_eq!(seen.all("x-keep"), ["a", "b"]);
        assert_eq!(seen.all("host"), ["h.test"]);
        assert_eq!(seen.all("content-length"), ["9"]);
        // The names are written in the form hyper uses for the inspection as well.
        assert!(seen.fields.iter().any(|(n, _)| n == "X-Forwarded-For"));
        assert!(seen.fields.iter().any(|(n, _)| n == "Content-Length"));
        budget_back(&ctx).await;
    });
}

#[test]
fn a_request_with_no_body_gets_no_framing_and_nothing_else_added() {
    run(async {
        let (addr, up) = upstream(|sock| async move {
            let seen = read_request(&sock).await;
            put(&sock, b"HTTP/1.1 204 No Content\r\n\r\n")
                .await
                .unwrap();
            seen
        })
        .await;
        let ctx = ctx(config(addr));
        let response = forward(bare(&ctx, "GET"), &ctx, far()).await.unwrap();
        assert_eq!(response.status(), 204);
        let seen = up.await.unwrap();
        assert_eq!(seen.line, "GET /p?q=1 HTTP/1.1");
        assert_eq!(
            seen.names(),
            [
                "connection",
                "host",
                "x-forwarded-for",
                "x-forwarded-host",
                "x-forwarded-proto"
            ]
        );
        assert!(seen.body.is_empty());
    });
}

#[test]
fn the_body_arrives_byte_for_byte_and_its_budget_comes_back_after_the_exchange() {
    run(async {
        let body: Vec<u8> = (0..100_000u32).map(|i| (i * 31 % 256) as u8).collect();
        let (addr, up) = upstream(|sock| async move {
            let seen = read_request(&sock).await;
            put(&sock, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            seen
        })
        .await;
        let ctx = ctx(config(addr));
        let f = request(
            &ctx,
            "POST",
            &[
                ("Host", "h.test"),
                ("Content-Type", "multipart/form-data"),
                ("Content-Length", "100000"),
            ],
            &body,
        );
        assert_eq!(ctx.budget.available_permits(), BUDGET - body.len());
        let response = forward(f, &ctx, far()).await.unwrap();
        assert_eq!(response.status(), 200);
        let seen = up.await.unwrap();
        assert_eq!(seen.body, body);
        assert_eq!(seen.all("content-length"), ["100000"]);
        assert!(seen.all("transfer-encoding").is_empty());
        drop(response);
        budget_back(&ctx).await;
    });
}

#[test]
fn the_budget_comes_back_on_every_way_out() {
    run(async {
        // Refused connection.
        let addr = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let ctx1 = ctx(config(addr));
        let f = request(&ctx1, "POST", &[("Host", "h.test")], &[7u8; 5000]);
        assert_eq!(
            refused(forward(f, &ctx1, far()).await),
            OriginError::Connect
        );
        budget_back(&ctx1).await;
        // An answer that is refused.
        let (addr, up) =
            upstream(|sock| answering(sock, b"HTTP/1.1 600 X\r\n\r\n".to_vec(), true)).await;
        let ctx2 = ctx(config(addr));
        let f = request(&ctx2, "POST", &[("Host", "h.test")], &[7u8; 5000]);
        assert_eq!(
            refused(forward(f, &ctx2, far()).await),
            OriginError::Invalid
        );
        budget_back(&ctx2).await;
        assert!(up.await.unwrap());
        // An upstream that does not answer in time.
        let (addr, up) = upstream(|sock| async move {
            read_request(&sock).await;
            closed(&sock).await
        })
        .await;
        let mut cfg = config(addr);
        cfg.upstream_header = Duration::from_millis(200);
        let ctx3 = ctx(cfg);
        let f = request(&ctx3, "POST", &[("Host", "h.test")], &[7u8; 5000]);
        assert_eq!(refused(forward(f, &ctx3, far()).await), OriginError::Head);
        budget_back(&ctx3).await;
        assert!(up.await.unwrap());
    });
}

#[test]
fn an_answer_that_comes_before_the_body_was_sent_ends_the_writing_and_returns_the_budget() {
    run(async {
        // The upstream answers after the head and never reads the body, so most of it stays unsent.
        let (addr, up) = upstream(|sock| async move {
            read_request_head(&sock).await;
            put(&sock, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            closed(&sock).await
        })
        .await;
        let mut cfg = config(addr);
        cfg.max_buffered_bytes = 96 << 20;
        let ctx = ctx(cfg);
        let body = vec![1u8; 64 << 20];
        let pairs = [("Host", "h.test"), ("Content-Length", "67108864")];
        let response = forward(request(&ctx, "POST", &pairs, &body), &ctx, far())
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        // The body is not kept for a write that is no longer wanted, though the answer is still in use.
        budget_back(&ctx).await;
        drop(response);
        assert!(up.await.unwrap());
    });
}

// ---- the answer ----

fn parts(status: u16, lines: &[(&str, &str)]) -> Parts {
    let mut builder = Response::builder().status(status);
    for (name, value) in lines {
        builder = builder.header(*name, *value);
    }
    builder.body(()).unwrap().into_parts().0
}

fn checked(status: u16, lines: &[(&str, &str)]) -> Result<Parts, OriginError> {
    let mut head = parts(status, lines);
    check_head(&mut head, false).map(|()| head)
}

#[test]
fn only_200_to_599_is_passed_on() {
    for status in [100, 101, 102, 199, 600, 999] {
        assert_eq!(
            checked(status, &[]).err(),
            Some(OriginError::Invalid),
            "{status}"
        );
    }
    for status in [200, 204, 299, 304, 399, 400, 599] {
        assert!(checked(status, &[]).is_ok(), "{status}");
    }
}

#[test]
fn the_status_is_checked_on_the_wire() {
    run(async {
        for (status, passes) in [(200, true), (599, true), (600, false)] {
            let reply = format!("HTTP/1.1 {status} Reason\r\nContent-Length: 0\r\n\r\n");
            let (out, up) = ask("GET", reply.as_bytes(), true).await;
            if passes {
                assert_eq!(out.unwrap().status(), status);
            } else {
                assert_eq!(refused(out), OriginError::Invalid);
                assert!(up.await.unwrap(), "the upstream connection was dropped");
            }
        }
        // 101 is a final answer for hyper and is refused here.
        let reply =
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: x\r\n\r\n";
        let (out, up) = ask("GET", reply, true).await;
        assert_eq!(refused(out), OriginError::Invalid);
        assert!(up.await.unwrap());
        // An informational answer is read over and the final one decides, 199 included.
        let reply = b"HTTP/1.1 199 Odd\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let (out, _) = ask("GET", reply, true).await;
        assert_eq!(out.unwrap().status(), 200);
        // An informational answer and no final one is no head.
        let (out, _) = ask("GET", b"HTTP/1.1 199 Odd\r\n\r\n", false).await;
        assert_eq!(refused(out), OriginError::Head);
    });
}

#[test]
fn framing_must_be_one_chunked_line_or_one_line_of_digits() {
    let length = |value: &str| checked(200, &[("Content-Length", value)]).err();
    let coding = |value: &str| checked(200, &[("Transfer-Encoding", value)]).err();
    // Content-Length: the boundary of the digits and of 64 bits.
    for value in ["0", "5", "007", "18446744073709551615"] {
        assert_eq!(length(value), None, "{value:?}");
    }
    for value in [
        "",
        " ",
        "+5",
        "-5",
        "5 5",
        "5,5",
        "5, 5",
        "0x5",
        "5a",
        "18446744073709551616",
    ] {
        assert_eq!(length(value), Some(OriginError::Invalid), "{value:?}");
    }
    let twice = [("Content-Length", "5"), ("Content-Length", "5")];
    assert_eq!(checked(200, &twice).err(), Some(OriginError::Invalid));
    let differ = [("Content-Length", "5"), ("Content-Length", "6")];
    assert_eq!(checked(200, &differ).err(), Some(OriginError::Invalid));
    // Transfer-Encoding: exactly one line that says chunked, in any case, and no length.
    for value in ["chunked", "Chunked", "CHUNKED"] {
        assert_eq!(coding(value), None, "{value:?}");
    }
    for value in [
        "",
        "gzip",
        "gzip, chunked",
        "chunked, gzip",
        "chunked,",
        "identity",
    ] {
        assert_eq!(coding(value), Some(OriginError::Invalid), "{value:?}");
    }
    let twice = [
        ("Transfer-Encoding", "chunked"),
        ("Transfer-Encoding", "chunked"),
    ];
    assert_eq!(checked(200, &twice).err(), Some(OriginError::Invalid));
    let both = [("Transfer-Encoding", "chunked"), ("Content-Length", "5")];
    assert_eq!(checked(200, &both).err(), Some(OriginError::Invalid));
    // The same for the statuses and requests that have no body, where hyper looks at no framing at all.
    for status in [204, 304] {
        assert_eq!(
            checked(status, &[("Content-Length", "x")]).err(),
            Some(OriginError::Invalid)
        );
    }
    let mut head = parts(200, &[("Content-Length", "5, 5")]);
    assert_eq!(check_head(&mut head, true), Err(OriginError::Invalid));
}

#[test]
fn framing_is_checked_on_the_wire() {
    run(async {
        let cases: [(&[u8], &str, Option<OriginError>); 8] = [
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n",
                "GET",
                Some(OriginError::Invalid),
            ),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
                "GET",
                Some(OriginError::Invalid),
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 5, 5\r\n\r\nhello",
                "GET",
                Some(OriginError::Invalid),
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello",
                "GET",
                Some(OriginError::Invalid),
            ),
            (
                b"HTTP/1.1 304 Not Modified\r\nContent-Length: abc\r\n\r\n",
                "GET",
                Some(OriginError::Invalid),
            ),
            (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n0\r\n\r\n", "GET", None),
            (b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", "GET", None),
            (b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", "HEAD", None),
        ];
        for (reply, method, expected) in cases {
            let (out, up) = ask(method, reply, true).await;
            match expected {
                Some(error) => {
                    assert_eq!(refused(out), error, "{}", String::from_utf8_lossy(reply));
                    assert!(up.await.unwrap(), "the upstream connection was dropped");
                }
                None => assert_eq!(out.unwrap().status(), 200),
            }
        }
    });
}

#[test]
fn connection_lines_must_be_token_lists_that_name_nothing_the_answer_keeps() {
    let line = |value: &str| checked(200, &[("Connection", value)]).err();
    for value in [
        "close",
        "close, X-Hop",
        " keep-alive ,\tX-Hop ",
        "x-content-length, content-lengths",
    ] {
        assert_eq!(line(value), None, "{value:?}");
    }
    for value in [
        "", ",", "a,,b", "a,", ",a", "a b", "a;b", "\"a\"", "a\u{e9}",
    ] {
        assert_eq!(line(value), Some(OriginError::Invalid), "{value:?}");
    }
    for value in [
        "content-length",
        "Content-Type",
        "CONTENT-ENCODING",
        "content-range",
        "close, Content-Range",
        "x-hop,\tContent-Length ",
    ] {
        assert_eq!(line(value), Some(OriginError::Invalid), "{value:?}");
    }
    // Any line decides, not only the first.
    let second = [("Connection", "close"), ("Connection", "content-type")];
    assert_eq!(checked(200, &second).err(), Some(OriginError::Invalid));
    let second = [("Connection", "close"), ("Connection", "a,,b")];
    assert_eq!(checked(200, &second).err(), Some(OriginError::Invalid));
    // A long list is read to its end: the names are removed, and a name at the very end still decides.
    let names = "a,".repeat(4000);
    let mut head = parts(
        200,
        &[("Connection", &format!("{names}x-hop")), ("X-Hop", "1")],
    );
    check_head(&mut head, false).unwrap();
    assert!(head.headers.is_empty());
    let last = format!("{names}content-type");
    assert_eq!(
        checked(200, &[("Connection", &last)]).err(),
        Some(OriginError::Invalid)
    );
}

#[test]
fn connection_lines_are_checked_on_the_wire() {
    run(async {
        let cases: [(&[u8], Option<OriginError>); 4] = [
            (
                b"HTTP/1.1 200 OK\r\nConnection: close, Content-Encoding\r\nContent-Length: 0\r\n\r\n",
                Some(OriginError::Invalid),
            ),
            (
                b"HTTP/1.1 200 OK\r\nConnection: a,,b\r\nContent-Length: 0\r\n\r\n",
                Some(OriginError::Invalid),
            ),
            (
                b"HTTP/1.1 200 OK\r\nConnection: close, X-Hop\r\nContent-Length: 0\r\n\r\n",
                None,
            ),
            (b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", None),
        ];
        for (reply, expected) in cases {
            let (out, up) = ask("GET", reply, true).await;
            match expected {
                Some(error) => {
                    assert_eq!(refused(out), error);
                    assert!(up.await.unwrap());
                }
                None => assert_eq!(out.unwrap().status(), 200),
            }
        }
    });
}

#[test]
fn the_answer_loses_what_belongs_to_the_upstream_connection_and_keeps_the_rest() {
    let mut head = parts(
        200,
        &[
            ("Connection", "close, X-Hop"),
            ("X-Hop", "1"),
            ("Keep-Alive", "timeout=1"),
            ("Proxy-Connection", "x"),
            ("Proxy-Authenticate", "y"),
            ("TE", "trailers"),
            ("Trailer", "Expires"),
            ("Upgrade", "h2c"),
            ("Transfer-Encoding", "chunked"),
            ("X-Keep", "a"),
            ("Set-Cookie", "c=1"),
            ("X-Keep", "b"),
            ("Set-Cookie", "d=2"),
        ],
    );
    check_head(&mut head, false).unwrap();
    assert_eq!(head.headers.len(), 4);
    assert_eq!(only(&head.headers, "x-keep"), [b"a", b"b"]);
    assert_eq!(only(&head.headers, "set-cookie"), [b"c=1", b"d=2"]);
    // Nothing but the version of this proxy and no extension of the upstream's answer goes on.
    let mut head = Response::builder()
        .version(Version::HTTP_10)
        .extension(7u32)
        .extension(hyper::ext::ReasonPhrase::from_static(b"Weird Reason"))
        .body(())
        .unwrap()
        .into_parts()
        .0;
    check_head(&mut head, false).unwrap();
    assert_eq!(head.version, Version::HTTP_11);
    assert!(head.extensions.get::<u32>().is_none());
    assert!(head.extensions.get::<hyper::ext::ReasonPhrase>().is_none());
}

#[test]
fn content_length_stays_for_head_and_304_and_goes_otherwise() {
    let kept = |status: u16, head_request: bool| {
        let mut head = parts(status, &[("Content-Length", "5")]);
        check_head(&mut head, head_request).unwrap();
        only(&head.headers, "content-length").len()
    };
    assert_eq!(kept(200, true), 1);
    assert_eq!(kept(304, false), 1);
    assert_eq!(kept(304, true), 1);
    assert_eq!(kept(200, false), 0);
    assert_eq!(kept(204, false), 0);
    assert_eq!(kept(404, false), 0);
}

/// Reads the bytes of an upstream through `forward` and checks the head and the body that it returns, not what
/// a client reads: `hyper_writes_the_kept_length_only_in_an_answer_to_head` serves such a response.
#[test]
fn forward_keeps_the_upstream_length_in_the_head_it_returns_only_for_head_and_304() {
    run(async {
        let cases: [LengthCase; 4] = [
            (
                "HEAD",
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n",
                Some("5"),
                Some(0),
            ),
            (
                "GET",
                b"HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\n\r\n",
                Some("5"),
                Some(0),
            ),
            (
                "GET",
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
                None,
                Some(5),
            ),
            (
                "GET",
                b"HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n",
                None,
                Some(0),
            ),
        ];
        for (method, reply, length, exact) in cases {
            let (out, _) = ask(method, reply, true).await;
            let response = out.unwrap();
            assert_eq!(
                response
                    .headers()
                    .get("content-length")
                    .map(HeaderValue::as_bytes),
                length.map(str::as_bytes),
                "{method} {}",
                String::from_utf8_lossy(reply)
            );
            // What hyper sends on is decided by the size of the body.
            assert_eq!(response.body().size_hint().exact(), exact);
        }
    });
}

/// Serves `response` through hyper's server and returns what a client reads, and whether the server future
/// panicked (hyper's debug assertions are live in a test build).
async fn through_server(method: &str, response: Response<OriginBody>) -> (Vec<u8>, bool) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cell = Arc::new(Mutex::new(Some(response)));
    let serving = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        let mut http = server::Builder::new();
        http.keep_alive(false).title_case_headers(true);
        let service = service_fn(move |_req| {
            let response = cell.lock().unwrap().take().unwrap();
            async move { Ok::<_, Infallible>(response) }
        });
        http.serve_connection(TokioIo::new(sock), service).await
    });
    let client = TcpStream::connect(addr).await.unwrap();
    let request = format!("{method} / HTTP/1.1\r\nHost: h.test\r\n\r\n");
    put(&client, request.as_bytes()).await.unwrap();
    let raw = read_to_end(&client).await;
    let panicked = serving.await.is_err_and(|e| e.is_panic());
    (raw, panicked)
}

fn lowercase(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw).to_ascii_lowercase()
}

#[test]
fn hyper_writes_the_kept_length_only_in_an_answer_to_head() {
    run(async {
        // hyper's server writes the length that a HEAD answer carries, whatever its status, and for a 200 answer
        // the length of the body it is given. For a 204 or 304 answer to any other request it writes none.
        let cases: [(&str, &[u8], &str, bool); 7] = [
            (
                "HEAD",
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n",
                "HTTP/1.1 200",
                true,
            ),
            (
                "GET",
                b"HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\nETag: x\r\n\r\n",
                "HTTP/1.1 304",
                false,
            ),
            (
                "GET",
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
                "HTTP/1.1 200",
                true,
            ),
            (
                "GET",
                b"HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n",
                "HTTP/1.1 204",
                false,
            ),
            (
                "HEAD",
                b"HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\n\r\n",
                "HTTP/1.1 304",
                true,
            ),
            (
                "HEAD",
                b"HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n",
                "HTTP/1.1 204",
                true,
            ),
            (
                "HEAD",
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 5\r\n\r\n",
                "HTTP/1.1 404",
                true,
            ),
        ];
        for (method, reply, status_line, has_length) in cases {
            let (out, _) = ask(method, reply, true).await;
            let (raw, panicked) = through_server(method, out.unwrap()).await;
            let text = lowercase(&raw);
            assert!(
                !panicked,
                "hyper's server panicked for {method} {status_line}"
            );
            assert!(
                text.starts_with(&status_line.to_ascii_lowercase()),
                "{text}"
            );
            assert_eq!(text.contains("content-length: 5\r\n"), has_length, "{text}");
            assert!(!text.contains("transfer-encoding"), "{text}");
            assert_eq!(
                text.ends_with("hello"),
                method == "GET" && status_line.ends_with("200")
            );
        }
    });
}

#[test]
fn an_answer_of_an_older_version_is_passed_on_in_this_proxys_version() {
    run(async {
        let reply = b"HTTP/1.0 200 OK\r\nX-A: b\r\n\r\nbody";
        let (out, _) = ask("GET", reply, false).await;
        let response = out.unwrap();
        assert_eq!(response.version(), Version::HTTP_11);
        assert_eq!(response.headers().get("x-a").unwrap(), "b");
        let (data, trailers) = collect(response.into_body()).await;
        assert_eq!((data.as_slice(), trailers), (&b"body"[..], 0));
        // On the wire the client is told this proxy's version and the usual reason of the status; the
        // version and the reason of the upstream's answer are not passed on.
        let (out, _) = ask("GET", reply, false).await;
        let (raw, panicked) = through_server("GET", out.unwrap()).await;
        assert!(!panicked);
        assert!(raw.starts_with(b"HTTP/1.1 200 OK\r\n"), "{raw:?}");
        let reply = b"HTTP/1.1 200 Weird Reason\r\nContent-Length: 2\r\n\r\nok";
        let (out, _) = ask("GET", reply, false).await;
        let (raw, panicked) = through_server("GET", out.unwrap()).await;
        assert!(!panicked);
        assert!(raw.starts_with(b"HTTP/1.1 200 OK\r\n"), "{raw:?}");
    });
}

#[test]
fn the_body_streams_and_its_trailers_are_dropped() {
    run(async {
        let (addr, up) = upstream(|sock| async move {
            read_request(&sock).await;
            put(
                &sock,
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-T\r\nX-A: b\r\n\r\n5\r\nhello\r\n",
            )
            .await
            .unwrap();
            sleep(Duration::from_millis(100)).await;
            put(&sock, b"5\r\nworld\r\n0\r\nX-T: 1\r\n\r\n").await.unwrap();
            closed(&sock).await
        })
        .await;
        let ctx = ctx(config(addr));
        let response = forward(bare(&ctx, "GET"), &ctx, far()).await.unwrap();
        assert!(response.headers().get("transfer-encoding").is_none());
        assert!(response.headers().get("trailer").is_none());
        assert_eq!(response.headers().get("x-a").unwrap(), "b");
        let (data, trailers) = collect(response.into_body()).await;
        assert_eq!((data.as_slice(), trailers), (&b"helloworld"[..], 0));
        assert!(up.await.unwrap(), "the connection ended with the body");
    });
}

fn is_send<T: Send>(_: &T) {}

#[test]
fn the_exchange_and_its_body_can_move_between_threads() {
    run(async {
        let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let (out, _) = ask("GET", reply, true).await;
        is_send(&out);
        drop(out);
        // Spawned as a whole, the way a connection is.
        let ctx = Arc::new(ctx(config("127.0.0.1:1".parse().unwrap())));
        is_send(&forward(bare(&ctx, "GET"), &ctx, far()));
        let spawned =
            tokio::spawn(async move { forward(bare(&ctx, "GET"), &ctx, far()).await.is_err() });
        assert!(spawned.await.unwrap());
    });
}

#[test]
fn dropping_the_body_ends_the_upstream_connection() {
    run(async {
        let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nabc";
        let (out, up) = ask("GET", reply, true).await;
        let response = out.unwrap();
        assert_eq!(response.body().size_hint().exact(), Some(100));
        drop(response);
        assert!(up.await.unwrap(), "the upstream saw the connection close");
    });
}

// ---- limits and failures before the head ----

#[test]
fn the_bytes_up_to_the_final_head_are_capped_as_a_whole() {
    run(async {
        let mut reply = Vec::new();
        for _ in 0..60 {
            reply.extend_from_slice(b"HTTP/1.1 102 Processing\r\n\r\n");
        }
        reply.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        // The cap is exactly the bytes sent: nothing is over. One byte less and the last byte is.
        for (cap, passes) in [(reply.len(), true), (reply.len() - 1, false)] {
            let r = reply.clone();
            let (addr, up) = upstream(move |sock| answering(sock, r, true)).await;
            let mut cfg = config(addr);
            cfg.upstream_head_wire = cap;
            let ctx = ctx(cfg);
            let out = forward(bare(&ctx, "GET"), &ctx, far()).await;
            if passes {
                let response = out.unwrap();
                assert_eq!(response.status(), 200);
                drop(response);
            } else {
                assert_eq!(refused(out), OriginError::Head);
            }
            assert!(
                up.await.unwrap(),
                "the upstream connection is closed (cap {cap})"
            );
        }
    });
}

#[test]
fn a_head_that_ends_at_the_cap_with_its_body_already_in_flight_is_not_passed_on() {
    run(async {
        let mut reply = Vec::new();
        for _ in 0..60 {
            reply.extend_from_slice(b"HTTP/1.1 102 Processing\r\n\r\n");
        }
        reply.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Length: 3000\r\n\r\n");
        let cap = reply.len();
        reply.extend_from_slice(&[b'x'; 3000]);
        let (addr, up) = upstream(move |sock| answering(sock, reply, true)).await;
        let mut cfg = config(addr);
        cfg.upstream_head_wire = cap;
        let ctx = ctx(cfg);
        let out = forward(bare(&ctx, "GET"), &ctx, far()).await;
        assert_eq!(refused(out), OriginError::Head);
        assert!(up.await.unwrap(), "the upstream connection is closed");
    });
}

#[test]
fn the_cap_is_lifted_once_the_head_is_here() {
    run(async {
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 3000\r\n\r\n";
        let (addr, up) = upstream(move |sock| async move {
            read_request(&sock).await;
            put(&sock, head).await.unwrap();
            sleep(Duration::from_millis(100)).await;
            put(&sock, &[b'x'; 3000]).await.unwrap();
            closed(&sock).await
        })
        .await;
        // The head fits and the body does not: only a cap that is lifted lets it through.
        let mut cfg = config(addr);
        cfg.upstream_head_wire = head.len() + 1500;
        let ctx = ctx(cfg);
        let response = forward(bare(&ctx, "GET"), &ctx, far()).await.unwrap();
        let (data, _) = collect(response.into_body()).await;
        assert_eq!(data.len(), 3000);
        assert!(up.await.unwrap());
    });
}

#[test]
fn a_refused_connection_is_connect() {
    run(async {
        let addr = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let ctx = ctx(config(addr));
        let out = forward(bare(&ctx, "GET"), &ctx, far()).await;
        assert_eq!(refused(out), OriginError::Connect);
    });
}

#[test]
fn a_stage_that_is_already_over_starts_nothing() {
    run(async {
        // The end of the exchange has passed, or the connect stage has no time: no connection is made.
        let attempted = Arc::new(AtomicBool::new(false));
        let seen = attempted.clone();
        let (addr, up) = upstream(move |_sock| async move {
            seen.store(true, Ordering::SeqCst);
        })
        .await;
        let ctx1 = ctx(config(addr));
        let out = forward(bare(&ctx1, "GET"), &ctx1, Instant::now()).await;
        assert_eq!(refused(out), OriginError::Connect);
        let mut cfg = config(addr);
        cfg.upstream_connect = Duration::ZERO;
        let ctx2 = ctx(cfg);
        let out = forward(bare(&ctx2, "GET"), &ctx2, far()).await;
        assert_eq!(refused(out), OriginError::Connect);
        let mut cfg = config(addr);
        cfg.upstream_connect = Duration::MAX;
        let ctx3 = ctx(cfg);
        let out = forward(bare(&ctx3, "GET"), &ctx3, Instant::now()).await;
        assert_eq!(refused(out), OriginError::Connect);
        sleep(Duration::from_millis(100)).await;
        assert!(!attempted.load(Ordering::SeqCst), "a connection was made");
        up.abort();
        // The head stage has no time: the connection is made and nothing is sent over it.
        let (addr, up) = upstream(|sock| async move { read_to_end(&sock).await }).await;
        let mut cfg = config(addr);
        cfg.upstream_header = Duration::ZERO;
        let ctx4 = ctx(cfg);
        let f = request(&ctx4, "POST", &[("Host", "h.test")], b"abc");
        assert_eq!(refused(forward(f, &ctx4, far()).await), OriginError::Head);
        assert!(up.await.unwrap().is_empty(), "something was sent");
        budget_back(&ctx4).await;
    });
}

#[test]
fn an_upstream_that_never_answers_ends_at_the_deadline_with_head() {
    run(async {
        // The stage deadline decides.
        let (addr, up) = upstream(|sock| async move {
            read_request(&sock).await;
            closed(&sock).await
        })
        .await;
        let mut cfg = config(addr);
        cfg.upstream_header = Duration::from_millis(400);
        let ctx1 = ctx(cfg);
        let start = StdInstant::now();
        let out = forward(bare(&ctx1, "GET"), &ctx1, far()).await;
        let took = start.elapsed();
        assert_eq!(refused(out), OriginError::Head);
        assert!(took >= Duration::from_millis(350), "{took:?}");
        assert!(took < Duration::from_secs(5), "{took:?}");
        assert!(up.await.unwrap(), "the upstream connection was dropped");
        // The end of the exchange decides, and the longer stage does not extend it.
        let (addr, up) = upstream(|sock| async move {
            read_request(&sock).await;
            closed(&sock).await
        })
        .await;
        let mut cfg = config(addr);
        cfg.upstream_header = Duration::from_secs(30);
        let ctx2 = ctx(cfg);
        let by = Instant::now() + Duration::from_millis(300);
        let start = StdInstant::now();
        let out = forward(bare(&ctx2, "GET"), &ctx2, by).await;
        let took = start.elapsed();
        assert_eq!(refused(out), OriginError::Head);
        assert!(took >= Duration::from_millis(250), "{took:?}");
        assert!(took < Duration::from_secs(5), "{took:?}");
        assert!(up.await.unwrap());
    });
}

#[test]
fn an_idle_upstream_ends_with_head_when_the_idle_limit_is_shorter_than_the_stage() {
    run(async {
        let (addr, up) = upstream(|sock| async move {
            read_request(&sock).await;
            closed(&sock).await
        })
        .await;
        let mut cfg = config(addr);
        cfg.response_idle = Duration::from_millis(300);
        let ctx = ctx(cfg);
        let start = StdInstant::now();
        let out = forward(bare(&ctx, "GET"), &ctx, far()).await;
        let took = start.elapsed();
        assert_eq!(refused(out), OriginError::Head);
        assert!(took >= Duration::from_millis(250), "{took:?}");
        assert!(took < Duration::from_secs(5), "{took:?}");
        assert!(up.await.unwrap());
    });
}

#[test]
fn a_failure_is_head_once_an_answer_began_and_send_before() {
    run(async {
        // Nothing of an answer: the upstream closes after reading the request.
        let (out, _) = ask("GET", b"", false).await;
        assert_eq!(refused(out), OriginError::Send);
        // Part of a status line, then the end.
        let (out, _) = ask("GET", b"HTTP/1.1 20", false).await;
        assert_eq!(refused(out), OriginError::Head);
        // Bytes that are not an answer.
        let (out, _) = ask("GET", b"NOT HTTP\r\n\r\n", false).await;
        assert_eq!(refused(out), OriginError::Head);
        // A head that is longer than hyper takes.
        let mut long = b"HTTP/1.1 200 OK\r\nX-Long: ".to_vec();
        long.extend_from_slice(&[b'a'; 9000]);
        long.extend_from_slice(b"\r\nContent-Length: 0\r\n\r\n");
        let (out, _) = ask("GET", &long, false).await;
        assert_eq!(refused(out), OriginError::Head);
    });
}
