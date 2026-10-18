use std::future::Future;
use std::io;
use std::time::Instant as StdInstant;

use http_body_util::BodyExt;
use tokio::net::TcpListener;
use tokio::runtime::Builder;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

use super::*;
use crate::config::ProxyConfig;
use crate::log::start_logger;
use crate::rules::routes::{Routes, SharedRoutes};

const BUDGET: usize = 4 << 20;
const PEER: &str = "203.0.113.9:5555";

type Outcome = Result<Response<OriginBody>, OriginError>;

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
        routes: SharedRoutes::new(Routes::default()),
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
fn x_forwarded_for_joins_the_lines_in_order_and_ends_with_the_peer() {
    let v4: IpAddr = "203.0.113.9".parse().unwrap();
    let cases: [(&[&str], IpAddr, &[u8]); 4] = [
        (&[], v4, b"203.0.113.9"),
        (&["198.51.100.1"], v4, b"198.51.100.1, 203.0.113.9"),
        (
            &["198.51.100.1", "198.51.100.2, 198.51.100.3"],
            v4,
            b"198.51.100.1, 198.51.100.2, 198.51.100.3, 203.0.113.9",
        ),
        // The address of the peer is written in its canonical form.
        (&[], "::ffff:203.0.113.9".parse().unwrap(), b"203.0.113.9"),
    ];
    for (lines, peer, expected) in cases {
        let mut pairs = vec![("Host", "h.test")];
        pairs.extend(lines.iter().map(|line| ("X-Forwarded-For", *line)));
        let out = forwarded_fields(fields(&pairs), peer).unwrap();
        assert_eq!(only(&out, "x-forwarded-for"), [expected], "{lines:?}");
    }
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
                ("Connection", "X-Forwarded-For, X-Hop"),
                ("X-Forwarded-For", "198.51.100.1"),
                ("X-Forwarded-Proto", "https"),
                ("X-Hop", "1"),
                ("X-Keep", "a"),
                ("Keep-Alive", "timeout=5"),
                ("Transfer-Encoding", "chunked"),
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
        assert_eq!(seen.all("x-forwarded-proto"), ["http"]);
        budget_back(&ctx).await;
    });
}

#[test]
fn framing_must_be_one_chunked_line_or_one_line_of_digits() {
    let length = |value: &str| checked(200, &[("Content-Length", value)]).err();
    let coding = |value: &str| checked(200, &[("Transfer-Encoding", value)]).err();
    // Content-Length: the boundary of the digits and of 64 bits.
    for value in ["0", "007", "18446744073709551615"] {
        assert_eq!(length(value), None, "{value:?}");
    }
    for value in ["", "+5", "5,5", "0x5", "18446744073709551616"] {
        assert_eq!(length(value), Some(OriginError::Invalid), "{value:?}");
    }
    let twice = [("Content-Length", "5"), ("Content-Length", "5")];
    assert_eq!(checked(200, &twice).err(), Some(OriginError::Invalid));
    // Transfer-Encoding: exactly one line that says chunked, in any case, and no length.
    assert_eq!(coding("Chunked"), None);
    for value in ["gzip", "gzip, chunked"] {
        assert_eq!(coding(value), Some(OriginError::Invalid), "{value:?}");
    }
    let both = [("Transfer-Encoding", "chunked"), ("Content-Length", "5")];
    assert_eq!(checked(200, &both).err(), Some(OriginError::Invalid));
    // The same for the statuses that have no body, where hyper looks at no framing at all.
    assert_eq!(
        checked(304, &[("Content-Length", "x")]).err(),
        Some(OriginError::Invalid)
    );
}

#[test]
fn connection_lines_must_be_token_lists_that_name_nothing_the_answer_keeps() {
    let line = |value: &str| checked(200, &[("Connection", value)]).err();
    for value in ["close", " keep-alive ,\tX-Hop ", "x-content-length"] {
        assert_eq!(line(value), None, "{value:?}");
    }
    for value in [
        "",
        "a,,b",
        "a b",
        "content-length",
        "close, Content-Range",
        "x-hop,\tContent-Type ",
    ] {
        assert_eq!(line(value), Some(OriginError::Invalid), "{value:?}");
    }
    // Any line decides, not only the first.
    let second = [("Connection", "close"), ("Connection", "content-type")];
    assert_eq!(checked(200, &second).err(), Some(OriginError::Invalid));
    // A long list is read to its end: a name at the very end still decides.
    let last = format!("{}content-type", "a,".repeat(4000));
    assert_eq!(
        checked(200, &[("Connection", &last)]).err(),
        Some(OriginError::Invalid)
    );
}

#[test]
fn the_answer_loses_what_belongs_to_the_upstream_connection_and_keeps_the_rest() {
    let mut head = parts(
        200,
        &[
            ("Connection", "close, X-Hop"),
            ("X-Hop", "1"),
            ("Keep-Alive", "timeout=1"),
            ("TE", "trailers"),
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
}

#[test]
fn an_upstream_that_never_answers_ends_at_the_deadline_with_head() {
    run(async {
        let (addr, up) = upstream(|sock| async move {
            read_request(&sock).await;
            closed(&sock).await
        })
        .await;
        let mut cfg = config(addr);
        cfg.upstream_header = Duration::from_millis(400);
        let ctx = ctx(cfg);
        let start = StdInstant::now();
        let out = forward(bare(&ctx, "GET"), &ctx, far()).await;
        let took = start.elapsed();
        assert_eq!(refused(out), OriginError::Head);
        assert!(took >= Duration::from_millis(350), "{took:?}");
        assert!(took < Duration::from_secs(5), "{took:?}");
        assert!(up.await.unwrap(), "the upstream connection was dropped");
    });
}
