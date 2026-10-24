use std::future::Future;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant as StdInstant;

use http::response::Parts;
use http_body_util::BodyExt;
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::runtime::Builder;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

use super::*;
use crate::config::{ForwardConfig, ProxyConfig};
use crate::forward::connect::connect_error;
use crate::forward::group::Upstreams;
use crate::inbound::transport::tls::Tls;
use crate::inspect::driver::Ingress;
use crate::log::start_logger;
use crate::rules::routes::{Routes, SharedRoutes};

const BUDGET: usize = 4 << 20;
const PEER: &str = "203.0.113.9:5555";

pub(in crate::forward) type Outcome = Result<Response<OriginBody>, OriginError>;

pub(in crate::forward) fn config() -> ProxyConfig {
    let secs = Duration::from_secs;
    ProxyConfig {
        listeners: Vec::new(),
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
        keepalive_timeout: secs(75),
        keepalive_requests: 1000,
        keepalive_time: secs(10),
        lingering_time: secs(10),
        lingering_timeout: secs(5),
        lingering_bytes: 262_144,
        trusted_proxies: Vec::new(),
        // A connection is not kept, unless a test turns it on.
        upstream_keepalive: 0,
        upstream_keepalive_timeout: secs(5),
        upstream_keepalive_requests: 1000,
    }
}

/// A context whose one group has one server, at `upstream`.
pub(in crate::forward) fn ctx(upstream: SocketAddr, cfg: ProxyConfig) -> Ctx {
    ctx_of(&ForwardConfig::of(&[upstream]), cfg)
}

pub(in crate::forward) fn ctx_of(forward: &ForwardConfig, cfg: ProxyConfig) -> Ctx {
    // The forwarding never reaches the driver: nobody receives on this channel.
    let (to_driver, _) = std::sync::mpsc::sync_channel(1);
    Ctx {
        upstreams: Upstreams::new(forward, &cfg),
        budget: Arc::new(Semaphore::new(cfg.max_buffered_bytes)),
        inspect: Arc::new(Semaphore::new(1)),
        routes: SharedRoutes::new(Routes::default()),
        log: start_logger().unwrap(),
        ingress: Arc::new(Ingress::new(to_driver)),
        tls: Tls::none(),
        cfg,
    }
}

/// Runs a test body; a body that hangs fails the test instead of the run.
pub(in crate::forward) fn run<F: Future>(body: F) -> F::Output {
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

/// Forwards to the one group of `ctx`, and returns what came of it.
pub(in crate::forward) async fn send(f: Forward, ctx: &Ctx, by: Instant) -> Outcome {
    forward(f, ctx.upstreams.group(0), &Rewrite::default(), ctx, by)
        .await
        .result
}

/// Far enough away to play no part.
pub(in crate::forward) fn far() -> Instant {
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

pub(in crate::forward) fn request(
    ctx: &Ctx,
    method: &str,
    pairs: &[(&str, &str)],
    body: &[u8],
) -> Forward {
    Forward {
        method: method.parse().unwrap(),
        uri: "/p?q=1".parse().unwrap(),
        fields: fields(pairs),
        body: hold(ctx, body),
        peer: PEER.parse().unwrap(),
        https: false,
        websocket: false,
    }
}

/// A request with a Host field and nothing else.
pub(in crate::forward) fn bare(ctx: &Ctx, method: &str) -> Forward {
    request(ctx, method, &[("Host", "h.test")], b"")
}

// ---- a raw upstream: a listener on 127.0.0.1 that serves one connection ----

pub(in crate::forward) async fn pull(sock: &TcpStream, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        sock.readable().await?;
        match sock.try_read(buf) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            other => return other,
        }
    }
}

pub(in crate::forward) async fn put(sock: &TcpStream, mut bytes: &[u8]) -> io::Result<()> {
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
pub(in crate::forward) struct Seen {
    pub(in crate::forward) line: String,
    pub(in crate::forward) fields: Vec<(String, String)>,
    pub(in crate::forward) body: Vec<u8>,
}

impl Seen {
    pub(in crate::forward) fn all(&self, name: &str) -> Vec<&str> {
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

/// The next request on the connection, or `None` when the other side has closed before a byte of it came.
pub(in crate::forward) async fn next_request(sock: &TcpStream) -> Option<Seen> {
    let mut raw = Vec::new();
    let mut buf = [0u8; 16384];
    let end = loop {
        if let Some(at) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        let n = pull(sock, &mut buf).await.unwrap_or(0);
        if n == 0 && raw.is_empty() {
            return None;
        }
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
    Some(Seen { line, fields, body })
}

pub(in crate::forward) async fn read_request(sock: &TcpStream) -> Seen {
    next_request(sock)
        .await
        .expect("the request ended before its head did")
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
    let ctx = ctx(addr, config());
    let out = send(bare(&ctx, method), &ctx, far()).await;
    (out, up)
}

pub(in crate::forward) fn refused(out: Outcome) -> OriginError {
    match out {
        Ok(response) => panic!("passed on with status {}", response.status()),
        Err(e) => e,
    }
}

/// The data of a body and the number of trailer frames it gave.
pub(in crate::forward) async fn collect(mut body: OriginBody) -> (Vec<u8>, usize) {
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
        let out = forwarded_fields(sent, peer, true, true, false, false).unwrap();
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
    let out = forwarded_fields(sent, peer, true, true, false, false).unwrap();
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
        let out = forwarded_fields(fields(&pairs), peer, true, true, false, false).unwrap();
        assert_eq!(only(&out, "x-forwarded-for"), [expected], "{lines:?}");
    }
}

#[test]
fn the_scheme_of_the_listener_is_the_forwarded_proto_unless_a_trusted_peer_says_http_or_https() {
    let peer: IpAddr = "203.0.113.9".parse().unwrap();
    let proto = |pairs: &[(&str, &str)], trusted: bool, https: bool| {
        let out = forwarded_fields(fields(pairs), peer, trusted, false, false, https).unwrap();
        only(&out, "x-forwarded-proto")
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>()
    };
    // A peer that is not believed gets the scheme of the listener whatever it wrote.
    let lies = [("Host", "h.test"), ("X-Forwarded-Proto", "http")];
    assert_eq!(proto(&lies, false, true), [b"https"]);
    assert_eq!(proto(&lies, false, false), [b"http"]);
    // A trusted peer keeps its exact line; any other claim is replaced by the scheme of the listener.
    assert_eq!(proto(&lies, true, true), [b"http"]);
    let odd = [("Host", "h.test"), ("X-Forwarded-Proto", "ftp")];
    assert_eq!(proto(&odd, true, true), [b"https"]);
    assert_eq!(proto(&[("Host", "h.test")], true, false), [b"http"]);
}

#[test]
fn a_peer_that_is_not_trusted_cannot_tell_the_upstream_who_the_client_is() {
    let peer: IpAddr = "203.0.113.9".parse().unwrap();
    let sent = fields(&[
        ("Host", "h.test"),
        ("X-Forwarded-For", "198.51.100.1, 10.0.0.1"),
        ("X-Forwarded-For", "192.0.2.5"),
        ("X-Real-IP", "198.51.100.1"),
        ("Forwarded", "for=198.51.100.1;proto=https"),
        ("X-Forwarded-Proto", "https"),
        ("X-Forwarded-Host", "evil.test"),
        ("X-Keep", "k"),
    ]);
    let out = forwarded_fields(sent, peer, false, false, false, false).unwrap();
    // The upstream gets the address of the peer alone, and our own scheme and host.
    assert_eq!(only(&out, "x-forwarded-for"), [b"203.0.113.9"]);
    assert_eq!(only(&out, "x-forwarded-proto"), [b"http"]);
    assert_eq!(only(&out, "x-forwarded-host"), [b"h.test"]);
    assert!(out.get("x-real-ip").is_none());
    assert!(out.get("forwarded").is_none());
    // Nothing else is touched, and the connection is not told to close when it is kept.
    assert_eq!(only(&out, "x-keep"), [b"k"]);
    assert!(out.get("connection").is_none());
    assert_eq!(out.len(), 5);
}

#[test]
fn a_trusted_peer_keeps_its_claims_and_the_scheme_is_http_or_https_only() {
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let sent = fields(&[
        ("Host", "h.test"),
        ("X-Forwarded-For", "198.51.100.1"),
        ("X-Real-IP", "198.51.100.1"),
        ("Forwarded", "for=198.51.100.1"),
        ("X-Forwarded-Proto", "https"),
    ]);
    let out = forwarded_fields(sent, peer, true, false, false, false).unwrap();
    assert_eq!(only(&out, "x-forwarded-for"), [b"198.51.100.1, 10.0.0.2"]);
    assert_eq!(only(&out, "x-real-ip"), [b"198.51.100.1"]);
    assert_eq!(only(&out, "forwarded"), [b"for=198.51.100.1"]);
    assert_eq!(only(&out, "x-forwarded-proto"), [b"https"]);
    // Only these two values, byte for byte and on one line, are kept; anything else is our own.
    let proto = |lines: &[&str]| {
        let mut pairs = vec![("Host", "h.test")];
        pairs.extend(lines.iter().map(|line| ("X-Forwarded-Proto", *line)));
        let out = forwarded_fields(fields(&pairs), peer, true, false, false, false).unwrap();
        only(&out, "x-forwarded-proto")
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>()
    };
    assert_eq!(proto(&["http"]), [b"http"]);
    assert_eq!(proto(&["https"]), [b"https"]);
    for lines in [
        &["HTTPS"][..],
        &["ftp"],
        &[""],
        &["https, http"],
        &[" https"],
        &["https", "https"],
        &[],
    ] {
        assert_eq!(proto(lines), [b"http"], "{lines:?}");
    }
}

#[test]
fn the_other_claims_about_the_client_are_kept_from_a_trusted_peer_and_dropped_from_any_other() {
    // `X-Forwarded-For` and `X-Forwarded-Proto` are made anew in both cases, and are looked at above.
    let claims = CLIENT_CLAIMS
        .into_iter()
        .filter(|name| !matches!(*name, "x-forwarded-for" | "x-forwarded-proto"));
    for name in claims {
        let sent = fields(&[("Host", "h.test"), (name, "198.51.100.1"), ("X-Keep", "k")]);
        let untrusted = forwarded_fields(
            sent.clone(),
            "203.0.113.9".parse().unwrap(),
            false,
            false,
            false,
            false,
        );
        let untrusted = untrusted.unwrap();
        assert!(untrusted.get(name).is_none(), "{name}");
        assert_eq!(only(&untrusted, "x-keep"), [b"k"], "{name}");
        let trusted =
            forwarded_fields(sent, "10.0.0.2".parse().unwrap(), true, false, false, false).unwrap();
        assert_eq!(only(&trusted, name), [b"198.51.100.1"], "{name}");
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
fn a_handshake_leaves_with_fixed_upgrade_fields_and_only_a_proper_101_comes_back() {
    let peer: IpAddr = "203.0.113.9".parse().unwrap();
    let sent = fields(&[
        ("Host", "h.test"),
        ("Upgrade", "WebSocket"),
        ("Connection", "keep-alive, Upgrade, X-Hop"),
        ("X-Hop", "1"),
        ("Sec-WebSocket-Key", "k"),
    ]);
    let out = forwarded_fields(sent, peer, false, true, true, false).unwrap();
    assert_eq!(only(&out, "connection"), [b"upgrade"]);
    assert_eq!(only(&out, "upgrade"), [b"websocket"]);
    assert_eq!(only(&out, "sec-websocket-key"), [b"k"]);
    assert!(out.get("x-hop").is_none());

    let switch = |lines: &[(&str, &str)]| {
        let mut head = parts(101, lines);
        check_switch(&mut head).map(|()| head)
    };
    let good = [
        ("Upgrade", "WebSocket"),
        ("Connection", "upgrade, X-Hop"),
        ("X-Hop", "1"),
        ("Content-Length", "3"),
        ("Sec-WebSocket-Accept", "a"),
    ];
    let head = switch(&good).unwrap();
    assert_eq!(head.status.as_u16(), 101);
    assert_eq!(only(&head.headers, "connection"), [b"upgrade"]);
    assert_eq!(only(&head.headers, "upgrade"), [b"websocket"]);
    assert_eq!(only(&head.headers, "sec-websocket-accept"), [b"a"]);
    assert!(head.headers.get("x-hop").is_none() && head.headers.get("content-length").is_none());
    let bad: [&[(&str, &str)]; 6] = [
        &[("Connection", "upgrade")],
        &[("Upgrade", "websocket")],
        &[
            ("Upgrade", "websocket"),
            ("Upgrade", "websocket"),
            ("Connection", "upgrade"),
        ],
        &[("Upgrade", "h2c"), ("Connection", "upgrade")],
        &[
            ("Upgrade", "websocket"),
            ("Connection", "upgrade, content-length"),
        ],
        &[("Upgrade", "websocket"), ("Connection", "upgrade, a b")],
    ];
    for lines in bad {
        assert_eq!(switch(lines).err(), Some(OriginError::Invalid), "{lines:?}");
    }
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
        let ctx = ctx(addr, config());
        let response = send(bare(&ctx, "GET"), &ctx, far()).await.unwrap();
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
            let mut cfg = config();
            cfg.upstream_head_wire = cap;
            let ctx = ctx(addr, cfg);
            let out = send(bare(&ctx, "GET"), &ctx, far()).await;
            if passes {
                let response = out.unwrap();
                assert_eq!(response.status(), 200);
                drop(response);
            } else {
                assert_eq!(refused(out), OriginError::Invalid);
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
        let mut cfg = config();
        cfg.upstream_head_wire = head.len() + 1500;
        let ctx = ctx(addr, cfg);
        let response = send(bare(&ctx, "GET"), &ctx, far()).await.unwrap();
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
        let ctx = ctx(addr, config());
        let out = send(bare(&ctx, "GET"), &ctx, far()).await;
        assert_eq!(refused(out), OriginError::Connect);
    });
}

#[test]
fn a_failure_is_send_before_an_answer_began_head_after_it_and_invalid_if_the_head_is_not_one() {
    run(async {
        // Nothing of an answer: the upstream closes after reading the request.
        let (out, _) = ask("GET", b"", false).await;
        assert_eq!(refused(out), OriginError::Send);
        // Part of a status line, then the end.
        let (out, _) = ask("GET", b"HTTP/1.1 20", false).await;
        assert_eq!(refused(out), OriginError::Head);
        // Bytes that are not an answer.
        let (out, _) = ask("GET", b"NOT HTTP\r\n\r\n", false).await;
        assert_eq!(refused(out), OriginError::Invalid);
        // A head that is longer than hyper takes.
        let mut long = b"HTTP/1.1 200 OK\r\nX-Long: ".to_vec();
        long.extend_from_slice(&[b'a'; 9000]);
        long.extend_from_slice(b"\r\nContent-Length: 0\r\n\r\n");
        let (out, _) = ask("GET", &long, false).await;
        assert_eq!(refused(out), OriginError::Invalid);
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
        let ctx = ctx(addr, config());
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
        let response = send(f, &ctx, far()).await.unwrap();
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
        let mut cfg = config();
        cfg.upstream_header = Duration::from_millis(400);
        let ctx = ctx(addr, cfg);
        let start = StdInstant::now();
        let out = send(bare(&ctx, "GET"), &ctx, far()).await;
        let took = start.elapsed();
        assert_eq!(refused(out), OriginError::Head);
        assert!(took >= Duration::from_millis(350), "{took:?}");
        assert!(took < Duration::from_secs(5), "{took:?}");
        assert!(up.await.unwrap(), "the upstream connection was dropped");
    });
}

// ---- the next server of the group ----

const OK_REPLY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

/// An address where nothing listens.
async fn nobody() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

/// A server that reads each request and closes the connection with no answer. It counts the connections.
async fn silent() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let counted = count.clone();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            next_request(&sock).await;
        }
    });
    (addr, count)
}

#[test]
fn a_connection_that_cannot_be_made_goes_on_to_the_next_server_for_any_method() {
    run(async {
        for method in ["GET", "POST"] {
            let dead = nobody().await;
            let (live, up) = upstream(|sock| answering(sock, OK_REPLY.to_vec(), false)).await;
            let ctx = ctx_of(&ForwardConfig::of(&[dead, live]), config());
            let sent = forward(
                bare(&ctx, method),
                ctx.upstreams.group(0),
                &Rewrite::default(),
                &ctx,
                far(),
            )
            .await;
            assert_eq!(sent.server, Some(live), "{method}");
            assert_eq!(sent.result.unwrap().status(), 200, "{method}");
            up.await.unwrap();
        }
    });
}

#[test]
fn a_request_that_was_sent_goes_on_only_if_it_does_no_harm_when_sent_twice() {
    run(async {
        for (method, goes_on) in [("GET", true), ("POST", false)] {
            let (silent, seen) = silent().await;
            let (live, up) = upstream(|sock| answering(sock, OK_REPLY.to_vec(), false)).await;
            let ctx = ctx_of(&ForwardConfig::of(&[silent, live]), config());
            let sent = forward(
                bare(&ctx, method),
                ctx.upstreams.group(0),
                &Rewrite::default(),
                &ctx,
                far(),
            )
            .await;
            assert_eq!(seen.load(Ordering::SeqCst), 1, "{method}");
            if goes_on {
                assert_eq!(sent.server, Some(live));
                assert_eq!(sent.result.unwrap().status(), 200);
                up.await.unwrap();
            } else {
                // It stops at the first server: the second one is not asked.
                assert_eq!(sent.server, Some(silent));
                assert_eq!(refused(sent.result), OriginError::Send);
                assert!(!up.is_finished());
                up.abort();
            }
        }
    });
}

#[test]
fn each_server_is_tried_once_and_a_group_with_none_to_try_is_unavailable() {
    run(async {
        let mut addresses = Vec::new();
        let mut counts = Vec::new();
        for _ in 0..3 {
            let (addr, seen) = silent().await;
            addresses.push(addr);
            counts.push(seen);
        }
        let ctx = ctx_of(&ForwardConfig::of(&addresses), config());
        let group = ctx.upstreams.group(0);
        let tried = |counts: &[Arc<AtomicUsize>]| -> Vec<usize> {
            counts.iter().map(|c| c.load(Ordering::SeqCst)).collect()
        };
        let sent = forward(bare(&ctx, "GET"), group, &Rewrite::default(), &ctx, far()).await;
        assert_eq!(refused(sent.result), OriginError::Send);
        assert_eq!(tried(&counts), [1, 1, 1]);
        // Each one failed once, and one failure leaves a server out: the next request has none to try.
        let sent = forward(bare(&ctx, "GET"), group, &Rewrite::default(), &ctx, far()).await;
        assert_eq!(sent.server, None);
        assert_eq!(refused(sent.result), OriginError::Unavailable);
        assert_eq!(tried(&counts), [1, 1, 1]);
    });
}

/// A server that takes each connection and never answers. It counts the connections.
async fn mute() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let counted = count.clone();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((sock, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            held.push(sock);
        }
    });
    (addr, count)
}

/// A server where a new connection stays pending: its queue of connections is full, and what is more is neither
/// taken nor refused. The listener and the connections that fill the queue are returned to be kept.
async fn stalled() -> (SocketAddr, (TcpListener, Vec<TcpStream>)) {
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let listener = socket.listen(1).unwrap();
    let addr = listener.local_addr().unwrap();
    let mut filled = Vec::new();
    loop {
        match timeout(Duration::from_millis(200), TcpStream::connect(addr)).await {
            Ok(Ok(sock)) => filled.push(sock),
            Ok(Err(e)) => panic!("the connection failed: {e}"),
            Err(_) => break,
        }
        assert!(filled.len() < 64, "the queue of the listener does not fill");
    }
    (addr, (listener, filled))
}

/// The servers that the group gives over four choices, none tried.
fn gives(group: &Group) -> Vec<usize> {
    (0..4)
        .filter_map(|_| group.pick(Tried::default(), Instant::now()))
        .collect()
}

/// A GET to a group of `slow`, which holds up one stage, and a live server, with the request time ending at `by`.
/// `own`: the limit of the stage in `cfg` comes first, so the server failed. It is left out, and the request went
/// on to the live server. Otherwise the end of the request time comes first and no server is at fault: nothing is
/// counted, and the request ends there.
async fn held_up(slow: SocketAddr, cfg: ProxyConfig, by: Instant, own: bool) {
    let (live, up) = upstream(|sock| answering(sock, OK_REPLY.to_vec(), false)).await;
    let ctx = ctx_of(&ForwardConfig::of(&[slow, live]), cfg);
    let group = ctx.upstreams.group(0);
    let sent = forward(bare(&ctx, "GET"), group, &Rewrite::default(), &ctx, by).await;
    if own {
        assert_eq!(sent.server, Some(live));
        assert_eq!(sent.result.unwrap().status(), 200);
        up.await.unwrap();
        assert!(!gives(group).contains(&0), "the server is left out");
    } else {
        assert_eq!(sent.server, Some(slow));
        assert_eq!(refused(sent.result), OriginError::Late);
        assert!(!up.is_finished(), "the live server was not asked");
        up.abort();
        assert!(gives(group).contains(&0), "the server is not left out");
    }
}

#[test]
fn a_head_wait_cut_short_by_the_request_time_is_not_the_fault_of_the_server() {
    run(async {
        for own in [true, false] {
            let (mute, seen) = mute().await;
            let mut cfg = config();
            // One failure leaves a server out. The wait for the head lasts 0.3 s or 5 s, and the request time
            // ends after 0.3 s or 30 s.
            cfg.upstream_header = Duration::from_millis(if own { 300 } else { 5000 });
            let by = Instant::now() + Duration::from_millis(if own { 30_000 } else { 300 });
            held_up(mute, cfg, by, own).await;
            assert_eq!(seen.load(Ordering::SeqCst), 1, "own: {own}");
        }
    });
}

#[test]
fn a_connect_cut_short_by_the_request_time_is_not_the_fault_of_the_server() {
    run(async {
        for own in [true, false] {
            let (stalled, _kept) = stalled().await;
            let mut cfg = config();
            cfg.upstream_connect = Duration::from_millis(if own { 300 } else { 5000 });
            let by = Instant::now() + Duration::from_millis(if own { 30_000 } else { 300 });
            held_up(stalled, cfg, by, own).await;
        }
    });
}

#[test]
fn a_request_time_that_is_used_up_before_the_first_try_asks_no_server_and_is_late() {
    run(async {
        let (mute, seen) = mute().await;
        let ctx = ctx_of(&ForwardConfig::of(&[mute]), config());
        let group = ctx.upstreams.group(0);
        let sent = forward(
            bare(&ctx, "GET"),
            group,
            &Rewrite::default(),
            &ctx,
            Instant::now(),
        )
        .await;
        assert_eq!(sent.server, None);
        assert_eq!(refused(sent.result), OriginError::Late);
        sleep(Duration::from_millis(100)).await;
        assert_eq!(seen.load(Ordering::SeqCst), 0);
    });
}

#[test]
fn only_a_refusal_a_reset_or_an_unreachable_server_fails_a_connect_other_errors_are_local() {
    for kind in [
        io::ErrorKind::ConnectionRefused,
        io::ErrorKind::ConnectionReset,
        io::ErrorKind::HostUnreachable,
        io::ErrorKind::NetworkUnreachable,
        io::ErrorKind::TimedOut,
    ] {
        assert_eq!(
            connect_error(&io::Error::from(kind)),
            OriginError::Connect,
            "{kind:?}"
        );
    }
    // ENOMEM, ENFILE, EMFILE, ENOBUFS, EADDRNOTAVAIL, EPERM; and an error that has no number.
    for errno in [12, 23, 24, 105, 99, 1] {
        assert_eq!(
            connect_error(&io::Error::from_raw_os_error(errno)),
            OriginError::Local,
            "{errno}"
        );
    }
    assert_eq!(connect_error(&io::Error::other("x")), OriginError::Local);
    // Such an error and a time that ran out are counted against no server, and are not tried on another.
    for error in [OriginError::Local, OriginError::Late] {
        assert!(!failure_of_server(error), "{error:?}");
        assert!(!may_go_on(error, &Method::GET), "{error:?}");
    }
}

/// A GET to a group of two servers: the first is served by `serve`, the other answers 200. Tells what came of it
/// (the status, or why there was none), whether it went on to the second server, and whether the first one is
/// left out of the group afterwards.
async fn first_of_two<T, F, Fut>(
    serve: F,
    cfg: ProxyConfig,
) -> (Result<u16, OriginError>, bool, bool)
where
    F: FnOnce(TcpStream) -> Fut + Send + 'static,
    Fut: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let (first, _) = upstream(serve).await;
    let (second, _) = upstream(|sock| answering(sock, OK_REPLY.to_vec(), false)).await;
    let ctx = ctx_of(&ForwardConfig::of(&[first, second]), cfg);
    let group = ctx.upstreams.group(0);
    let sent = forward(bare(&ctx, "GET"), group, &Rewrite::default(), &ctx, far()).await;
    let went_on = sent.server == Some(second);
    let result = sent.result.map(|response| response.status().as_u16());
    (result, went_on, !gives(group).contains(&0))
}

#[test]
fn a_head_over_a_limit_is_not_the_fault_of_the_server_and_is_not_tried_on_another() {
    run(async {
        // What the request alone can make an upstream say (a path, an `Origin` or a `Cookie` that it repeats into
        // a `Location` or a `Set-Cookie`): a field longer than hyper takes, more fields than it takes (64), and
        // more bytes up to the final head than the cap.
        let mut long = b"HTTP/1.1 200 OK\r\nX-Long: ".to_vec();
        long.extend_from_slice(&[b'a'; 9000]);
        long.extend_from_slice(b"\r\nContent-Length: 0\r\n\r\n");
        let mut many = b"HTTP/1.1 200 OK\r\n".to_vec();
        for i in 0..65 {
            many.extend_from_slice(format!("X-{i}: a\r\n").as_bytes());
        }
        many.extend_from_slice(b"Content-Length: 0\r\n\r\n");
        let mut early = Vec::new();
        for _ in 0..60 {
            early.extend_from_slice(b"HTTP/1.1 102 Processing\r\n\r\n");
        }
        early.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let cap = early.len() - 1;
        for (name, reply, cap) in [
            ("long", long, 65536),
            ("many", many, 65536),
            ("early", early, cap),
        ] {
            let mut cfg = config();
            cfg.upstream_head_wire = cap;
            let (result, went_on, left_out) =
                first_of_two(move |sock| answering(sock, reply, false), cfg).await;
            assert_eq!(result, Err(OriginError::Invalid), "{name}");
            assert!(!went_on, "{name}: it was tried on the second server");
            assert!(!left_out, "{name}: the server is left out");
        }
    });
}

#[test]
fn a_connection_reset_in_the_middle_of_a_head_is_the_fault_of_the_server() {
    run(async {
        let (result, went_on, left_out) = first_of_two(
            |sock| async move {
                read_request(&sock).await;
                put(&sock, b"HTTP/1.1 20").await.unwrap();
                // Closing with a reset in place of the end of the stream.
                sock.set_zero_linger().unwrap();
            },
            config(),
        )
        .await;
        assert_eq!(result, Ok(200));
        assert!(went_on, "it was not tried on the second server");
        assert!(left_out, "the server is not left out");
    });
}

// ---- the edits of a route ----

use crate::forward::rewrite::{Headers, Query};

fn strings(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_string()).collect()
}

fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
    list.iter()
        .map(|(n, v)| ((*n).to_string(), (*v).to_string()))
        .collect()
}

/// The edits of a route for `/api/` that has every kind.
fn edits() -> Rewrite {
    let query = Query::new(
        strings(&["debug"]),
        vec![],
        pairs(&[("src", "edge")]),
        vec![],
    )
    .unwrap();
    let request = Headers::request(
        strings(&["x-drop"]),
        pairs(&[("x-set", "new")]),
        pairs(&[("x-added", "a")]),
    )
    .unwrap();
    let response = Headers::response(
        strings(&["x-up"]),
        vec![],
        pairs(&[("x-served-by", "edge")]),
    )
    .unwrap();
    Rewrite::new(
        Some("/api/"),
        Some("inner.test:8080"),
        Some("/v2/"),
        query,
        request,
        response,
    )
    .unwrap()
}

#[test]
fn the_forwarded_request_differs_from_the_inspected_one_only_by_the_edits_of_the_route() {
    let peer: IpAddr = "203.0.113.9".parse().unwrap();
    let inspected = fields(&[
        ("Host", "app.test"),
        ("Cookie", "c=1"),
        ("X-Keep", "k"),
        ("X-Drop", "d"),
        ("X-Set", "old"),
    ]);
    let plain = forwarded_fields(inspected, peer, false, false, false, false).unwrap();
    let uri = "/api/x/y?debug=1&keep=%41".parse().unwrap();
    let (edited, uri) = edits().request(plain.clone(), uri).unwrap();
    // `X-Forwarded-Host` is made from the `Host` that the client sent, before the route sets another one.
    assert_eq!(only(&edited, "x-forwarded-host"), [b"app.test"]);
    let mut expected = plain;
    expected.insert(HOST, HeaderValue::from_static("inner.test:8080"));
    expected.remove("x-drop");
    expected.insert("x-set", HeaderValue::from_static("new"));
    expected.append("x-added", HeaderValue::from_static("a"));
    assert_eq!(edited, expected);
    assert_eq!(uri.to_string(), "/v2/x/y?keep=%41&src=edge");
}

#[test]
fn a_route_with_edits_sends_the_edited_request_and_edits_the_head_of_the_response() {
    run(async {
        let (addr, up) = upstream(|sock| async move {
            let seen = read_request(&sock).await;
            let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Up: 1\r\n\r\nok";
            put(&sock, reply).await.unwrap();
            seen
        })
        .await;
        let ctx = ctx(addr, config());
        let mut f = request(&ctx, "GET", &[("Host", "app.test"), ("X-Drop", "d")], b"");
        f.uri = "/api/x?debug=1&keep=1".parse().unwrap();
        let group = ctx.upstreams.group(0);
        let sent = forward(f, group, &edits(), &ctx, far()).await;
        let response = sent.result.unwrap();
        assert_eq!(only(response.headers(), "x-served-by"), [b"edge"]);
        assert!(response.headers().get("x-up").is_none());
        let seen = up.await.unwrap();
        assert_eq!(seen.line, "GET /v2/x?keep=1&src=edge HTTP/1.1");
        assert_eq!(seen.all("host"), ["inner.test:8080"]);
        assert_eq!(seen.all("x-forwarded-host"), ["app.test"]);
        assert_eq!(seen.all("x-added"), ["a"]);
        assert!(seen.all("x-drop").is_empty());
    });
}

#[test]
fn a_request_whose_edits_cannot_be_made_is_not_sent_and_no_server_is_blamed() {
    run(async {
        let (dead, _) = silent().await;
        let ctx = ctx(dead, config());
        let value = pairs(&[("k", &"v".repeat(200))]);
        let query = Query::new(vec![], vec![], vec![], value).unwrap();
        let rewrite = Rewrite::new(
            None,
            None,
            None,
            query,
            Headers::default(),
            Headers::default(),
        )
        .unwrap();
        let mut f = bare(&ctx, "GET");
        f.uri = format!("/{}", "a".repeat(tukuyomi_kernel::limits::URI - 11))
            .parse()
            .unwrap();
        let group = ctx.upstreams.group(0);
        let sent = forward(f, group, &rewrite, &ctx, far()).await;
        assert_eq!(sent.server, None);
        assert_eq!(refused(sent.result), OriginError::Send);
    });
}
