//! Real-process tests of the HTTP front.
//!
//! Every test starts the proxy binary with a configuration file that it writes into its own 0700 root, the real
//! inspector and the test rules of the kernel crate (rule 9201: a URI beginning `/block-probe`, phase 1, status
//! 403; rule 9202: the urlencoded argument `probe=block`, phase 2, status 403). It also runs a small upstream of
//! its own on a loopback port, which records every connection and the bytes it received, and it talks to the
//! proxy with a raw TCP client: the exact bytes out, everything read back until the proxy closes.
//!
//! These tests need the environment variables `TUKUYOMI_TEST_INSPECTOR` (the built inspector),
//! `TUKUYOMI_TEST_RULES` (the rules file), `TUKUYOMI_TEST_RULES_SHA256` (its hash, 64 hex digits) and
//! `TUKUYOMI_TEST_TMP` (the parent of the per-test 0700 roots). They fail when one is missing: a skipped
//! real-process test must never look like a pass. Run them with `-- --ignored`.
//!
//! How the scenes are made:
//! - A slow inspection is a 1 MiB urlencoded body with a drive slice of 400 ms. The driver then needs about 17
//!   steps of one slice each, so the inspection takes several seconds. The inspector process is found through
//!   `/proc/<proxy pid>/task/*/children`, and the test knows that the body is being inspected when the inspector's
//!   read counter in `/proc/<pid>/io` has grown by one body frame.
//! - The listen port is chosen by binding `127.0.0.1:0` and releasing the socket right before the start. A
//!   process that takes the port in between would make the start fail with a clear record line.
//! - Resources that come back are shown in two ways: a normal request passes after the scene, and the record
//!   line that the proxy writes when it is told to stop shows the kernel holding no record, no slot and no
//!   waiting request. Deadlines that fire with the byte budget, or the connection limit, at their minimum show
//!   the budget or the permit coming back directly.
//! - Waiting is done on a channel, a condition variable or an exit. The few pauses that remain are polls of a
//!   `/proc` counter or of a socket state every 2 to 20 ms, bounded by `PATIENCE`.

use std::fs::{self, DirBuilder};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde_json::json;

const MS: Duration = Duration::from_millis(1);
const SEC: Duration = Duration::from_secs(1);
/// How long a test waits for something that must happen. Reaching it is a failure, never a pass.
const PATIENCE: Duration = Duration::from_secs(60);

const URLENCODED: &str = "application/x-www-form-urlencoded";
/// The largest body the proxy is configured to take, which is also the largest body the kernel accepts.
const MAX_BODY: usize = 1 << 20;
/// `max_buffered_bytes` at its lowest: twice the largest body and the largest set of header fields.
const MIN_BUFFERED: usize = 2 * MAX_BODY + 24 * 1024;
/// The inspector has read a body frame (64 KiB) once its read counter has grown by this much.
const FRAME: u64 = 64 * 1024;
/// The body of the upstream's answer.
const UPSTREAM_BODY: &str = "hello-from-upstream";

// ---------------------------------------------------------------------------------------------------------
// The environment
// ---------------------------------------------------------------------------------------------------------

fn var(name: &str) -> String {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => v,
        _ => panic!("{name} is not set: this real-process test needs it and is never skipped"),
    }
}

/// The rules hash as the configuration file wants it: 64 lowercase hex digits.
fn parse_sha256(s: &str) -> String {
    assert!(
        s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()),
        "TUKUYOMI_TEST_RULES_SHA256 must be 64 hex digits"
    );
    s.to_ascii_lowercase()
}

/// A new 0700 root for one test, under `TUKUYOMI_TEST_TMP`. Its name has the process id and the test name, so
/// earlier runs do not meet. The end of a test removes it, and fails if it holds anything but the configuration.
fn make_root(test: &str) -> PathBuf {
    let root =
        PathBuf::from(var("TUKUYOMI_TEST_TMP")).join(format!("{test}-{}", std::process::id()));
    DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .unwrap_or_else(|e| panic!("cannot create the test root {root:?}: {e}"));
    let mode = fs::symlink_metadata(&root)
        .expect("the test root exists")
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0, "the test root has group or other bits");
    root
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Polls `cond` every 5 ms until it holds. A counter in `/proc` has no other way to be waited for.
fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + PATIENCE;
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(5 * MS);
    }
}

// ---------------------------------------------------------------------------------------------------------
// Counters and the record stream
// ---------------------------------------------------------------------------------------------------------

/// A count that can be waited for.
#[derive(Default)]
struct Counter {
    n: Mutex<usize>,
    changed: Condvar,
}

impl Counter {
    fn add(&self) {
        *lock(&self.n) += 1;
        self.changed.notify_all();
    }

    fn get(&self) -> usize {
        *lock(&self.n)
    }

    fn wait_for(&self, what: &str, at_least: usize) {
        let deadline = Instant::now() + PATIENCE;
        let mut n = lock(&self.n);
        while *n < at_least {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(!left.is_zero(), "timed out waiting for {what}");
            n = self
                .changed
                .wait_timeout(n, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }
}

#[derive(Default)]
struct RecordState {
    lines: Vec<String>,
    /// The proxy closed its stderr.
    ended: bool,
}

/// The lines the proxy writes to stderr, as they arrive.
#[derive(Default)]
struct Records {
    state: Mutex<RecordState>,
    changed: Condvar,
}

impl Records {
    fn push(&self, line: String) {
        lock(&self.state).lines.push(line);
        self.changed.notify_all();
    }

    fn end(&self) {
        lock(&self.state).ended = true;
        self.changed.notify_all();
    }

    fn lines(&self) -> Vec<String> {
        lock(&self.state).lines.clone()
    }

    /// Waits for `n` lines that satisfy `want` (lines that are there already count) and returns them. Fails with
    /// all the lines when the proxy ends first or nothing comes in time.
    fn wait_lines(&self, what: &str, n: usize, want: impl Fn(&str) -> bool) -> Vec<String> {
        let deadline = Instant::now() + PATIENCE;
        let mut state = lock(&self.state);
        loop {
            let found: Vec<String> = state.lines.iter().filter(|l| want(l)).cloned().collect();
            if found.len() >= n {
                return found;
            }
            assert!(
                !state.ended,
                "the proxy ended before {what}; its records: {:#?}",
                state.lines
            );
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(
                !left.is_zero(),
                "timed out waiting for {what}; the records so far: {:#?}",
                state.lines
            );
            state = self
                .changed
                .wait_timeout(state, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    fn wait_line(&self, what: &str, want: impl Fn(&str) -> bool) -> String {
        self.wait_lines(what, 1, want).remove(0)
    }

    /// The connection record that satisfies `want`.
    fn conn(&self, what: &str, want: impl Fn(&str) -> bool) -> String {
        self.wait_line(what, |l| l.starts_with("conn ") && want(l))
    }

    /// `n` connection records that satisfy `want`.
    fn conns(&self, what: &str, n: usize, want: impl Fn(&str) -> bool) -> Vec<String> {
        self.wait_lines(what, n, |l| l.starts_with("conn ") && want(l))
    }
}

// ---------------------------------------------------------------------------------------------------------
// HTTP text
// ---------------------------------------------------------------------------------------------------------

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// A message split into its start line, its fields (lower-case name, trimmed value) and its body.
struct Message {
    start: String,
    fields: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Message {
    fn parse(raw: &[u8]) -> Message {
        let end = find(raw, b"\r\n\r\n")
            .unwrap_or_else(|| panic!("no end of head in {:?}", String::from_utf8_lossy(raw)));
        let head = String::from_utf8_lossy(&raw[..end]).into_owned();
        let mut lines = head.split("\r\n");
        let start = lines.next().unwrap_or_default().to_string();
        let fields = lines
            .filter_map(|l| l.split_once(':'))
            .map(|(n, v)| (n.to_ascii_lowercase(), v.trim().to_string()))
            .collect();
        Message {
            start,
            fields,
            body: raw[end + 4..].to_vec(),
        }
    }

    /// The status of a response (`HTTP/1.1 200 OK` gives 200).
    fn status(&self) -> u16 {
        self.start
            .split(' ')
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("no status in {:?}", self.start))
    }

    /// The values of every field of that name, in order.
    fn values(&self, name: &str) -> Vec<&str> {
        self.fields
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    fn names(&self) -> Vec<&str> {
        self.fields.iter().map(|(n, _)| n.as_str()).collect()
    }
}

/// What a client got back: every byte until the proxy closed, and how long that took.
struct Reply {
    raw: Vec<u8>,
    took: Duration,
}

impl Reply {
    fn message(&self) -> Message {
        Message::parse(&self.raw)
    }

    fn status(&self) -> u16 {
        self.message().status()
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.raw).into_owned()
    }
}

/// An answer the proxy makes itself: the status, no body, `Content-Length: 0` and `Connection: close`.
fn assert_empty_answer(reply: &Reply, status: u16) {
    let m = reply.message();
    assert_eq!(m.status(), status, "answer: {:?}", reply.text());
    assert!(m.body.is_empty(), "answer has a body: {:?}", reply.text());
    assert_eq!(
        m.values("content-length"),
        ["0"],
        "answer: {:?}",
        reply.text()
    );
    assert_eq!(
        m.values("connection"),
        ["close"],
        "answer: {:?}",
        reply.text()
    );
}

fn get(path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: example.test\r\n\r\n").into_bytes()
}

fn post_form(path: &str, body: &[u8]) -> Vec<u8> {
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: example.test\r\nContent-Type: {URLENCODED}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(body);
    request
}

/// A urlencoded body of exactly `total` bytes whose `probe` argument is `probe`.
fn padded_form(probe: &str, total: usize) -> Vec<u8> {
    let mut body = format!("probe={probe}&pad=").into_bytes();
    assert!(total >= body.len());
    body.resize(total, b'a');
    body
}

/// A chunked urlencoded request whose body is `body`, exactly as given (it is the chunked coding, right or wrong).
fn chunked_request(path: &str, body: &[u8]) -> Vec<u8> {
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: example.test\r\nContent-Type: {URLENCODED}\r\nTransfer-Encoding: chunked\r\n\r\n"
    )
    .into_bytes();
    request.extend_from_slice(body);
    request
}

/// Chunks in the chunked coding, then the last chunk and `trailer` (raw field lines, each ending in CRLF).
fn chunked_body(chunks: &[&[u8]], trailer: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in chunks {
        out.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
        out.extend_from_slice(chunk);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"0\r\n");
    out.extend_from_slice(trailer);
    out.extend_from_slice(b"\r\n");
    out
}

// ---------------------------------------------------------------------------------------------------------
// The raw client
// ---------------------------------------------------------------------------------------------------------

fn connect(port: u16) -> TcpStream {
    let sock = TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), 10 * SEC)
        .expect("connect to the proxy");
    sock.set_nodelay(true).expect("set TCP_NODELAY");
    sock.set_write_timeout(Some(PATIENCE))
        .expect("set the write timeout");
    sock
}

/// Reads until the peer closes. A reset after some bytes ends the read as well: the proxy may close a socket
/// whose request it did not read to the end. No close within `PATIENCE` fails the test.
fn read_to_close(sock: &mut TcpStream) -> Vec<u8> {
    let deadline = Instant::now() + PATIENCE;
    let mut raw = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        assert!(
            !left.is_zero(),
            "the proxy did not close in time; got {} bytes",
            raw.len()
        );
        sock.set_read_timeout(Some(left))
            .expect("set the read timeout");
        match sock.read(&mut chunk) {
            Ok(0) => return raw,
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
            Err(e)
                if !raw.is_empty()
                    && matches!(
                        e.kind(),
                        io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
                    ) =>
            {
                return raw;
            }
            Err(e) => panic!("read from the proxy failed after {} bytes: {e}", raw.len()),
        }
    }
}

/// Reads until `marker` is in what was read; returns everything read so far.
fn read_until(sock: &mut TcpStream, marker: &[u8]) -> Vec<u8> {
    let deadline = Instant::now() + PATIENCE;
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    while find(&raw, marker).is_none() {
        let left = deadline.saturating_duration_since(Instant::now());
        assert!(!left.is_zero(), "no {marker:?} in time; got {raw:?}");
        sock.set_read_timeout(Some(left))
            .expect("set the read timeout");
        match sock.read(&mut chunk) {
            Ok(0) => panic!("the proxy closed before {marker:?}; got {raw:?}"),
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
            Err(e) => panic!("read from the proxy failed: {e}; got {raw:?}"),
        }
    }
    raw
}

/// Everything the proxy answers until it closes; `start` is when the exchange began.
fn collect(sock: &mut TcpStream, start: Instant) -> Reply {
    Reply {
        raw: read_to_close(sock),
        took: start.elapsed(),
    }
}

/// One request on a new connection, then everything the proxy answers.
fn exchange(port: u16, request: &[u8]) -> Reply {
    let start = Instant::now();
    let mut sock = connect(port);
    sock.write_all(request).expect("send the request");
    collect(&mut sock, start)
}

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .expect("bind a free port")
        .local_addr()
        .expect("the local address")
        .port()
}

// ---------------------------------------------------------------------------------------------------------
// The upstream
// ---------------------------------------------------------------------------------------------------------

/// What the upstream does with a request once it has read it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Behaviour {
    /// Answers with `upstream_reply` and closes.
    #[default]
    Reply,
    /// Never answers; waits for the proxy to close.
    Silent,
    /// Sends a head that promises 10 body bytes and 3 of them, then waits for the proxy to close.
    Cut,
}

fn upstream_reply() -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close, X-Up-Hop\r\nKeep-Alive: timeout=9\r\nX-Up-Hop: 1\r\nX-Up: visible\r\n\r\n{UPSTREAM_BODY}",
        UPSTREAM_BODY.len()
    )
    .into_bytes()
}

fn upstream_cut() -> Vec<u8> {
    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 10\r\n\r\nabc".to_vec()
}

#[derive(Default)]
struct Seen {
    behaviour: Mutex<Behaviour>,
    /// Connections accepted.
    connections: Counter,
    /// The bytes of each request that was read to its end (head and body).
    requests: Mutex<Vec<Vec<u8>>>,
    arrived: Counter,
    /// Connections that the proxy closed while the upstream waited (or before a request was complete).
    closed: Counter,
}

/// A loopback listener on a port of its own. It counts every connection, also those that never send a byte.
struct Upstream {
    addr: SocketAddr,
    seen: Arc<Seen>,
    stopping: Arc<AtomicBool>,
    accepter: Option<JoinHandle<Vec<JoinHandle<()>>>>,
}

impl Upstream {
    fn start() -> Upstream {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind the upstream");
        listener
            .set_nonblocking(true)
            .expect("make the upstream non-blocking");
        let addr = listener.local_addr().expect("the upstream address");
        let seen = Arc::new(Seen::default());
        let stopping = Arc::new(AtomicBool::new(false));
        let accepter = {
            let (seen, stopping) = (seen.clone(), stopping.clone());
            thread::spawn(move || accept_loop(&listener, &seen, &stopping))
        };
        Upstream {
            addr,
            seen,
            stopping,
            accepter: Some(accepter),
        }
    }

    fn behave(&self, behaviour: Behaviour) {
        *lock(&self.seen.behaviour) = behaviour;
    }

    fn connections(&self) -> usize {
        self.seen.connections.get()
    }

    fn requests(&self) -> Vec<Vec<u8>> {
        lock(&self.seen.requests).clone()
    }

    /// Closes the listener (the port then refuses connections) once every connection that was waiting to be
    /// accepted has been accepted and counted, and waits for the connection threads. Safe to call twice.
    fn stop(&mut self) {
        self.stopping.store(true, Ordering::SeqCst);
        if let Some(accepter) = self.accepter.take() {
            let handlers = accepter.join().expect("the upstream accept loop panicked");
            for handler in handlers {
                handler.join().expect("an upstream connection panicked");
            }
        }
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        // After a failed test the loop still has to end.
        self.stopping.store(true, Ordering::SeqCst);
    }
}

/// Accepts until told to stop. The listener is non-blocking, and the loop leaves only when the accept queue is
/// empty, so the connections made before the stop are all counted.
fn accept_loop(
    listener: &TcpListener,
    seen: &Arc<Seen>,
    stopping: &AtomicBool,
) -> Vec<JoinHandle<()>> {
    let mut handlers = Vec::new();
    loop {
        match listener.accept() {
            Ok((sock, _)) => {
                seen.connections.add();
                let seen = seen.clone();
                handlers.push(thread::spawn(move || serve_upstream(sock, &seen)));
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                if stopping.load(Ordering::SeqCst) {
                    break;
                }
                thread::sleep(2 * MS);
            }
            Err(_) => break,
        }
    }
    handlers
}

fn serve_upstream(mut sock: TcpStream, seen: &Seen) {
    sock.set_nonblocking(false)
        .expect("make the upstream connection blocking");
    sock.set_read_timeout(Some(PATIENCE))
        .expect("set the upstream read timeout");
    let Some(request) = read_request(&mut sock) else {
        seen.closed.add();
        return;
    };
    lock(&seen.requests).push(request);
    seen.arrived.add();
    let behaviour = *lock(&seen.behaviour);
    match behaviour {
        Behaviour::Reply => {
            let _ = sock.write_all(&upstream_reply());
        }
        Behaviour::Silent => {
            wait_closed(&mut sock);
            seen.closed.add();
        }
        Behaviour::Cut => {
            let _ = sock.write_all(&upstream_cut());
            wait_closed(&mut sock);
            seen.closed.add();
        }
    }
}

/// A request read to its end: the head, and as many body bytes as its `Content-Length` says. `None` if the
/// peer closes first.
fn read_request(sock: &mut TcpStream) -> Option<Vec<u8>> {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    let mut total = None;
    loop {
        if total.is_none()
            && let Some(end) = find(&raw, b"\r\n\r\n")
        {
            let head = Message::parse(&raw[..end + 4]);
            let length = head
                .values("content-length")
                .first()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(0);
            total = Some(end + 4 + length);
        }
        if total.is_some_and(|n| raw.len() >= n) {
            return Some(raw);
        }
        match sock.read(&mut chunk) {
            Ok(0) | Err(_) => return None,
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
        }
    }
}

/// Reads and drops what comes until the peer closes (or the read times out).
fn wait_closed(sock: &mut TcpStream) {
    let mut chunk = [0u8; 4096];
    while matches!(sock.read(&mut chunk), Ok(n) if n > 0) {}
}

// ---------------------------------------------------------------------------------------------------------
// The proxy under test
// ---------------------------------------------------------------------------------------------------------

/// The choices a test makes. These are the test's own values for the scenes, not defaults or recommendations.
#[derive(Clone)]
struct Knobs {
    /// The driver's slice and the kernel's tick.
    slice_ms: u64,
    tick_ms: u64,
    slots: usize,
    wait_deadline_ms: u64,
    max_conns: usize,
    max_buffered_bytes: usize,
    head_read_ms: u64,
    body_read_ms: u64,
    upstream_header_ms: u64,
    response_idle_ms: u64,
    restarts: u32,
    stop_inspect_ms: u64,
    stop_wait_ms: u64,
}

impl Knobs {
    /// Short steps: small requests are inspected in a few milliseconds.
    fn quick() -> Knobs {
        Knobs {
            slice_ms: 20,
            tick_ms: 20,
            slots: 2,
            wait_deadline_ms: 5_000,
            max_conns: 64,
            max_buffered_bytes: 8 << 20,
            head_read_ms: 10_000,
            body_read_ms: 10_000,
            upstream_header_ms: 10_000,
            response_idle_ms: 10_000,
            restarts: 0,
            stop_inspect_ms: 10_000,
            stop_wait_ms: 20_000,
        }
    }

    /// A slice of 400 ms: an inspection of a 1 MiB body takes about 17 slices. A stop leaves the inspection more
    /// time than a whole slow one needs.
    fn slow() -> Knobs {
        Knobs {
            slice_ms: 400,
            tick_ms: 500,
            stop_inspect_ms: 20_000,
            stop_wait_ms: 30_000,
            ..Knobs::quick()
        }
    }
}

fn config_json(k: &Knobs, listen: SocketAddr, upstream: SocketAddr, root: &Path) -> String {
    json!({
        "proxy": {
            "listen": listen.to_string(),
            "upstream": upstream.to_string(),
            "max_conns": k.max_conns,
            "max_head_bytes": 8192,
            "max_body": MAX_BODY,
            "max_body_wire": 2 * MAX_BODY,
            "max_buffered_bytes": k.max_buffered_bytes,
            "upstream_max_headers": 100,
            "upstream_max_head_bytes": 16384,
            "upstream_head_wire": 65536,
            "drive_slice_ms": k.slice_ms,
            "ready_wait_ms": 20_000,
            "head_read_ms": k.head_read_ms,
            "body_read_ms": k.body_read_ms,
            "inspect_wait_ms": 55_000,
            "upstream_connect_ms": 5_000,
            "upstream_header_ms": k.upstream_header_ms,
            "request_total_ms": 60_000,
            "response_idle_ms": k.response_idle_ms,
            "conn_total_ms": 120_000,
            "stop_inspect_ms": k.stop_inspect_ms,
            "stop_wait_ms": k.stop_wait_ms,
        },
        "kernel": {
            "inspector": var("TUKUYOMI_TEST_INSPECTOR"),
            "rules": var("TUKUYOMI_TEST_RULES"),
            "rules_sha256": parse_sha256(&var("TUKUYOMI_TEST_RULES_SHA256")),
            "tmp_root": root.to_string_lossy(),
            "gomaxprocs": 2,
            "gomemlimit": 256 << 20,
            "slots": k.slots,
            // A connection holds at most one inspection, so the queue is never longer than the connections.
            "wait_queue": k.max_conns.min(4),
            "records": 16,
            "discard_limit": 8,
            "tick_ms": k.tick_ms,
            "hello_wait_ms": 10_000,
            "frame_io_ms": 1_000,
            "verdict_wait_ms": 3_000,
            "wait_deadline_ms": k.wait_deadline_ms,
            "closed_wait_ms": 3_000,
            "stop_after_ms": 5_000,
            "drain_wait_ms": 3_000,
            "exit_wait_ms": 3_000,
            "kill_grace_ms": 2_000,
            "restarts": k.restarts,
        },
    })
    .to_string()
}

fn run_kill(signal: &str, pid: u32) {
    let status = Command::new("kill")
        .arg("-s")
        .arg(signal)
        .arg(pid.to_string())
        .status()
        .expect("run the kill command");
    assert!(status.success(), "kill -s {signal} {pid} failed: {status}");
}

/// The processes that are children of any thread of `pid`.
fn children_of(pid: u32) -> Vec<u32> {
    let Ok(tasks) = fs::read_dir(format!("/proc/{pid}/task")) else {
        return Vec::new();
    };
    tasks
        .flatten()
        .filter_map(|task| fs::read_to_string(task.path().join("children")).ok())
        .flat_map(|text| {
            text.split_whitespace()
                .filter_map(|word| word.parse().ok())
                .collect::<Vec<u32>>()
        })
        .collect()
}

/// Whether the process runs the inspector executable of this test.
fn is_inspector(pid: u32) -> bool {
    let wanted = fs::canonicalize(var("TUKUYOMI_TEST_INSPECTOR")).expect("the inspector path");
    fs::read_link(format!("/proc/{pid}/exe")).is_ok_and(|exe| exe == wanted)
}

/// The bytes the process has read so far, from `/proc/<pid>/io`.
fn read_chars(pid: u32) -> Option<u64> {
    fs::read_to_string(format!("/proc/{pid}/io"))
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("rchar:")?.trim().parse().ok())
}

fn assert_gone(pids: &[u32]) {
    for pid in pids {
        assert!(
            !Path::new(&format!("/proc/{pid}")).exists(),
            "inspector process {pid} is still there"
        );
    }
}

/// The kernel's numbers in the record line that the driver writes when it is told to stop.
#[derive(Debug, PartialEq, Eq)]
struct StopCounts {
    records: u64,
    held: u64,
    waiting: u64,
}

impl StopCounts {
    const NONE: StopCounts = StopCounts {
        records: 0,
        held: 0,
        waiting: 0,
    };

    fn of(lines: &[String]) -> StopCounts {
        let line = lines
            .iter()
            .find(|l| l.starts_with("driver: stop, records "))
            .unwrap_or_else(|| panic!("no stop line in {lines:#?}"));
        let numbers: Vec<u64> = line
            .split(|c: char| !c.is_ascii_digit())
            .filter(|s| !s.is_empty())
            .map(|s| s.parse().expect("a number"))
            .collect();
        match numbers[..] {
            [records, held, waiting] => StopCounts {
                records,
                held,
                waiting,
            },
            _ => panic!("cannot read the stop line {line:?}"),
        }
    }
}

struct Proxy {
    root: PathBuf,
    port: u16,
    pid: u32,
    exit: Receiver<io::Result<ExitStatus>>,
    reader: Option<JoinHandle<()>>,
    records: Arc<Records>,
    upstream: Upstream,
    /// Every inspector process that was seen, to check at the end that none is left.
    inspectors: Vec<u32>,
    knobs: Knobs,
    done: bool,
}

impl Proxy {
    /// Starts the proxy and waits until it listens and its inspector is there.
    fn start(test: &str, knobs: Knobs) -> Proxy {
        let root = make_root(test);
        let upstream = Upstream::start();
        let port = free_port();
        let listen = SocketAddr::from(([127, 0, 0, 1], port));
        let config = root.join("config.json");
        fs::write(&config, config_json(&knobs, listen, upstream.addr, &root))
            .expect("write the configuration");
        let mut child = Command::new(env!("CARGO_BIN_EXE_tukuyomi-proxy"))
            .arg(&config)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start the proxy");
        let pid = child.id();
        let stderr = child.stderr.take().expect("the proxy's stderr is piped");
        let records = Arc::new(Records::default());
        let reader = {
            let records = records.clone();
            thread::spawn(move || {
                let mut input = BufReader::new(stderr);
                let mut buf = Vec::new();
                loop {
                    buf.clear();
                    match input.read_until(b'\n', &mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => records.push(String::from_utf8_lossy(&buf).trim_end().to_string()),
                    }
                }
                records.end();
            })
        };
        let (tx, exit) = mpsc::channel();
        thread::spawn(move || {
            let _ = tx.send(child.wait());
        });
        let mut proxy = Proxy {
            root,
            port,
            pid,
            exit,
            reader: Some(reader),
            records,
            upstream,
            inspectors: Vec::new(),
            knobs,
            done: false,
        };
        proxy
            .records
            .wait_line("the proxy to listen", |l| l == "start: listening");
        proxy.wait_inspector(None);
        proxy
    }

    /// Waits for a live inspector process other than `old`, and remembers it.
    fn wait_inspector(&mut self, old: Option<u32>) -> u32 {
        let mut found = None;
        wait_until("an inspector process", || {
            let live: Vec<u32> = children_of(self.pid)
                .into_iter()
                .filter(|&pid| Some(pid) != old && is_inspector(pid))
                .collect();
            found = live.first().copied();
            live.len() == 1
        });
        let pid = found.expect("an inspector was found");
        self.inspectors.push(pid);
        pid
    }

    /// The inspector the test is talking to.
    fn inspector(&self) -> u32 {
        *self.inspectors.last().expect("an inspector was seen")
    }

    /// Sends `request` on a new connection and returns once the inspector has read the first body frame, so the
    /// request is being inspected. The slice makes the rest of the inspection last for seconds.
    fn start_slow(&self, request: &[u8]) -> TcpStream {
        let pid = self.inspector();
        let base = read_chars(pid).expect("read the inspector's counter");
        let mut sock = connect(self.port);
        sock.write_all(request).expect("send the request");
        wait_until("the inspector to read the body", || {
            read_chars(pid).is_some_and(|now| now >= base + FRAME)
        });
        sock
    }

    fn term(&self) -> Instant {
        run_kill("TERM", self.pid);
        Instant::now()
    }

    /// Ends the test: SIGTERM, a clean exit within `stop_wait`, and then every check of what must be left (or
    /// not left): the records, the processes, the root, the upstream's connection count.
    fn finish(self, upstream_connections: usize) -> StopCounts {
        let since = self.term();
        self.finish_after_term(since, upstream_connections)
    }

    /// The same, for a test that has sent SIGTERM at `since` itself.
    fn finish_after_term(mut self, since: Instant, upstream_connections: usize) -> StopCounts {
        let limit = Duration::from_millis(self.knobs.stop_wait_ms) + 30 * SEC;
        let status = self
            .exit
            .recv_timeout(limit)
            .unwrap_or_else(|_| {
                panic!(
                    "the proxy did not exit; its records: {:#?}",
                    self.records.lines()
                )
            })
            .expect("wait for the proxy");
        let took = since.elapsed();
        self.done = true;
        self.reader
            .take()
            .expect("the reader runs")
            .join()
            .expect("the reader panicked");
        let lines = self.records.lines();
        assert_eq!(
            status.code(),
            Some(0),
            "exit status {status}; records: {lines:#?}"
        );
        assert!(
            took < Duration::from_millis(self.knobs.stop_wait_ms),
            "the proxy needed {took:?} to stop; stop_wait is {} ms",
            self.knobs.stop_wait_ms
        );
        assert!(
            lines.iter().any(|l| l == "stop: SIGTERM"),
            "no stop record: {lines:#?}"
        );
        assert!(
            lines.iter().any(|l| l.starts_with(
                "stop: kernel Stopped, bye true, exit_confirmed true, dir_removed true, held_left 0, waiting_left 0"
            )),
            "the kernel did not stop cleanly: {lines:#?}"
        );
        assert!(
            !lines.iter().any(|l| l.contains("panic")
                || l.contains("internal fault")
                || l.contains("log lines dropped")),
            "the records show a fault: {lines:#?}"
        );
        let counts = StopCounts::of(&lines);
        assert_gone(&self.inspectors);

        // Only the configuration is left in the root: the kernel removed its own directory.
        let left: Vec<_> = fs::read_dir(&self.root)
            .expect("the test root is readable")
            .map(|e| e.map(|e| e.file_name()))
            .collect::<Result<_, _>>()
            .expect("list the test root");
        assert_eq!(
            left,
            ["config.json"],
            "the test root holds more than the configuration"
        );
        fs::remove_file(self.root.join("config.json")).expect("remove the configuration");
        fs::remove_dir(&self.root).expect("the empty test root is removed");

        // The proxy is gone, so every connection it made to the upstream has been accepted by now.
        self.upstream.stop();
        assert_eq!(
            self.upstream.connections(),
            upstream_connections,
            "connections to the upstream; records: {lines:#?}"
        );
        counts
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        // A test that failed: leave no proxy and no inspector behind.
        let _ = Command::new("kill")
            .args(["-s", "KILL", &self.pid.to_string()])
            .status();
        for &pid in &self.inspectors {
            if is_inspector(pid) {
                let _ = Command::new("kill")
                    .args(["-s", "KILL", &pid.to_string()])
                    .status();
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------------------
// Forwarding, rule blocks and refusals
// ---------------------------------------------------------------------------------------------------------

#[test]
#[ignore = "needs a built inspector"]
fn an_allowed_get_is_forwarded_without_hop_by_hop_fields_and_with_forwarding_fields() {
    let proxy = Proxy::start("forward_get", Knobs::quick());
    let request = concat!(
        "GET /ok?q=1 HTTP/1.1\r\n",
        "Host: example.test\r\n",
        "X-Keep: kept\r\n",
        "X-Forwarded-For: 203.0.113.7\r\n",
        "X-Forwarded-Host: spoofed.test\r\n",
        "X-Forwarded-Proto: https\r\n",
        "Connection: keep-alive, X-Hop\r\n",
        "X-Hop: 1\r\n",
        "Keep-Alive: timeout=5\r\n",
        "Proxy-Connection: keep-alive\r\n",
        "Proxy-Authorization: Basic eDp5\r\n",
        "TE: trailers\r\n",
        "Trailer: X-Late\r\n",
        "Upgrade: h2c\r\n",
        "\r\n"
    );
    let reply = exchange(proxy.port, request.as_bytes());
    let answer = reply.message();
    assert_eq!(answer.status(), 200, "answer: {:?}", reply.text());
    assert_eq!(answer.body, UPSTREAM_BODY.as_bytes());
    // The upstream's own hop-by-hop fields, and the field it listed in `Connection`, do not reach the client.
    assert_eq!(answer.values("x-up"), ["visible"]);
    assert!(
        !answer.names().contains(&"keep-alive") && !answer.names().contains(&"x-up-hop"),
        "answer fields: {:?}",
        answer.names()
    );
    assert_eq!(answer.values("connection"), ["close"]);

    proxy
        .upstream
        .seen
        .arrived
        .wait_for("the upstream's request", 1);
    let requests = proxy.upstream.requests();
    assert_eq!(requests.len(), 1);
    let seen = Message::parse(&requests[0]);
    assert_eq!(seen.start, "GET /ok?q=1 HTTP/1.1");
    for name in [
        "keep-alive",
        "proxy-connection",
        "proxy-authorization",
        "proxy-authenticate",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "expect",
        "x-hop",
    ] {
        assert!(
            !seen.names().contains(&name),
            "the upstream saw {name}: {:?}",
            seen.fields
        );
    }
    // The proxy ends the upstream connection itself, and says so once.
    assert_eq!(seen.values("connection"), ["close"]);
    assert_eq!(seen.values("host"), ["example.test"]);
    assert_eq!(seen.values("x-keep"), ["kept"]);
    assert_eq!(seen.values("x-forwarded-for"), ["203.0.113.7, 127.0.0.1"]);
    assert_eq!(seen.values("x-forwarded-host"), ["example.test"]);
    assert_eq!(seen.values("x-forwarded-proto"), ["http"]);
    assert!(seen.body.is_empty());

    proxy.records.conn("the forwarded record", |l| {
        l.contains(": forwarded 200 forwarded rule - ")
    });
    assert_eq!(proxy.finish(1), StopCounts::NONE);
}

#[test]
#[ignore = "needs a built inspector"]
fn the_uri_rule_blocks_with_its_status_and_the_upstream_is_not_contacted() {
    let proxy = Proxy::start("uri_block", Knobs::quick());
    let blocked = exchange(proxy.port, &get("/block-probe/x"));
    assert_empty_answer(&blocked, 403);
    proxy.records.conn("the blocked record", |l| {
        l.contains(": blocked 403 blocked by a rule rule 9201 ")
    });
    assert_eq!(proxy.upstream.connections(), 0);

    // A request the rule does not match passes on the same proxy.
    let passed = exchange(proxy.port, &get("/other"));
    assert_eq!(passed.status(), 200);
    assert_eq!(passed.message().body, UPSTREAM_BODY.as_bytes());
    assert_eq!(proxy.finish(1), StopCounts::NONE);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_stopped_upstream_gives_502() {
    let mut proxy = Proxy::start("upstream_stopped", Knobs::quick());
    let first = exchange(proxy.port, &get("/up"));
    assert_eq!(first.status(), 200);

    // The listener is closed: the port refuses connections now.
    proxy.upstream.stop();
    let second = exchange(proxy.port, &get("/down"));
    assert_empty_answer(&second, 502);
    proxy.records.conn("the 502 record", |l| {
        l.contains(": failed 502 upstream connection failed ")
    });
    assert_eq!(proxy.finish(1), StopCounts::NONE);
}

#[test]
#[ignore = "needs a built inspector"]
fn transfer_encoding_with_content_length_gives_400_and_no_upstream_connection() {
    let proxy = Proxy::start("te_and_cl", Knobs::quick());
    // Both orders: the second is the one that a parser which drops the length after the coding would hide.
    for fields in [
        "Transfer-Encoding: chunked\r\nContent-Length: 11\r\n",
        "Content-Length: 11\r\nTransfer-Encoding: chunked\r\n",
    ] {
        let request = format!(
            "POST /x HTTP/1.1\r\nHost: example.test\r\nContent-Type: {URLENCODED}\r\n{fields}\r\nb\r\nprobe=block\r\n0\r\n\r\n"
        );
        let reply = exchange(proxy.port, request.as_bytes());
        assert_empty_answer(&reply, 400);
    }
    proxy.records.conns("two malformed-head records", 2, |l| {
        l.contains(": rejected 400 malformed request head ")
    });
    assert_eq!(proxy.upstream.connections(), 0);
    assert_eq!(proxy.finish(0), StopCounts::NONE);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_content_length_over_the_limit_gives_413_and_no_100_continue() {
    let proxy = Proxy::start("too_large", Knobs::quick());

    // A control: a request within the limit that asks for it gets its 100 Continue, so the missing one below means
    // something. The upstream does not see the Expect field.
    let head = format!(
        "POST /ok HTTP/1.1\r\nHost: example.test\r\nContent-Type: {URLENCODED}\r\nContent-Length: 8\r\nExpect: 100-continue\r\n\r\n"
    );
    let mut sock = connect(proxy.port);
    let start = Instant::now();
    sock.write_all(head.as_bytes()).expect("send the head");
    let interim = read_until(&mut sock, b"\r\n\r\n");
    assert_eq!(interim, b"HTTP/1.1 100 Continue\r\n\r\n");
    sock.write_all(b"probe=ok").expect("send the body");
    let allowed = collect(&mut sock, start);
    assert_eq!(allowed.status(), 200, "answer: {:?}", allowed.text());
    let requests = proxy.upstream.requests();
    let seen = Message::parse(&requests[0]);
    assert!(
        !seen.names().contains(&"expect"),
        "fields: {:?}",
        seen.fields
    );
    assert_eq!(seen.body, b"probe=ok");

    // Over the limit by one byte: the answer is 413 at once, and no 100 Continue is sent for a body that
    // cannot be taken.
    let head = format!(
        "POST /big HTTP/1.1\r\nHost: example.test\r\nContent-Type: {URLENCODED}\r\nContent-Length: {}\r\nExpect: 100-continue\r\n\r\n",
        MAX_BODY + 1
    );
    let refused = exchange(proxy.port, head.as_bytes());
    assert!(
        !refused.text().contains("100 Continue"),
        "answer: {:?}",
        refused.text()
    );
    assert_empty_answer(&refused, 413);
    proxy.records.conn("the 413 record", |l| {
        l.contains(": rejected 413 body over the limit ")
    });
    assert_eq!(proxy.upstream.connections(), 1);
    assert_eq!(proxy.finish(1), StopCounts::NONE);
}

// ---------------------------------------------------------------------------------------------------------
// Stopping, a client that leaves, and the deadlines
// ---------------------------------------------------------------------------------------------------------

#[test]
#[ignore = "needs a built inspector"]
fn sigterm_lets_an_in_flight_request_finish_and_the_proxy_exits_within_stop_wait() {
    let proxy = Proxy::start("sigterm_in_flight", Knobs::slow());
    let mut sock = proxy.start_slow(&post_form("/submit", &padded_form("ok", MAX_BODY)));
    let since = proxy.term();

    // The inspection goes on after the signal, the request is forwarded, and its answer comes back whole.
    let answer = collect(&mut sock, since);
    assert_eq!(answer.status(), 200, "answer: {:?}", answer.text());
    assert_eq!(answer.message().body, UPSTREAM_BODY.as_bytes());
    let requests = proxy.upstream.requests();
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0].len() > MAX_BODY,
        "the upstream got {} bytes",
        requests[0].len()
    );

    let counts = proxy.finish_after_term(since, 1);
    assert!(
        counts.records >= 1,
        "the request was in flight when the stop began: {counts:?}"
    );
}

#[test]
#[ignore = "needs a built inspector"]
fn a_client_that_goes_away_during_the_inspection_causes_no_upstream_connection() {
    // One slot: the next request can only be inspected when the slot of the abandoned one is free again.
    let knobs = Knobs {
        slots: 1,
        wait_deadline_ms: 20_000,
        ..Knobs::slow()
    };
    let proxy = Proxy::start("client_gone", knobs);
    // Exactly the declared bytes and nothing after them, so the proxy sees the close.
    let sock = proxy.start_slow(&post_form("/submit", &padded_form("ok", MAX_BODY)));
    let gone = Instant::now();
    drop(sock);
    proxy
        .records
        .conn("the record of the abandoned connection", |l| {
            l.contains(": closed 0 ")
        });
    // The connection ended long before the inspection could have (it needs several seconds).
    assert!(gone.elapsed() < 3 * SEC, "took {:?}", gone.elapsed());
    assert_eq!(proxy.upstream.connections(), 0);

    let after = exchange(proxy.port, &get("/after"));
    assert_eq!(after.status(), 200, "answer: {:?}", after.text());
    assert_eq!(proxy.finish(1), StopCounts::NONE);
}

#[test]
#[ignore = "needs a built inspector"]
fn the_head_deadline_gives_408_and_the_connection_permits_come_back() {
    let knobs = Knobs {
        max_conns: 2,
        head_read_ms: 1_500,
        ..Knobs::quick()
    };
    let proxy = Proxy::start("head_deadline", knobs);
    // Two connections that never finish their head hold both permits.
    let partial = b"GET /slow HTTP/1.1\r\nHost: example.test\r\n";
    let started = Instant::now();
    let mut a = connect(proxy.port);
    a.write_all(partial).expect("send half a head");
    let mut b = connect(proxy.port);
    b.write_all(partial).expect("send half a head");

    // A third request is not accepted before a permit is back, so it is answered only after the deadline.
    let third = exchange(proxy.port, &get("/third"));
    assert_eq!(third.status(), 200, "answer: {:?}", third.text());
    assert!(
        third.took >= SEC,
        "the third request was answered after {:?}; it should have waited for a permit",
        third.took
    );
    for sock in [&mut a, &mut b] {
        let late = collect(sock, started);
        assert_empty_answer(&late, 408);
        assert!(late.took >= SEC, "408 after {:?}", late.took);
    }
    proxy.records.conns("two head-deadline records", 2, |l| {
        l.contains(": rejected 408 head not received in time ")
    });
    assert_eq!(proxy.finish(1), StopCounts::NONE);
}

#[test]
#[ignore = "needs a built inspector"]
fn the_body_deadline_gives_408_and_the_byte_budget_comes_back() {
    let knobs = Knobs {
        max_buffered_bytes: MIN_BUFFERED,
        body_read_ms: 3_000,
        ..Knobs::quick()
    };
    let proxy = Proxy::start("body_deadline", knobs);
    // Two requests that declare the largest body and send a little of it hold all but 24 KiB of the budget.
    let stalled = || {
        let mut sock = connect(proxy.port);
        let head = format!(
            "POST /stall HTTP/1.1\r\nHost: example.test\r\nContent-Type: {URLENCODED}\r\nContent-Length: {MAX_BODY}\r\n\r\n"
        );
        sock.write_all(head.as_bytes()).expect("send the head");
        sock.write_all(&padded_form("ok", 100))
            .expect("send a little of the body");
        sock
    };
    let started = Instant::now();
    let mut a = stalled();
    let mut b = stalled();

    // A 30 KiB body that the rule blocks needs more than is left. It is refused for the budget (503) once the
    // two requests above hold theirs; before that it reaches the rule (403), so it is sent again.
    let small = post_form("/small", &padded_form("block", 30 * 1024));
    let refused = loop {
        let reply = exchange(proxy.port, &small);
        match reply.status() {
            503 => break reply,
            403 => {}
            other => panic!("status {other}: {:?}", reply.text()),
        }
        assert!(
            started.elapsed() < 2 * SEC,
            "the stalled requests did not take the budget"
        );
        thread::sleep(20 * MS);
    };
    assert_empty_answer(&refused, 503);
    proxy.records.conn("the budget record", |l| {
        l.contains(": failed 503 byte budget exhausted ")
    });
    for sock in [&mut a, &mut b] {
        let late = collect(sock, started);
        assert_empty_answer(&late, 408);
        assert!(late.took >= 2 * SEC, "408 after {:?}", late.took);
    }
    proxy.records.conns("two body-deadline records", 2, |l| {
        l.contains(": rejected 408 body not received in time ")
    });

    // The budget is back: the same request now reaches the rule, and a normal one passes.
    let again = exchange(proxy.port, &small);
    assert_empty_answer(&again, 403);
    let normal = exchange(proxy.port, &get("/after"));
    assert_eq!(normal.status(), 200, "answer: {:?}", normal.text());
    assert_eq!(proxy.finish(1), StopCounts::NONE);
}

#[test]
#[ignore = "needs a built inspector"]
fn the_upstream_header_deadline_gives_502_and_the_resources_come_back() {
    let knobs = Knobs {
        max_buffered_bytes: MIN_BUFFERED,
        upstream_header_ms: 1_500,
        ..Knobs::quick()
    };
    let proxy = Proxy::start("upstream_header_deadline", knobs);
    proxy.upstream.behave(Behaviour::Silent);
    // 600 KiB twice cannot be held at once with the minimum budget (each takes the body and the kernel's copy),
    // so the second request passes only if the first gave its bytes back.
    let big = post_form("/slow", &padded_form("ok", 600 * 1024));
    let first = exchange(proxy.port, &big);
    assert_empty_answer(&first, 502);
    assert!(first.took >= SEC, "502 after {:?}", first.took);
    proxy.records.conn("the 502 record", |l| {
        l.contains(": failed 502 upstream response head failed ")
    });
    proxy
        .upstream
        .seen
        .arrived
        .wait_for("the request at the upstream", 1);
    // The proxy dropped its connection to the upstream.
    proxy
        .upstream
        .seen
        .closed
        .wait_for("the proxy to close its upstream connection", 1);

    proxy.upstream.behave(Behaviour::Reply);
    let second = exchange(proxy.port, &big);
    assert_eq!(second.status(), 200, "answer: {:?}", second.text());
    assert_eq!(proxy.finish(2), StopCounts::NONE);
}

#[test]
#[ignore = "needs a built inspector"]
fn the_response_idle_deadline_cuts_a_stalled_answer_without_its_end() {
    let knobs = Knobs {
        response_idle_ms: 1_500,
        ..Knobs::quick()
    };
    let proxy = Proxy::start("response_idle_deadline", knobs);
    proxy.upstream.behave(Behaviour::Cut);
    let cut = exchange(proxy.port, &get("/cut"));
    let answer = cut.message();
    assert_eq!(answer.status(), 200, "answer: {:?}", cut.text());
    // Three of the ten promised bytes arrived, and the connection was closed after the idle time.
    assert_eq!(answer.values("content-length"), ["10"]);
    assert_eq!(answer.body, b"abc");
    assert!(cut.took >= SEC, "closed after {:?}", cut.took);
    proxy.records.conn("the cut-off record", |l| {
        l.contains(": forwarded 200 closed while the response was sent ")
    });
    proxy
        .upstream
        .seen
        .closed
        .wait_for("the proxy to close its upstream connection", 1);

    proxy.upstream.behave(Behaviour::Reply);
    let next = exchange(proxy.port, &get("/after"));
    assert_eq!(next.status(), 200, "answer: {:?}", next.text());
    assert_eq!(proxy.finish(2), StopCounts::NONE);
}

// ---------------------------------------------------------------------------------------------------------
// Bodies
// ---------------------------------------------------------------------------------------------------------

#[test]
#[ignore = "needs a built inspector"]
fn a_urlencoded_body_rule_blocks_a_body_with_a_content_length() {
    let proxy = Proxy::start("body_block_length", Knobs::quick());
    let blocked = exchange(proxy.port, &post_form("/submit", b"probe=block"));
    assert_empty_answer(&blocked, 403);
    proxy.records.conn("the blocked record", |l| {
        l.contains(": blocked 403 blocked by a rule rule 9202 ")
    });
    assert_eq!(proxy.upstream.connections(), 0);

    let passed = exchange(proxy.port, &post_form("/submit", b"probe=ok"));
    assert_eq!(passed.status(), 200, "answer: {:?}", passed.text());
    let requests = proxy.upstream.requests();
    assert_eq!(requests.len(), 1);
    let seen = Message::parse(&requests[0]);
    assert_eq!(seen.start, "POST /submit HTTP/1.1");
    assert_eq!(seen.values("content-length"), ["8"]);
    assert_eq!(seen.body, b"probe=ok");
    assert_eq!(proxy.finish(1), StopCounts::NONE);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_urlencoded_body_rule_blocks_a_chunked_body_and_a_clean_one_is_forwarded_with_a_length() {
    let proxy = Proxy::start("body_block_chunked", Knobs::quick());
    // The rule's argument is split over two chunks: the body is decoded before it is inspected.
    let blocked = exchange(
        proxy.port,
        &chunked_request("/submit", &chunked_body(&[b"pro", b"be=block"], b"")),
    );
    assert_empty_answer(&blocked, 403);
    proxy.records.conn("the blocked record", |l| {
        l.contains(": blocked 403 blocked by a rule rule 9202 ")
    });
    assert_eq!(proxy.upstream.connections(), 0);

    let passed = exchange(
        proxy.port,
        &chunked_request("/submit", &chunked_body(&[b"pro", b"be=ok"], b"")),
    );
    assert_eq!(passed.status(), 200, "answer: {:?}", passed.text());
    let requests = proxy.upstream.requests();
    assert_eq!(requests.len(), 1);
    // What was inspected is what was forwarded: the decoded body, with its length and without the coding.
    let seen = Message::parse(&requests[0]);
    assert!(
        !seen.names().contains(&"transfer-encoding"),
        "fields: {:?}",
        seen.fields
    );
    assert_eq!(seen.values("content-length"), ["8"]);
    assert_eq!(seen.body, b"probe=ok");
    assert_eq!(proxy.finish(1), StopCounts::NONE);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_broken_chunked_body_and_a_non_empty_trailer_give_400() {
    let proxy = Proxy::start("chunked_400", Knobs::quick());
    let cases: [(&[u8], &str); 3] = [
        (b"zz\r\nabc\r\n0\r\n\r\n", "malformed body"),
        (b"3\r\nabcXX0\r\n\r\n", "malformed body"),
        (
            &chunked_body(&[b"abc"], b"X-Late: v\r\n"),
            "request trailers not supported",
        ),
    ];
    for (body, reason) in cases {
        let reply = exchange(proxy.port, &chunked_request("/submit", body));
        assert_empty_answer(&reply, 400);
        proxy
            .records
            .conn(reason, |l| l.contains(&format!(": rejected 400 {reason} ")));
    }
    assert_eq!(proxy.upstream.connections(), 0);
    assert_eq!(proxy.finish(0), StopCounts::NONE);
}

#[test]
#[ignore = "needs a built inspector"]
fn json_and_gzip_bodies_give_415() {
    let proxy = Proxy::start("media_415", Knobs::quick());
    let json = b"{\"probe\":\"block\"}";
    let json_request = format!(
        "POST /j HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        json.len(),
        String::from_utf8_lossy(json)
    );
    // A gzip stream (header bytes only; it is refused before anything looks at it).
    let mut gzip_request = format!(
        "POST /g HTTP/1.1\r\nHost: example.test\r\nContent-Type: {URLENCODED}\r\nContent-Encoding: gzip\r\nContent-Length: 10\r\n\r\n"
    )
    .into_bytes();
    gzip_request.extend_from_slice(&[0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3]);
    let mut chunked_json = b"POST /c HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    chunked_json.extend_from_slice(&chunked_body(&[json], b""));
    for request in [json_request.into_bytes(), gzip_request, chunked_json] {
        let reply = exchange(proxy.port, &request);
        assert_empty_answer(&reply, 415);
    }
    proxy.records.conns("three 415 records", 3, |l| {
        l.contains(": rejected 415 body type not supported ")
    });
    assert_eq!(proxy.upstream.connections(), 0);

    // Not a state of the proxy: a normal request still passes.
    let normal = exchange(proxy.port, &get("/after"));
    assert_eq!(normal.status(), 200, "answer: {:?}", normal.text());
    assert_eq!(proxy.finish(1), StopCounts::NONE);
}

#[test]
#[ignore = "needs a built inspector"]
fn killing_the_inspector_during_an_inspection_gives_503_and_no_upstream_connection() {
    // One restart in the budget: without it the kernel would give up, and the proxy would stop on that failure.
    let knobs = Knobs {
        restarts: 1,
        ..Knobs::slow()
    };
    let mut proxy = Proxy::start("kill_inspector", knobs);
    let victim = proxy.inspector();
    let mut sock = proxy.start_slow(&post_form("/submit", &padded_form("ok", MAX_BODY)));
    run_kill("KILL", victim);
    let answer = collect(&mut sock, Instant::now());
    assert_empty_answer(&answer, 503);
    proxy
        .records
        .conn("the 503 record", |l| l.contains(": failed 503 inspector "));
    assert_eq!(proxy.upstream.connections(), 0);

    // The kernel started a new inspector, and a normal request passes through it.
    let after = exchange(proxy.port, &get("/after"));
    assert_eq!(after.status(), 200, "answer: {:?}", after.text());
    let replacement = proxy.wait_inspector(Some(victim));
    assert_ne!(replacement, victim);
    assert_eq!(proxy.finish(1), StopCounts::NONE);
}
