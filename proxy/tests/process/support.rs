use std::fs::{self, DirBuilder};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use flate2::Compression;
use flate2::write::GzEncoder;
use serde_json::{Value, json};

pub(crate) const MS: Duration = Duration::from_millis(1);
pub(crate) const SEC: Duration = Duration::from_secs(1);
/// How long a test waits for something that must happen. Reaching it is a failure, never a pass.
const PATIENCE: Duration = Duration::from_secs(60);

pub(crate) const URLENCODED: &str = "application/x-www-form-urlencoded";
pub(crate) const JSON: &str = "application/json";
/// The largest body the proxy is configured to take, which is also the largest body the kernel accepts.
pub(crate) const MAX_BODY: usize = 1 << 20;
/// The inspector has read a body frame (64 KiB) once its read counter has grown by this much.
const FRAME: u64 = 64 * 1024;
/// The body of the upstream's answer.
pub(crate) const UPSTREAM_BODY: &str = "hello-from-upstream";
/// The longest head the proxy reads from the upstream, interim answers included (`upstream_head_wire`).
pub(crate) const UPSTREAM_HEAD_WIRE: usize = 64 * 1024;
/// The time the kernel gives a process to end after it was told to stop (`kill_grace`).
pub(crate) const KILL_GRACE_MS: u64 = 2_000;
/// The time the proxy may take to look up the names of the upstream servers.
pub(crate) const RESOLVE_TIMEOUT_MS: u64 = 30_000;
/// The name of the rules store directory, in the test root.
pub(crate) const STORE: &str = "store";
/// What a test adds to a time it has computed, where it only needs the event to come about in reasonable time.
pub(crate) const MARGIN: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------------------------------------
// The environment
// ---------------------------------------------------------------------------------------------------------

fn var(name: &str) -> String {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => v,
        _ => panic!("{name} is not set: this real-process test needs it and is never skipped"),
    }
}

/// The rules hash as the name of a generation wants it: 64 lowercase hex digits.
fn parse_sha256(s: &str) -> String {
    assert!(
        s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()),
        "TUKUYOMI_TEST_RULES_SHA256 must be 64 hex digits"
    );
    s.to_ascii_lowercase()
}

/// The name of the generation that the store of a test holds: the fingerprint of the test rules.
pub(crate) fn generation() -> String {
    parse_sha256(&var("TUKUYOMI_TEST_RULES_SHA256"))
}

/// The rule file of the test rules, which `rules import` takes as `--rules`: the bundle of the test rules has this one
/// file, so the generation that the import makes is the one that `generation` names.
pub(crate) fn rules_file() -> PathBuf {
    Path::new(&var("TUKUYOMI_TEST_RULES"))
        .join("rules")
        .join("basic.conf")
}

/// The directory of that generation, in the store of the test root `root`.
pub(crate) fn generation_dir(root: &Path) -> PathBuf {
    root.join(STORE).join("generations").join(generation())
}

fn make_dir(path: &Path) {
    DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(path)
        .unwrap_or_else(|e| panic!("cannot create {path:?}: {e}"));
}

/// Copies the regular files of the directory `from` to `to`, with the directories below it, each made 0700. Anything
/// else in `from` fails the test: a copy that left it out would only show up as a refusal of the inspector.
fn copy_tree(from: &Path, to: &Path) {
    make_dir(to);
    for entry in fs::read_dir(from).unwrap_or_else(|e| panic!("cannot read {from:?}: {e}")) {
        let entry = entry.expect("list a directory of the rules");
        let (source, target) = (entry.path(), to.join(entry.file_name()));
        let kind = entry
            .file_type()
            .expect("the kind of an entry of the rules");
        if kind.is_dir() {
            copy_tree(&source, &target);
        } else if kind.is_file() {
            fs::copy(&source, &target).unwrap_or_else(|e| panic!("cannot copy {source:?}: {e}"));
        } else {
            panic!("{source:?} is neither a directory nor a regular file");
        }
    }
}

/// The rules store of a test root: the bundle in `TUKUYOMI_TEST_RULES` as the generation named by
/// `TUKUYOMI_TEST_RULES_SHA256`, and `current`, which chooses it. The directories are 0700, as the proxy demands
/// of the store directory.
fn make_store(root: &Path) {
    copy_tree(
        Path::new(&var("TUKUYOMI_TEST_RULES")),
        &generation_dir(root),
    );
    fs::write(
        root.join(STORE).join("current"),
        format!("{}\n", generation()),
    )
    .expect("write the record of the current generation");
}

/// A fresh 0700 directory, removed with everything in it when dropped.
struct TestDir(PathBuf);

impl TestDir {
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A new 0700 root for one test, under `TUKUYOMI_TEST_TMP`. Its name has the process id and the test name, so
/// earlier runs do not meet. The end of a test removes it, and fails if it holds anything but the configuration.
/// A test that fails leaves nothing in `TUKUYOMI_TEST_TMP`: the guard removes the root with what it holds.
fn make_root(test: &str) -> TestDir {
    let root =
        PathBuf::from(var("TUKUYOMI_TEST_TMP")).join(format!("{test}-{}", std::process::id()));
    DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .unwrap_or_else(|e| panic!("cannot create the test root {root:?}: {e}"));
    // The guard owns the root from here on, also when the check below fails.
    let root = TestDir(root);
    let mode = fs::symlink_metadata(root.path())
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
// The record stream
// ---------------------------------------------------------------------------------------------------------

/// What the proxy writes to stderr, as it arrives: one JSON object per line, each with a time (`ts`) and a type
/// (`type`: `line` for a text of the process such as `start: listening`, `request`, `connection`, `tunnel` or
/// `dropped`). A line that is not such an object is kept as the text it is, and fails the test that looks at the
/// records.
#[derive(Default)]
pub(crate) struct Records {
    items: Mutex<Vec<Value>>,
    /// The proxy closed its stderr.
    ended: AtomicBool,
}

impl Records {
    /// Every record, parsed.
    pub(crate) fn all(&self) -> Vec<Value> {
        let items = lock(&self.items).clone();
        for item in &items {
            let ts = item["ts"].as_str().unwrap_or_default();
            assert!(
                ts.len() == 24 && ts.ends_with('Z') && item["type"].is_string(),
                "not a record of the proxy: {item}"
            );
        }
        items
    }

    /// The text of every record: the `line` of a record of the type `line`, and the JSON text of any other.
    pub(crate) fn lines(&self) -> Vec<String> {
        self.all()
            .into_iter()
            .map(|item| match item["line"].as_str() {
                Some(text) if item["type"] == "line" => text.to_string(),
                _ => item.to_string(),
            })
            .collect()
    }

    /// Waits for `n` records that satisfy `want` (records that are there already count) and returns them. Fails
    /// with all the records when the proxy ends first or nothing comes in time.
    pub(crate) fn wait_records(
        &self,
        what: &str,
        n: usize,
        want: impl Fn(&Value) -> bool,
    ) -> Vec<Value> {
        let deadline = Instant::now() + PATIENCE;
        loop {
            // The end is read first: the records are all there once it is set.
            let ended = self.ended.load(Ordering::SeqCst);
            let found: Vec<Value> = self.all().into_iter().filter(|r| want(r)).collect();
            if found.len() >= n {
                return found;
            }
            assert!(
                !ended,
                "the proxy ended before {what}; its records: {:#?}",
                self.lines()
            );
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {what}; the records so far: {:#?}",
                self.lines()
            );
            thread::sleep(5 * MS);
        }
    }

    /// Waits for `n` texts of the process (the `line` of the records of the type `line`) that satisfy `want`.
    pub(crate) fn wait_lines(
        &self,
        what: &str,
        n: usize,
        want: impl Fn(&str) -> bool,
    ) -> Vec<String> {
        self.wait_records(what, n, |r| {
            r["type"] == "line" && r["line"].as_str().is_some_and(&want)
        })
        .iter()
        .map(|r| r["line"].as_str().unwrap_or_default().to_string())
        .collect()
    }

    /// The record of a request, a connection or a tunnel that satisfies `want`.
    pub(crate) fn conn(&self, what: &str, want: impl Fn(&Value) -> bool) -> Value {
        self.conns(what, 1, want).remove(0)
    }

    /// `n` records of a request, a connection or a tunnel that satisfy `want`.
    pub(crate) fn conns(&self, what: &str, n: usize, want: impl Fn(&Value) -> bool) -> Vec<Value> {
        self.wait_records(what, n, |r| r["type"] != "line" && want(r))
    }
}

/// Whether `record` is the record of an answer that was written to a client, with this class, status and reason.
pub(crate) fn is_answer(record: &Value, class: &str, status: u16, reason: &str) -> bool {
    record["type"] == "request" && shows(record, class, status, reason)
}

/// Whether `record` shows this class, status and reason, whether it is the record of a request or of a connection
/// (a connection that ended with no answer shows the class `closed` and the status 0).
pub(crate) fn shows(record: &Value, class: &str, status: u16, reason: &str) -> bool {
    record["class"] == class && record["status"] == status && record["reason"] == reason
}

/// Whether `record` has no `key`: a value that there is none of is not written.
pub(crate) fn no(record: &Value, key: &str) -> bool {
    record.get(key).is_none()
}

// ---------------------------------------------------------------------------------------------------------
// HTTP text
// ---------------------------------------------------------------------------------------------------------

pub(crate) fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// A message split into its start line, its fields (lower-case name, trimmed value) and its body.
pub(crate) struct Message {
    pub(crate) start: String,
    pub(crate) fields: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

impl Message {
    pub(crate) fn parse(raw: &[u8]) -> Message {
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
    pub(crate) fn status(&self) -> u16 {
        self.start
            .split(' ')
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("no status in {:?}", self.start))
    }

    /// The values of every field of that name, in order.
    pub(crate) fn values(&self, name: &str) -> Vec<&str> {
        self.fields
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    pub(crate) fn names(&self) -> Vec<&str> {
        self.fields.iter().map(|(n, _)| n.as_str()).collect()
    }
}

/// What a client got back: every byte until the proxy closed, and how long that took.
pub(crate) struct Reply {
    pub(crate) raw: Vec<u8>,
    pub(crate) took: Duration,
}

impl Reply {
    pub(crate) fn message(&self) -> Message {
        Message::parse(&self.raw)
    }

    pub(crate) fn status(&self) -> u16 {
        self.message().status()
    }

    pub(crate) fn text(&self) -> String {
        String::from_utf8_lossy(&self.raw).into_owned()
    }
}

/// An answer the proxy makes itself: the status, no body, `Content-Length: 0` and `Connection: close`.
pub(crate) fn assert_empty_answer(reply: &Reply, status: u16) {
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

pub(crate) fn get(path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: example.test\r\n\r\n").into_bytes()
}

/// A POST with a `Content-Length` and the `Content-Type` value exactly as given (it may be any spelling).
pub(crate) fn post_typed(path: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: example.test\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(body);
    request
}

pub(crate) fn post_form(path: &str, body: &[u8]) -> Vec<u8> {
    post_typed(path, URLENCODED, body)
}

/// A urlencoded body of exactly `total` bytes whose `probe` argument is `probe`.
pub(crate) fn padded_form(probe: &str, total: usize) -> Vec<u8> {
    let mut body = format!("probe={probe}&pad=").into_bytes();
    assert!(total >= body.len());
    body.resize(total, b'a');
    body
}

/// A chunked request with the `Content-Type` value as given, whose body is `body`, exactly as given (it is the
/// chunked coding, right or wrong).
pub(crate) fn chunked_typed(path: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: example.test\r\nContent-Type: {content_type}\r\nTransfer-Encoding: chunked\r\n\r\n"
    )
    .into_bytes();
    request.extend_from_slice(body);
    request
}

/// The same for the urlencoded type.
pub(crate) fn chunked_request(path: &str, body: &[u8]) -> Vec<u8> {
    chunked_typed(path, URLENCODED, body)
}

/// Chunks in the chunked coding, then the last chunk and `trailer` (raw field lines, each ending in CRLF).
pub(crate) fn chunked_body(chunks: &[&[u8]], trailer: &[u8]) -> Vec<u8> {
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

pub(crate) fn connect(port: u16) -> TcpStream {
    let sock = TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), 10 * SEC)
        .expect("connect to the proxy");
    sock.set_nodelay(true).expect("set TCP_NODELAY");
    sock.set_write_timeout(Some(PATIENCE))
        .expect("set the write timeout");
    sock
}

/// Reads until the peer closes. A reset after some bytes ends the read as well: the proxy may close a socket
/// whose request it did not read to the end. No close within `PATIENCE` fails the test.
pub(crate) fn read_to_close(sock: &mut TcpStream) -> Vec<u8> {
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

/// Everything the proxy answers until it closes; `start` is when the exchange began.
pub(crate) fn collect(sock: &mut TcpStream, start: Instant) -> Reply {
    Reply {
        raw: read_to_close(sock),
        took: start.elapsed(),
    }
}

/// One request on a new connection, then everything the proxy answers.
pub(crate) fn exchange(port: u16, request: &[u8]) -> Reply {
    let start = Instant::now();
    let mut sock = connect(port);
    sock.write_all(request).expect("send the request");
    collect(&mut sock, start)
}

pub(crate) fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .expect("bind a free port")
        .local_addr()
        .expect("the local address")
        .port()
}

// ---------------------------------------------------------------------------------------------------------
// The upstream
// ---------------------------------------------------------------------------------------------------------

/// The answer of the upstream: it ends the connection, unless the upstream keeps connections.
fn upstream_reply(keeps: bool) -> Vec<u8> {
    if keeps {
        return format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nX-Up: visible\r\nX-Request-ID: from-the-upstream\r\n\r\n{UPSTREAM_BODY}",
            UPSTREAM_BODY.len()
        )
        .into_bytes();
    }
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close, X-Up-Hop\r\nKeep-Alive: timeout=9\r\nX-Up-Hop: 1\r\nX-Up: visible\r\nX-Request-ID: from-the-upstream\r\n\r\n{UPSTREAM_BODY}",
        UPSTREAM_BODY.len()
    )
    .into_bytes()
}

#[derive(Default)]
pub(crate) struct Seen {
    /// Connections accepted.
    connections: AtomicUsize,
    /// The bytes of each request that was read to its end (head and body).
    requests: Mutex<Vec<Vec<u8>>>,
}

/// A loopback listener on a port of its own that answers every request with `upstream_reply`. It counts every
/// connection, also those that never send a byte. It answers once and closes the connection, or, when it keeps
/// connections, answers one request after another until the other side closes. The handshake of a WebSocket is
/// answered with 101, and then every byte it reads is sent back (`echo`).
pub(crate) struct Upstream {
    addr: SocketAddr,
    pub(crate) seen: Arc<Seen>,
    stopping: Arc<AtomicBool>,
    accepter: Option<JoinHandle<Vec<JoinHandle<()>>>>,
}

impl Upstream {
    fn start(keeps: bool) -> Upstream {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind the upstream");
        listener
            .set_nonblocking(true)
            .expect("make the upstream non-blocking");
        let addr = listener.local_addr().expect("the upstream address");
        let seen = Arc::new(Seen::default());
        let stopping = Arc::new(AtomicBool::new(false));
        let accepter = {
            let (seen, stopping) = (seen.clone(), stopping.clone());
            thread::spawn(move || accept_loop(&listener, &seen, &stopping, keeps))
        };
        Upstream {
            addr,
            seen,
            stopping,
            accepter: Some(accepter),
        }
    }

    pub(crate) fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub(crate) fn connections(&self) -> usize {
        self.seen.connections.load(Ordering::SeqCst)
    }

    pub(crate) fn requests(&self) -> Vec<Vec<u8>> {
        lock(&self.seen.requests).clone()
    }

    /// Closes the listener (the port then refuses connections) once every connection that was waiting to be
    /// accepted has been accepted and counted, and waits for the connection threads. Safe to call twice.
    pub(crate) fn stop(&mut self) {
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
    keeps: bool,
) -> Vec<JoinHandle<()>> {
    let mut handlers = Vec::new();
    loop {
        match listener.accept() {
            Ok((sock, _)) => {
                seen.connections.fetch_add(1, Ordering::SeqCst);
                let seen = seen.clone();
                handlers.push(thread::spawn(move || serve_upstream(sock, &seen, keeps)));
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

/// The answer to the handshake of a WebSocket.
const SWITCHING: &str = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";

/// Switches to the WebSocket protocol, as far as the tests need it: the upstream says 101 and then sends back every
/// byte it reads, those that came with the handshake first, until the other side ends the connection.
fn echo(sock: &mut TcpStream, request: &[u8]) {
    let mut behind = request[find(request, b"\r\n\r\n").map_or(0, |end| end + 4)..].to_vec();
    if sock.write_all(SWITCHING.as_bytes()).is_err() {
        return;
    }
    let mut chunk = [0u8; 4096];
    loop {
        if !behind.is_empty() && sock.write_all(&std::mem::take(&mut behind)).is_err() {
            return;
        }
        match sock.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => behind.extend_from_slice(&chunk[..n]),
        }
    }
}

fn serve_upstream(mut sock: TcpStream, seen: &Seen, keeps: bool) {
    sock.set_nonblocking(false)
        .expect("make the upstream connection blocking");
    sock.set_read_timeout(Some(PATIENCE))
        .expect("set the upstream read timeout");
    sock.set_write_timeout(Some(PATIENCE))
        .expect("set the upstream write timeout");
    sock.set_nodelay(true).expect("set TCP_NODELAY");
    while let Some(request) = read_request(&mut sock) {
        lock(&seen.requests).push(request.clone());
        if Message::parse(&request).values("upgrade") == ["websocket"] {
            echo(&mut sock, &request);
            return;
        }
        if sock.write_all(&upstream_reply(keeps)).is_err() || !keeps {
            return;
        }
    }
}

/// A request read to its end: the head, and as many body bytes as its `Content-Length` says, or, for a chunked body,
/// up to its last chunk. `None` if the peer closes first.
fn read_request(sock: &mut TcpStream) -> Option<Vec<u8>> {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    let mut total = None;
    let mut chunked = false;
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
            chunked = head.values("transfer-encoding") == ["chunked"];
            total = Some(end + 4 + length);
        }
        if total.is_some_and(|n| raw.len() >= n) && (!chunked || raw.ends_with(b"\r\n0\r\n\r\n")) {
            return Some(raw);
        }
        match sock.read(&mut chunk) {
            Ok(0) | Err(_) => return None,
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
        }
    }
}

// ---------------------------------------------------------------------------------------------------------
// The proxy under test
// ---------------------------------------------------------------------------------------------------------

/// The choices a test makes. These are the test's own values for the scenes, not defaults or recommendations.
#[derive(Clone)]
pub(crate) struct Knobs {
    /// The driver's slice and the kernel's tick.
    pub(crate) slice_ms: u64,
    pub(crate) tick_ms: u64,
    pub(crate) max_conns: usize,
    pub(crate) head_read_ms: u64,
    /// How long a connection waits for its next request after a response; 0: it closes after every response.
    pub(crate) keepalive_timeout_ms: u64,
    /// The most connections to the upstream that wait to be used again; 0: every request has a connection of its own.
    pub(crate) upstream_keepalive: usize,
    /// The upstream keeps a connection and answers one request after another on it, instead of answering once.
    pub(crate) upstream_keeps: bool,
    /// The networks of `trusted_proxies`.
    pub(crate) trusted_proxies: Vec<String>,
    /// How many upstreams are started, each on a port of its own. The first is `Proxy::upstream`, the others are
    /// `Proxy::others`.
    pub(crate) upstreams: usize,
    /// The `forward` object, made from the addresses of the upstreams in the order they were started.
    pub(crate) forward: fn(&[SocketAddr]) -> Value,
    pub(crate) restarts: u32,
    pub(crate) stop_inspect_ms: u64,
    pub(crate) stop_wait_ms: u64,
    /// The most bytes a body may have, and how many of its first bytes are inspected.
    pub(crate) max_body: usize,
    pub(crate) inspect_body: usize,
    /// The value of `NOTIFY_SOCKET` of the proxy's environment; none: the variable is not set.
    pub(crate) notify_socket: Option<String>,
}

impl Knobs {
    /// Short steps: small requests are inspected in a few milliseconds.
    pub(crate) fn quick() -> Knobs {
        Knobs {
            slice_ms: 20,
            tick_ms: 20,
            max_conns: 64,
            head_read_ms: 10_000,
            // The tests that read until the proxy closes need a connection that closes after its response.
            keepalive_timeout_ms: 0,
            // Each request has a connection to the upstream of its own, and the upstream ends it.
            upstream_keepalive: 0,
            upstream_keeps: false,
            trusted_proxies: Vec::new(),
            upstreams: 1,
            forward: only_first,
            restarts: 0,
            stop_inspect_ms: 10_000,
            stop_wait_ms: 20_000,
            // A body is inspected whole, up to the most the kernel takes.
            max_body: MAX_BODY,
            inspect_body: MAX_BODY,
            notify_socket: None,
        }
    }

    /// Bodies of up to 32 MiB, of which the first 16 KiB are inspected.
    pub(crate) fn long_bodies() -> Knobs {
        Knobs {
            max_body: 32 << 20,
            inspect_body: 16 << 10,
            ..Knobs::quick()
        }
    }

    /// A slice of 400 ms: an inspection of a 1 MiB body takes about 17 slices. A stop leaves the inspection more
    /// time than a whole slow one needs.
    pub(crate) fn slow() -> Knobs {
        Knobs {
            slice_ms: 400,
            tick_ms: 500,
            stop_inspect_ms: 20_000,
            stop_wait_ms: 30_000,
            ..Knobs::quick()
        }
    }
}

/// A server of a group: weight 1, one failure leaves it out for 30 s, not a backup.
pub(crate) fn server(address: impl ToString) -> Value {
    json!({
        "address": address.to_string(),
        "weight": 1,
        "max_fails": 1,
        "fail_timeout_ms": 30_000,
        "backup": false,
    })
}

/// The `forward` object of a proxy with the first upstream only: one group, every request goes to it.
fn only_first(addresses: &[SocketAddr]) -> Value {
    json!({
        "resolve_timeout_ms": RESOLVE_TIMEOUT_MS,
        "upstreams": {"main": {"servers": [server(addresses[0])]}},
        "routes": [],
        "default_upstream": "main",
    })
}

fn config_json(k: &Knobs, listen: SocketAddr, upstreams: &[SocketAddr], root: &Path) -> String {
    json!({
        "proxy": {
            "listeners": [{"address": listen.to_string()}],
            "max_conns": k.max_conns,
            "max_head_bytes": 8192,
            "max_body": k.max_body,
            "inspect_body": k.inspect_body,
            "max_body_wire": 2 * k.max_body,
            "max_buffered_bytes": 8 << 20,
            "upstream_max_headers": 100,
            "upstream_max_head_bytes": 16384,
            "upstream_head_wire": UPSTREAM_HEAD_WIRE,
            "drive_slice_ms": k.slice_ms,
            "ready_wait_ms": 20_000,
            "head_read_ms": k.head_read_ms,
            "body_read_ms": 10_000,
            "inspect_wait_ms": 55_000,
            "upstream_connect_ms": 5_000,
            "upstream_header_ms": 10_000,
            "request_total_ms": 60_000,
            "response_idle_ms": 10_000,
            "conn_total_ms": 120_000,
            "stop_inspect_ms": k.stop_inspect_ms,
            "stop_wait_ms": k.stop_wait_ms,
            "keepalive_timeout_ms": k.keepalive_timeout_ms,
            "keepalive_requests": 1000,
            // A request that starts before this ends before conn_total_ms (this plus request_total_ms).
            "keepalive_time_ms": 60_000,
            "lingering_time_ms": 30_000,
            "lingering_timeout_ms": 5_000,
            "lingering_bytes": 262_144,
            "trusted_proxies": k.trusted_proxies,
            "upstream_keepalive": k.upstream_keepalive,
            // Not above response_idle_ms.
            "upstream_keepalive_timeout_ms": 10_000,
            "upstream_keepalive_requests": 1000,
        },
        "forward": (k.forward)(upstreams),
        "kernel": {
            "inspector": var("TUKUYOMI_TEST_INSPECTOR"),
            "tmp_root": root.to_string_lossy(),
            "gomaxprocs": 2,
            "gomemlimit": 256 << 20,
            "slots": 2,
            // A connection holds at most one inspection, so the queue is never longer than the connections.
            "wait_queue": k.max_conns.min(4),
            "records": 16,
            "discard_limit": 8,
            "tick_ms": k.tick_ms,
            "hello_wait_ms": 10_000,
            "frame_io_ms": 1_000,
            "verdict_wait_ms": 3_000,
            "wait_deadline_ms": 5_000,
            "closed_wait_ms": 3_000,
            "stop_after_ms": 5_000,
            "drain_wait_ms": 3_000,
            "exit_wait_ms": 3_000,
            "kill_grace_ms": KILL_GRACE_MS,
            "restarts": k.restarts,
            "restart_window_ms": 60_000,
        },
        "rules": {
            "store": {
                "kind": "file",
                "dir": root.join(STORE).to_string_lossy(),
            },
        },
    })
    .to_string()
}

pub(crate) fn run_kill(signal: &str, pid: u32) {
    let status = Command::new("kill")
        .arg("-s")
        .arg(signal)
        .arg(pid.to_string())
        .status()
        .expect("run the kill command");
    assert!(status.success(), "kill -s {signal} {pid} failed: {status}");
}

/// The processes that are children of any thread of `pid`.
pub(crate) fn children_of(pid: u32) -> Vec<u32> {
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
pub(crate) fn is_inspector(pid: u32) -> bool {
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

pub(crate) fn assert_gone(pids: &[u32]) {
    for pid in pids {
        assert!(
            !Path::new(&format!("/proc/{pid}")).exists(),
            "inspector process {pid} is still there"
        );
    }
}

/// The kernel's numbers in the record line that the driver writes when it is told to stop: the records, the
/// requests held and the requests waiting.
fn stop_counts(lines: &[String]) -> [u64; 3] {
    let line = lines
        .iter()
        .find(|l| l.starts_with("driver: stop, records "))
        .unwrap_or_else(|| panic!("no stop line in {lines:#?}"));
    let numbers: Vec<u64> = line
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .map(|s| s.parse().expect("a number"))
        .collect();
    numbers[..]
        .try_into()
        .unwrap_or_else(|_| panic!("cannot read the stop line {line:?}"))
}

/// The root of a test that runs a command on the configuration of a proxy that is not started: the configuration and
/// the rules store as `Proxy::spawn_with` makes them. The upstream is at a port where nothing listens, and `port` is
/// the one that the configuration listens on; no process holds either.
pub(crate) struct Idle {
    pub(crate) port: u16,
    root: TestDir,
}

impl Idle {
    /// Writes the configuration and the store, then lets `edit` change the root, as `Proxy::spawn_with` does.
    pub(crate) fn new(test: &str, knobs: &Knobs, edit: impl FnOnce(&Path)) -> Idle {
        let root = make_root(test);
        let port = free_port();
        let listen = SocketAddr::from(([127, 0, 0, 1], port));
        let upstream = SocketAddr::from(([127, 0, 0, 1], free_port()));
        fs::write(
            root.path().join("config.json"),
            config_json(knobs, listen, &[upstream], root.path()),
        )
        .expect("write the configuration");
        make_store(root.path());
        edit(root.path());
        Idle { port, root }
    }

    /// The root of the test: the configuration, the store, and what the test adds.
    pub(crate) fn root(&self) -> &Path {
        self.root.path()
    }
}

pub(crate) struct Proxy {
    pub(crate) port: u16,
    pub(crate) pid: u32,
    pub(crate) exit: Receiver<io::Result<ExitStatus>>,
    reader: Option<JoinHandle<()>>,
    pub(crate) records: Arc<Records>,
    pub(crate) upstream: Upstream,
    /// The upstreams after the first, if the test started more.
    pub(crate) others: Vec<Upstream>,
    /// Every inspector process that was seen, to check at the end that none is left.
    pub(crate) inspectors: Vec<u32>,
    knobs: Knobs,
    /// When the process was started.
    pub(crate) started: Instant,
    done: bool,
    /// The last field: the fields are dropped in order, after `Proxy::drop` has stopped the processes, so the
    /// root is removed after everything else of the proxy is gone.
    root: TestDir,
}

impl Proxy {
    /// Starts the proxy and waits until it listens and its inspector is there.
    pub(crate) fn start(test: &str, knobs: Knobs) -> Proxy {
        Proxy::start_with(test, knobs, |_| {})
    }

    /// The same, with a change to the test root as `spawn_with` makes it.
    pub(crate) fn start_with(test: &str, knobs: Knobs, edit: impl FnOnce(&Path)) -> Proxy {
        let mut proxy = Proxy::spawn_with(test, knobs, edit);
        proxy
            .records
            .wait_lines("the proxy to listen", 1, |l| l == "start: listening");
        proxy.wait_inspector(None);
        proxy
    }

    /// Starts the proxy and returns at once, for a test that does not wait for it to listen.
    pub(crate) fn spawn(test: &str, knobs: Knobs) -> Proxy {
        Proxy::spawn_with(test, knobs, |_| {})
    }

    /// The same, with a change to the test root (the store above all) that `edit` makes after the configuration,
    /// the store and the stand-in are written and before the process starts.
    pub(crate) fn spawn_with(test: &str, knobs: Knobs, edit: impl FnOnce(&Path)) -> Proxy {
        let root = make_root(test);
        let upstream = Upstream::start(knobs.upstream_keeps);
        let others: Vec<Upstream> = (1..knobs.upstreams)
            .map(|_| Upstream::start(knobs.upstream_keeps))
            .collect();
        let addresses: Vec<SocketAddr> = std::iter::once(&upstream)
            .chain(&others)
            .map(|up| up.addr)
            .collect();
        let port = free_port();
        let listen = SocketAddr::from(([127, 0, 0, 1], port));
        let config = root.path().join("config.json");
        fs::write(
            &config,
            config_json(&knobs, listen, &addresses, root.path()),
        )
        .expect("write the configuration");
        make_store(root.path());
        edit(root.path());
        let started = Instant::now();
        let mut command = Command::new(env!("CARGO_BIN_EXE_tukuyomi-proxy"));
        command
            .arg(&config)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        // The environment of the test run does not leak into the proxy: the variable is what the test says.
        match &knobs.notify_socket {
            Some(socket) => command.env("NOTIFY_SOCKET", socket),
            None => command.env_remove("NOTIFY_SOCKET"),
        };
        let mut child = command.spawn().expect("start the proxy");
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
                        Ok(_) => {
                            let text = String::from_utf8_lossy(&buf).trim_end().to_string();
                            let item = serde_json::from_str(&text).unwrap_or(Value::String(text));
                            lock(&records.items).push(item);
                        }
                    }
                }
                records.ended.store(true, Ordering::SeqCst);
            })
        };
        let (tx, exit) = mpsc::channel();
        thread::spawn(move || {
            let _ = tx.send(child.wait());
        });
        Proxy {
            port,
            pid,
            exit,
            reader: Some(reader),
            records,
            upstream,
            others,
            inspectors: Vec::new(),
            knobs,
            started,
            done: false,
            root,
        }
    }

    /// Waits for a live inspector process other than `old`, and remembers it.
    pub(crate) fn wait_inspector(&mut self, old: Option<u32>) -> u32 {
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

    /// The root of the test: the configuration, the store, and what the test adds.
    pub(crate) fn root(&self) -> &Path {
        self.root.path()
    }

    /// The inspector the test is talking to.
    pub(crate) fn inspector(&self) -> u32 {
        *self.inspectors.last().expect("an inspector was seen")
    }

    /// Sends `request` on a new connection and returns once the inspector has read the first body frame, so the
    /// request is being inspected. The slice makes the rest of the inspection last for seconds.
    pub(crate) fn start_slow(&self, request: &[u8]) -> TcpStream {
        let pid = self.inspector();
        let base = read_chars(pid).expect("read the inspector's counter");
        let mut sock = connect(self.port);
        sock.write_all(request).expect("send the request");
        wait_until("the inspector to read the body", || {
            read_chars(pid).is_some_and(|now| now >= base + FRAME)
        });
        sock
    }

    /// Sends the signal (`TERM`, `INT` or `HUP`) and returns the time just before it was sent. The proxy takes
    /// its own time for the stop after that, so a time counted from here is never shorter than the proxy's.
    pub(crate) fn signal(&self, signal: &str) -> Instant {
        let at = Instant::now();
        run_kill(signal, self.pid);
        at
    }

    pub(crate) fn term(&self) -> Instant {
        self.signal("TERM")
    }

    /// Waits for the exit of the proxy and for the end of its records, for at most `limit`. Returns the exit
    /// status and the time since `since`.
    pub(crate) fn wait_exit(&mut self, since: Instant, limit: Duration) -> (ExitStatus, Duration) {
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
        (status, took)
    }

    /// Checks that the root holds the files the test put there and nothing else (the kernel removed its own
    /// directory), and removes them and the root. A name that is a directory (the store) goes with all it holds.
    pub(crate) fn clear_root(&self, files: &[&str]) {
        let mut left: Vec<String> = fs::read_dir(self.root.path())
            .expect("the test root is readable")
            .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect::<Result<_, _>>()
            .expect("list the test root");
        left.sort();
        let mut want = files.to_vec();
        want.sort_unstable();
        assert_eq!(left, want, "the test root holds other files");
        for file in files {
            let path = self.root.path().join(file);
            let meta = fs::symlink_metadata(&path).expect("look at a file of the test root");
            if meta.is_dir() {
                fs::remove_dir_all(&path).expect("remove a directory of the test root");
            } else {
                fs::remove_file(&path).expect("remove a file of the test root");
            }
        }
        fs::remove_dir(self.root.path()).expect("the empty test root is removed");
    }

    /// Ends the test: SIGTERM, a clean exit within `stop_wait`, and then every check of what must be left (or
    /// not left): the records, the processes, the root, the upstream's connection count. The kernel holds nothing.
    pub(crate) fn finish(self, upstream_connections: usize) {
        let since = self.term();
        let counts = self.finish_after_term(since, upstream_connections);
        assert_eq!(counts, [0, 0, 0], "the kernel held something at the stop");
    }

    /// The same, for a test that has sent SIGTERM at `since` itself. Returns the kernel's numbers (records, held,
    /// waiting) at the start of the stop.
    pub(crate) fn finish_after_term(
        mut self,
        since: Instant,
        upstream_connections: usize,
    ) -> [u64; 3] {
        let within = Duration::from_millis(self.knobs.stop_wait_ms);
        let (status, took) = self.wait_exit(since, within + 30 * SEC);
        let lines = self.records.lines();
        assert_eq!(
            status.code(),
            Some(0),
            "exit status {status}; records: {lines:#?}"
        );
        assert!(
            took < within,
            "the proxy needed {took:?} to stop; the limit is {within:?}"
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
            !lines
                .iter()
                .any(|l| l.contains("panic") || l.contains("internal fault")),
            "the records show a fault: {lines:#?}"
        );
        assert!(
            !self.records.all().iter().any(|r| r["type"] == "dropped"),
            "records were dropped: {lines:#?}"
        );
        let counts = stop_counts(&lines);
        assert_gone(&self.inspectors);

        // Only the configuration and the store are left in the root: the kernel removed its own directory.
        self.clear_root(&["config.json", STORE]);

        // The proxy is gone, so every connection it made to the upstream has been accepted by now.
        self.upstream.stop();
        for other in &mut self.others {
            other.stop();
        }
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
        // The guard removes the root after this, so the proxy must be gone first: a killed process may need a
        // moment to exit, and must not make anything in the root while it is removed. The wait ends at the exit.
        let _ = self.exit.recv_timeout(MARGIN);
    }
}

/// A new connection to the port is turned away: refused, or closed or reset before any byte of an answer (a
/// connection that was in the queue of the listener when it was closed is reset). Any byte of an answer, and a
/// connection that stays open, fail the test.
pub(crate) fn assert_turned_away(port: u16) {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let mut sock = match TcpStream::connect_timeout(&addr, 10 * SEC) {
        Ok(sock) => sock,
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => return,
        Err(e) => panic!("connecting to the proxy failed in another way: {e}"),
    };
    // The write may fail with the reset as well; that is no answer either.
    let _ = sock.write_all(&get("/late"));
    sock.set_read_timeout(Some(PATIENCE))
        .expect("set the read timeout");
    let mut chunk = [0u8; 4096];
    match sock.read(&mut chunk) {
        Ok(0) => {}
        Ok(n) => panic!(
            "a new connection got an answer: {:?}",
            String::from_utf8_lossy(&chunk[..n])
        ),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
            ) => {}
        Err(e) => panic!("the new connection neither closed nor reset: {e}"),
    }
}

// ---------------------------------------------------------------------------------------------------------
// Bodies of the JSON type
// ---------------------------------------------------------------------------------------------------------

/// A JSON body that rule 9203 blocks: its top-level member `probe` is `block`, the second of two members.
pub(crate) const BLOCKED_JSON: &str = "{\"note\": \"hello\", \"probe\": \"block\"}";

/// A JSON body that a proxy which parsed and wrote it again would change: blanks and line breaks, an escape
/// (`é`) next to the same letter as UTF-8, a three-byte character, numbers with a fraction and with an
/// exponent, `null`, nesting, an empty string and a final line feed. Its member `probe` is `ok`.
pub(crate) const CLEAN_JSON: &str = concat!(
    "{\n",
    "  \"probe\": \"ok\",\n",
    "  \"note\": \"caf\\u00e9 caf\u{e9} \u{4e2d}\",\n",
    "  \"n\": [1, 2.50, 2.5e3, true, null, {\"a\": {\"b\": []}}],\n",
    "  \"empty\": \"\"\n",
    "}\n"
);

/// Whether `record` is the record of a request that rule `id` blocked with 403.
pub(crate) fn blocked_by(record: &Value, id: i64) -> bool {
    is_answer(record, "blocked", 403, "blocked by a rule") && record["rule"] == id
}

/// Checks what the upstream got as its request number `index` (from 0): the start line, the `Content-Type` value
/// as it was sent, the length of the body and no chunked coding, and the body byte for byte.
pub(crate) fn assert_forwarded_json(
    proxy: &Proxy,
    index: usize,
    start: &str,
    content_type: &str,
    body: &[u8],
) {
    let requests = proxy.upstream.requests();
    let seen = Message::parse(
        requests
            .get(index)
            .unwrap_or_else(|| panic!("the upstream got {} requests", requests.len())),
    );
    assert_eq!(seen.start, start);
    assert_eq!(seen.values("content-type"), [content_type]);
    assert_eq!(seen.values("content-length"), [body.len().to_string()]);
    assert!(
        !seen.names().contains(&"transfer-encoding"),
        "fields: {:?}",
        seen.fields
    );
    assert_eq!(
        seen.body,
        body,
        "the upstream got another body: {:?}",
        String::from_utf8_lossy(&seen.body)
    );
}

// ---------------------------------------------------------------------------------------------------------
// Bodies with the gzip coding
// ---------------------------------------------------------------------------------------------------------

/// One gzip member of `data`.
pub(crate) fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).expect("compress the body");
    encoder.finish().expect("finish the gzip stream")
}

/// A POST with a `Content-Length` whose body is `coded` and whose `Content-Encoding` line has the value `coding`
/// exactly as given (it may be any spelling, or hold a second line).
pub(crate) fn post_coded(path: &str, content_type: &str, coding: &str, coded: &[u8]) -> Vec<u8> {
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: example.test\r\nContent-Type: {content_type}\r\nContent-Encoding: {coding}\r\nContent-Length: {}\r\n\r\n",
        coded.len()
    )
    .into_bytes();
    request.extend_from_slice(coded);
    request
}

/// The same request chunked, with `coded` cut into pieces of 7 bytes: the cuts fall inside the gzip header, inside
/// the compressed data and inside the trailer.
pub(crate) fn chunked_coded(path: &str, content_type: &str, coding: &str, coded: &[u8]) -> Vec<u8> {
    let chunks: Vec<&[u8]> = coded.chunks(7).collect();
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: example.test\r\nContent-Type: {content_type}\r\nContent-Encoding: {coding}\r\nTransfer-Encoding: chunked\r\n\r\n"
    )
    .into_bytes();
    request.extend_from_slice(&chunked_body(&chunks, b""));
    request
}

/// Checks what the upstream got as its request number `index` after a gzip request: the decoded body byte for
/// byte, with the length of the decoded body and without the coding or the chunked framing, and no byte of the
/// coded stream anywhere (its first two bytes, the gzip magic, are not in the bytes the upstream read).
pub(crate) fn assert_forwarded_decoded(
    proxy: &Proxy,
    index: usize,
    start: &str,
    content_type: &str,
    plain: &[u8],
) {
    assert_forwarded_json(proxy, index, start, content_type, plain);
    let requests = proxy.upstream.requests();
    let seen = Message::parse(&requests[index]);
    assert!(
        !seen.names().contains(&"content-encoding"),
        "fields: {:?}",
        seen.fields
    );
    assert!(
        find(&requests[index], &[0x1f, 0x8b]).is_none(),
        "the upstream got coded bytes"
    );
}
