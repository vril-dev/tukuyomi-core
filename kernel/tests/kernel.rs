//! Public-API tests of the kernel.
//!
//! Without `#[ignore]`: no process and no file system (the paths of the fake configuration are never touched).
//! With `#[ignore = "needs a built inspector"]`: a real inspector. They read `TUKUYOMI_TEST_INSPECTOR`,
//! `TUKUYOMI_TEST_RULES` (the rule bundle directory), `TUKUYOMI_TEST_RULES_SHA256` (the SHA-256 of its
//! `manifest.json`, 64 hex digits) and `TUKUYOMI_TEST_TMP` (the parent of the per-test 0700 roots) and FAIL when
//! one is missing: a skipped real-process test must never look like a pass. Run them with `-- --include-ignored`.
//!
//! The values below are the test's own choices for this check, not defaults or recommendations. The limits of
//! `Config::check` are written out as numbers on purpose: the constants are not public.

use std::ffi::OsStr;
use std::fs::{self, DirBuilder};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tukuyomi_kernel::{
    Config, Failure, Phase, Reason, Refused, ReqId, Request, Status, Supervisor, Verdict,
};

const MS: Duration = Duration::from_millis(1);
const SEC: Duration = Duration::from_secs(1);
/// `MAX_WAIT`, `MAX_TICK`, `MAX_TMP_ROOT` and `codec::MAX_CONCUR_TX` as `Config::check` states them.
const MAX_WAIT: Duration = Duration::from_secs(3600);
const MAX_TICK: Duration = Duration::from_secs(1);
const MAX_TMP_ROOT: usize = 3840;
const MAX_CONCUR_TX: usize = 4;
/// `MAX_RESTARTS` (the most `restarts` that `Config::check` accepts).
const MAX_RESTARTS: u32 = 1000;
/// `codec::MAX_DECLARED` (the largest body the protocol declares).
const MAX_BODY: usize = 1 << 20;
/// `codec::MAX_HEADERS`, `MAX_HDR_VALUE` and `MAX_HDR_TOTAL` (the limits of the headers of one request).
const MAX_HEADERS: usize = 64;
const MAX_HDR_VALUE: usize = 4096;
const MAX_HDR_TOTAL: usize = 24 * 1024;

const URLENCODED: &[u8] = b"application/x-www-form-urlencoded";
const UNAVAILABLE: Verdict = Verdict::Uninspectable(Reason::Unavailable);

/// A configuration that passes `check` and names nothing that exists.
fn fake_config() -> Config {
    Config {
        inspector: PathBuf::from("/kernel-test/inspector"),
        rules: PathBuf::from("/kernel-test/rules.conf"),
        rules_sha256: [0; 32],
        tmp_root: PathBuf::from("/kernel-test/tmp"),
        gomaxprocs: 2,
        gomemlimit: 256 << 20,
        slots: 2,
        wait_queue: 4,
        records: 8,
        discard_limit: 8,
        tick: 20 * MS,
        hello_wait: 10 * SEC,
        frame_io: 2900 * MS,
        verdict_wait: 10 * SEC,
        wait_deadline: 20 * SEC,
        closed_wait: 10 * SEC,
        stop_after: 30 * SEC,
        drain_wait: 10 * SEC,
        exit_wait: 10 * SEC,
        kill_grace: 5 * SEC,
        restarts: 0,
        restart_window: 60 * SEC,
    }
}

fn header<'a>(name: &'a [u8], value: &'a [u8]) -> (&'a [u8], &'a [u8]) {
    (name, value)
}

fn request<'a>(
    method: &'a [u8],
    uri: &'a [u8],
    headers: &'a [(&'a [u8], &'a [u8])],
    body: &'a [u8],
) -> Request<'a> {
    Request {
        client_addr: b"192.0.2.1",
        client_port: 40000,
        server_addr: b"192.0.2.2",
        server_port: 80,
        method,
        uri,
        proto: b"HTTP/1.1",
        headers,
        body,
    }
}

/// The ledger of one Supervisor: what was submitted and every result received, so that the end of a test can
/// check that each submitted request was answered exactly once.
struct Run {
    sup: Supervisor,
    /// Declared after `sup` on purpose: the fields are dropped in declaration order, so the root is removed only
    /// after the Supervisor has stopped its inspector and removed its per-start directory.
    root: Option<TestDir>,
    submitted: Vec<ReqId>,
    got: Vec<(ReqId, Verdict)>,
}

impl Run {
    fn new(cfg: Config, root: Option<TestDir>) -> Run {
        Run {
            sup: Supervisor::new(cfg)
                .unwrap_or_else(|e| panic!("the test configuration is refused: {e:?}")),
            root,
            submitted: Vec::new(),
            got: Vec::new(),
        }
    }

    fn submit(&mut self, req: &Request<'_>) -> ReqId {
        let id = self
            .sup
            .submit(req)
            .unwrap_or_else(|e| panic!("submit was refused: {e:?}"));
        self.submitted.push(id);
        id
    }

    /// `submit` must refuse, and a refusal makes no record.
    fn refused(&mut self, req: &Request<'_>) -> Refused {
        let before = self.sup.status();
        let e = self
            .sup
            .submit(req)
            .expect_err("submit must refuse this request");
        assert_eq!(self.sup.status(), before, "a refusal must change nothing");
        e
    }

    /// Polls until `done` holds; fails with the status after one minute.
    fn wait_for(&mut self, what: &str, done: impl Fn(&Run) -> bool) {
        let limit = Instant::now() + 60 * SEC;
        while !done(self) {
            assert!(
                Instant::now() < limit,
                "timed out waiting for {what}: {:?}, got {:?}",
                self.sup.status(),
                self.got
            );
            let got = self.sup.poll(Instant::now() + 50 * MS);
            self.got.extend(got);
        }
    }

    fn wait_results(&mut self, n: usize) {
        self.wait_for("results", |r| r.got.len() >= n);
    }

    fn verdict(&self, id: ReqId) -> Verdict {
        let mut found = self.got.iter().filter(|&&(i, _)| i == id);
        let v = found.next().expect("the request has a result").1;
        assert!(found.next().is_none(), "request {id} was answered twice");
        v
    }

    /// Ends the Supervisor and checks the state it must leave: nothing unreaped, no directory, no held slot or
    /// waiting request, an empty test root, and exactly one result for each submitted request. Returns the
    /// status after the shutdown and whether the BYE was received.
    fn finish(mut self) -> (Status, bool) {
        let sd = self.sup.shutdown(Instant::now() + 20 * SEC);
        assert!(sd.exit_confirmed, "an inspector process is left unreaped");
        assert!(sd.dir_removed, "a per-start directory is left");
        assert_eq!(sd.held_left, 0);
        assert_eq!(sd.waiting_left, 0);
        assert_eq!(sd.phase, self.sup.status().phase);
        self.got.extend(sd.results);
        let mut ids: Vec<ReqId> = self.got.iter().map(|&(i, _)| i).collect();
        ids.sort_unstable();
        let mut want = self.submitted.clone();
        want.sort_unstable();
        assert_eq!(ids, want, "results differ from what was submitted");
        ids.dedup();
        assert_eq!(ids.len(), want.len(), "a result was delivered twice");
        if let Some(root) = &self.root {
            let left: Vec<_> = fs::read_dir(root.path())
                .expect("the test root is readable")
                .map(|e| e.map(|e| e.file_name()))
                .collect();
            assert!(left.is_empty(), "the test root is not empty: {left:?}");
            fs::remove_dir(root.path()).expect("the empty test root is removed");
        }
        (self.sup.status(), sd.bye)
    }
}

// ---- Without a process ----

#[test]
fn shutdown_before_any_request_decides_the_waiting_request_once() {
    let hs = [header(b"Host", b"example.test")];
    let get = request(b"GET", b"/", &hs, b"");
    let mut sup = Supervisor::new(fake_config()).expect("valid");
    let a = sup.submit(&get).expect("accepted");
    let c = sup.submit(&get).expect("accepted");
    assert_eq!((a, c), (0, 1));
    // A cancel decides at once; an unknown id is ignored.
    sup.cancel(c);
    sup.cancel(99);

    let sd = sup.shutdown(Instant::now());
    let cancelled = Verdict::Uninspectable(Reason::Cancelled);
    assert_eq!(sd.results, vec![(c, cancelled), (a, UNAVAILABLE)]);
    assert_eq!(sd.phase, Phase::Stopped);
    assert!(!sd.bye && sd.exit_confirmed && sd.dir_removed);
    assert_eq!((sd.held_left, sd.waiting_left), (0, 0));
    let st = sup.status();
    assert_eq!((st.phase, st.inc, st.restarts), (Phase::Stopped, 1, 0));

    // A second call returns nothing new. After the shutdown a new request is answered at once, and nothing is
    // started.
    assert!(sup.shutdown(Instant::now()).results.is_empty());
    let b = sup.submit(&get).expect("accepted");
    assert_eq!(sup.poll(Instant::now()), vec![(b, UNAVAILABLE)]);
    assert_eq!(sup.status().inc, 1);
}

#[test]
fn refused_body_over_the_protocol_limit() {
    let mut run = Run::new(fake_config(), None);
    // The first rule wins: nothing else about this request is right either.
    let big = vec![b'a'; MAX_BODY + 1];
    let r = run.refused(&request(b"GET", b"/", &[], &big));
    assert_eq!(r, Refused::Unsupported("body over the protocol limit"));

    // The limit itself is accepted.
    let cl = MAX_BODY.to_string();
    let hs = [
        header(b"Content-Length", cl.as_bytes()),
        header(b"Content-Type", URLENCODED),
    ];
    let edge = vec![b'a'; MAX_BODY];
    run.submit(&request(b"POST", b"/", &hs, &edge));
    run.finish();
}

#[test]
fn refused_transfer_and_content_encoding() {
    let mut run = Run::new(fake_config(), None);
    let te = [header(b"transfer-ENCODING", b"chunked")];
    let r = run.refused(&request(b"POST", b"/", &te, b""));
    assert_eq!(r, Refused::Unsupported("transfer-encoding"));

    let ce = [header(b"Content-encoding", b"gzip")];
    let r = run.refused(&request(b"POST", b"/", &ce, b""));
    assert_eq!(r, Refused::Unsupported("content-encoding"));

    // Earlier rules win over later ones (the Content-Length is wrong as well).
    let both = [
        header(b"Content-Length", b"9"),
        header(b"Transfer-Encoding", b"chunked"),
    ];
    let r = run.refused(&request(b"POST", b"/", &both, b"a=b"));
    assert_eq!(r, Refused::Unsupported("transfer-encoding"));
    run.finish();
}

#[test]
fn refused_content_length() {
    let mut run = Run::new(fake_config(), None);
    let ct = header(b"Content-Type", URLENCODED);
    let why = Refused::Unsupported("content-length");
    // Not digits, empty, a sign, a number that is not the length of the body.
    let wrong: [&[u8]; 4] = [b"1x", b"", b"+3", b"4"];
    for cl in wrong {
        let hs = [header(b"content-LENGTH", cl), ct];
        assert_eq!(
            run.refused(&request(b"POST", b"/", &hs, b"a=b")),
            why,
            "{cl:?}"
        );
    }
    // Two of them are refused even when both are right, and one with no body to match.
    let two = [
        header(b"Content-Length", b"3"),
        header(b"Content-Length", b"3"),
        ct,
    ];
    assert_eq!(run.refused(&request(b"POST", b"/", &two, b"a=b")), why);
    let one = [header(b"Content-Length", b"1")];
    assert_eq!(run.refused(&request(b"GET", b"/", &one, b"")), why);

    // A right one passes, and so does "0" with no body.
    let zero = [header(b"Content-Length", b"0")];
    run.submit(&request(b"GET", b"/", &zero, b""));
    let hs = [header(b"Content-Length", b"3"), ct];
    run.submit(&request(b"POST", b"/", &hs, b"a=b"));
    run.finish();
}

#[test]
fn refused_content_type() {
    let mut run = Run::new(fake_config(), None);
    let cl = header(b"Content-Length", b"3");
    let refuse = |run: &mut Run, hs: &[(&[u8], &[u8])]| {
        let r = run.refused(&request(b"POST", b"/", hs, b"a=b"));
        assert_eq!(r, Refused::Unsupported("content-type"), "{hs:?}");
    };
    // None, or two of them, are refused.
    refuse(&mut run, &[cl]);
    let two = [
        cl,
        header(b"Content-Type", URLENCODED),
        header(b"content-type", URLENCODED),
    ];
    refuse(&mut run, &two);
    // A type that is not parsed, or that only starts or ends like one that is.
    let named = |n: usize| [&b"application/"[..], &vec![b'a'; n], b"+json"].concat();
    let too_long = named(123);
    let wrong: [&[u8]; 8] = [
        b"text/plain",
        b"",
        b"application/jsonp",
        b"x/application/json",
        b"application/x-www-form-urlencoded-x",
        b"application/+json",
        b"application/x-www-form-urlencoded+json",
        &too_long,
    ];
    for ct in wrong {
        refuse(&mut run, &[cl, header(b"Content-Type", ct)]);
    }

    // The types Coraza picks a body processor for pass, in any case, with parameters and blanks: the form types,
    // application/json and application/<name>+json with a name of 1 to 122 characters.
    let longest = named(122);
    let right: [&[u8]; 6] = [
        b" Application/X-WWW-Form-URLENCODED ; charset=UTF-8",
        b"multipart/form-data; boundary=x",
        b"\tapplication/json\t ; x=y",
        b"application/vnd.api+json",
        b"application/a+json",
        &longest,
    ];
    for ct in right {
        let hs = [cl, header(b"content-TYPE", ct)];
        run.submit(&request(b"POST", b"/", &hs, b"a=b"));
    }
    // The rule is about a body: a request with none passes whatever it says.
    let hs = [header(b"Content-Type", b"application/xml")];
    run.submit(&request(b"GET", b"/", &hs, b""));
    run.finish();
}

#[test]
fn refused_limits_of_the_headers_come_before_the_header_rules() {
    let mut run = Run::new(fake_config(), None);
    let te = header(b"Transfer-Encoding", b"chunked");
    let ce = header(b"Content-Encoding", b"gzip");
    let ct = header(b"Content-Type", URLENCODED);
    let transfer = Refused::Unsupported("transfer-encoding");

    // A field of TX_BEGIN that is not a header is refused first as well.
    let r = run.refused(&request(b"", b"/", &[te], b""));
    assert_eq!(r, Refused::Invalid("method length out of range"));
    // 65 headers with a Transfer-Encoding among them: the count is refused, not the Transfer-Encoding. 64 are not.
    let mut many = vec![te];
    many.resize(MAX_HEADERS + 1, header(b"X", b""));
    let r = run.refused(&request(b"POST", b"/", &many, b""));
    assert_eq!(r, Refused::Invalid("header count out of range"));
    many.pop();
    let r = run.refused(&request(b"POST", b"/", &many, b""));
    assert_eq!(r, transfer);

    // A Content-Length of 4097 bytes that is not a number: the length is refused, not the Content-Length. With 4096
    // bytes it is within the limit, so the Content-Length is refused as it was.
    let mut over = vec![b'0'; MAX_HDR_VALUE];
    over.push(b'x');
    let hs = [header(b"Content-Length", &over), ct];
    let r = run.refused(&request(b"POST", b"/", &hs, b"a=b"));
    assert_eq!(r, Refused::Invalid("header value length out of range"));
    let hs = [header(b"Content-Length", &over[1..]), ct];
    let r = run.refused(&request(b"POST", b"/", &hs, b"a=b"));
    assert_eq!(r, Refused::Unsupported("content-length"));

    // Every value is within its limit, but the total is over 24 KiB: the total is refused, not the Content-Encoding.
    let pad = vec![b'v'; MAX_HDR_VALUE];
    let mut crowded = vec![ce];
    crowded.resize(1 + MAX_HDR_TOTAL / MAX_HDR_VALUE, header(b"X-Pad", &pad));
    let r = run.refused(&request(b"POST", b"/", &crowded, b""));
    assert_eq!(r, Refused::Invalid("header total length out of range"));
    run.finish();
}

#[test]
fn refused_full_when_the_records_are_used() {
    let cfg = fake_config();
    let (records, wait_queue) = (cfg.records, cfg.wait_queue);
    let mut run = Run::new(cfg, None);
    let get = request(b"GET", b"/", &[], b"");
    for _ in 0..records {
        run.submit(&get);
    }
    assert_eq!(run.refused(&get), Refused::Full);
    assert_eq!(run.sup.status().records, records);
    // Nothing has started: the first wait_queue requests wait, the others were decided by QueueFull at once.
    let sd = run.sup.shutdown(Instant::now());
    let count = |v: Verdict| sd.results.iter().filter(|&&(_, w)| w == v).count();
    let unavailable = count(UNAVAILABLE);
    let queue_full = count(Verdict::Uninspectable(Reason::QueueFull));
    run.got.extend(sd.results);
    assert_eq!(unavailable, wait_queue);
    assert_eq!(queue_full, records - wait_queue);
    run.finish();
}

// ---- Config::check ----

/// `check` and `Supervisor::new` must both return this error.
fn rejected(change: impl FnOnce(&mut Config), msg: &str) {
    let mut c = fake_config();
    change(&mut c);
    let e = c.check().expect_err("check must refuse");
    assert_eq!(e.0, msg);
    assert_eq!(Supervisor::new(c).err(), Some(e));
}

fn accepted(change: impl FnOnce(&mut Config)) {
    let mut c = fake_config();
    change(&mut c);
    assert_eq!(c.check(), Ok(()));
    assert!(Supervisor::new(c).is_ok());
}

#[test]
fn check_discard_limit_below_u32_max() {
    rejected(
        |c| c.discard_limit = u32::MAX,
        "discard_limit must be below u32::MAX",
    );
    accepted(|c| c.discard_limit = u32::MAX - 1);
    accepted(|c| c.discard_limit = 0);
}

#[test]
fn check_paths() {
    let not_clean = ["", "/", "rel/x", "/a/", "/a//b", "/a/../b", "/a/b\0c"];
    for p in not_clean {
        rejected(
            |c| c.inspector = PathBuf::from(p),
            "inspector path is not an absolute clean path",
        );
        rejected(
            |c| c.rules = PathBuf::from(p),
            "rules path is not an absolute clean path",
        );
        rejected(
            |c| c.tmp_root = PathBuf::from(p),
            "tmp_root is not an absolute clean UTF-8 path",
        );
    }
    // Only tmp_root must be UTF-8, and it has at most MAX_TMP_ROOT bytes.
    let odd = PathBuf::from(OsStr::from_bytes(b"/kernel-test/\xff"));
    rejected(
        |c| c.tmp_root = odd.clone(),
        "tmp_root is not an absolute clean UTF-8 path",
    );
    accepted(|c| c.inspector = odd.clone());
    let tmp = |n: usize| PathBuf::from(format!("/{}", "a".repeat(n - 1)));
    accepted(|c| c.tmp_root = tmp(MAX_TMP_ROOT));
    rejected(
        |c| c.tmp_root = tmp(MAX_TMP_ROOT + 1),
        "tmp_root is too long",
    );
    // 4096 bytes is beyond what any path argument may be.
    accepted(|c| c.inspector = tmp(4095));
    rejected(
        |c| c.inspector = tmp(4096),
        "inspector path is not an absolute clean path",
    );
}

#[test]
fn check_go_limits() {
    rejected(|c| c.gomaxprocs = 0, "gomaxprocs is 0");
    accepted(|c| c.gomaxprocs = u16::MAX);
    rejected(|c| c.gomemlimit = 0, "gomemlimit is out of range");
    rejected(
        |c| c.gomemlimit = i64::MAX as u64 + 1,
        "gomemlimit is out of range",
    );
    rejected(|c| c.gomemlimit = u64::MAX, "gomemlimit is out of range");
    accepted(|c| c.gomemlimit = 1);
    accepted(|c| c.gomemlimit = i64::MAX as u64);
}

#[test]
fn check_counts() {
    rejected(|c| c.slots = 0, "slots is out of range");
    rejected(|c| c.slots = MAX_CONCUR_TX + 1, "slots is out of range");
    accepted(|c| {
        c.slots = MAX_CONCUR_TX;
        c.records = MAX_CONCUR_TX + c.wait_queue;
    });
    rejected(|c| c.wait_queue = 0, "wait_queue is 0");
    let why = "records is below slots plus wait_queue";
    rejected(|c| c.records = c.slots + c.wait_queue - 1, why);
    accepted(|c| c.records = c.slots + c.wait_queue);
    // The sum overflows: that is a refusal, not a wrap.
    rejected(|c| c.wait_queue = usize::MAX, why);
}

#[test]
fn check_restarts_are_at_most_1000_and_the_window_is_a_time() {
    accepted(|c| c.restarts = MAX_RESTARTS);
    rejected(|c| c.restarts = MAX_RESTARTS + 1, "restarts is above 1000");
    accepted(|c| c.restart_window = MAX_WAIT);
    let why = "restart_window is out of range";
    rejected(|c| c.restart_window = MAX_WAIT + MS, why);
    rejected(|c| c.restart_window = Duration::ZERO, why);
}

/// A time of `Config` by name, and the way to it.
type Time = (&'static str, fn(&mut Config) -> &mut Duration);

/// The times of `Config`.
const TIMES: [Time; 11] = [
    ("tick", |c| &mut c.tick),
    ("hello_wait", |c| &mut c.hello_wait),
    ("frame_io", |c| &mut c.frame_io),
    ("verdict_wait", |c| &mut c.verdict_wait),
    ("wait_deadline", |c| &mut c.wait_deadline),
    ("closed_wait", |c| &mut c.closed_wait),
    ("stop_after", |c| &mut c.stop_after),
    ("drain_wait", |c| &mut c.drain_wait),
    ("exit_wait", |c| &mut c.exit_wait),
    ("kill_grace", |c| &mut c.kill_grace),
    ("restart_window", |c| &mut c.restart_window),
];

#[test]
fn check_times_are_above_zero_and_at_most_the_maximum() {
    for (name, time) in TIMES {
        let msg = format!("{name} is out of range");
        rejected(|c| *time(c) = Duration::ZERO, &msg);
        rejected(|c| *time(c) = MAX_WAIT + Duration::from_nanos(1), &msg);
        if name != "tick" {
            accepted(|c| *time(c) = MAX_WAIT);
        }
    }
}

#[test]
fn check_tick_is_short_and_not_above_any_other_time() {
    let long = |c: &mut Config| TIMES.iter().for_each(|(_, time)| *time(c) = MAX_WAIT);
    accepted(|c| {
        long(c);
        c.tick = MAX_TICK;
    });
    rejected(
        |c| {
            long(c);
            c.tick = MAX_TICK + Duration::from_nanos(1);
        },
        "tick is above the longest tick",
    );
    for (_, time) in &TIMES[1..] {
        let tick = fake_config().tick;
        rejected(
            |c| *time(c) = tick - Duration::from_nanos(1),
            "tick is above another time",
        );
        accepted(|c| *time(c) = tick);
    }
}

// ---- With a real inspector (ignored by default; run with `-- --include-ignored`) ----

fn var(name: &str) -> String {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => v,
        _ => panic!("{name} is not set: this real-process test needs it and is never skipped"),
    }
}

fn parse_sha256(s: &str) -> [u8; 32] {
    assert!(
        s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()),
        "TUKUYOMI_TEST_RULES_SHA256 must be 64 hex digits"
    );
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex digits");
    }
    out
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

fn make_root(test: &str) -> TestDir {
    let root =
        PathBuf::from(var("TUKUYOMI_TEST_TMP")).join(format!("{test}-{}", std::process::id()));
    DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .unwrap_or_else(|e| panic!("cannot create the test root {root:?}: {e}"));
    TestDir(root)
}

/// The configuration of a real run: the environment's inspector, rules and hash, and the test's own root.
fn real_config(root: &Path, sha256: [u8; 32]) -> Config {
    let mut c = fake_config();
    c.inspector = PathBuf::from(var("TUKUYOMI_TEST_INSPECTOR"));
    c.rules = PathBuf::from(var("TUKUYOMI_TEST_RULES"));
    c.rules_sha256 = sha256;
    c.tmp_root = root.to_path_buf();
    c
}

/// A run whose inspector does not exist: every start fails at spawn, before any process exists.
fn absent_inspector_run(test: &str, edit: impl FnOnce(&mut Config)) -> Run {
    let root = make_root(test);
    let mut cfg = fake_config();
    cfg.tmp_root = root.path().to_path_buf();
    cfg.inspector = root.path().join("absent-inspector");
    cfg.rules = root.path().join("absent-rules.conf");
    edit(&mut cfg);
    Run::new(cfg, Some(root))
}

fn real_run(test: &str) -> Run {
    let sha = parse_sha256(&var("TUKUYOMI_TEST_RULES_SHA256"));
    let root = make_root(test);
    Run::new(real_config(root.path(), sha), Some(root))
}

/// The end of a test that ran a live inspector: a BYE answered the DRAIN and the exit was a normal one.
fn finish_stopped(run: Run) {
    let (st, bye) = run.finish();
    assert_eq!(st.phase, Phase::Stopped);
    assert!(bye, "the inspector did not answer DRAIN with BYE");
}

#[test]
#[ignore = "needs a built inspector"]
fn normal_get_is_allowed() {
    let mut run = real_run("normal_get");
    let hs = [header(b"Host", b"example.test")];
    let id = run.submit(&request(b"GET", b"/", &hs, b""));
    run.wait_results(1);
    assert_eq!(run.verdict(id), Verdict::Allow);
    finish_stopped(run);
}

#[test]
#[ignore = "needs a built inspector"]
fn uri_rule_blocks_in_phase_1() {
    let mut run = real_run("uri_block");
    let hs = [header(b"Host", b"example.test")];
    let blocked = run.submit(&request(b"GET", b"/block-probe/x", &hs, b""));
    let passed = run.submit(&request(b"GET", b"/other", &hs, b""));
    run.wait_results(2);
    assert_eq!(
        run.verdict(blocked),
        Verdict::Block {
            phase: 1,
            rule_id: 9201,
            status: 403
        }
    );
    assert_eq!(run.verdict(passed), Verdict::Allow);
    finish_stopped(run);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_different_rules_hash_fails_at_hello_without_restart() {
    let mut sha = parse_sha256(&var("TUKUYOMI_TEST_RULES_SHA256"));
    sha[31] ^= 1;
    let root = make_root("wrong_sha");
    let mut run = Run::new(real_config(root.path(), sha), Some(root));
    let hs = [header(b"Host", b"example.test")];
    let id = run.submit(&request(b"GET", b"/", &hs, b""));
    run.wait_for("the failure at HELLO", |r| {
        r.got.len() == 1 && matches!(r.sup.status().phase, Phase::Failed(_))
    });
    let want = Phase::Failed(Failure::Hello("hello rules sha256 differs"));
    let st = run.sup.status();
    assert_eq!((st.phase, st.restarts), (want, 0));
    assert_eq!(run.verdict(id), UNAVAILABLE);
    // The reason stays after the shutdown, and nothing is left behind.
    let (st, bye) = run.finish();
    assert_eq!((st.phase, st.restarts, bye), (want, 0, false));
}

#[test]
#[ignore = "needs a built inspector"]
fn the_body_rules_block_in_phase_2_for_the_types_submit_accepts() {
    // The types and forms `submit` accepts must reach the inspector's body processor: a body that matches a rule
    // is blocked, one that does not is allowed.
    // The six requests all wait for HELLO, so the queue is larger than the fake configuration's.
    let sha = parse_sha256(&var("TUKUYOMI_TEST_RULES_SHA256"));
    let root = make_root("body_block");
    let mut cfg = real_config(root.path(), sha);
    (cfg.wait_queue, cfg.records) = (8, 16);
    let mut run = Run::new(cfg, Some(root));
    type Case = (&'static [u8], &'static [u8], &'static [u8], i64);
    let cases: [Case; 3] = [
        (
            b" application/x-www-form-urlencoded; charset=UTF-8",
            b"probe=block",
            b"probe=pass",
            9202,
        ),
        (
            b"Application/JSON; charset=UTF-8",
            br#"{"probe":"block"}"#,
            br#"{"probe":"pass"}"#,
            9203,
        ),
        (
            b"application/vnd.api+json",
            br#"{"probe":"block"}"#,
            br#"{"probe":"pass"}"#,
            9203,
        ),
    ];
    let mut post = |content_type: &[u8], body: &[u8]| {
        let cl = body.len().to_string();
        let hs = [
            header(b"Host", b"example.test"),
            header(b"Content-Type", content_type),
            header(b"Content-Length", cl.as_bytes()),
        ];
        run.submit(&request(b"POST", b"/submit", &hs, body))
    };
    let ids: Vec<_> = cases
        .iter()
        .map(|&(ct, block, pass, _)| (post(ct, block), post(ct, pass)))
        .collect();
    run.wait_results(2 * cases.len());
    for ((blocked, passed), (_, _, _, rule_id)) in ids.into_iter().zip(cases) {
        let want = Verdict::Block {
            phase: 2,
            rule_id,
            status: 403,
        };
        assert_eq!(run.verdict(blocked), want);
        assert_eq!(run.verdict(passed), Verdict::Allow);
    }
    finish_stopped(run);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_failed_start_ends_the_supervisor_when_no_restart_is_allowed() {
    let mut run = absent_inspector_run("no_restart", |c| c.restarts = 0);
    let hs = [header(b"Host", b"example.test")];
    let id = run.submit(&request(b"GET", b"/", &hs, b""));
    run.wait_for("the failure of the start", |r| {
        r.got.len() == 1 && matches!(r.sup.status().phase, Phase::Failed(_))
    });
    let st = run.sup.status();
    assert_eq!(st.phase, Phase::Failed(Failure::BudgetExhausted));
    assert_eq!((st.restarts, st.inc), (0, 2));
    assert_eq!((st.waiting, st.held), (0, 0));
    assert_eq!(run.verdict(id), UNAVAILABLE);
    let (st, bye) = run.finish();
    assert_eq!(st.phase, Phase::Failed(Failure::BudgetExhausted));
    assert_eq!((st.restarts, st.inc, bye), (0, 2, false));
}

#[test]
#[ignore = "needs a built inspector"]
fn a_full_restart_window_waits_and_the_supervisor_does_not_fail() {
    // One restart is allowed in a window of 300 ms.
    let window = 300 * MS;
    let mut run = absent_inspector_run("window", |c| {
        (c.restarts, c.restart_window, c.wait_deadline) = (1, window, 400 * MS)
    });
    let hs = [header(b"Host", b"example.test")];
    let started = Instant::now();
    let waiting = run.submit(&request(b"GET", b"/", &hs, b""));
    // Two whole windows pass. The supervisor never fails, it restarts no faster than once a window (at most one
    // more than the windows that have passed), and its incarnations follow the restarts.
    run.wait_for("two more restarts", |r| {
        let st = r.sup.status();
        assert_eq!(st.phase, Phase::Starting, "{st:?}");
        assert!(
            u128::from(st.restarts) <= 1 + started.elapsed().as_nanos() / window.as_nanos(),
            "{st:?}"
        );
        assert!(
            (st.restarts + 1..=st.restarts + 2).contains(&st.inc),
            "{st:?}"
        );
        st.restarts >= 3
    });
    assert!(started.elapsed() >= 2 * window);
    // The request that waited ended at its own deadline, not at the window or by a failure.
    assert_eq!(
        run.verdict(waiting),
        Verdict::Uninspectable(Reason::WaitDeadline)
    );
    // A request that comes now waits, and the shutdown ends the wait.
    let late = run.submit(&request(b"GET", b"/", &hs, b""));
    let sd = run.sup.shutdown(Instant::now() + 20 * SEC);
    assert_eq!(sd.results, vec![(late, UNAVAILABLE)]);
    assert_eq!(sd.phase, Phase::Stopped);
    run.got.extend(sd.results);
    let (st, bye) = run.finish();
    assert_eq!((st.phase, bye), (Phase::Stopped, false));
}
