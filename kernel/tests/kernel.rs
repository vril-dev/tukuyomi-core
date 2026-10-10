//! Public-API tests of the kernel.
//!
//! Without `#[ignore]`: no process and no file system (the paths of the fake configuration are never touched).
//! With `#[ignore = "needs a built inspector"]`: a real inspector. They read `TUKUYOMI_TEST_INSPECTOR`,
//! `TUKUYOMI_TEST_RULES`, `TUKUYOMI_TEST_RULES_SHA256` (64 hex digits) and `TUKUYOMI_TEST_TMP` (the parent of
//! the per-test 0700 roots) and FAIL when one is missing: a skipped real-process test must never look like a
//! pass. Run them with `-- --include-ignored`.
//!
//! The values below are the test's own choices for this check, not defaults or recommendations. The limits of
//! `Config::check` are written out as numbers on purpose: the constants are not public.

use std::ffi::OsStr;
use std::fs::{self, DirBuilder};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tukuyomi_kernel::{
    Config, ConfigError, Failure, Phase, Reason, Refused, ReqId, Request, Status, Supervisor,
    Verdict,
};

const MS: Duration = Duration::from_millis(1);
const SEC: Duration = Duration::from_secs(1);
/// `MAX_WAIT`, `MAX_TICK`, `MAX_TMP_ROOT` and `codec::MAX_CONCUR_TX` as `Config::check` states them.
const MAX_WAIT: Duration = Duration::from_secs(3600);
const MAX_TICK: Duration = Duration::from_secs(1);
const MAX_TMP_ROOT: usize = 3840;
const MAX_CONCUR_TX: usize = 4;
/// `codec::MAX_DECLARED` (the largest body the protocol declares).
const MAX_BODY: usize = 1 << 20;
/// `codec::MAX_HEADERS`, `MAX_HDR_NAME`, `MAX_HDR_VALUE` and `MAX_HDR_TOTAL` (the limits of the headers of one request).
const MAX_HEADERS: usize = 64;
const MAX_HDR_NAME: usize = 256;
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
    root: Option<PathBuf>,
    submitted: Vec<ReqId>,
    got: Vec<(ReqId, Verdict)>,
}

impl Run {
    fn new(cfg: Config, root: Option<PathBuf>) -> Run {
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
            let left: Vec<_> = fs::read_dir(root)
                .expect("the test root is readable")
                .map(|e| e.map(|e| e.file_name()))
                .collect();
            assert!(left.is_empty(), "the test root is not empty: {left:?}");
            fs::remove_dir(root).expect("the empty test root is removed");
        }
        (self.sup.status(), sd.bye)
    }
}

// ---------------------------------------------------------------------------------------------------------
// Without a process
// ---------------------------------------------------------------------------------------------------------

#[test]
fn shutdown_before_any_request_decides_the_waiting_request_once() {
    let hs = [header(b"Host", b"example.test")];
    let get = request(b"GET", b"/", &hs, b"");
    let mut sup = Supervisor::new(fake_config()).expect("valid");
    let a = sup.submit(&get).expect("accepted");
    assert_eq!(a, 0);

    let sd = sup.shutdown(Instant::now());
    assert_eq!(sd.results, vec![(a, UNAVAILABLE)]);
    assert_eq!(sd.phase, Phase::Stopped);
    assert!(!sd.bye);
    assert!(sd.exit_confirmed && sd.dir_removed);
    assert_eq!((sd.held_left, sd.waiting_left), (0, 0));
    let st = sup.status();
    assert_eq!((st.phase, st.inc, st.restarts), (Phase::Stopped, 1, 0));
    assert_eq!((st.waiting, st.held), (0, 0));

    // A second call returns nothing new and keeps the phase.
    let sd = sup.shutdown(Instant::now());
    assert!(sd.results.is_empty());
    assert_eq!(sd.phase, Phase::Stopped);
    assert!(sd.exit_confirmed && sd.dir_removed);

    // After the shutdown a new request is answered at once, and nothing is started.
    let b = sup.submit(&get).expect("accepted");
    assert_eq!(b, 1);
    assert_eq!(sup.poll(Instant::now()), vec![(b, UNAVAILABLE)]);
    let st = sup.status();
    assert_eq!((st.phase, st.inc, st.restarts), (Phase::Stopped, 1, 0));
    assert!(sup.shutdown(Instant::now()).results.is_empty());
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
    let bad = |cl: &'static [u8]| [header(b"content-LENGTH", cl), ct];
    let wrong: [&[u8]; 7] = [b"1x", b"", b"-1", b"+3", b" 3", b"4", b"2"];
    for cl in wrong {
        let hs = bad(cl);
        let r = run.refused(&request(b"POST", b"/", &hs, b"a=b"));
        assert_eq!(r, Refused::Unsupported("content-length"), "{cl:?}");
    }
    // Two of them are refused even when both are right.
    let two = [
        header(b"Content-Length", b"3"),
        header(b"Content-Length", b"3"),
        ct,
    ];
    let r = run.refused(&request(b"POST", b"/", &two, b"a=b"));
    assert_eq!(r, Refused::Unsupported("content-length"));
    // A Content-Length with no body is checked as well; an empty one too.
    let one = [header(b"Content-Length", b"1")];
    let r = run.refused(&request(b"GET", b"/", &one, b""));
    assert_eq!(r, Refused::Unsupported("content-length"));
    let empty = [header(b"Content-Length", b"")];
    let r = run.refused(&request(b"GET", b"/", &empty, b""));
    assert_eq!(r, Refused::Unsupported("content-length"));
    // The rule comes before the Content-Type rule.
    let alone = [header(b"Content-Length", b"4")];
    let r = run.refused(&request(b"POST", b"/", &alone, b"a=b"));
    assert_eq!(r, Refused::Unsupported("content-length"));

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
    let none = [cl];
    let r = run.refused(&request(b"POST", b"/", &none, b"a=b"));
    assert_eq!(r, Refused::Unsupported("content-type"));
    let two = [
        cl,
        header(b"Content-Type", URLENCODED),
        header(b"content-type", URLENCODED),
    ];
    let r = run.refused(&request(b"POST", b"/", &two, b"a=b"));
    assert_eq!(r, Refused::Unsupported("content-type"));
    let wrong: [&[u8]; 6] = [
        b"application/json",
        b"text/plain",
        b"application/xml",
        b"",
        b"application/x-www-form-urlencoded-x",
        b"x/application/x-www-form-urlencoded",
    ];
    for ct in wrong {
        let hs = [cl, header(b"Content-Type", ct)];
        let r = run.refused(&request(b"POST", b"/", &hs, b"a=b"));
        assert_eq!(r, Refused::Unsupported("content-type"), "{ct:?}");
    }

    // The two types Coraza picks a body processor for pass, in any case, with parameters and blanks.
    let right: [&[u8]; 4] = [
        URLENCODED,
        b" Application/X-WWW-Form-URLENCODED ; charset=UTF-8",
        b"multipart/form-data; boundary=x",
        b"MULTIPART/FORM-DATA",
    ];
    for ct in right {
        let hs = [cl, header(b"content-TYPE", ct)];
        run.submit(&request(b"POST", b"/", &hs, b"a=b"));
    }
    // The rule is about a body: a request with none passes whatever it says.
    let hs = [header(b"Content-Type", b"application/json")];
    run.submit(&request(b"GET", b"/", &hs, b""));
    run.finish();
}

#[test]
fn refused_invalid_request() {
    let mut run = Run::new(fake_config(), None);
    let r = run.refused(&request(b"", b"/", &[], b""));
    assert_eq!(r, Refused::Invalid("method length out of range"));
    let r = run.refused(&request(b"GET", b"", &[], b""));
    assert!(matches!(r, Refused::Invalid(_)), "{r:?}");
    run.finish();
}

#[test]
fn refused_limits_of_the_headers_come_before_the_header_rules() {
    let mut run = Run::new(fake_config(), None);
    let te = header(b"Transfer-Encoding", b"chunked");
    let ce = header(b"Content-Encoding", b"gzip");
    let ct = header(b"Content-Type", URLENCODED);
    let total = |hs: &[(&[u8], &[u8])]| hs.iter().map(|&(n, v)| n.len() + v.len()).sum::<usize>();
    let too_many = Refused::Invalid("header count out of range");
    let too_long = Refused::Invalid("header value length out of range");
    let transfer = Refused::Unsupported("transfer-encoding");

    // 65 headers with a Transfer-Encoding among them: the count is refused, not the Transfer-Encoding.
    let mut many = vec![te];
    many.resize(MAX_HEADERS + 1, header(b"X", b""));
    let r = run.refused(&request(b"POST", b"/", &many, b""));
    assert_eq!(r, too_many);
    // The limit of the body still comes first.
    let big = vec![b'a'; MAX_BODY + 1];
    let r = run.refused(&request(b"POST", b"/", &many, &big));
    assert_eq!(r, Refused::Unsupported("body over the protocol limit"));
    // 64 headers are within the limit, so the Transfer-Encoding is refused as it was.
    many.pop();
    let r = run.refused(&request(b"POST", b"/", &many, b""));
    assert_eq!(r, transfer);

    // A Content-Length of 4098 bytes that is not a number: the length is refused, not the Content-Length.
    let mut over = vec![b'0'; MAX_HDR_VALUE + 1];
    over.push(b'x');
    let hs = [header(b"Content-Length", &over), ct];
    let r = run.refused(&request(b"POST", b"/", &hs, b"a=b"));
    assert_eq!(r, too_long);
    // With 4096 bytes it is within the limit, so the Content-Length is refused as it was.
    let mut edge = vec![b'0'; MAX_HDR_VALUE - 1];
    edge.push(b'x');
    let hs = [header(b"Content-Length", &edge), ct];
    let r = run.refused(&request(b"POST", b"/", &hs, b"a=b"));
    assert_eq!(r, Refused::Unsupported("content-length"));
    // Digits only and no body: 4097 of them are refused, 4096 are a right Content-Length (the value is 0).
    let zeros = vec![b'0'; MAX_HDR_VALUE + 1];
    let hs = [header(b"Content-Length", &zeros)];
    let r = run.refused(&request(b"GET", b"/", &hs, b""));
    assert_eq!(r, too_long);
    let hs = [header(b"Content-Length", &zeros[1..])];
    run.submit(&request(b"GET", b"/", &hs, b""));

    // A value that does not fit in the 16 bits of its length.
    let huge = vec![b'x'; usize::from(u16::MAX) + 1];
    let hs = [te, header(b"X-Big", &huge)];
    let r = run.refused(&request(b"POST", b"/", &hs, b""));
    assert_eq!(r, too_long);

    // Every value is within its limit, but the total is over 24 KiB: the total is refused, not the Content-Encoding.
    let pad = vec![b'v'; MAX_HDR_VALUE];
    let mut crowded = vec![ce];
    crowded.resize(1 + MAX_HDR_TOTAL / MAX_HDR_VALUE, header(b"X-Pad", &pad));
    assert!(crowded.len() <= MAX_HEADERS && total(&crowded) > MAX_HDR_TOTAL);
    let r = run.refused(&request(b"POST", b"/", &crowded, b""));
    assert_eq!(r, Refused::Invalid("header total length out of range"));

    // A field of TX_BEGIN that is not a header is refused first as well.
    let hs = [te];
    let r = run.refused(&request(b"", b"/", &hs, b""));
    assert_eq!(r, Refused::Invalid("method length out of range"));

    // All the limits at once, exactly: 64 headers, a name of 256 bytes, values of 4096 bytes, a total of 24 KiB.
    let wide = vec![b'n'; MAX_HDR_NAME];
    let mut limit = vec![te, header(&wide, &pad)];
    limit.extend([header(b"X", &pad); 4]);
    limit.resize(MAX_HEADERS - 1, header(b"h", b""));
    let rest = vec![b'v'; MAX_HDR_TOTAL - total(&limit) - 1];
    limit.push(header(b"g", &rest));
    assert_eq!(limit.len(), MAX_HEADERS);
    assert_eq!(total(&limit), MAX_HDR_TOTAL);
    assert!(rest.len() <= MAX_HDR_VALUE);
    let r = run.refused(&request(b"POST", b"/", &limit, b""));
    assert_eq!(r, transfer);
    // Without the Transfer-Encoding (a name of the same length) the same headers are accepted.
    limit[0] = header(b"X-Transfer-Encode", b"chunked");
    assert_eq!(total(&limit), MAX_HDR_TOTAL);
    run.submit(&request(b"POST", b"/", &limit, b""));
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

// ---------------------------------------------------------------------------------------------------------
// Config::check
// ---------------------------------------------------------------------------------------------------------

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
fn check_accepts_the_fake_configuration() {
    assert_eq!(fake_config().check(), Ok(()));
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
    let not_clean = [
        "", "/", "rel/x", "/a/", "/a//b", "/a/./b", "/a/../b", "/a/b\0c",
    ];
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
    let not_utf8 = PathBuf::from(OsStr::from_bytes(b"/kernel-test/\xff"));
    rejected(
        |c| c.tmp_root = not_utf8,
        "tmp_root is not an absolute clean UTF-8 path",
    );
    // The same bytes are fine for the two files: only tmp_root must be UTF-8.
    let odd = PathBuf::from(OsStr::from_bytes(b"/kernel-test/\xff"));
    accepted(|c| c.inspector = odd.clone());
    accepted(|c| c.rules = odd);

    let tmp = |n: usize| PathBuf::from(format!("/{}", "a".repeat(n - 1)));
    accepted(|c| c.tmp_root = tmp(MAX_TMP_ROOT));
    rejected(
        |c| c.tmp_root = tmp(MAX_TMP_ROOT + 1),
        "tmp_root is too long",
    );
    // 4096 bytes is beyond what any path argument may be.
    rejected(
        |c| c.inspector = tmp(4096),
        "inspector path is not an absolute clean path",
    );
    accepted(|c| c.inspector = tmp(4095));
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
    accepted(|c| {
        c.slots = 1;
        c.records = 1 + c.wait_queue;
    });
    rejected(|c| c.wait_queue = 0, "wait_queue is 0");
    rejected(
        |c| c.records = c.slots + c.wait_queue - 1,
        "records is below slots plus wait_queue",
    );
    accepted(|c| c.records = c.slots + c.wait_queue);
    // The sum overflows: that is a refusal, not a wrap.
    rejected(
        |c| c.wait_queue = usize::MAX,
        "records is below slots plus wait_queue",
    );
    rejected(
        |c| {
            c.wait_queue = usize::MAX;
            c.records = usize::MAX;
        },
        "records is below slots plus wait_queue",
    );
    accepted(|c| c.restarts = u32::MAX);
    accepted(|c| c.rules_sha256 = [0xff; 32]);
}

/// Sets the time named `name` (the names of the fields of `Config`).
fn set_time(c: &mut Config, name: &str, d: Duration) {
    match name {
        "tick" => c.tick = d,
        "hello_wait" => c.hello_wait = d,
        "frame_io" => c.frame_io = d,
        "verdict_wait" => c.verdict_wait = d,
        "wait_deadline" => c.wait_deadline = d,
        "closed_wait" => c.closed_wait = d,
        "stop_after" => c.stop_after = d,
        "drain_wait" => c.drain_wait = d,
        "exit_wait" => c.exit_wait = d,
        "kill_grace" => c.kill_grace = d,
        _ => panic!("not a time: {name}"),
    }
}

const TIMES: [&str; 10] = [
    "tick",
    "hello_wait",
    "frame_io",
    "verdict_wait",
    "wait_deadline",
    "closed_wait",
    "stop_after",
    "drain_wait",
    "exit_wait",
    "kill_grace",
];

#[test]
fn check_times_are_above_zero_and_at_most_the_maximum() {
    for name in TIMES {
        let msg = format!("{name} is out of range");
        rejected(|c| set_time(c, name, Duration::ZERO), &msg);
        rejected(
            |c| set_time(c, name, MAX_WAIT + Duration::from_nanos(1)),
            &msg,
        );
        rejected(|c| set_time(c, name, Duration::MAX), &msg);
        if name != "tick" {
            accepted(|c| set_time(c, name, MAX_WAIT));
            accepted(|c| {
                let t = c.tick;
                set_time(c, name, t);
            });
        }
    }
}

#[test]
fn check_tick_is_short_and_not_above_any_other_time() {
    rejected(
        |c| {
            for name in TIMES {
                set_time(c, name, MAX_WAIT);
            }
            c.tick = MAX_TICK + Duration::from_nanos(1);
        },
        "tick is above the longest tick",
    );
    accepted(|c| {
        for name in TIMES {
            set_time(c, name, MAX_WAIT);
        }
        c.tick = MAX_TICK;
    });
    for name in &TIMES[1..] {
        rejected(
            |c| {
                let t = c.tick - Duration::from_nanos(1);
                set_time(c, name, t);
            },
            "tick is above another time",
        );
        accepted(|c| {
            let t = c.tick;
            set_time(c, name, t);
        });
    }
}

/// The messages in the order of the rules, and what repairs the one that is reported.
const ORDER: [&str; 10] = [
    "inspector path is not an absolute clean path",
    "rules path is not an absolute clean path",
    "tmp_root is not an absolute clean UTF-8 path",
    "gomaxprocs is 0",
    "gomemlimit is out of range",
    "slots is out of range",
    "wait_queue is 0",
    "records is below slots plus wait_queue",
    "discard_limit must be below u32::MAX",
    "tick is out of range",
];

fn repair(c: &mut Config, step: usize) {
    match step {
        0 => c.inspector = PathBuf::from("/a"),
        1 => c.rules = PathBuf::from("/a"),
        2 => c.tmp_root = PathBuf::from("/a"),
        3 => c.gomaxprocs = 1,
        4 => c.gomemlimit = 1,
        5 => c.slots = 1,
        6 => c.wait_queue = 1,
        7 => c.records = 2,
        8 => c.discard_limit = 0,
        9 => TIMES.iter().for_each(|&name| set_time(c, name, SEC)),
        _ => panic!("no such step"),
    }
}

#[test]
fn check_reports_the_first_broken_rule() {
    // Everything is broken at once; each repair uncovers the next rule in the order of the checks.
    let mut c = fake_config();
    c.inspector = PathBuf::from("rel");
    c.rules = PathBuf::from("rel");
    c.tmp_root = PathBuf::from("rel");
    c.gomaxprocs = 0;
    c.gomemlimit = 0;
    c.slots = 0;
    c.wait_queue = 0;
    c.records = 0;
    c.discard_limit = u32::MAX;
    TIMES
        .iter()
        .for_each(|&name| set_time(&mut c, name, Duration::ZERO));
    for (step, msg) in ORDER.iter().enumerate() {
        assert_eq!(c.check(), Err(ConfigError(msg)), "step {step}");
        repair(&mut c, step);
    }
    assert_eq!(c.check(), Ok(()));
}

// ---------------------------------------------------------------------------------------------------------
// With a real inspector (ignored by default; run with `-- --include-ignored`)
// ---------------------------------------------------------------------------------------------------------

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

/// A new 0700 root for one test, under `TUKUYOMI_TEST_TMP`. Its name has the process id and the test name, so
/// parallel tests and earlier runs do not meet. `Run::finish` removes it, and fails if it is not empty.
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

/// The configuration of a real run: the environment's inspector, rules and hash, and the test's own root.
fn real_config(root: &Path, sha256: [u8; 32]) -> Config {
    let mut c = fake_config();
    c.inspector = PathBuf::from(var("TUKUYOMI_TEST_INSPECTOR"));
    c.rules = PathBuf::from(var("TUKUYOMI_TEST_RULES"));
    c.rules_sha256 = sha256;
    c.tmp_root = root.to_path_buf();
    c
}

/// The configuration of a run that needs only the test root: no inspector and no rules are read.
fn real_config_without_inspector(root: &Path) -> Config {
    let mut c = fake_config();
    c.tmp_root = root.to_path_buf();
    c
}

fn real_run(test: &str) -> Run {
    let sha = parse_sha256(&var("TUKUYOMI_TEST_RULES_SHA256"));
    let root = make_root(test);
    Run::new(real_config(&root, sha), Some(root))
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
            rule_id: 9201
        }
    );
    assert_eq!(run.verdict(passed), Verdict::Allow);
    finish_stopped(run);
}

#[test]
#[ignore = "needs a built inspector"]
fn urlencoded_body_rule_blocks_in_phase_2() {
    let mut run = real_run("body_block");
    let mut post = |body: &[u8]| {
        let cl = body.len().to_string();
        let hs = [
            header(b"Host", b"example.test"),
            header(b"Content-Type", URLENCODED),
            header(b"Content-Length", cl.as_bytes()),
        ];
        run.submit(&request(b"POST", b"/submit", &hs, body))
    };
    let blocked = post(b"probe=block");
    let passed = post(b"probe=ok");
    run.wait_results(2);
    assert_eq!(
        run.verdict(blocked),
        Verdict::Block {
            phase: 2,
            rule_id: 9202
        }
    );
    assert_eq!(run.verdict(passed), Verdict::Allow);
    finish_stopped(run);
}

#[test]
#[ignore = "needs a built inspector"]
fn urlencoded_content_type_forms_the_submit_accepts_are_parsed() {
    // A parameter after `;` and a leading space are accepted by `submit`; the body must still be parsed.
    let mut run = real_run("ct_forms");
    let mut post = |content_type: &[u8], body: &[u8]| {
        let cl = body.len().to_string();
        let hs = [
            header(b"Host", b"example.test"),
            header(b"Content-Type", content_type),
            header(b"Content-Length", cl.as_bytes()),
        ];
        run.submit(&request(b"POST", b"/submit", &hs, body))
    };
    let with_charset = post(
        b"application/x-www-form-urlencoded; charset=UTF-8",
        b"probe=block",
    );
    let leading_space = post(b" application/x-www-form-urlencoded", b"probe=block");
    let passed = post(
        b"application/x-www-form-urlencoded; charset=UTF-8",
        b"probe=pass",
    );
    run.wait_results(3);
    let blocked = Verdict::Block {
        phase: 2,
        rule_id: 9202,
    };
    assert_eq!(run.verdict(with_charset), blocked);
    assert_eq!(run.verdict(leading_space), blocked);
    assert_eq!(run.verdict(passed), Verdict::Allow);
    finish_stopped(run);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_different_rules_hash_fails_at_hello_without_restart() {
    let mut sha = parse_sha256(&var("TUKUYOMI_TEST_RULES_SHA256"));
    sha[31] ^= 1;
    let root = make_root("wrong_sha");
    let mut run = Run::new(real_config(&root, sha), Some(root));
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
fn a_budget_of_one_restart_is_used_up_by_two_failed_starts() {
    // The inspector does not exist: both starts fail at spawn, before any process exists.
    let root = make_root("budget");
    let mut cfg = real_config_without_inspector(&root);
    cfg.inspector = root.join("absent-inspector");
    cfg.rules = root.join("absent-rules.conf");
    cfg.restarts = 1;
    let mut run = Run::new(cfg, Some(root));
    let hs = [header(b"Host", b"example.test")];
    let id = run.submit(&request(b"GET", b"/", &hs, b""));
    run.wait_for("the budget to be used up", |r| {
        r.got.len() == 1 && matches!(r.sup.status().phase, Phase::Failed(_))
    });
    let st = run.sup.status();
    assert_eq!(st.phase, Phase::Failed(Failure::BudgetExhausted));
    assert_eq!((st.restarts, st.inc), (1, 3));
    assert_eq!((st.waiting, st.held), (0, 0));
    assert_eq!(run.verdict(id), UNAVAILABLE);
    let (st, bye) = run.finish();
    assert_eq!(st.phase, Phase::Failed(Failure::BudgetExhausted));
    assert_eq!((st.restarts, st.inc, bye), (1, 3, false));
}
