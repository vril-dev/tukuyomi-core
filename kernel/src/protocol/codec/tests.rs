use super::*;
use std::io;

const GOLDEN: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../inspector/testdata/v1-golden.txt"
));
const RUN: u64 = 0x0102_0304_0506_0708;
const INC: u32 = 7;
const SENT: [&str; 8] = [
    "tx_begin",
    "body",
    "body_end",
    "resp_begin",
    "resp_body",
    "resp_end",
    "tx_end",
    "drain",
];
const RECEIVED: [&str; 13] = [
    "hello",
    "verdict_continue",
    "verdict_block",
    "verdict_block_rule0",
    "verdict_truncated",
    "verdict_detected",
    "verdict_allow_rules",
    "verdict_rules_more",
    "verdict_rules_severity",
    "error_not_created",
    "error_tx_failed",
    "closed",
    "bye",
];
/// The VERDICTs that the receiver must refuse (the names that start with `bad_`), each with the reason.
const REFUSED: [(&str, &str); 7] = [
    ("bad_verdict_rules_17", "verdict rule count out of range"),
    (
        "bad_verdict_more_short",
        "verdict more flag needs a full list of rule ids",
    ),
    ("bad_verdict_severity", "verdict severity out of range"),
    ("bad_verdict_score", "verdict score out of range"),
    ("bad_verdict_rule_id", "verdict rule id out of range"),
    (
        "bad_verdict_rules_phase",
        "verdict of a response phase carries rules, a severity or a score",
    ),
    ("bad_verdict_no_tail", "payload too short"),
];
/// The whole frame of the HELLO of version 0: the HELLO of the golden file with the version 0000.
const HELLO_V0: &str = concat!(
    "544b5630010000000000006f01020304050607080000000700000000000000000000000000000000",
    "1092000102030405060708090a0b0c0d0e0f01020304050607080000000700",
    "08676f312e32372e32000676332e382e31000768313a6162633da0a1a2a3a4a5a6a7a8a9aaabacad",
    "aeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf001000000000000010000000000200040011"
);
// Receivable kinds with their payload limits.
const RECV: [(u8, usize); 5] = [
    (KIND_HELLO, MAX_HELLO),
    (KIND_BYE, MAX_BYE),
    (KIND_VERDICT, MAX_VERDICT),
    (KIND_ERROR, MAX_ERROR),
    (KIND_CLOSED, MAX_CLOSED),
];

// ---- golden file ----

/// The whole frame of a golden vector: a line `name hex-of-the-whole-frame` (`#` lines are notes).
fn golden(name: &str) -> Vec<u8> {
    let hex = GOLDEN
        .lines()
        .filter_map(|l| l.trim().split_once(' '))
        .find(|(n, _)| *n == name)
        .unwrap_or_else(|| panic!("golden vector {name} missing"))
        .1
        .trim();
    assert!(hex.len().is_multiple_of(2), "odd hex length");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex digits"))
        .collect()
}

fn golden_payload(name: &str) -> Vec<u8> {
    golden(name)[HEADER_LEN..].to_vec()
}

// ---- Rust to Go: encoders against the golden bytes ----

#[test]
fn rust_to_go_frames_are_byte_identical_to_the_golden_vectors() {
    let hs: [(&[u8], &[u8]); 2] = [
        (b"Host", b"example.test"),
        (b"Content-Type", b"application/x-www-form-urlencoded"),
    ];
    let tx_begin = encode_tx_begin(&TxBegin {
        client_addr: b"127.0.0.1",
        client_port: 40000,
        server_addr: b"127.0.0.1",
        server_port: 8080,
        method: b"POST",
        uri: b"/a?q=1",
        proto: b"HTTP/1.1",
        declared: 5,
        headers: &hs,
    })
    .unwrap();
    let tx_end = encode_tx_end(1).unwrap();
    // The response vectors stay in the golden file (Go receives them); Rust does not send them.
    let cases = [
        (
            "tx_begin",
            encode_frame(KIND_TX_BEGIN, 0, RUN, INC, 0x10, 1, &tx_begin),
        ),
        (
            "tx_begin_cut",
            encode_frame(KIND_TX_BEGIN, FLAG_BODY_CUT, RUN, INC, 0x10, 1, &tx_begin),
        ),
        (
            "body",
            encode_frame(KIND_BODY, 0, RUN, INC, 0x10, 2, b"a=b&c"),
        ),
        (
            "body_end",
            encode_frame(KIND_BODY_END, 0, RUN, INC, 0x10, 3, &[]),
        ),
        (
            "tx_end",
            encode_frame(KIND_TX_END, 0, RUN, INC, 0x10, 7, &tx_end),
        ),
        ("drain", encode_frame(KIND_DRAIN, 0, RUN, INC, 0, 0, &[])),
    ];
    for (name, got) in cases {
        assert_eq!(got.unwrap(), golden(name), "{name}");
    }
}

// ---- Go to Rust: read_frame and decode_* against the golden bytes ----

fn hdr(kind: u8, len: u32, tx: u64, msg: u32) -> Header {
    Header {
        kind,
        len,
        run: RUN,
        inc: INC,
        tx,
        msg,
    }
}

/// Reads `name` followed by two sentinel bytes: the frame must be consumed exactly, not a byte more.
fn read_golden(name: &str) -> (Header, Vec<u8>) {
    let mut bytes = golden(name);
    let n = bytes.len();
    bytes.extend_from_slice(&[0xaa, 0xbb]);
    let mut r: &[u8] = &bytes;
    let (h, p) = read_frame(&mut r, RUN, INC).unwrap_or_else(|e| panic!("{name}: {e:?}"));
    assert_eq!(r, &[0xaa, 0xbb], "{name}: not consumed exactly");
    assert_eq!((h.len as usize, p.len()), (n - HEADER_LEN, n - HEADER_LEN));
    (h, p)
}

#[test]
fn golden_hello_reads_and_decodes() {
    let (h, p) = read_golden("hello");
    assert_eq!(h, hdr(KIND_HELLO, 111, 0, 0));
    let nonce: [u8; 16] = std::array::from_fn(|i| i as u8);
    let sha: [u8; 32] = std::array::from_fn(|i| 0xa0 + i as u8);
    let hello = decode_hello(&p).unwrap();
    assert_eq!(
        hello,
        Hello {
            version: 1,
            pid: 0x1092,
            nonce,
            run: RUN,
            inc: INC,
            go_version: b"go1.27.2".to_vec(),
            coraza_version: b"v3.8.1".to_vec(),
            coraza_sum: b"h1:abc=".to_vec(),
            rules_sha256: sha,
            body_limit: 0x0010_0000,
            mem_limit: 0x1000_0000,
            gomaxprocs: 2,
            tx_limit: 4,
            queue: 0x11,
        }
    );
    // The limits Go reports are the ones `check_hello` compares with.
    assert_eq!(u64::from(hello.body_limit), MAX_DECLARED);
    assert_eq!((hello.tx_limit, hello.queue), (MAX_CONCUR_TX, QUEUE_DEPTH));
}

/// The rules that matched, as the test writes them.
fn matched(ids: &[i64], more: bool, severity: u8, score: i32) -> Matched {
    let mut all = [0; matched::MAX_RULE_IDS];
    all[..ids.len()].copy_from_slice(ids);
    Matched {
        count: ids.len() as u8,
        ids: all,
        more,
        severity,
        score,
    }
}

#[test]
fn golden_verdicts_read_and_decode() {
    let v = |phase, block, flags, rule_id, status, action: &[u8], data: &[u8], matched| Verdict {
        phase,
        block,
        flags,
        rule_id,
        status,
        action: action.to_vec(),
        data: data.to_vec(),
        matched,
    };
    let more_ids: Vec<i64> = (930100..930116).collect();
    let none = Matched::NONE;
    let cases = [
        (
            "verdict_continue",
            hdr(KIND_VERDICT, 24, 0x10, 1),
            v(1, false, 0, 0, 0, b"", b"", none),
        ),
        (
            "verdict_block",
            hdr(KIND_VERDICT, 37, 0x10, 2),
            v(
                2,
                true,
                0,
                1021,
                403,
                b"deny",
                b"x",
                matched(&[942100], false, 2, 5),
            ),
        ),
        (
            "verdict_block_rule0",
            hdr(KIND_VERDICT, 28, 0x10, 3),
            v(2, true, 0, 0, 413, b"deny", b"", none),
        ),
        (
            "verdict_truncated",
            hdr(KIND_VERDICT, 312, 0x10, 6),
            v(4, true, 3, 1040, 403, &[b'a'; 32], &[b'd'; 256], none),
        ),
        (
            "verdict_detected",
            hdr(KIND_VERDICT, 44, 0x10, 4),
            v(
                2,
                false,
                FLAG_DETECTED,
                949110,
                403,
                b"deny",
                b"",
                matched(&[942100, 941100], false, 2, 10),
            ),
        ),
        (
            "verdict_allow_rules",
            hdr(KIND_VERDICT, 48, 0x10, 5),
            v(
                2,
                false,
                0,
                0,
                0,
                b"",
                b"",
                matched(&[920280, 942100, 7000005], false, 5, 0),
            ),
        ),
        (
            "verdict_rules_more",
            hdr(KIND_VERDICT, 156, 0x10, 7),
            v(
                2,
                true,
                FLAG_MORE_RULES,
                949110,
                403,
                b"deny",
                b"",
                matched(&more_ids, true, 2, 80),
            ),
        ),
        (
            "verdict_rules_severity",
            hdr(KIND_VERDICT, 28, 0x10, 8),
            v(
                1,
                true,
                0,
                7000006,
                403,
                b"deny",
                b"",
                matched(&[], false, 3, -1),
            ),
        ),
    ];
    for (name, want_h, want_v) in cases {
        let (h, p) = read_golden(name);
        assert_eq!(h, want_h, "{name}");
        assert_eq!(decode_verdict(&p).unwrap(), want_v, "{name}");
    }
}

/// The names of the golden file, in its order.
fn golden_names() -> Vec<&'static str> {
    GOLDEN
        .lines()
        .filter_map(|l| l.trim().split_once(' '))
        .map(|(name, _)| name)
        .filter(|name| !name.starts_with('#'))
        .collect()
}

#[test]
fn every_valid_golden_verdict_decodes_and_every_bad_one_is_refused_for_its_reason() {
    let names = golden_names();
    let bad: Vec<&str> = names
        .iter()
        .copied()
        .filter(|name| name.starts_with("bad_"))
        .collect();
    // A refused vector that this table does not name would never be tried.
    assert_eq!(bad, REFUSED.map(|(name, _)| name));
    for (name, why) in REFUSED {
        // The frame itself is good: only the content is refused.
        let (_, p) = read_golden(name);
        assert_eq!(reason(decode_verdict(&p)), why, "{name}");
    }
    let mut valid = 0;
    for name in names.iter().filter(|name| !name.starts_with("bad_")) {
        if golden(name)[4] == KIND_VERDICT {
            let (_, p) = read_golden(name);
            assert!(decode_verdict(&p).is_ok(), "{name}");
            valid += 1;
        }
    }
    assert_eq!(valid, 8);
}

#[test]
fn golden_errors_closed_and_bye_read_and_decode() {
    let (h, p) = read_golden("error_not_created");
    assert_eq!(h, hdr(KIND_ERROR, 23, 0x11, 1));
    assert_eq!(
        decode_error(&p).unwrap(),
        ErrorMsg {
            class: 1,
            code: 1,
            text: b"concurrency limit".to_vec()
        }
    );
    let (h, p) = read_golden("error_tx_failed");
    assert_eq!(h, hdr(KIND_ERROR, 40, 0x10, 3));
    assert_eq!(
        decode_error(&p).unwrap(),
        ErrorMsg {
            class: 2,
            code: 22,
            text: b"request body shorter than declared".to_vec()
        }
    );
    let (h, p) = read_golden("closed");
    assert_eq!(h, hdr(KIND_CLOSED, 1, 0x10, 7));
    assert_eq!(decode_closed(&p), Ok(false));
    let (h, p) = read_golden("bye");
    assert_eq!(h, hdr(KIND_BYE, 24, 0, 0));
    assert_eq!(
        decode_bye(&p),
        Ok(Bye {
            started: 3,
            closed: 3,
            close_errors: 0
        })
    );
}

// ---- direction and kinds ----

fn header(kind: u8, len: u32, tx: u64, msg: u32) -> [u8; HEADER_LEN] {
    let mut b = [0u8; HEADER_LEN];
    b[..4].copy_from_slice(&MAGIC);
    b[4] = kind;
    b[8..12].copy_from_slice(&len.to_be_bytes());
    b[12..20].copy_from_slice(&RUN.to_be_bytes());
    b[20..24].copy_from_slice(&INC.to_be_bytes());
    b[24..32].copy_from_slice(&tx.to_be_bytes());
    b[32..36].copy_from_slice(&msg.to_be_bytes());
    b
}

#[test]
fn sent_goldens_are_wrong_direction_for_check_header() {
    for name in SENT {
        let b = golden(name);
        let head: [u8; HEADER_LEN] = b[..HEADER_LEN].try_into().unwrap();
        assert_eq!(
            check_header(&head, RUN, INC),
            Err(ConnError::WrongDirection(b[4])),
            "{name}"
        );
    }
    // FAULT (0x7f) is reserved but unknown to this build, like any other unlisted kind.
    for kind in [0x00, 0x17, 0x7f, 0xff] {
        assert_eq!(
            check_header(&header(kind, 0, 0x10, 1), RUN, INC),
            Err(ConnError::UnknownKind(kind))
        );
    }
}

#[test]
fn the_cut_flag_is_sent_on_tx_begin_only_and_is_not_accepted_when_received() {
    let begin = encode_tx_begin(&begin()).unwrap();
    let flags = |kind, flags, payload: &[u8]| {
        encode_frame(kind, flags, RUN, INC, 0x10, 1, payload).map_err(|e| e.0)
    };
    assert!(flags(KIND_TX_BEGIN, FLAG_BODY_CUT, &begin).is_ok());
    // Any other bit, and the flag on any other kind, is refused before the payload is looked at.
    let refused = Err("frame flags out of range");
    assert_eq!(flags(KIND_TX_BEGIN, 0x02, &begin), refused);
    assert_eq!(flags(KIND_TX_BEGIN, 0x03, &begin), refused);
    assert_eq!(flags(KIND_BODY, FLAG_BODY_CUT, b"x"), refused);
    assert_eq!(flags(KIND_BODY_END, FLAG_BODY_CUT, b""), refused);
    assert_eq!(flags(KIND_TX_END, FLAG_BODY_CUT, &[1]), refused);
    // What Rust receives has no flags: the frame with the flag is not a frame it takes.
    let b = golden("tx_begin_cut");
    let head: [u8; HEADER_LEN] = b[..HEADER_LEN].try_into().unwrap();
    assert_eq!(check_header(&head, RUN, INC), Err(ConnError::Flags(1)));
}

#[test]
fn encode_frame_accepts_only_the_kinds_rust_sends() {
    // The kind alone decides: before the ids and the payload are looked at.
    let received = Err(ContentError(
        "frame kind is received, not sent, by this side",
    ));
    let response = Err(ContentError("frame kind is not sent by this side"));
    let unknown = Err(ContentError("unknown frame kind"));
    let big = vec![0u8; MAX_BODY + 1];
    for (kind, _) in RECV {
        assert_eq!(encode_frame(kind, 0, RUN, INC, 0, 1, &big), received);
    }
    for kind in [KIND_RESP_BEGIN, KIND_RESP_BODY, KIND_RESP_END] {
        assert_eq!(encode_frame(kind, 0, RUN, INC, 0x10, 1, b"x"), response);
        assert_eq!(encode_frame(kind, 0, RUN, INC, 0, 1, &big), response);
    }
    for kind in [0x00, 0x17, 0x7f] {
        assert_eq!(encode_frame(kind, 0, RUN, INC, 0x10, 1, b""), unknown);
    }
}

// ---- header checks ----

/// A valid header of a receivable kind: control kinds carry tx = msg = 0, the others both nonzero.
fn base(kind: u8) -> [u8; HEADER_LEN] {
    if kind == KIND_HELLO || kind == KIND_BYE {
        header(kind, 0, 0, 0)
    } else {
        header(kind, 0, 0x10, 1)
    }
}

fn mutated(kind: u8, f: impl FnOnce(&mut [u8; HEADER_LEN])) -> Result<Header, ConnError> {
    let mut b = base(kind);
    f(&mut b);
    check_header(&b, RUN, INC)
}

fn set_ids(b: &mut [u8; HEADER_LEN], tx: u64, msg: u32) {
    b[24..32].copy_from_slice(&tx.to_be_bytes());
    b[32..36].copy_from_slice(&msg.to_be_bytes());
}

#[test]
fn header_magic_flags_reserved_run_and_incarnation_are_checked() {
    for (kind, _) in RECV {
        assert_eq!(mutated(kind, |b| b[0] ^= 1), Err(ConnError::BadMagic));
        assert_eq!(mutated(kind, |b| b[3] ^= 0x80), Err(ConnError::BadMagic));
        assert_eq!(mutated(kind, |b| b[5] = 1), Err(ConnError::Flags(1)));
        assert_eq!(
            mutated(kind, |b| b[6] = 1),
            Err(ConnError::Reserved(0x0100))
        );
        assert_eq!(mutated(kind, |b| b[7] = 1), Err(ConnError::Reserved(1)));
        assert_eq!(
            mutated(kind, |b| b[12] ^= 0xff),
            Err(ConnError::RunMismatch(RUN ^ (0xff << 56)))
        );
        assert_eq!(
            mutated(kind, |b| b[19] ^= 1),
            Err(ConnError::RunMismatch(RUN ^ 1))
        );
        assert_eq!(
            mutated(kind, |b| b[23] ^= 1),
            Err(ConnError::IncMismatch(INC ^ 1))
        );
    }
}

#[test]
fn header_length_exactly_the_limit_passes_and_one_more_is_too_long() {
    for (kind, max) in RECV {
        let max = max as u32;
        let ok = mutated(kind, |b| b[8..12].copy_from_slice(&max.to_be_bytes())).unwrap();
        assert_eq!(ok.len, max, "kind {kind:#04x}");
        for len in [max + 1, u32::MAX] {
            assert_eq!(
                mutated(kind, |b| b[8..12].copy_from_slice(&len.to_be_bytes())),
                Err(ConnError::TooLong { kind, len }),
                "kind {kind:#04x} len {len}"
            );
        }
    }
}

#[test]
fn header_control_frames_need_zero_ids_and_the_others_nonzero_ids() {
    for kind in [KIND_HELLO, KIND_BYE] {
        assert_eq!(mutated(kind, |b| b[31] = 1), Err(ConnError::ControlIds));
        assert_eq!(mutated(kind, |b| b[35] = 1), Err(ConnError::ControlIds));
    }
    for kind in [KIND_VERDICT, KIND_ERROR, KIND_CLOSED] {
        assert_eq!(
            mutated(kind, |b| b[24..32].fill(0)),
            Err(ConnError::ZeroIds)
        );
        assert_eq!(
            mutated(kind, |b| b[32..36].fill(0)),
            Err(ConnError::ZeroIds)
        );
        let max = mutated(kind, |b| set_ids(b, u64::MAX, u32::MAX)).unwrap();
        assert_eq!((max.tx, max.msg), (u64::MAX, u32::MAX));
    }
}

// ---- read_frame: no allocation before the check, EOF, interruption, short reads ----

/// A Read that serves `data` and counts what it served in `pos`. It can report more than it was given. A read with
/// an empty buffer is a test failure.
struct Fake<'a> {
    data: &'a [u8],
    pos: usize,
    over_report: bool,
}

impl<'a> Fake<'a> {
    fn new(data: &'a [u8]) -> Self {
        Fake {
            data,
            pos: 0,
            over_report: false,
        }
    }
}

impl Read for Fake<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        assert!(!buf.is_empty(), "read called with an empty buffer");
        if self.over_report {
            return Ok(buf.len() + 1);
        }
        let n = buf.len().min(self.data.len() - self.pos);
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

#[test]
fn oversize_header_is_rejected_after_exactly_36_bytes() {
    // A VERDICT of u32::MAX bytes, with plenty more bytes available: only the header is consumed.
    let mut data = header(KIND_VERDICT, u32::MAX, 0x10, 1).to_vec();
    data.extend_from_slice(&[0u8; 200]);
    let mut f = Fake::new(&data);
    assert_eq!(
        read_frame(&mut f, RUN, INC),
        Err(ConnError::TooLong {
            kind: KIND_VERDICT,
            len: u32::MAX
        })
    );
    assert_eq!(f.pos, HEADER_LEN);
}

#[test]
fn eof_before_the_first_byte_is_peer_closed_and_later_eof_is_truncated() {
    let full = golden("verdict_block");
    let payload_len = full.len() - HEADER_LEN;
    let read = |n: usize| read_frame(&mut Fake::new(&full[..n]), RUN, INC);
    assert_eq!(read(0), Err(ConnError::PeerClosed));
    for n in [1, HEADER_LEN - 1] {
        let want = HEADER_LEN;
        assert_eq!(read(n), Err(ConnError::Truncated { got: n, want }));
    }
    for n in [HEADER_LEN, full.len() - 1] {
        let (got, want) = (n - HEADER_LEN, payload_len);
        assert_eq!(read(n), Err(ConnError::Truncated { got, want }));
    }
}

#[test]
fn a_read_that_reports_more_than_it_was_given_is_an_io_error() {
    let data = golden("closed");
    let mut f = Fake {
        over_report: true,
        ..Fake::new(&data)
    };
    assert_eq!(
        read_frame(&mut f, RUN, INC),
        Err(ConnError::Io(ErrorKind::InvalidData))
    );
}

#[test]
fn a_zero_length_payload_is_returned_without_reading_it() {
    // The Fake panics on a read with an empty buffer. decode_* then reject the empty content.
    let data = header(KIND_VERDICT, 0, 0x10, 1);
    let mut f = Fake::new(&data);
    let (h, p) = read_frame(&mut f, RUN, INC).unwrap();
    assert_eq!((h.len, p.len(), f.pos), (0, 0, HEADER_LEN));
    assert!(decode_verdict(&p).is_err());
}

// ---- payloads of the five received kinds ----

fn tstr(v: &mut Vec<u8>, s: &[u8]) {
    v.extend_from_slice(&(s.len() as u16).to_be_bytes());
    v.extend_from_slice(s);
}

#[allow(clippy::too_many_arguments)]
fn verdict(
    phase: u8,
    decision: u8,
    flags: u8,
    reserved: u8,
    rule: i64,
    status: u16,
    action: &[u8],
    data: &[u8],
) -> Vec<u8> {
    let mut v = vec![phase, decision, flags, reserved];
    v.extend_from_slice(&rule.to_be_bytes());
    v.extend_from_slice(&status.to_be_bytes());
    tstr(&mut v, action);
    tstr(&mut v, data);
    v.extend_from_slice(&NO_TAIL);
    v
}

/// The end of a VERDICT that says nothing: no rules, no severity (255), no score (-1).
const NO_TAIL: [u8; 6] = [0, 255, 255, 255, 255, 255];

/// `payload` (made by `verdict`) with the end `tail` in place of the end that says nothing.
fn with_tail(mut payload: Vec<u8>, tail: &[u8]) -> Vec<u8> {
    payload.truncate(payload.len() - NO_TAIL.len());
    payload.extend_from_slice(tail);
    payload
}

/// The end of a VERDICT: the count, the ids, the severity and the score.
fn tail(ids: &[i64], severity: u8, score: i32) -> Vec<u8> {
    let mut v = vec![ids.len() as u8];
    for id in ids {
        v.extend_from_slice(&id.to_be_bytes());
    }
    v.push(severity);
    v.extend_from_slice(&score.to_be_bytes());
    v
}

fn errmsg(class: u8, reserved: u8, code: u16, text: &[u8]) -> Vec<u8> {
    let mut v = vec![class, reserved];
    v.extend_from_slice(&code.to_be_bytes());
    tstr(&mut v, text);
    v
}

fn hello(version: u16, go: &[u8], coraza: &[u8], sum: &[u8]) -> Vec<u8> {
    let mut v = version.to_be_bytes().to_vec();
    v.extend_from_slice(&0x1092u32.to_be_bytes());
    v.extend(0..16u8);
    v.extend_from_slice(&RUN.to_be_bytes());
    v.extend_from_slice(&INC.to_be_bytes());
    tstr(&mut v, go);
    tstr(&mut v, coraza);
    tstr(&mut v, sum);
    v.extend((0..32u8).map(|i| 0xa0 + i));
    v.extend_from_slice(&0x0010_0000u32.to_be_bytes());
    v.extend_from_slice(&0x1000_0000u64.to_be_bytes());
    v.extend_from_slice(&2u16.to_be_bytes());
    v.extend_from_slice(&4u16.to_be_bytes());
    v.extend_from_slice(&17u16.to_be_bytes());
    v
}

fn reason<T: std::fmt::Debug>(r: Result<T, ContentError>) -> &'static str {
    r.unwrap_err().0
}

/// Decodes a received payload with the decoder of its kind.
fn decode_named(name: &str, p: &[u8]) -> Result<(), ContentError> {
    match name {
        "hello" => decode_hello(p).map(drop),
        "closed" => decode_closed(p).map(drop),
        "bye" => decode_bye(p).map(drop),
        n if n.starts_with("verdict") => decode_verdict(p).map(drop),
        n if n.starts_with("error") => decode_error(p).map(drop),
        n => panic!("no decoder for {n}"),
    }
}

#[test]
fn every_golden_payload_with_one_byte_missing_one_extra_or_cut_anywhere_is_rejected() {
    for name in RECEIVED {
        let p = golden_payload(name);
        assert!(decode_named(name, &p).is_ok(), "{name}");
        for n in 0..p.len() {
            assert!(decode_named(name, &p[..n]).is_err(), "{name} cut to {n}");
        }
        let mut extra = p.clone();
        extra.push(0);
        assert!(decode_named(name, &extra).is_err(), "{name} plus one byte");
    }
    let p = golden_payload("verdict_block");
    assert_eq!(
        reason(decode_verdict(&p[..p.len() - 1])),
        "payload too short"
    );
    let mut extra = p;
    extra.push(0);
    assert_eq!(reason(decode_verdict(&extra)), "trailing bytes in payload");
}

#[test]
fn verdict_accepts_the_boundaries_go_emits() {
    for phase in [1, 4] {
        assert!(decode_verdict(&verdict(phase, 0, 0, 0, 0, 0, b"", b"")).is_ok());
    }
    // Exactly 32 / 256 bytes with each cut flag (and none), a negative rule id, the largest status, and bytes that
    // are not UTF-8 pass unchanged.
    for flags in [0, 1, 2, 3] {
        let p = verdict(2, 1, flags, 0, i64::MIN, 65535, &[0xff; 32], &[0x80; 256]);
        let v = decode_verdict(&p).unwrap();
        assert_eq!((v.flags, v.rule_id, v.status), (flags, i64::MIN, 65535));
        assert_eq!((v.action, v.data), (vec![0xff; 32], vec![0x80; 256]));
    }
    // A detection carries the fields of a block with the same cuts at their limits; a cut flag needs the exact
    // length here too.
    let both = FLAG_DETECTED | FLAG_ACTION_TRUNCATED | FLAG_DATA_TRUNCATED;
    let p = verdict(2, 0, both, 0, i64::MIN, 65535, &[0xff; 32], &[0x80; 256]);
    let v = decode_verdict(&p).unwrap();
    assert_eq!(
        (v.block, v.flags, v.rule_id, v.status),
        (false, both, i64::MIN, 65535)
    );
    let short = verdict(
        2,
        0,
        FLAG_DETECTED | FLAG_ACTION_TRUNCATED,
        0,
        1,
        403,
        &[b'a'; 31],
        b"",
    );
    assert_eq!(
        reason(decode_verdict(&short)),
        "verdict action cut flag needs a full-length action"
    );
}

#[test]
fn verdict_rejects_out_of_range_values_with_the_matching_reason() {
    // One byte of a block verdict out of range at a time: phase, decision, flags, reserved.
    let block = verdict(2, 1, 0, 0, 1, 403, b"deny", b"x");
    let bytes = [
        (0, 0, "verdict phase out of range"),
        (0, 5, "verdict phase out of range"),
        (1, 2, "verdict decision out of range"),
        (2, 0x10, "verdict flags out of range"),
        (3, 1, "verdict reserved not zero"),
    ];
    for (at, value, why) in bytes {
        let mut p = block.clone();
        p[at] = value;
        assert_eq!(reason(decode_verdict(&p)), why);
    }
    // A continuation carries no rule id, status, action or data.
    let rest: [(i64, u16, &[u8], &[u8]); 4] = [
        (1, 0, b"", b""),
        (0, 403, b"", b""),
        (0, 0, b"a", b""),
        (0, 0, b"", b"d"),
    ];
    for (rule, status, action, data) in rest {
        let p = verdict(1, 0, 0, 0, rule, status, action, data);
        let why = "verdict continue carries interruption fields";
        assert_eq!(reason(decode_verdict(&p)), why);
    }
    // The detection flag belongs to a continue of phase 2 only: not to a block, not to another phase.
    let why = "verdict detected flag needs a continue of phase 2";
    for (phase, decision) in [(2, 1), (1, 0), (3, 0), (4, 0)] {
        let p = verdict(phase, decision, FLAG_DETECTED, 0, 1, 403, b"deny", b"");
        assert_eq!(reason(decode_verdict(&p)), why, "phase {phase}");
    }
    // One byte over the limits of action (32) and data (256); a cut flag needs the exact cut length.
    let bad = |flags, action: &[u8], data: &[u8]| {
        reason(decode_verdict(&verdict(
            2, 1, flags, 0, 1, 403, action, data,
        )))
    };
    let range = "string length out of range";
    assert_eq!(bad(0, &[b'a'; 33], b""), range);
    assert_eq!(bad(0, b"deny", &[b'd'; 257]), range);
    let cut = "verdict action cut flag needs a full-length action";
    assert_eq!(bad(1, &[b'a'; 31], b""), cut);
    let cut = "verdict data cut flag needs a full-length data";
    assert_eq!(bad(2, b"deny", &[b'd'; 255]), cut);
}

#[test]
fn the_rules_that_matched_are_held_to_their_limits() {
    // A block of phase `phase` with this end; `flags` are the VERDICT flags.
    let decode = |phase: u8, flags: u8, end: Vec<u8>| {
        let p = verdict(phase, 1, flags, 0, 1, 403, b"deny", b"");
        decode_verdict(&with_tail(p, &end))
    };
    let phase2 = |flags: u8, end: Vec<u8>| decode(2, flags, end);
    // The limits themselves: 16 ids of the most digits, the flag that says there are more, the lightest severity and
    // the highest score.
    let full = [i64::MAX; matched::MAX_RULE_IDS];
    let got = phase2(FLAG_MORE_RULES, tail(&full, 7, i32::MAX)).unwrap();
    assert_eq!(got.matched, matched(&full, true, 7, i32::MAX));
    assert_eq!(got.matched.ids(), full);
    // A full list needs no flag; the heaviest severity, no severity and no score are values too.
    assert!(phase2(0, tail(&full, 0, 0)).is_ok());
    assert!(phase2(0, tail(&[1], 255, -1)).is_ok());
    // One past each limit: a list of 17, the id 0 (and a negative one), the flag with a list of 15, the severities
    // 8 and 254, and the scores -2 and the lowest.
    let count = "verdict rule count out of range";
    assert_eq!(reason(phase2(0, tail(&[1; 17], 2, 5))), count);
    for id in [0, -1] {
        let why = "verdict rule id out of range";
        assert_eq!(reason(phase2(0, tail(&[1, id], 2, 5))), why);
    }
    let why = "verdict more flag needs a full list of rule ids";
    assert_eq!(
        reason(phase2(FLAG_MORE_RULES, tail(&full[..15], 2, 5))),
        why
    );
    for severity in [8, 254] {
        let why = "verdict severity out of range";
        assert_eq!(reason(phase2(0, tail(&[1], severity, 5))), why);
    }
    for score in [-2, i32::MIN] {
        let why = "verdict score out of range";
        assert_eq!(reason(phase2(0, tail(&[1], 2, score))), why);
    }
    // The phases 3 and 4 carry the end that says nothing and no other.
    let why = "verdict of a response phase carries rules, a severity or a score";
    for phase in [3, 4] {
        assert_eq!(
            decode(phase, 0, NO_TAIL.to_vec()).unwrap().matched,
            Matched::NONE
        );
        for end in [tail(&[1], 255, -1), tail(&[], 0, -1), tail(&[], 255, 0)] {
            assert_eq!(reason(decode(phase, 0, end)), why, "phase {phase}");
        }
    }
}

#[test]
fn error_rejects_out_of_range_values_with_the_matching_reason() {
    // Class 1 has the codes 1..=4 and class 2 the codes 16..=31; the text has at most 256 bytes.
    for (class, code) in [(1, 1), (1, 4), (2, 16), (2, 31)] {
        let e = decode_error(&errmsg(class, 0, code, &[b't'; 256])).unwrap();
        assert_eq!((e.code, e.text.len()), (code, MAX_ERR_MSG));
    }
    let bad = |p: Vec<u8>| reason(decode_error(&p));
    for (class, code) in [(1, 0), (1, 5), (1, 16), (2, 4), (2, 15), (2, 32)] {
        assert_eq!(
            bad(errmsg(class, 0, code, b"")),
            "error code out of range for its class",
            "{class}/{code}"
        );
    }
    for class in [0, 3] {
        assert_eq!(bad(errmsg(class, 0, 1, b"")), "error class out of range");
    }
    assert_eq!(bad(errmsg(1, 1, 1, b"")), "error reserved not zero");
    assert_eq!(
        bad(errmsg(2, 0, 17, &[b't'; 257])),
        "string length out of range"
    );
}

#[test]
fn hello_accepts_the_string_boundaries_and_rejects_the_rest() {
    let s = |n: usize| vec![b'x'; n];
    let lens = |go, coraza, sum| decode_hello(&hello(1, &s(go), &s(coraza), &s(sum)));
    let h = lens(64, 64, 128).unwrap();
    let got = (
        h.go_version.len(),
        h.coraza_version.len(),
        h.coraza_sum.len(),
    );
    assert_eq!(got, (64, 64, 128));
    for (go, coraza, sum) in [(0, 1, 1), (65, 1, 1), (1, 65, 1), (1, 1, 0), (1, 1, 129)] {
        let why = "string length out of range";
        assert_eq!(reason(lens(go, coraza, sum)), why, "{go} {coraza} {sum}");
    }
    let why = "hello contract version is not v1";
    for version in [0, 2] {
        assert_eq!(reason(decode_hello(&hello(version, b"g", b"v", b"s"))), why);
    }
}

#[test]
fn a_hello_of_version_0_is_refused() {
    // The frame is good, the version is not: the bytes of a v0 inspector.
    let bytes: Vec<u8> = (0..HELLO_V0.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&HELLO_V0[i..i + 2], 16).expect("hex digits"))
        .collect();
    assert_eq!(&bytes[HEADER_LEN..HEADER_LEN + 2], [0, 0]);
    let (h, p) = read_frame(&mut &bytes[..], RUN, INC).unwrap();
    assert_eq!(h, hdr(KIND_HELLO, 111, 0, 0));
    assert_eq!(reason(decode_hello(&p)), "hello contract version is not v1");
    // The same payload with the version 0001 is the HELLO of the golden file.
    let mut v1 = p;
    v1[1] = 1;
    assert_eq!(v1, golden_payload("hello"));
    assert!(decode_hello(&v1).is_ok());
}

#[test]
fn closed_and_bye_need_their_exact_lengths_and_values() {
    assert_eq!(
        (decode_closed(&[0]), decode_closed(&[1])),
        (Ok(false), Ok(true))
    );
    for p in [&[2u8][..], &[], &[0, 0]] {
        assert!(decode_closed(p).is_err(), "{p:?}");
    }
    let ones = 0x0101_0101_0101_0101;
    let bye = Bye {
        started: ones,
        closed: ones,
        close_errors: ones,
    };
    assert_eq!(decode_bye(&[1u8; 24]), Ok(bye));
    for n in [0, 23, 25] {
        assert!(decode_bye(&vec![1u8; n]).is_err(), "len {n}");
    }
}

// ---- encoders: boundaries ----

fn begin<'a>() -> TxBegin<'a> {
    TxBegin {
        client_addr: b"127.0.0.1",
        client_port: 40000,
        server_addr: b"127.0.0.1",
        server_port: 8080,
        method: b"POST",
        uri: b"/a?q=1",
        proto: b"HTTP/1.1",
        declared: 5,
        headers: &[],
    }
}

/// `begin()` with one of its five strings replaced.
fn with_item<'a>(field: &str, bytes: &'a [u8]) -> TxBegin<'a> {
    let mut t = begin();
    match field {
        "client_addr" => t.client_addr = bytes,
        "server_addr" => t.server_addr = bytes,
        "method" => t.method = bytes,
        "uri" => t.uri = bytes,
        "proto" => t.proto = bytes,
        _ => panic!("no such item: {field}"),
    }
    t
}

/// Accepted by the encoder and then by the frame check that repeats Go's rules (`encode_frame`).
fn accept_begin(t: &TxBegin) {
    let p = encode_tx_begin(t).unwrap_or_else(|e| panic!("{e:?}: {t:?}"));
    encode_frame(KIND_TX_BEGIN, 0, RUN, INC, 0x10, 1, &p)
        .unwrap_or_else(|e| panic!("{e:?}: {t:?}"));
}

fn reject_begin(t: &TxBegin, why: &str) {
    assert_eq!(reason(encode_tx_begin(t)), why);
}

#[test]
fn tx_begin_item_boundaries() {
    let items = [
        ("client_addr", 64, "client address length out of range"),
        ("server_addr", 64, "server address length out of range"),
        ("method", 32, "method length out of range"),
        ("uri", 4096, "uri length out of range"),
        ("proto", 16, "protocol length out of range"),
    ];
    for (field, max, why) in items {
        // The shortest and the longest are accepted; 0, one more, and a length that wraps a u16 (65537 is 1) are not.
        for n in [1, max] {
            accept_begin(&with_item(field, &vec![b'x'; n]));
        }
        for n in [0, max + 1, 65537] {
            reject_begin(&with_item(field, &vec![b'x'; n]), why);
        }
    }
    // Declared 0..=1 MiB.
    accept_begin(&TxBegin {
        declared: MAX_DECLARED,
        ..begin()
    });
    let over = TxBegin {
        declared: MAX_DECLARED + 1,
        ..begin()
    };
    reject_begin(&over, "declared body length out of range");
    // Bytes that are not UTF-8 are not converted, trimmed or normalised.
    let uri = TxBegin {
        uri: &[0xc3, 0x28, b' '],
        ..begin()
    };
    let p = encode_tx_begin(&uri).unwrap();
    assert!(p.windows(5).any(|w| w == [0, 3, 0xc3, 0x28, b' ']));
}

#[test]
fn tx_begin_header_boundaries() {
    let ok = |hs: &[(&[u8], &[u8])]| {
        accept_begin(&TxBegin {
            headers: hs,
            ..begin()
        })
    };
    let bad = |hs: &[(&[u8], &[u8])], why| {
        reject_begin(
            &TxBegin {
                headers: hs,
                ..begin()
            },
            why,
        )
    };
    let (n256, n257, v4096, v4097) = (
        vec![b'n'; 256],
        vec![b'n'; 257],
        vec![b'v'; 4096],
        vec![b'v'; 4097],
    );
    ok(&[]);
    ok(&vec![(&b"n"[..], &b"v"[..]); 64]);
    bad(
        &vec![(&b"n"[..], &b"v"[..]); 65],
        "header count out of range",
    );
    // Names 1..=256, values 0..=4096; a length that wraps a u16 is refused, not truncated.
    ok(&[(&n256, b"")]);
    ok(&[(b"n", &v4096)]);
    ok(&[(b"n", b"")]);
    bad(&[(&n257, b"")], "header name length out of range");
    bad(&[(b"", b"v")], "header name length out of range");
    bad(&[(b"n", &v4097)], "header value length out of range");
    bad(
        &[(b"n", &vec![b'v'; 65537])],
        "header value length out of range",
    );
    // The name + value total: 6 x (256 + 3840) is 24 KiB exactly, one more byte is over it.
    let v3840 = vec![b'v'; 3840];
    let mut hs = vec![(&n256[..], &v3840[..]); 6];
    ok(&hs);
    hs.push((b"x", b""));
    bad(&hs, "header total length out of range");
}

#[test]
fn encode_frame_length_and_id_boundaries() {
    let f = |kind, tx, msg, payload: &[u8]| {
        encode_frame(kind, 0, RUN, INC, tx, msg, payload).map_err(|e| e.0)
    };
    let length = Err("payload length out of range");
    // BODY: 1..=64 KiB; the empty kinds take no payload.
    assert_eq!(f(KIND_BODY, 0x10, 2, b""), length);
    assert_eq!(
        f(KIND_BODY, 0x10, 2, &[7u8; 65536]).unwrap().len(),
        HEADER_LEN + 65536
    );
    assert_eq!(f(KIND_BODY, 0x10, 2, &[7u8; 65537]), length);
    assert_eq!(f(KIND_BODY_END, 0x10, 3, b"x"), length);
    // TX_BEGIN: up to 32 KiB by length, then by content. TX_END: up to 8 by length, then exactly one byte 1..=5.
    assert_eq!(
        f(KIND_TX_BEGIN, 0x10, 1, &vec![0u8; MAX_TX_BEGIN + 1]),
        length
    );
    assert!(f(KIND_TX_BEGIN, 0x10, 1, &vec![0u8; MAX_TX_BEGIN]).is_err());
    assert_eq!(f(KIND_TX_END, 0x10, 7, &[1; 9]), length);
    assert!(f(KIND_TX_END, 0x10, 7, &[1; 8]).is_err());
    // Control has tx = msg = 0; the others have both nonzero.
    assert_eq!(
        f(KIND_DRAIN, 1, 0, b""),
        Err("control frame with tx or msg")
    );
    for (tx, msg) in [(0, 1), (0x10, 0)] {
        let why = "transaction frame with zero tx or msg";
        assert_eq!(f(KIND_BODY_END, tx, msg, b""), Err(why));
    }
    assert!(f(KIND_BODY_END, u64::MAX, u32::MAX, b"").is_ok());
}

#[test]
fn begin_payloads_go_would_reject_are_rejected() {
    let send = |msg, payload: &[u8]| {
        encode_frame(KIND_TX_BEGIN, 0, RUN, INC, 0x10, msg, payload).map_err(|e| e.0)
    };
    let good = encode_tx_begin(&begin()).unwrap();
    assert!(send(1, &good).is_ok());
    // Go does not create a transaction for another message number.
    assert_eq!(send(2, &good), Err("tx_begin message number is not 1"));
    // A cut at any length, and one trailing byte.
    for n in 0..good.len() {
        assert!(send(1, &good[..n]).is_err(), "cut to {n}");
    }
    let extra = [&good[..], &[0]].concat();
    assert_eq!(send(1, &extra), Err("trailing bytes in payload"));
    // Written by hand: the declared length (8 bytes before the header count) over the limit.
    let n = good.len();
    let mut over = good.clone();
    over[n - 10..n - 2].copy_from_slice(&(MAX_DECLARED + 1).to_be_bytes());
    assert_eq!(send(1, &over), Err("declared body length out of range"));
}

// ---- check_hello ----

const NONCE: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const PID: u32 = 4242;
const RULES: [u8; 32] = [7; 32];
const MEM: u64 = 256 << 20;

type Mutation = (&'static str, fn(&mut Hello));

fn good_hello() -> Hello {
    Hello {
        version: 1,
        pid: PID,
        nonce: NONCE,
        run: RUN,
        inc: INC,
        go_version: INSPECTOR_GO_VERSION.to_vec(),
        coraza_version: INSPECTOR_CORAZA_VERSION.to_vec(),
        coraza_sum: INSPECTOR_CORAZA_SUM.to_vec(),
        rules_sha256: RULES,
        body_limit: MAX_DECLARED as u32,
        mem_limit: MEM,
        gomaxprocs: 1,
        tx_limit: MAX_CONCUR_TX,
        queue: QUEUE_DEPTH,
    }
}

fn checked(h: &Hello) -> Result<(), &'static str> {
    let expect = HelloExpect {
        rules_sha256: &RULES,
        mem_limit: MEM,
        gomaxprocs: 1,
    };
    check_hello(h, &expect, RUN, INC, PID, &NONCE)
}

#[test]
fn hello_matches_and_every_field_is_checked() {
    assert_eq!(checked(&good_hello()), Ok(()));
    let one: [Mutation; 14] = [
        ("hello contract version is not v1", |h| h.version = 0),
        ("hello pid is not the child's pid", |h| h.pid += 1),
        ("hello nonce differs", |h| h.nonce[15] ^= 1),
        ("hello run id differs", |h| h.run += 1),
        ("hello incarnation differs", |h| h.inc += 1),
        ("hello go version differs", |h| {
            h.go_version = b"go1.27.1".to_vec()
        }),
        ("hello coraza version differs", |h| {
            h.coraza_version = b"v3.8.0".to_vec()
        }),
        ("hello coraza sum differs", |h| h.coraza_sum.push(b'x')),
        ("hello rules sha256 differs", |h| h.rules_sha256[31] ^= 1),
        ("hello body limit differs", |h| h.body_limit -= 1),
        ("hello memory limit differs", |h| h.mem_limit = 0),
        ("hello gomaxprocs differs", |h| h.gomaxprocs += 1),
        ("hello transaction limit differs", |h| h.tx_limit += 1),
        ("hello queue depth differs", |h| h.queue += 1),
    ];
    for (want, m) in one {
        let mut h = good_hello();
        m(&mut h);
        assert_eq!(checked(&h), Err(want));
    }
}
