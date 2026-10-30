use super::*;
use crate::testkit::{INC, RUN, begin_with, golden, golden_names, header_bytes, inbound, out};

// The vectors of the golden file by direction. Every name of the file is in one of the three lists.
const SENT: [&str; 13] = [
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
const RECEIVED: [&str; 9] = [
    "tx_begin",
    "tx_begin_cut",
    "body",
    "body_end",
    "resp_begin",
    "resp_body",
    "resp_end",
    "tx_end",
    "drain",
];
const REFUSED: [&str; 7] = [
    "bad_verdict_rules_17",
    "bad_verdict_more_short",
    "bad_verdict_severity",
    "bad_verdict_score",
    "bad_verdict_rule_id",
    "bad_verdict_rules_phase",
    "bad_verdict_no_tail",
];

fn detail(ids: &[i64], severity: u8, score: i32) -> RuleDetail {
    RuleDetail {
        ids: ids.to_vec(),
        more: false,
        severity,
        score,
    }
}

fn verdict(
    msg: u32,
    phase: u8,
    decision: Decision,
    (rule_id, status): (i64, i32),
    (action, data): (&[u8], &[u8]),
    rules: &RuleDetail,
) -> Vec<u8> {
    let v = Verdict {
        decision,
        rule_id,
        status,
        action,
        data,
        rules,
    };
    encode_verdict(RUN, INC, 0x10, msg, phase, &v).unwrap()
}

#[test]
fn every_vector_of_the_golden_file_is_tried() {
    let mut all: Vec<&str> = [SENT.as_slice(), &RECEIVED, &REFUSED].concat();
    let mut names = golden_names();
    all.sort_unstable();
    names.sort_unstable();
    assert_eq!(names, all);
}

#[test]
fn what_the_inspector_sends_is_byte_identical_to_the_golden_vectors() {
    let nothing: (&[u8], &[u8]) = (b"", b"");
    let deny: &[u8] = b"deny";
    let mut nonce = [0u8; 16];
    for (i, b) in nonce.iter_mut().enumerate() {
        *b = u8::try_from(i).unwrap();
    }
    let mut sha = [0u8; 32];
    for (i, b) in sha.iter_mut().enumerate() {
        *b = 0xa0 + u8::try_from(i).unwrap();
    }
    let hello = encode_hello(
        RUN,
        INC,
        &Hello {
            pid: 4242,
            nonce,
            toolchain: b"go1.27.2",
            engine_version: b"v3.8.1",
            engine_source: b"h1:abc=",
            rules_sha256: sha,
            mem_limit: 268_435_456,
            gomaxprocs: 2,
        },
    )
    .unwrap();
    let many: Vec<i64> = (930_100..930_116).collect();
    let more = RuleDetail {
        more: true,
        ..detail(&many, 2, 80)
    };
    let long_action = vec![b'a'; 33];
    let long_data = vec![b'd'; 300];
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("hello", hello),
        (
            "verdict_continue",
            verdict(1, 1, Decision::Continue, (0, 0), nothing, &RuleDetail::NONE),
        ),
        (
            "verdict_block",
            verdict(
                2,
                2,
                Decision::Block,
                (1021, 403),
                (deny, b"x"),
                &detail(&[942_100], 2, 5),
            ),
        ),
        (
            "verdict_block_rule0",
            verdict(
                3,
                2,
                Decision::Block,
                (0, 413),
                (deny, b""),
                &RuleDetail::NONE,
            ),
        ),
        (
            "verdict_truncated",
            verdict(
                6,
                4,
                Decision::Block,
                (1040, 403),
                (&long_action, &long_data),
                &RuleDetail::NONE,
            ),
        ),
        (
            "verdict_detected",
            verdict(
                4,
                2,
                Decision::Detected,
                (949_110, 403),
                (deny, b""),
                &detail(&[942_100, 941_100], 2, 10),
            ),
        ),
        (
            "verdict_allow_rules",
            verdict(
                5,
                2,
                Decision::Continue,
                (0, 0),
                nothing,
                &detail(&[920_280, 942_100, 7_000_005], 5, 0),
            ),
        ),
        (
            "verdict_rules_more",
            verdict(7, 2, Decision::Block, (949_110, 403), (deny, b""), &more),
        ),
        (
            "verdict_rules_severity",
            verdict(
                8,
                1,
                Decision::Block,
                (7_000_006, 403),
                (deny, b""),
                &detail(&[], 3, -1),
            ),
        ),
        (
            "error_not_created",
            encode_error(
                RUN,
                INC,
                0x11,
                1,
                CLASS_NOT_CREATED,
                CODE_LIMIT,
                "concurrency limit",
            ),
        ),
        (
            "error_tx_failed",
            encode_error(
                RUN,
                INC,
                0x10,
                3,
                CLASS_TX_FAILED,
                CODE_REQ_TRUNCATED,
                "request body shorter than declared",
            ),
        ),
        ("closed", encode_closed(RUN, INC, 0x10, 7, false)),
        ("bye", encode_bye(RUN, INC, 3, 3, 0)),
    ];
    let names: Vec<&str> = cases.iter().map(|(name, _)| *name).collect();
    assert_eq!(names, SENT);
    for (name, got) in cases {
        assert_eq!(got, golden(name), "{name}");
    }
}

/// The header of a golden vector, as `check_header` reads it.
fn golden_header(name: &str) -> Result<Header, ConnError> {
    let g = golden(name);
    let b: [u8; HEADER_LEN] = g[..HEADER_LEN].try_into().unwrap();
    check_header(&b, RUN, INC)
}

#[test]
fn what_the_kernel_sends_is_read_and_the_response_kinds_are_refused() {
    for name in [
        "tx_begin",
        "tx_begin_cut",
        "body",
        "body_end",
        "tx_end",
        "drain",
    ] {
        let h = golden_header(name).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(h.len as usize, golden(name).len() - HEADER_LEN, "{name}");
    }
    let g = golden("tx_begin");
    let begin = decode_tx_begin(&g[HEADER_LEN..], false).unwrap();
    assert_eq!(begin.client_addr, b"127.0.0.1");
    assert_eq!(begin.client_port, 40000);
    assert_eq!(begin.server_addr, b"127.0.0.1");
    assert_eq!(begin.server_port, 8080);
    assert_eq!(
        (begin.method, begin.uri, begin.proto),
        (&b"POST"[..], &b"/a?q=1"[..], &b"HTTP/1.1"[..])
    );
    assert_eq!(begin.declared, 5);
    assert_eq!(
        begin.headers,
        [
            (&b"Host"[..], &b"example.test"[..]),
            (
                &b"Content-Type"[..],
                &b"application/x-www-form-urlencoded"[..]
            )
        ]
    );
    // The cut body is the same payload with the header flag.
    assert!(!golden_header("tx_begin").unwrap().cut);
    assert!(golden_header("tx_begin_cut").unwrap().cut);
    assert_eq!(g[HEADER_LEN..], golden("tx_begin_cut")[HEADER_LEN..]);
    assert_eq!(decode_tx_end(&golden("tx_end")[HEADER_LEN..]), Ok(1));
    for (name, kind) in [
        ("resp_begin", KIND_RESP_BEGIN),
        ("resp_body", KIND_RESP_BODY),
        ("resp_end", KIND_RESP_END),
    ] {
        assert_eq!(golden_header(name), Err(ConnError::Unsupported(kind)));
    }
}

/// The values in the payload of a VERDICT, read without any check of their range.
struct Parsed {
    phase: u8,
    decision: Decision,
    rule_id: i64,
    status: i32,
    action: Vec<u8>,
    data: Vec<u8>,
    rules: RuleDetail,
}

fn parse_verdict(p: &[u8]) -> Option<Parsed> {
    let mut c = Cursor { p };
    let [phase] = c.array().ok()?;
    let [block] = c.array().ok()?;
    let [flags] = c.array().ok()?;
    let [_reserved] = c.array::<1>().ok()?;
    let rule_id = i64::from_be_bytes(c.array().ok()?);
    let status = i32::from(c.u16().ok()?);
    let action = c.str16(0, 0xffff).ok()?.to_vec();
    let data = c.str16(0, 0xffff).ok()?.to_vec();
    let [count] = c.array().ok()?;
    let mut ids = Vec::new();
    for _ in 0..count {
        ids.push(i64::from_be_bytes(c.array().ok()?));
    }
    let [severity] = c.array().ok()?;
    let score = i32::from_be_bytes(c.array().ok()?);
    c.done().ok()?;
    let decision = if flags & FLAG_DETECTED != 0 {
        Decision::Detected
    } else if block == 1 {
        Decision::Block
    } else {
        Decision::Continue
    };
    let rules = RuleDetail {
        ids,
        more: flags & FLAG_MORE_RULES != 0,
        severity,
        score,
    };
    Some(Parsed {
        phase,
        decision,
        rule_id,
        status,
        action,
        data,
        rules,
    })
}

#[test]
fn every_refused_vector_is_refused() {
    for name in REFUSED {
        // The frame is a good one but for the one thing that its name says; a VERDICT is not a frame
        // that the inspector takes.
        assert_eq!(
            golden_header(name),
            Err(ConnError::WrongDirection(KIND_VERDICT)),
            "{name}"
        );
        // The values in it cannot be written by the encoder. The last one has no end of the VERDICT to read.
        let parsed = parse_verdict(&golden(name)[HEADER_LEN..]);
        let Some(p) = parsed else {
            assert_eq!(name, "bad_verdict_no_tail");
            continue;
        };
        let v = Verdict {
            decision: p.decision,
            rule_id: p.rule_id,
            status: p.status,
            action: &p.action,
            data: &p.data,
            rules: &p.rules,
        };
        assert!(
            encode_verdict(RUN, INC, 1, 1, p.phase, &v).is_err(),
            "{name}"
        );
    }
}

#[test]
fn the_header_limits_hold_at_the_limit_and_one_past_it() {
    let check = |kind: u8, len: usize| {
        let (tx, msg) = if kind == KIND_DRAIN { (0, 0) } else { (1, 1) };
        check_header(
            &header_bytes(kind, 0, u32::try_from(len).unwrap(), tx, msg),
            RUN,
            INC,
        )
    };
    for (kind, limit) in [
        (KIND_DRAIN, 0),
        (KIND_BODY_END, 0),
        (KIND_TX_BEGIN, MAX_TX_BEGIN),
        (KIND_BODY, MAX_BODY),
        (KIND_TX_END, MAX_TX_END),
    ] {
        assert!(check(kind, limit).is_ok(), "kind {kind:#x} at {limit}");
        assert_eq!(
            check(kind, limit + 1),
            Err(ConnError::TooLong {
                kind,
                len: u32::try_from(limit + 1).unwrap()
            })
        );
    }
}

#[test]
fn a_header_that_breaks_the_protocol_is_refused() {
    let ok = header_bytes(KIND_BODY, 0, 3, 1, 2);
    let with = |f: &dyn Fn(&mut [u8; HEADER_LEN])| {
        let mut b = ok;
        f(&mut b);
        check_header(&b, RUN, INC)
    };
    assert!(check_header(&ok, RUN, INC).is_ok());
    assert_eq!(with(&|b| b[3] = b'1'), Err(ConnError::BadMagic));
    assert_eq!(with(&|b| b[5] = 1), Err(ConnError::Flags(1)));
    assert_eq!(with(&|b| b[7] = 1), Err(ConnError::Reserved(1)));
    assert_eq!(with(&|b| b[4] = 0x7f), Err(ConnError::UnknownKind(0x7f)));
    assert_eq!(
        with(&|b| b[4] = KIND_HELLO),
        Err(ConnError::WrongDirection(KIND_HELLO))
    );
    assert_eq!(with(&|b| b[19] ^= 1), Err(ConnError::RunMismatch(RUN ^ 1)));
    assert_eq!(with(&|b| b[23] ^= 1), Err(ConnError::IncMismatch(INC ^ 1)));
    assert_eq!(with(&|b| b[31] = 0), Err(ConnError::ZeroIds));
    assert_eq!(with(&|b| b[35] = 0), Err(ConnError::ZeroIds));
    // Only a TX_BEGIN may have a flag, and only the cut flag.
    assert_eq!(
        with(&|b| {
            b[4] = KIND_TX_BEGIN;
            b[5] = 2;
        }),
        Err(ConnError::Flags(2))
    );
    assert!(
        with(&|b| {
            b[4] = KIND_TX_BEGIN;
            b[5] = FLAG_BODY_CUT;
        })
        .is_ok_and(|h| h.cut)
    );
    // A control frame has no transaction and no message number.
    let drain = header_bytes(KIND_DRAIN, 0, 0, 1, 0);
    assert_eq!(check_header(&drain, RUN, INC), Err(ConnError::ControlIds));
}

#[test]
fn a_long_header_is_refused_before_the_payload_is_read() {
    // A header that announces 4 GiB is refused after exactly 36 bytes; the reader has more than that.
    struct Counting<'a>(&'a [u8], usize);
    impl Read for Counting<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.0.read(buf)?;
            self.1 += n;
            Ok(n)
        }
    }
    let mut bytes = header_bytes(KIND_BODY, 0, 0, 1, 2).to_vec();
    bytes[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
    bytes.extend_from_slice(&[0; 100]);
    let mut r = Counting(&bytes, 0);
    assert_eq!(
        read_frame(&mut r, RUN, INC).unwrap_err(),
        ConnError::TooLong {
            kind: KIND_BODY,
            len: u32::MAX
        }
    );
    assert_eq!(r.1, HEADER_LEN);
    // The end of the connection before a frame, and in the middle of one.
    assert_eq!(
        read_frame(&mut &b""[..], RUN, INC).unwrap_err(),
        ConnError::PeerClosed
    );
    let whole = inbound(KIND_BODY, 0, 1, 2, b"abc");
    assert_eq!(
        read_frame(&mut &whole[..whole.len() - 1], RUN, INC).unwrap_err(),
        ConnError::Truncated { got: 2, want: 3 }
    );
    assert_eq!(
        read_frame(&mut &whole[..], RUN, INC).unwrap().1,
        b"abc".to_vec()
    );
}

#[test]
fn tx_begin_is_taken_at_its_limits_and_not_past_them() {
    let rep = |c: u8, n: usize| vec![c; n];
    let build = |uri: &[u8], headers: &[(Vec<u8>, Vec<u8>)], declared: u64| {
        let headers: Vec<(&[u8], &[u8])> = headers
            .iter()
            .map(|(n, v)| (n.as_slice(), v.as_slice()))
            .collect();
        begin_with(b"POST", uri, &headers, declared)
    };
    let ok = |p: &[u8]| decode_tx_begin(p, false).is_ok();
    let header = |n: usize| (b"n".to_vec(), rep(b'v', n));
    assert!(ok(&build(&rep(b'u', MAX_URI), &[], 0)));
    assert!(!ok(&build(&rep(b'u', MAX_URI + 1), &[], 0)));
    // The method and the URI have at least one byte.
    assert!(ok(&begin_with(b"G", b"/", &[], 0)));
    assert!(!ok(&begin_with(b"", b"/", &[], 0)));
    assert!(!ok(&begin_with(b"G", b"", &[], 0)));
    assert!(ok(&build(b"/", &vec![header(1); MAX_HEADERS], 0)));
    assert!(!ok(&build(b"/", &vec![header(1); MAX_HEADERS + 1], 0)));
    // Six headers of 256 + 3840 bytes are exactly the total that is allowed.
    let six = vec![
        (
            rep(b'n', MAX_HDR_NAME),
            rep(b'v', MAX_HDR_TOTAL / 6 - MAX_HDR_NAME)
        );
        6
    ];
    assert!(ok(&build(b"/", &six, 0)));
    let mut seven = six.clone();
    seven.push((b"x".to_vec(), Vec::new()));
    assert!(!ok(&build(b"/", &seven, 0)));
    assert!(ok(&build(b"/", &[], MAX_DECLARED)));
    assert!(!ok(&build(b"/", &[], MAX_DECLARED + 1)));
    // A cut body has declared bytes; the payload ends where it ends.
    assert!(decode_tx_begin(&build(b"/", &[], 1), true).is_ok());
    assert!(decode_tx_begin(&build(b"/", &[], 0), true).is_err());
    let mut longer = build(b"/", &[], 0);
    longer.push(0);
    assert_eq!(
        decode_tx_begin(&longer, false),
        Err(ContentError("trailing bytes in payload"))
    );
}

#[test]
fn a_verdict_is_written_within_its_range_and_cut_at_its_limits() {
    let write = |phase: u8, v: &Verdict<'_>| encode_verdict(RUN, INC, 1, 1, phase, v);
    let block = |status: i32, action: &'static [u8], rules: &RuleDetail| {
        let v = Verdict {
            decision: Decision::Block,
            rule_id: -7,
            status,
            action,
            data: b"",
            rules,
        };
        write(2, &v)
    };
    let none = RuleDetail::NONE;
    assert!(block(65535, b"deny", &none).is_ok());
    assert!(block(65536, b"deny", &none).is_err());
    assert!(block(-1, b"deny", &none).is_err());
    // 16 rule ids, with or without the mark that there are more; not 17, and not the mark with 15.
    let ids = |n: i64| (930_100..930_100 + n).collect::<Vec<_>>();
    let with = |n: i64, more: bool| RuleDetail {
        ids: ids(n),
        more,
        ..detail(&[], 2, 80)
    };
    assert!(block(403, b"", &with(16, false)).is_ok());
    assert!(block(403, b"", &with(16, true)).is_ok());
    assert!(block(403, b"", &with(17, false)).is_err());
    assert!(block(403, b"", &with(15, true)).is_err());
    // Severity 7 and 8, a score of 0 and of -2, and an id of 1 and of 0.
    assert!(block(403, b"", &detail(&[], 7, 0)).is_ok());
    assert!(block(403, b"", &detail(&[], 8, 0)).is_err());
    assert!(block(403, b"", &detail(&[], 2, -2)).is_err());
    assert!(block(403, b"", &detail(&[1], 2, 0)).is_ok());
    assert!(block(403, b"", &detail(&[1, 0], 2, 0)).is_err());
    // A response phase carries nothing; a continue carries no fields; a detection is a continue of phase 2.
    let one = detail(&[1], 2, 0);
    let v = |decision: Decision, rule_id: i64, rules: &'static RuleDetail| Verdict {
        decision,
        rule_id,
        status: 0,
        action: b"",
        data: b"",
        rules,
    };
    static NONE: RuleDetail = RuleDetail::NONE;
    assert!(write(3, &v(Decision::Continue, 0, &NONE)).is_ok());
    assert!(
        write(
            3,
            &Verdict {
                rules: &one,
                ..v(Decision::Continue, 0, &NONE)
            }
        )
        .is_err()
    );
    assert!(write(2, &v(Decision::Continue, 5, &NONE)).is_err());
    assert!(write(2, &v(Decision::Detected, 5, &NONE)).is_ok());
    assert!(write(1, &v(Decision::Detected, 5, &NONE)).is_err());
    assert!(write(0, &v(Decision::Continue, 0, &NONE)).is_err());
    assert!(write(5, &v(Decision::Continue, 0, &NONE)).is_err());
    // An action of 33 bytes and a data of 257 are cut to 32 and 256 with their flags.
    let (action, data) = (vec![b'a'; MAX_ACTION + 1], vec![b'd'; MAX_DATA + 1]);
    let cut = write(
        2,
        &Verdict {
            decision: Decision::Block,
            rule_id: 1,
            status: 403,
            action: &action,
            data: &data,
            rules: &none,
        },
    )
    .unwrap();
    let parsed = parse_verdict(&out(&cut).payload).unwrap();
    assert_eq!(
        (parsed.action.len(), parsed.data.len()),
        (MAX_ACTION, MAX_DATA)
    );
    assert_eq!(
        out(&cut).payload[2],
        FLAG_ACTION_TRUNCATED | FLAG_DATA_TRUNCATED
    );
}

#[test]
fn a_hello_and_an_error_text_are_bounded() {
    let hello = |toolchain: &[u8], version: &[u8], source: &[u8]| {
        encode_hello(
            RUN,
            INC,
            &Hello {
                pid: 1,
                nonce: [0; 16],
                toolchain,
                engine_version: version,
                engine_source: source,
                rules_sha256: [0; 32],
                mem_limit: 0,
                gomaxprocs: 1,
            },
        )
    };
    assert!(hello(&[b'a'; 64], &[b'b'; 64], &[b'c'; 128]).is_ok());
    assert!(hello(&[b'a'; 65], b"v", b"s").is_err());
    assert!(hello(b"t", &[b'b'; 65], b"s").is_err());
    assert!(hello(b"t", b"v", &[b'c'; 129]).is_err());
    assert!(hello(b"", b"v", b"s").is_err());
    // The text of an ERROR is cut at MAX_ERR_MSG, and the frame stays within MAX_ERROR.
    static LONG: &str = concat!(
        "0123456789012345678901234567890123456789012345678901234567890123",
        "0123456789012345678901234567890123456789012345678901234567890123",
        "0123456789012345678901234567890123456789012345678901234567890123",
        "0123456789012345678901234567890123456789012345678901234567890123",
        "0123456789"
    );
    let e = encode_error(RUN, INC, 1, 1, CLASS_TX_FAILED, CODE_ORDER, LONG);
    assert_eq!(e.len() - HEADER_LEN, 4 + 2 + MAX_ERR_MSG);
    assert!(e.len() - HEADER_LEN <= MAX_ERROR);
    // CLOSED and BYE are far inside their limits.
    assert!(encode_closed(RUN, INC, 1, 1, true).len() - HEADER_LEN <= MAX_CLOSED);
    assert!(encode_bye(RUN, INC, 1, 1, 1).len() - HEADER_LEN <= MAX_BYE);
}
