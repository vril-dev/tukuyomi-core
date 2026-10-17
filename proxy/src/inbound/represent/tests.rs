use flate2::Compression;
use flate2::write::GzEncoder;
use std::io::Write;

use super::*;
use crate::inbound::answer::Class;
use crate::inbound::conn::tests::{FORM, gz, pair};
use crate::inbound::head::{self, Limits};

const LIM: Limits = Limits {
    max_head_bytes: 32 * 1024,
    max_body: 1 << 20,
};

pub(in crate::inbound) fn head_of(raw: &str) -> Head {
    head::parse(raw.as_bytes(), &LIM)
        .expect("accepted")
        .expect("complete")
}

fn represented(raw: &str, body_len: usize) -> Represented {
    represent(&head_of(raw), body_len).expect("represented")
}

fn pairs(rep: &Represented) -> Vec<(String, String)> {
    rep.headers
        .iter()
        .map(|(name, value)| {
            (
                String::from_utf8_lossy(name).into_owned(),
                String::from_utf8_lossy(value).into_owned(),
            )
        })
        .collect()
}

#[test]
fn a_chunked_request_loses_its_encoding_and_gets_the_decoded_length() {
    let raw = format!(
        "POST /x HTTP/1.1\r\nContent-Type: {FORM}\r\nHost: h\r\nTransfer-Encoding: chunked\r\nx-forwarded-for: 1.2.3.4\r\n\r\n"
    );
    let rep = represented(&raw, 3);
    assert_eq!(
        pairs(&rep),
        [
            pair("Host", "h"),
            pair("Content-Type", FORM),
            pair("X-Forwarded-For", "1.2.3.4"),
            pair("Content-Length", "3"),
        ]
    );
    assert!(rep.fields.get(TRANSFER_ENCODING).is_none());
    assert_eq!(rep.fields.get_all(CONTENT_LENGTH).iter().count(), 1);
    assert_eq!(rep.fields.get(CONTENT_LENGTH).unwrap(), "3");
    assert_eq!(rep.fields.len(), 4);
}

#[test]
fn a_gzip_request_loses_its_coding_and_gets_the_decoded_length() {
    // The coding and the length are replaced by the decoded length, which comes last as a chunked request's
    // does; the others keep their order.
    let raw = format!(
        "POST /x HTTP/1.1\r\nContent-Type: {FORM}\r\nHost: h\r\nContent-Encoding: gzip\r\nContent-Length: 31\r\nx-forwarded-for: 1.2.3.4\r\n\r\n"
    );
    let rep = represented(&raw, 11);
    let expected = [
        pair("Host", "h"),
        pair("Content-Type", FORM),
        pair("X-Forwarded-For", "1.2.3.4"),
        pair("Content-Length", "11"),
    ];
    assert_eq!(pairs(&rep), expected);
    assert!(rep.fields.get(CONTENT_ENCODING).is_none());
    assert_eq!(rep.fields.get_all(CONTENT_LENGTH).iter().count(), 1);
    assert_eq!(rep.fields.get(CONTENT_LENGTH).unwrap(), "11");
    assert_eq!(rep.fields.len(), 4);
    // Chunked and gzip: both framing fields go and one length comes.
    let raw = format!(
        "POST /x HTTP/1.1\r\nContent-Encoding: gzip\r\nContent-Type: {FORM}\r\nHost: h\r\nTransfer-Encoding: chunked\r\nx-forwarded-for: 1.2.3.4\r\n\r\n"
    );
    assert_eq!(pairs(&represented(&raw, 11)), expected);
}

/// `len` bytes that neither repeat nor compress.
pub(in crate::inbound) fn noise(len: usize) -> Vec<u8> {
    let mut state = 0x2545_f491u32;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            (state >> 24) as u8
        })
        .collect()
}

/// The status and the reason of a body that `gunzip` refuses.
fn gunzip_refusal(coded: &[u8], max: usize) -> (u16, &'static str) {
    let reply = gunzip(coded, max).expect_err("refused");
    assert_eq!(reply.class, Class::Rejected);
    assert!(!reply.internal);
    (reply.status, reply.reason)
}

const MALFORMED: (u16, &str) = (400, "malformed gzip body");
const AFTER: (u16, &str) = (400, "data after the gzip member");
const OVER: (u16, &str) = (413, "decoded body over the limit");

#[test]
fn a_gzip_member_is_decoded() {
    let data = b"probe=block&a=%41&b=";
    assert_eq!(gunzip(&gz(data), 1024).unwrap(), data);
    let mut encoder = GzEncoder::new(Vec::new(), Compression::none());
    encoder.write_all(data).unwrap();
    assert_eq!(gunzip(&encoder.finish().unwrap(), 1024).unwrap(), data);
    // Many blocks: data that does not repeat, longer than the window.
    let long = noise(200_000);
    assert_eq!(gunzip(&gz(&long), long.len()).unwrap(), long);
    // A member of nothing is a body of nothing, not an error.
    assert_eq!(gunzip(&gz(b""), 0).unwrap(), b"");
}

#[test]
fn the_decoded_length_limit_is_exact() {
    for max in [0usize, 1, 1024] {
        let at = vec![b'a'; max];
        assert_eq!(gunzip(&gz(&at), max).unwrap(), at, "max {max}");
        let over = vec![b'a'; max + 1];
        assert_eq!(gunzip_refusal(&gz(&over), max), OVER, "max {max}");
    }
    // A stream that decodes to far more is refused as well: it is not decoded to its end.
    let bomb = gz(&vec![0u8; 4 << 20]);
    assert!(bomb.len() < 16 << 10, "{}", bomb.len());
    assert_eq!(gunzip_refusal(&bomb, 1024), OVER);
    // The limit comes before a fault that is further on: the stream is not read that far.
    let mut broken = gz(&vec![b'a'; 4096]);
    let last = broken.len() - 8;
    broken[last] ^= 1;
    assert_eq!(gunzip_refusal(&broken, 1024), OVER);
    assert_eq!(gunzip_refusal(&broken, 4096), MALFORMED);
}

#[test]
fn a_stream_that_is_not_valid_is_400() {
    let good = gz(b"probe=block&a=%41&b=");
    let mut wrong_magic = good.clone();
    wrong_magic[1] ^= 1;
    for coded in [&b""[..], b"probe=block", &wrong_magic] {
        assert_eq!(gunzip_refusal(coded, 1024), MALFORMED, "{coded:?}");
    }
    // A cut at any place, in the header, in the data and in the trailer, is never a body.
    for cut in 0..good.len() {
        assert_eq!(gunzip_refusal(&good[..cut], 1024), MALFORMED, "cut {cut}");
    }
    // A trailer that does not match: the CRC, and the length.
    for at in [8, 4] {
        let mut bad = good.clone();
        let place = bad.len() - at;
        bad[place] ^= 0x10;
        assert_eq!(
            gunzip_refusal(&bad, 1024),
            MALFORMED,
            "byte {at} from the end"
        );
    }
}

#[test]
fn nothing_may_follow_the_one_member() {
    let data = b"probe=block";
    let good = gz(data);
    let with = |tail: &[u8]| {
        let mut coded = good.clone();
        coded.extend_from_slice(tail);
        coded
    };
    // One byte of anything, padding, and the start of another member.
    for tail in [&b"\0"[..], b"\r\n", &[0u8; 512], &[0x1f, 0x8b]] {
        assert_eq!(gunzip_refusal(&with(tail), 1024), AFTER, "{tail:?}");
    }
    // Two members, whole.
    assert_eq!(gunzip_refusal(&with(&gz(data)), 1024), AFTER);
    assert_eq!(gunzip_refusal(&with(&gz(data)), data.len()), AFTER);
}

#[test]
fn a_post_put_or_patch_without_a_length_gets_content_length_0() {
    for method in ["POST", "PUT", "PATCH"] {
        let rep = represented(&format!("{method} / HTTP/1.1\r\nHost: h\r\n\r\n"), 0);
        assert_eq!(
            pairs(&rep),
            [pair("Host", "h"), pair("Content-Length", "0")],
            "{method}"
        );
    }
    let rep = represented("GET / HTTP/1.1\r\nHost: h\r\n\r\n", 0);
    assert_eq!(pairs(&rep), [pair("Host", "h")]);
    // A request that already has a length keeps its own and gets no second one.
    let rep = represented("POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n", 0);
    assert_eq!(rep.fields.get_all(CONTENT_LENGTH).iter().count(), 1);
}

#[test]
fn names_are_title_case_and_values_stay_as_received() {
    let rep = represented(
        "GET / HTTP/1.1\r\nhost: h\r\nx-a-b: a\tb\r\nACCEPT-ENCODING: gzip\r\nA.b_c-d: \tv \r\n\r\n",
        0,
    );
    assert_eq!(
        pairs(&rep),
        [
            pair("Host", "h"),
            pair("X-A-B", "a\tb"),
            pair("Accept-Encoding", "gzip"),
            pair("A.b_c-D", "v"),
        ]
    );
}

#[test]
fn host_comes_first_and_the_others_keep_the_order_received() {
    let rep = represented(
        "GET / HTTP/1.1\r\na: 1\r\nHost: h\r\nb: 2\r\nA: 3\r\n\r\n",
        0,
    );
    assert_eq!(
        pairs(&rep),
        [
            pair("Host", "h"),
            pair("A", "1"),
            pair("B", "2"),
            pair("A", "3")
        ]
    );
    assert_eq!(rep.fields.len(), 4);
}

pub(in crate::inbound) fn numbered(count: usize, method: &str) -> String {
    let mut raw = format!("{method} / HTTP/1.1\r\nHost: h\r\n");
    for n in 1..count {
        raw.push_str(&format!("X-{n}: v\r\n"));
    }
    raw.push_str("\r\n");
    raw
}

#[test]
fn a_64_field_request_that_gets_content_length_0_is_65_fields_and_refused() {
    let head = head_of(&numbered(64, "POST"));
    assert_eq!(head.fields().len(), 64);
    assert_eq!(represent(&head, 0).err(), Some(Reject::FieldsTooLarge));
    // The same head with a method that gets nothing added, and 63 fields plus the added one, pass.
    assert_eq!(
        represent(&head_of(&numbered(64, "GET")), 0)
            .unwrap()
            .headers
            .len(),
        64
    );
    assert_eq!(
        represent(&head_of(&numbered(63, "POST")), 0)
            .unwrap()
            .headers
            .len(),
        64
    );
}

#[test]
fn the_size_limits_are_checked_after_the_framing_is_added() {
    // The total of names and values is 24576 with the added `Content-Length: 0` (14 + 1 bytes), or 24577.
    let with_last = |last: usize| {
        let mut raw = String::from("POST / HTTP/1.1\r\nHost: example.test\r\n");
        for n in 1..=5 {
            raw.push_str(&format!("F00{n}: {}\r\n", "a".repeat(4096)));
        }
        raw.push_str(&format!("F006: {}\r\n\r\n", "a".repeat(last)));
        raw
    };
    let rep = represent(&head_of(&with_last(4041)), 0).unwrap();
    assert_eq!(rep.field_bytes, limits::HEADER_TOTAL);
    assert_eq!(
        represent(&head_of(&with_last(4042)), 0).err(),
        Some(Reject::FieldsTooLarge)
    );
    // The head itself was within the limits; only the added field is over.
    assert!(
        head::parse(with_last(4042).as_bytes(), &LIM)
            .unwrap()
            .is_some()
    );
}
