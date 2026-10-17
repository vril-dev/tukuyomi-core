use std::convert::Infallible;
use std::time::Duration;

use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio::runtime::{Builder, Runtime};
use tokio::time::timeout;

use super::*;

const LIM: Limits = Limits {
    max_head_bytes: 32 * 1024,
    max_body: 1 << 20,
};
const FORM: &str = "Content-Type: application/x-www-form-urlencoded";
const JSON: &str = "Content-Type: application/json";
const SUFFIXED: &str = "Content-Type: application/vnd.api+json";

/// A GET head with a Host line and then the given lines.
fn head_with(lines: &[&str]) -> Vec<u8> {
    let mut raw = String::from("GET / HTTP/1.1\r\nHost: example.test\r\n");
    for line in lines {
        raw.push_str(line);
        raw.push_str("\r\n");
    }
    raw.push_str("\r\n");
    raw.into_bytes()
}

fn ok(raw: &[u8]) -> Head {
    parse(raw, &LIM).expect("accepted").expect("complete")
}

fn refused(raw: &[u8]) -> Reject {
    parse(raw, &LIM).expect_err("refused")
}

/// A head whose request line is `line` and which is otherwise valid.
fn with_request_line(line: &str) -> Vec<u8> {
    format!("{line}\r\nHost: example.test\r\n\r\n").into_bytes()
}

#[test]
fn a_plain_head_passes_and_gives_its_parts() {
    let mut raw = b"POST /a?b=1 HTTP/1.1\r\nHost: example.test\r\nX-A:\t  v \t\r\n".to_vec();
    raw.extend_from_slice(
        b"Content-Length: 3\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n",
    );
    let head_len = raw.len();
    raw.extend_from_slice(b"a=b");
    let head = ok(&raw);
    assert_eq!(head.len, head_len);
    assert_eq!(&head.buf[..], &raw[..]);
    assert_eq!(head.method(), b"POST");
    assert_eq!(head.target(), b"/a?b=1");
    let fields: Vec<(&[u8], &[u8])> = head.fields().collect();
    assert_eq!(fields.len(), 4);
    assert_eq!(fields[0], (&b"Host"[..], &b"example.test"[..]));
    assert_eq!(fields[1], (&b"X-A"[..], &b"v"[..]));
    assert_eq!(head.content_length(), Some(3));
    assert!(!head.chunked());
    assert!(head.inspectable_type());
}

#[test]
fn a_head_that_is_not_complete_is_not_an_error() {
    assert!(parse(b"", &LIM).unwrap().is_none());
    assert!(parse(b"GET / HTT", &LIM).unwrap().is_none());
    assert!(
        parse(b"GET / HTTP/1.1\r\nHost: a\r\n", &LIM)
            .unwrap()
            .is_none()
    );
    assert!(
        parse(b"GET / HTTP/1.1\r\nHost: a\r\n\r", &LIM)
            .unwrap()
            .is_none()
    );
    assert!(
        parse(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", &LIM)
            .unwrap()
            .is_some()
    );
}

#[test]
fn line_ends_must_be_crlf() {
    assert_eq!(
        refused(b"GET / HTTP/1.1\nHost: a\r\n\r\n"),
        Reject::BadRequest
    );
    assert_eq!(
        refused(b"GET / HTTP/1.1\r\nHost: a\n\r\n"),
        Reject::BadRequest
    );
    assert_eq!(
        refused(b"GET / HTTP/1.1\r\nHost: a\r\n\n"),
        Reject::BadRequest
    );
    assert_eq!(
        refused(b"GET / HTTP/1.1\r\nHost: a\rb\r\n\r\n"),
        Reject::BadRequest
    );
    ok(&head_with(&[]));
}

#[test]
fn the_head_does_not_start_with_an_empty_line() {
    assert_eq!(
        refused(b"\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n"),
        Reject::BadRequest
    );
    assert_eq!(
        refused(b"\nGET / HTTP/1.1\r\nHost: a\r\n\r\n"),
        Reject::BadRequest
    );
    ok(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
}

#[test]
fn the_method_is_a_token_of_1_to_32_bytes() {
    let longest = "M".repeat(32);
    assert_eq!(
        ok(&with_request_line(&format!("{longest} / HTTP/1.1"))).method(),
        longest.as_bytes()
    );
    let too_long = "M".repeat(33);
    assert_eq!(
        refused(&with_request_line(&format!("{too_long} / HTTP/1.1"))),
        Reject::BadRequest
    );
    assert_eq!(
        refused(&with_request_line(" / HTTP/1.1")),
        Reject::BadRequest
    );
    assert_eq!(
        refused(&with_request_line("G@T / HTTP/1.1")),
        Reject::BadRequest
    );
    assert_eq!(ok(&with_request_line("get / HTTP/1.1")).method(), b"get");
}

#[test]
fn the_target_is_origin_form_of_1_to_4096_bytes_that_hyper_takes_without_a_fragment() {
    let longest = format!("/{}", "a".repeat(4095));
    assert_eq!(
        ok(&with_request_line(&format!("GET {longest} HTTP/1.1"))).target(),
        longest.as_bytes()
    );
    let too_long = format!("/{}", "a".repeat(4096));
    let raw = with_request_line(&format!("GET {too_long} HTTP/1.1"));
    assert_eq!(refused(&raw), Reject::UriTooLong);
    for target in [
        "*",
        "http://example.test/",
        "a",
        "/a#b",
        "/a?b#c",
        "/a\u{7f}",
        "/\u{e9}",
        "/a<b",
        "/a>b",
        "/a`b",
        "/?q=\"x\"",
        "/?q=<x>",
        "/?q=>",
    ] {
        let raw = with_request_line(&format!("GET {target} HTTP/1.1"));
        assert_eq!(refused(&raw), Reject::BadRequest, "target {target:?}");
    }
    assert_eq!(
        refused(b"GET  / HTTP/1.1\r\nHost: a\r\n\r\n"),
        Reject::BadRequest
    );
    assert_eq!(
        refused(b"GET /a b HTTP/1.1\r\nHost: a\r\n\r\n"),
        Reject::BadRequest
    );
    assert_eq!(
        ok(&with_request_line("GET /a%20b?c=d&e=%41 HTTP/1.1")).target(),
        b"/a%20b?c=d&e=%41"
    );
    // The path takes `"`, `{`, `|` and `}` and not the backtick; the query takes the backtick and not `"`.
    for target in [
        "/a\"b",
        "/{\"k\":1}|",
        "/?q=`x`",
        "/a\"b?c`d{e}",
        "/?",
        "/??",
        "/a?b?c",
    ] {
        let raw = with_request_line(&format!("GET {target} HTTP/1.1"));
        assert_eq!(ok(&raw).target(), target.as_bytes(), "target {target:?}");
    }
}

#[test]
fn only_http_1_1_passes() {
    ok(&with_request_line("GET / HTTP/1.1"));
    assert_eq!(
        refused(&with_request_line("GET / HTTP/1.0")),
        Reject::VersionNotSupported
    );
    assert_eq!(
        refused(&with_request_line("GET / HTTP/1.2")),
        Reject::BadRequest
    );
    assert_eq!(
        refused(&with_request_line("GET / HTTP/2.0")),
        Reject::BadRequest
    );
    assert_eq!(
        refused(&with_request_line("GET / FTP/1.1")),
        Reject::BadRequest
    );
}

fn fields_numbered(count: usize) -> Vec<u8> {
    let lines: Vec<String> = (1..count).map(|n| format!("X-{n}: v")).collect();
    let lines: Vec<&str> = lines.iter().map(String::as_str).collect();
    head_with(&lines)
}

#[test]
fn at_most_64_fields() {
    assert_eq!(ok(&fields_numbered(64)).fields().len(), 64);
    assert_eq!(refused(&fields_numbered(65)), Reject::FieldsTooLarge);
    assert_eq!(refused(&fields_numbered(80)), Reject::FieldsTooLarge);
}

#[test]
fn a_name_has_1_to_256_bytes() {
    let longest = format!("{}: v", "N".repeat(256));
    ok(&head_with(&[&longest]));
    let too_long = format!("{}: v", "N".repeat(257));
    assert_eq!(refused(&head_with(&[&too_long])), Reject::FieldsTooLarge);
    assert_eq!(refused(&head_with(&[": v"])), Reject::BadRequest);
}

#[test]
fn a_value_has_at_most_4096_bytes_without_the_blanks_around_it() {
    let longest = format!("X-A: {}", "v".repeat(4096));
    ok(&head_with(&[&longest]));
    let padded = format!("X-A:  \t{} \t ", "v".repeat(4096));
    assert_eq!(
        ok(&head_with(&[&padded])).fields().nth(1).unwrap().1.len(),
        4096
    );
    let too_long = format!("X-A: {}", "v".repeat(4097));
    assert_eq!(refused(&head_with(&[&too_long])), Reject::FieldsTooLarge);
}

#[test]
fn names_and_values_together_are_at_most_24_kib() {
    // Host (4 + 12) and five fields of 4 + 4096 bytes are 20516; the last field brings the total to `total`.
    let with_total = |last: usize| {
        let mut lines: Vec<String> = (1..=5)
            .map(|n| format!("F00{n}: {}", "a".repeat(4096)))
            .collect();
        lines.push(format!("F006: {}", "a".repeat(last)));
        let lines: Vec<&str> = lines.iter().map(String::as_str).collect();
        head_with(&lines)
    };
    let head = ok(&with_total(4056));
    let total: usize = head
        .fields()
        .map(|(name, value)| name.len() + value.len())
        .sum();
    assert_eq!(total, 24 * 1024);
    assert_eq!(refused(&with_total(4057)), Reject::FieldsTooLarge);
}

#[test]
fn field_syntax_is_strict() {
    for line in ["X-A : v", "X@A: v", "X A: v", "X-A v"] {
        assert_eq!(
            refused(&head_with(&[line])),
            Reject::BadRequest,
            "line {line:?}"
        );
    }
    // obs-fold: a continuation line.
    assert_eq!(
        refused(b"GET / HTTP/1.1\r\nHost: a\r\nX-A: v\r\n  folded\r\n\r\n"),
        Reject::BadRequest
    );
    assert_eq!(
        refused(b"GET / HTTP/1.1\r\n Host: a\r\n\r\n"),
        Reject::BadRequest
    );
    let head = ok(&head_with(&["X-A:", "x-b:    ", "X-C:v"]));
    let fields: Vec<(&[u8], &[u8])> = head.fields().collect();
    assert_eq!(fields[1], (&b"X-A"[..], &b""[..]));
    assert_eq!(fields[2], (&b"x-b"[..], &b""[..]));
    assert_eq!(fields[3], (&b"X-C"[..], &b"v"[..]));
}

#[test]
fn a_value_has_no_control_byte_except_htab() {
    let line = |byte: u8| [b"X-A: a".as_slice(), &[byte], b"b\r\n"].concat();
    let with = |bytes: Vec<u8>| {
        [
            b"GET / HTTP/1.1\r\nHost: a\r\n".to_vec(),
            bytes,
            b"\r\n".to_vec(),
        ]
        .concat()
    };
    for byte in [0x00, 0x01, 0x08, 0x0b, 0x1f, 0x7f] {
        assert_eq!(
            refused(&with(line(byte))),
            Reject::BadRequest,
            "byte {byte:#04x}"
        );
    }
    for byte in [0x09, 0x20, 0x7e, 0x80, 0xff] {
        ok(&with(line(byte)));
    }
    // The blanks around a value are not part of it, so they are not control bytes either.
    let head = ok(&with(b"X-A:\t a\tb \t\r\n".to_vec()));
    assert_eq!(head.fields().nth(1).unwrap().1, b"a\tb");
}

#[test]
fn there_is_exactly_one_host_without_blanks() {
    assert_eq!(
        refused(b"GET / HTTP/1.1\r\nX-A: v\r\n\r\n"),
        Reject::BadRequest
    );
    assert_eq!(
        refused(&head_with(&["Host: example.test"])),
        Reject::BadRequest
    );
    assert_eq!(
        refused(&head_with(&["HOST: other.test"])),
        Reject::BadRequest
    );
    assert_eq!(
        refused(b"GET / HTTP/1.1\r\nHost:\r\n\r\n"),
        Reject::BadRequest
    );
    assert_eq!(
        refused(b"GET / HTTP/1.1\r\nHost:  \t \r\n\r\n"),
        Reject::BadRequest
    );
    assert_eq!(
        refused(b"GET / HTTP/1.1\r\nHost: a b\r\n\r\n"),
        Reject::BadRequest
    );
    assert_eq!(
        refused(b"GET / HTTP/1.1\r\nHost: a\tb\r\n\r\n"),
        Reject::BadRequest
    );
    ok(b"GET / HTTP/1.1\r\nhOsT: a\r\n\r\n");
    ok(b"GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n");
}

#[test]
fn transfer_encoding_is_one_line_that_is_chunked() {
    assert!(ok(&head_with(&["Transfer-Encoding: chunked"])).chunked());
    assert!(ok(&head_with(&["transfer-encoding:  CHUNKED \t"])).chunked());
    for line in [
        "Transfer-Encoding: gzip, chunked",
        "Transfer-Encoding: chunked, gzip",
        "Transfer-Encoding: identity",
        "Transfer-Encoding:",
    ] {
        assert_eq!(
            refused(&head_with(&[line])),
            Reject::BadRequest,
            "line {line:?}"
        );
    }
    let twice = head_with(&["Transfer-Encoding: chunked", "Transfer-Encoding: chunked"]);
    assert_eq!(refused(&twice), Reject::BadRequest);
    let both = head_with(&["Transfer-Encoding: chunked", "Content-Length: 0"]);
    assert_eq!(refused(&both), Reject::BadRequest);
    let both = head_with(&["Content-Length: 5", "Transfer-Encoding: chunked"]);
    assert_eq!(refused(&both), Reject::BadRequest);
}

#[test]
fn content_length_is_one_line_of_digits_within_the_limit() {
    assert_eq!(
        ok(&head_with(&["Content-Length: 0"])).content_length(),
        Some(0)
    );
    assert_eq!(
        ok(&head_with(&["content-length: 007", FORM])).content_length(),
        Some(7)
    );
    let largest = format!("Content-Length: {}", LIM.max_body);
    assert_eq!(
        ok(&head_with(&[&largest, FORM])).content_length(),
        Some(LIM.max_body)
    );
    let over = format!("Content-Length: {}", LIM.max_body + 1);
    assert_eq!(refused(&head_with(&[&over, FORM])), Reject::ContentTooLarge);
    // Fits in 64 bits and is over the limit: 413. Does not fit: 400.
    assert_eq!(
        refused(&head_with(&["Content-Length: 18446744073709551615"])),
        Reject::ContentTooLarge
    );
    assert_eq!(
        refused(&head_with(&["Content-Length: 18446744073709551616"])),
        Reject::BadRequest
    );
    for line in [
        "Content-Length:",
        "Content-Length: +5",
        "Content-Length: -5",
        "Content-Length: 5 6",
        "Content-Length: 0x5",
        "Content-Length: 5,5",
    ] {
        assert_eq!(
            refused(&head_with(&[line, FORM])),
            Reject::BadRequest,
            "line {line:?}"
        );
    }
    // A repeated line is refused even when both say the same.
    assert_eq!(
        refused(&head_with(&["Content-Length: 0", "Content-Length: 0"])),
        Reject::BadRequest
    );
    let tight = Limits { max_body: 0, ..LIM };
    assert!(
        parse(&head_with(&["Content-Length: 0"]), &tight)
            .unwrap()
            .is_some()
    );
    assert_eq!(
        parse(&head_with(&["Content-Length: 1", FORM]), &tight).unwrap_err(),
        Reject::ContentTooLarge
    );
}

#[test]
fn expect_is_absent_or_exactly_100_continue() {
    assert!(parse(&head_with(&[]), &LIM).unwrap().is_some());
    ok(&head_with(&["Expect: 100-continue"]));
    ok(&head_with(&["expect:  100-CONTINUE "]));
    for line in [
        "Expect: 200-ok",
        "Expect:",
        "Expect: 100-continue, 100-continue",
        "Expect: 100-continue x",
    ] {
        assert_eq!(
            refused(&head_with(&[line])),
            Reject::ExpectationFailed,
            "line {line:?}"
        );
    }
    let twice = head_with(&["Expect: 100-continue", "Expect: 100-continue"]);
    assert_eq!(refused(&twice), Reject::ExpectationFailed);
}

#[test]
fn connection_is_a_list_of_tokens_that_does_not_name_the_fixed_fields() {
    ok(&head_with(&["Connection: keep-alive"]));
    ok(&head_with(&[
        "Connection: close",
        "Connection: Upgrade,  X-Hop \t",
    ]));
    ok(&head_with(&["Connection: x-hosts, content-lengths"]));
    for line in [
        "Connection: host",
        "Connection: close, HOST",
        "Connection: content-length",
        "Connection: x, Content-Type",
        "Connection: content-encoding",
        "Connection:",
        "Connection: a,,b",
        "Connection: a,",
        "Connection: ,a",
        "Connection: a b",
        "Connection: a;b",
        "Connection: \"a\"",
    ] {
        assert_eq!(
            refused(&head_with(&[line])),
            Reject::BadRequest,
            "line {line:?}"
        );
    }
    // One bad line among good ones is enough.
    assert_eq!(
        refused(&head_with(&["Connection: close", "Connection: host"])),
        Reject::BadRequest
    );
}

#[test]
fn content_encoding_is_absent_or_one_line_that_is_gzip() {
    // Absent: the body is not gzip, whatever else the head says.
    assert!(!ok(&head_with(&[])).gzip());
    assert!(!ok(&head_with(&["Content-Length: 1", FORM])).gzip());
    assert!(!ok(&head_with(&["Transfer-Encoding: chunked", FORM])).gzip());
    assert!(!ok(&head_with(&["Content-Language: en"])).gzip());
    // Exactly `gzip`, ASCII case ignored, the blanks around the value dropped; with a length and chunked.
    for line in [
        "Content-Encoding: gzip",
        "content-encoding: GZIP",
        "CONTENT-ENCODING: GzIp",
        "Content-Encoding:  gzip \t",
        "Content-Encoding:\tgzip",
    ] {
        let sized = ok(&head_with(&["Content-Length: 1", FORM, line]));
        assert!(sized.gzip() && !sized.chunked(), "line {line:?}");
        assert_eq!(sized.content_length(), Some(1), "line {line:?}");
        let chunked = ok(&head_with(&["Transfer-Encoding: chunked", FORM, line]));
        assert!(chunked.gzip() && chunked.chunked(), "line {line:?}");
    }
    // Any other value is 415: another coding, a list of any length, an empty value, a near miss. The value
    // decides before the body (or the lack of one) is looked at.
    for line in [
        "Content-Encoding: x-gzip",
        "Content-Encoding: X-GZIP",
        "Content-Encoding: deflate",
        "Content-Encoding: br",
        "Content-Encoding: zstd",
        "Content-Encoding: identity",
        "Content-Encoding: compress",
        "Content-Encoding: x-compress",
        "Content-Encoding: gzip, gzip",
        "Content-Encoding: gzip,gzip",
        "Content-Encoding: gzip, identity",
        "Content-Encoding: identity, gzip",
        "Content-Encoding: gzip, br",
        "Content-Encoding: br, gzip",
        "Content-Encoding: gzip,",
        "Content-Encoding: ,gzip",
        "Content-Encoding:",
        "Content-Encoding:  \t",
        "Content-Encoding: gzip;q=1",
        "Content-Encoding: gzipx",
        "Content-Encoding: xgzip",
        "Content-Encoding: gzi",
        "Content-Encoding: g zip",
        "Content-Encoding: gzip gzip",
        "Content-Encoding: \"gzip\"",
    ] {
        let sized = head_with(&["Content-Length: 1", FORM, line]);
        assert_eq!(refused(&sized), Reject::UnsupportedMedia, "line {line:?}");
        let chunked = head_with(&["Transfer-Encoding: chunked", FORM, line]);
        assert_eq!(refused(&chunked), Reject::UnsupportedMedia, "line {line:?}");
        let empty = head_with(&["Content-Length: 0", line]);
        assert_eq!(refused(&empty), Reject::UnsupportedMedia, "line {line:?}");
        assert_eq!(
            refused(&head_with(&[line])),
            Reject::UnsupportedMedia,
            "line {line:?}"
        );
    }
    // Two lines are refused whatever they say, in any case of the name.
    for lines in [
        &["Content-Encoding: gzip", "Content-Encoding: gzip"],
        &["Content-Encoding: gzip", "content-encoding: GZIP"],
        &["Content-Encoding: gzip", "Content-Encoding: identity"],
        &["Content-Encoding: identity", "Content-Encoding: gzip"],
        &["Content-Encoding: br", "Content-Encoding: br"],
    ] {
        let mut all = vec!["Content-Length: 1", FORM];
        all.extend_from_slice(lines);
        assert_eq!(
            refused(&head_with(&all)),
            Reject::UnsupportedMedia,
            "lines {lines:?}"
        );
    }
}

#[test]
fn a_gzip_body_that_is_empty_on_its_face_is_400() {
    // No bytes by length or by the lack of any framing: not a gzip stream.
    for lines in [
        &["Content-Encoding: gzip", "Content-Length: 0"][..],
        &["Content-Encoding: gzip", "Content-Length: 0", FORM],
        &["content-encoding:  GZIP ", "content-length: 000"],
        &["Content-Encoding: gzip"],
        &["Content-Encoding: gzip", FORM],
    ] {
        assert_eq!(
            refused(&head_with(lines)),
            Reject::BadRequest,
            "lines {lines:?}"
        );
    }
    // One byte is enough to pass the rule, and a chunked body is not known to be empty yet.
    let sized = ok(&head_with(&[
        "Content-Encoding: gzip",
        "Content-Length: 1",
        FORM,
    ]));
    assert!(sized.gzip());
    let chunked = ok(&head_with(&[
        "Content-Encoding: gzip",
        "Transfer-Encoding: chunked",
        FORM,
    ]));
    assert!(chunked.gzip() && chunked.chunked());
    // The same bodies without the coding are not refused for it.
    assert!(
        !ok(&head_with(&["Content-Length: 0"])).gzip() && !ok(&head_with(&[])).gzip(),
        "an empty body is fine without gzip"
    );
    // The type rule is the one of a body with a length: a gzip body needs the type of the decoded body.
    assert_eq!(
        refused(&head_with(&["Content-Encoding: gzip", "Content-Length: 1"])),
        Reject::UnsupportedMedia
    );
    assert_eq!(
        refused(&head_with(&[
            "Content-Encoding: gzip",
            "Content-Length: 1",
            "Content-Type: text/plain"
        ])),
        Reject::UnsupportedMedia
    );
    for essence in [
        JSON,
        SUFFIXED,
        "Content-Type: multipart/form-data; boundary=x",
    ] {
        let head = ok(&head_with(&[
            "Content-Encoding: gzip",
            "Content-Length: 1",
            essence,
        ]));
        assert!(head.gzip() && head.inspectable_type(), "type {essence:?}");
    }
    // A chunked gzip body of another type passes the head and is checked by the caller.
    let chunked = ok(&head_with(&[
        "Content-Encoding: gzip",
        "Transfer-Encoding: chunked",
        "Content-Type: text/plain",
    ]));
    assert!(chunked.gzip() && chunked.chunked() && !chunked.inspectable_type());
}

#[test]
fn a_body_needs_exactly_one_inspectable_content_type() {
    let lengthy = |lines: &[&str]| {
        let mut all = vec!["Content-Length: 1"];
        all.extend_from_slice(lines);
        head_with(&all)
    };
    ok(&lengthy(&[FORM]));
    ok(&lengthy(&[
        "Content-Type: application/x-www-form-urlencoded; charset=utf-8",
    ]));
    ok(&lengthy(&[
        "content-type:  MULTIPART/Form-Data ; boundary=xyz",
    ]));
    ok(&lengthy(&["Content-Type: multipart/form-data"]));
    // JSON is compared like the other two: the part before the first `;`, blanks and case ignored.
    ok(&lengthy(&[JSON]));
    ok(&lengthy(&["Content-Type: application/json; charset=UTF-8"]));
    ok(&lengthy(&["Content-Type: Application/JSON"]));
    ok(&lengthy(&[
        "content-type:  application/json ; charset=utf-8",
    ]));
    ok(&lengthy(&[
        "Content-Type:\tapplication/json\t;\tcharset=utf-8",
    ]));
    // `application/<name>+json` is compared the same way, and the name has its own rule.
    ok(&lengthy(&[SUFFIXED]));
    ok(&lengthy(&["Content-Type: application/problem+json"]));
    ok(&lengthy(&["Content-Type: application/merge-patch+json"]));
    ok(&lengthy(&[
        "Content-Type: Application/VND.API+JSON; charset=UTF-8",
    ]));
    ok(&lengthy(&[
        "content-type:  application/vnd.api+json ; charset=utf-8",
    ]));
    ok(&lengthy(&[
        "Content-Type:\tapplication/problem+json\t;\tcharset=utf-8",
    ]));
    // The name: one byte, a digit first, `.` and `-` inside.
    ok(&lengthy(&["Content-Type: application/x+json"]));
    ok(&lengthy(&["Content-Type: application/1+json"]));
    ok(&lengthy(&["Content-Type: application/vnd.api-v1.2+json"]));
    // The `x-www-form-urlencoded` start is refused only when the name really starts with it.
    ok(&lengthy(&[
        "Content-Type: application/x-www-form-urlencode+json",
    ]));
    ok(&lengthy(&[
        "Content-Type: application/xx-www-form-urlencoded+json",
    ]));
    // The longest name is 122 bytes.
    let named = |len: usize| format!("Content-Type: application/{}+json", "a".repeat(len));
    ok(&lengthy(&[&named(122)]));
    assert_eq!(refused(&lengthy(&[&named(123)])), Reject::UnsupportedMedia);
    for lines in [
        &[][..],
        &["Content-Type: text/plain"],
        &["Content-Type: application/xml"],
        &["Content-Type: application/x-www-form-urlencodedx"],
        &["Content-Type:"],
        &["Content-Type: multipart/form-data, text/plain"],
        &[FORM, FORM],
        &[FORM, "Content-Type: text/plain"],
        &["Content-Type: application/jsonp"],
        &["Content-Type: text/x+json"],
        &["Content-Type: text/json"],
        &["Content-Type: application /json"],
        &["Content-Type: application/json, text/plain"],
        &[JSON, JSON],
        &[JSON, "Content-Type: text/plain"],
        &["Content-Type: application/vnd.api+json, text/plain"],
        &[SUFFIXED, SUFFIXED],
        &[SUFFIXED, JSON],
        &[SUFFIXED, "Content-Type: text/plain"],
        // A name that is empty, starts with a symbol, or has a byte outside letters, digits, `.` and `-`.
        &["Content-Type: application/+json"],
        &["Content-Type: application/.x+json"],
        &["Content-Type: application/-x+json"],
        &["Content-Type: application/a+b+json"],
        &["Content-Type: application/a_b+json"],
        &["Content-Type: application/a/b+json"],
        &["Content-Type: application/\u{e9}+json"],
        &["Content-Type: application/vnd.api +json"],
        &["Content-Type: application/vnd.api+ json"],
        // A name that starts with the urlencoded type (any case), and types that are not `application/<name>+json`.
        &["Content-Type: application/x-www-form-urlencoded+json"],
        &["Content-Type: application/x-www-form-urlencoded-x+json"],
        &["Content-Type: Application/X-WWW-Form-Urlencoded+JSON"],
        &["Content-Type: application/x+json2"],
        &["Content-Type: application/x+jsonp"],
        &["Content-Type: application/x+jso"],
        &["Content-Type: application/vnd.api-json"],
        &["Content-Type: application/jso"],
        &["Content-Type: application/"],
        &["Content-Type: text/x+json"],
        &["Content-Type: xapplication/x+json"],
        &["Content-Type: text/plain-and-more+json"],
    ] {
        assert_eq!(
            refused(&lengthy(lines)),
            Reject::UnsupportedMedia,
            "lines {lines:?}"
        );
    }
    // No body: no type needed, and the flag says what the type is.
    assert!(!ok(&head_with(&["Content-Length: 0"])).inspectable_type());
    assert!(ok(&head_with(&["Content-Length: 0", FORM])).inspectable_type());
    assert!(ok(&head_with(&["Content-Length: 0", JSON])).inspectable_type());
    assert!(ok(&head_with(&["Content-Length: 0", SUFFIXED])).inspectable_type());
    assert!(!ok(&head_with(&["Content-Type: text/plain"])).inspectable_type());
    // A chunked body is checked by the caller once it knows the body is not empty.
    let chunked = ok(&head_with(&[
        "Transfer-Encoding: chunked",
        "Content-Type: text/plain",
    ]));
    assert!(chunked.chunked() && !chunked.inspectable_type());
    assert!(ok(&head_with(&["Transfer-Encoding: chunked", FORM])).inspectable_type());
    assert!(ok(&head_with(&["Transfer-Encoding: chunked", JSON])).inspectable_type());
    assert!(ok(&head_with(&["Transfer-Encoding: chunked", SUFFIXED])).inspectable_type());
    let near = head_with(&["Transfer-Encoding: chunked", "Content-Type: text/x+json"]);
    assert!(!ok(&near).inspectable_type());
}

#[test]
fn the_first_broken_rule_decides() {
    // The version before the fields, the line ends before everything, a size before the Host rule.
    assert_eq!(
        refused(b"GET / HTTP/1.0\r\nX-A: v\r\n\r\n"),
        Reject::VersionNotSupported
    );
    assert_eq!(
        refused(b"GET / HTTP/1.0\nHost: a\r\n\r\n"),
        Reject::BadRequest
    );
    let big = format!("GET / HTTP/1.1\r\nX-A: {}\r\n\r\n", "x".repeat(4097));
    assert_eq!(refused(big.as_bytes()), Reject::FieldsTooLarge);
    // Content-Length over the limit is decided before Expect, Connection and the body type.
    let raw = head_with(&[
        "Content-Length: 2097152",
        "Expect: nope",
        "Connection: host",
    ]);
    assert_eq!(refused(&raw), Reject::ContentTooLarge);
    let raw = head_with(&["Expect: nope", "Connection: host", "Content-Encoding: br"]);
    assert_eq!(refused(&raw), Reject::ExpectationFailed);
    let raw = head_with(&["Connection: host", "Content-Encoding: br"]);
    assert_eq!(refused(&raw), Reject::BadRequest);
    // Within rule 8 the coding is decided first, then the body that has no bytes, then the body type.
    let raw = head_with(&["Content-Encoding: br", "Content-Length: 0"]);
    assert_eq!(refused(&raw), Reject::UnsupportedMedia);
    let raw = head_with(&["Content-Encoding: gzip", "Content-Length: 0"]);
    assert_eq!(refused(&raw), Reject::BadRequest);
}

#[test]
fn every_refusal_has_the_fixed_answer_of_its_status() {
    let all = [
        Reject::BadRequest,
        Reject::UriTooLong,
        Reject::FieldsTooLarge,
        Reject::ContentTooLarge,
        Reject::ExpectationFailed,
        Reject::VersionNotSupported,
        Reject::UnsupportedMedia,
        Reject::Timeout,
        Reject::Closed,
    ];
    for reject in all {
        assert!(!reject.reason().is_empty());
        match (reject.status(), reject.response()) {
            (None, None) => assert_eq!(reject, Reject::Closed),
            (Some(status), Some(bytes)) => {
                let reason = http::StatusCode::from_u16(status)
                    .unwrap()
                    .canonical_reason()
                    .unwrap();
                let expected = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                assert_eq!(bytes, expected.as_bytes(), "{reject:?}");
            }
            other => panic!("status and answer disagree: {other:?}"),
        }
    }
    assert_eq!(Reject::BadRequest.status(), Some(400));
    assert_eq!(Reject::UriTooLong.status(), Some(414));
    assert_eq!(Reject::FieldsTooLarge.status(), Some(431));
    assert_eq!(Reject::ContentTooLarge.status(), Some(413));
    assert_eq!(Reject::ExpectationFailed.status(), Some(417));
    assert_eq!(Reject::VersionNotSupported.status(), Some(505));
    assert_eq!(Reject::UnsupportedMedia.status(), Some(415));
    assert_eq!(Reject::Timeout.status(), Some(408));
}

fn runtime() -> Runtime {
    Builder::new_current_thread().enable_all().build().unwrap()
}

async fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    (server, client)
}

async fn put(sock: &TcpStream, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        sock.writable().await.unwrap();
        match sock.try_write(bytes) {
            Ok(n) => bytes = &bytes[n..],
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => panic!("write failed: {e}"),
        }
    }
}

fn soon(ms: u64) -> Instant {
    Instant::now() + Duration::from_millis(ms)
}

/// A head of exactly `size` bytes: a request line, a Host and a padding field.
fn head_of_size(size: usize) -> Vec<u8> {
    let fixed = "GET / HTTP/1.1\r\nHost: a\r\nX-Pad: \r\n\r\n".len();
    let raw = format!(
        "GET / HTTP/1.1\r\nHost: a\r\nX-Pad: {}\r\n\r\n",
        "p".repeat(size - fixed)
    );
    assert_eq!(raw.len(), size);
    raw.into_bytes()
}

#[test]
fn read_returns_the_head_and_what_came_after_it() {
    runtime().block_on(async {
        let (mut server, client) = pair().await;
        let raw = head_with(&["Content-Length: 4", FORM]);
        let writer = tokio::spawn(async move {
            // The head arrives in pieces; the body starts in the same write as the end of the head.
            put(&client, &raw[..10]).await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            put(&client, &raw[10..raw.len() - 2]).await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            put(&client, b"\r\na=b&").await;
            client
        });
        let (head, rest) = read(&mut server, &LIM, soon(10_000)).await.unwrap();
        assert_eq!(head.method(), b"GET");
        assert_eq!(head.content_length(), Some(4));
        assert_eq!(&rest[..], b"a=b&");
        assert_eq!(&head.buf[head.len..], b"a=b&");
        drop(writer.await.unwrap());
    });
}

#[test]
fn read_refuses_a_head_that_does_not_fit_the_buffer() {
    let small = Limits {
        max_head_bytes: 1024,
        max_body: 1 << 20,
    };
    runtime().block_on(async {
        // A head of exactly the buffer size is read; one byte more is not.
        let (mut server, client) = pair().await;
        put(&client, &head_of_size(1024)).await;
        let (head, rest) = read(&mut server, &small, soon(10_000)).await.unwrap();
        assert_eq!((head.len, rest.len()), (1024, 0));
        let (mut server, client) = pair().await;
        put(&client, &head_of_size(1025)).await;
        assert_eq!(
            read(&mut server, &small, soon(10_000)).await.unwrap_err(),
            Reject::FieldsTooLarge
        );
        // No line end in a full buffer: the request line is the part that is too long.
        let (mut server, client) = pair().await;
        put(&client, format!("GET /{}", "a".repeat(2000)).as_bytes()).await;
        assert_eq!(
            read(&mut server, &small, soon(10_000)).await.unwrap_err(),
            Reject::UriTooLong
        );
        drop(client);
    });
}

#[test]
fn read_ends_with_timeout_or_closed_when_the_head_does_not_come() {
    runtime().block_on(async {
        let (mut server, client) = pair().await;
        let start = std::time::Instant::now();
        assert_eq!(
            read(&mut server, &LIM, soon(150)).await.unwrap_err(),
            Reject::Timeout
        );
        assert!(start.elapsed() >= Duration::from_millis(140));
        // A deadline that has passed ends the read at once, with what was sent so far unparsed.
        put(&client, b"GET / HTTP/1.1\r\nHo").await;
        assert_eq!(
            read(&mut server, &LIM, Instant::now()).await.unwrap_err(),
            Reject::Timeout
        );
        // The peer goes away with half a head, and another one without sending anything.
        drop(client);
        assert_eq!(
            read(&mut server, &LIM, soon(10_000)).await.unwrap_err(),
            Reject::Closed
        );
        let (mut server, client) = pair().await;
        drop(client);
        assert_eq!(
            read(&mut server, &LIM, soon(10_000)).await.unwrap_err(),
            Reject::Closed
        );
    });
}

#[test]
fn read_refuses_a_bad_head_without_waiting_for_the_rest() {
    runtime().block_on(async {
        let (mut server, client) = pair().await;
        put(&client, b"GET / HTTP/1.0\r\n\r\n").await;
        assert_eq!(
            read(&mut server, &LIM, soon(10_000)).await.unwrap_err(),
            Reject::VersionNotSupported
        );
        let (mut server, client) = pair().await;
        put(&client, b"GET / HTTP/1.1\nHost: a\n\n").await;
        assert_eq!(
            read(&mut server, &LIM, soon(10_000)).await.unwrap_err(),
            Reject::BadRequest
        );
        drop(client);
    });
}

/// Everything that arrives on `sock` until the peer closes it.
async fn read_all(sock: &TcpStream) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    timeout(Duration::from_secs(30), async {
        loop {
            sock.readable().await.unwrap();
            match sock.try_read(&mut buf) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => break,
            }
        }
    })
    .await
    .expect("the server closed the connection");
    out
}

/// Sends a GET for `target` (the rest of the head is valid) to a hyper server set up as `conn` sets it up:
/// true if hyper hands the request to its service, false if it answers 400 by itself.
async fn hyper_takes(listener: &TcpListener, target: &[u8]) -> bool {
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let request = [b"GET ".as_slice(), target, b" HTTP/1.1\r\nHost: a\r\n\r\n"].concat();
    put(&client, &request).await;
    let mut hyper = http1::Builder::new();
    hyper
        .keep_alive(false)
        .half_close(false)
        .timer(TokioTimer::new())
        .header_read_timeout(None)
        .max_headers(limits::HEADERS)
        .max_header_size(LIM.max_head_bytes)
        .max_buf_size(LIM.max_head_bytes)
        .title_case_headers(true);
    let service = service_fn(|_: Request<Incoming>| async {
        Ok::<_, Infallible>(Response::new(Empty::<Bytes>::new()))
    });
    let _ = timeout(
        Duration::from_secs(30),
        hyper.serve_connection(TokioIo::new(server), service),
    )
    .await
    .expect("hyper ended the connection");
    let answer = read_all(&client).await;
    if answer.starts_with(b"HTTP/1.1 200 ") {
        true
    } else if answer.starts_with(b"HTTP/1.1 400 ") {
        false
    } else {
        panic!("an answer of hyper: {:?}", String::from_utf8_lossy(&answer));
    }
}

/// Runs `target` through `http::Uri` (what hyper calls for the target), through a hyper server and through
/// the head check, and checks that they agree: the head check takes it exactly when hyper does, except that
/// it also refuses a `#` and a byte outside `0x21..=0x7e`. Returns whether the head check took it.
async fn guard_and_hyper_agree(listener: &TcpListener, target: &[u8]) -> bool {
    let shown = target.escape_ascii().to_string();
    let uri = http::Uri::from_maybe_shared(Bytes::copy_from_slice(target)).is_ok();
    let hyper = hyper_takes(listener, target).await;
    assert_eq!(uri, hyper, "target {shown}: the URI parser and the server");
    let stricter = target.contains(&b'#') || !target.iter().all(|b| (0x21..=0x7e).contains(b));
    let raw = [b"GET ".as_slice(), target, b" HTTP/1.1\r\nHost: a\r\n\r\n"].concat();
    match parse(&raw, &LIM) {
        Ok(Some(head)) => {
            assert!(
                hyper && !stricter,
                "target {shown}: taken by the check only"
            );
            assert_eq!(head.target(), target, "target {shown}");
            true
        }
        Ok(None) => panic!("target {shown}: the head is complete"),
        Err(reject) => {
            assert!(
                !hyper || stricter,
                "target {shown}: refused by the check only"
            );
            assert_eq!(reject, Reject::BadRequest, "target {shown}");
            false
        }
    }
}

#[test]
fn the_head_check_takes_a_request_target_exactly_when_hyper_takes_it() {
    runtime().block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        // Every visible byte in the middle of the path, and in the middle of the query.
        let (mut path_refused, mut query_refused) = (Vec::new(), Vec::new());
        for b in 0x21..=0x7eu8 {
            let path = [b"/a".as_slice(), &[b], b"c"].concat();
            if !guard_and_hyper_agree(&listener, &path).await {
                path_refused.push(b);
            }
            let query = [b"/a?b".as_slice(), &[b], b"c"].concat();
            if !guard_and_hyper_agree(&listener, &query).await {
                query_refused.push(b);
            }
        }
        assert_eq!(path_refused, b"#<>`");
        assert_eq!(query_refused, b"\"#<>");
        // A few bytes outside that range: the head check refuses all of them.
        for b in [0x00u8, 0x09, 0x1f, 0x20, 0x7f, 0x80, 0xff] {
            for target in [
                [b"/a".as_slice(), &[b], b"c"].concat(),
                [b"/a?b".as_slice(), &[b], b"c"].concat(),
            ] {
                assert!(!guard_and_hyper_agree(&listener, &target).await);
            }
        }
        // Whole targets: the bytes that are taken in one part and refused in the other, in both parts.
        let whole = [
            ("/", true),
            ("/?", true),
            ("/??", true),
            ("//", true),
            ("/a?b?c", true),
            ("/a%zz?b=%", true),
            ("/a\"b?c`d", true),
            ("/{\"k\":1}|~?x={`y`}", true),
            ("/a<b?c`d", false),
            ("/a\"b?c\"d", false),
            ("/a`b?c`d", false),
        ];
        for (target, taken) in whole {
            let got = guard_and_hyper_agree(&listener, target.as_bytes()).await;
            assert_eq!(got, taken, "target {target:?}");
        }
        // The two places where the head check is stricter on purpose: hyper cuts a fragment off and goes on,
        // and takes valid UTF-8 above 0x7f.
        for target in ["/a#c", "/a?b#c", "/\u{e9}", "/?\u{e9}"] {
            assert!(
                hyper_takes(&listener, target.as_bytes()).await,
                "{target:?}"
            );
            assert!(!guard_and_hyper_agree(&listener, target.as_bytes()).await);
        }
    });
}
