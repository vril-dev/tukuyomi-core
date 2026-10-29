use std::convert::Infallible;
use std::io;
use std::time::Duration;

use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::{TcpListener, TcpStream};
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
    assert_eq!(&head.buf[..], &raw[..head_len]);
    assert_eq!(head.method(), b"POST");
    assert_eq!(head.target(), b"/a?b=1");
    let fields: Vec<(&[u8], &[u8])> = head.fields().collect();
    assert_eq!(fields.len(), 4);
    assert_eq!(fields[1], (&b"X-A"[..], &b"v"[..]));
    assert_eq!(head.content_length(), Some(3));
    assert!(!head.chunked());
    assert!(head.inspectable_type());
}

#[test]
fn line_ends_must_be_crlf() {
    for raw in [
        &b"GET / HTTP/1.1\nHost: a\r\n\r\n"[..],
        b"GET / HTTP/1.1\r\nHost: a\rb\r\n\r\n",
        b"\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n",
    ] {
        assert_eq!(refused(raw), Reject::BadRequest);
    }
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
}

#[test]
fn connect_is_refused_whatever_its_target() {
    for line in ["CONNECT /x HTTP/1.1", "CONNECT example.test:443 HTTP/1.1"] {
        assert_eq!(refused(&with_request_line(line)), Reject::BadRequest);
    }
    // The method is case sensitive: this is another method.
    assert_eq!(
        ok(&with_request_line("connect /x HTTP/1.1")).method(),
        b"connect"
    );
}

#[test]
fn an_upgrade_line_marks_the_head_and_only_a_plain_handshake_is_a_websocket() {
    let head = ok(&head_with(&[
        "Upgrade: WebSocket",
        "Connection: keep-alive, Upgrade",
    ]));
    assert!(head.upgrade() && head.websocket());
    assert!(!ok(&head_with(&[])).upgrade());
    assert!(!ok(&head_with(&["Connection: Upgrade"])).upgrade());
    // Each of these has an Upgrade line and is not the handshake of a WebSocket.
    for lines in [
        &["Upgrade: h2c", "Connection: Upgrade"][..],
        &["Upgrade: websocket"][..],
        &[
            "Upgrade: websocket",
            "Upgrade: websocket",
            "Connection: Upgrade",
        ][..],
        &["Upgrade: websocket, h2c", "Connection: Upgrade"][..],
        &["Upgrade: websocket", "Connection: Upgrade, close"][..],
        &[
            "Upgrade: websocket",
            "Connection: Upgrade",
            "Transfer-Encoding: chunked",
        ][..],
    ] {
        let head = ok(&head_with(lines));
        assert!(head.upgrade() && !head.websocket(), "{lines:?}");
    }
    // A body of length 0 is no body. The method and the version are fixed.
    let sized = [
        "Upgrade: websocket",
        "Connection: Upgrade",
        "Content-Length: 0",
    ];
    assert!(ok(&head_with(&sized)).websocket());
    let rest = "Host: example.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
    for (line, websocket) in [
        ("GET /ws HTTP/1.1", true),
        ("POST /ws HTTP/1.1", false),
        ("GET /ws HTTP/1.0", false),
    ] {
        let head = ok(format!("{line}\r\n{rest}").as_bytes());
        assert!(head.upgrade(), "{line}");
        assert_eq!(head.websocket(), websocket, "{line}");
    }
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
    for target in ["*", "http://example.test/", "/a#b", "/a<b", "/?q=\"x\""] {
        let raw = with_request_line(&format!("GET {target} HTTP/1.1"));
        assert_eq!(refused(&raw), Reject::BadRequest, "target {target:?}");
    }
    // The path takes `"`, `{`, `|` and `}` and not the backtick; the query takes the backtick and not `"`.
    for target in ["/a%20b?c=d&e=%41", "/{\"k\":1}|", "/?q=`x`"] {
        let raw = with_request_line(&format!("GET {target} HTTP/1.1"));
        assert_eq!(ok(&raw).target(), target.as_bytes(), "target {target:?}");
    }
}

#[test]
fn http_1_0_and_1_1_pass_and_a_1_0_request_has_no_transfer_encoding() {
    let old = ok(&with_request_line("GET / HTTP/1.0"));
    assert!(old.http10());
    assert_eq!(old.proto(), b"HTTP/1.0");
    let new = ok(&with_request_line("GET / HTTP/1.1"));
    assert!(!new.http10());
    assert_eq!(new.proto(), b"HTTP/1.1");
    assert_eq!(
        refused(&with_request_line("GET / HTTP/1.2")),
        Reject::BadRequest
    );
    let raw = b"POST / HTTP/1.0\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n";
    assert_eq!(refused(raw), Reject::BadRequest);
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
    for line in ["X-A : v", "X@A: v"] {
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
}

#[test]
fn a_value_has_no_control_byte_except_htab() {
    let with = |byte: u8| {
        [
            b"GET / HTTP/1.1\r\nHost: a\r\nX-A: a".as_slice(),
            &[byte],
            b"b\r\n\r\n",
        ]
        .concat()
    };
    for byte in [0x00, 0x08, 0x1f, 0x7f] {
        assert_eq!(refused(&with(byte)), Reject::BadRequest, "{byte:#04x}");
    }
    for byte in [0x09, 0x7e, 0x80] {
        ok(&with(byte));
    }
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
        refused(b"GET / HTTP/1.1\r\nHost:\r\n\r\n"),
        Reject::BadRequest
    );
    assert_eq!(
        refused(b"GET / HTTP/1.1\r\nHost: a b\r\n\r\n"),
        Reject::BadRequest
    );
    ok(b"GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n");
}

#[test]
fn transfer_encoding_is_one_line_that_is_chunked() {
    assert!(ok(&head_with(&["transfer-encoding:  CHUNKED \t"])).chunked());
    for line in ["Transfer-Encoding: gzip, chunked", "Transfer-Encoding:"] {
        assert_eq!(
            refused(&head_with(&[line])),
            Reject::BadRequest,
            "line {line:?}"
        );
    }
    let twice = head_with(&["Transfer-Encoding: chunked", "Transfer-Encoding: chunked"]);
    assert_eq!(refused(&twice), Reject::BadRequest);
    // Both framings together are a smuggling shape: refused in either order.
    let both = head_with(&["Transfer-Encoding: chunked", "Content-Length: 0"]);
    assert_eq!(refused(&both), Reject::BadRequest);
    let both = head_with(&["Content-Length: 5", "Transfer-Encoding: chunked"]);
    assert_eq!(refused(&both), Reject::BadRequest);
}

#[test]
fn content_length_is_one_line_of_digits_within_the_limit() {
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
}

#[test]
fn expect_is_absent_or_exactly_100_continue() {
    ok(&head_with(&["expect:  100-CONTINUE "]));
    for line in ["Expect: 200-ok", "Expect: 100-continue, 100-continue"] {
        assert_eq!(
            refused(&head_with(&[line])),
            Reject::ExpectationFailed,
            "line {line:?}"
        );
    }
}

#[test]
fn connection_is_a_list_of_tokens_that_does_not_name_the_fixed_fields() {
    assert!(
        ok(&head_with(&[
            "Connection: close",
            "Connection: Upgrade,  X-Hop",
        ]))
        .close()
    );
    assert!(ok(&head_with(&["Connection: X-Hop,  CLOSE "])).close());
    assert!(!ok(&head_with(&["Connection: keep-alive, closed"])).close());
    assert!(!ok(&head_with(&[])).close());
    for line in [
        "Connection: close, HOST",
        "Connection: content-length",
        "Connection: a,,b",
    ] {
        assert_eq!(
            refused(&head_with(&[line])),
            Reject::BadRequest,
            "line {line:?}"
        );
    }
}

#[test]
fn content_encoding_is_absent_or_one_line_that_is_gzip() {
    assert!(!ok(&head_with(&["Content-Length: 1", FORM])).gzip());
    // Exactly `gzip`, ASCII case ignored, the blanks around the value dropped; with a length and chunked.
    let sized = ok(&head_with(&[
        "Content-Length: 1",
        FORM,
        "content-encoding: GZIP \t",
    ]));
    assert!(sized.gzip() && !sized.chunked());
    let chunked = ok(&head_with(&[
        "Transfer-Encoding: chunked",
        FORM,
        "Content-Encoding: gzip",
    ]));
    assert!(chunked.gzip() && chunked.chunked());
    // Any other value is 415, before the body (or the lack of one) is looked at.
    for line in [
        "Content-Encoding: deflate",
        "Content-Encoding: identity",
        "Content-Encoding: gzip, identity",
        "Content-Encoding:",
        "Content-Encoding: gzipx",
    ] {
        let sized = head_with(&["Content-Length: 1", FORM, line]);
        assert_eq!(refused(&sized), Reject::UnsupportedMedia, "line {line:?}");
        let empty = head_with(&["Content-Length: 0", line]);
        assert_eq!(refused(&empty), Reject::UnsupportedMedia, "line {line:?}");
    }
    // Two lines are refused whatever they say.
    let twice = head_with(&[
        "Content-Length: 1",
        FORM,
        "Content-Encoding: gzip",
        "content-encoding: GZIP",
    ]);
    assert_eq!(refused(&twice), Reject::UnsupportedMedia);
}

#[test]
fn a_gzip_body_that_is_empty_on_its_face_is_400() {
    // No bytes by length or by the lack of any framing: not a gzip stream.
    for lines in [
        &["Content-Encoding: gzip", "Content-Length: 0", FORM][..],
        &["Content-Encoding: gzip"],
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
    // The type is not a rule of the head: the caller asks for the type of the decoded body.
    let untyped = ok(&head_with(&["Content-Encoding: gzip", "Content-Length: 1"]));
    assert!(untyped.gzip() && !untyped.inspectable_type());
}

#[test]
fn the_head_says_whether_a_body_has_exactly_one_inspectable_content_type() {
    let lengthy = |lines: &[&str]| {
        let mut all = vec!["Content-Length: 1"];
        all.extend_from_slice(lines);
        head_with(&all)
    };
    for line in [
        FORM,
        "content-type:  MULTIPART/Form-Data ; boundary=xyz",
        "Content-Type: application/json; charset=UTF-8",
        SUFFIXED,
        "Content-Type: application/x+json",
        // The `x-www-form-urlencoded` start is refused only when the name really starts with it.
        "Content-Type: application/xx-www-form-urlencoded+json",
    ] {
        assert!(ok(&lengthy(&[line])).inspectable_type(), "line {line:?}");
    }
    // The longest name is 122 bytes.
    let named = |len: usize| format!("Content-Type: application/{}+json", "a".repeat(len));
    assert!(ok(&lengthy(&[&named(122)])).inspectable_type());
    // A body of another type is not refused by the head: the caller refuses it if the request is inspected.
    assert!(!ok(&lengthy(&[&named(123)])).inspectable_type());
    for lines in [
        &[][..],
        &["Content-Type: text/plain"],
        &["Content-Type: application/jsonp"],
        &["Content-Type: text/x+json"],
        &["Content-Type: application/+json"],
        &["Content-Type: application/a_b+json"],
        &["Content-Type: application/x-www-form-urlencoded+json"],
    ] {
        let head = ok(&lengthy(lines));
        assert!(
            !head.inspectable_type() && !head.repeated_type(),
            "lines {lines:?}"
        );
        assert_eq!(head.content_length(), Some(1));
    }
    // More than one line is refused with a body that has a length, whatever the lines say, for a reader may take any
    // of them for the type. With no body, and with a chunked one that the caller judges once it has been read, the
    // head passes and says so.
    for lines in [
        &[FORM, FORM][..],
        &[FORM, "Content-Type: text/plain"],
        &["Content-Type: text/plain", "Content-Type: text/xml"],
    ] {
        assert_eq!(
            refused(&lengthy(lines)),
            Reject::UnsupportedMedia,
            "lines {lines:?}"
        );
        for framing in ["Content-Length: 0", "Transfer-Encoding: chunked"] {
            let head = ok(&head_with(&[&[framing][..], lines].concat()));
            assert!(
                head.repeated_type() && !head.inspectable_type(),
                "{framing} {lines:?}"
            );
        }
    }
    // No body: no type needed, and the flag says what the type is. A chunked body is checked by the caller.
    assert!(!ok(&head_with(&["Content-Length: 0"])).inspectable_type());
    assert!(ok(&head_with(&["Content-Length: 0", JSON])).inspectable_type());
    let chunked = ok(&head_with(&[
        "Transfer-Encoding: chunked",
        "Content-Type: text/plain",
    ]));
    assert!(chunked.chunked() && !chunked.inspectable_type());
}

#[test]
fn the_first_broken_rule_decides() {
    // A size before the Host rule.
    let big = format!("GET / HTTP/1.1\r\nX-A: {}\r\n\r\n", "x".repeat(4097));
    assert_eq!(refused(big.as_bytes()), Reject::FieldsTooLarge);
    // Content-Length over the limit is decided before Expect and Connection.
    let raw = head_with(&[
        "Content-Length: 2097152",
        "Expect: nope",
        "Connection: host",
    ]);
    assert_eq!(refused(&raw), Reject::ContentTooLarge);
    let raw = head_with(&["Expect: nope", "Connection: host", "Content-Encoding: br"]);
    assert_eq!(refused(&raw), Reject::ExpectationFailed);
    // Within rule 8 the coding is decided first, then the body that has no bytes.
    let raw = head_with(&["Content-Encoding: br", "Content-Length: 0"]);
    assert_eq!(refused(&raw), Reject::UnsupportedMedia);
}

#[test]
fn every_refusal_has_the_fixed_answer_of_its_status() {
    for (reject, status) in [
        (Reject::BadRequest, 400),
        (Reject::UriTooLong, 414),
        (Reject::FieldsTooLarge, 431),
        (Reject::ContentTooLarge, 413),
        (Reject::ExpectationFailed, 417),
        (Reject::UnsupportedMedia, 415),
        (Reject::Timeout, 408),
    ] {
        assert_eq!(reject.status(), Some(status));
        let reason = http::StatusCode::from_u16(status)
            .unwrap()
            .canonical_reason()
            .unwrap();
        let expected = format!(
            "HTTP/1.1 {status} {reason}\r\nX-Request-ID: 0123456789abcdef-1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        assert_eq!(
            reject.response("0123456789abcdef-1"),
            Some(expected.into_bytes()),
            "{reject:?}"
        );
    }
    assert_eq!(
        (
            Reject::Closed.status(),
            Reject::Closed.response("0123456789abcdef-1")
        ),
        (None, None)
    );
}

fn runtime() -> Runtime {
    Builder::new_current_thread().enable_all().build().unwrap()
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

/// Checks that the head check takes a target exactly when hyper does, except that it also refuses a `#` and a
/// byte outside `0x21..=0x7e`. Returns whether the head check took it.
async fn guard_and_hyper_agree(listener: &TcpListener, target: &[u8]) -> bool {
    let shown = target.escape_ascii().to_string();
    let hyper = hyper_takes(listener, target).await;
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
    });
}
