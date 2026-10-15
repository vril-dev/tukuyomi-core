//! Reading and strictly checking the request head before hyper sees it.
//!
//! The head is read into a buffer of fixed size and parsed with `httparse` (default settings). The end of the
//! head is the end that `httparse` reports, not a search for a blank line. A head that parses is then held to
//! the rules below, in this order, and the first rule that is broken decides the answer:
//!
//! 1. Every LF is preceded by CR and every CR is followed by LF; the head does not start with an empty line.
//! 2. The method is 1 to 32 token bytes. The request target is origin-form: it starts with `/`, has 1 to 4096
//!    bytes and no `#`, and none of its bytes is one that hyper's URI parser refuses in that place (path or
//!    query), so hyper never answers for a head that passed. The version is `HTTP/1.1` (`HTTP/1.0` is answered
//!    with 505).
//! 3. At most 64 fields; a name has 1 to 256 bytes, a value (without the blanks around it) at most 4096, and the
//!    names and values together at most 24 KiB. A value has no control byte except HTAB.
//! 4. Exactly one non-empty `Host` without blank or control bytes.
//! 5. `Transfer-Encoding` and `Content-Length` together are refused. `Transfer-Encoding` is one line that is
//!    exactly `chunked`. `Content-Length` is one line of digits that fits in 64 bits and is not over the body
//!    limit.
//! 6. `Expect` is absent or one line that is exactly `100-continue`.
//! 7. `Connection` lines are comma separated lists of tokens (no empty element) that do not name `host`,
//!    `content-length`, `content-type` or `content-encoding`.
//! 8. `Content-Encoding` is refused. A body that is not empty needs exactly one `Content-Type` that is
//!    `application/x-www-form-urlencoded` or `multipart/form-data`; for a chunked body the caller applies the
//!    same rule once the body has been read.
//!
//! A refusal is a fixed answer with no body that closes the connection.

use std::io;
use std::ops::Range;

use bytes::Bytes;
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout_at};
use tukuyomi_kernel::limits;

/// The bounds the head rules need. Both come from the configuration.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Size of the head buffer. A head that does not fit is refused.
    pub max_head_bytes: usize,
    /// The largest `Content-Length` accepted.
    pub max_body: u64,
}

/// Why a head was refused. `Closed` is the one case with no answer: the peer is gone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    BadRequest,
    UriTooLong,
    FieldsTooLarge,
    ContentTooLarge,
    ExpectationFailed,
    VersionNotSupported,
    UnsupportedMedia,
    Timeout,
    Closed,
}

impl Reject {
    /// The status of the answer; `None` when the connection is closed without one.
    pub fn status(self) -> Option<u16> {
        match self {
            Reject::BadRequest => Some(400),
            Reject::UriTooLong => Some(414),
            Reject::FieldsTooLarge => Some(431),
            Reject::ContentTooLarge => Some(413),
            Reject::ExpectationFailed => Some(417),
            Reject::VersionNotSupported => Some(505),
            Reject::UnsupportedMedia => Some(415),
            Reject::Timeout => Some(408),
            Reject::Closed => None,
        }
    }

    /// The whole answer as it is written to the socket: the status line, `Content-Length: 0` and
    /// `Connection: close`, no body.
    pub fn response(self) -> Option<&'static [u8]> {
        match self {
            Reject::BadRequest => Some(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
            Reject::UriTooLong => Some(b"HTTP/1.1 414 URI Too Long\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
            Reject::FieldsTooLarge => Some(
                b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            ),
            Reject::ContentTooLarge => {
                Some(b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            }
            Reject::ExpectationFailed => {
                Some(b"HTTP/1.1 417 Expectation Failed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            }
            Reject::VersionNotSupported => {
                Some(b"HTTP/1.1 505 HTTP Version Not Supported\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            }
            Reject::UnsupportedMedia => {
                Some(b"HTTP/1.1 415 Unsupported Media Type\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            }
            Reject::Timeout => Some(b"HTTP/1.1 408 Request Timeout\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
            Reject::Closed => None,
        }
    }

    /// A fixed short text for the record.
    pub fn reason(self) -> &'static str {
        match self {
            Reject::BadRequest => "malformed request head",
            Reject::UriTooLong => "request target too long",
            Reject::FieldsTooLarge => "request head too large",
            Reject::ContentTooLarge => "body over the limit",
            Reject::ExpectationFailed => "expectation not supported",
            Reject::VersionNotSupported => "http version not supported",
            Reject::UnsupportedMedia => "body type not supported",
            Reject::Timeout => "head not received in time",
            Reject::Closed => "closed before the head was complete",
        }
    }
}

/// A head that passed every rule.
#[derive(Clone, Debug)]
pub struct Head {
    /// Every byte that was read: the head, then whatever followed it in the same reads.
    pub buf: Bytes,
    /// Length of the head. The bytes from here on in `buf` belong to the body.
    pub len: usize,
    method: Range<usize>,
    target: Range<usize>,
    /// Name and value of each field in the order received; the value is without the blanks around it.
    fields: Vec<(Range<usize>, Range<usize>)>,
    content_length: Option<u64>,
    chunked: bool,
    form_type: bool,
}

impl Head {
    pub fn method(&self) -> &[u8] {
        &self.buf[self.method.clone()]
    }

    pub fn target(&self) -> &[u8] {
        &self.buf[self.target.clone()]
    }

    /// The fields in the order received, as name and value.
    pub fn fields(&self) -> impl ExactSizeIterator<Item = (&[u8], &[u8])> {
        self.fields
            .iter()
            .map(|(name, value)| (&self.buf[name.clone()], &self.buf[value.clone()]))
    }

    /// The value of the one `Content-Length` line, if there is one.
    pub fn content_length(&self) -> Option<u64> {
        self.content_length
    }

    /// The body is chunked (`Transfer-Encoding` is exactly `chunked`).
    pub fn chunked(&self) -> bool {
        self.chunked
    }

    /// There is exactly one `Content-Type` and it is a form type that the inspection reads.
    pub fn form_type(&self) -> bool {
        self.form_type
    }
}

/// Parses the start of `buf`. `Ok(None)` means the head is not complete yet. This is pure: it reads nothing and
/// keeps no state.
pub fn parse(buf: &[u8], lim: &Limits) -> Result<Option<Head>, Reject> {
    Ok(scan(buf, lim)?.map(|head| Head {
        buf: Bytes::copy_from_slice(buf),
        ..head
    }))
}

/// Reads from `sock` until the head is complete. The head must end within `lim.max_head_bytes` bytes and before
/// `by`. The second value is what was read after the head.
pub async fn read(
    sock: &mut TcpStream,
    lim: &Limits,
    by: Instant,
) -> Result<(Head, Bytes), Reject> {
    let mut buf = vec![0u8; lim.max_head_bytes];
    let mut filled = 0;
    loop {
        if filled == buf.len() {
            // Without a line end the request line is still incomplete.
            return Err(if buf[..filled].contains(&b'\n') {
                Reject::FieldsTooLarge
            } else {
                Reject::UriTooLong
            });
        }
        match timeout_at(by, sock.readable()).await {
            Err(_) => return Err(Reject::Timeout),
            Ok(Err(_)) => return Err(Reject::Closed),
            Ok(Ok(())) => {}
        }
        let got = match sock.try_read(&mut buf[filled..]) {
            Ok(0) => return Err(Reject::Closed),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(_) => return Err(Reject::Closed),
        };
        let before = filled;
        filled += got;
        // The head can only become complete by a line feed, so a read without one is not parsed again. A full
        // buffer is parsed once more in any case.
        let may_be_complete = filled == buf.len() || buf[before..filled].contains(&b'\n');
        if may_be_complete && let Some(head) = scan(&buf[..filled], lim)? {
            buf.truncate(filled);
            let head = Head {
                buf: Bytes::from(buf),
                ..head
            };
            let rest = head.buf.slice(head.len..);
            return Ok((head, rest));
        }
    }
}

/// Where `part` lies inside `whole`; `part` must be a sub-slice of `whole`.
fn range_in(whole: &[u8], part: &[u8]) -> Option<Range<usize>> {
    let start = (part.as_ptr() as usize).checked_sub(whole.as_ptr() as usize)?;
    let end = start.checked_add(part.len())?;
    (end <= whole.len()).then_some(start..end)
}

/// The slice without leading and trailing SP and HTAB.
pub fn trim_ows(mut value: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = value {
        value = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = value {
        value = rest;
    }
    value
}

/// Every LF is preceded by CR and every CR is followed by LF.
fn crlf_only(head: &[u8]) -> bool {
    head.iter().enumerate().all(|(at, &b)| match b {
        b'\n' => at.checked_sub(1).and_then(|prev| head.get(prev)) == Some(&b'\r'),
        b'\r' => head.get(at + 1) == Some(&b'\n'),
        _ => true,
    })
}

/// An origin-form target: `/` first, then only bytes that hyper's URI parser takes. Up to the first `?` they are
/// the bytes of `path_byte`, after it those of `query_byte`. `#` is in neither: hyper would cut a fragment off
/// and go on, the guard refuses it.
fn origin_form(target: &[u8]) -> bool {
    let (path, query) = match target.iter().position(|&b| b == b'?') {
        Some(at) => (&target[..at], Some(&target[at + 1..])),
        None => (target, None),
    };
    path.first() == Some(&b'/')
        && path.iter().all(|&b| path_byte(b))
        && query.is_none_or(|rest| rest.iter().all(|&b| query_byte(b)))
}

/// A byte of the path of a target: visible ASCII except `#`, `<`, `>` and the backtick. The `?` that ends the path
/// is not part of it.
fn path_byte(b: u8) -> bool {
    matches!(b, 0x21 | 0x22 | 0x24..=0x3b | 0x3d | 0x40..=0x5f | 0x61..=0x7e)
}

/// A byte of the query of a target: visible ASCII except `"`, `#`, `<` and `>`.
fn query_byte(b: u8) -> bool {
    matches!(b, 0x21 | 0x24..=0x3b | 0x3d | 0x3f..=0x7e)
}

fn is_control(b: u8) -> bool {
    b <= 0x08 || (0x0a..=0x1f).contains(&b) || b == 0x7f
}

fn is_token(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Digits only and a value that fits in 64 bits (a leading `+` is not a digit).
fn parse_length(value: &[u8]) -> Option<u64> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(value).ok()?.parse().ok()
}

/// A `Connection` line: a list of tokens separated by commas, no empty element, and none of the names that
/// must stay with the request.
fn connection_ok(value: &[u8]) -> bool {
    const KEPT: [&[u8]; 4] = [
        b"host",
        b"content-length",
        b"content-type",
        b"content-encoding",
    ];
    value.split(|&b| b == b',').all(|item| {
        let item = trim_ows(item);
        !item.is_empty()
            && item.iter().all(|&b| is_token(b))
            && !KEPT.iter().any(|name| item.eq_ignore_ascii_case(name))
    })
}

/// The type of a body that the inspection reads. Same comparison as the kernel's: the part before the first `;`
/// without blanks, ASCII case ignored.
fn form_essence(value: &[u8]) -> bool {
    let essence = value
        .split(|&b| b == b';')
        .next()
        .unwrap_or_default()
        .trim_ascii();
    essence.eq_ignore_ascii_case(b"application/x-www-form-urlencoded")
        || essence.eq_ignore_ascii_case(b"multipart/form-data")
}

/// The rules. `buf` is what has been read so far; `Ok(None)` while the head is not complete. The result has an
/// empty `buf`; the caller puts the bytes in.
fn scan(buf: &[u8], lim: &Limits) -> Result<Option<Head>, Reject> {
    let mut storage = [httparse::EMPTY_HEADER; limits::HEADERS];
    let mut req = httparse::Request::new(&mut storage);
    let len = match req.parse(buf) {
        Ok(httparse::Status::Complete(len)) => len,
        Ok(httparse::Status::Partial) => return Ok(None),
        Err(httparse::Error::TooManyHeaders) => return Err(Reject::FieldsTooLarge),
        Err(_) => return Err(Reject::BadRequest),
    };
    let (Some(method), Some(target), Some(version)) = (req.method, req.path, req.version) else {
        return Err(Reject::BadRequest);
    };
    let (method, target) = (method.as_bytes(), target.as_bytes());

    // Rule 1.
    if !crlf_only(&buf[..len]) || matches!(buf.first(), Some(b'\r' | b'\n')) {
        return Err(Reject::BadRequest);
    }
    // Rule 2.
    if method.is_empty() || method.len() > limits::METHOD {
        return Err(Reject::BadRequest);
    }
    if target.len() > limits::URI {
        return Err(Reject::UriTooLong);
    }
    if !origin_form(target) {
        return Err(Reject::BadRequest);
    }
    match version {
        1 => {}
        0 => return Err(Reject::VersionNotSupported),
        _ => return Err(Reject::BadRequest),
    }
    let method_at = range_in(buf, method).ok_or(Reject::BadRequest)?;
    let target_at = range_in(buf, target).ok_or(Reject::BadRequest)?;

    // Rule 3: sizes first, then the bytes of the values.
    let mut fields = Vec::with_capacity(req.headers.len());
    let mut lines: Vec<(&[u8], &[u8])> = Vec::with_capacity(req.headers.len());
    let mut total = 0usize;
    for field in req.headers.iter() {
        let name = field.name.as_bytes();
        let value = trim_ows(field.value);
        if name.is_empty() || name.len() > limits::HEADER_NAME || value.len() > limits::HEADER_VALUE
        {
            return Err(Reject::FieldsTooLarge);
        }
        total = total
            .checked_add(name.len())
            .and_then(|sum| sum.checked_add(value.len()))
            .filter(|&sum| sum <= limits::HEADER_TOTAL)
            .ok_or(Reject::FieldsTooLarge)?;
        let name_at = range_in(buf, name).ok_or(Reject::BadRequest)?;
        let value_at = range_in(buf, value).ok_or(Reject::BadRequest)?;
        fields.push((name_at, value_at));
        lines.push((name, value));
    }
    if lines
        .iter()
        .any(|(_, value)| value.iter().any(|&b| is_control(b)))
    {
        return Err(Reject::BadRequest);
    }
    let named = |name: &'static [u8]| {
        lines
            .iter()
            .filter(move |(have, _)| have.eq_ignore_ascii_case(name))
            .map(|&(_, value)| value)
    };

    // Rule 4.
    let mut hosts = named(b"host");
    match (hosts.next(), hosts.next()) {
        (Some(host), None)
            if !host.is_empty()
                && !host
                    .iter()
                    .any(|&b| b == b' ' || is_control(b) || b == b'\t') => {}
        _ => return Err(Reject::BadRequest),
    }
    // Rule 5.
    let transfer: Vec<&[u8]> = named(b"transfer-encoding").collect();
    let lengths: Vec<&[u8]> = named(b"content-length").collect();
    if !transfer.is_empty() && !lengths.is_empty() {
        return Err(Reject::BadRequest);
    }
    let chunked = match transfer.as_slice() {
        [] => false,
        [value] if value.eq_ignore_ascii_case(b"chunked") => true,
        _ => return Err(Reject::BadRequest),
    };
    let content_length = match lengths.as_slice() {
        [] => None,
        [value] => Some(parse_length(value).ok_or(Reject::BadRequest)?),
        _ => return Err(Reject::BadRequest),
    };
    if content_length.is_some_and(|n| n > lim.max_body) {
        return Err(Reject::ContentTooLarge);
    }
    // Rule 6.
    let mut expects = named(b"expect");
    match (expects.next(), expects.next()) {
        (None, _) => {}
        (Some(value), None) if value.eq_ignore_ascii_case(b"100-continue") => {}
        _ => return Err(Reject::ExpectationFailed),
    }
    // Rule 7.
    if !named(b"connection").all(connection_ok) {
        return Err(Reject::BadRequest);
    }
    // Rule 8.
    if named(b"content-encoding").next().is_some() {
        return Err(Reject::UnsupportedMedia);
    }
    let types: Vec<&[u8]> = named(b"content-type").collect();
    let form_type = matches!(types.as_slice(), [value] if form_essence(value));
    if content_length.is_some_and(|n| n > 0) && !form_type {
        return Err(Reject::UnsupportedMedia);
    }

    Ok(Some(Head {
        buf: Bytes::new(),
        len,
        method: method_at,
        target: target_at,
        fields,
        content_length,
        chunked,
        form_type,
    }))
}

#[cfg(test)]
mod tests {
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
        assert!(head.form_type());
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
    fn content_encoding_is_not_supported() {
        assert_eq!(
            refused(&head_with(&["Content-Encoding: gzip"])),
            Reject::UnsupportedMedia
        );
        assert_eq!(
            refused(&head_with(&["content-encoding: identity"])),
            Reject::UnsupportedMedia
        );
        assert_eq!(
            refused(&head_with(&[
                "Content-Encoding: gzip",
                "Content-Length: 1",
                FORM
            ])),
            Reject::UnsupportedMedia
        );
        ok(&head_with(&["Content-Language: en"]));
    }

    #[test]
    fn a_body_needs_exactly_one_form_content_type() {
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
        for lines in [
            &[][..],
            &["Content-Type: text/plain"],
            &["Content-Type: application/json"],
            &["Content-Type: application/x-www-form-urlencodedx"],
            &["Content-Type:"],
            &["Content-Type: multipart/form-data, text/plain"],
            &[FORM, FORM],
            &[FORM, "Content-Type: text/plain"],
        ] {
            assert_eq!(
                refused(&lengthy(lines)),
                Reject::UnsupportedMedia,
                "lines {lines:?}"
            );
        }
        // No body: no type needed, and the flag says what the type is.
        assert!(!ok(&head_with(&["Content-Length: 0"])).form_type());
        assert!(ok(&head_with(&["Content-Length: 0", FORM])).form_type());
        assert!(!ok(&head_with(&["Content-Type: text/plain"])).form_type());
        // A chunked body is checked by the caller once it knows the body is not empty.
        let chunked = ok(&head_with(&[
            "Transfer-Encoding: chunked",
            "Content-Type: text/plain",
        ]));
        assert!(chunked.chunked() && !chunked.form_type());
        assert!(ok(&head_with(&["Transfer-Encoding: chunked", FORM])).form_type());
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
        let raw = head_with(&["Expect: nope", "Connection: host", "Content-Encoding: gzip"]);
        assert_eq!(refused(&raw), Reject::ExpectationFailed);
        let raw = head_with(&["Connection: host", "Content-Encoding: gzip"]);
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

    /// Sends a GET for `target` (the rest of the head is valid) to a hyper server set up as the front sets it up:
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
}
