//! Strictly checking a request head before hyper sees it.
//!
//! The head is parsed with `httparse` (default settings). The end of the head is the end that `httparse`
//! reports, not a search for a blank line. A head that parses is then held to the rules below, in this order, and
//! the first rule that is broken decides the answer:
//!
//! 1. Every LF is preceded by CR and every CR is followed by LF; the head does not start with an empty line.
//! 2. The method is 1 to 32 token bytes and is not `CONNECT` (a tunnel to a host is not something this proxy
//!    makes). The request target is origin-form: it starts with `/`, has 1 to 4096
//!    bytes and no `#`, and none of its bytes is one that hyper's URI parser refuses in that place (path or
//!    query), so hyper never answers for a head that passed. The version is `HTTP/1.1` or `HTTP/1.0`.
//! 3. At most 64 fields; a name has 1 to 256 bytes, a value (without the blanks around it) at most 4096, and the
//!    names and values together at most 24 KiB. A value has no control byte except HTAB.
//! 4. Exactly one non-empty `Host` without blank or control bytes.
//! 5. `Transfer-Encoding` and `Content-Length` together are refused. `Transfer-Encoding` is one line that is
//!    exactly `chunked`, and an `HTTP/1.0` request has none. `Content-Length` is one line of digits that fits in
//!    64 bits and is not over the body limit.
//! 6. `Expect` is absent or one line that is exactly `100-continue`.
//! 7. `Connection` lines are comma separated lists of tokens (no empty element) that do not name `host`,
//!    `content-length`, `content-type` or `content-encoding`. A head with an `Upgrade` line is marked `upgrade`,
//!    and one that is a WebSocket handshake is marked `websocket` too (see `Head::websocket`).
//! 8. `Content-Encoding` is absent, or one line that is exactly `gzip` (ASCII case ignored); any other value, a
//!    list and a repeated line are refused with 415. A gzip body that is empty on its face (`Content-Length: 0`,
//!    or no body framing at all) is refused with 400, for it is not a gzip stream; for a chunked body the caller
//!    applies that rule once the body has been read. A body that is not empty needs exactly one `Content-Type` that
//!    is `application/x-www-form-urlencoded`, `multipart/form-data`, `application/json` or
//!    `application/<name>+json` (the name is described at `inspectable_essence`); for a chunked body the caller
//!    applies the same rule once the body has been read.
//!
//! A refusal is a fixed answer with no body that closes the connection. It has the number of the request in an
//! `X-Request-ID` field, so a client that was refused can name it.
//!
//! The fields of a request of an HTTP/2 stream are first written as the bytes of an HTTP/1.1 head (see
//! `http2::head`) and then checked by the same rules; the `Head` that results is marked as made from HTTP/2.

use std::ops::Range;

use bytes::Bytes;
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
            Reject::UnsupportedMedia => Some(415),
            Reject::Timeout => Some(408),
            Reject::Closed => None,
        }
    }

    /// The whole answer as it is written to the socket: the status line, the number `id` of the request in an
    /// `X-Request-ID` field, `Content-Length: 0` and `Connection: close`, no body.
    pub fn response(self, id: &str) -> Option<Vec<u8>> {
        let status = match self {
            Reject::BadRequest => "400 Bad Request",
            Reject::UriTooLong => "414 URI Too Long",
            Reject::FieldsTooLarge => "431 Request Header Fields Too Large",
            Reject::ContentTooLarge => "413 Payload Too Large",
            Reject::ExpectationFailed => "417 Expectation Failed",
            Reject::UnsupportedMedia => "415 Unsupported Media Type",
            Reject::Timeout => "408 Request Timeout",
            Reject::Closed => return None,
        };
        Some(
            format!(
                "HTTP/1.1 {status}\r\nX-Request-ID: {id}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .into_bytes(),
        )
    }

    /// A fixed short text for the record.
    pub fn reason(self) -> &'static str {
        match self {
            Reject::BadRequest => "malformed request head",
            Reject::UriTooLong => "request target too long",
            Reject::FieldsTooLarge => "request head too large",
            Reject::ContentTooLarge => "body over the limit",
            Reject::ExpectationFailed => "expectation not supported",
            Reject::UnsupportedMedia => "body type not supported",
            Reject::Timeout => "head not received in time",
            Reject::Closed => "closed before the head was complete",
        }
    }
}

/// A head that passed every rule.
#[derive(Clone, Debug)]
pub struct Head {
    /// The bytes of the head, from the request line to the blank line.
    pub buf: Bytes,
    /// Length of the head, which is the length of `buf`.
    pub len: usize,
    method: Range<usize>,
    target: Range<usize>,
    /// Name and value of each field in the order received; the value is without the blanks around it.
    fields: Vec<(Range<usize>, Range<usize>)>,
    http10: bool,
    content_length: Option<u64>,
    chunked: bool,
    close: bool,
    upgrade: bool,
    websocket: bool,
    gzip: bool,
    inspectable_type: bool,
    http2: bool,
}

impl Head {
    pub fn method(&self) -> &[u8] {
        &self.buf[self.method.clone()]
    }

    pub fn target(&self) -> &[u8] {
        &self.buf[self.target.clone()]
    }

    /// The value of the `Host` field. The head check has made sure that there is exactly one.
    pub fn host(&self) -> Option<&[u8]> {
        self.fields()
            .find(|(name, _)| name.eq_ignore_ascii_case(b"host"))
            .map(|(_, value)| value)
    }

    /// The fields in the order received, as name and value.
    pub fn fields(&self) -> impl ExactSizeIterator<Item = (&[u8], &[u8])> {
        self.fields
            .iter()
            .map(|(name, value)| (&self.buf[name.clone()], &self.buf[value.clone()]))
    }

    /// The request is HTTP/1.0. The connection closes after its response.
    pub fn http10(&self) -> bool {
        self.http10
    }

    /// The protocol as the inspection is told: `HTTP/1.0`, `HTTP/1.1`, or `HTTP/2.0` for the head of a stream.
    pub fn proto(&self) -> &'static [u8] {
        if self.http2 {
            b"HTTP/2.0"
        } else if self.http10 {
            b"HTTP/1.0"
        } else {
            b"HTTP/1.1"
        }
    }

    /// The head was made from the fields of an HTTP/2 stream.
    pub fn into_http2(self) -> Head {
        Head {
            http2: true,
            ..self
        }
    }

    /// The value of the one `Content-Length` line, if there is one.
    pub fn content_length(&self) -> Option<u64> {
        self.content_length
    }

    /// The body is chunked (`Transfer-Encoding` is exactly `chunked`).
    pub fn chunked(&self) -> bool {
        self.chunked
    }

    /// A `Connection` line names `close`: the client asks for the connection to end after the response.
    pub fn close(&self) -> bool {
        self.close
    }

    /// There is an `Upgrade` line. The head is the last one of its connection: whatever the client sends behind it
    /// is not a request, whether the upstream switches protocols or not.
    pub fn upgrade(&self) -> bool {
        self.upgrade
    }

    /// The head asks for a WebSocket: a `GET` of HTTP/1.1 with no body, exactly one `Upgrade` line that is
    /// `websocket` (ASCII case ignored), a `Connection` line that lists `upgrade` and none that lists `close`.
    pub fn websocket(&self) -> bool {
        self.websocket
    }

    /// The body is gzip coded (`Content-Encoding` is exactly `gzip`). The caller decodes it before the
    /// inspection and the forwarding, so the body that is inspected is the decoded one.
    pub fn gzip(&self) -> bool {
        self.gzip
    }

    /// There is exactly one `Content-Type` and its type is one that the inspection reads (urlencoded,
    /// multipart or JSON).
    pub fn inspectable_type(&self) -> bool {
        self.inspectable_type
    }
}

/// Parses the start of `buf`; what follows the head is not looked at and not kept. `Ok(None)` means the head is
/// not complete yet. This is pure: it reads nothing and keeps no state.
pub fn parse(buf: &[u8], lim: &Limits) -> Result<Option<Head>, Reject> {
    Ok(scan(buf, lim)?.map(|head| Head {
        buf: Bytes::copy_from_slice(&buf[..head.len]),
        ..head
    }))
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

/// A `Connection` line that lists `token`, ASCII case ignored.
fn lists(value: &[u8], token: &[u8]) -> bool {
    value
        .split(|&b| b == b',')
        .any(|item| trim_ows(item).eq_ignore_ascii_case(token))
}

/// The type of a body that the inspection reads: urlencoded, multipart or JSON. Same comparison as the kernel's:
/// the part before the first `;` without blanks, ASCII case ignored. The first three types are equal to the whole
/// name (so `application/jsonp` and `text/json` are not JSON). The fourth is `application/<name>+json`, see
/// `is_json_suffix_type` (so `text/x+json` and `application/x+jsonp` are not JSON either).
fn inspectable_essence(value: &[u8]) -> bool {
    let essence = value
        .split(|&b| b == b';')
        .next()
        .unwrap_or_default()
        .trim_ascii();
    essence.eq_ignore_ascii_case(b"application/x-www-form-urlencoded")
        || essence.eq_ignore_ascii_case(b"multipart/form-data")
        || essence.eq_ignore_ascii_case(b"application/json")
        || is_json_suffix_type(essence)
}

/// `application/<name>+json`, ASCII case ignored. The name has 1 to 122 bytes: the first is an ASCII letter or
/// digit, the others ASCII letters, digits, `.` or `-`. A name that starts with `x-www-form-urlencoded` is
/// refused: the inspection takes any type that starts with `application/x-www-form-urlencoded` for urlencoded,
/// so such a body would not be read as JSON.
fn is_json_suffix_type(essence: &[u8]) -> bool {
    const NAME_MAX: usize = 122;
    const FORM: &[u8] = b"x-www-form-urlencoded";
    let Some((prefix, rest)) = essence.split_at_checked(b"application/".len()) else {
        return false;
    };
    let Some(cut) = rest.len().checked_sub(b"+json".len()) else {
        return false;
    };
    let (name, suffix) = rest.split_at(cut);
    prefix.eq_ignore_ascii_case(b"application/")
        && suffix.eq_ignore_ascii_case(b"+json")
        && (1..=NAME_MAX).contains(&name.len())
        && name.first().is_some_and(u8::is_ascii_alphanumeric)
        && name
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        && !name
            .get(..FORM.len())
            .is_some_and(|start| start.eq_ignore_ascii_case(FORM))
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
    if method.is_empty() || method.len() > limits::METHOD || method == b"CONNECT" {
        return Err(Reject::BadRequest);
    }
    if target.len() > limits::URI {
        return Err(Reject::UriTooLong);
    }
    if !origin_form(target) {
        return Err(Reject::BadRequest);
    }
    let http10 = match version {
        1 => false,
        0 => true,
        _ => return Err(Reject::BadRequest),
    };
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
    if http10 && !transfer.is_empty() {
        return Err(Reject::BadRequest);
    }
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
    let close = named(b"connection").any(|value| lists(value, b"close"));
    let upgrades: Vec<&[u8]> = named(b"upgrade").collect();
    // Rule 8.
    let codings: Vec<&[u8]> = named(b"content-encoding").collect();
    let gzip = match codings.as_slice() {
        [] => false,
        [value] if value.eq_ignore_ascii_case(b"gzip") => true,
        _ => return Err(Reject::UnsupportedMedia),
    };
    // A chunked body is not known to be empty before it has been read; every other body is.
    if gzip && !chunked && content_length.is_none_or(|n| n == 0) {
        return Err(Reject::BadRequest);
    }
    let types: Vec<&[u8]> = named(b"content-type").collect();
    let inspectable_type = matches!(types.as_slice(), [value] if inspectable_essence(value));
    if content_length.is_some_and(|n| n > 0) && !inspectable_type {
        return Err(Reject::UnsupportedMedia);
    }

    let websocket = method == b"GET"
        && !http10
        && !chunked
        && content_length.is_none_or(|n| n == 0)
        && !close
        && matches!(upgrades.as_slice(), [value] if value.eq_ignore_ascii_case(b"websocket"))
        && named(b"connection").any(|value| lists(value, b"upgrade"));

    Ok(Some(Head {
        buf: Bytes::new(),
        len,
        method: method_at,
        target: target_at,
        fields,
        http10,
        content_length,
        chunked,
        close,
        upgrade: !upgrades.is_empty(),
        websocket,
        gzip,
        inspectable_type,
        http2: false,
    }))
}

#[cfg(test)]
mod tests;
