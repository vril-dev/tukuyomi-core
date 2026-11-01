//! The request body processor that the Content-Type of a request asks for.

use crate::ffi::Processor;

/// The space characters of the C library (`isspace` in the C locale), which is what the library reads the
/// Content-Type with.
fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

fn trim(mut bytes: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = bytes
        && is_space(*first)
    {
        bytes = rest;
    }
    while let [rest @ .., last] = bytes
        && is_space(*last)
    {
        bytes = rest;
    }
    bytes
}

/// The type of a multipart body, and the name of the parameter that holds its boundary.
const MULTIPART: &[u8] = b"multipart/form-data";
const BOUNDARY: &[u8] = b"boundary";

/// The longest Content-Type value that the multipart reader of the library takes.
const MULTIPART_VALUE_LIMIT: usize = 1024;

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// How many times `boundary` is written, in any case, with a `=` somewhere after it (`count_boundary_params`,
/// `multipart.cc` line 1345).
fn boundary_parameters(header: &[u8]) -> usize {
    let lower = header.to_ascii_lowercase();
    let mut rest = lower.as_slice();
    let mut count = 0;
    while let Some(at) = find(rest, BOUNDARY) {
        rest = &rest[at + BOUNDARY.len()..];
        if rest.contains(&b'=') {
            count += 1;
        }
    }
    count
}

/// Whether the library skips the body of a multipart request without a word.
///
/// The library reads a multipart body with `Multipart::init` and the parser after it (libmodsecurity 3.0.17,
/// `src/request_body_processor/multipart.cc`, line 1362 on), and `init` reads the boundary from the Content-Type.
/// Every way it can refuse the header sets an error text, which becomes `REQBODY_ERROR`, except two: a boundary
/// that is empty, whether it is quoted (line 1474) or not (line 1492). There it returns false and sets nothing,
/// the body is never parsed, and the library goes on as if it had been parsed without a problem. The library
/// has nothing that tells a body that was not parsed from one that was: it sets every `MULTIPART_*` variable to 0
/// either way, and a multipart body with no parts is a legitimate one. So the two are told from the header, by the
/// steps of `init` in their order, and this is true only where `init` returns at one of those two lines. At any
/// other refusal it is false, because the library flags that and the inspection blocks it.
///
/// `value` is the header as the library gets it, not trimmed. The library measures it as a string of bytes in its
/// first two checks and reads it as a C string after that, so a NUL byte ends it for every other step.
fn multipart_is_skipped(value: &[u8]) -> bool {
    // Lines 1369-1382: no header, and one longer than the limit.
    if value.is_empty() || value.len() > MULTIPART_VALUE_LIMIT {
        return false;
    }
    let header = value.split(|&byte| byte == 0).next().unwrap_or_default();
    // Lines 1385-1389: a type other than `multipart/form-data`, compared without case, over its length.
    let Some((kind, after_kind)) = header.split_at_checked(MULTIPART.len()) else {
        return false;
    };
    if !kind.eq_ignore_ascii_case(MULTIPART) {
        return false;
    }
    // Lines 1393-1398: more than one `boundary` parameter.
    if boundary_parameters(header) > 1 {
        return false;
    }
    // Line 1401: the first `boundary` written in lower case (the type has no `b`, so the search starts after it).
    let Some(at) = find(after_kind, BOUNDARY) else {
        return false;
    };
    let (before, from_name) = after_kind.split_at(at);
    // Lines 1410-1425: before the name there are only white space and one `;`.
    let mut others = before.iter().filter(|&&byte| !is_space(byte));
    if !matches!(
        (others.next(), others.next()),
        (None, _) | (Some(b';'), None)
    ) {
        return false;
    }
    // Lines 1432-1460: a `=` after the name, with only white space between them.
    let after_name = &from_name[BOUNDARY.len()..];
    let Some(equals) = after_name.iter().position(|&byte| byte == b'=') else {
        return false;
    };
    if !after_name[..equals].iter().all(|&byte| is_space(byte)) {
        return false;
    }
    // Lines 1462-1493: what is left is the boundary. In quotes that hold nothing (line 1474), or with no quotes
    // and nothing (line 1492), the library returns without a word. A quote on one side only, and any boundary that
    // holds something, are refused or taken further on.
    let boundary = &after_name[equals + 1..];
    boundary.is_empty() || boundary == b"\"\""
}

/// The processor that the Content-Type header picks. The value is read trimmed and in lower case, and compared by
/// its start: a URL-encoded form, a multipart form, and JSON, which is `application/json` and any
/// `application/<name>+json`. Anything else, a request with no Content-Type, and a request with more than one
/// picks none, and a request with a body and no processor is not let through (`transaction`). So does a multipart
/// request whose boundary is empty, which the library does not parse (`multipart_is_skipped`).
///
/// More than one Content-Type is not settled by taking one of them. The library reads the boundary of a multipart
/// body from the last, so a processor chosen from another could disagree with it about where the parts of the body
/// are, and values of the body would be hidden from the rules.
pub(super) fn choose(headers: &[(&[u8], &[u8])]) -> Processor {
    let mut types = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(b"content-type"));
    let (Some((_, raw)), None) = (types.next(), types.next()) else {
        return Processor::None;
    };
    let value = trim(raw).to_ascii_lowercase();
    let essence = trim(value.split(|&byte| byte == b';').next().unwrap_or_default());
    if value.starts_with(b"application/x-www-form-urlencoded") {
        Processor::UrlEncoded
    } else if value.starts_with(MULTIPART) {
        if multipart_is_skipped(raw) {
            Processor::None
        } else {
            Processor::Multipart
        }
    } else if value.starts_with(b"application/json")
        || (essence.starts_with(b"application/") && essence.ends_with(b"+json"))
    {
        Processor::Json
    } else {
        Processor::None
    }
}
