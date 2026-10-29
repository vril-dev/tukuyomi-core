//! The head of a request of an HTTP/2 stream, as the head of an HTTP/1.1 request.
//!
//! The pseudo fields and the fields of the stream are written as the bytes of an HTTP/1.1 head, and `head::parse`
//! checks those bytes with the rules of every other request (so `CONNECT`, which has no `:path`, and `OPTIONS *` are
//! refused there). The head is written like this:
//! - The request line has the method and the path with its query (`:path`) and nothing else; `:scheme` is dropped.
//! - The `Host` line comes first. It is the `:authority` if the stream has one, and then a `host` field has to be the
//!   same name (ASCII case ignored) or be absent; a stream with no `:authority` needs exactly one `host` field. Two
//!   `host` fields, a `host` that is not the `:authority`, no name at all, and an `:authority` with a user
//!   information in it (`@`) are refused with 400: the name that the routes, the certificate check and the
//!   upstream see must be one.
//! - The `cookie` fields are one line, joined with `; ` (RFC 9113, 8.2.3); every other field is copied as it is.
//!   A value with a CR, an LF or a NUL in it is refused, although h2 has refused such a stream before.
//! - A stream whose `HEADERS` frame did not end it, and that has no `content-length`, gets
//!   `Transfer-Encoding: chunked`, for the rules of the head and the reading of the body to take it for a body whose
//!   end is not known. The client sent no such field (h2 refuses one), so the inspection is not shown it (see
//!   `represent`). A `content-length` is kept: h2 has made sure that the data frames are as long, and the rule on
//!   the size of the body can answer before the body is read.
//! - A head of more than `max_head_bytes` is refused with 431.
//!
//! The target that the upstream is sent is the one of the head, in origin-form: the `uri` of the request that h2
//! made has the scheme and the name in front of the path.

use http::header::{CONTENT_LENGTH, COOKIE, HOST};
use http::request::Parts;
use http::{HeaderName, Uri};

use crate::inbound::head::{self, Head, Limits, Reject};

/// The head of the request of `parts`. `no_body` is true when the `HEADERS` frame of the stream ended it, so that no
/// body follows.
pub(super) fn build(parts: &Parts, no_body: bool, limits: &Limits) -> Result<Head, Reject> {
    let target = parts
        .uri
        .path_and_query()
        .ok_or(Reject::BadRequest)?
        .as_str();
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(parts.method.as_str().as_bytes());
    out.push(b' ');
    out.extend_from_slice(target.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    out.extend_from_slice(host(parts)?);
    out.extend_from_slice(b"\r\n");
    let mut length = false;
    for name in parts.headers.keys() {
        if name == HOST {
            continue;
        }
        if name == COOKIE {
            let joined: Vec<&[u8]> = parts
                .headers
                .get_all(COOKIE)
                .iter()
                .map(|value| value.as_bytes())
                .collect();
            line(&mut out, name, &joined.join(&b"; "[..]), limits)?;
            continue;
        }
        length |= name == CONTENT_LENGTH;
        for value in parts.headers.get_all(name) {
            line(&mut out, name, value.as_bytes(), limits)?;
        }
    }
    if !length && !no_body {
        out.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
    }
    out.extend_from_slice(b"\r\n");
    if out.len() > limits.max_head_bytes {
        return Err(Reject::FieldsTooLarge);
    }
    match head::parse(&out, limits)? {
        Some(head) => Ok(head.into_http2()),
        None => Err(Reject::BadRequest),
    }
}

/// The name of the `Host` line (see the module documentation).
fn host(parts: &Parts) -> Result<&[u8], Reject> {
    let authority = parts.uri.authority().map(|authority| authority.as_str());
    let mut hosts = parts.headers.get_all(HOST).iter();
    match (authority, hosts.next(), hosts.next()) {
        (Some(authority), _, _) if authority.contains('@') => Err(Reject::BadRequest),
        (Some(authority), None, _) => Ok(authority.as_bytes()),
        (Some(authority), Some(host), None)
            if host.as_bytes().eq_ignore_ascii_case(authority.as_bytes()) =>
        {
            Ok(authority.as_bytes())
        }
        (None, Some(host), None) => Ok(host.as_bytes()),
        _ => Err(Reject::BadRequest),
    }
}

/// Adds the line of a field to the head; the head is cut off as soon as it is over the size.
fn line(out: &mut Vec<u8>, name: &HeaderName, value: &[u8], limits: &Limits) -> Result<(), Reject> {
    if value.iter().any(|&b| matches!(b, b'\r' | b'\n' | 0)) {
        return Err(Reject::BadRequest);
    }
    out.extend_from_slice(name.as_str().as_bytes());
    out.extend_from_slice(b": ");
    out.extend_from_slice(value);
    out.extend_from_slice(b"\r\n");
    if out.len() > limits.max_head_bytes {
        return Err(Reject::FieldsTooLarge);
    }
    Ok(())
}

/// The `uri` of the request for the upstream: the target of the head in origin-form.
pub(super) fn upstream_uri(head: &Head) -> Result<Uri, Reject> {
    Uri::try_from(head.target()).map_err(|_| Reject::BadRequest)
}

#[cfg(test)]
mod tests;
