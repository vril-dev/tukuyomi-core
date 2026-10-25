//! The checks of the head of an answer of the upstream. A head that does not pass is `OriginError::Invalid`.
//!
//! `check_head` is for the final response of a request: its framing must be clear, its `Connection` lines must be
//! lists of tokens, and what belongs to the connection with the upstream is taken out. `check_switch` is for the 101
//! that answers the handshake of a WebSocket. `lasts` tells whether the connection with the upstream can carry
//! another request after the answer.

use http::header::{
    CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, TRANSFER_ENCODING,
    UPGRADE,
};
use http::response::Parts;
use http::{Extensions, HeaderMap, HeaderName, HeaderValue, StatusCode, Version};

use super::OriginError;
use super::fields::{RESPONSE_HOP, listed};
use crate::inbound::head::trim_ows;

/// Digits only and a value that fits in 64 bits (a leading `+` is not a digit).
pub(super) fn is_length(value: &[u8]) -> bool {
    !value.is_empty()
        && value.iter().all(u8::is_ascii_digit)
        && std::str::from_utf8(value).is_ok_and(|digits| digits.parse::<u64>().is_ok())
}

/// The only line of `name`, if there is one; more than one line is refused whatever the lines say.
pub(super) fn single<'a>(
    headers: &'a HeaderMap,
    name: &HeaderName,
) -> Result<Option<&'a HeaderValue>, OriginError> {
    let mut lines = headers.get_all(name).iter();
    let first = lines.next();
    if lines.next().is_some() {
        return Err(OriginError::Invalid);
    }
    Ok(first)
}

/// Takes out of the fields of an answer what belongs to the connection with the upstream: the names listed in its
/// `Connection` lines, which must be tokens and must not be a name that describes the body, and the hop-by-hop
/// fields.
pub(super) fn unlist(headers: &mut HeaderMap) -> Result<(), OriginError> {
    // The names are removed as the lines are read. An answer that is refused is not used at all, so this is the
    // same as removing them afterwards, and no list of names is built from what the upstream sent.
    let lines: Vec<HeaderValue> = headers.get_all(CONNECTION).iter().cloned().collect();
    for line in &lines {
        for name in listed(line) {
            let name = name.map_err(|_| OriginError::Invalid)?;
            if name == CONTENT_LENGTH
                || name == CONTENT_TYPE
                || name == CONTENT_ENCODING
                || name == CONTENT_RANGE
            {
                return Err(OriginError::Invalid);
            }
            headers.remove(&name);
        }
    }
    for name in RESPONSE_HOP {
        headers.remove(name);
    }
    Ok(())
}

/// Checks the head of the final response and takes out what belongs to the connection with the upstream.
/// `head_request` is true when the request was a HEAD request. The checked `Content-Length` of the upstream stays
/// in the head for a HEAD request and for a 304 only; otherwise it goes, and hyper sets the length from the body it
/// sends. hyper's server writes a kept length only in the answer to a HEAD request: a 304 to any other request goes
/// out without one.
pub(super) fn check_head(parts: &mut Parts, head_request: bool) -> Result<(), OriginError> {
    if !(200..=599).contains(&parts.status.as_u16()) {
        return Err(OriginError::Invalid);
    }
    let headers = &mut parts.headers;
    match (
        single(headers, &TRANSFER_ENCODING)?,
        single(headers, &CONTENT_LENGTH)?,
    ) {
        (Some(_), Some(_)) => return Err(OriginError::Invalid),
        (Some(coding), None) if !coding.as_bytes().eq_ignore_ascii_case(b"chunked") => {
            return Err(OriginError::Invalid);
        }
        (None, Some(length)) if !is_length(length.as_bytes()) => return Err(OriginError::Invalid),
        _ => {}
    }
    unlist(headers)?;
    if !head_request && parts.status != StatusCode::NOT_MODIFIED {
        headers.remove(CONTENT_LENGTH);
    }
    parts.version = Version::HTTP_11;
    parts.extensions = Extensions::new();
    Ok(())
}

/// Checks the head of the 101 that answers the handshake of a WebSocket, and makes it the head that the client gets:
/// `Connection: upgrade` and `Upgrade: websocket` as fixed values, no length, the other fields as they are. The
/// answer must have exactly one `Upgrade` line that is `websocket` (ASCII case ignored) and list `upgrade` in its
/// `Connection` lines; any other 101 is refused.
pub(super) fn check_switch(parts: &mut Parts) -> Result<(), OriginError> {
    let headers = &mut parts.headers;
    let websocket = single(headers, &UPGRADE)?
        .is_some_and(|line| trim_ows(line.as_bytes()).eq_ignore_ascii_case(b"websocket"));
    let upgrades = headers
        .get_all(CONNECTION)
        .iter()
        .flat_map(listed)
        .any(|name| name.is_ok_and(|name| name == UPGRADE));
    if !websocket || !upgrades {
        return Err(OriginError::Invalid);
    }
    unlist(headers)?;
    headers.remove(CONTENT_LENGTH);
    headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
    headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
    parts.version = Version::HTTP_11;
    parts.extensions = Extensions::new();
    Ok(())
}

/// True when nothing in the head of the answer ends the connection with the upstream: it is HTTP/1.1, no
/// `Connection` line lists `close` or `upgrade`, and the body is not the bytes up to the end of the connection
/// (the answer to a HEAD request, a 204 and a 304 have none, the others say how long they are).
pub(super) fn lasts(parts: &Parts, head_request: bool) -> bool {
    let framed = head_request
        || matches!(parts.status.as_u16(), 204 | 304)
        || parts.headers.contains_key(CONTENT_LENGTH)
        || parts.headers.contains_key(TRANSFER_ENCODING);
    framed
        && parts.version == Version::HTTP_11
        && !parts
            .headers
            .get_all(CONNECTION)
            .iter()
            .flat_map(listed)
            .any(|name| name.is_ok_and(|name| name == "close" || name == "upgrade"))
}
