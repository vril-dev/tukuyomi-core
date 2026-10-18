//! The form of the request that is inspected and forwarded, and the decoding of a gzip body.
//!
//! A field whose name has an underscore is dropped where the fields of the head become the fields of the request:
//! it is neither inspected nor forwarded, whoever the peer is. Many servers behind a proxy read `X_Forwarded_For`
//! and `X-Forwarded-For` as the same variable, so a client could use that name to speak for the address that the
//! proxy sets. A server that does not accept underscores in field names does the same. The head check is not
//! changed.

use std::io::Read;

use bytes::Bytes;
use flate2::bufread::GzDecoder;
use http::header::{CONTENT_ENCODING, CONTENT_LENGTH, HOST, TRANSFER_ENCODING};
use http::{HeaderMap, HeaderName, HeaderValue};
use tukuyomi_kernel::limits;

use crate::inbound::answer::Reply;
use crate::inbound::head::{Head, Reject};

/// Decodes `coded` as exactly one gzip member. The output is cut at one byte over `max`, so a stream that decodes
/// to more than that is 413 without being decoded further. A stream that is not valid, that ends early or whose
/// CRC or length does not match, and any byte after the member, are 400. The answers carry fixed texts, never the
/// text of the decoder's error. The decoder keeps the header fields (at most 64 KiB each) and the state of the
/// inflater, a few tens of KiB, until this returns; they are not counted in the byte budget.
pub(super) fn gunzip(coded: &[u8], max: usize) -> Result<Vec<u8>, Reply> {
    let mut decoder = GzDecoder::new(coded);
    let mut plain = Vec::new();
    let cut = u64::try_from(max).map_or(u64::MAX, |max| max.saturating_add(1));
    decoder
        .by_ref()
        .take(cut)
        .read_to_end(&mut plain)
        .map_err(|_| Reply::rejected(400, "malformed gzip body"))?;
    if plain.len() > max {
        return Err(Reply::rejected(413, "decoded body over the limit"));
    }
    if !decoder.into_inner().is_empty() {
        return Err(Reply::rejected(400, "data after the gzip member"));
    }
    // The vector grew by doubling; the budget counts the length, so the memory held is that length.
    plain.shrink_to_fit();
    Ok(plain)
}

/// The request as it is inspected and, unchanged, forwarded.
pub(super) struct Represented {
    /// The fields in the order received; this is the one map the forwarding is made from.
    pub(super) fields: HeaderMap,
    /// What the inspection gets: `Host` first, then the others in the order received.
    pub(super) headers: Vec<(Bytes, Bytes)>,
    /// Bytes of all names and values of `headers`.
    pub(super) field_bytes: usize,
}

/// A field name the way hyper writes it: the first letter and each letter after a hyphen in upper case.
fn title_case(name: &str) -> Bytes {
    let mut out = Vec::with_capacity(name.len());
    let mut upper = true;
    for &b in name.as_bytes() {
        out.push(if upper {
            b.to_ascii_uppercase()
        } else {
            b.to_ascii_lowercase()
        });
        upper = b == b'-';
    }
    Bytes::from(out)
}

/// Builds the inspected and forwarded form of the request, whose body is `body_len` bytes once decoded. A field
/// with an underscore in its name is left out. The changes to the framing: a chunked request loses its
/// `Transfer-Encoding` and gets a `Content-Length` of the decoded length; a gzip request loses its
/// `Content-Encoding` and its `Content-Length` (if it has one) and gets one `Content-Length` of the decoded
/// length, last like a chunked one; a POST, PUT or PATCH with neither gets `Content-Length: 0`. The limits of the
/// kernel are checked on the result, so a request that fit before the change and not after it is refused here and
/// never reaches the kernel.
pub(super) fn represent(head: &Head, body_len: usize) -> Result<Represented, Reject> {
    let mut fields = HeaderMap::with_capacity(head.fields().len() + 1);
    let mut host = None;
    let mut others = Vec::with_capacity(head.fields().len() + 1);
    for (name, value) in head.fields() {
        if name.contains(&b'_') {
            continue;
        }
        let name = HeaderName::from_bytes(name).map_err(|_| Reject::BadRequest)?;
        if head.chunked() && name == TRANSFER_ENCODING {
            continue;
        }
        if head.gzip() && (name == CONTENT_ENCODING || name == CONTENT_LENGTH) {
            continue;
        }
        let entry = (title_case(name.as_str()), Bytes::copy_from_slice(value));
        fields.append(
            name.clone(),
            HeaderValue::from_bytes(value).map_err(|_| Reject::BadRequest)?,
        );
        if name == HOST {
            host = Some(entry);
        } else {
            others.push(entry);
        }
    }
    let length = if head.chunked() || head.gzip() {
        Some(body_len)
    } else if head.content_length().is_none()
        && matches!(head.method(), b"POST" | b"PUT" | b"PATCH")
    {
        Some(0)
    } else {
        None
    };
    if let Some(length) = length {
        let value = HeaderValue::from(u64::try_from(length).map_err(|_| Reject::FieldsTooLarge)?);
        others.push((
            title_case(CONTENT_LENGTH.as_str()),
            Bytes::copy_from_slice(value.as_bytes()),
        ));
        fields.append(CONTENT_LENGTH, value);
    }
    let mut headers = Vec::with_capacity(others.len() + 1);
    headers.extend(host);
    headers.extend(others);
    let mut field_bytes = 0usize;
    for (name, value) in &headers {
        if name.len() > limits::HEADER_NAME || value.len() > limits::HEADER_VALUE {
            return Err(Reject::FieldsTooLarge);
        }
        field_bytes = field_bytes
            .checked_add(name.len())
            .and_then(|sum| sum.checked_add(value.len()))
            .filter(|&sum| sum <= limits::HEADER_TOTAL)
            .ok_or(Reject::FieldsTooLarge)?;
    }
    if headers.len() > limits::HEADERS {
        return Err(Reject::FieldsTooLarge);
    }
    Ok(Represented {
        fields,
        headers,
        field_bytes,
    })
}

#[cfg(test)]
pub(super) mod tests;
