//! The fields that belong to one hop, of the request and of the answer, the fields by which a peer says who the
//! client is, and the making of the forwarding fields that the upstream gets.

use std::net::IpAddr;

use http::header::{CONNECTION, HOST, InvalidHeaderName, UPGRADE};
use http::{HeaderMap, HeaderName, HeaderValue};

use super::OriginError;
use crate::inbound::head::trim_ows;

static X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
static X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");
static X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");
static X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// Fields of the request that belong to the connection with the client or to a single hop. `Connection` and the
/// names it lists go as well.
pub(in crate::forward) const REQUEST_HOP: [&str; 10] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "expect",
];

/// Fields of the answer that belong to the connection with the upstream. `Connection` and the names it lists go
/// as well.
pub(in crate::forward) const RESPONSE_HOP: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Fields by which a peer says who the client is and how it came, in the spellings that servers and proxies in
/// common use take for the address of the client. They are believed from a trusted peer only. `X-Forwarded-Host` is
/// not among them: it is always made from the `Host` of the request. The names with an underscore never get here
/// (see `represent`).
pub(in crate::forward) const CLIENT_CLAIMS: [&str; 13] = [
    "x-forwarded-for",
    "x-real-ip",
    "forwarded",
    "x-forwarded-proto",
    "x-forwarded-port",
    "x-forwarded-ssl",
    "x-forwarded-scheme",
    "x-client-ip",
    "true-client-ip",
    "x-cluster-client-ip",
    "cf-connecting-ip",
    "fastly-client-ip",
    "x-original-forwarded-for",
];

/// The names of one `Connection` line: its comma separated items, each of which must be a token.
pub(super) fn listed(
    line: &HeaderValue,
) -> impl Iterator<Item = Result<HeaderName, InvalidHeaderName>> + '_ {
    line.as_bytes()
        .split(|&b| b == b',')
        .map(|item| HeaderName::from_bytes(trim_ows(item)))
}

/// The `X-Forwarded-For` value: the lines the request has, in order, and then the address of the peer. The
/// address is the one of the connection, not the client address that the lines may lead to.
fn forwarded_for(fields: &HeaderMap, peer: IpAddr) -> Result<HeaderValue, OriginError> {
    let mut chain = Vec::new();
    for line in fields.get_all(&X_FORWARDED_FOR) {
        chain.extend_from_slice(line.as_bytes());
        chain.extend_from_slice(b", ");
    }
    chain.extend_from_slice(peer.to_canonical().to_string().as_bytes());
    HeaderValue::from_bytes(&chain).map_err(|_| OriginError::Send)
}

/// The `X-Forwarded-Proto` value: the one line the request has if it is exactly `http` or `https`, the scheme of the
/// listener (`https` if `https`) otherwise.
fn forwarded_proto(fields: &HeaderMap, https: bool) -> HeaderValue {
    let mut lines = fields.get_all(&X_FORWARDED_PROTO).iter();
    match (lines.next(), lines.next()) {
        (Some(line), None) if matches!(line.as_bytes(), b"http" | b"https") => line.clone(),
        _ if https => HeaderValue::from_static("https"),
        _ => HeaderValue::from_static("http"),
    }
}

/// The fields the upstream gets, in this order: the names listed in `Connection` are collected from the fields as
/// they were inspected; the hop-by-hop fields and the listed names are removed; if the peer is not `trusted`, so
/// are the fields by which it says who the client is; then the forwarding fields are put in, and `Connection:
/// upgrade` with `Upgrade: websocket` for a handshake, or `Connection: close` if `close`. Every `X-Request-ID` field
/// is removed, whoever the peer is, and one with `id` is put in. All other fields stay as they were inspected.
/// `https` is whether the listener ended TLS.
pub(super) fn forwarded_fields(
    mut fields: HeaderMap,
    peer: IpAddr,
    trusted: bool,
    close: bool,
    websocket: bool,
    https: bool,
    id: &str,
) -> Result<HeaderMap, OriginError> {
    let named: Vec<HeaderName> = fields
        .get_all(CONNECTION)
        .iter()
        .flat_map(listed)
        .filter_map(Result::ok)
        .collect();
    for name in REQUEST_HOP {
        fields.remove(name);
    }
    for name in &named {
        fields.remove(name);
    }
    fields.remove(&X_REQUEST_ID);
    if !trusted {
        for name in CLIENT_CLAIMS {
            fields.remove(name);
        }
    }
    let chain = forwarded_for(&fields, peer)?;
    let proto = forwarded_proto(&fields, https);
    let host = fields.get(HOST).cloned();
    fields.insert(X_FORWARDED_FOR.clone(), chain);
    match host {
        Some(host) => {
            fields.insert(X_FORWARDED_HOST.clone(), host);
        }
        None => {
            fields.remove(&X_FORWARDED_HOST);
        }
    }
    fields.insert(X_FORWARDED_PROTO.clone(), proto);
    fields.insert(
        X_REQUEST_ID.clone(),
        HeaderValue::from_str(id).map_err(|_| OriginError::Send)?,
    );
    if websocket {
        fields.insert(CONNECTION, HeaderValue::from_static("upgrade"));
        fields.insert(UPGRADE, HeaderValue::from_static("websocket"));
    } else if close {
        fields.insert(CONNECTION, HeaderValue::from_static("close"));
    }
    Ok(fields)
}
