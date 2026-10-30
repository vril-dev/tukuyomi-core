//! The records the proxy writes as JSON, one line each: the types that a caller queues, and their encoding.
//!
//! A record is queued as a value and encoded on the logger thread, so the caller only copies what it has. Every
//! line is one JSON object whose first two fields are `ts` and `type`; then come the fields of the type in the
//! order they are declared here, and a field that has no value is left out. The types are `request` (an answer
//! that was written to a client), `connection` (a connection that ended without one), `tunnel`, `line` (a text of
//! the process, see `Log::line`), `audit` (a line of the audit log of the admin process, see `admin::audit`) and
//! `dropped` (how many records could not be queued since the last report). A
//! `request` that the rules judged also shows what they matched, as numbers of the rule set and never as text of the
//! request: `rules`, `rules_more`, `severity` and `score`.
//!
//! Text that comes from a request (method, `Host`, path) is written in a form that cannot hurt the reader: every
//! byte outside 0x21 to 0x7e, and `"` and `\`, becomes `%XX` in upper-case hexadecimal (a `%` stays as it is, so a
//! received `%80` and a received byte 0x80 are the same text). The result is cut to the limit of the field in
//! bytes, never inside a `%XX`, and the name of the field goes into `cut`. A request side copies at most the limit
//! in bytes of the received value (`Raw`) and leaves the rest to the logger thread. A record that would be longer
//! than `RECORD_MAX` bytes with its line feed is not written (the limits of the fields keep every record far
//! below it).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::Serialize;
use tukuyomi_kernel::Matched;

use super::time::rfc3339;

/// Longest method, `Host` and path in bytes, after the escaping.
pub const METHOD_MAX: usize = 32;
pub const HOST_MAX: usize = 255;
pub const PATH_MAX: usize = 1024;
/// Longest line in bytes, its line feed included.
pub const RECORD_MAX: usize = 4096;

const HEX: &[u8; 16] = b"0123456789ABCDEF";

/// The time in milliseconds, for the records.
pub fn millis(time: Duration) -> u64 {
    u64::try_from(time.as_millis()).unwrap_or(u64::MAX)
}

/// A text from a request, as the request side copies it: at most the limit of the field in bytes of the received
/// value, and whether the value had more.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Raw {
    bytes: Vec<u8>,
    more: bool,
}

impl Raw {
    /// The first `limit` bytes of `value`.
    pub fn copy(value: &[u8], limit: usize) -> Raw {
        let kept = value.len().min(limit);
        Raw {
            bytes: value[..kept].to_vec(),
            more: value.len() > kept,
        }
    }

    /// The text for the record, at most `limit` bytes, and whether anything of the value was left out.
    fn text(&self, limit: usize) -> (String, bool) {
        let bytes = &self.bytes;
        let mut out = String::with_capacity(limit.min(bytes.len().saturating_mul(3)));
        let mut at = 0;
        while at < bytes.len() {
            let byte = bytes[at];
            // The bytes taken from the value, and the bytes they take in the text.
            let (taken, width) = match byte {
                b'%' => match bytes.get(at + 1..at + 3) {
                    Some([high, low]) if high.is_ascii_hexdigit() && low.is_ascii_hexdigit() => {
                        (3, 3)
                    }
                    // The end of a copy that is not the end of the value: what follows may complete a `%XX`.
                    None if self.more => break,
                    _ => (1, 1),
                },
                0x21..=0x7e if byte != b'"' && byte != b'\\' => (1, 1),
                _ => (1, 3),
            };
            if out.len() + width > limit {
                return (out, true);
            }
            if width > taken {
                out.push('%');
                out.push(char::from(HEX[usize::from(byte >> 4)]));
                out.push(char::from(HEX[usize::from(byte & 15)]));
            } else {
                // A byte that stays, or the three bytes of a `%XX` that was received.
                out.extend(bytes[at..at + taken].iter().map(|&b| char::from(b)));
            }
            at += taken;
        }
        (out, self.more || at < bytes.len())
    }
}

/// The method, `Host` and path of a request, as copied for the record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seen {
    pub method: Raw,
    pub host: Option<Raw>,
    pub path: Raw,
}

impl Seen {
    /// What the record keeps of a request with this `method`, `host` and `target`: the path is the target up to the
    /// first `?`, as received.
    pub fn of(method: &[u8], host: Option<&[u8]>, target: &[u8]) -> Seen {
        let end = target
            .iter()
            .position(|&b| b == b'?')
            .unwrap_or(target.len());
        Seen {
            method: Raw::copy(method, METHOD_MAX),
            host: host.map(|host| Raw::copy(host, HOST_MAX)),
            path: Raw::copy(&target[..end], PATH_MAX),
        }
    }
}

/// An answer that was written to a client, or a response that was cut off.
#[derive(Clone, Debug)]
pub struct Request {
    pub id: String,
    pub conn: u64,
    pub listener: usize,
    pub proto: &'static str,
    pub tls: bool,
    pub client: IpAddr,
    /// None for a request whose head did not pass the head check.
    pub seen: Option<Seen>,
    pub class: &'static str,
    pub status: u16,
    pub reason: &'static str,
    pub ms: u64,
    pub upstream: Option<Arc<str>>,
    pub server: Option<SocketAddr>,
    pub mode: Option<&'static str>,
    pub engine: Option<&'static str>,
    /// The fingerprint of the generation that gave the verdict; the record shows its first 8 bytes.
    pub generation: Option<[u8; 32]>,
    pub rule: Option<i64>,
    /// The rules that matched, as the verdict says them. The record shows their ids (`rules`, `rules_more`), the
    /// severity and the score, and leaves out what is none: no ids, severity 255, a score of -1 or 0.
    pub matched: Matched,
    pub body: Option<u64>,
    pub inspected: Option<u64>,
    pub sent: u64,
}

/// A connection that ended with no answer written to it, or an HTTP/2 connection at its end.
#[derive(Clone, Debug)]
pub struct Connection {
    pub conn: u64,
    pub listener: usize,
    pub client: IpAddr,
    pub class: &'static str,
    pub status: u16,
    pub reason: &'static str,
    pub ms: u64,
    pub streams: Option<u64>,
}

/// The end of a tunnel.
#[derive(Clone, Debug)]
pub struct Tunnel {
    /// The number of the request that opened it.
    pub id: String,
    pub conn: u64,
    pub client: IpAddr,
    pub upstream: Option<Arc<str>>,
    pub server: Option<SocketAddr>,
    pub end: &'static str,
    pub ms: u64,
    pub to_upstream: u64,
    pub from_upstream: u64,
}

/// What a caller queues besides a line.
#[derive(Clone, Debug)]
pub enum Record {
    Request(Box<Request>),
    Connection(Connection),
    Tunnel(Tunnel),
    /// A line of the audit log, already encoded as `framed` does it with the type `audit`: the logger writes it as
    /// it is.
    Audit(String),
}

/// The first two fields of every line, and the fields of its type.
#[derive(Serialize)]
struct Framed<'a, T: Serialize> {
    ts: &'a str,
    #[serde(rename = "type")]
    kind: &'static str,
    #[serde(flatten)]
    body: T,
}

#[derive(Serialize)]
struct LineBody<'a> {
    line: &'a str,
}

#[derive(Serialize)]
struct DroppedBody {
    count: u64,
}

#[derive(Serialize)]
struct RequestBody<'a> {
    id: &'a str,
    conn: u64,
    listener: usize,
    proto: &'static str,
    tls: bool,
    client: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    cut: Vec<&'static str>,
    class: &'static str,
    status: u16,
    reason: &'static str,
    ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    upstream: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    server: Option<SocketAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    engine: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    generation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rules: Option<&'a [i64]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rules_more: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    score: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    inspected: Option<u64>,
    sent: u64,
}

#[derive(Serialize)]
struct ConnectionBody {
    conn: u64,
    listener: usize,
    client: IpAddr,
    class: &'static str,
    status: u16,
    reason: &'static str,
    ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    streams: Option<u64>,
}

#[derive(Serialize)]
struct TunnelBody<'a> {
    id: &'a str,
    conn: u64,
    client: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    upstream: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    server: Option<SocketAddr>,
    end: &'static str,
    ms: u64,
    to_upstream: u64,
    from_upstream: u64,
}

/// The line, or `None` if it is longer than `RECORD_MAX` bytes with its line feed.
pub(crate) fn framed<T: Serialize>(at: SystemTime, kind: &'static str, body: T) -> Option<String> {
    let ts = rfc3339(at);
    let line = serde_json::to_string(&Framed {
        ts: &ts,
        kind,
        body,
    })
    .ok()?;
    (line.len() < RECORD_MAX).then_some(line)
}

/// A text of the process as a line of `type` `line`.
pub fn encode_line(at: SystemTime, text: &str) -> Option<String> {
    framed(at, "line", LineBody { line: text })
}

/// The report of `count` records that were dropped.
pub fn encode_dropped(at: SystemTime, count: u64) -> Option<String> {
    framed(at, "dropped", DroppedBody { count })
}

/// The line of a typed record, or `None` if it is longer than `RECORD_MAX` bytes with its line feed.
pub fn encode(at: SystemTime, record: &Record) -> Option<String> {
    match record {
        Record::Request(request) => encode_request(at, request),
        Record::Audit(line) => (line.len() < RECORD_MAX).then(|| line.clone()),
        Record::Connection(c) => framed(
            at,
            "connection",
            ConnectionBody {
                conn: c.conn,
                listener: c.listener,
                client: c.client.to_canonical(),
                class: c.class,
                status: c.status,
                reason: c.reason,
                ms: c.ms,
                streams: c.streams,
            },
        ),
        Record::Tunnel(t) => framed(
            at,
            "tunnel",
            TunnelBody {
                id: &t.id,
                conn: t.conn,
                client: t.client.to_canonical(),
                upstream: t.upstream.as_deref(),
                server: t.server,
                end: t.end,
                ms: t.ms,
                to_upstream: t.to_upstream,
                from_upstream: t.from_upstream,
            },
        ),
    }
}

fn encode_request(at: SystemTime, r: &Request) -> Option<String> {
    let mut cut = Vec::new();
    let mut field = |name: &'static str, raw: &Raw, limit: usize| {
        let (text, was_cut) = raw.text(limit);
        if was_cut {
            cut.push(name);
        }
        text
    };
    let method = r
        .seen
        .as_ref()
        .map(|seen| field("method", &seen.method, METHOD_MAX));
    let host = r
        .seen
        .as_ref()
        .and_then(|seen| seen.host.as_ref())
        .map(|host| field("host", host, HOST_MAX));
    let path = r
        .seen
        .as_ref()
        .map(|seen| field("path", &seen.path, PATH_MAX));
    let matched = &r.matched;
    framed(
        at,
        "request",
        RequestBody {
            id: &r.id,
            conn: r.conn,
            listener: r.listener,
            proto: r.proto,
            tls: r.tls,
            client: r.client.to_canonical(),
            method: method.as_deref(),
            host: host.as_deref(),
            path: path.as_deref(),
            cut,
            class: r.class,
            status: r.status,
            reason: r.reason,
            ms: r.ms,
            upstream: r.upstream.as_deref(),
            server: r.server,
            mode: r.mode,
            engine: r.engine,
            generation: r
                .generation
                .map(|g| g.iter().take(8).map(|b| format!("{b:02x}")).collect()),
            rule: r.rule,
            rules: (!matched.ids().is_empty()).then_some(matched.ids()),
            rules_more: matched.more.then_some(true),
            severity: (matched.severity != Matched::NONE.severity).then_some(matched.severity),
            score: (matched.score > 0).then_some(matched.score),
            body: r.body,
            inspected: r.inspected,
            sent: r.sent,
        },
    )
}

#[cfg(test)]
mod tests;
