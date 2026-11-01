//! A line of the record files as the columns of the table `tukuyomi_records`.
//!
//! A line that is a JSON object with a known `type` gives its fields to the columns that have their names (a field
//! that is missing, or is not of the type of its column, leaves the column empty). Any other line is stored with the
//! type `unknown`, and its `ts` only if it is an object that has a good one. The whole line is kept in `raw` and its
//! SHA-256 in `line_hash`, which the table holds once: a line that is shipped twice is stored once.
//!
//! One line must never make the database refuse a batch, for the batch would then be tried for ever. So every value
//! is made to fit its column before it is bound: a time is accepted only in the form the proxy writes and with
//! values that exist (else the database gives the time it stores the row), a number only when it fits its column,
//! an address only when it parses, and a text only after a NUL (which a text column cannot hold) became U+FFFD and
//! after it was cut to the longest the proxy writes: the method, `Host` and path at their limits, and the request
//! number (`request_id`, which has an index that refuses a long value) at `ID_MAX`. The other texts are words that
//! the proxy picks, and no line is longer than `RECORD_MAX`. The cut never ends inside a character. `raw` keeps the
//! whole line. A line that is not UTF-8 is stored with U+FFFD in place of the bad bytes in `raw`; its hash is that
//! of its bytes.

use std::net::IpAddr;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use tukuyomi_proxy::log::record::{HOST_MAX, METHOD_MAX, PATH_MAX};

/// The types of record there are.
const KNOWN: [&str; 6] = [
    "request",
    "connection",
    "tunnel",
    "line",
    "audit",
    "dropped",
];
/// The type of a line that is not a record of a known type.
pub const UNKNOWN: &str = "unknown";
/// The longest `request_id` in bytes. The proxy writes 16 hexadecimal digits, a hyphen and a number; a value that
/// is not that is cut here.
pub const ID_MAX: usize = 128;

/// The columns of one row. `ts` is empty when the line has no good time; the row then gets the time at which the
/// database stores it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub ts: Option<String>,
    pub kind: &'static str,
    pub request_id: Option<String>,
    pub client: Option<String>,
    pub method: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
    pub class: Option<String>,
    pub status: Option<i32>,
    pub reason: Option<String>,
    pub ms: Option<i64>,
    pub upstream: Option<String>,
    pub mode: Option<String>,
    pub engine: Option<String>,
    pub generation: Option<String>,
    pub rule: Option<i64>,
    pub rules: Option<String>,
    pub score: Option<i32>,
    pub body: Option<i64>,
    pub sent: Option<i64>,
    pub raw: String,
    pub line_hash: Vec<u8>,
}

/// A text for a column: a NUL becomes U+FFFD.
fn clean(text: &str) -> String {
    text.replace('\0', "\u{fffd}")
}

/// `text` cut to at most `max` bytes, at a character.
fn cut(mut text: String, max: usize) -> String {
    if text.len() > max {
        text.truncate(text.floor_char_boundary(max));
    }
    text
}

fn text(map: &Map<String, Value>, key: &str) -> Option<String> {
    map.get(key)?.as_str().map(clean)
}

/// The text of `key` cut to at most `max` bytes.
fn short(map: &Map<String, Value>, key: &str, max: usize) -> Option<String> {
    text(map, key).map(|text| cut(text, max))
}

fn integer(map: &Map<String, Value>, key: &str) -> Option<i64> {
    map.get(key)?.as_i64()
}

fn small(map: &Map<String, Value>, key: &str) -> Option<i32> {
    integer(map, key).and_then(|n| i32::try_from(n).ok())
}

/// The days of a month.
fn days_in(year: u32, month: u32) -> u32 {
    match month {
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// `text` if it is a time in the form the proxy writes (`2026-10-25T08:00:00.123Z`) with values that exist, in the
/// years 1 to 9999 that the database takes.
fn timestamp(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    if !text.is_ascii() || bytes.len() != 24 {
        return None;
    }
    for (at, sign) in [
        (4, b'-'),
        (7, b'-'),
        (10, b'T'),
        (13, b':'),
        (16, b':'),
        (19, b'.'),
        (23, b'Z'),
    ] {
        if bytes[at] != sign {
            return None;
        }
    }
    let number = |from: usize, to: usize| -> Option<u32> {
        let digits = &text[from..to];
        digits
            .bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| digits.parse().ok())?
    };
    let (year, month, day) = (number(0, 4)?, number(5, 7)?, number(8, 10)?);
    let (hour, minute, second) = (number(11, 13)?, number(14, 16)?, number(17, 19)?);
    number(20, 23)?;
    let fits = (1..=9999).contains(&year)
        && (1..=12).contains(&month)
        && day >= 1
        && day <= days_in(year, month)
        && hour <= 23
        && minute <= 59
        && second <= 59;
    fits.then(|| text.to_owned())
}

/// The ids of a `rules` field as the text of the JSON array, if it is an array of integers.
fn rules(map: &Map<String, Value>) -> Option<String> {
    let array = map.get("rules")?.as_array()?;
    array
        .iter()
        .all(|id| id.as_i64().is_some())
        .then(|| Value::Array(array.clone()).to_string())
}

impl Row {
    /// The row of `line`, which is the bytes between two line feeds.
    pub fn of(line: &[u8]) -> Row {
        let hash: [u8; 32] = Sha256::digest(line).into();
        let map = match serde_json::from_slice::<Value>(line) {
            Ok(Value::Object(map)) => Some(map),
            _ => None,
        };
        let ts = map
            .as_ref()
            .and_then(|map| map.get("ts")?.as_str())
            .and_then(timestamp);
        let kind = map
            .as_ref()
            .and_then(|map| map.get("type")?.as_str())
            .and_then(|kind| KNOWN.iter().find(|known| **known == kind).copied());
        let mut row = Row {
            ts,
            kind: kind.unwrap_or(UNKNOWN),
            request_id: None,
            client: None,
            method: None,
            host: None,
            path: None,
            class: None,
            status: None,
            reason: None,
            ms: None,
            upstream: None,
            mode: None,
            engine: None,
            generation: None,
            rule: None,
            rules: None,
            score: None,
            body: None,
            sent: None,
            raw: clean(&String::from_utf8_lossy(line)),
            line_hash: hash.to_vec(),
        };
        if let (Some(map), Some(_)) = (&map, kind) {
            row.request_id = short(map, "id", ID_MAX);
            row.client = map
                .get("client")
                .and_then(Value::as_str)
                .and_then(|client| client.parse::<IpAddr>().ok())
                .map(|client| client.to_canonical().to_string());
            row.method = short(map, "method", METHOD_MAX);
            row.host = short(map, "host", HOST_MAX);
            row.path = short(map, "path", PATH_MAX);
            row.class = text(map, "class");
            row.status = small(map, "status");
            row.reason = text(map, "reason");
            row.ms = integer(map, "ms");
            row.upstream = text(map, "upstream");
            row.mode = text(map, "mode");
            row.engine = text(map, "engine");
            row.generation = text(map, "generation");
            row.rule = integer(map, "rule");
            row.rules = rules(map);
            row.score = small(map, "score");
            row.body = integer(map, "body");
            row.sent = integer(map, "sent");
        }
        row
    }
}

#[cfg(test)]
mod tests;
