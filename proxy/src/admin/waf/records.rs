//! The record files of the proxy, read back for `GET /api/records`: `records.log`, `records.1.log` and so on in
//! `records.dir`, the newest line first. The lines are given as they are in the file (a JSON object each, the text
//! that came from a request still in the `%XX` form the proxy wrote); of each object the keys may be in another order,
//! for a line is read and written again.
//!
//! The query has these fields, each at most once: `from` and `to` (a time in UTC in RFC 3339 form, with `Z` and a
//! fraction of up to 9 digits or none, the first and the last time wanted), `type` (the type of the record), `class`,
//! `status`, `rule` (the id of a rule, as the verdict or among the matched ones), `id` (the number of a request),
//! `client` (an IP address), `generation` (16 or 64 digits of a generation) and, together or not at all, `file`,
//! `offset` and `inode`, the continuation that an earlier answer gave. A value is percent-decoded; a field that is not
//! known, a value that is not of the form of its field and a field twice are refused.
//!
//! One answer has at most `Limits::lines` lines and reads at most `Limits::read` bytes of the files (a chunk is read
//! whole, but a first chunk is always read). When either limit stops the read before the records end, the answer
//! carries the continuation: the number of the file, the offset in it up to which its lines are still to be read (the
//! start of the last line looked at), and the inode of the file, since a rotation between two answers moves a file to a
//! higher number; the file is found again by its inode. A continuation that names no file any more, or a place that is
//! not the end of a line, is `Error::Gone`.
//!
//! The directory is looked at first, as the rules store looks at its own: a real directory (not a link) owned by this
//! user without group or other permission bits, else the answer is 503 with the sentence of `run::host`.
//!
//! A file is read from its end in chunks. A last line that has no line feed yet (the proxy is writing it) is left out,
//! and so is a line that is longer than a record can be or is not a JSON object with a `ts`. The records are in the
//! order of their `ts`, so the read ends at the first line older than `from`.

use std::fs::{File, OpenOptions};
use std::io;
use std::net::IpAddr;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

use http::StatusCode;
use serde_json::{Value, json};

use super::{Waf, conflict};
use crate::admin::server::Answer;
use crate::log::record::RECORD_MAX;
use crate::log::sink::name;
use crate::rules::file_store::{O_NOCTTY, O_NOFOLLOW, O_NONBLOCK};
use crate::run::host;

const STEM: &str = "records";
/// The types of record there are.
const TYPES: [&str; 6] = [
    "request",
    "connection",
    "tunnel",
    "line",
    "audit",
    "dropped",
];
/// The most bytes of a value of the query, once decoded.
const VALUE_MAX: usize = 128;
/// The bytes at the end of a file that are looked at for its last line feed: a record is shorter than half of it.
const LAST: u64 = 2 * RECORD_MAX as u64;

/// How much one answer holds and reads.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// The most lines in the answer.
    pub lines: usize,
    /// The most bytes read from the files.
    pub read: u64,
    /// The bytes read at a time.
    pub chunk: usize,
}

impl Limits {
    pub const STANDARD: Limits = Limits {
        lines: 500,
        read: 256 << 20,
        chunk: 64 * 1024,
    };
}

/// Where an earlier answer stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Start {
    pub file: usize,
    pub offset: u64,
    pub inode: u64,
}

impl Start {
    /// The continuation as the answer shows it. The inode is text, for a number above 2^53 is not safe in JSON.
    pub fn json(&self) -> Value {
        json!({"file": self.file, "offset": self.offset, "inode": self.inode.to_string()})
    }
}

/// What the lines must have. The times are in the form of the `ts` of a record.
#[derive(Debug, Default, PartialEq, Eq)]
struct Filter {
    from: Option<String>,
    to: Option<String>,
    kind: Option<String>,
    class: Option<String>,
    status: Option<u64>,
    rule: Option<i64>,
    id: Option<String>,
    client: Option<String>,
    generation: Option<String>,
}

/// A query: the filter and where to go on.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Query {
    filter: Filter,
    start: Option<Start>,
}

/// An answer.
pub struct Page {
    pub records: Vec<Value>,
    /// Where to go on, if the read was stopped by a limit before the records ended.
    pub next: Option<Start>,
}

/// Why records cannot be given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The continuation names no file or no end of a line.
    Gone,
    /// A file cannot be read.
    Unreadable,
}

/// The text that `value` percent-decodes to. None: a `%` without two digits after it, text that is not UTF-8, a
/// control character, or more than `VALUE_MAX` bytes.
fn unescape(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' {
            let digits = value.get(at + 1..at + 3)?;
            out.push(u8::from_str_radix(digits, 16).ok()?);
            at += 3;
        } else {
            out.push(bytes[at]);
            at += 1;
        }
    }
    let text = String::from_utf8(out).ok()?;
    (text.len() <= VALUE_MAX && !text.chars().any(char::is_control)).then_some(text)
}

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

/// `text` in the form of the `ts` of a record (`2026-10-25T08:00:00.123Z`). It is read as
/// `YYYY-MM-DDTHH:MM:SS`, a fraction of 1 to 9 digits or none, and `Z`; the fraction is cut or filled to three
/// digits. None: it is not such a time, or a part of it is out of range.
fn timestamp(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    if !text.is_ascii() || !(20..=30).contains(&bytes.len()) || bytes[bytes.len() - 1] != b'Z' {
        return None;
    }
    for (at, sign) in [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')] {
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
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let fraction = &text[19..text.len() - 1];
    let millis = match fraction.strip_prefix('.') {
        None if fraction.is_empty() => "000".to_owned(),
        Some(digits)
            if (1..=9).contains(&digits.len()) && digits.bytes().all(|b| b.is_ascii_digit()) =>
        {
            format!("{digits:0<3}")[..3].to_owned()
        }
        _ => return None,
    };
    Some(format!("{}.{millis}Z", &text[..19]))
}

/// `value` if it is 1 to `longest` bytes of the characters that `allowed` takes.
fn token(value: &str, longest: usize, allowed: impl Fn(u8) -> bool) -> Option<String> {
    (!value.is_empty() && value.len() <= longest && value.bytes().all(allowed))
        .then(|| value.to_owned())
}

impl Query {
    /// The query that `text` (the part after the `?`) makes, or the sentence that says why it is refused.
    pub fn parse(text: &str) -> Result<Query, &'static str> {
        let mut filter = Filter::default();
        let (mut file, mut offset, mut inode) = (None, None, None);
        let mut seen: Vec<&str> = Vec::new();
        for pair in text.split('&').filter(|_| !text.is_empty()) {
            let (key, value) = pair
                .split_once('=')
                .ok_or("a field of the query has no value")?;
            if seen.contains(&key) {
                return Err("a field of the query is given twice");
            }
            seen.push(key);
            let value = unescape(value).ok_or("a value of the query is not valid")?;
            let bad = "a value of the query is not of the form of its field";
            match key {
                "from" => filter.from = Some(timestamp(&value).ok_or(bad)?),
                "to" => filter.to = Some(timestamp(&value).ok_or(bad)?),
                "type" => {
                    filter.kind = Some(
                        TYPES
                            .iter()
                            .find(|kind| **kind == value)
                            .ok_or(bad)?
                            .to_string(),
                    );
                }
                "class" => {
                    let word = |b: u8| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-'
                    };
                    filter.class = Some(token(&value, 32, word).ok_or(bad)?);
                }
                "status" => {
                    filter.status = Some(
                        token(&value, 3, |b| b.is_ascii_digit())
                            .and_then(|v| v.parse().ok())
                            .ok_or(bad)?,
                    );
                }
                "rule" => {
                    filter.rule = Some(
                        token(&value, 20, |b| b.is_ascii_digit() || b == b'-')
                            .and_then(|v| v.parse().ok())
                            .ok_or(bad)?,
                    );
                }
                "id" => {
                    filter.id = Some(
                        token(&value, 40, |b| {
                            b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || b == b'-'
                        })
                        .ok_or(bad)?,
                    );
                }
                "client" => {
                    filter.client = Some(
                        value
                            .parse::<IpAddr>()
                            .map_err(|_| bad)?
                            .to_canonical()
                            .to_string(),
                    );
                }
                "generation" => {
                    let digits = token(&value, 64, |b| {
                        b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                    })
                    .ok_or(bad)?;
                    if digits.len() != 16 && digits.len() != 64 {
                        return Err(bad);
                    }
                    // A record shows the first 8 bytes of the generation.
                    filter.generation = Some(digits[..16].to_owned());
                }
                "file" => {
                    file = Some(
                        token(&value, 4, |b| b.is_ascii_digit())
                            .and_then(|v| v.parse().ok())
                            .ok_or(bad)?,
                    )
                }
                "offset" => {
                    offset = Some(
                        token(&value, 20, |b| b.is_ascii_digit())
                            .and_then(|v| v.parse().ok())
                            .ok_or(bad)?,
                    )
                }
                "inode" => {
                    inode = Some(
                        token(&value, 20, |b| b.is_ascii_digit())
                            .and_then(|v| v.parse().ok())
                            .ok_or(bad)?,
                    )
                }
                _ => return Err("a field of the query is not known"),
            }
        }
        let start = match (file, offset, inode) {
            (None, None, None) => None,
            (Some(file), Some(offset), Some(inode)) => Some(Start {
                file,
                offset,
                inode,
            }),
            _ => return Err("file, offset and inode of the query go together"),
        };
        Ok(Query { filter, start })
    }
}

/// What the filter makes of a line.
enum Judged {
    Keep(Value),
    Skip,
    /// The line is older than `from`, and so are the lines before it.
    Older,
}

fn judge(line: &[u8], filter: &Filter) -> Judged {
    let Ok(Value::Object(map)) = serde_json::from_slice::<Value>(line) else {
        return Judged::Skip;
    };
    let text = |key: &str| map.get(key).and_then(Value::as_str);
    let Some(ts) = text("ts") else {
        return Judged::Skip;
    };
    if filter.from.as_deref().is_some_and(|from| ts < from) {
        return Judged::Older;
    }
    let words = [
        ("type", &filter.kind),
        ("class", &filter.class),
        ("id", &filter.id),
        ("client", &filter.client),
        ("generation", &filter.generation),
    ];
    let rule = |wanted: i64| {
        map.get("rule").and_then(Value::as_i64) == Some(wanted)
            || map
                .get("rules")
                .and_then(Value::as_array)
                .is_some_and(|ids| ids.iter().any(|id| id.as_i64() == Some(wanted)))
    };
    let wanted = filter.to.as_deref().is_none_or(|to| ts <= to)
        && words
            .iter()
            .all(|(key, want)| want.as_deref().is_none_or(|want| text(key) == Some(want)))
        && filter
            .status
            .is_none_or(|status| map.get("status").and_then(Value::as_u64) == Some(status))
        && filter.rule.is_none_or(rule);
    if wanted {
        Judged::Keep(Value::Object(map))
    } else {
        Judged::Skip
    }
}

/// The read budget of an answer.
struct Budget {
    left: u64,
    /// A chunk has been read.
    started: bool,
}

enum Next {
    /// A line.
    Line(Vec<u8>),
    /// The file has no line left.
    End,
    /// The budget does not allow the next chunk.
    Budget,
}

/// A file read from its end towards its start, one line at a time.
struct Tail {
    file: File,
    chunk: usize,
    /// The lines below this offset are not read; the bytes from it up to the end of the line being assembled are in
    /// `carry`.
    pos: u64,
    carry: Vec<u8>,
    /// The line being assembled is longer than a record can be; the rest of it is left out.
    overlong: bool,
    /// The lines of the last chunk, the oldest first, so that `pop` gives the newest.
    ready: Vec<(u64, Vec<u8>)>,
    end: bool,
    /// The lines below this offset are not handed out: where the next answer goes on.
    resume: u64,
}

impl Tail {
    /// The lines of `file` below `offset`, which is 0 or follows a line feed.
    fn new(file: File, offset: u64, chunk: usize) -> Tail {
        let pos = offset.saturating_sub(1);
        Tail {
            file,
            chunk: chunk.max(1),
            pos,
            carry: Vec::new(),
            overlong: false,
            ready: Vec::new(),
            end: pos == 0,
            resume: offset,
        }
    }

    fn next(&mut self, budget: &mut Budget) -> io::Result<Next> {
        loop {
            if let Some((at, line)) = self.ready.pop() {
                self.resume = at;
                return Ok(Next::Line(line));
            }
            if self.end {
                return Ok(Next::End);
            }
            let size = self.pos.min(u64::try_from(self.chunk).unwrap_or(u64::MAX));
            if budget.started && budget.left < size {
                return Ok(Next::Budget);
            }
            budget.started = true;
            budget.left = budget.left.saturating_sub(size);
            let start = self.pos - size;
            let mut data = vec![0u8; usize::try_from(size).unwrap_or(0)];
            self.file.read_exact_at(&mut data, start)?;
            data.extend_from_slice(&self.carry);
            self.split(start, &data);
        }
    }

    /// Takes the lines out of `data`, which is the bytes from `start` up to the end of a line.
    fn split(&mut self, start: u64, data: &[u8]) {
        let mut end = data.len();
        // The last line of `data` is the rest of one that was left out for being too long.
        let mut skip = self.overlong;
        let mut lines = Vec::new();
        while let Some(feed) = data[..end].iter().rposition(|&b| b == b'\n') {
            let line = &data[feed + 1..end];
            if skip {
                skip = false;
                self.overlong = false;
            } else if !line.is_empty() && line.len() < RECORD_MAX {
                lines.push((start + feed as u64 + 1, line.to_vec()));
            }
            end = feed;
        }
        self.pos = start;
        self.carry.clear();
        if start == 0 {
            let line = &data[..end];
            if !skip && !line.is_empty() && line.len() < RECORD_MAX {
                lines.push((0, line.to_vec()));
            }
            self.end = true;
        } else if skip || end >= RECORD_MAX {
            self.overlong = true;
        } else {
            self.carry.extend_from_slice(&data[..end]);
        }
        lines.reverse();
        self.ready = lines;
    }
}

/// File number `n` of the records, opened as every file of the stores is: a link is not followed, a FIFO is not
/// waited for.
fn open(dir: &Path, n: usize) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK | O_NOCTTY)
        .open(name(dir, STEM, n))?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a regular file",
        ));
    }
    Ok(file)
}

/// The offset after the last line feed of `file`, which is `len` bytes long: where its last whole line ends. 0: it
/// has none.
fn boundary(file: &File, len: u64) -> Result<u64, Error> {
    let size = len.min(LAST);
    if size == 0 {
        return Ok(0);
    }
    let mut data = vec![0u8; usize::try_from(size).unwrap_or(0)];
    file.read_exact_at(&mut data, len - size)
        .map_err(|_| Error::Unreadable)?;
    Ok(data
        .iter()
        .rposition(|&b| b == b'\n')
        .map_or(0, |at| len - size + at as u64 + 1))
}

/// The number of the file that `start` names now, and that its offset is the end of a line in.
fn locate(dir: &Path, files: usize, start: &Start) -> Result<usize, Error> {
    for n in start.file..files {
        let file = match open(dir, n) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => return Err(Error::Unreadable),
        };
        let meta = file.metadata().map_err(|_| Error::Unreadable)?;
        if meta.ino() != start.inode {
            continue;
        }
        let mut feed = [0u8; 1];
        let whole = start.offset <= meta.len()
            && (start.offset == 0
                || (file.read_exact_at(&mut feed, start.offset - 1).is_ok() && feed[0] == b'\n'));
        return if whole { Ok(n) } else { Err(Error::Gone) };
    }
    Err(Error::Gone)
}

/// The place at the end of the first file from number `from` on that was not read.
fn later(dir: &Path, files: usize, from: usize, seen: &[u64]) -> Option<Start> {
    (from..files).find_map(|n| {
        let file = open(dir, n).ok()?;
        let meta = file.metadata().ok()?;
        if seen.contains(&meta.ino()) {
            return None;
        }
        Some(Start {
            file: n,
            offset: boundary(&file, meta.len()).ok()?,
            inode: meta.ino(),
        })
    })
}

/// The lines of the record files in `dir` (at most `files` of them) that `query` asks for, newest first.
pub fn read(dir: &Path, files: usize, query: &Query, limits: Limits) -> Result<Page, Error> {
    let mut page = Page {
        records: Vec::new(),
        next: None,
    };
    let mut budget = Budget {
        left: limits.read,
        started: false,
    };
    let mut seen = Vec::new();
    let mut moved = false;
    let mut resume = query.start;
    let mut n = match &query.start {
        Some(start) => locate(dir, files, start)?,
        None => 0,
    };
    while n < files {
        let file = match open(dir, n) {
            Ok(file) => file,
            // A rotation has renamed `records.log` and not yet made the new one.
            Err(e) if e.kind() == io::ErrorKind::NotFound && n == 0 => {
                n += 1;
                continue;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => break,
            Err(_) => return Err(Error::Unreadable),
        };
        let meta = file.metadata().map_err(|_| Error::Unreadable)?;
        // A rotation since the first file was opened can show the same file under another number.
        if seen.contains(&meta.ino()) {
            n += 1;
            continue;
        }
        seen.push(meta.ino());
        let offset = match resume.take() {
            // A rotation between `locate` and the open above has put another file under the number.
            Some(start) if meta.ino() != start.inode => return Err(Error::Gone),
            Some(start) => start.offset,
            None => boundary(&file, meta.len())?,
        };
        let mut tail = Tail::new(file, offset, limits.chunk);
        loop {
            let stop = match tail.next(&mut budget).map_err(|_| Error::Unreadable)? {
                Next::End => break,
                Next::Budget => true,
                Next::Line(line) => {
                    moved = true;
                    match judge(&line, &query.filter) {
                        Judged::Older => return Ok(page),
                        Judged::Keep(record) => {
                            page.records.push(record);
                            page.records.len() >= limits.lines
                        }
                        Judged::Skip => false,
                    }
                }
            };
            if stop {
                page.next = if tail.resume > 0 {
                    // A budget that stops the read before any line was looked at would give the same place again.
                    moved.then_some(Start {
                        file: n,
                        offset: tail.resume,
                        inode: meta.ino(),
                    })
                } else {
                    later(dir, files, n + 1, &seen)
                };
                return Ok(page);
            }
        }
        moved = true;
        n += 1;
    }
    Ok(page)
}

impl Waf {
    pub(super) fn records(&self, query: &str) -> Answer {
        let Some(config) = &self.records else {
            return Answer::error(StatusCode::NOT_FOUND, "records are not configured");
        };
        let query = match Query::parse(query) {
            Ok(query) => query,
            Err(words) => return Answer::error(StatusCode::BAD_REQUEST, words),
        };
        // The directory is looked at as the rules store looks at its own: only this user can have put a file in it.
        if let Err(words) = host::fs_uid().and_then(|uid| host::private_dir(&config.dir, uid)) {
            return Answer::error(StatusCode::SERVICE_UNAVAILABLE, words);
        }
        match read(&config.dir, config.files, &query, Limits::STANDARD) {
            Ok(page) => Answer::json(
                StatusCode::OK,
                json!({"records": page.records, "next": page.next.map(|start| start.json())}),
            ),
            Err(Error::Gone) => {
                conflict("the continuation names no place in the record files any more")
            }
            Err(Error::Unreadable) => Answer::unavailable(),
        }
    }
}

#[cfg(test)]
mod tests;
