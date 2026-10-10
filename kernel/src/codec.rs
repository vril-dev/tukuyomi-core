//! Rust side of the wire protocol 0 (the accepted v0 bytes).
//!
//! The same bytes as the Go inspector's `codec.go` and `testdata/v0-golden.txt`. Every integer is big-endian; a `str`
//! is a u16 length and the bytes. Strings stay `&[u8]` / `Vec<u8>`: no UTF-8 conversion, normalisation or trimming.
//! Rust receives HELLO, BYE, VERDICT, ERROR and CLOSED and sends DRAIN, TX_BEGIN, BODY, BODY_END and TX_END. The
//! response kinds (RESP_BEGIN, RESP_BODY, RESP_END) are v0 kinds that Rust never sends: `encode_frame` refuses them and
//! `check_header` reports one received as a wrong direction.
//!
//! Faults are split in two types: `ConnError` is a connection-wide violation (header or read; the frame boundary can no
//! longer be trusted) and `ContentError` is an invalid payload behind a valid header, or a failed check before sending
//! (an individual violation). This module does no deadline handling: `read_frame` takes any `std::io::Read`.
//!
//! `check_hello` compares a decoded HELLO with the start and with the pinned inspector build (`INSPECTOR_*`).
#![forbid(unsafe_code)]

use std::io::{ErrorKind, Read};

pub(crate) const HEADER_LEN: usize = 36;
pub(crate) const MAGIC: [u8; 4] = *b"TKV0";

// Frame kinds. FAULT (0x7f) is reserved: it has no constant and no encoder here, and an incoming 0x7f is an unknown
// kind.
pub(crate) const KIND_HELLO: u8 = 0x01;
pub(crate) const KIND_DRAIN: u8 = 0x02;
pub(crate) const KIND_BYE: u8 = 0x03;
pub(crate) const KIND_TX_BEGIN: u8 = 0x10;
pub(crate) const KIND_BODY: u8 = 0x11;
pub(crate) const KIND_BODY_END: u8 = 0x12;
// The response kinds are never sent by this side: they only classify a received kind as a wrong direction and a kind
// to encode as refused.
pub(crate) const KIND_RESP_BEGIN: u8 = 0x13;
pub(crate) const KIND_RESP_BODY: u8 = 0x14;
pub(crate) const KIND_RESP_END: u8 = 0x15;
pub(crate) const KIND_TX_END: u8 = 0x16;
pub(crate) const KIND_VERDICT: u8 = 0x20;
pub(crate) const KIND_ERROR: u8 = 0x21;
pub(crate) const KIND_CLOSED: u8 = 0x22;

// Payload limits per kind and item bounds (bytes unless noted). Same values as the Go constants (codec.go).
pub(crate) const MAX_HELLO: usize = 1024;
pub(crate) const MAX_TX_BEGIN: usize = 32 * 1024;
pub(crate) const MAX_BODY: usize = 64 * 1024;
pub(crate) const MAX_VERDICT: usize = 1024;
pub(crate) const MAX_ERROR: usize = 512;
pub(crate) const MAX_TX_END: usize = 8;
pub(crate) const MAX_CLOSED: usize = 8;
pub(crate) const MAX_BYE: usize = 64;
pub(crate) const MAX_DECLARED: u64 = 1 << 20; // v0 declared body length limit (Go's `maxDeclared`, 1 MiB)
pub(crate) const MAX_ADDR: usize = 64;
pub(crate) const MAX_METHOD: usize = 32;
pub(crate) const MAX_URI: usize = 4096;
pub(crate) const MAX_PROTO: usize = 16;
pub(crate) const MAX_HEADERS: usize = 64;
pub(crate) const MAX_HDR_NAME: usize = 256;
pub(crate) const MAX_HDR_VALUE: usize = 4096;
pub(crate) const MAX_HDR_TOTAL: usize = 24 * 1024;
pub(crate) const MAX_ACTION: usize = 32;
pub(crate) const MAX_DATA: usize = 256;
pub(crate) const MAX_ERR_MSG: usize = 256;
pub(crate) const MAX_CONCUR_TX: u16 = 4;
pub(crate) const QUEUE_DEPTH: u16 = 17;

// HELLO string bounds (v0).
const MAX_GO_VERSION: usize = 64;
const MAX_CORAZA_VERSION: usize = 64;
const MAX_CORAZA_SUM: usize = 128;

// VERDICT cut flags and ERROR classes.
pub(crate) const FLAG_ACTION_TRUNCATED: u8 = 1 << 0;
pub(crate) const FLAG_DATA_TRUNCATED: u8 = 1 << 1;
pub(crate) const CLASS_NOT_CREATED: u8 = 1;
pub(crate) const CLASS_TX_FAILED: u8 = 2;

// TX_END reasons: 1 complete .. 5 deadline.
const END_COMPLETE: u8 = 1;
const END_DEADLINE: u8 = 5;

/// A decoded 36-byte frame header (`check_header` has accepted it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Header {
    pub kind: u8,
    pub len: u32,
    pub run: u64,
    pub inc: u32,
    pub tx: u64,
    pub msg: u32,
}

/// A connection-wide violation (header or read). The frame boundary can no longer be trusted.
///
/// `Truncated` counts per section: for a cut header `got` bytes of `want` = `HEADER_LEN`; for a cut payload `got`
/// payload bytes of `want` = the header's length (so a cut exactly after the header has `got` 0).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ConnError {
    /// EOF before the first byte of a frame.
    PeerClosed,
    Truncated {
        got: usize,
        want: usize,
    },
    BadMagic,
    UnknownKind(u8),
    WrongDirection(u8),
    Flags(u8),
    Reserved(u16),
    TooLong {
        kind: u8,
        len: u32,
    },
    RunMismatch(u64),
    IncMismatch(u32),
    ControlIds,
    ZeroIds,
    Io(ErrorKind),
}

/// An invalid payload behind a valid header, or a failed check before sending (an individual violation).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ContentError(pub &'static str);

fn be32(b: &[u8; HEADER_LEN], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn be64(b: &[u8; HEADER_LEN], o: usize) -> u64 {
    u64::from_be_bytes([
        b[o],
        b[o + 1],
        b[o + 2],
        b[o + 3],
        b[o + 4],
        b[o + 5],
        b[o + 6],
        b[o + 7],
    ])
}

/// Payload limit of every kind this side receives; `None` for the kinds it sends and for unknown kinds.
fn received_max(kind: u8) -> Option<usize> {
    match kind {
        KIND_HELLO => Some(MAX_HELLO),
        KIND_BYE => Some(MAX_BYE),
        KIND_VERDICT => Some(MAX_VERDICT),
        KIND_ERROR => Some(MAX_ERROR),
        KIND_CLOSED => Some(MAX_CLOSED),
        _ => None,
    }
}

/// Payload length range (min, max) of every kind this side sends; `None` for the kinds it receives, the response kinds
/// and unknown kinds.
fn sent_range(kind: u8) -> Option<(usize, usize)> {
    match kind {
        KIND_DRAIN | KIND_BODY_END => Some((0, 0)),
        KIND_TX_BEGIN => Some((0, MAX_TX_BEGIN)),
        KIND_BODY => Some((1, MAX_BODY)),
        KIND_TX_END => Some((0, MAX_TX_END)),
        _ => None,
    }
}

/// Control frames (no transaction): tx and msg are both 0. The others carry both, nonzero.
fn is_control(kind: u8) -> bool {
    kind == KIND_DRAIN || kind == KIND_HELLO || kind == KIND_BYE
}

/// Validates a received header before the payload is allocated. Same order as Go's `checkHeader`: magic, flags,
/// reserved, kind (unknown, or a kind this side sends or never receives), length, run, incarnation, then the ids.
pub(crate) fn check_header(b: &[u8; HEADER_LEN], run: u64, inc: u32) -> Result<Header, ConnError> {
    if b[..4] != MAGIC {
        return Err(ConnError::BadMagic);
    }
    if b[5] != 0 {
        return Err(ConnError::Flags(b[5]));
    }
    let reserved = u16::from_be_bytes([b[6], b[7]]);
    if reserved != 0 {
        return Err(ConnError::Reserved(reserved));
    }
    let h = Header {
        kind: b[4],
        len: be32(b, 8),
        run: be64(b, 12),
        inc: be32(b, 20),
        tx: be64(b, 24),
        msg: be32(b, 32),
    };
    let Some(limit) = received_max(h.kind) else {
        return Err(
            if sent_range(h.kind).is_some()
                || matches!(h.kind, KIND_RESP_BEGIN | KIND_RESP_BODY | KIND_RESP_END)
            {
                ConnError::WrongDirection(h.kind)
            } else {
                ConnError::UnknownKind(h.kind)
            },
        );
    };
    if u64::from(h.len) > limit as u64 {
        return Err(ConnError::TooLong {
            kind: h.kind,
            len: h.len,
        });
    }
    if h.run != run {
        return Err(ConnError::RunMismatch(h.run));
    }
    if h.inc != inc {
        return Err(ConnError::IncMismatch(h.inc));
    }
    if is_control(h.kind) {
        if h.tx != 0 || h.msg != 0 {
            return Err(ConnError::ControlIds);
        }
    } else if h.tx == 0 || h.msg == 0 {
        return Err(ConnError::ZeroIds);
    }
    Ok(h)
}

/// Fills `buf`. Returns how many bytes arrived: fewer than `buf.len()` means EOF. `Interrupted` is retried.
fn fill<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<usize, ConnError> {
    let mut off = 0;
    while off < buf.len() {
        match r.read(&mut buf[off..]) {
            Ok(0) => break,
            // A Read that reports more than it was given would otherwise slice out of range.
            Ok(n) if n > buf.len() - off => return Err(ConnError::Io(ErrorKind::InvalidData)),
            Ok(n) => off += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(ConnError::Io(e.kind())),
        }
    }
    Ok(off)
}

/// Reads exactly one frame: the 36-byte header, then (only after `check_header` accepted it) a payload buffer of
/// exactly `len` bytes. A real deadline is the caller's job (a `Read` wrapper); this only needs `std::io::Read`.
pub(crate) fn read_frame<R: Read>(
    r: &mut R,
    run: u64,
    inc: u32,
) -> Result<(Header, Vec<u8>), ConnError> {
    let mut b = [0u8; HEADER_LEN];
    if fill(r, &mut b[..1])? == 0 {
        return Err(ConnError::PeerClosed);
    }
    let got = 1 + fill(r, &mut b[1..])?;
    if got < HEADER_LEN {
        return Err(ConnError::Truncated {
            got,
            want: HEADER_LEN,
        });
    }
    let h = check_header(&b, run, inc)?;
    // check_header bounded len by a limit of at most MAX_VERDICT/MAX_HELLO, so the conversion is exact.
    let want = h.len as usize;
    let mut p = vec![0u8; want];
    let got = fill(r, &mut p)?;
    if got < want {
        return Err(ConnError::Truncated { got, want });
    }
    Ok((h, p))
}

/// Builds one frame Rust sends. Only the kinds Rust sends are accepted; control (DRAIN) has tx = msg = 0 and the others
/// both nonzero; the payload length is within the kind's range (BODY 1..=64 KiB, the empty kinds 0). The content of
/// TX_BEGIN and TX_END comes from `encode_tx_begin` and `encode_tx_end`, and is checked here with the rules of Go's
/// `decodeTxBegin` and `decodeTxEnd`, so no frame Go rejects is built. A TX_BEGIN also needs msg 1: Go does not create a
/// transaction for another number (ERROR class 1, code 3).
///
/// A kind this side receives, a response kind, an unknown kind and wrong control or transaction ids are the caller's
/// mistakes, not an invalid request content; they are reported first, before the payload is looked at.
pub(crate) fn encode_frame(
    kind: u8,
    run: u64,
    inc: u32,
    tx: u64,
    msg: u32,
    payload: &[u8],
) -> Result<Vec<u8>, ContentError> {
    let Some((min, max)) = sent_range(kind) else {
        return Err(ContentError(if received_max(kind).is_some() {
            "frame kind is received, not sent, by this side"
        } else if matches!(kind, KIND_RESP_BEGIN | KIND_RESP_BODY | KIND_RESP_END) {
            "frame kind is not sent by this side"
        } else {
            "unknown frame kind"
        }));
    };
    if is_control(kind) {
        if tx != 0 || msg != 0 {
            return Err(ContentError("control frame with tx or msg"));
        }
    } else if tx == 0 || msg == 0 {
        return Err(ContentError("transaction frame with zero tx or msg"));
    }
    if payload.len() < min || payload.len() > max {
        return Err(ContentError("payload length out of range"));
    }
    match kind {
        KIND_TX_BEGIN => {
            if msg != 1 {
                return Err(ContentError("tx_begin message number is not 1"));
            }
            check_tx_begin(payload)?;
        }
        KIND_TX_END => check_tx_end(payload)?,
        _ => {}
    }
    let len = payload.len() as u32; // at most MAX_BODY, checked above
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&MAGIC);
    out.push(kind);
    out.push(0); // flags
    out.extend_from_slice(&[0, 0]); // reserved
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&run.to_be_bytes());
    out.extend_from_slice(&inc.to_be_bytes());
    out.extend_from_slice(&tx.to_be_bytes());
    out.extend_from_slice(&msg.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Appends a `str` (u16 length and the bytes) whose length must be in `lo..=hi`. The length is checked before any
/// byte is copied.
fn put_str(
    out: &mut Vec<u8>,
    s: &[u8],
    lo: usize,
    hi: usize,
    why: &'static str,
) -> Result<(), ContentError> {
    let n = u16::try_from(s.len()).map_err(|_| ContentError(why))?;
    if usize::from(n) < lo || usize::from(n) > hi {
        return Err(ContentError(why));
    }
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(s);
    Ok(())
}

fn put_declared(out: &mut Vec<u8>, declared: u64, why: &'static str) -> Result<(), ContentError> {
    if declared > MAX_DECLARED {
        return Err(ContentError(why));
    }
    out.extend_from_slice(&declared.to_be_bytes());
    Ok(())
}

/// Appends the header count and the (name, value) list. The count is checked first and the lengths of a name and a value
/// before each is copied; the running name + value total is checked after each item is appended.
fn put_headers(out: &mut Vec<u8>, headers: &[(&[u8], &[u8])]) -> Result<(), ContentError> {
    if headers.len() > MAX_HEADERS {
        return Err(ContentError("header count out of range"));
    }
    out.extend_from_slice(&(headers.len() as u16).to_be_bytes()); // at most MAX_HEADERS, checked above
    let mut total = 0usize;
    for (name, value) in headers {
        put_str(
            out,
            name,
            1,
            MAX_HDR_NAME,
            "header name length out of range",
        )?;
        put_str(
            out,
            value,
            0,
            MAX_HDR_VALUE,
            "header value length out of range",
        )?;
        total += name.len() + value.len();
        if total > MAX_HDR_TOTAL {
            return Err(ContentError("header total length out of range"));
        }
    }
    Ok(())
}

/// The limit of TX_BEGIN. The item bounds keep the payload under 30 KB, so this cannot fail.
fn finish_begin(out: Vec<u8>) -> Result<Vec<u8>, ContentError> {
    if out.len() > MAX_TX_BEGIN {
        return Err(ContentError("begin payload over limit"));
    }
    Ok(out)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TxBegin<'a> {
    pub client_addr: &'a [u8],
    pub client_port: u16,
    pub server_addr: &'a [u8],
    pub server_port: u16,
    pub method: &'a [u8],
    pub uri: &'a [u8],
    pub proto: &'a [u8],
    pub declared: u64,
    pub headers: &'a [(&'a [u8], &'a [u8])],
}

/// The TX_BEGIN payload, checked with the bounds of Go's `decodeTxBegin` before it is sent.
pub(crate) fn encode_tx_begin(t: &TxBegin) -> Result<Vec<u8>, ContentError> {
    let mut out = Vec::with_capacity(256);
    put_str(
        &mut out,
        t.client_addr,
        1,
        MAX_ADDR,
        "client address length out of range",
    )?;
    out.extend_from_slice(&t.client_port.to_be_bytes());
    put_str(
        &mut out,
        t.server_addr,
        1,
        MAX_ADDR,
        "server address length out of range",
    )?;
    out.extend_from_slice(&t.server_port.to_be_bytes());
    put_str(
        &mut out,
        t.method,
        1,
        MAX_METHOD,
        "method length out of range",
    )?;
    put_str(&mut out, t.uri, 1, MAX_URI, "uri length out of range")?;
    put_str(
        &mut out,
        t.proto,
        1,
        MAX_PROTO,
        "protocol length out of range",
    )?;
    put_declared(&mut out, t.declared, "declared body length out of range")?;
    put_headers(&mut out, t.headers)?;
    finish_begin(out)
}

/// The TX_END payload: the reason, 1 complete, 2 blocked, 3 uninspectable, 4 client disconnect, 5 deadline.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the engine builds the TX_END payload itself; the unit tests use this encoder"
    )
)]
pub(crate) fn encode_tx_end(reason: u8) -> Result<Vec<u8>, ContentError> {
    if !(END_COMPLETE..=END_DEADLINE).contains(&reason) {
        return Err(ContentError("tx_end reason out of range"));
    }
    Ok(vec![reason])
}

/// Checks the header count and the (name, value) list with the bounds of Go's `readHeaders`.
fn check_headers(c: &mut Cursor<'_>) -> Result<(), ContentError> {
    let n = c.u16()?;
    if usize::from(n) > MAX_HEADERS {
        return Err(ContentError("header count out of range"));
    }
    let mut total = 0usize;
    for _ in 0..n {
        let name = c.str16(1, MAX_HDR_NAME)?;
        let value = c.str16(0, MAX_HDR_VALUE)?;
        total += name.len() + value.len();
        if total > MAX_HDR_TOTAL {
            return Err(ContentError("header total length out of range"));
        }
    }
    Ok(())
}

/// Checks a TX_BEGIN payload with the structure and bounds of Go's `decodeTxBegin`, the same constants as
/// `encode_tx_begin`.
fn check_tx_begin(p: &[u8]) -> Result<(), ContentError> {
    let mut c = Cursor { p };
    c.str16(1, MAX_ADDR)?;
    c.u16()?;
    c.str16(1, MAX_ADDR)?;
    c.u16()?;
    c.str16(1, MAX_METHOD)?;
    c.str16(1, MAX_URI)?;
    c.str16(1, MAX_PROTO)?;
    if c.u64()? > MAX_DECLARED {
        return Err(ContentError("declared body length out of range"));
    }
    check_headers(&mut c)?;
    c.done()
}

/// Checks a TX_END payload as Go's `decodeTxEnd` does: exactly one byte, 1..=5.
fn check_tx_end(p: &[u8]) -> Result<(), ContentError> {
    match p {
        [r] if (END_COMPLETE..=END_DEADLINE).contains(r) => Ok(()),
        _ => Err(ContentError("tx_end payload is not one byte 1..=5")),
    }
}

/// Decodes a payload. Every read is bounds-checked; `done` requires the payload to be consumed exactly.
struct Cursor<'a> {
    p: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ContentError> {
        if self.p.len() < n {
            return Err(ContentError("payload too short"));
        }
        let (v, rest) = self.p.split_at(n);
        self.p = rest;
        Ok(v)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ContentError> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N)?);
        Ok(a)
    }

    fn u8(&mut self) -> Result<u8, ContentError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, ContentError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, ContentError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, ContentError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    /// A u16-prefixed byte string whose length must be in `lo..=hi`. The range is checked before the bytes are taken.
    fn str16(&mut self, lo: usize, hi: usize) -> Result<&'a [u8], ContentError> {
        let n = usize::from(self.u16()?);
        if n < lo || n > hi {
            return Err(ContentError("string length out of range"));
        }
        self.take(n)
    }

    fn done(&self) -> Result<(), ContentError> {
        if self.p.is_empty() {
            Ok(())
        } else {
            Err(ContentError("trailing bytes in payload"))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Hello {
    pub version: u16,
    pub pid: u32,
    pub nonce: [u8; 16],
    pub run: u64,
    pub inc: u32,
    pub go_version: Vec<u8>,
    pub coraza_version: Vec<u8>,
    pub coraza_sum: Vec<u8>,
    pub rules_sha256: [u8; 32],
    pub body_limit: u32,
    pub mem_limit: u64,
    pub gomaxprocs: u16,
    pub tx_limit: u16,
    pub queue: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Verdict {
    pub phase: u8,
    pub block: bool,
    pub flags: u8,
    pub rule_id: i64,
    pub status: u16,
    pub action: Vec<u8>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ErrorMsg {
    pub class: u8,
    pub code: u16,
    pub text: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Bye {
    pub started: u64,
    pub closed: u64,
    pub close_errors: u64,
}

/// Decodes HELLO. A version other than v0 is its own reason ("hello contract version is not v0"): the caller treats it
/// as a deterministic mismatch (no restart). The values (pid, nonce, run, inc, versions, sha256, limits) are
/// checked by the caller, not here.
pub(crate) fn decode_hello(p: &[u8]) -> Result<Hello, ContentError> {
    let mut c = Cursor { p };
    let version = c.u16()?;
    if version != 0 {
        return Err(ContentError("hello contract version is not v0"));
    }
    let pid = c.u32()?;
    let nonce = c.array::<16>()?;
    let run = c.u64()?;
    let inc = c.u32()?;
    let go_version = c.str16(1, MAX_GO_VERSION)?;
    let coraza_version = c.str16(1, MAX_CORAZA_VERSION)?;
    let coraza_sum = c.str16(1, MAX_CORAZA_SUM)?;
    let rules_sha256 = c.array::<32>()?;
    let body_limit = c.u32()?;
    let mem_limit = c.u64()?;
    let gomaxprocs = c.u16()?;
    let tx_limit = c.u16()?;
    let queue = c.u16()?;
    c.done()?;
    Ok(Hello {
        version,
        pid,
        nonce,
        run,
        inc,
        go_version: go_version.to_vec(),
        coraza_version: coraza_version.to_vec(),
        coraza_sum: coraza_sum.to_vec(),
        rules_sha256,
        body_limit,
        mem_limit,
        gomaxprocs,
        tx_limit,
        queue,
    })
}

/// Decodes VERDICT. Go cuts action and data only at their limits and then sets the matching flag (codec.go
/// `encodeVerdict`), so a flag needs the exact cut length (32 or 256), and a continuation carries no rule id, status,
/// action or data.
pub(crate) fn decode_verdict(p: &[u8]) -> Result<Verdict, ContentError> {
    let mut c = Cursor { p };
    let phase = c.u8()?;
    if !(1..=4).contains(&phase) {
        return Err(ContentError("verdict phase out of range"));
    }
    let block = match c.u8()? {
        0 => false,
        1 => true,
        _ => return Err(ContentError("verdict decision out of range")),
    };
    let flags = c.u8()?;
    if flags & !(FLAG_ACTION_TRUNCATED | FLAG_DATA_TRUNCATED) != 0 {
        return Err(ContentError("verdict flags out of range"));
    }
    if c.u8()? != 0 {
        return Err(ContentError("verdict reserved not zero"));
    }
    let rule_id = i64::from_be_bytes(c.array()?);
    let status = c.u16()?;
    let action = c.str16(0, MAX_ACTION)?;
    let data = c.str16(0, MAX_DATA)?;
    c.done()?;
    if !block && (rule_id != 0 || status != 0 || !action.is_empty() || !data.is_empty()) {
        return Err(ContentError("verdict continue carries interruption fields"));
    }
    if flags & FLAG_ACTION_TRUNCATED != 0 && action.len() != MAX_ACTION {
        return Err(ContentError(
            "verdict action cut flag needs a full-length action",
        ));
    }
    if flags & FLAG_DATA_TRUNCATED != 0 && data.len() != MAX_DATA {
        return Err(ContentError(
            "verdict data cut flag needs a full-length data",
        ));
    }
    Ok(Verdict {
        phase,
        block,
        flags,
        rule_id,
        status,
        action: action.to_vec(),
        data: data.to_vec(),
    })
}

/// Decodes ERROR. Class 1 (not created) has codes 1..=4 and class 2 (a created transaction failed) 16..=31.
pub(crate) fn decode_error(p: &[u8]) -> Result<ErrorMsg, ContentError> {
    let mut c = Cursor { p };
    let class = c.u8()?;
    if class != CLASS_NOT_CREATED && class != CLASS_TX_FAILED {
        return Err(ContentError("error class out of range"));
    }
    if c.u8()? != 0 {
        return Err(ContentError("error reserved not zero"));
    }
    let code = c.u16()?;
    let known = if class == CLASS_NOT_CREATED {
        (1..=4).contains(&code)
    } else {
        (16..=31).contains(&code)
    };
    if !known {
        return Err(ContentError("error code out of range for its class"));
    }
    let text = c.str16(0, MAX_ERR_MSG)?;
    c.done()?;
    Ok(ErrorMsg {
        class,
        code,
        text: text.to_vec(),
    })
}

/// Decodes CLOSED: exactly one byte, 0 (no Close error) or 1.
pub(crate) fn decode_closed(p: &[u8]) -> Result<bool, ContentError> {
    match p {
        [0] => Ok(false),
        [1] => Ok(true),
        _ => Err(ContentError("closed payload is not one byte 0 or 1")),
    }
}

/// Decodes BYE: exactly 24 bytes (started, closed, close errors).
pub(crate) fn decode_bye(p: &[u8]) -> Result<Bye, ContentError> {
    if p.len() != 24 {
        return Err(ContentError("bye payload is not 24 bytes"));
    }
    let mut c = Cursor { p };
    Ok(Bye {
        started: c.u64()?,
        closed: c.u64()?,
        close_errors: c.u64()?,
    })
}

/// The inspector build the product accepts: Go's toolchain and the Coraza module (version and `go.sum` hash). A HELLO
/// that reports anything else is refused. Change these together with the inspector's `go.mod` and `go.sum`.
pub(crate) const INSPECTOR_GO_VERSION: &[u8] = b"go1.27.2";
pub(crate) const INSPECTOR_CORAZA_VERSION: &[u8] = b"v3.8.1";
pub(crate) const INSPECTOR_CORAZA_SUM: &[u8] = b"h1:dMV55FbMR2vOks/acrT43RShR+VkzU6jwp+XPdxay8o=";

/// What a valid HELLO contains besides the start's own pid, run, incarnation and nonce, and the pinned inspector
/// build. The rules sha256 comes from the configuration. Go hashes the bytes it read and builds the WAF
/// from the same bytes, so HELLO ties the loaded rules to `rules_sha256`. `mem_limit` is `GOMEMLIMIT` and `gomaxprocs`
/// is `GOMAXPROCS`, as the inspector reports them.
pub(crate) struct HelloExpect<'a> {
    pub rules_sha256: &'a [u8; 32],
    pub mem_limit: u64,
    pub gomaxprocs: u16,
}

/// Compares a decoded HELLO with the start: `run` and `inc` are the ones passed in the environment, `pid` is the
/// child's pid and `nonce` the one passed in `TKV0_NONCE`. Any difference is deterministic: the caller does not
/// restart. The contract version is already checked by `decode_hello`; it is checked again. The body limit is Go's
/// `maxDeclared`, the transaction limit its `maxConcurTx` and the queue depth its `queueDepth`.
pub(crate) fn check_hello(
    h: &Hello,
    exp: &HelloExpect<'_>,
    run: u64,
    inc: u32,
    pid: u32,
    nonce: &[u8; 16],
) -> Result<(), &'static str> {
    if h.version != 0 {
        return Err("hello contract version is not v0");
    }
    if h.pid != pid {
        return Err("hello pid is not the child's pid");
    }
    if h.nonce != *nonce {
        return Err("hello nonce differs");
    }
    if h.run != run {
        return Err("hello run id differs");
    }
    if h.inc != inc {
        return Err("hello incarnation differs");
    }
    if h.go_version != INSPECTOR_GO_VERSION {
        return Err("hello go version differs");
    }
    if h.coraza_version != INSPECTOR_CORAZA_VERSION {
        return Err("hello coraza version differs");
    }
    if h.coraza_sum != INSPECTOR_CORAZA_SUM {
        return Err("hello coraza sum differs");
    }
    if h.rules_sha256 != *exp.rules_sha256 {
        return Err("hello rules sha256 differs");
    }
    if h.body_limit != MAX_DECLARED as u32 {
        return Err("hello body limit differs");
    }
    if h.mem_limit != exp.mem_limit {
        return Err("hello memory limit differs");
    }
    if h.gomaxprocs != exp.gomaxprocs {
        return Err("hello gomaxprocs differs");
    }
    if h.tx_limit != MAX_CONCUR_TX {
        return Err("hello transaction limit differs");
    }
    if h.queue != QUEUE_DEPTH {
        return Err("hello queue depth differs");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::io;

    const GOLDEN: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../inspector/testdata/v0-golden.txt"
    ));
    const RUN: u64 = 0x0102_0304_0506_0708;
    const INC: u32 = 7;
    const SENT: [&str; 8] = [
        "tx_begin",
        "body",
        "body_end",
        "resp_begin",
        "resp_body",
        "resp_end",
        "tx_end",
        "drain",
    ];
    const RECEIVED: [&str; 9] = [
        "hello",
        "verdict_continue",
        "verdict_block",
        "verdict_block_rule0",
        "verdict_truncated",
        "error_not_created",
        "error_tx_failed",
        "closed",
        "bye",
    ];
    // Receivable kinds with their payload limits.
    const RECV: [(u8, usize); 5] = [
        (KIND_HELLO, MAX_HELLO),
        (KIND_BYE, MAX_BYE),
        (KIND_VERDICT, MAX_VERDICT),
        (KIND_ERROR, MAX_ERROR),
        (KIND_CLOSED, MAX_CLOSED),
    ];

    // ---- golden file ----

    fn hex_decode(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0, "odd hex length");
        assert!(
            s.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
            "not lower-case hex"
        );
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The golden file in file order: `#` lines are notes, the others are `name hex-of-the-whole-frame`.
    fn parse_golden(text: &str) -> Vec<(String, Vec<u8>)> {
        let mut v = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (name, hx) = line.split_once(' ').expect("golden: bad line");
            v.push((name.to_string(), hex_decode(hx.trim())));
        }
        v
    }

    fn golden(name: &str) -> Vec<u8> {
        let mut hit = parse_golden(GOLDEN).into_iter().filter(|(n, _)| n == name);
        let (_, b) = hit
            .next()
            .unwrap_or_else(|| panic!("golden vector {name} missing"));
        assert!(hit.next().is_none(), "golden vector {name} duplicated");
        b
    }

    fn golden_payload(name: &str) -> Vec<u8> {
        golden(name)[HEADER_LEN..].to_vec()
    }

    #[test]
    fn golden_file_has_the_17_independent_vectors() {
        let all = parse_golden(GOLDEN);
        let names: Vec<&str> = all.iter().map(|(n, _)| n.as_str()).collect();
        let set: BTreeSet<&str> = names.iter().copied().collect();
        assert_eq!(all.len(), 17);
        assert_eq!(set.len(), names.len(), "duplicate golden name");
        let want: BTreeSet<&str> = SENT.iter().chain(RECEIVED.iter()).copied().collect();
        assert_eq!(set, want);
        for (n, b) in &all {
            assert!(b.len() >= HEADER_LEN, "{n} shorter than a header");
            assert_eq!(&b[..4], &MAGIC, "{n}");
            let len = u32::from_be_bytes([b[8], b[9], b[10], b[11]]) as usize;
            assert_eq!(len, b.len() - HEADER_LEN, "{n}: length field");
        }
    }

    // ---- Rust to Go: encoders against the golden bytes ----

    #[test]
    fn rust_to_go_frames_are_byte_identical_to_the_golden_vectors() {
        let hs: [(&[u8], &[u8]); 2] = [
            (b"Host", b"example.test"),
            (b"Content-Type", b"application/x-www-form-urlencoded"),
        ];
        let tx_begin = encode_tx_begin(&TxBegin {
            client_addr: b"127.0.0.1",
            client_port: 40000,
            server_addr: b"127.0.0.1",
            server_port: 8080,
            method: b"POST",
            uri: b"/a?q=1",
            proto: b"HTTP/1.1",
            declared: 5,
            headers: &hs,
        })
        .unwrap();
        let tx_end = encode_tx_end(1).unwrap();
        let cases: [(&str, Result<Vec<u8>, ContentError>); 5] = [
            (
                "tx_begin",
                encode_frame(KIND_TX_BEGIN, RUN, INC, 0x10, 1, &tx_begin),
            ),
            ("body", encode_frame(KIND_BODY, RUN, INC, 0x10, 2, b"a=b&c")),
            (
                "body_end",
                encode_frame(KIND_BODY_END, RUN, INC, 0x10, 3, &[]),
            ),
            (
                "tx_end",
                encode_frame(KIND_TX_END, RUN, INC, 0x10, 7, &tx_end),
            ),
            ("drain", encode_frame(KIND_DRAIN, RUN, INC, 0, 0, &[])),
        ];
        // The response vectors stay in the golden file (Go receives them); Rust does not send them.
        let covered: BTreeSet<&str> = cases.iter().map(|(n, _)| *n).collect();
        let sent: BTreeSet<&str> = SENT
            .iter()
            .copied()
            .filter(|n| !n.starts_with("resp_"))
            .collect();
        assert_eq!(covered, sent);
        for (name, got) in cases {
            assert_eq!(got.unwrap(), golden(name), "{name}");
        }
    }

    // ---- Go to Rust: read_frame and decode_* against the golden bytes ----

    fn hdr(kind: u8, len: u32, tx: u64, msg: u32) -> Header {
        Header {
            kind,
            len,
            run: RUN,
            inc: INC,
            tx,
            msg,
        }
    }

    /// Reads `name` followed by two sentinel bytes: the frame must be consumed exactly, not a byte more.
    fn read_golden(name: &str) -> (Header, Vec<u8>) {
        let mut bytes = golden(name);
        let n = bytes.len();
        bytes.extend_from_slice(&[0xaa, 0xbb]);
        let mut r: &[u8] = &bytes;
        let (h, p) = read_frame(&mut r, RUN, INC).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(
            r,
            &[0xaa, 0xbb],
            "{name}: consumed {} bytes, frame is {n}",
            bytes.len() - r.len()
        );
        assert_eq!(p.len(), n - HEADER_LEN, "{name}");
        assert_eq!(h.len as usize, p.len(), "{name}");
        (h, p)
    }

    #[test]
    fn golden_hello_reads_and_decodes() {
        let (h, p) = read_golden("hello");
        assert_eq!(h, hdr(KIND_HELLO, 111, 0, 0));
        let mut nonce = [0u8; 16];
        for (i, b) in nonce.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut sha = [0u8; 32];
        for (i, b) in sha.iter_mut().enumerate() {
            *b = 0xa0 + i as u8;
        }
        assert_eq!(
            decode_hello(&p).unwrap(),
            Hello {
                version: 0,
                pid: 0x1092,
                nonce,
                run: RUN,
                inc: INC,
                go_version: b"go1.27.2".to_vec(),
                coraza_version: b"v3.8.1".to_vec(),
                coraza_sum: b"h1:abc=".to_vec(),
                rules_sha256: sha,
                body_limit: 0x0010_0000,
                mem_limit: 0x1000_0000,
                gomaxprocs: 2,
                tx_limit: 4,
                queue: 0x11,
            }
        );
        assert_eq!(
            u64::from(decode_hello(&p).unwrap().body_limit),
            MAX_DECLARED
        );
        assert_eq!(decode_hello(&p).unwrap().tx_limit, MAX_CONCUR_TX);
        assert_eq!(decode_hello(&p).unwrap().queue, QUEUE_DEPTH);
    }

    #[test]
    fn golden_verdicts_read_and_decode() {
        let v = |phase, block, flags, rule_id, status, action: &[u8], data: &[u8]| Verdict {
            phase,
            block,
            flags,
            rule_id,
            status,
            action: action.to_vec(),
            data: data.to_vec(),
        };
        let cases = [
            (
                "verdict_continue",
                hdr(KIND_VERDICT, 18, 0x10, 1),
                v(1, false, 0, 0, 0, b"", b""),
            ),
            (
                "verdict_block",
                hdr(KIND_VERDICT, 23, 0x10, 2),
                v(2, true, 0, 1021, 403, b"deny", b"x"),
            ),
            (
                "verdict_block_rule0",
                hdr(KIND_VERDICT, 22, 0x10, 3),
                v(2, true, 0, 0, 413, b"deny", b""),
            ),
            (
                "verdict_truncated",
                hdr(KIND_VERDICT, 306, 0x10, 6),
                v(4, true, 3, 1040, 403, &[b'a'; 32], &[b'd'; 256]),
            ),
        ];
        for (name, want_h, want_v) in cases {
            let (h, p) = read_golden(name);
            assert_eq!(h, want_h, "{name}");
            assert_eq!(decode_verdict(&p).unwrap(), want_v, "{name}");
        }
    }

    #[test]
    fn golden_errors_read_and_decode() {
        let (h, p) = read_golden("error_not_created");
        assert_eq!(h, hdr(KIND_ERROR, 23, 0x11, 1));
        assert_eq!(
            decode_error(&p).unwrap(),
            ErrorMsg {
                class: 1,
                code: 1,
                text: b"concurrency limit".to_vec()
            }
        );
        let (h, p) = read_golden("error_tx_failed");
        assert_eq!(h, hdr(KIND_ERROR, 40, 0x10, 3));
        assert_eq!(
            decode_error(&p).unwrap(),
            ErrorMsg {
                class: 2,
                code: 22,
                text: b"request body shorter than declared".to_vec()
            }
        );
    }

    #[test]
    fn golden_closed_and_bye_read_and_decode() {
        let (h, p) = read_golden("closed");
        assert_eq!(h, hdr(KIND_CLOSED, 1, 0x10, 7));
        assert_eq!(decode_closed(&p), Ok(false));
        let (h, p) = read_golden("bye");
        assert_eq!(h, hdr(KIND_BYE, 24, 0, 0));
        assert_eq!(
            decode_bye(&p),
            Ok(Bye {
                started: 3,
                closed: 3,
                close_errors: 0
            })
        );
    }

    // ---- direction, FAULT and unknown kinds ----

    fn head_of(b: &[u8]) -> [u8; HEADER_LEN] {
        b[..HEADER_LEN].try_into().unwrap()
    }

    #[test]
    fn sent_goldens_are_wrong_direction_for_check_header() {
        for name in SENT {
            let b = golden(name);
            assert_eq!(
                check_header(&head_of(&b), RUN, INC),
                Err(ConnError::WrongDirection(b[4])),
                "{name}"
            );
        }
    }

    #[test]
    fn received_goldens_pass_check_header() {
        for name in RECEIVED {
            let b = golden(name);
            let h =
                check_header(&head_of(&b), RUN, INC).unwrap_or_else(|e| panic!("{name}: {e:?}"));
            assert_eq!(h.len as usize, b.len() - HEADER_LEN, "{name}");
        }
    }

    #[test]
    fn check_header_splits_all_256_kinds_into_received_sent_and_unknown() {
        for kind in 0..=255u8 {
            let received = RECV.iter().any(|(k, _)| *k == kind);
            let sent = SENT.iter().any(|n| golden(n)[4] == kind);
            let control = kind == KIND_HELLO || kind == KIND_BYE;
            let b = header(
                kind,
                0,
                if control { 0 } else { 0x10 },
                if control { 0 } else { 1 },
            );
            let got = check_header(&b, RUN, INC);
            if received {
                assert!(got.is_ok(), "kind {kind:#04x}: {got:?}");
            } else if sent {
                assert_eq!(
                    got,
                    Err(ConnError::WrongDirection(kind)),
                    "kind {kind:#04x}"
                );
            } else {
                assert_eq!(got, Err(ConnError::UnknownKind(kind)), "kind {kind:#04x}");
            }
        }
        // FAULT is reserved but unknown to this build.
        assert_eq!(
            check_header(&header(0x7f, 0, 0x10, 1), RUN, INC),
            Err(ConnError::UnknownKind(0x7f))
        );
    }

    #[test]
    fn encode_frame_accepts_only_the_kinds_rust_sends() {
        let mut accepted = 0;
        for kind in 0..=255u8 {
            let received = RECV.iter().any(|(k, _)| *k == kind);
            let resp = matches!(kind, KIND_RESP_BEGIN | KIND_RESP_BODY | KIND_RESP_END);
            let sent = !resp && SENT.iter().any(|n| golden(n)[4] == kind);
            let (tx, msg) = if kind == KIND_DRAIN {
                (0, 0)
            } else {
                (0x10, 1)
            };
            // The content of a begin or an end must decode, so these two kinds take the encoders' output.
            let payload: Vec<u8> = match kind {
                KIND_BODY | KIND_RESP_BODY => b"x".to_vec(),
                KIND_TX_BEGIN => encode_tx_begin(&begin()).unwrap(),
                KIND_TX_END => encode_tx_end(1).unwrap(),
                _ => Vec::new(),
            };
            let got = encode_frame(kind, RUN, INC, tx, msg, &payload);
            if sent {
                assert_eq!(got.unwrap()[4], kind, "kind {kind:#04x}");
                accepted += 1;
            } else if received {
                assert_eq!(
                    got,
                    Err(ContentError(
                        "frame kind is received, not sent, by this side"
                    )),
                    "kind {kind:#04x}"
                );
            } else if resp {
                assert_eq!(
                    got,
                    Err(ContentError("frame kind is not sent by this side")),
                    "kind {kind:#04x}"
                );
            } else {
                assert_eq!(
                    got,
                    Err(ContentError("unknown frame kind")),
                    "kind {kind:#04x}"
                );
            }
        }
        assert_eq!(accepted, 5);
        assert_eq!(
            encode_frame(0x7f, RUN, INC, 0x10, 1, b""),
            Err(ContentError("unknown frame kind"))
        );
    }

    #[test]
    fn a_response_kind_is_refused_before_ids_and_payload_are_looked_at() {
        let refused = Err(ContentError("frame kind is not sent by this side"));
        for kind in [KIND_RESP_BEGIN, KIND_RESP_BODY, KIND_RESP_END] {
            // Valid ids and an empty or a valid-looking payload, wrong ids, an oversize payload: the kind decides.
            assert_eq!(
                encode_frame(kind, RUN, INC, 0x10, 1, b"x"),
                refused,
                "{kind:#04x}"
            );
            assert_eq!(
                encode_frame(kind, RUN, INC, 0, 0, b""),
                refused,
                "{kind:#04x}"
            );
            assert_eq!(
                encode_frame(kind, RUN, INC, 0, 1, &vec![0u8; MAX_BODY + 1]),
                refused,
                "{kind:#04x}"
            );
        }
    }

    // ---- header mutations ----

    fn header(kind: u8, len: u32, tx: u64, msg: u32) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[..4].copy_from_slice(&MAGIC);
        b[4] = kind;
        b[8..12].copy_from_slice(&len.to_be_bytes());
        b[12..20].copy_from_slice(&RUN.to_be_bytes());
        b[20..24].copy_from_slice(&INC.to_be_bytes());
        b[24..32].copy_from_slice(&tx.to_be_bytes());
        b[32..36].copy_from_slice(&msg.to_be_bytes());
        b
    }

    /// A valid header of a receivable kind: control kinds carry tx = msg = 0, the others both nonzero.
    fn base(kind: u8) -> [u8; HEADER_LEN] {
        if kind == KIND_HELLO || kind == KIND_BYE {
            header(kind, 0, 0, 0)
        } else {
            header(kind, 0, 0x10, 1)
        }
    }

    fn set_ids(b: &mut [u8; HEADER_LEN], tx: u64, msg: u32) {
        b[24..32].copy_from_slice(&tx.to_be_bytes());
        b[32..36].copy_from_slice(&msg.to_be_bytes());
    }

    fn mutated(kind: u8, f: impl FnOnce(&mut [u8; HEADER_LEN])) -> Result<Header, ConnError> {
        let mut b = base(kind);
        f(&mut b);
        check_header(&b, RUN, INC)
    }

    #[test]
    fn header_magic_every_byte_and_bit() {
        for (kind, _) in RECV {
            for i in 0..4 {
                for bit in 0..8 {
                    assert_eq!(
                        mutated(kind, |b| b[i] ^= 1 << bit),
                        Err(ConnError::BadMagic),
                        "byte {i} bit {bit}"
                    );
                }
            }
        }
    }

    #[test]
    fn header_flags_every_nonzero_value() {
        for (kind, _) in RECV {
            for v in 1..=255u8 {
                assert_eq!(mutated(kind, |b| b[5] = v), Err(ConnError::Flags(v)));
            }
        }
    }

    #[test]
    fn header_reserved_both_bytes() {
        for (kind, _) in RECV {
            assert_eq!(
                mutated(kind, |b| b[6] = 1),
                Err(ConnError::Reserved(0x0100))
            );
            assert_eq!(
                mutated(kind, |b| b[7] = 1),
                Err(ConnError::Reserved(0x0001))
            );
            assert_eq!(
                mutated(kind, |b| b[6..8].copy_from_slice(&[0xff, 0xff])),
                Err(ConnError::Reserved(0xffff))
            );
        }
    }

    #[test]
    fn header_length_exactly_the_limit_passes_and_one_more_is_too_long() {
        for (kind, max) in RECV {
            let max = max as u32;
            let ok = mutated(kind, |b| b[8..12].copy_from_slice(&max.to_be_bytes())).unwrap();
            assert_eq!(ok.len, max, "kind {kind:#04x}");
            for len in [max + 1, 0x0001_0000, u32::MAX] {
                assert_eq!(
                    mutated(kind, |b| b[8..12].copy_from_slice(&len.to_be_bytes())),
                    Err(ConnError::TooLong { kind, len }),
                    "kind {kind:#04x} len {len}"
                );
            }
        }
    }

    #[test]
    fn header_run_and_incarnation_mismatch_every_byte() {
        for (kind, _) in RECV {
            for i in 12..20 {
                let want = RUN ^ (0xffu64 << (8 * (19 - i)));
                assert_eq!(
                    mutated(kind, |b| b[i] ^= 0xff),
                    Err(ConnError::RunMismatch(want)),
                    "run byte {i}"
                );
            }
            for i in 20..24 {
                let want = INC ^ (0xffu32 << (8 * (23 - i)));
                assert_eq!(
                    mutated(kind, |b| b[i] ^= 0xff),
                    Err(ConnError::IncMismatch(want)),
                    "inc byte {i}"
                );
            }
        }
    }

    #[test]
    fn header_control_frames_need_zero_ids_and_the_others_nonzero_ids() {
        for kind in [KIND_HELLO, KIND_BYE] {
            assert_eq!(mutated(kind, |b| b[31] = 1), Err(ConnError::ControlIds));
            assert_eq!(mutated(kind, |b| b[35] = 1), Err(ConnError::ControlIds));
            assert_eq!(mutated(kind, |b| b[24] = 0x80), Err(ConnError::ControlIds));
            assert_eq!(
                mutated(kind, |b| set_ids(b, u64::MAX, u32::MAX)),
                Err(ConnError::ControlIds)
            );
        }
        for kind in [KIND_VERDICT, KIND_ERROR, KIND_CLOSED] {
            assert_eq!(
                mutated(kind, |b| b[24..32].fill(0)),
                Err(ConnError::ZeroIds)
            );
            assert_eq!(
                mutated(kind, |b| b[32..36].fill(0)),
                Err(ConnError::ZeroIds)
            );
            assert_eq!(mutated(kind, |b| set_ids(b, 0, 0)), Err(ConnError::ZeroIds));
            let max = mutated(kind, |b| set_ids(b, u64::MAX, u32::MAX)).unwrap();
            assert_eq!((max.tx, max.msg), (u64::MAX, u32::MAX));
        }
    }

    #[test]
    fn header_checks_run_in_the_go_order() {
        let long = (MAX_VERDICT as u32 + 1).to_be_bytes();
        // magic before flags
        assert_eq!(
            mutated(KIND_VERDICT, |b| {
                b[0] = b'X';
                b[5] = 1;
            }),
            Err(ConnError::BadMagic)
        );
        // flags before reserved
        assert_eq!(
            mutated(KIND_VERDICT, |b| {
                b[5] = 1;
                b[7] = 1;
            }),
            Err(ConnError::Flags(1))
        );
        // flags and reserved come before the kind (Go checks them first): a kind Rust sends, and an unknown kind
        assert_eq!(
            mutated(KIND_VERDICT, |b| {
                b[4] = KIND_DRAIN;
                b[5] = 1;
            }),
            Err(ConnError::Flags(1))
        );
        assert_eq!(
            mutated(KIND_VERDICT, |b| {
                b[4] = 0x7f;
                b[7] = 1;
            }),
            Err(ConnError::Reserved(1))
        );
        // the kind before the length, run, incarnation and ids
        assert_eq!(
            mutated(KIND_VERDICT, |b| {
                b[4] = KIND_TX_BEGIN;
                b[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
                b[19] ^= 1;
                b[23] ^= 1;
                set_ids(b, 0, 0);
            }),
            Err(ConnError::WrongDirection(KIND_TX_BEGIN))
        );
        assert_eq!(
            mutated(KIND_VERDICT, |b| {
                b[4] = 0x7f;
                b[19] ^= 1;
            }),
            Err(ConnError::UnknownKind(0x7f))
        );
        // the length before run, incarnation and ids
        assert_eq!(
            mutated(KIND_VERDICT, |b| {
                b[8..12].copy_from_slice(&long);
                b[19] ^= 1;
                b[23] ^= 1;
                set_ids(b, 0, 0);
            }),
            Err(ConnError::TooLong {
                kind: KIND_VERDICT,
                len: MAX_VERDICT as u32 + 1
            })
        );
        // run before incarnation before ids
        assert_eq!(
            mutated(KIND_VERDICT, |b| {
                b[19] ^= 1;
                b[23] ^= 1;
                set_ids(b, 0, 0);
            }),
            Err(ConnError::RunMismatch(RUN ^ 1))
        );
        assert_eq!(
            mutated(KIND_VERDICT, |b| {
                b[23] ^= 1;
                set_ids(b, 0, 0);
            }),
            Err(ConnError::IncMismatch(INC ^ 1))
        );
        assert_eq!(
            mutated(KIND_VERDICT, |b| set_ids(b, 0, 0)),
            Err(ConnError::ZeroIds)
        );
    }

    // ---- read_frame: no allocation before the check, EOF, interruption, short reads ----

    /// A scripted Read: serves `data` in pieces of at most `chunk` bytes, optionally fails with `Interrupted` before
    /// every other read, errors once `fail` bytes were served, or reports more than it was given. `pos` is how many
    /// bytes were consumed; a read with an empty buffer is a test failure.
    struct Fake<'a> {
        data: &'a [u8],
        pos: usize,
        chunk: usize,
        interrupt: bool,
        calls: usize,
        fail: Option<(usize, ErrorKind)>,
        over_report: bool,
    }

    impl<'a> Fake<'a> {
        fn new(data: &'a [u8]) -> Self {
            Fake {
                data,
                pos: 0,
                chunk: usize::MAX,
                interrupt: false,
                calls: 0,
                fail: None,
                over_report: false,
            }
        }
    }

    impl Read for Fake<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            assert!(!buf.is_empty(), "read called with an empty buffer");
            self.calls += 1;
            if self.interrupt && self.calls % 2 == 1 {
                return Err(io::Error::from(ErrorKind::Interrupted));
            }
            let mut n = buf.len().min(self.chunk).min(self.data.len() - self.pos);
            if let Some((at, kind)) = self.fail {
                if self.pos >= at {
                    return Err(io::Error::from(kind));
                }
                n = n.min(at - self.pos);
            }
            if self.over_report {
                return Ok(buf.len() + 1);
            }
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    #[test]
    fn oversize_header_is_rejected_after_exactly_36_bytes() {
        // A VERDICT of u32::MAX bytes, with plenty more bytes available: only the header is consumed.
        let mut data = header(KIND_VERDICT, u32::MAX, 0x10, 1).to_vec();
        data.extend_from_slice(&[0u8; 200]);
        let mut f = Fake::new(&data);
        assert_eq!(
            read_frame(&mut f, RUN, INC),
            Err(ConnError::TooLong {
                kind: KIND_VERDICT,
                len: u32::MAX
            })
        );
        assert_eq!(f.pos, HEADER_LEN);
        // The limit plus one for every receivable kind, and a wrong-direction kind: the same.
        for (kind, max) in RECV {
            let mut b = base(kind);
            b[8..12].copy_from_slice(&(max as u32 + 1).to_be_bytes());
            let mut data = b.to_vec();
            data.extend_from_slice(&[0u8; 2000]);
            let mut f = Fake::new(&data);
            let got = read_frame(&mut f, RUN, INC);
            assert!(
                matches!(got, Err(ConnError::TooLong { .. })),
                "kind {kind:#04x}: {got:?}"
            );
            assert_eq!(f.pos, HEADER_LEN, "kind {kind:#04x}");
        }
        let mut data = header(KIND_TX_BEGIN, u32::MAX, 0x10, 1).to_vec();
        data.extend_from_slice(&[0u8; 200]);
        let mut f = Fake::new(&data);
        assert_eq!(
            read_frame(&mut f, RUN, INC),
            Err(ConnError::WrongDirection(KIND_TX_BEGIN))
        );
        assert_eq!(f.pos, HEADER_LEN);
    }

    #[test]
    fn eof_before_the_first_byte_is_peer_closed_and_later_eof_is_truncated() {
        let full = golden("verdict_block");
        let payload_len = full.len() - HEADER_LEN;
        let mut f = Fake::new(&[]);
        assert_eq!(read_frame(&mut f, RUN, INC), Err(ConnError::PeerClosed));
        for n in 1..HEADER_LEN {
            let mut f = Fake::new(&full[..n]);
            assert_eq!(
                read_frame(&mut f, RUN, INC),
                Err(ConnError::Truncated {
                    got: n,
                    want: HEADER_LEN
                }),
                "{n}"
            );
        }
        for n in HEADER_LEN..full.len() {
            let mut f = Fake::new(&full[..n]);
            assert_eq!(
                read_frame(&mut f, RUN, INC),
                Err(ConnError::Truncated {
                    got: n - HEADER_LEN,
                    want: payload_len
                }),
                "{n}"
            );
        }
        let mut f = Fake::new(&full);
        let (h, p) = read_frame(&mut f, RUN, INC).unwrap();
        assert_eq!(
            (h.kind, p.len(), f.pos),
            (KIND_VERDICT, payload_len, full.len())
        );
    }

    #[test]
    fn interrupted_reads_and_one_byte_reads_give_the_same_frames() {
        for name in RECEIVED {
            let data = golden(name);
            let (want_h, want_p) = read_golden(name);
            for (chunk, interrupt) in [(1, false), (1, true), (7, true), (usize::MAX, true)] {
                let mut f = Fake {
                    chunk,
                    interrupt,
                    ..Fake::new(&data)
                };
                let (h, p) = read_frame(&mut f, RUN, INC)
                    .unwrap_or_else(|e| panic!("{name} {chunk} {interrupt}: {e:?}"));
                assert_eq!(
                    (h, p),
                    (want_h, want_p.clone()),
                    "{name} chunk {chunk} interrupt {interrupt}"
                );
                assert_eq!(f.pos, data.len(), "{name}");
            }
        }
    }

    #[test]
    fn io_errors_are_reported_with_their_kind_and_the_position_does_not_matter() {
        let data = golden("verdict_block");
        for (at, kind) in [
            (0, ErrorKind::TimedOut),
            (10, ErrorKind::WouldBlock),
            (HEADER_LEN + 3, ErrorKind::ConnectionReset),
        ] {
            let mut f = Fake {
                fail: Some((at, kind)),
                ..Fake::new(&data)
            };
            assert_eq!(
                read_frame(&mut f, RUN, INC),
                Err(ConnError::Io(kind)),
                "fail at {at}"
            );
        }
    }

    #[test]
    fn a_read_that_reports_more_than_it_was_given_is_an_io_error() {
        let data = golden("closed");
        let mut f = Fake {
            over_report: true,
            ..Fake::new(&data)
        };
        assert_eq!(
            read_frame(&mut f, RUN, INC),
            Err(ConnError::Io(ErrorKind::InvalidData))
        );
    }

    /// Reports 10 bytes on the first read and then one more than the room it was given: that is less than the whole
    /// buffer, but more than what is left after the 10.
    struct OverAfterTen {
        calls: usize,
    }

    impl Read for OverAfterTen {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.calls += 1;
            if self.calls == 1 {
                buf[..10].fill(0);
                Ok(10)
            } else {
                Ok(buf.len() + 1)
            }
        }
    }

    #[test]
    fn fill_rejects_a_count_over_the_room_left_after_a_partial_read() {
        let mut buf = [0u8; HEADER_LEN];
        let mut r = OverAfterTen { calls: 0 };
        assert_eq!(
            fill(&mut r, &mut buf),
            Err(ConnError::Io(ErrorKind::InvalidData))
        );
        assert_eq!(r.calls, 2);
    }

    #[test]
    fn a_zero_length_payload_is_returned_without_reading_it() {
        // The Fake panics on a read with an empty buffer. decode_* then reject the empty content.
        let data = header(KIND_VERDICT, 0, 0x10, 1);
        let mut f = Fake::new(&data);
        let (h, p) = read_frame(&mut f, RUN, INC).unwrap();
        assert_eq!((h.len, p.len(), f.pos), (0, 0, HEADER_LEN));
        assert!(decode_verdict(&p).is_err());
    }

    // ---- payload mutations (the five received kinds) ----

    fn tstr(v: &mut Vec<u8>, s: &[u8]) {
        v.extend_from_slice(&(s.len() as u16).to_be_bytes());
        v.extend_from_slice(s);
    }

    fn verdict(
        phase: u8,
        decision: u8,
        flags: u8,
        reserved: u8,
        rule: i64,
        status: u16,
        action: &[u8],
        data: &[u8],
    ) -> Vec<u8> {
        let mut v = vec![phase, decision, flags, reserved];
        v.extend_from_slice(&rule.to_be_bytes());
        v.extend_from_slice(&status.to_be_bytes());
        tstr(&mut v, action);
        tstr(&mut v, data);
        v
    }

    fn errmsg(class: u8, reserved: u8, code: u16, text: &[u8]) -> Vec<u8> {
        let mut v = vec![class, reserved];
        v.extend_from_slice(&code.to_be_bytes());
        tstr(&mut v, text);
        v
    }

    fn hello(version: u16, go: &[u8], coraza: &[u8], sum: &[u8]) -> Vec<u8> {
        let mut v = version.to_be_bytes().to_vec();
        v.extend_from_slice(&0x1092u32.to_be_bytes());
        v.extend(0..16u8);
        v.extend_from_slice(&RUN.to_be_bytes());
        v.extend_from_slice(&INC.to_be_bytes());
        tstr(&mut v, go);
        tstr(&mut v, coraza);
        tstr(&mut v, sum);
        v.extend((0..32u8).map(|i| 0xa0 + i));
        v.extend_from_slice(&0x0010_0000u32.to_be_bytes());
        v.extend_from_slice(&0x1000_0000u64.to_be_bytes());
        v.extend_from_slice(&2u16.to_be_bytes());
        v.extend_from_slice(&4u16.to_be_bytes());
        v.extend_from_slice(&17u16.to_be_bytes());
        v
    }

    fn reason<T: std::fmt::Debug>(r: Result<T, ContentError>) -> &'static str {
        r.unwrap_err().0
    }

    /// Decodes a received payload with the decoder of its kind.
    fn decode_named(name: &str, p: &[u8]) -> Result<(), ContentError> {
        match name {
            "hello" => decode_hello(p).map(drop),
            "closed" => decode_closed(p).map(drop),
            "bye" => decode_bye(p).map(drop),
            n if n.starts_with("verdict") => decode_verdict(p).map(drop),
            n if n.starts_with("error") => decode_error(p).map(drop),
            n => panic!("no decoder for {n}"),
        }
    }

    #[test]
    fn test_payload_builders_reproduce_the_golden_payloads() {
        assert_eq!(
            verdict(1, 0, 0, 0, 0, 0, b"", b""),
            golden_payload("verdict_continue")
        );
        assert_eq!(
            verdict(2, 1, 0, 0, 1021, 403, b"deny", b"x"),
            golden_payload("verdict_block")
        );
        assert_eq!(
            verdict(2, 1, 0, 0, 0, 413, b"deny", b""),
            golden_payload("verdict_block_rule0")
        );
        assert_eq!(
            verdict(4, 1, 3, 0, 1040, 403, &[b'a'; 32], &[b'd'; 256]),
            golden_payload("verdict_truncated")
        );
        assert_eq!(
            errmsg(1, 0, 1, b"concurrency limit"),
            golden_payload("error_not_created")
        );
        assert_eq!(
            errmsg(2, 0, 22, b"request body shorter than declared"),
            golden_payload("error_tx_failed")
        );
        assert_eq!(
            hello(0, b"go1.27.2", b"v3.8.1", b"h1:abc="),
            golden_payload("hello")
        );
    }

    #[test]
    fn every_golden_payload_with_one_byte_missing_one_extra_or_cut_anywhere_is_rejected() {
        for name in RECEIVED {
            let p = golden_payload(name);
            assert!(decode_named(name, &p).is_ok(), "{name}");
            for n in 0..p.len() {
                assert!(decode_named(name, &p[..n]).is_err(), "{name} cut to {n}");
            }
            let mut extra = p.clone();
            extra.push(0);
            assert!(decode_named(name, &extra).is_err(), "{name} plus one byte");
        }
        // The reasons of the two simplest cases.
        let p = golden_payload("verdict_block");
        assert_eq!(
            reason(decode_verdict(&p[..p.len() - 1])),
            "payload too short"
        );
        let mut extra = p.clone();
        extra.push(0);
        assert_eq!(reason(decode_verdict(&extra)), "trailing bytes in payload");
    }

    #[test]
    fn verdict_accepts_the_boundaries_go_emits() {
        // Phases 1..=4, continue and block.
        for phase in 1..=4 {
            assert!(decode_verdict(&verdict(phase, 0, 0, 0, 0, 0, b"", b"")).is_ok());
            assert!(decode_verdict(&verdict(phase, 1, 0, 0, 7, 403, b"deny", b"")).is_ok());
        }
        // Exactly 32 / 256 bytes without a flag (Go's encodeVerdict only flags what it cut).
        let v = decode_verdict(&verdict(2, 1, 0, 0, 1, 403, &[b'a'; 32], &[b'd'; 256])).unwrap();
        assert_eq!(
            (v.flags, v.action.len(), v.data.len()),
            (0, MAX_ACTION, MAX_DATA)
        );
        // A negative rule id (two's complement) and the largest status.
        let v = decode_verdict(&verdict(3, 1, 0, 0, -7, 65535, b"deny", b"x")).unwrap();
        assert_eq!((v.rule_id, v.status), (-7, 65535));
        let v = decode_verdict(&verdict(3, 1, 0, 0, i64::MIN, 0, b"", b"")).unwrap();
        assert_eq!((v.rule_id, v.status), (i64::MIN, 0));
        // Each cut flag with exactly the cut length, and both.
        assert_eq!(
            decode_verdict(&verdict(2, 1, 1, 0, 1, 403, &[b'a'; 32], b"x"))
                .unwrap()
                .flags,
            1
        );
        assert_eq!(
            decode_verdict(&verdict(2, 1, 2, 0, 1, 403, b"deny", &[b'd'; 256]))
                .unwrap()
                .flags,
            2
        );
        assert_eq!(
            decode_verdict(&verdict(2, 1, 3, 0, 1, 403, &[b'a'; 32], &[b'd'; 256]))
                .unwrap()
                .flags,
            3
        );
        // Non-UTF-8 bytes pass through unchanged.
        let v = decode_verdict(&verdict(2, 1, 0, 0, 1, 403, &[0xff, 0x00], &[0x80])).unwrap();
        assert_eq!((v.action, v.data), (vec![0xff, 0x00], vec![0x80]));
    }

    #[test]
    fn verdict_rejects_out_of_range_values_with_the_matching_reason() {
        let ok = |phase, decision, flags, reserved, rule, status, action: &[u8], data: &[u8]| {
            reason(decode_verdict(&verdict(
                phase, decision, flags, reserved, rule, status, action, data,
            )))
        };
        assert_eq!(
            ok(0, 1, 0, 0, 1, 403, b"deny", b""),
            "verdict phase out of range"
        );
        assert_eq!(
            ok(5, 1, 0, 0, 1, 403, b"deny", b""),
            "verdict phase out of range"
        );
        assert_eq!(
            ok(255, 0, 0, 0, 0, 0, b"", b""),
            "verdict phase out of range"
        );
        assert_eq!(
            ok(1, 2, 0, 0, 0, 0, b"", b""),
            "verdict decision out of range"
        );
        assert_eq!(
            ok(1, 255, 0, 0, 0, 0, b"", b""),
            "verdict decision out of range"
        );
        for flags in [4, 8, 0x80, 0xfc, 0xff] {
            assert_eq!(
                ok(2, 1, flags, 0, 1, 403, b"deny", b""),
                "verdict flags out of range",
                "flags {flags}"
            );
        }
        assert_eq!(
            ok(2, 1, 0, 1, 1, 403, b"deny", b""),
            "verdict reserved not zero"
        );
        assert_eq!(
            ok(2, 1, 0, 255, 1, 403, b"deny", b""),
            "verdict reserved not zero"
        );
        // A continuation carries no rule id, status, action or data.
        assert_eq!(
            ok(1, 0, 0, 0, 1, 0, b"", b""),
            "verdict continue carries interruption fields"
        );
        assert_eq!(
            ok(1, 0, 0, 0, -1, 0, b"", b""),
            "verdict continue carries interruption fields"
        );
        assert_eq!(
            ok(1, 0, 0, 0, 0, 403, b"", b""),
            "verdict continue carries interruption fields"
        );
        assert_eq!(
            ok(1, 0, 0, 0, 0, 0, b"a", b""),
            "verdict continue carries interruption fields"
        );
        assert_eq!(
            ok(1, 0, 0, 0, 0, 0, b"", b"d"),
            "verdict continue carries interruption fields"
        );
        // Lengths: action 33, data 257, and a length that exceeds what is left.
        assert_eq!(
            ok(2, 1, 0, 0, 1, 403, &[b'a'; 33], b""),
            "string length out of range"
        );
        assert_eq!(
            ok(2, 1, 0, 0, 1, 403, b"deny", &[b'd'; 257]),
            "string length out of range"
        );
        let mut p = verdict(2, 1, 0, 0, 1, 403, b"deny", b"x");
        p[14..16].copy_from_slice(&20u16.to_be_bytes()); // action length 20 but only 7 bytes follow
        assert_eq!(reason(decode_verdict(&p)), "payload too short");
        p[14..16].copy_from_slice(&0xffffu16.to_be_bytes());
        assert_eq!(reason(decode_verdict(&p)), "string length out of range");
        // A cut flag needs the exact cut length.
        assert_eq!(
            ok(2, 1, 1, 0, 1, 403, b"deny", b""),
            "verdict action cut flag needs a full-length action"
        );
        assert_eq!(
            ok(2, 1, 1, 0, 1, 403, &[b'a'; 31], b""),
            "verdict action cut flag needs a full-length action"
        );
        assert_eq!(
            ok(2, 1, 2, 0, 1, 403, b"deny", b"x"),
            "verdict data cut flag needs a full-length data"
        );
        assert_eq!(
            ok(2, 1, 2, 0, 1, 403, b"deny", &[b'd'; 255]),
            "verdict data cut flag needs a full-length data"
        );
        // A flag on a continuation fails because the cut field is empty.
        assert_eq!(
            ok(1, 0, 1, 0, 0, 0, b"", b""),
            "verdict action cut flag needs a full-length action"
        );
    }

    #[test]
    fn error_accepts_every_code_of_its_class_and_the_text_boundaries() {
        for code in 1..=4 {
            assert_eq!(decode_error(&errmsg(1, 0, code, b"x")).unwrap().code, code);
        }
        for code in 16..=31 {
            assert_eq!(decode_error(&errmsg(2, 0, code, b"x")).unwrap().code, code);
        }
        assert_eq!(
            decode_error(&errmsg(1, 0, 1, b"")).unwrap().text,
            Vec::<u8>::new()
        );
        assert_eq!(
            decode_error(&errmsg(2, 0, 17, &[b't'; 256]))
                .unwrap()
                .text
                .len(),
            MAX_ERR_MSG
        );
        assert_eq!(
            decode_error(&errmsg(2, 0, 17, &[0xff, 0x00])).unwrap().text,
            vec![0xff, 0x00]
        );
    }

    #[test]
    fn error_rejects_out_of_range_values_with_the_matching_reason() {
        for class in [0, 3, 255] {
            assert_eq!(
                reason(decode_error(&errmsg(class, 0, 1, b""))),
                "error class out of range"
            );
        }
        assert_eq!(
            reason(decode_error(&errmsg(1, 1, 1, b""))),
            "error reserved not zero"
        );
        assert_eq!(
            reason(decode_error(&errmsg(2, 255, 17, b""))),
            "error reserved not zero"
        );
        // Codes outside their class, including the codes of the other class and the neighbours of each range.
        for code in [0, 5, 15, 16, 17, 31, 32, 0xffff] {
            assert_eq!(
                reason(decode_error(&errmsg(1, 0, code, b""))),
                "error code out of range for its class",
                "1/{code}"
            );
        }
        for code in [0, 1, 4, 5, 15, 32, 0xffff] {
            assert_eq!(
                reason(decode_error(&errmsg(2, 0, code, b""))),
                "error code out of range for its class",
                "2/{code}"
            );
        }
        assert_eq!(
            reason(decode_error(&errmsg(2, 0, 17, &[b't'; 257]))),
            "string length out of range"
        );
        let mut p = errmsg(2, 0, 17, b"abc");
        p[4..6].copy_from_slice(&10u16.to_be_bytes()); // text length 10 but only 3 bytes follow
        assert_eq!(reason(decode_error(&p)), "payload too short");
    }

    #[test]
    fn hello_accepts_the_string_boundaries_and_rejects_the_rest() {
        let s = |b: u8, n: usize| vec![b; n];
        let h = decode_hello(&hello(0, &s(b'g', 64), &s(b'v', 64), &s(b's', 128))).unwrap();
        assert_eq!(
            (
                h.go_version.len(),
                h.coraza_version.len(),
                h.coraza_sum.len()
            ),
            (64, 64, 128)
        );
        assert_eq!(
            decode_hello(&hello(0, &[0xff], &[0x00], &[0x80]))
                .unwrap()
                .go_version,
            vec![0xff]
        );
        let bad =
            |go: &[u8], coraza: &[u8], sum: &[u8]| reason(decode_hello(&hello(0, go, coraza, sum)));
        assert_eq!(bad(b"", b"v", b"s"), "string length out of range");
        assert_eq!(bad(&s(b'g', 65), b"v", b"s"), "string length out of range");
        assert_eq!(bad(b"g", b"", b"s"), "string length out of range");
        assert_eq!(bad(b"g", &s(b'v', 65), b"s"), "string length out of range");
        assert_eq!(bad(b"g", b"v", b""), "string length out of range");
        assert_eq!(bad(b"g", b"v", &s(b's', 129)), "string length out of range");
        // The version has its own reason; any other value is the same.
        for version in [1u16, 0x0100, 0xffff] {
            assert_eq!(
                reason(decode_hello(&hello(version, b"g", b"v", b"s"))),
                "hello contract version is not v0"
            );
        }
        // A string length that exceeds what is left.
        let mut p = hello(0, b"g", b"v", b"s");
        p[34..36].copy_from_slice(&60u16.to_be_bytes());
        assert_eq!(reason(decode_hello(&p)), "payload too short");
        // The largest HELLO stays within its header limit.
        assert!(hello(0, &s(b'g', 64), &s(b'v', 64), &s(b's', 128)).len() <= MAX_HELLO);
    }

    #[test]
    fn closed_and_bye_need_their_exact_lengths_and_values() {
        assert_eq!(decode_closed(&[0]), Ok(false));
        assert_eq!(decode_closed(&[1]), Ok(true));
        for p in [&[2u8][..], &[255], &[], &[0, 0], &[1, 0], &[0; 8]] {
            assert_eq!(
                decode_closed(p),
                Err(ContentError("closed payload is not one byte 0 or 1")),
                "{p:?}"
            );
        }
        let bye = |n: usize| decode_bye(&vec![1u8; n]);
        assert_eq!(
            bye(24),
            Ok(Bye {
                started: 0x0101_0101_0101_0101,
                closed: 0x0101_0101_0101_0101,
                close_errors: 0x0101_0101_0101_0101
            })
        );
        for n in [0, 1, 8, 16, 23, 25, 32, 64] {
            assert_eq!(
                bye(n),
                Err(ContentError("bye payload is not 24 bytes")),
                "len {n}"
            );
        }
        let mut p = Vec::new();
        for v in [u64::MAX, 2, 1] {
            p.extend_from_slice(&v.to_be_bytes());
        }
        assert_eq!(
            decode_bye(&p),
            Ok(Bye {
                started: u64::MAX,
                closed: 2,
                close_errors: 1
            })
        );
    }

    // ---- encoders: boundaries ----

    fn begin<'a>() -> TxBegin<'a> {
        TxBegin {
            client_addr: b"127.0.0.1",
            client_port: 40000,
            server_addr: b"127.0.0.1",
            server_port: 8080,
            method: b"POST",
            uri: b"/a?q=1",
            proto: b"HTTP/1.1",
            declared: 5,
            headers: &[],
        }
    }

    fn accept_begin(t: &TxBegin) {
        assert!(encode_tx_begin(t).is_ok(), "{:?}", encode_tx_begin(t));
    }

    fn reject_begin(t: &TxBegin, why: &str) {
        assert_eq!(reason(encode_tx_begin(t)), why);
    }

    #[test]
    fn tx_begin_item_boundaries() {
        let rep = |b: u8, n: usize| vec![b; n];
        // The minimum.
        accept_begin(&TxBegin {
            client_addr: b"a",
            server_addr: b"b",
            method: b"G",
            uri: b"/",
            proto: b"H",
            declared: 0,
            ..begin()
        });
        // Addresses 1..=64.
        let a64 = rep(b'1', 64);
        accept_begin(&TxBegin {
            client_addr: &a64,
            server_addr: &a64,
            ..begin()
        });
        reject_begin(
            &TxBegin {
                client_addr: &rep(b'1', 65),
                ..begin()
            },
            "client address length out of range",
        );
        reject_begin(
            &TxBegin {
                client_addr: b"",
                ..begin()
            },
            "client address length out of range",
        );
        reject_begin(
            &TxBegin {
                server_addr: &rep(b'1', 65),
                ..begin()
            },
            "server address length out of range",
        );
        reject_begin(
            &TxBegin {
                server_addr: b"",
                ..begin()
            },
            "server address length out of range",
        );
        // Method 1..=32.
        accept_begin(&TxBegin {
            method: &rep(b'M', 32),
            ..begin()
        });
        reject_begin(
            &TxBegin {
                method: &rep(b'M', 33),
                ..begin()
            },
            "method length out of range",
        );
        reject_begin(
            &TxBegin {
                method: b"",
                ..begin()
            },
            "method length out of range",
        );
        // URI 1..=4096.
        accept_begin(&TxBegin {
            uri: &rep(b'u', 4096),
            ..begin()
        });
        reject_begin(
            &TxBegin {
                uri: &rep(b'u', 4097),
                ..begin()
            },
            "uri length out of range",
        );
        reject_begin(
            &TxBegin {
                uri: b"",
                ..begin()
            },
            "uri length out of range",
        );
        // A length that would wrap a u16 (65536 is 0, 65537 is 1) is rejected, not truncated.
        reject_begin(
            &TxBegin {
                uri: &rep(b'u', 65536),
                ..begin()
            },
            "uri length out of range",
        );
        reject_begin(
            &TxBegin {
                client_addr: &rep(b'1', 65537),
                ..begin()
            },
            "client address length out of range",
        );
        // Protocol 1..=16.
        accept_begin(&TxBegin {
            proto: &rep(b'p', 16),
            ..begin()
        });
        reject_begin(
            &TxBegin {
                proto: &rep(b'p', 17),
                ..begin()
            },
            "protocol length out of range",
        );
        reject_begin(
            &TxBegin {
                proto: b"",
                ..begin()
            },
            "protocol length out of range",
        );
        // Declared 0..=1 MiB.
        accept_begin(&TxBegin {
            declared: MAX_DECLARED,
            ..begin()
        });
        reject_begin(
            &TxBegin {
                declared: MAX_DECLARED + 1,
                ..begin()
            },
            "declared body length out of range",
        );
        reject_begin(
            &TxBegin {
                declared: u64::MAX,
                ..begin()
            },
            "declared body length out of range",
        );
        // Ports take any u16.
        let t = TxBegin {
            client_port: 0,
            server_port: 65535,
            ..begin()
        };
        let p = encode_tx_begin(&t).unwrap();
        assert_eq!(
            (&p[11..13], &p[24..26]),
            (&[0u8, 0][..], &[0xffu8, 0xff][..])
        );
    }

    #[test]
    fn tx_begin_header_boundaries() {
        let many = |n: usize| vec![(&b"n"[..], &b"v"[..]); n];
        accept_begin(&TxBegin {
            headers: &many(0),
            ..begin()
        });
        accept_begin(&TxBegin {
            headers: &many(64),
            ..begin()
        });
        reject_begin(
            &TxBegin {
                headers: &many(65),
                ..begin()
            },
            "header count out of range",
        );
        // Names 1..=256, values 0..=4096.
        let n256 = vec![b'n'; 256];
        let n257 = vec![b'n'; 257];
        let v4096 = vec![b'v'; 4096];
        let v4097 = vec![b'v'; 4097];
        accept_begin(&TxBegin {
            headers: &[(&n256, b"")],
            ..begin()
        });
        accept_begin(&TxBegin {
            headers: &[(b"n", &v4096)],
            ..begin()
        });
        accept_begin(&TxBegin {
            headers: &[(b"n", b"")],
            ..begin()
        });
        reject_begin(
            &TxBegin {
                headers: &[(&n257, b"")],
                ..begin()
            },
            "header name length out of range",
        );
        reject_begin(
            &TxBegin {
                headers: &[(b"", b"v")],
                ..begin()
            },
            "header name length out of range",
        );
        reject_begin(
            &TxBegin {
                headers: &[(b"n", &v4097)],
                ..begin()
            },
            "header value length out of range",
        );
        // Lengths that would wrap a u16 are rejected too.
        reject_begin(
            &TxBegin {
                headers: &[(b"n", &vec![b'v'; 65536])],
                ..begin()
            },
            "header value length out of range",
        );
        reject_begin(
            &TxBegin {
                headers: &[(&vec![b'n'; 65537], b"v")],
                ..begin()
            },
            "header name length out of range",
        );
        // The name + value total: 6 x (256 + 3840) = 24 KiB exactly, then one more byte.
        let v3840 = vec![b'v'; 3840];
        let six = vec![(&n256[..], &v3840[..]); 6];
        accept_begin(&TxBegin {
            headers: &six,
            ..begin()
        });
        let mut seven = six.clone();
        seven.push((&b"x"[..], &b""[..]));
        reject_begin(
            &TxBegin {
                headers: &seven,
                ..begin()
            },
            "header total length out of range",
        );
        let v3841 = vec![b'v'; 3841];
        let mut plus_one = vec![(&n256[..], &v3841[..])];
        plus_one.extend(vec![(&n256[..], &v3840[..]); 5]);
        reject_begin(
            &TxBegin {
                headers: &plus_one,
                ..begin()
            },
            "header total length out of range",
        );
        // The count of 64 maximal headers fails on the total, not on an overflow.
        let v4096 = vec![b'v'; 4096];
        reject_begin(
            &TxBegin {
                headers: &vec![(&n256[..], &v4096[..]); 64],
                ..begin()
            },
            "header total length out of range",
        );
    }

    #[test]
    fn tx_begin_bytes_pass_through_unchanged_and_the_largest_payload_fits() {
        // Non-UTF-8 bytes are not converted, trimmed or normalised.
        let hs: [(&[u8], &[u8]); 1] = [(&[0xff, 0xfe], &[0x00, 0x80, 0xc3])];
        let p = encode_tx_begin(&TxBegin {
            uri: &[0xc3, 0x28, b' '],
            headers: &hs,
            ..begin()
        })
        .unwrap();
        assert!(p.ends_with(&[0, 1, 0, 2, 0xff, 0xfe, 0, 3, 0x00, 0x80, 0xc3]));
        assert!(p.windows(5).any(|w| w == [0, 3, 0xc3, 0x28, b' ']));
        // The worst case allowed by the item bounds stays under the 32 KiB limit, so that check cannot fail:
        // 64 headers with the 24 KiB total.
        let name = vec![b'n'; 128];
        let value = vec![b'v'; 256];
        let hs = vec![(&name[..], &value[..]); 64];
        let t = TxBegin {
            client_addr: &[b'1'; 64],
            server_addr: &[b'2'; 64],
            method: &[b'M'; 32],
            uri: &[b'u'; 4096],
            proto: &[b'p'; 16],
            declared: MAX_DECLARED,
            headers: &hs,
            ..begin()
        };
        let p = encode_tx_begin(&t).unwrap();
        assert_eq!(
            p.len(),
            68 + 68 + 34 + 4098 + 18 + 8 + 2 + 64 * (128 + 256 + 4)
        );
        assert!(p.len() < MAX_TX_BEGIN);
    }

    #[test]
    fn tx_end_reason_is_1_to_5() {
        for reason_code in 0..=255u8 {
            let got = encode_tx_end(reason_code);
            if (1..=5).contains(&reason_code) {
                assert_eq!(got, Ok(vec![reason_code]));
            } else {
                assert_eq!(
                    got,
                    Err(ContentError("tx_end reason out of range")),
                    "{reason_code}"
                );
            }
        }
    }

    #[test]
    fn encode_frame_length_and_id_boundaries() {
        let f = |kind, tx, msg, payload: &[u8]| encode_frame(kind, RUN, INC, tx, msg, payload);
        let why = |r: Result<Vec<u8>, ContentError>| reason(r);
        // BODY: 1..=64 KiB.
        for kind in [KIND_BODY] {
            assert_eq!(why(f(kind, 0x10, 2, b"")), "payload length out of range");
            assert_eq!(f(kind, 0x10, 2, b"x").unwrap().len(), HEADER_LEN + 1);
            let full = f(kind, 0x10, 2, &vec![7u8; 65536]).unwrap();
            assert_eq!(full.len(), HEADER_LEN + 65536);
            assert_eq!(&full[8..12], &65536u32.to_be_bytes());
            assert_eq!(
                why(f(kind, 0x10, 2, &vec![7u8; 65537])),
                "payload length out of range"
            );
        }
        // The empty kinds take no payload.
        for kind in [KIND_BODY_END] {
            assert!(f(kind, 0x10, 3, b"").is_ok());
            assert_eq!(why(f(kind, 0x10, 3, b"x")), "payload length out of range");
        }
        assert_eq!(
            why(f(KIND_DRAIN, 0, 0, b"x")),
            "payload length out of range"
        );
        // TX_BEGIN: up to 32 KiB by length, and the content must decode like Go's (32 KiB of zeros does not). TX_END:
        // up to 8 by length, and exactly one byte 1..=5 by content (8 bytes do not).
        for (kind, bad) in [(KIND_TX_BEGIN, "string length out of range")] {
            assert_eq!(why(f(kind, 0x10, 1, &vec![0u8; MAX_TX_BEGIN])), bad);
            assert_eq!(
                why(f(kind, 0x10, 1, &vec![0u8; MAX_TX_BEGIN + 1])),
                "payload length out of range"
            );
        }
        assert_eq!(
            why(f(KIND_TX_END, 0x10, 7, &[1; 8])),
            "tx_end payload is not one byte 1..=5"
        );
        assert_eq!(
            why(f(KIND_TX_END, 0x10, 7, &[1; 9])),
            "payload length out of range"
        );
        // Control has tx = msg = 0; the others have both nonzero.
        assert_eq!(
            why(f(KIND_DRAIN, 1, 0, b"")),
            "control frame with tx or msg"
        );
        assert_eq!(
            why(f(KIND_DRAIN, 0, 1, b"")),
            "control frame with tx or msg"
        );
        for kind in [KIND_TX_BEGIN, KIND_BODY, KIND_BODY_END, KIND_TX_END] {
            assert_eq!(
                why(f(kind, 0, 1, b"x")),
                "transaction frame with zero tx or msg",
                "{kind:#04x}"
            );
            assert_eq!(
                why(f(kind, 0x10, 0, b"x")),
                "transaction frame with zero tx or msg",
                "{kind:#04x}"
            );
            assert_eq!(
                why(f(kind, 0, 0, b"x")),
                "transaction frame with zero tx or msg",
                "{kind:#04x}"
            );
        }
        let max = f(KIND_BODY_END, u64::MAX, u32::MAX, b"").unwrap();
        assert_eq!(
            (&max[24..32], &max[32..36]),
            (&[0xffu8; 8][..], &[0xffu8; 4][..])
        );
    }

    // ---- encode_frame checks the content like Go's decoders ----

    fn send(kind: u8, msg: u32, payload: &[u8]) -> Result<Vec<u8>, ContentError> {
        encode_frame(kind, RUN, INC, 0x10, msg, payload)
    }

    #[test]
    fn tx_begin_needs_msg_1() {
        let tb = encode_tx_begin(&begin()).unwrap();
        assert_eq!(send(KIND_TX_BEGIN, 1, &tb).unwrap()[4], KIND_TX_BEGIN);
        for msg in [2, 5, u32::MAX] {
            assert_eq!(
                reason(send(KIND_TX_BEGIN, msg, &tb)),
                "tx_begin message number is not 1",
                "msg {msg}"
            );
        }
        assert_eq!(
            reason(send(KIND_TX_BEGIN, 0, &tb)),
            "transaction frame with zero tx or msg"
        );
    }

    #[test]
    fn begin_payloads_go_would_reject_are_rejected() {
        let tb = encode_tx_begin(&begin()).unwrap();
        for (kind, good) in [(KIND_TX_BEGIN, &tb)] {
            assert!(send(kind, 1, good).is_ok());
            // Empty, and a cut at every length: the payload is too short (or, for the empty one, has no first field).
            for n in 0..good.len() {
                assert!(send(kind, 1, &good[..n]).is_err(), "{kind:#04x} cut to {n}");
            }
            // One trailing byte is not allowed.
            let mut extra = good.clone();
            extra.push(0);
            assert_eq!(
                reason(send(kind, 1, &extra)),
                "trailing bytes in payload",
                "{kind:#04x}"
            );
        }
        assert_eq!(reason(send(KIND_TX_BEGIN, 1, b"")), "payload too short");
        // A str length within its bound but over what is left: the first str.
        assert_eq!(
            reason(send(KIND_TX_BEGIN, 1, &[0, 20, b'a', b'b', b'c'])),
            "payload too short"
        );
        // Out of the item bounds, written by hand: client address of 0 and of 65.
        assert_eq!(
            reason(send(KIND_TX_BEGIN, 1, &[0, 0])),
            "string length out of range"
        );
        let mut long = vec![0, 65];
        long.extend_from_slice(&[b'1'; 65]);
        assert_eq!(
            reason(send(KIND_TX_BEGIN, 1, &long)),
            "string length out of range"
        );
    }

    #[test]
    fn hand_built_declared_and_headers_over_a_bound_are_rejected() {
        let tb = encode_tx_begin(&begin()).unwrap();
        for (kind, good, declared_why) in
            [(KIND_TX_BEGIN, &tb, "declared body length out of range")]
        {
            // The payload ends with the declared length (8 bytes) and the header count 0 (2 bytes).
            let n = good.len();
            let declared = |v: u64| {
                let mut p = good.clone();
                p[n - 10..n - 2].copy_from_slice(&v.to_be_bytes());
                p
            };
            assert!(send(kind, 1, &declared(MAX_DECLARED)).is_ok());
            for v in [MAX_DECLARED + 1, u64::MAX] {
                assert_eq!(reason(send(kind, 1, &declared(v))), declared_why);
            }
            let with = |count: u16, items: &[u8]| {
                let mut p = good[..n - 2].to_vec();
                p.extend_from_slice(&count.to_be_bytes());
                p.extend_from_slice(items);
                p
            };
            let range = "string length out of range";
            // A name of 0 and of 257, and a value of 4097.
            assert_eq!(reason(send(kind, 1, &with(1, &[0, 0, 0, 0]))), range);
            assert_eq!(reason(send(kind, 1, &with(1, &[1, 1]))), range);
            assert_eq!(reason(send(kind, 1, &with(1, &[0, 1, b'n', 16, 1]))), range);
            // The count is larger than the items that follow.
            assert_eq!(
                reason(send(kind, 1, &with(2, &[0, 1, b'n', 0, 0]))),
                "payload too short"
            );
            // 6 x (256 + 3840) is the 24 KiB total; one more header of a single byte is over it.
            let mut items = Vec::new();
            for _ in 0..6 {
                items.extend_from_slice(&256u16.to_be_bytes());
                items.extend_from_slice(&[b'n'; 256]);
                items.extend_from_slice(&3840u16.to_be_bytes());
                items.extend_from_slice(&[b'v'; 3840]);
            }
            assert!(send(kind, 1, &with(6, &items)).is_ok());
            items.extend_from_slice(&[0, 1, b'x', 0, 0]);
            assert_eq!(
                reason(send(kind, 1, &with(7, &items))),
                "header total length out of range"
            );
        }
    }

    #[test]
    fn hand_built_begin_strs_are_checked_at_both_ends() {
        // client address, server address, method, uri, protocol of a TX_BEGIN; every other field is valid.
        let tx_begin_with = |lens: [usize; 5]| {
            let mut v = Vec::new();
            tstr(&mut v, &vec![b'a'; lens[0]]);
            v.extend_from_slice(&1u16.to_be_bytes());
            tstr(&mut v, &vec![b'b'; lens[1]]);
            v.extend_from_slice(&2u16.to_be_bytes());
            tstr(&mut v, &vec![b'm'; lens[2]]);
            tstr(&mut v, &vec![b'u'; lens[3]]);
            tstr(&mut v, &vec![b'p'; lens[4]]);
            v.extend_from_slice(&0u64.to_be_bytes());
            v.extend_from_slice(&0u16.to_be_bytes());
            v
        };
        let range = "string length out of range";
        let bounds = [
            (1, MAX_ADDR),
            (1, MAX_ADDR),
            (1, MAX_METHOD),
            (1, MAX_URI),
            (1, MAX_PROTO),
        ];
        for (i, (lo, hi)) in bounds.into_iter().enumerate() {
            for n in [lo, hi] {
                let mut lens = [1; 5];
                lens[i] = n;
                assert!(
                    send(KIND_TX_BEGIN, 1, &tx_begin_with(lens)).is_ok(),
                    "str {i} len {n}"
                );
            }
            for n in [lo - 1, hi + 1] {
                let mut lens = [1; 5];
                lens[i] = n;
                assert_eq!(
                    reason(send(KIND_TX_BEGIN, 1, &tx_begin_with(lens))),
                    range,
                    "str {i} len {n}"
                );
            }
        }
    }

    #[test]
    fn tx_end_payload_is_exactly_one_byte_1_to_5() {
        let bad = "tx_end payload is not one byte 1..=5";
        for p in [&[][..], &[1, 1], &[1; 8], &[0], &[6], &[255]] {
            assert_eq!(reason(send(KIND_TX_END, 7, p)), bad, "{p:?}");
        }
        for r in 1..=5u8 {
            assert_eq!(send(KIND_TX_END, 7, &[r]).unwrap()[HEADER_LEN..], [r]);
        }
    }

    #[test]
    fn the_encoders_outputs_at_their_bounds_are_accepted_by_encode_frame() {
        let sendable = |t: &TxBegin| {
            let p = encode_tx_begin(t).unwrap();
            assert!(send(KIND_TX_BEGIN, 1, &p).is_ok(), "{t:?}");
            p.len()
        };
        // The minimum, and the largest payload the item bounds allow: every str at its limit, 64 headers with the
        // 24 KiB total reached exactly.
        sendable(&TxBegin {
            client_addr: b"a",
            server_addr: b"b",
            method: b"G",
            uri: b"/",
            proto: b"H",
            declared: 0,
            ..begin()
        });
        let name = vec![b'n'; 256];
        let value = vec![b'v'; 128];
        let hs = vec![(&name[..], &value[..]); 64];
        let n = sendable(&TxBegin {
            client_addr: &[b'1'; 64],
            server_addr: &[b'2'; 64],
            method: &[b'M'; 32],
            uri: &[b'u'; 4096],
            proto: &[b'p'; 16],
            declared: MAX_DECLARED,
            headers: &hs,
            ..begin()
        });
        assert_eq!(n, 68 + 68 + 34 + 4098 + 18 + 8 + 2 + 64 * (4 + 256 + 128));
        assert!(n <= MAX_TX_BEGIN);
        // A name of 256, a value of 4096, and the total of exactly 24 KiB in 6 headers.
        let v4096 = vec![b'v'; 4096];
        let v3840 = vec![b'v'; 3840];
        sendable(&TxBegin {
            headers: &[(&name, &v4096)],
            ..begin()
        });
        sendable(&TxBegin {
            headers: &vec![(&name[..], &v3840[..]); 6],
            ..begin()
        });
        sendable(&TxBegin {
            headers: &[(b"n", b"")],
            ..begin()
        });
        // TX_END: every reason.
        for r in END_COMPLETE..=END_DEADLINE {
            assert!(send(KIND_TX_END, 7, &encode_tx_end(r).unwrap()).is_ok());
        }
    }

    // ---- check_hello ----

    const NONCE: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    const PID: u32 = 4242;
    const RULES: [u8; 32] = [7; 32];
    const MEM: u64 = 256 << 20;

    fn expect() -> HelloExpect<'static> {
        HelloExpect {
            rules_sha256: &RULES,
            mem_limit: MEM,
            gomaxprocs: 1,
        }
    }

    fn good_hello() -> Hello {
        Hello {
            version: 0,
            pid: PID,
            nonce: NONCE,
            run: RUN,
            inc: INC,
            go_version: INSPECTOR_GO_VERSION.to_vec(),
            coraza_version: INSPECTOR_CORAZA_VERSION.to_vec(),
            coraza_sum: INSPECTOR_CORAZA_SUM.to_vec(),
            rules_sha256: RULES,
            body_limit: MAX_DECLARED as u32,
            mem_limit: MEM,
            gomaxprocs: 1,
            tx_limit: MAX_CONCUR_TX,
            queue: QUEUE_DEPTH,
        }
    }

    fn checked(h: &Hello) -> Result<(), &'static str> {
        check_hello(h, &expect(), RUN, INC, PID, &NONCE)
    }

    #[test]
    fn the_pinned_inspector_build_and_limits_are_the_accepted_ones() {
        assert_eq!(INSPECTOR_GO_VERSION, b"go1.27.2");
        assert_eq!(INSPECTOR_CORAZA_VERSION, b"v3.8.1");
        assert_eq!(
            INSPECTOR_CORAZA_SUM,
            b"h1:dMV55FbMR2vOks/acrT43RShR+VkzU6jwp+XPdxay8o="
        );
        assert_eq!(MAX_DECLARED as u32, 1 << 20);
        assert_eq!((MAX_CONCUR_TX, QUEUE_DEPTH), (4, 17));
        // The pinned strings are inside the HELLO bounds, so a HELLO that carries them decodes.
        let p = hello(
            0,
            INSPECTOR_GO_VERSION,
            INSPECTOR_CORAZA_VERSION,
            INSPECTOR_CORAZA_SUM,
        );
        let h = decode_hello(&p).unwrap();
        assert_eq!(h.go_version, INSPECTOR_GO_VERSION);
        assert_eq!(h.coraza_version, INSPECTOR_CORAZA_VERSION);
        assert_eq!(h.coraza_sum, INSPECTOR_CORAZA_SUM);
    }

    #[test]
    fn hello_matches_and_every_field_is_checked() {
        assert_eq!(checked(&good_hello()), Ok(()));
        let one: [(&str, fn(&mut Hello)); 13] = [
            ("hello contract version is not v0", |h| h.version = 1),
            ("hello pid is not the child's pid", |h| h.pid += 1),
            ("hello nonce differs", |h| h.nonce[15] ^= 1),
            ("hello run id differs", |h| h.run += 1),
            ("hello incarnation differs", |h| h.inc += 1),
            ("hello go version differs", |h| {
                h.go_version = b"go1.27.1".to_vec()
            }),
            ("hello coraza version differs", |h| {
                h.coraza_version = b"v3.8.0".to_vec()
            }),
            ("hello coraza sum differs", |h| h.coraza_sum.push(b'x')),
            ("hello rules sha256 differs", |h| h.rules_sha256[31] ^= 1),
            ("hello body limit differs", |h| h.body_limit -= 1),
            ("hello memory limit differs", |h| h.mem_limit = 0),
            ("hello gomaxprocs differs", |h| h.gomaxprocs += 1),
            ("hello transaction limit differs", |h| h.tx_limit += 1),
        ];
        for (want, m) in one {
            let mut h = good_hello();
            m(&mut h);
            assert_eq!(checked(&h), Err(want));
        }
        let mut h = good_hello();
        h.queue += 1;
        assert_eq!(checked(&h), Err("hello queue depth differs"));
        // An inspector that reports the other value of a compared limit is refused too.
        let mut h = good_hello();
        h.body_limit += 1;
        assert_eq!(checked(&h), Err("hello body limit differs"));
        // The expected values come from the arguments: the same HELLO against another start.
        let h = good_hello();
        assert_eq!(
            check_hello(&h, &expect(), RUN, INC, PID + 1, &NONCE),
            Err("hello pid is not the child's pid")
        );
        assert_eq!(
            check_hello(&h, &expect(), RUN, INC, PID, &[0; 16]),
            Err("hello nonce differs")
        );
        assert_eq!(
            check_hello(&h, &expect(), RUN + 1, INC, PID, &NONCE),
            Err("hello run id differs")
        );
        assert_eq!(
            check_hello(&h, &expect(), RUN, INC + 1, PID, &NONCE),
            Err("hello incarnation differs")
        );
        let other = [8u8; 32];
        let e = HelloExpect {
            rules_sha256: &other,
            ..expect()
        };
        assert_eq!(
            check_hello(&h, &e, RUN, INC, PID, &NONCE),
            Err("hello rules sha256 differs")
        );
        let e = HelloExpect {
            mem_limit: MEM + 1,
            ..expect()
        };
        assert_eq!(
            check_hello(&h, &e, RUN, INC, PID, &NONCE),
            Err("hello memory limit differs")
        );
        let e = HelloExpect {
            gomaxprocs: 2,
            ..expect()
        };
        assert_eq!(
            check_hello(&h, &e, RUN, INC, PID, &NONCE),
            Err("hello gomaxprocs differs")
        );
    }

    #[test]
    fn hello_fields_are_compared_in_a_fixed_order() {
        // Every field is wrong at first; fixing them one by one in the order of the checks moves to the next reason.
        let mut h = Hello {
            version: 1,
            pid: PID + 1,
            nonce: [0; 16],
            run: RUN + 1,
            inc: INC + 1,
            go_version: Vec::new(),
            coraza_version: Vec::new(),
            coraza_sum: Vec::new(),
            rules_sha256: [0; 32],
            body_limit: 0,
            mem_limit: 0,
            gomaxprocs: 0,
            tx_limit: 0,
            queue: 0,
        };
        assert_eq!(checked(&h), Err("hello contract version is not v0"));
        h.version = 0;
        assert_eq!(checked(&h), Err("hello pid is not the child's pid"));
        h.pid = PID;
        assert_eq!(checked(&h), Err("hello nonce differs"));
        h.nonce = NONCE;
        assert_eq!(checked(&h), Err("hello run id differs"));
        h.run = RUN;
        assert_eq!(checked(&h), Err("hello incarnation differs"));
        h.inc = INC;
        assert_eq!(checked(&h), Err("hello go version differs"));
        h.go_version = INSPECTOR_GO_VERSION.to_vec();
        assert_eq!(checked(&h), Err("hello coraza version differs"));
        h.coraza_version = INSPECTOR_CORAZA_VERSION.to_vec();
        assert_eq!(checked(&h), Err("hello coraza sum differs"));
        h.coraza_sum = INSPECTOR_CORAZA_SUM.to_vec();
        assert_eq!(checked(&h), Err("hello rules sha256 differs"));
        h.rules_sha256 = RULES;
        assert_eq!(checked(&h), Err("hello body limit differs"));
        h.body_limit = MAX_DECLARED as u32;
        assert_eq!(checked(&h), Err("hello memory limit differs"));
        h.mem_limit = MEM;
        assert_eq!(checked(&h), Err("hello gomaxprocs differs"));
        h.gomaxprocs = 1;
        assert_eq!(checked(&h), Err("hello transaction limit differs"));
        h.tx_limit = MAX_CONCUR_TX;
        assert_eq!(checked(&h), Err("hello queue depth differs"));
        h.queue = QUEUE_DEPTH;
        assert_eq!(checked(&h), Ok(()));
    }

    // ---- constants and the longest ERROR ----

    #[test]
    fn limits_match_the_protocol_v0_bounds() {
        let limits = [
            ("HELLO", MAX_HELLO, 1024),
            ("TX_BEGIN", MAX_TX_BEGIN, 32768),
            ("BODY", MAX_BODY, 65536),
            ("VERDICT", MAX_VERDICT, 1024),
            ("ERROR", MAX_ERROR, 512),
            ("TX_END", MAX_TX_END, 8),
            ("CLOSED", MAX_CLOSED, 8),
            ("BYE", MAX_BYE, 64),
            ("uri", MAX_URI, 4096),
            ("headers", MAX_HEADERS, 64),
            ("header name", MAX_HDR_NAME, 256),
            ("header value", MAX_HDR_VALUE, 4096),
            ("header total", MAX_HDR_TOTAL, 24576),
            ("action", MAX_ACTION, 32),
            ("data", MAX_DATA, 256),
            ("error text", MAX_ERR_MSG, 256),
            // Also the values of Go's constants (codec.go), which the begin checks share with the encoders.
            ("address", MAX_ADDR, 64),
            ("method", MAX_METHOD, 32),
            ("protocol", MAX_PROTO, 16),
        ];
        for (what, got, want) in limits {
            assert_eq!(got, want, "{what}");
        }
        assert_eq!(MAX_DECLARED, 1_048_576);
    }

    #[test]
    fn the_longest_error_with_a_256_byte_text_reads_and_decodes() {
        let payload = errmsg(2, 0, 17, &[b't'; MAX_ERR_MSG]);
        assert_eq!(payload.len(), 262);
        let mut bytes = header(KIND_ERROR, 262, 0x10, 1).to_vec();
        bytes.extend_from_slice(&payload);
        let mut r: &[u8] = &bytes;
        let (h, p) = read_frame(&mut r, RUN, INC).unwrap();
        assert_eq!((h, r.len()), (hdr(KIND_ERROR, 262, 0x10, 1), 0));
        let e = decode_error(&p).unwrap();
        assert_eq!((e.class, e.code, e.text.len()), (CLASS_TX_FAILED, 17, 256));
    }
}
