//! Rust side of the wire protocol 1.
//!
//! The same bytes as the Go inspector's `codec.go` and `testdata/v1-golden.txt`. Every integer is big-endian; a `str`
//! is a u16 length and the bytes. Strings stay `&[u8]` / `Vec<u8>`: no UTF-8 conversion, normalisation or trimming.
//! Rust receives HELLO, BYE, VERDICT, ERROR and CLOSED and sends DRAIN, TX_BEGIN, BODY, BODY_END and TX_END. The
//! header flags of a frame Rust receives are zero. The only flag Rust sends is `FLAG_BODY_CUT`, on TX_BEGIN. The
//! response kinds (RESP_BEGIN, RESP_BODY, RESP_END) are kinds of the protocol that Rust never sends: `encode_frame`
//! refuses them and `check_header` reports one received as a wrong direction. A VERDICT ends with the rules that
//! matched the request (`matched`).
//!
//! Faults are split in two types: `ConnError` is a connection-wide violation (header or read; the frame boundary can no
//! longer be trusted) and `ContentError` is an invalid payload behind a valid header, or a failed check before sending
//! (an individual violation). This module does no deadline handling: `read_frame` takes any `std::io::Read`.
//!
//! The HELLO is in the child `hello`: `check_hello` compares a decoded HELLO with the start and with the pinned
//! inspector build of the engine (`Engine::pinned`).
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
pub(crate) const MAX_DECLARED: u64 = 1 << 20; // declared body length limit (Go's `maxDeclared`, 1 MiB)
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

// Header flags of a frame Rust sends: the body that follows TX_BEGIN is only the first bytes of the request body.
pub(crate) const FLAG_BODY_CUT: u8 = 1 << 0;

// VERDICT flags (the two cuts, the detection and the rules past the list) and ERROR classes.
pub(crate) const FLAG_ACTION_TRUNCATED: u8 = 1 << 0;
pub(crate) const FLAG_DATA_TRUNCATED: u8 = 1 << 1;
/// A continue of phase 2 that carries a match which did not stop the request (the rules only detect).
pub(crate) const FLAG_DETECTED: u8 = 1 << 2;
/// More rules matched than the `MAX_RULE_IDS` ids that the VERDICT lists.
pub(crate) const FLAG_MORE_RULES: u8 = 1 << 3;
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
/// both nonzero; the payload length is within the kind's range (BODY 1..=64 KiB, the empty kinds 0). The header
/// flags are 0, or `FLAG_BODY_CUT` on a TX_BEGIN: no other flag and no other kind is built. The content of
/// TX_BEGIN and TX_END comes from `encode_tx_begin` and `encode_tx_end`, and is checked here with the rules of Go's
/// `decodeTxBegin` and `decodeTxEnd`, so no frame Go rejects is built. A TX_BEGIN also needs msg 1: Go does not create a
/// transaction for another number (ERROR class 1, code 3).
///
/// A kind this side receives, a response kind, an unknown kind and wrong control or transaction ids are the caller's
/// mistakes, not an invalid request content; they are reported first, before the payload is looked at.
pub(crate) fn encode_frame(
    kind: u8,
    flags: u8,
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
    if flags != 0 && !(flags == FLAG_BODY_CUT && kind == KIND_TX_BEGIN) {
        return Err(ContentError("frame flags out of range"));
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
    out.push(flags);
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
pub(crate) struct Verdict {
    pub phase: u8,
    pub block: bool,
    pub flags: u8,
    pub rule_id: i64,
    pub status: u16,
    pub action: Vec<u8>,
    pub data: Vec<u8>,
    pub matched: Matched,
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

/// Decodes VERDICT. Go cuts action and data only at their limits and then sets the matching flag (codec.go
/// `encodeVerdict`), so a flag needs the exact cut length (32 or 256). A continuation carries no rule id, status,
/// action or data, except the continue of phase 2 with `FLAG_DETECTED`: it carries them like a block, with the same
/// cuts. That flag is refused on a block and in any other phase. The payload ends with the rules that matched
/// (`matched::read`): a payload without that end is refused, and so is a value outside its limits.
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
    if flags & !(FLAG_ACTION_TRUNCATED | FLAG_DATA_TRUNCATED | FLAG_DETECTED | FLAG_MORE_RULES) != 0
    {
        return Err(ContentError("verdict flags out of range"));
    }
    if c.u8()? != 0 {
        return Err(ContentError("verdict reserved not zero"));
    }
    let rule_id = i64::from_be_bytes(c.array()?);
    let status = c.u16()?;
    let action = c.str16(0, MAX_ACTION)?;
    let data = c.str16(0, MAX_DATA)?;
    let matched = matched::read(&mut c, phase, flags & FLAG_MORE_RULES != 0)?;
    c.done()?;
    let detected = flags & FLAG_DETECTED != 0;
    if detected && (block || phase != 2) {
        return Err(ContentError(
            "verdict detected flag needs a continue of phase 2",
        ));
    }
    if !block
        && !detected
        && (rule_id != 0 || status != 0 || !action.is_empty() || !data.is_empty())
    {
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
        matched,
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

mod hello;
mod matched;
pub(crate) use hello::{HelloExpect, check_hello, decode_hello};
pub use matched::Matched;

#[cfg(test)]
mod tests;
