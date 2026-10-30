//! Inspector side of the wire protocol 1.
//!
//! The same bytes as the kernel's `protocol/codec.rs`, fixed by `inspector/testdata/v1-golden.txt`. Every integer is
//! big-endian; a `str` is a u16 length and the bytes. Strings stay `&[u8]`: no UTF-8 conversion, normalisation or
//! trimming. The inspector receives DRAIN, TX_BEGIN, BODY, BODY_END and TX_END and sends HELLO, BYE, VERDICT, ERROR
//! and CLOSED. The response kinds (RESP_BEGIN, RESP_BODY, RESP_END) belong to the protocol, but the kernel never sends
//! them and this inspector does not inspect responses: `check_header` refuses them. The one header flag a frame may
//! carry is `FLAG_BODY_CUT`, on TX_BEGIN.
//!
//! Faults are split in two types: `ConnError` is a connection-wide violation (header or read; the frame boundary can
//! no longer be trusted) and `ContentError` is an invalid payload behind a valid header, or a value that cannot be
//! written into a frame. This module does no deadline handling: `read_frame` takes any `std::io::Read`.
//!
//! The HELLO is in the child `hello`.
#![forbid(unsafe_code)]

use std::io::{ErrorKind, Read};

mod hello;
pub use hello::{Hello, encode_hello};

pub const HEADER_LEN: usize = 36;
pub const MAGIC: [u8; 4] = *b"TKV0";

// Frame kinds. FAULT (0x7f) is reserved: it has no constant, and an incoming 0x7f is an unknown kind.
pub const KIND_HELLO: u8 = 0x01;
pub const KIND_DRAIN: u8 = 0x02;
pub const KIND_BYE: u8 = 0x03;
pub const KIND_TX_BEGIN: u8 = 0x10;
pub const KIND_BODY: u8 = 0x11;
pub const KIND_BODY_END: u8 = 0x12;
// The response kinds only classify a received kind: this side neither takes nor sends them.
pub const KIND_RESP_BEGIN: u8 = 0x13;
pub const KIND_RESP_BODY: u8 = 0x14;
pub const KIND_RESP_END: u8 = 0x15;
pub const KIND_TX_END: u8 = 0x16;
pub const KIND_VERDICT: u8 = 0x20;
pub const KIND_ERROR: u8 = 0x21;
pub const KIND_CLOSED: u8 = 0x22;

// Payload limits per kind and item bounds (bytes unless noted). The kernel holds the same values.
pub const MAX_HELLO: usize = 1024;
pub const MAX_TX_BEGIN: usize = 32 * 1024;
pub const MAX_BODY: usize = 64 * 1024;
pub const MAX_VERDICT: usize = 1024;
pub const MAX_ERROR: usize = 512;
pub const MAX_TX_END: usize = 8;
pub const MAX_CLOSED: usize = 8;
pub const MAX_BYE: usize = 64;
pub const MAX_DECLARED: u64 = 1 << 20; // declared body length limit, 1 MiB
pub const MAX_ADDR: usize = 64;
pub const MAX_METHOD: usize = 32;
pub const MAX_URI: usize = 4096;
pub const MAX_PROTO: usize = 16;
pub const MAX_HEADERS: usize = 64;
pub const MAX_HDR_NAME: usize = 256;
pub const MAX_HDR_VALUE: usize = 4096;
pub const MAX_HDR_TOTAL: usize = 24 * 1024;
pub const MAX_ACTION: usize = 32;
pub const MAX_DATA: usize = 256;
pub const MAX_ERR_MSG: usize = 256;
pub const MAX_RULE_IDS: usize = 16; // matched rule ids in one VERDICT
pub const MAX_SEVERITY: u8 = 7; // 0 is the heaviest, 7 the lightest
pub const MAX_CONCUR_TX: usize = 4;
pub const QUEUE_DEPTH: u16 = 17;

/// The header flag of a TX_BEGIN whose request body goes on past the declared bytes.
pub const FLAG_BODY_CUT: u8 = 1 << 0;

// VERDICT flags (the two cuts, the detection and the rules past the list) and the values of "none" at its end.
const FLAG_ACTION_TRUNCATED: u8 = 1 << 0;
const FLAG_DATA_TRUNCATED: u8 = 1 << 1;
const FLAG_DETECTED: u8 = 1 << 2;
const FLAG_MORE_RULES: u8 = 1 << 3;
const SEVERITY_NONE: u8 = 255;
const SCORE_NONE: i32 = -1;

// TX_END reasons: 1 complete .. 5 deadline.
const END_COMPLETE: u8 = 1;
const END_DEADLINE: u8 = 5;

// ERROR classes and codes. Class 1 means no transaction exists for the id (the concurrency slot is not taken); class 2
// means a created transaction failed (CLOSED returns the slot). Code 24, a receive queue overflow, is never sent: see
// the comment on the queue depth in `link`. Codes 26 to 28, 30 and 31 belong to the response phases.
pub const CLASS_NOT_CREATED: u8 = 1;
pub const CLASS_TX_FAILED: u8 = 2;
pub const CODE_LIMIT: u16 = 1; // concurrency limit
pub const CODE_DRAINING: u16 = 2; // DRAIN received
pub const CODE_BAD_BEGIN: u16 = 3; // TX_BEGIN payload or message number invalid
pub const CODE_UNSTARTED: u16 = 4; // frame for an id that was never started
pub const CODE_ORDER: u16 = 16; // frame not allowed in this state, message number gap or duplicate
pub const CODE_BAD_CONTENT: u16 = 17; // payload of a frame of a created transaction invalid
pub const CODE_REQ_NOT_INSPECT: u16 = 18; // request body present but the engine cannot read it
pub const CODE_REQ_WRITE: u16 = 19; // the engine failed to take the request body
pub const CODE_REQ_SHORT: u16 = 20; // the engine took fewer bytes than it was given
pub const CODE_REQ_OVER: u16 = 21; // more body than declared
pub const CODE_REQ_TRUNCATED: u16 = 22; // BODY_END with fewer bytes than declared
pub const CODE_REQ_PROCESS: u16 = 23; // the engine failed to process the request body
pub const CODE_INCOMPLETE: u16 = 25; // the inspection could not be confirmed to have run to the end
pub const CODE_BAD_VERDICT: u16 = 29; // VERDICT fields out of the encodable range

/// The codes of class 2 that an inspection can report for a transaction: the codes of the class that this inspector
/// sends, which the kernel accepts. No other code can be named. Code 24 is left out because it is never sent, and so
/// are the codes of the response phases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum FaultCode {
    Order = CODE_ORDER,
    BadContent = CODE_BAD_CONTENT,
    ReqNotInspect = CODE_REQ_NOT_INSPECT,
    ReqWrite = CODE_REQ_WRITE,
    ReqShort = CODE_REQ_SHORT,
    ReqOver = CODE_REQ_OVER,
    ReqTruncated = CODE_REQ_TRUNCATED,
    ReqProcess = CODE_REQ_PROCESS,
    Incomplete = CODE_INCOMPLETE,
    BadVerdict = CODE_BAD_VERDICT,
}

impl From<FaultCode> for u16 {
    fn from(code: FaultCode) -> u16 {
        code as u16
    }
}

/// A decoded 36-byte frame header (`check_header` has accepted it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub kind: u8,
    /// `FLAG_BODY_CUT` is set (TX_BEGIN only).
    pub cut: bool,
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
pub enum ConnError {
    /// EOF before the first byte of a frame.
    PeerClosed,
    Truncated {
        got: usize,
        want: usize,
    },
    BadMagic,
    UnknownKind(u8),
    /// A kind that this side sends, not receives.
    WrongDirection(u8),
    /// A kind of the protocol that this side does not take (the response kinds).
    Unsupported(u8),
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

/// An invalid payload behind a valid header, or a value that cannot be written into a frame.
#[derive(Debug, PartialEq, Eq)]
pub struct ContentError(pub &'static str);

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

/// Payload limit of every kind this side receives; `None` for the kinds it sends, the response kinds and unknown kinds.
fn received_max(kind: u8) -> Option<usize> {
    match kind {
        KIND_DRAIN | KIND_BODY_END => Some(0),
        KIND_TX_BEGIN => Some(MAX_TX_BEGIN),
        KIND_BODY => Some(MAX_BODY),
        KIND_TX_END => Some(MAX_TX_END),
        _ => None,
    }
}

/// Control frames (no transaction): tx and msg are both 0. The others carry both, nonzero.
fn is_control(kind: u8) -> bool {
    kind == KIND_DRAIN || kind == KIND_HELLO || kind == KIND_BYE
}

/// Validates a received header before the payload is allocated, in this order: magic, flags, reserved, kind (unknown,
/// one this side sends, or a response kind), length, run, incarnation, then the ids.
pub fn check_header(b: &[u8; HEADER_LEN], run: u64, inc: u32) -> Result<Header, ConnError> {
    if b[..4] != MAGIC {
        return Err(ConnError::BadMagic);
    }
    let kind = b[4];
    let cut = match b[5] {
        0 => false,
        FLAG_BODY_CUT if kind == KIND_TX_BEGIN => true,
        flags => return Err(ConnError::Flags(flags)),
    };
    let reserved = u16::from_be_bytes([b[6], b[7]]);
    if reserved != 0 {
        return Err(ConnError::Reserved(reserved));
    }
    let h = Header {
        kind,
        cut,
        len: be32(b, 8),
        run: be64(b, 12),
        inc: be32(b, 20),
        tx: be64(b, 24),
        msg: be32(b, 32),
    };
    let Some(limit) = received_max(kind) else {
        return Err(match kind {
            KIND_HELLO | KIND_BYE | KIND_VERDICT | KIND_ERROR | KIND_CLOSED => {
                ConnError::WrongDirection(kind)
            }
            KIND_RESP_BEGIN | KIND_RESP_BODY | KIND_RESP_END => ConnError::Unsupported(kind),
            _ => ConnError::UnknownKind(kind),
        });
    };
    if u64::from(h.len) > limit as u64 {
        return Err(ConnError::TooLong { kind, len: h.len });
    }
    if h.run != run {
        return Err(ConnError::RunMismatch(h.run));
    }
    if h.inc != inc {
        return Err(ConnError::IncMismatch(h.inc));
    }
    if is_control(kind) {
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
pub fn read_frame<R: Read>(r: &mut R, run: u64, inc: u32) -> Result<(Header, Vec<u8>), ConnError> {
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
    // check_header bounded len by a limit of at most MAX_BODY, so the conversion is exact.
    let want = h.len as usize;
    let mut p = vec![0u8; want];
    let got = fill(r, &mut p)?;
    if got < want {
        return Err(ConnError::Truncated { got, want });
    }
    Ok((h, p))
}

/// Builds an outbound frame: the header first, the payload after it, and `finish` writes the payload length.
struct FrameBuilder {
    b: Vec<u8>,
}

impl FrameBuilder {
    fn new(kind: u8, run: u64, inc: u32, tx: u64, msg: u32) -> FrameBuilder {
        let mut b = Vec::with_capacity(HEADER_LEN + 64);
        b.extend_from_slice(&MAGIC);
        b.push(kind);
        b.push(0); // flags: only a TX_BEGIN has one, and this side does not send it
        b.extend_from_slice(&[0, 0]); // reserved
        b.extend_from_slice(&[0; 4]); // length, written by `finish`
        b.extend_from_slice(&run.to_be_bytes());
        b.extend_from_slice(&inc.to_be_bytes());
        b.extend_from_slice(&tx.to_be_bytes());
        b.extend_from_slice(&msg.to_be_bytes());
        FrameBuilder { b }
    }

    fn u8(&mut self, v: u8) {
        self.b.push(v);
    }

    fn u16(&mut self, v: u16) {
        self.b.extend_from_slice(&v.to_be_bytes());
    }

    fn raw(&mut self, v: &[u8]) {
        self.b.extend_from_slice(v);
    }

    /// A u16 length and the bytes. A string over 65535 bytes is cut, so the length always matches the bytes; the
    /// callers have bounded the string far below that.
    fn str16(&mut self, s: &[u8]) {
        let n = u16::try_from(s.len()).unwrap_or(u16::MAX);
        self.u16(n);
        self.raw(&s[..usize::from(n)]);
    }

    /// Writes the payload length, for a payload that the builder's callers have bounded to a few hundred bytes.
    fn finish(mut self) -> Vec<u8> {
        let n = u32::try_from(self.b.len() - HEADER_LEN).unwrap_or(u32::MAX);
        self.b[8..12].copy_from_slice(&n.to_be_bytes());
        self.b
    }

    /// As `finish`, for a payload whose size depends on values that were checked one by one: it must be within the
    /// limit of its kind.
    fn finish_within(self, limit: usize) -> Result<Vec<u8>, ContentError> {
        if self.b.len() - HEADER_LEN > limit {
            return Err(ContentError("payload over the limit of its kind"));
        }
        Ok(self.finish())
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

    fn u16(&mut self) -> Result<u16, ContentError> {
        Ok(u16::from_be_bytes(self.array()?))
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

/// A decoded TX_BEGIN. The strings are views into the payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxBegin<'a> {
    pub client_addr: &'a [u8],
    pub client_port: u16,
    pub server_addr: &'a [u8],
    pub server_port: u16,
    pub method: &'a [u8],
    pub uri: &'a [u8],
    pub proto: &'a [u8],
    pub declared: u64,
    pub headers: Vec<(&'a [u8], &'a [u8])>,
    /// The body goes on past the declared bytes (the header flag, given by the caller).
    pub cut: bool,
}

/// Decodes a TX_BEGIN payload with the bounds of the protocol. A cut body has declared bytes.
pub fn decode_tx_begin(p: &[u8], cut: bool) -> Result<TxBegin<'_>, ContentError> {
    let mut c = Cursor { p };
    let client_addr = c.str16(1, MAX_ADDR)?;
    let client_port = c.u16()?;
    let server_addr = c.str16(1, MAX_ADDR)?;
    let server_port = c.u16()?;
    let method = c.str16(1, MAX_METHOD)?;
    let uri = c.str16(1, MAX_URI)?;
    let proto = c.str16(1, MAX_PROTO)?;
    let declared = c.u64()?;
    if declared > MAX_DECLARED {
        return Err(ContentError("declared body length out of range"));
    }
    if cut && declared == 0 {
        return Err(ContentError("cut body without declared bytes"));
    }
    let count = usize::from(c.u16()?);
    if count > MAX_HEADERS {
        return Err(ContentError("header count out of range"));
    }
    let mut headers = Vec::with_capacity(count);
    let mut total = 0usize;
    for _ in 0..count {
        let name = c.str16(1, MAX_HDR_NAME)?;
        let value = c.str16(0, MAX_HDR_VALUE)?;
        total += name.len() + value.len();
        if total > MAX_HDR_TOTAL {
            return Err(ContentError("header total length out of range"));
        }
        headers.push((name, value));
    }
    c.done()?;
    Ok(TxBegin {
        client_addr,
        client_port,
        server_addr,
        server_port,
        method,
        uri,
        proto,
        declared,
        headers,
        cut,
    })
}

/// Decodes a TX_END payload: exactly one byte, the reason, 1 complete .. 5 deadline.
pub fn decode_tx_end(p: &[u8]) -> Result<u8, ContentError> {
    match p {
        [r] if (END_COMPLETE..=END_DEADLINE).contains(r) => Ok(*r),
        _ => Err(ContentError("tx_end payload is not one byte 1..=5")),
    }
}

/// What a VERDICT of the request phases says about the rules that matched: their ids in the order of evaluation (at
/// most `MAX_RULE_IDS`), whether more matched than that, the lowest severity number among them (0 is the heaviest)
/// and the anomaly score. Severity 0 is a severity, so the zero value is not "none": use `RuleDetail::default()`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleDetail {
    pub ids: Vec<i64>,
    pub more: bool,
    /// 0 to `MAX_SEVERITY`, or 255 for none.
    pub severity: u8,
    /// 0 or more, or -1 for none.
    pub score: i32,
}

impl RuleDetail {
    /// Nothing to say: no ids, no severity and no score.
    pub const NONE: RuleDetail = RuleDetail {
        ids: Vec::new(),
        more: false,
        severity: SEVERITY_NONE,
        score: SCORE_NONE,
    };

    /// Checks the detail against the limits of the protocol for a VERDICT of this phase and returns the score to
    /// write. `None` for more than `MAX_RULE_IDS` ids, an id below 1, the more mark without `MAX_RULE_IDS` ids, a
    /// severity outside 0 to `MAX_SEVERITY` and 255, a score below -1, and anything to carry in phase 3 or 4. A detail
    /// with no id, no severity and a score of -1 or 0 carries nothing and is written as none.
    fn wire(&self, phase: u8) -> Option<i32> {
        if self.ids.len() > MAX_RULE_IDS
            || (self.more && self.ids.len() != MAX_RULE_IDS)
            || (self.severity > MAX_SEVERITY && self.severity != SEVERITY_NONE)
            || self.score < SCORE_NONE
            || self.ids.iter().any(|&id| id < 1)
        {
            return None;
        }
        if self.ids.is_empty() && self.severity == SEVERITY_NONE && self.score <= 0 {
            return Some(SCORE_NONE);
        }
        (phase <= 2).then_some(self.score)
    }
}

/// `NONE`, not zeros: a severity 0 and a score 0 are values.
impl Default for RuleDetail {
    fn default() -> RuleDetail {
        RuleDetail::NONE
    }
}

/// What the inspection decided at the end of a phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// The request goes on.
    Continue,
    /// The request is stopped.
    Block,
    /// A continue of phase 2 that carries a match which did not stop the request (the rules only detect).
    Detected,
}

/// The content of a VERDICT. A plain `Continue` carries no rule id, status, action or data; a `Block` and a
/// `Detected` carry them, and `action` and `data` are cut to `MAX_ACTION` and `MAX_DATA` bytes with a flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verdict<'a> {
    pub decision: Decision,
    pub rule_id: i64,
    pub status: i32,
    pub action: &'a [u8],
    pub data: &'a [u8],
    pub rules: &'a RuleDetail,
}

/// The bytes of `s` up to `max`, and whether anything was cut off.
fn cut_to(s: &[u8], max: usize) -> (&[u8], bool) {
    if s.len() > max {
        (&s[..max], true)
    } else {
        (s, false)
    }
}

/// Encodes a VERDICT of `phase`. A value outside the encodable range (a phase, a status that is not 0 to 65535, the
/// rules, a plain `Continue` that carries fields, `Detected` outside phase 2) is refused, so that the caller sends
/// an ERROR instead.
pub fn encode_verdict(
    run: u64,
    inc: u32,
    tx: u64,
    msg: u32,
    phase: u8,
    v: &Verdict<'_>,
) -> Result<Vec<u8>, ContentError> {
    if !(1..=4).contains(&phase) {
        return Err(ContentError("verdict phase out of range"));
    }
    let carries = v.rule_id != 0 || v.status != 0 || !v.action.is_empty() || !v.data.is_empty();
    match v.decision {
        Decision::Continue if carries => {
            return Err(ContentError("verdict continue carries interruption fields"));
        }
        Decision::Detected if phase != 2 => {
            return Err(ContentError("verdict detected needs a continue of phase 2"));
        }
        _ => {}
    }
    let status =
        u16::try_from(v.status).map_err(|_| ContentError("verdict status out of range"))?;
    let score = v
        .rules
        .wire(phase)
        .ok_or(ContentError("verdict rules out of range"))?;
    let mut flags = 0;
    if v.decision == Decision::Detected {
        flags |= FLAG_DETECTED;
    }
    if v.rules.more {
        flags |= FLAG_MORE_RULES;
    }
    let (action, action_cut) = cut_to(v.action, MAX_ACTION);
    let (data, data_cut) = cut_to(v.data, MAX_DATA);
    if action_cut {
        flags |= FLAG_ACTION_TRUNCATED;
    }
    if data_cut {
        flags |= FLAG_DATA_TRUNCATED;
    }
    let mut f = FrameBuilder::new(KIND_VERDICT, run, inc, tx, msg);
    f.u8(phase);
    f.u8(u8::from(v.decision == Decision::Block));
    f.u8(flags);
    f.u8(0); // reserved
    f.raw(&v.rule_id.to_be_bytes());
    f.u16(status);
    f.str16(action);
    f.str16(data);
    // At most MAX_RULE_IDS, checked by `wire`.
    f.u8(u8::try_from(v.rules.ids.len()).unwrap_or(u8::MAX));
    for id in &v.rules.ids {
        f.raw(&id.to_be_bytes());
    }
    f.u8(v.rules.severity);
    f.raw(&score.to_be_bytes());
    f.finish_within(MAX_VERDICT)
}

/// Encodes an ERROR. The text is a fixed one of the inspector (so it holds no request value), cut to `MAX_ERR_MSG`.
pub fn encode_error(
    run: u64,
    inc: u32,
    tx: u64,
    msg: u32,
    class: u8,
    code: u16,
    text: &'static str,
) -> Vec<u8> {
    let mut f = FrameBuilder::new(KIND_ERROR, run, inc, tx, msg);
    f.u8(class);
    f.u8(0); // reserved
    f.u16(code);
    f.str16(cut_to(text.as_bytes(), MAX_ERR_MSG).0);
    f.finish()
}

/// Encodes a CLOSED; `close_error` says that closing the transaction failed.
pub fn encode_closed(run: u64, inc: u32, tx: u64, msg: u32, close_error: bool) -> Vec<u8> {
    let mut f = FrameBuilder::new(KIND_CLOSED, run, inc, tx, msg);
    f.u8(u8::from(close_error));
    f.finish()
}

/// Encodes a BYE: how many transactions were started, closed, and closed with an error.
pub fn encode_bye(run: u64, inc: u32, started: u64, closed: u64, close_errors: u64) -> Vec<u8> {
    let mut f = FrameBuilder::new(KIND_BYE, run, inc, 0, 0);
    f.raw(&started.to_be_bytes());
    f.raw(&closed.to_be_bytes());
    f.raw(&close_errors.to_be_bytes());
    f.finish()
}

#[cfg(test)]
mod tests;
