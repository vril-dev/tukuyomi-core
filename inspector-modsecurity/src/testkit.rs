//! Helpers shared by the unit tests: the golden file, the frames the kernel sends, a reader for the frames the
//! inspector sends, and a fake inspection.
use std::io::Read;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::codec::{FaultCode, HEADER_LEN, Header, MAGIC, RuleDetail, TxBegin};
use crate::owner::{Fault, Inspection, Outcome, Stop, Transaction};

pub const RUN: u64 = 0x0102_0304_0506_0708;
pub const INC: u32 = 7;

const GOLDEN: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../inspector/testdata/v1-golden.txt"
));

/// The names of the golden file, in its order.
pub fn golden_names() -> Vec<&'static str> {
    GOLDEN
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split_once(' '))
        .map(|(name, _)| name)
        .collect()
}

/// The whole frame of a golden vector: a line `name hex-of-the-whole-frame` (`#` lines are notes).
pub fn golden(name: &str) -> Vec<u8> {
    let hex = GOLDEN
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.trim().split_once(' '))
        .find(|(n, _)| *n == name)
        .unwrap_or_else(|| panic!("golden vector {name} missing"))
        .1
        .trim();
    assert!(hex.len().is_multiple_of(2), "odd hex length");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex digits"))
        .collect()
}

// ---- frames the kernel sends ----

/// A header the kernel sends, with the run and incarnation of the tests.
pub fn header_bytes(kind: u8, flags: u8, len: u32, tx: u64, msg: u32) -> [u8; HEADER_LEN] {
    let mut b = [0u8; HEADER_LEN];
    b[..4].copy_from_slice(&MAGIC);
    b[4] = kind;
    b[5] = flags;
    b[8..12].copy_from_slice(&len.to_be_bytes());
    b[12..20].copy_from_slice(&RUN.to_be_bytes());
    b[20..24].copy_from_slice(&INC.to_be_bytes());
    b[24..32].copy_from_slice(&tx.to_be_bytes());
    b[32..36].copy_from_slice(&msg.to_be_bytes());
    b
}

/// A whole frame the kernel sends.
pub fn inbound(kind: u8, flags: u8, tx: u64, msg: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).unwrap();
    let mut v = header_bytes(kind, flags, len, tx, msg).to_vec();
    v.extend_from_slice(payload);
    v
}

/// The header of a frame the kernel sends, as `check_header` gives it.
pub fn header(kind: u8, tx: u64, msg: u32) -> Header {
    Header {
        kind,
        cut: false,
        len: 0,
        run: RUN,
        inc: INC,
        tx,
        msg,
    }
}

fn put_str(p: &mut Vec<u8>, s: &[u8]) {
    p.extend_from_slice(&u16::try_from(s.len()).unwrap().to_be_bytes());
    p.extend_from_slice(s);
}

/// A TX_BEGIN payload for this method and URI, these headers and `declared` body bytes.
pub fn begin_with(method: &[u8], uri: &[u8], headers: &[(&[u8], &[u8])], declared: u64) -> Vec<u8> {
    let mut p = Vec::new();
    put_str(&mut p, b"127.0.0.1");
    p.extend_from_slice(&40000u16.to_be_bytes());
    put_str(&mut p, b"127.0.0.1");
    p.extend_from_slice(&8080u16.to_be_bytes());
    put_str(&mut p, method);
    put_str(&mut p, uri);
    put_str(&mut p, b"HTTP/1.1");
    p.extend_from_slice(&declared.to_be_bytes());
    p.extend_from_slice(&u16::try_from(headers.len()).unwrap().to_be_bytes());
    for (name, value) in headers {
        put_str(&mut p, name);
        put_str(&mut p, value);
    }
    p
}

/// A TX_BEGIN payload for `POST /a?q=1` with one header and `declared` body bytes.
pub fn begin_payload(declared: u64) -> Vec<u8> {
    begin_with(b"POST", b"/a?q=1", &[(b"Host", b"example.test")], declared)
}

// ---- frames the inspector sends ----

/// A frame the inspector sent, with its header checked.
#[derive(Debug)]
pub struct Out {
    pub kind: u8,
    pub tx: u64,
    pub msg: u32,
    pub payload: Vec<u8>,
}

pub fn out(frame: &[u8]) -> Out {
    assert!(frame.len() >= HEADER_LEN, "short frame");
    assert_eq!(frame[..4], MAGIC);
    assert_eq!(frame[5..8], [0, 0, 0], "flags and reserved");
    let len = u32::from_be_bytes(frame[8..12].try_into().unwrap()) as usize;
    assert_eq!(len, frame.len() - HEADER_LEN, "payload length");
    assert_eq!(u64::from_be_bytes(frame[12..20].try_into().unwrap()), RUN);
    assert_eq!(u32::from_be_bytes(frame[20..24].try_into().unwrap()), INC);
    Out {
        kind: frame[4],
        tx: u64::from_be_bytes(frame[24..32].try_into().unwrap()),
        msg: u32::from_be_bytes(frame[32..36].try_into().unwrap()),
        payload: frame[HEADER_LEN..].to_vec(),
    }
}

/// Reads one frame the inspector sent from the peer end of the socket; `None` at the end of the connection.
pub fn read_out(peer: &UnixStream) -> Option<Out> {
    peer.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut r = peer;
    let mut b = [0u8; HEADER_LEN];
    match r.read(&mut b[..1]).unwrap() {
        0 => return None,
        _ => r.read_exact(&mut b[1..]).unwrap(),
    }
    let len = u32::from_be_bytes(b[8..12].try_into().unwrap()) as usize;
    let mut frame = b.to_vec();
    frame.resize(HEADER_LEN + len, 0);
    r.read_exact(&mut frame[HEADER_LEN..]).unwrap();
    Some(out(&frame))
}

pub fn expect_verdict(frame: Option<Vec<u8>>, tx: u64, msg: u32, phase: u8, block: bool) {
    let o = out(&frame.expect("a VERDICT"));
    assert_eq!((o.kind, o.tx, o.msg), (0x20, tx, msg), "{o:?}");
    assert_eq!((o.payload[0], o.payload[1] == 1), (phase, block), "{o:?}");
}

pub fn expect_error(frame: Option<Vec<u8>>, tx: u64, msg: u32, class: u8, code: u16) {
    let o = out(&frame.expect("an ERROR"));
    assert_eq!((o.kind, o.tx, o.msg), (0x21, tx, msg), "{o:?}");
    let got = (
        o.payload[0],
        u16::from_be_bytes([o.payload[2], o.payload[3]]),
    );
    assert_eq!(got, (class, code), "{o:?}");
}

pub fn expect_closed(frame: Option<Vec<u8>>, tx: u64, msg: u32, close_error: bool) {
    let o = out(&frame.expect("a CLOSED"));
    assert_eq!((o.kind, o.tx, o.msg), (0x22, tx, msg), "{o:?}");
    assert_eq!(o.payload, [u8::from(close_error)]);
}

// ---- a fake inspection ----

/// What the fake inspection has been asked.
#[derive(Debug, Default)]
pub struct Log {
    /// The URI of each TX_BEGIN it was given.
    pub begins: Vec<Vec<u8>>,
    pub bodies: Vec<Vec<u8>>,
    pub ends: usize,
    pub closes: usize,
}

/// How the fake inspection answers; the default lets everything through.
#[derive(Clone, Copy, Default)]
pub struct Script {
    /// The n-th body (counted from 1) of a transaction blocks the request.
    pub block_at_body: Option<usize>,
    /// The end of the request blocks with this status (a status over 65535 cannot be written into a VERDICT).
    pub end_status: Option<i32>,
    pub body_fault: bool,
    pub start_fault: bool,
    pub close_error: bool,
    pub close_takes: Duration,
}

pub struct Fake {
    pub log: Arc<Mutex<Log>>,
    pub script: Script,
}

impl Fake {
    pub fn new(script: Script) -> (Fake, Arc<Mutex<Log>>) {
        let log = Arc::new(Mutex::new(Log::default()));
        (
            Fake {
                log: Arc::clone(&log),
                script,
            },
            log,
        )
    }
}

pub struct FakeTx {
    log: Arc<Mutex<Log>>,
    script: Script,
    bodies: usize,
}

fn stop(status: i32) -> Stop {
    Stop {
        rule_id: 1021,
        status,
        action: b"deny".to_vec(),
        data: b"x".to_vec(),
        rules: RuleDetail {
            ids: vec![942100],
            more: false,
            severity: 2,
            score: 5,
        },
    }
}

impl Inspection for Fake {
    type Tx = FakeTx;

    fn start(&mut self) -> Result<FakeTx, Fault> {
        if self.script.start_fault {
            return Err(Fault {
                code: FaultCode::Incomplete,
                text: "request inspection incomplete",
            });
        }
        Ok(FakeTx {
            log: Arc::clone(&self.log),
            script: self.script,
            bodies: 0,
        })
    }
}

impl Transaction for FakeTx {
    fn begin(&mut self, t: &TxBegin<'_>) -> Result<Outcome, Fault> {
        self.log.lock().unwrap().begins.push(t.uri.to_vec());
        Ok(Outcome::Continue(RuleDetail::NONE))
    }

    fn body(&mut self, bytes: &[u8]) -> Result<Option<Stop>, Fault> {
        self.log.lock().unwrap().bodies.push(bytes.to_vec());
        self.bodies += 1;
        if self.script.body_fault {
            return Err(Fault {
                code: FaultCode::ReqWrite,
                text: "request body write failed",
            });
        }
        Ok((self.script.block_at_body == Some(self.bodies)).then(|| stop(403)))
    }

    fn end(&mut self) -> Result<Outcome, Fault> {
        self.log.lock().unwrap().ends += 1;
        Ok(match self.script.end_status {
            Some(status) => Outcome::Block(stop(status)),
            None => Outcome::Continue(RuleDetail::NONE),
        })
    }

    fn close(self) -> bool {
        thread::sleep(self.script.close_takes);
        self.log.lock().unwrap().closes += 1;
        self.script.close_error
    }
}
