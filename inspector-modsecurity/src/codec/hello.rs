//! The HELLO of the wire protocol: its encoding. A child of `codec`, which has the framing.
//!
//! The version of the HELLO is 1 for every engine. Its three strings say the same thing whatever the engine is: the
//! toolchain that built the inspector, the version of the engine, and the hash of the source of the engine.
#![forbid(unsafe_code)]

use super::{
    ContentError, FrameBuilder, KIND_HELLO, MAX_CONCUR_TX, MAX_DECLARED, MAX_HELLO, QUEUE_DEPTH,
};

// HELLO string bounds: the toolchain that built the inspector, the version of the engine and the hash of its source.
const MAX_TOOLCHAIN: usize = 64;
const MAX_ENGINE_VERSION: usize = 64;
const MAX_ENGINE_SOURCE: usize = 128;

/// What the inspector says about itself. The body limit, the number of concurrent transactions and the queue depth
/// are those of the protocol and are written by the encoder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hello<'a> {
    pub pid: u32,
    pub nonce: [u8; 16],
    /// The toolchain that built the inspector.
    pub toolchain: &'a [u8],
    /// The version of the engine.
    pub engine_version: &'a [u8],
    /// The hash of the source of the engine.
    pub engine_source: &'a [u8],
    /// The sha256 of the manifest of the rules it loaded.
    pub rules_sha256: [u8; 32],
    pub mem_limit: u64,
    pub gomaxprocs: u16,
}

fn within(s: &[u8], hi: usize) -> bool {
    !s.is_empty() && s.len() <= hi
}

/// Encodes the HELLO of the start with this `run` and `inc`. A string outside its bounds is refused.
pub fn encode_hello(run: u64, inc: u32, h: &Hello<'_>) -> Result<Vec<u8>, ContentError> {
    if !within(h.toolchain, MAX_TOOLCHAIN)
        || !within(h.engine_version, MAX_ENGINE_VERSION)
        || !within(h.engine_source, MAX_ENGINE_SOURCE)
    {
        return Err(ContentError("hello string length out of range"));
    }
    let body_limit =
        u32::try_from(MAX_DECLARED).map_err(|_| ContentError("body limit out of range"))?;
    let tx_limit =
        u16::try_from(MAX_CONCUR_TX).map_err(|_| ContentError("transaction limit out of range"))?;
    let mut f = FrameBuilder::new(KIND_HELLO, run, inc, 0, 0);
    f.u16(1); // protocol version 1
    f.raw(&h.pid.to_be_bytes());
    f.raw(&h.nonce);
    f.raw(&run.to_be_bytes());
    f.raw(&inc.to_be_bytes());
    f.str16(h.toolchain);
    f.str16(h.engine_version);
    f.str16(h.engine_source);
    f.raw(&h.rules_sha256);
    f.raw(&body_limit.to_be_bytes());
    f.raw(&h.mem_limit.to_be_bytes());
    f.u16(h.gomaxprocs);
    f.u16(tx_limit);
    f.u16(QUEUE_DEPTH);
    f.finish_within(MAX_HELLO)
}
