//! The HELLO of the wire protocol: its decoding, and the comparison of a decoded one with the start and with the
//! inspector build that the kernel accepts for the engine of the generation (`Engine::pinned`). A child of `codec`,
//! which has the reading and the writing of the frames.
//!
//! The version of the HELLO is 1 for every engine. Its three strings say the same thing whatever the engine is: the
//! toolchain that built the inspector, the version of the engine, and the hash of the source of the engine.
#![forbid(unsafe_code)]

use super::{ContentError, Cursor, MAX_CONCUR_TX, MAX_DECLARED, QUEUE_DEPTH};
use crate::engine::Build;

// HELLO string bounds: the toolchain that built the inspector, the version of the engine and the hash of its source.
const MAX_TOOLCHAIN: usize = 64;
const MAX_ENGINE_VERSION: usize = 64;
const MAX_ENGINE_SOURCE: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Hello {
    pub version: u16,
    pub pid: u32,
    pub nonce: [u8; 16],
    pub run: u64,
    pub inc: u32,
    /// The toolchain that built the inspector.
    pub toolchain: Vec<u8>,
    /// The version of the engine.
    pub engine_version: Vec<u8>,
    /// The hash of the source of the engine.
    pub engine_source: Vec<u8>,
    pub rules_sha256: [u8; 32],
    pub body_limit: u32,
    pub mem_limit: u64,
    pub gomaxprocs: u16,
    pub tx_limit: u16,
    pub queue: u16,
}

/// Decodes HELLO. A version other than v1 is its own reason ("hello contract version is not v1"): the caller treats it
/// as a deterministic mismatch (no restart). The values (pid, nonce, run, inc, versions, sha256, limits) are
/// checked by the caller, not here.
pub(crate) fn decode_hello(p: &[u8]) -> Result<Hello, ContentError> {
    let mut c = Cursor { p };
    let version = c.u16()?;
    if version != 1 {
        return Err(ContentError("hello contract version is not v1"));
    }
    let pid = c.u32()?;
    let nonce = c.array::<16>()?;
    let run = c.u64()?;
    let inc = c.u32()?;
    let toolchain = c.str16(1, MAX_TOOLCHAIN)?;
    let engine_version = c.str16(1, MAX_ENGINE_VERSION)?;
    let engine_source = c.str16(1, MAX_ENGINE_SOURCE)?;
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
        toolchain: toolchain.to_vec(),
        engine_version: engine_version.to_vec(),
        engine_source: engine_source.to_vec(),
        rules_sha256,
        body_limit,
        mem_limit,
        gomaxprocs,
        tx_limit,
        queue,
    })
}

/// What a valid HELLO contains besides the start's own pid, run, incarnation and nonce. `build` is the inspector
/// build that the kernel accepts for the engine of the generation (`Engine::pinned`): a HELLO reports the toolchain
/// that built the inspector, the version of the engine and the hash of its source, and a HELLO that reports any other
/// build is refused. No build (an engine with none pinned) refuses every HELLO. The rules sha256 comes from the
/// configuration. Go hashes the bytes of the bundle's `manifest.json` it read, checks each file the manifest names
/// against the sha256 it gives and builds the WAF from the bytes it checked, so HELLO ties the loaded rules to
/// `rules_sha256`. `mem_limit` is `GOMEMLIMIT` and `gomaxprocs` is `GOMAXPROCS`, as the inspector reports them.
pub(crate) struct HelloExpect<'a> {
    pub build: Option<&'a Build>,
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
    if h.version != 1 {
        return Err("hello contract version is not v1");
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
    let Some(build) = exp.build else {
        return Err("hello engine is not pinned");
    };
    if h.toolchain != build.toolchain {
        return Err("hello toolchain differs");
    }
    if h.engine_version != build.version {
        return Err("hello engine version differs");
    }
    if h.engine_source != build.source {
        return Err("hello engine source differs");
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
