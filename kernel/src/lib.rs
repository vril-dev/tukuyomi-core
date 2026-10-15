#![forbid(unsafe_code)]
mod child;
mod codec;
mod config;
mod io;
mod start;
mod state;
mod supervisor;
pub use config::{Config, ConfigError};
pub use supervisor::{
    Failure, Phase, Reason, Refused, ReqId, Request, Shutdown, Status, Supervisor, Verdict,
};

/// The upper limits that `submit` enforces, for a host that checks its input before submitting.
pub mod limits {
    pub const BODY: u64 = crate::codec::MAX_DECLARED; // body bytes
    pub const ADDR: usize = crate::codec::MAX_ADDR; // client and server address bytes, each
    pub const METHOD: usize = crate::codec::MAX_METHOD;
    pub const URI: usize = crate::codec::MAX_URI;
    pub const HEADERS: usize = crate::codec::MAX_HEADERS; // header count
    pub const HEADER_NAME: usize = crate::codec::MAX_HDR_NAME;
    pub const HEADER_VALUE: usize = crate::codec::MAX_HDR_VALUE;
    pub const HEADER_TOTAL: usize = crate::codec::MAX_HDR_TOTAL; // sum of the name and value lengths of all headers
}
