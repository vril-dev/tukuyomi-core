#![forbid(unsafe_code)]
mod config;
mod process;
mod protocol;
mod requests;
pub use config::{Config, ConfigError};
pub use protocol::codec::Matched;
pub use requests::supervisor::{
    Failure, Phase, Reason, Refused, ReqId, Request, Shutdown, Status, Supervisor, Verdict,
};

/// The upper limits that `submit` enforces, for a host that checks its input before submitting.
pub mod limits {
    pub const BODY: u64 = crate::protocol::codec::MAX_DECLARED; // body bytes inspected
    pub const ADDR: usize = crate::protocol::codec::MAX_ADDR; // client and server address bytes, each
    pub const METHOD: usize = crate::protocol::codec::MAX_METHOD;
    pub const URI: usize = crate::protocol::codec::MAX_URI;
    pub const HEADERS: usize = crate::protocol::codec::MAX_HEADERS; // header count
    pub const HEADER_NAME: usize = crate::protocol::codec::MAX_HDR_NAME;
    pub const HEADER_VALUE: usize = crate::protocol::codec::MAX_HDR_VALUE;
    pub const HEADER_TOTAL: usize = crate::protocol::codec::MAX_HDR_TOTAL; // sum of the name and value lengths of all headers
}
