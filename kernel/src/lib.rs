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
