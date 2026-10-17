#![forbid(unsafe_code)]
//! HTTP/1.1 front of the inspection kernel: one listener, one upstream, and every request inspected before it is
//! forwarded.

pub mod config;
pub mod forward;
pub mod host;
pub mod inbound;
pub mod inspect;
pub mod log;
pub mod rules;
