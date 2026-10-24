#![forbid(unsafe_code)]
//! HTTP/1.1 front of the inspection kernel: the listeners (plain, TLS, or a redirect to https), the upstream groups
//! that its routes choose from, and every request inspected before it is forwarded.

pub mod config;
pub mod forward;
pub mod host;
pub mod inbound;
pub mod inspect;
pub mod log;
pub mod route;
pub mod rules;
