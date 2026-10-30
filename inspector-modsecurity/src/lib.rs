//! The ModSecurity inspection process: the inspector side of the wire protocol 1 and the calls into
//! libmodsecurity.
#![deny(unsafe_code)]

pub mod codec;
#[allow(unsafe_code)]
pub mod ffi;
pub mod link;
pub mod owner;

#[cfg(test)]
mod testkit;
