//! The ModSecurity inspection process: the inspector side of the wire protocol 1 and the calls into
//! libmodsecurity.
#![deny(unsafe_code)]

pub mod bundle;
pub mod codec;
#[allow(unsafe_code)]
pub mod ffi;
pub mod link;
pub mod owner;
pub mod rules;
#[allow(unsafe_code)]
pub mod sandbox;

#[cfg(test)]
mod testkit;
