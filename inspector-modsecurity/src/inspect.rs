//! The inspection of requests by libmodsecurity: one transaction of the library for each transaction of the
//! kernel.
//!
//! `Inspector` holds the library's engine and the rules of one generation and makes the inspection of each request
//! (`InspectedRequest`), which `owner` drives with the frames of the kernel. The request is fed to the library in
//! its order, phase 1 gives a first answer, the body is fed and parsed, and phase 2 gives the last.
//!
//! A request is let through only when the inspection can say that it ran to the end: the library cannot say so on
//! its own, because the rules of the operator can switch the engine or the body access off for one request,
//! change how the body is parsed, or leave a regular expression that failed or gave up (`transaction`).
//! Whatever cannot be confirmed ends the request as one that was not inspected. The blocks that the inspector
//! makes itself (a body that does not parse, too many arguments, a target that cannot be parsed) do not depend on
//! the rules of the operator either.
#![forbid(unsafe_code)]

mod arguments;
mod inspector;
mod processor;
mod transaction;
mod uri;

pub use inspector::Inspector;
pub use transaction::InspectedRequest;

#[cfg(test)]
mod tests;
