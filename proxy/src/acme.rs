//! The ACME client: `tukuyomi-proxy acme renew <config>` issues and renews the certificates that have `acme` (RFC 8555,
//! with the challenge HTTP-01 only), and the plain and the redirecting listeners of the running proxy answer the
//! challenge (see `inbound::challenge`). When the first argument of the process is `acme` the process is this
//! command instead of the proxy, as it is for `rules`, and nothing of the proxy starts. The running proxy does not
//! notice the command: the operator runs it from a timer, and sends SIGUSR2 to the proxy when a certificate is new.
//!
//! The parts, each with its own file: `base64` (the two alphabets), `der` (the few encodings of X.509 that are
//! needed: the end of the time of validity of a certificate, the request for a certificate, the form of a
//! signature), `key` (a key on the curve P-256, for the account and for a certificate), `jws` (the signed messages,
//! the JWK and its thumbprint), `client` (HTTPS to the CA), `order` (the account and the order of a certificate
//! with its challenges), `files` (the account key, the files of the challenges and the writing of a certificate)
//! and `command` (the arguments, the decision which certificates are due, and the report). The crypto provider is
//! the one of rustls, so no part needs another crate.
//!
//! A failure of a step is a `Failure` (see `failure`): a fixed sentence, or the `type` of the problem document that
//! the CA sent, with every byte outside 0x20 to 0x7e written as `\xNN`. Nothing else from the CA is written out.

pub(crate) mod base64;
mod client;
pub mod command;
mod der;
mod failure;
mod files;
mod jws;
mod key;
mod order;

pub use failure::Failure;

#[cfg(test)]
pub(crate) mod tests;
