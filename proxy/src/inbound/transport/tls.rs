//! TLS for the listeners that end it.
//!
//! A TLS listener has certificates, each with a chain file, a private key file and the hosts it serves (see
//! `config`). The files are read when the proxy starts, and a file that fails a check ends the start (`certs`,
//! `keys`); SIGUSR2 reads them again, and a failure leaves the ones in use as they are. A certificate with `acme`
//! whose files do not exist yet does not end the start or the reading: it waits to be issued by the command
//! `acme renew` and read by the next SIGUSR2 (`Tls::waiting`). The handshake chooses the
//! certificate by the server name of the client, from the hosts of the settings and from nothing else (`sni`,
//! `handshake`). After it, a request on the connection is served as on a plain one, over HTTP/1.1 or, if the
//! listener has `http2` and the client chose it, HTTP/2, with one more rule: its `Host` has to be one that the
//! certificate of the handshake covers, or it is answered with 421 (see `conn`).

mod certs;
mod handshake;
mod keys;
mod set;
mod sni;

pub(crate) use certs::check;
pub use certs::{Fault, Place, Refusal};
pub use handshake::Handshake;
pub(crate) use keys::read_file;
pub use keys::{Files, KeySource};
pub use set::Tls;
pub use sni::{Hosts, Names, host_name};

#[cfg(test)]
pub(in crate::inbound) mod tests;
