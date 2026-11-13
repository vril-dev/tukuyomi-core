//! TLS for the listeners that end it.
//!
//! A TLS listener has certificates, each with a chain file, a private key file and the hosts it serves (see
//! `config`). The files are read when the proxy starts, and a file that fails a check ends the start (`certs`,
//! `keys`). When the proxy reads the configuration file again (SIGHUP) they are read into the TLS of the new setup,
//! and a failure refuses the file. SIGUSR2 reads them again into the TLS in use, and a failure leaves the ones in use
//! as they are. A certificate with `acme` whose files do not exist yet does not end the start or the reading: it
//! waits to be issued by the command `acme renew` and read by the next SIGUSR2 (`Tls::waiting`). The handshake
//! chooses the certificate by the server name of the client, from the hosts of the settings and from nothing else
//! (`sni`, `handshake`). After it, a request on the connection is served as on a plain one, over HTTP/1.1 or, if the
//! listener has `http2` and the client chose it, HTTP/2, with one more rule: its `Host` has to be one that the
//! certificate of the handshake covers, or it is answered with 421 (see `conn`). With `managed`, every TLS listener
//! chooses from the certificate of the way to the admin process and those of the sites of the version (`table`), and
//! SIGUSR2 reads the certificate of the way from its files again and those of the sites from the managed store. The
//! certificate of the way and those of the sites may have `acme` as well: the files of the way are those that
//! `admin.route` names, and those of a site with `acme` are in `acme/` of the managed store; either waits as a
//! certificate of a listener with `acme` does until its files are there.

mod certs;
mod handshake;
mod keys;
mod set;
mod sni;
mod table;

pub(crate) use certs::check;
pub use certs::{Fault, Place, Refusal};
pub use handshake::Handshake;
pub use keys::{Files, KeySource};
pub(crate) use keys::{certified, chain_of, read_file};
pub use set::Tls;
pub use sni::{Hosts, Names, host_name};

#[cfg(test)]
pub(in crate::inbound) mod tests;
