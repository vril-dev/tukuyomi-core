//! TLS to the database: `rustls` with the `aws-lc-rs` provider, which is the one the proxy uses.
//!
//! The certificate of the server is always verified, against the authorities of the system (see `roots`), for the
//! name the connection string gives (a name or an address that the certificate lists). There is no way to turn the
//! check off: `sslmode=disable`, when it is written, is the way to speak without TLS, and with any other mode a
//! server whose certificate is not accepted is not connected to, and neither is one that does not offer TLS. The
//! connection string cannot name a file of authorities (`tokio-postgres` knows no `sslrootcert`).

use std::sync::Arc;

use rustls::crypto::aws_lc_rs::default_provider;
use rustls::{ClientConfig, version};
use tokio_postgres_rustls::MakeRustlsConnect;

use crate::store::roots;
use crate::store::{Error, ROOTS};

/// The TLS of one connection: TLS 1.3 and 1.2, the authorities of the system, no certificate of our own.
pub(super) fn connector() -> Result<MakeRustlsConnect, Error> {
    let path = roots::bundle().ok_or(Error::new(ROOTS))?;
    let config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&version::TLS13, &version::TLS12])
        .map_err(|_| Error::new(ROOTS))?
        .with_root_certificates(roots::roots_from(&path)?)
        .with_no_client_auth();
    Ok(MakeRustlsConnect::new(config))
}

#[cfg(test)]
mod tests;
