//! TLS to the database: `rustls` with the `aws-lc-rs` provider, which is the one the proxy uses.
//!
//! The certificate of the server is always verified, against the authorities of a file of certificates in PEM, for
//! the name the connection string gives (a name or an address that the certificate lists). There is no way to turn
//! the check off: `sslmode=disable`, when it is written, is the way to speak without TLS, and with any other mode a
//! server whose certificate is not accepted is not connected to, and neither is one that does not offer TLS.
//!
//! The authorities are those of the system: the file that the variable `SSL_CERT_FILE` names (the variable that
//! OpenSSL and many tools use), else the bundle at the place of the system (Debian and Ubuntu, Fedora and Red Hat,
//! openSUSE). The connection string cannot name a file of authorities (`tokio-postgres` knows no `sslrootcert`), and
//! the crate that reads the store of the system (`rustls-native-certs`) is not among the dependencies, so the
//! bundle is read here with the PEM reader that `rustls` has. A file without any usable certificate is an error,
//! never an empty store that would refuse everything or a store that accepts everything.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::crypto::aws_lc_rs::default_provider;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use rustls::{ClientConfig, RootCertStore, version};
use tokio_postgres_rustls::MakeRustlsConnect;

use crate::files;
use crate::store::{Error, ROOTS};

/// The bundles of the authorities of the system, by distribution.
const BUNDLES: [&str; 3] = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
];
/// The longest bundle in bytes; the one of Debian is about 200 KiB.
const MAX_BUNDLE: u64 = 8 << 20;

/// The file of the authorities: `SSL_CERT_FILE` if it is set and not empty, else the first bundle of the system that
/// is there.
fn bundle() -> Option<PathBuf> {
    match std::env::var_os("SSL_CERT_FILE") {
        Some(path) if !path.is_empty() => Some(PathBuf::from(path)),
        _ => BUNDLES
            .iter()
            .map(PathBuf::from)
            .find(|path| path.is_file()),
    }
}

/// The authorities of the PEM file at `path`: the certificates that can be trust anchors. An error if there is none.
pub(super) fn roots_from(path: &Path) -> Result<RootCertStore, Error> {
    let file = files::open_followed(path).map_err(|_| Error::new(ROOTS))?;
    if !file.metadata().is_ok_and(|meta| meta.is_file()) {
        return Err(Error::new(ROOTS));
    }
    let mut bytes = Vec::new();
    file.take(MAX_BUNDLE + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::new(ROOTS))?;
    if u64::try_from(bytes.len()).is_ok_and(|n| n > MAX_BUNDLE) {
        return Err(Error::new(ROOTS));
    }
    let mut roots = RootCertStore::empty();
    let (added, _) = roots.add_parsable_certificates(
        CertificateDer::pem_slice_iter(&bytes)
            .filter_map(Result::ok)
            .map(CertificateDer::into_owned),
    );
    if added == 0 {
        return Err(Error::new(ROOTS));
    }
    Ok(roots)
}

/// The TLS of one connection: TLS 1.3 and 1.2, the authorities of the system, no certificate of our own.
pub(super) fn connector() -> Result<MakeRustlsConnect, Error> {
    let path = bundle().ok_or(Error::new(ROOTS))?;
    let config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&version::TLS13, &version::TLS12])
        .map_err(|_| Error::new(ROOTS))?
        .with_root_certificates(roots_from(&path)?)
        .with_no_client_auth();
    Ok(MakeRustlsConnect::new(config))
}

#[cfg(test)]
mod tests;
