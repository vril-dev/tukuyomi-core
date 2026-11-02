//! The certificate authorities of the system and the TLS errors, for the connection to the database of any driver.
//!
//! The authorities are those of the system: the file that the variable `SSL_CERT_FILE` names (the variable that
//! OpenSSL and many tools use), else the bundle at the place of the system (Debian and Ubuntu, Fedora and Red Hat,
//! openSUSE). A connection string cannot name a file of authorities, and the crate that reads the store of the
//! system (`rustls-native-certs`) is not among the dependencies, so the bundle is read here with the PEM reader that
//! `rustls` has. A file without any usable certificate is an error, never an empty store that would refuse everything
//! or a store that accepts everything.

use std::io::Read;
use std::path::{Path, PathBuf};

use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;

use super::{Error, ROOTS};
use crate::files;

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
pub(super) fn bundle() -> Option<PathBuf> {
    match std::env::var_os("SSL_CERT_FILE") {
        Some(path) if !path.is_empty() => Some(PathBuf::from(path)),
        _ => BUNDLES
            .iter()
            .map(PathBuf::from)
            .find(|path| path.is_file()),
    }
}

/// The bytes of the regular file at `path`, at most `MAX_BUNDLE` of them.
fn read(path: &Path) -> Result<Vec<u8>, Error> {
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
    Ok(bytes)
}

/// The authorities of the PEM file at `path`: the certificates that can be trust anchors. An error if there is none.
pub(super) fn roots_from(path: &Path) -> Result<RootCertStore, Error> {
    let bytes = read(path)?;
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

/// The same authorities as `roots_from` takes, one by one, for a client that adds each of them to its own store and
/// fails on the first it cannot use. An error if there is none.
pub(super) fn certificates_from(path: &Path) -> Result<Vec<CertificateDer<'static>>, Error> {
    let bytes = read(path)?;
    let certificates: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&bytes)
        .filter_map(Result::ok)
        .map(CertificateDer::into_owned)
        .filter(|certificate| RootCertStore::empty().add(certificate.clone()).is_ok())
        .collect();
    if certificates.is_empty() {
        return Err(Error::new(ROOTS));
    }
    Ok(certificates)
}

/// Whether an error is the refusal of the certificate of the server: the cause is a TLS error of that kind.
pub(super) fn refused_certificate(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut cause = Some(error);
    while let Some(error) = cause {
        let tls = error.downcast_ref::<rustls::Error>().or_else(|| {
            error
                .downcast_ref::<std::io::Error>()?
                .get_ref()?
                .downcast_ref::<rustls::Error>()
        });
        if let Some(tls) = tls {
            return matches!(tls, rustls::Error::InvalidCertificate(_));
        }
        cause = error.source();
    }
    false
}

#[cfg(test)]
mod tests;
