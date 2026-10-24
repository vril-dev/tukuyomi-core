//! Where a certificate and its private key come from.
//!
//! `KeySource` is the one way in: it gives the chain and a key that can sign. `Files` reads two PEM files. A file
//! is a regular file of at most 1 MiB. The certificate file holds 1 to 10 certificates, the first of which is the
//! one for the host. The key file holds exactly one private key, in a form (PKCS#8, SEC1 or PKCS#1) of a type that
//! the crypto provider can load. The bytes of the key file and the key in the form of the file are overwritten with
//! zeros as soon as the provider has made its own key of them, or the load has failed.

use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use rustls::crypto::aws_lc_rs::sign::any_supported_type;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;
use zeroize::Zeroizing;

use super::certs::Fault;
use crate::rules::file_store::{O_NOCTTY, O_NONBLOCK};

/// The longest certificate or key file in bytes.
const MAX_FILE: u64 = 1 << 20;
/// The most certificates in a chain.
const MAX_CHAIN: usize = 10;

/// What gives the proxy a certificate and the key to it. The files are named by the settings of the certificate;
/// another source may use them as names only.
pub trait KeySource {
    /// The chain, the certificate for the host first, and a key that signs for it. Whether the two go together,
    /// and what the certificate covers, is checked by the caller.
    fn load(&self, cert_file: &Path, key_file: &Path) -> Result<CertifiedKey, Fault>;
}

/// The source that reads the two files.
#[derive(Clone, Copy, Debug)]
pub struct Files;

/// A whole file, zeroed when it is dropped.
fn read(path: &Path) -> Result<Zeroizing<Vec<u8>>, Fault> {
    // O_NONBLOCK: opening a FIFO must not wait for a writer; the check of the file type below then refuses it. It
    // does not affect reads of a regular file. O_NOCTTY: a terminal that is opened before that check is never made
    // the controlling terminal of the process. A link is followed (there is no O_NOFOLLOW): the path of a certificate
    // is often a link, for example into the directory of the version that is in use. The type and the size are those
    // of the file that was opened, so a path that is changed after the open does not change what is read.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK | O_NOCTTY)
        .open(path)
        .map_err(|_| Fault::Unreadable)?;
    let meta = file.metadata().map_err(|_| Fault::Unreadable)?;
    if !meta.is_file() {
        return Err(Fault::Unreadable);
    }
    if meta.len() > MAX_FILE {
        return Err(Fault::TooLarge);
    }
    // Room for the byte that shows the end, so that the bytes already read are not moved to a new place.
    let room = usize::try_from(meta.len()).map_or(0, |n| n.saturating_add(1));
    let mut bytes = Zeroizing::new(Vec::with_capacity(room));
    file.take(MAX_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Fault::Unreadable)?;
    if u64::try_from(bytes.len()).is_ok_and(|n| n > MAX_FILE) {
        return Err(Fault::TooLarge);
    }
    Ok(bytes)
}

impl KeySource for Files {
    fn load(&self, cert_file: &Path, key_file: &Path) -> Result<CertifiedKey, Fault> {
        let chain = {
            let bytes = read(cert_file)?;
            CertificateDer::pem_slice_iter(&bytes)
                .take(MAX_CHAIN + 1)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| Fault::NotCertificates)?
        };
        if chain.is_empty() || chain.len() > MAX_CHAIN {
            return Err(Fault::NotCertificates);
        }
        let bytes = read(key_file)?;
        let mut keys = PrivateKeyDer::pem_slice_iter(&bytes)
            .take(2)
            .map(|key| key.map(Zeroizing::new))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Fault::NotOneKey)?;
        let (Some(key), None) = (keys.pop(), keys.pop()) else {
            return Err(Fault::NotOneKey);
        };
        let signing = any_supported_type(&key).map_err(|_| Fault::KeyType)?;
        Ok(CertifiedKey::new(chain, signing))
    }
}
