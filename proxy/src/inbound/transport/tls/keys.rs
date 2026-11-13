//! Where a certificate and its private key come from.
//!
//! `KeySource` is the one way in for the files of the listeners: it gives the chain and a key that can sign. `Files`
//! reads two PEM files, and `certified` takes the same from bytes that were read already (those of the managed store).
//! `chain_of` takes the chain alone from the bytes of a certificate file, for the admin process, which shows the
//! certificates of the store.
//! A file is a regular file of at most 1 MiB (`read_file` opens a file so, with the size as a parameter, for the
//! account key too). The certificate file holds 1 to 10 certificates, the first of which is the one for the host. The
//! key file holds exactly one private key, in a form (PKCS#8, SEC1 or PKCS#1) of a type that the crypto provider can
//! load. The bytes of the key file and the key in the form of the file are overwritten with zeros as soon as the
//! provider has made its own key of them, or the load has failed.

use std::fs::OpenOptions;
use std::io::{self, Read};
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

/// A whole file of at most `limit` bytes, zeroed when it is dropped. A file that does not exist is `Fault::Missing`.
pub(crate) fn read_file(path: &Path, limit: u64) -> Result<Zeroizing<Vec<u8>>, Fault> {
    // O_NONBLOCK: opening a FIFO must not wait for a writer; the check of the file type below then refuses it. It
    // does not affect reads of a regular file. O_NOCTTY: a terminal that is opened before that check is never made
    // the controlling terminal of the process. A link is followed (there is no O_NOFOLLOW): the path of a certificate
    // is often a link, for example into the directory of the version that is in use. The type and the size are those
    // of the file that was opened, so a path that is changed after the open does not change what is read.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK | O_NOCTTY)
        .open(path)
        .map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                Fault::Missing
            } else {
                Fault::Unreadable
            }
        })?;
    let meta = file.metadata().map_err(|_| Fault::Unreadable)?;
    if !meta.is_file() {
        return Err(Fault::Unreadable);
    }
    if meta.len() > limit {
        return Err(Fault::TooLarge);
    }
    // Room for the byte that shows the end, so that the bytes already read are not moved to a new place.
    let room = usize::try_from(meta.len()).map_or(0, |n| n.saturating_add(1));
    let mut bytes = Zeroizing::new(Vec::with_capacity(room));
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| Fault::Unreadable)?;
    if u64::try_from(bytes.len()).is_ok_and(|n| n > limit) {
        return Err(Fault::TooLarge);
    }
    Ok(bytes)
}

impl KeySource for Files {
    fn load(&self, cert_file: &Path, key_file: &Path) -> Result<CertifiedKey, Fault> {
        let chain = chain_of(&read_file(cert_file, MAX_FILE)?)?;
        key_of(chain, &read_file(key_file, MAX_FILE)?)
    }
}

/// The chain and the key that the bytes of a certificate file and of a key file hold, as `Files` takes them from the
/// files: the bytes of a file of the managed store, which the store has read and checked.
pub(crate) fn certified(chain: &[u8], key: &[u8]) -> Result<CertifiedKey, Fault> {
    key_of(chain_of(chain)?, key)
}

/// The 1 to 10 certificates of the bytes of a certificate file.
pub(crate) fn chain_of(bytes: &[u8]) -> Result<Vec<CertificateDer<'static>>, Fault> {
    let chain = CertificateDer::pem_slice_iter(bytes)
        .take(MAX_CHAIN + 1)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Fault::NotCertificates)?;
    if chain.is_empty() || chain.len() > MAX_CHAIN {
        return Err(Fault::NotCertificates);
    }
    Ok(chain)
}

/// `chain` with the one private key of the bytes of a key file, which signs for it.
fn key_of(chain: Vec<CertificateDer<'static>>, bytes: &[u8]) -> Result<CertifiedKey, Fault> {
    let mut keys = PrivateKeyDer::pem_slice_iter(bytes)
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
