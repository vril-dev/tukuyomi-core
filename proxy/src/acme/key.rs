//! A key on the curve P-256 that signs with ECDSA and SHA-256: the key of the account at the CA, and the key of a
//! certificate.
//!
//! The crypto provider is the one of rustls (aws-lc-rs). It signs for TLS, so it hands out a signature in the DER form
//! (`SEQUENCE { r, s }`), which is what the request for a certificate holds; the JWS of ES256 holds `r` and `s` as 64
//! bytes, which `der::ecdsa_fixed` makes of it. A new key is 32 random bytes from the provider's generator, tried as
//! the secret number `d` of the key in `1..n` (`n` is the order of the curve; a number outside that is drawn again, so
//! that the keys are not biased), written as a PKCS #8 key without the public part, which the provider fills in when
//! it loads the key. The bytes and the text of a private key are zeroed when they are dropped.

use std::sync::Arc;

use rustls::SignatureScheme;
use rustls::crypto::aws_lc_rs::default_provider;
use rustls::crypto::aws_lc_rs::sign::any_ecdsa_type;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::SigningKey;
use zeroize::Zeroizing;

use super::{Failure, base64, der};

const SCHEME: SignatureScheme = SignatureScheme::ECDSA_NISTP256_SHA256;
/// How many numbers are drawn for a key before the generator is given up on. One in 2^32 is out of range.
const DRAWS: usize = 8;

/// The order `n` of P-256, big endian.
const ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// A PKCS #8 key for P-256 up to the 32 bytes of the secret number: the version, the algorithm (`id-ecPublicKey`,
/// `prime256v1`), and the `ECPrivateKey` with its version and the octet string that holds the number.
const PKCS8_PREFIX: [u8; 35] = [
    0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x27, 0x30, 0x25, 0x02, 0x01,
    0x01, 0x04, 0x20,
];

/// A `SubjectPublicKeyInfo` for P-256 up to the point, which follows as 65 bytes (`04`, `x`, `y`).
const SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// A signing key on P-256, and its public point.
pub struct Key {
    signing: Arc<dyn SigningKey>,
    /// `04`, `x` and `y`.
    point: [u8; 65],
}

/// Whether `d` is a number from 1 to `n - 1`.
fn in_range(d: &[u8; 32]) -> bool {
    d.iter().any(|&byte| byte != 0) && d[..] < ORDER[..]
}

impl Key {
    fn load(der: &PrivateKeyDer<'_>) -> Result<Key, Failure> {
        const NOT_P256: Failure = Failure::Text("a key is not an ECDSA key on the curve P-256");
        let signing = any_ecdsa_type(der).map_err(|_| NOT_P256)?;
        // The provider tells the curve by the scheme it signs with.
        signing.choose_scheme(&[SCHEME]).ok_or(NOT_P256)?;
        let spki = signing.public_key().ok_or(NOT_P256)?;
        let point = spki
            .as_ref()
            .strip_prefix(&SPKI_PREFIX[..])
            .and_then(|point| <[u8; 65]>::try_from(point).ok())
            .filter(|point| point[0] == 4)
            .ok_or(NOT_P256)?;
        Ok(Key { signing, point })
    }

    /// The key in a PEM text that holds exactly one private key.
    pub fn from_pem(pem: &[u8]) -> Result<Key, Failure> {
        let mut keys = PrivateKeyDer::pem_slice_iter(pem)
            .take(2)
            .map(|key| key.map(Zeroizing::new))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "a key file does not hold a private key in PEM")?;
        match (keys.pop(), keys.pop()) {
            (Some(key), None) => Key::load(&key),
            _ => Err("a key file does not hold exactly one private key in PEM".into()),
        }
    }

    /// A new key, and its PKCS #8 form as PEM.
    pub fn generate() -> Result<(Key, Zeroizing<String>), Failure> {
        for _ in 0..DRAWS {
            let mut d = Zeroizing::new([0u8; 32]);
            default_provider()
                .secure_random
                .fill(&mut d[..])
                .map_err(|_| "no random number is available")?;
            if !in_range(&d) {
                continue;
            }
            let mut pkcs8 = Zeroizing::new(Vec::with_capacity(PKCS8_PREFIX.len() + d.len()));
            pkcs8.extend_from_slice(&PKCS8_PREFIX);
            pkcs8.extend_from_slice(&d[..]);
            let key = Key::load(&PrivateKeyDer::from(PrivatePkcs8KeyDer::from(&pkcs8[..])))?;
            return Ok((key, base64::pem("PRIVATE KEY", &pkcs8)));
        }
        Err("no usable random number for a key".into())
    }

    /// The `x` coordinate of the public point.
    pub fn x(&self) -> &[u8] {
        &self.point[1..33]
    }

    /// The `y` coordinate of the public point.
    pub fn y(&self) -> &[u8] {
        &self.point[33..]
    }

    /// The public key as a `SubjectPublicKeyInfo`.
    pub fn spki(&self) -> Vec<u8> {
        [&SPKI_PREFIX[..], &self.point[..]].concat()
    }

    /// The key as the provider's signing key, for a `CertifiedKey`.
    pub fn signing_key(&self) -> Arc<dyn SigningKey> {
        self.signing.clone()
    }

    /// The signature of `message` in the DER form.
    pub fn sign_der(&self, message: &[u8]) -> Result<Vec<u8>, Failure> {
        self.signing
            .choose_scheme(&[SCHEME])
            .ok_or("a key cannot sign")?
            .sign(message)
            .map_err(|_| "a key failed to sign".into())
    }

    /// The signature of `message` as the 64 bytes `r` and `s`.
    pub fn sign_fixed(&self, message: &[u8]) -> Result<[u8; 64], Failure> {
        der::ecdsa_fixed(&self.sign_der(message)?)
            .map_err(|_| "a signature is not in the form of ECDSA".into())
    }
}

#[cfg(test)]
mod tests;
