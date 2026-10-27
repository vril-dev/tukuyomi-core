//! Names, passwords and random bytes.
//!
//! A name is 1 to 32 bytes of `a-z`, `0-9`, `.`, `_` and `-`. A password is 12 to 128 bytes of UTF-8 and has no other
//! rule. A password is kept as a hash (`Hash`): PBKDF2-HMAC-SHA256 with a random salt of 16 bytes and an output of 32
//! bytes. The number of iterations is kept with the hash, so that it can be raised later; a new hash has `ITERATIONS`.
//! The hash of a password that is checked is compared with the stored one in constant time, by the provider. The
//! provider is aws-lc-rs, the one that rustls uses, and the random bytes come from it as they do for the keys of the
//! certificates (see `acme::key`).
//!
//! A password that came in a request or on the standard input is a `Secret`: its text is zeroed when it is dropped.

use std::fmt;
use std::num::NonZeroU32;

use aws_lc_rs::pbkdf2;
use rustls::crypto::aws_lc_rs::default_provider;
use serde::{Deserialize, Deserializer};
use zeroize::Zeroize;

/// The iterations of a new hash.
pub const ITERATIONS: u32 = 600_000;
/// The most iterations that a stored hash may have: a value above it is not read, so that a file cannot make the
/// login take for ever.
const MAX_ITERATIONS: u32 = 10_000_000;
pub const SALT_LEN: usize = 16;
pub const HASH_LEN: usize = 32;
pub const NAME_MAX: usize = 32;
pub const PASSWORD_MIN: usize = 12;
pub const PASSWORD_MAX: usize = 128;

/// Whether `name` is a name of a user.
pub fn valid_name(name: &str) -> bool {
    (1..=NAME_MAX).contains(&name.len())
        && name
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
}

/// Whether `password` is a password that may be set.
pub fn valid_password(password: &str) -> bool {
    (PASSWORD_MIN..=PASSWORD_MAX).contains(&password.len())
}

/// Fills `buf` with random bytes. False: the provider has none.
pub fn random(buf: &mut [u8]) -> bool {
    default_provider().secure_random.fill(buf).is_ok()
}

/// `bytes` as lowercase hexadecimal digits.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `N` bytes from exactly `2 * N` lowercase hexadecimal digits.
pub fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let digits = text.as_bytes();
    if digits.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (byte, pair) in out.iter_mut().zip(digits.chunks_exact(2)) {
        *byte = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(out)
}

fn nibble(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

/// A password in a request or on the standard input. It is not shown by `Debug` and its text is zeroed when it is
/// dropped.
pub struct Secret(String);

impl Secret {
    pub fn new(text: String) -> Secret {
        Secret(text)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(..)")
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Secret, D::Error> {
        String::deserialize(deserializer).map(Secret)
    }
}

/// The key that PBKDF2-HMAC-SHA256 makes of `password` and `salt` after `iterations` rounds.
fn derive(password: &[u8], salt: &[u8], iterations: NonZeroU32) -> [u8; HASH_LEN] {
    let mut out = [0u8; HASH_LEN];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        salt,
        password,
        &mut out,
    );
    out
}

/// The number of iterations, if it is one that is read: 1 to `MAX_ITERATIONS`.
fn rounds(iterations: u32) -> Option<NonZeroU32> {
    NonZeroU32::new(iterations).filter(|n| n.get() <= MAX_ITERATIONS)
}

/// The hash of a password: the iterations, the salt and the key.
#[derive(Clone, PartialEq, Eq)]
pub struct Hash {
    iterations: NonZeroU32,
    salt: [u8; SALT_LEN],
    hash: [u8; HASH_LEN],
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Hash(..)")
    }
}

impl Hash {
    /// The hash of `password` with a new salt after `iterations` rounds. None: the iterations are not 1 to
    /// `MAX_ITERATIONS`, or the provider has no random number.
    pub fn new(password: &str, iterations: u32) -> Option<Hash> {
        let iterations = rounds(iterations)?;
        let mut salt = [0u8; SALT_LEN];
        if !random(&mut salt) {
            return None;
        }
        let hash = derive(password.as_bytes(), &salt, iterations);
        Some(Hash {
            iterations,
            salt,
            hash,
        })
    }

    /// A hash that was stored. None: the iterations are not 1 to `MAX_ITERATIONS`.
    pub fn from_parts(iterations: u32, salt: [u8; SALT_LEN], hash: [u8; HASH_LEN]) -> Option<Hash> {
        Some(Hash {
            iterations: rounds(iterations)?,
            salt,
            hash,
        })
    }

    /// Whether `password` is the one this hash was made of. The comparison takes the same time whatever the bytes.
    pub fn verify(&self, password: &str) -> bool {
        pbkdf2::verify(
            pbkdf2::PBKDF2_HMAC_SHA256,
            self.iterations,
            &self.salt,
            password.as_bytes(),
            &self.hash,
        )
        .is_ok()
    }

    pub fn iterations(&self) -> u32 {
        self.iterations.get()
    }

    pub fn salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }

    pub fn hash(&self) -> &[u8; HASH_LEN] {
        &self.hash
    }
}

#[cfg(test)]
mod tests;
