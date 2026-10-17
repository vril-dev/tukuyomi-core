//! The fingerprint of a rule bundle.

fn digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// The fingerprint of a rule bundle: the SHA-256 of the bytes of its manifest.json. It names a generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// Reads a fingerprint written as exactly 64 lowercase hexadecimal digits and nothing else: no sign, no
    /// space, no newline, no uppercase digit.
    pub fn from_hex(text: &[u8]) -> Option<Fingerprint> {
        if text.len() != 64 {
            return None;
        }
        let mut out = [0; 32];
        for (byte, pair) in out.iter_mut().zip(text.chunks_exact(2)) {
            *byte = digit(pair[0])? << 4 | digit(pair[1])?;
        }
        Some(Fingerprint(out))
    }

    /// The 64 lowercase hexadecimal digits of the fingerprint.
    pub fn hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The 32 bytes of the fingerprint.
    pub fn bytes(&self) -> [u8; 32] {
        self.0
    }
}

#[cfg(test)]
mod tests;
