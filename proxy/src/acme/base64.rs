//! Base64 (RFC 4648): the URL-safe alphabet without padding, which the JWS and the request for a certificate use, and
//! the standard one with padding, which PEM uses.

use zeroize::Zeroizing;

const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/// The characters of a line of PEM.
const PEM_LINE: usize = 64;

fn encode(bytes: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let at = |i: usize| chunk.get(i).copied().unwrap_or(0);
        let (a, b, c) = (at(0), at(1), at(2));
        let sextets = [
            a >> 2,
            ((a & 3) << 4) | (b >> 4),
            ((b & 15) << 2) | (c >> 6),
            c & 63,
        ];
        // One byte gives two characters, two give three, three give four.
        for &sextet in &sextets[..=chunk.len()] {
            out.push(char::from(alphabet[usize::from(sextet)]));
        }
        if pad {
            for _ in chunk.len() + 1..4 {
                out.push('=');
            }
        }
    }
    out
}

/// `bytes` in the URL-safe alphabet without padding.
pub fn url(bytes: &[u8]) -> String {
    encode(bytes, URL, false)
}

/// `der` as a PEM object with the label `label`: the standard alphabet with padding, in lines of 64 characters. The
/// text is zeroed when it is dropped, for it may be a private key.
pub fn pem(label: &str, der: &[u8]) -> Zeroizing<String> {
    let text = Zeroizing::new(encode(der, STANDARD, true));
    let mut out = Zeroizing::new(format!("-----BEGIN {label}-----\n"));
    for line in text.as_bytes().chunks(PEM_LINE) {
        out.push_str(&String::from_utf8_lossy(line));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

#[cfg(test)]
mod tests;
