//! Base64 (RFC 4648): the URL-safe alphabet without padding, which the JWS and the request for a certificate use, and
//! the standard one with padding, which PEM uses and the files uploaded to the admin API are coded in.

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

/// The value of a character of the standard alphabet.
fn sextet(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// The bytes that `text` stands for in the standard alphabet with padding. None when `text` is not exactly that form:
/// a length that is not a multiple of 4, a character outside the alphabet, padding (one or two `=`) anywhere but at
/// the end, or unused bits of the last character that are not zero, so that each value has one text.
pub fn decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(4) {
        return None;
    }
    let groups = text.len() / 4;
    let mut out = Vec::with_capacity(groups * 3);
    for (at, group) in text.as_bytes().chunks_exact(4).enumerate() {
        let pad = if at + 1 == groups {
            group.iter().rev().take_while(|&&c| c == b'=').count()
        } else {
            0
        };
        if pad > 2 {
            return None;
        }
        let mut bits = 0u32;
        for &c in &group[..4 - pad] {
            bits = bits << 6 | u32::from(sextet(c)?);
        }
        bits <<= 6 * pad;
        // Eight unused bits for each byte that the padding takes.
        if bits & ((1 << (8 * pad)) - 1) != 0 {
            return None;
        }
        out.extend_from_slice(&bits.to_be_bytes()[1..4 - pad]);
    }
    Some(out)
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
