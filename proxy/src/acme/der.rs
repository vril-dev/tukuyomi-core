//! The few encodings of X.509 that the command needs, written and read by hand.
//!
//! The writer makes the request for a certificate (PKCS #10, RFC 2986): an empty subject, the hosts as the names
//! of the alternative-name extension, signed with the key of the certificate. The reader is strict: it takes a
//! definite length in the shortest form only (the short form below 128, else the long form of 1 to 4 bytes without a
//! leading zero), refuses the indefinite length, a length that goes past the end of what holds the element, a tag
//! of the long form, and bytes left over where nothing may follow. It reads the end of the time of validity of a
//! certificate (`not_after`, in seconds since the epoch) and the two numbers of an ECDSA signature (`ecdsa_fixed`).

use super::Failure;
use super::base64;
use super::key::Key;

const INTEGER: u8 = 0x02;
const BIT_STRING: u8 = 0x03;
const OCTET_STRING: u8 = 0x04;
const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;
/// `[0]`, constructed: the version of a certificate, the attributes of a request.
const CONTEXT_0: u8 = 0xa0;
/// `[2]`, primitive: a `dNSName` of a general name.
const DNS_NAME: u8 = 0x82;

/// The object identifiers of the request, with their tag and length: `ecdsa-with-SHA256`, `extensionRequest`,
/// `subjectAltName`.
const ECDSA_WITH_SHA256: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const EXTENSION_REQUEST: [u8; 11] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e,
];
const SUBJECT_ALT_NAME: [u8; 5] = [0x06, 0x03, 0x55, 0x1d, 0x11];

/// What cannot be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Malformed;

/// `content` with its tag and its length in the shortest form.
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    match u8::try_from(content.len()) {
        Ok(short) if short < 0x80 => out.push(short),
        _ => {
            let bytes = content.len().to_be_bytes();
            let digits = &bytes[bytes.iter().take_while(|b| **b == 0).count()..];
            out.push(0x80 | u8::try_from(digits.len()).unwrap_or(0));
            out.extend_from_slice(digits);
        }
    }
    out.extend_from_slice(content);
    out
}

fn sequence(parts: &[&[u8]]) -> Vec<u8> {
    tlv(SEQUENCE, &parts.concat())
}

/// The request for a certificate for `hosts`, signed by `key`. The hosts are the lowercase names that the
/// configuration allows, so each is a valid `IA5String`.
pub fn csr(key: &Key, hosts: &[String]) -> Result<Vec<u8>, Failure> {
    if hosts.is_empty() || !hosts.iter().all(|host| host.is_ascii()) {
        return Err("a certificate request needs hosts that are ASCII".into());
    }
    let names: Vec<u8> = hosts
        .iter()
        .flat_map(|host| tlv(DNS_NAME, host.as_bytes()))
        .collect();
    let extension = sequence(&[
        &SUBJECT_ALT_NAME,
        &tlv(OCTET_STRING, &tlv(SEQUENCE, &names)),
    ]);
    let attribute = sequence(&[&EXTENSION_REQUEST, &tlv(SET, &sequence(&[&extension]))]);
    let info = sequence(&[
        &tlv(INTEGER, &[0]),
        &tlv(SEQUENCE, &[]),
        &key.spki(),
        &tlv(CONTEXT_0, &attribute),
    ]);
    let signature = key.sign_der(&info)?;
    let signature = tlv(BIT_STRING, &[&[0u8][..], &signature].concat());
    Ok(sequence(&[
        &info,
        &tlv(SEQUENCE, &ECDSA_WITH_SHA256[..]),
        &signature,
    ]))
}

/// The request as the text that the CA is sent: URL-safe base64 without padding.
pub fn csr_text(key: &Key, hosts: &[String]) -> Result<String, Failure> {
    Ok(base64::url(&csr(key, hosts)?))
}

/// The elements of a DER string, one after the other.
pub struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Reader<'a> {
        Reader { rest: bytes }
    }

    pub fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    /// The tag and the content of the next element.
    pub fn element(&mut self) -> Result<(u8, &'a [u8]), Malformed> {
        let (&tag, rest) = self.rest.split_first().ok_or(Malformed)?;
        if tag & 0x1f == 0x1f {
            return Err(Malformed);
        }
        let (&first, rest) = rest.split_first().ok_or(Malformed)?;
        let (len, rest) = if first < 0x80 {
            (usize::from(first), rest)
        } else {
            // 0x80 is the indefinite length, and 0xff is not a length.
            let count = usize::from(first & 0x7f);
            if count == 0 || count > 4 || rest.len() < count {
                return Err(Malformed);
            }
            let (digits, rest) = rest.split_at(count);
            let len = digits
                .iter()
                .fold(0usize, |len, &digit| (len << 8) | usize::from(digit));
            // The shortest form: no leading zero, and not a length that the short form holds.
            if digits[0] == 0 || len < 0x80 {
                return Err(Malformed);
            }
            (len, rest)
        };
        if len > rest.len() {
            return Err(Malformed);
        }
        let (content, rest) = rest.split_at(len);
        self.rest = rest;
        Ok((tag, content))
    }

    /// The content of the next element, which has to have `tag`.
    pub fn expect(&mut self, tag: u8) -> Result<&'a [u8], Malformed> {
        match self.element()? {
            (found, content) if found == tag => Ok(content),
            _ => Err(Malformed),
        }
    }
}

/// The content of the one element of `bytes`, which has `tag` and has nothing after it.
fn only(bytes: &[u8], tag: u8) -> Result<&[u8], Malformed> {
    let mut reader = Reader::new(bytes);
    let content = reader.expect(tag)?;
    if reader.is_empty() {
        Ok(content)
    } else {
        Err(Malformed)
    }
}

/// The end of the time of validity of the certificate `cert`, in seconds since 1970-01-01 00:00:00 UTC.
pub fn not_after(cert: &[u8]) -> Result<i64, Malformed> {
    let mut certificate = Reader::new(only(cert, SEQUENCE)?);
    let mut tbs = Reader::new(certificate.expect(SEQUENCE)?);
    // The version, which is there for all but the oldest form, then the serial number.
    let (mut tag, _) = tbs.element()?;
    if tag == CONTEXT_0 {
        tag = tbs.element()?.0;
    }
    if tag != INTEGER {
        return Err(Malformed);
    }
    tbs.expect(SEQUENCE)?; // the algorithm of the signature
    tbs.expect(SEQUENCE)?; // the issuer
    let mut validity = Reader::new(tbs.expect(SEQUENCE)?);
    let (before, _) = validity.element()?;
    if before != UTC_TIME && before != GENERALIZED_TIME {
        return Err(Malformed);
    }
    let (tag, text) = validity.element()?;
    if !validity.is_empty() {
        return Err(Malformed);
    }
    time(tag, text)
}

/// A number of ASCII digits.
fn digits(text: &[u8]) -> Option<i64> {
    text.iter().try_fold(0i64, |number, &byte| {
        byte.is_ascii_digit()
            .then(|| number * 10 + i64::from(byte - b'0'))
    })
}

/// A time of a certificate as seconds since the epoch: `UTCTime` (`YYMMDDHHMMSSZ`, from 1950 to 2049) or
/// `GeneralizedTime` (`YYYYMMDDHHMMSSZ`), in UTC, with whole seconds, as RFC 5280 has them.
fn time(tag: u8, text: &[u8]) -> Result<i64, Malformed> {
    let (year, rest) = match (tag, text.len()) {
        (UTC_TIME, 13) => {
            let year = digits(&text[..2]).ok_or(Malformed)?;
            (
                if year >= 50 { 1900 + year } else { 2000 + year },
                &text[2..],
            )
        }
        (GENERALIZED_TIME, 15) => (digits(&text[..4]).ok_or(Malformed)?, &text[4..]),
        _ => return Err(Malformed),
    };
    let (rest, zulu) = rest.split_at(10);
    if zulu != b"Z" {
        return Err(Malformed);
    }
    let field = |at: usize| digits(&rest[at..at + 2]).ok_or(Malformed);
    let (month, day, hour, minute, second) =
        (field(0)?, field(2)?, field(4)?, field(6)?, field(8)?);
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return Err(Malformed),
    };
    if !(1..=in_month).contains(&day) || hour > 23 || minute > 59 || second > 59 {
        return Err(Malformed);
    }
    Ok(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second)
}

/// The days from 1970-01-01 to the date (proleptic Gregorian calendar).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// One number of a signature as 32 bytes: positive, in the shortest form, at most 32 bytes without its sign byte.
fn scalar(integer: &[u8]) -> Result<[u8; 32], Malformed> {
    let (&first, _) = integer.split_first().ok_or(Malformed)?;
    if first & 0x80 != 0 {
        return Err(Malformed);
    }
    let digits = if first == 0 {
        // A zero byte in front is there only to keep the number positive.
        match integer.get(1) {
            Some(next) if next & 0x80 != 0 => &integer[1..],
            _ => return Err(Malformed),
        }
    } else {
        integer
    };
    if digits.len() > 32 {
        return Err(Malformed);
    }
    let mut out = [0u8; 32];
    out[32 - digits.len()..].copy_from_slice(digits);
    Ok(out)
}

/// The signature `SEQUENCE { r INTEGER, s INTEGER }` of ECDSA on P-256 as the 64 bytes `r` and `s` that JWS wants.
pub fn ecdsa_fixed(signature: &[u8]) -> Result<[u8; 64], Malformed> {
    let mut numbers = Reader::new(only(signature, SEQUENCE)?);
    let r = scalar(numbers.expect(INTEGER)?)?;
    let s = scalar(numbers.expect(INTEGER)?)?;
    if !numbers.is_empty() {
        return Err(Malformed);
    }
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&r);
    out[32..].copy_from_slice(&s);
    Ok(out)
}

#[cfg(test)]
mod tests;
