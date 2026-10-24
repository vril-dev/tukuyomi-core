use std::fs;
use std::process::Command;

use super::*;
use crate::acme::tests::{Scratch, openssl};

/// The seconds since the epoch of a UTC date and time written `2026-11-23 12:00:00`, by the `date` command.
fn epoch(text: &str) -> i64 {
    let out = Command::new("date")
        .args(["-u", "-d", &format!("{text} UTC"), "+%s"])
        .output()
        .expect("run the date command");
    String::from_utf8(out.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

/// A self-signed certificate that is good for `days` days, in `dir` as `c.pem`; its DER, and the end of its time of
/// validity as `openssl` writes it.
fn certificate(dir: &Scratch, days: u32) -> (Vec<u8>, i64) {
    openssl(
        dir.path(),
        &[
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-keyout",
            "c.key",
            "-out",
            "c.pem",
            "-subj",
            "/CN=x",
            "-days",
            &days.to_string(),
        ],
    );
    openssl(
        dir.path(),
        &["x509", "-in", "c.pem", "-outform", "DER", "-out", "c.der"],
    );
    let end = openssl(
        dir.path(),
        &[
            "x509", "-in", "c.pem", "-noout", "-enddate", "-dateopt", "iso_8601",
        ],
    );
    let end = end
        .trim()
        .strip_prefix("notAfter=")
        .unwrap()
        .trim_end_matches('Z');
    (fs::read(dir.join("c.der")).unwrap(), epoch(end))
}

#[test]
fn the_end_of_the_time_of_validity_is_what_openssl_reads_in_both_forms_of_time() {
    // 30 days from now is written as a UTCTime, and 9000 days (to 2051) as a GeneralizedTime.
    for (days, tag) in [(30, UTC_TIME), (9000, GENERALIZED_TIME)] {
        let dir = Scratch::new();
        let (der, want) = certificate(&dir, days);
        assert!(
            der.windows(2)
                .any(|w| w[0] == tag && usize::from(w[1]) == if tag == UTC_TIME { 13 } else { 15 }),
            "the certificate has no time of the form under test"
        );
        assert_eq!(not_after(&der), Ok(want));
    }
}

#[test]
fn a_time_follows_the_rules_of_rfc_5280() {
    assert_eq!(
        time(UTC_TIME, b"500101000000Z"),
        Ok(epoch("1950-01-01 00:00:00"))
    );
    assert_eq!(
        time(UTC_TIME, b"491231235959Z"),
        Ok(epoch("2049-12-31 23:59:59"))
    );
    assert_eq!(
        time(GENERALIZED_TIME, b"20240229120000Z"),
        Ok(epoch("2024-02-29 12:00:00"))
    );
    for (tag, text) in [
        (UTC_TIME, &b"230229120000Z"[..]), // no 29th of February in 2023
        (GENERALIZED_TIME, b"21000229120000Z"), // 2100 is not a leap year
        (UTC_TIME, b"261301120000Z"),      // month 13
        (UTC_TIME, b"260100120000Z"),      // day 0
        (UTC_TIME, b"260101240000Z"),      // hour 24
        (UTC_TIME, b"260101126000Z"),      // minute 60
        (UTC_TIME, b"260101120060Z"),      // second 60
        (UTC_TIME, b"260101120000+0100"),  // not UTC
        (UTC_TIME, b"26010112000Z"),       // too short
        (GENERALIZED_TIME, b"20260101120000.5Z"), // fraction of a second
        (UTC_TIME, b"26010112000aZ"),      // not a digit
        (0x13, b"260101120000Z"),          // not a time
    ] {
        assert_eq!(
            time(tag, text),
            Err(Malformed),
            "{}",
            String::from_utf8_lossy(text)
        );
    }
}

/// Whether the first element of `bytes` cannot be read.
fn refused(bytes: &[u8]) -> bool {
    Reader::new(bytes).element().is_err()
}

#[test]
fn a_length_is_read_in_the_shortest_definite_form_and_nothing_else() {
    assert_eq!(
        Reader::new(&[0x04, 0x02, 1, 2]).element(),
        Ok((0x04, &[1u8, 2][..]))
    );
    for len in [0x80usize, 0x100] {
        let mut long = if len == 0x80 {
            vec![0x04, 0x81, 0x80]
        } else {
            vec![0x04, 0x82, 0x01, 0x00]
        };
        long.extend(vec![7u8; len]);
        assert_eq!(
            Reader::new(&long)
                .element()
                .map(|(tag, content)| (tag, content.len())),
            Ok((0x04, len))
        );
    }
    let long_form_of_a_short_length = [&[0x04, 0x81, 0x05][..], &[7u8; 5]].concat();
    let leading_zero = [&[0x04, 0x82, 0x00, 0x80][..], &[7u8; 128]].concat();
    let five_length_bytes = [&[0x04, 0x85, 0, 0, 0, 0, 1][..], &[7u8; 1]].concat();
    let beyond_the_end = [&[0x04, 0x81, 0x90][..], &[7u8; 100]].concat();
    for bytes in [
        &[][..],
        &[0x04],                   // no length
        &[0x04, 0x81],             // the length is cut off
        &[0x04, 0x82, 0x01],       // the length is cut off
        &[0x04, 0x02, 1],          // the content is short
        &[0x04, 0x80, 1, 2, 0, 0], // indefinite
        &[0x04, 0xff, 1],          // not a length
        &[0x1f, 0x01, 0x00],       // a tag of the long form
        &long_form_of_a_short_length,
        &leading_zero,
        &five_length_bytes,
        &beyond_the_end,
    ] {
        assert!(refused(bytes), "{bytes:02x?}");
    }
    // A certificate with bytes after it, and one that is cut, are not read.
    let dir = Scratch::new();
    let (mut der, _) = certificate(&dir, 30);
    assert!(not_after(&der[..der.len() - 1]).is_err());
    der.push(0);
    assert!(not_after(&der).is_err());
}

/// The two numbers of a signature as the DER of `SEQUENCE { INTEGER, INTEGER }`, each in its shortest form.
fn signature(r: &[u8], s: &[u8]) -> Vec<u8> {
    let integer = |digits: &[u8]| {
        let mut digits = digits.to_vec();
        if digits[0] & 0x80 != 0 {
            digits.insert(0, 0);
        }
        tlv(INTEGER, &digits)
    };
    tlv(SEQUENCE, &[integer(r), integer(s)].concat())
}

#[test]
fn the_numbers_of_a_signature_become_32_bytes_each_and_a_form_that_is_not_theirs_is_refused() {
    let mut r = [0x11u8; 32];
    r[0] = 0xf0; // the first bit is set, so the INTEGER has a zero byte in front
    let s = [0x22u8; 31]; // one byte short
    let fixed = ecdsa_fixed(&signature(&r, &s)).unwrap();
    assert_eq!(&fixed[..32], &r);
    assert_eq!(fixed[32], 0);
    assert_eq!(&fixed[33..], &s);
    // Negative; a zero in front where it is not needed; more than 32 bytes; nothing for s; a third number; bytes after.
    let negative = tlv(
        SEQUENCE,
        &[tlv(INTEGER, &[0x80]), tlv(INTEGER, &[1])].concat(),
    );
    let padded = tlv(
        SEQUENCE,
        &[tlv(INTEGER, &[0, 1]), tlv(INTEGER, &[1])].concat(),
    );
    let long = tlv(
        SEQUENCE,
        &[tlv(INTEGER, &[1; 33]), tlv(INTEGER, &[1])].concat(),
    );
    let lone = tlv(SEQUENCE, &tlv(INTEGER, &[1]));
    let three = tlv(
        SEQUENCE,
        &[tlv(INTEGER, &[1]), tlv(INTEGER, &[1]), tlv(INTEGER, &[1])].concat(),
    );
    let after = [signature(&r, &s), vec![0]].concat();
    for bad in [negative, padded, long, lone, three, after] {
        assert!(ecdsa_fixed(&bad).is_err(), "{bad:02x?}");
    }
}

#[test]
fn the_request_for_a_certificate_verifies_and_holds_the_hosts_as_alternative_names() {
    let dir = Scratch::new();
    let (key, _) = Key::generate().unwrap();
    let hosts = ["a.test".to_owned(), "b.example.test".to_owned()];
    fs::write(dir.join("r.der"), csr(&key, &hosts).unwrap()).unwrap();
    let text = openssl(
        dir.path(),
        &[
            "req", "-inform", "DER", "-in", "r.der", "-verify", "-noout", "-text",
        ],
    );
    assert!(
        text.contains("Subject: \n") || text.contains("Subject:\n"),
        "{text}"
    );
    assert!(text.contains("DNS:a.test, DNS:b.example.test"), "{text}");
    // The key in the request is the key that signed it.
    let want = openssl(
        dir.path(),
        &["req", "-inform", "DER", "-in", "r.der", "-noout", "-pubkey"],
    );
    let pem = base64::pem("PUBLIC KEY", &key.spki());
    assert_eq!(want, **pem);
    assert!(csr(&key, &[]).is_err());
}
