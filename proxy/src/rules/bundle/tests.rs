use super::*;

const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn read(text: &str) -> Option<Fingerprint> {
    Fingerprint::from_hex(text.as_bytes())
}

#[test]
fn exactly_64_lowercase_hex_digits_are_a_fingerprint() {
    let fingerprint = read(HEX).unwrap();
    assert_eq!(fingerprint.bytes()[..2], [0x01, 0x23]);
    assert_eq!(fingerprint.bytes()[30..], [0xcd, 0xef]);
}

#[test]
fn any_other_text_is_not_a_fingerprint() {
    assert_eq!(read(&HEX[..63]), None);
    assert_eq!(read(&HEX.to_uppercase()), None);
    assert_eq!(read(&format!("{}g", &HEX[..63])), None);
}

#[test]
fn hex_gives_back_the_digits_that_were_read() {
    assert_eq!(read(HEX).unwrap().hex(), HEX);
}
