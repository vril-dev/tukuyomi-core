use super::*;

#[test]
fn the_url_form_is_the_one_of_rfc_4648_without_padding_and_with_its_own_signs() {
    for (plain, coded) in [
        ("", ""),
        ("f", "Zg"),
        ("fo", "Zm8"),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg"),
        ("fooba", "Zm9vYmE"),
        ("foobar", "Zm9vYmFy"),
    ] {
        assert_eq!(url(plain.as_bytes()), coded);
    }
    // 0xfb 0xff is `+/8=` in the standard alphabet.
    assert_eq!(url(&[0xfb, 0xff]), "-_8");
}

#[test]
fn a_pem_object_has_padding_and_lines_of_64_characters() {
    let text = pem("TEST", &[0xfb, 0xff, 0xfe]);
    assert_eq!(&**text, "-----BEGIN TEST-----\n+//+\n-----END TEST-----\n");
    let long = pem("TEST", &[7u8; 100]);
    let lines: Vec<&str> = long.lines().collect();
    // 100 bytes are 136 characters with padding: two lines of 64 and one of 8.
    assert_eq!(lines.len(), 5);
    assert_eq!(lines[1].len(), 64);
    assert_eq!(lines[2].len(), 64);
    assert_eq!(lines[3], "BwcHBw==");
    assert!(long.ends_with("-----END TEST-----\n"));
}
