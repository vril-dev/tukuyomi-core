use super::*;

/// The seed of the test values of RFC 6238, appendix B (SHA-1): the ASCII text `12345678901234567890`.
fn rfc_seed() -> Seed {
    Seed::from_bytes(*b"12345678901234567890")
}

#[test]
fn the_codes_of_the_test_values_of_rfc_6238_are_made() {
    // The 8-digit values of the RFC end in these 6 digits.
    for (time, want) in [
        (59, 287_082),
        (1_111_111_109, 81_804),
        (1_234_567_890, 5_924),
        (2_000_000_000, 279_037),
    ] {
        assert_eq!(code(&rfc_seed(), time / STEP_SECS), want, "T = {time}");
    }
}

#[test]
fn a_step_is_taken_once_one_step_either_side_is_taken_and_two_steps_are_not() {
    let seed = rfc_seed();
    let now = 1_234_567_890;
    let step = now / STEP_SECS;
    let text = |step: u64| format!("{:06}", code(&seed, step));
    assert_eq!(check(&seed, 0, &text(step), now), Some(step));
    assert_eq!(check(&seed, 0, &text(step - 1), now), Some(step - 1));
    assert_eq!(check(&seed, 0, &text(step + 1), now), Some(step + 1));
    assert_eq!(check(&seed, 0, &text(step - 2), now), None);
    assert_eq!(check(&seed, 0, &text(step + 2), now), None);
    // The same step twice is refused, and so is an earlier one; a later one is taken.
    assert_eq!(check(&seed, step, &text(step), now), None);
    assert_eq!(check(&seed, step, &text(step - 1), now), None);
    assert_eq!(check(&seed, step, &text(step + 1), now), Some(step + 1));
    // What is not 6 digits is not a code.
    for bad in ["", "12345", "1234567", "12345a", " 12345", "+12345"] {
        assert_eq!(check(&seed, 0, bad, now), None, "{bad:?}");
    }
}

#[test]
fn the_seed_is_given_as_base32_and_as_an_address() {
    // The test values of RFC 4648, section 10, without padding.
    for (text, want) in [
        ("", ""),
        ("f", "MY"),
        ("fo", "MZXQ"),
        ("foo", "MZXW6"),
        ("foob", "MZXW6YQ"),
        ("fooba", "MZXW6YTB"),
        ("foobar", "MZXW6YTBOI"),
    ] {
        assert_eq!(base32(text.as_bytes()), want, "{text:?}");
    }
    let address = uri("ann.lee", &rfc_seed());
    assert_eq!(
        address,
        "otpauth://totp/tukuyomi-core:ann.lee?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\
         &issuer=tukuyomi-core&algorithm=SHA1&digits=6&period=30"
    );
    // A character outside the plain ones is escaped.
    assert!(uri("a b", &rfc_seed()).contains(":a%20b?"));
}

#[test]
fn recovery_codes_are_ten_different_codes_and_each_is_found_by_its_hash_only() {
    let codes = recovery_codes().unwrap();
    assert_eq!(codes.len(), RECOVERY_CODES);
    for code in &codes {
        assert_eq!(code.len(), RECOVERY_CHARS, "{code}");
        assert!(code.bytes().all(|b| BASE32.contains(&b)), "{code}");
    }
    let mut sorted = codes.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), RECOVERY_CODES);
    let hashes: Vec<[u8; 32]> = codes.iter().map(|code| recovery_hash(code)).collect();
    for (at, code) in codes.iter().enumerate() {
        assert_eq!(recovery_match(&hashes, code), Some(at));
    }
    // A code of the right form that is not among them, one that is not of the form, and no hash at all.
    assert_eq!(recovery_match(&hashes, "AAAAAAAAAAAAAAAA"), None);
    assert_eq!(recovery_match(&hashes, &codes[0].to_lowercase()), None);
    assert_eq!(recovery_match(&hashes, &codes[0][1..]), None);
    assert_eq!(recovery_match(&[], &codes[0]), None);
}
