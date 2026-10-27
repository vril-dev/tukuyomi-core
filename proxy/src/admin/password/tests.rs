use super::*;

fn key(iterations: u32) -> String {
    hex(&derive(
        b"password",
        b"salt",
        NonZeroU32::new(iterations).unwrap(),
    ))
}

#[test]
fn pbkdf2_hmac_sha256_gives_the_published_keys() {
    // The inputs of RFC 6070 ("password", "salt") with SHA-256 as the function, for 1 and 4096 iterations.
    assert_eq!(
        key(1),
        "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
    );
    assert_eq!(
        key(4096),
        "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
    );
}

#[test]
fn a_hash_takes_its_password_only_and_keeps_its_iterations() {
    let hash = Hash::new("correct horse battery", 1000).unwrap();
    assert!(hash.verify("correct horse battery"));
    assert!(!hash.verify("correct horse batterz"));
    assert!(!hash.verify(""));
    assert_eq!(hash.iterations(), 1000);
    let again = Hash::from_parts(hash.iterations(), *hash.salt(), *hash.hash()).unwrap();
    assert_eq!(again, hash);
    // The iterations are 1 to the limit, for a new hash and for a stored one.
    assert!(Hash::new("x", 0).is_none());
    assert!(Hash::new("x", MAX_ITERATIONS + 1).is_none());
    assert!(Hash::from_parts(MAX_ITERATIONS + 1, [0; SALT_LEN], [0; HASH_LEN]).is_none());
    // Two hashes of one password have two salts.
    let other = Hash::new("correct horse battery", 1000).unwrap();
    assert_ne!(other.salt(), hash.salt());
}

#[test]
fn names_and_passwords_are_taken_at_their_limits_and_not_past_them() {
    assert!(valid_name("a") && valid_name(&"a".repeat(32)) && valid_name("a.b_c-9"));
    for bad in ["", "A", "a b", "a/b", "a\u{e9}"] {
        assert!(!valid_name(bad), "{bad:?}");
    }
    assert!(!valid_name(&"a".repeat(33)));
    assert!(valid_password(&"p".repeat(12)) && valid_password(&"p".repeat(128)));
    assert!(!valid_password(&"p".repeat(11)) && !valid_password(&"p".repeat(129)));
    // The limits are in bytes: four characters of three bytes are 12 bytes, three are 9.
    assert!(valid_password("\u{3042}\u{3044}\u{3046}\u{3048}"));
    assert!(!valid_password("\u{3042}\u{3044}\u{3046}"));
}

#[test]
fn hexadecimal_is_read_back_and_only_in_lowercase_and_the_right_size() {
    let bytes = [0x00, 0x0f, 0xa5, 0xff];
    assert_eq!(hex(&bytes), "000fa5ff");
    assert_eq!(unhex::<4>("000fa5ff"), Some(bytes));
    assert_eq!(unhex::<4>("000FA5FF"), None);
    assert_eq!(unhex::<4>("000fa5"), None);
    assert_eq!(unhex::<4>("000fa5fg"), None);
}
