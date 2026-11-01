use std::fs;

use super::*;

#[test]
fn the_bundle_of_the_system_gives_authorities() {
    let path = bundle().expect("the system has a bundle of authorities");
    let roots = roots_from(&path).unwrap();
    assert!(!roots.is_empty());
    assert!(connector().is_ok());
}

#[test]
fn a_file_without_a_usable_certificate_is_an_error() {
    let dir = std::env::temp_dir().join(format!("tukuyomi-ship-tls-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir(&dir).unwrap();
    for (name, bytes) in [
        ("empty", &b""[..]),
        ("text", &b"not a certificate\n"[..]),
        (
            "broken",
            &b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"[..],
        ),
    ] {
        let path = dir.join(name);
        fs::write(&path, bytes).unwrap();
        assert_eq!(roots_from(&path).unwrap_err(), Error::new(ROOTS), "{name}");
    }
    assert_eq!(roots_from(&dir).unwrap_err(), Error::new(ROOTS));
    assert_eq!(
        roots_from(&dir.join("none")).unwrap_err(),
        Error::new(ROOTS)
    );
    fs::remove_dir_all(&dir).unwrap();
}
