use std::fs;

use super::*;
use crate::acme::tests::{Scratch, openssl};

#[test]
fn a_secret_number_is_in_range_from_1_to_the_order_minus_1() {
    let mut below = ORDER;
    below[31] -= 1;
    let mut one = [0u8; 32];
    one[31] = 1;
    assert!(in_range(&below));
    assert!(in_range(&one));
    assert!(!in_range(&[0u8; 32]));
    assert!(!in_range(&ORDER));
    assert!(!in_range(&[0xff; 32]));
}

#[test]
fn a_new_key_is_a_pkcs8_key_that_openssl_reads_and_that_loads_again_as_the_same_key() {
    let dir = Scratch::new();
    let (key, pem) = Key::generate().unwrap();
    fs::write(dir.join("k.pem"), pem.as_bytes()).unwrap();
    // openssl derives the same public key from the private key as the provider does.
    let public = openssl(
        dir.path(),
        &[
            "pkey", "-in", "k.pem", "-pubout", "-outform", "DER", "-out", "p.der",
        ],
    );
    assert!(public.is_empty());
    assert_eq!(fs::read(dir.join("p.der")).unwrap(), key.spki());
    let again = Key::from_pem(pem.as_bytes()).unwrap();
    assert_eq!((again.x(), again.y()), (key.x(), key.y()));
    // Two keys are two different keys.
    assert_ne!(Key::generate().unwrap().0.x(), key.x());
}

#[test]
fn only_one_key_on_the_curve_p256_is_taken_from_a_file() {
    let dir = Scratch::new();
    let run = |args: &[&str]| {
        openssl(dir.path(), args);
    };
    run(&[
        "genpkey",
        "-algorithm",
        "EC",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-out",
        "p256.pem",
    ]);
    run(&[
        "ecparam",
        "-name",
        "prime256v1",
        "-genkey",
        "-noout",
        "-out",
        "sec1.pem",
    ]);
    run(&[
        "genpkey",
        "-algorithm",
        "EC",
        "-pkeyopt",
        "ec_paramgen_curve:P-384",
        "-out",
        "p384.pem",
    ]);
    run(&[
        "genpkey",
        "-algorithm",
        "RSA",
        "-pkeyopt",
        "rsa_keygen_bits:2048",
        "-out",
        "rsa.pem",
    ]);
    let read = |name: &str| fs::read(dir.join(name)).unwrap();
    // An operator's key, in either form, is taken.
    assert!(Key::from_pem(&read("p256.pem")).is_ok());
    assert!(Key::from_pem(&read("sec1.pem")).is_ok());
    // Another curve, another algorithm, two keys, no key, a key that is cut.
    assert!(Key::from_pem(&read("p384.pem")).is_err());
    assert!(Key::from_pem(&read("rsa.pem")).is_err());
    let two = [read("p256.pem"), read("sec1.pem")].concat();
    assert!(Key::from_pem(&two).is_err());
    assert!(Key::from_pem(b"").is_err());
    let text = read("p256.pem");
    assert!(Key::from_pem(&text[..text.len() / 2]).is_err());
}
