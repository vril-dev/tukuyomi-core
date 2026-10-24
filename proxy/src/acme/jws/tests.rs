use rustls::SignatureScheme;
use rustls::crypto::aws_lc_rs::default_provider;

use serde_json::Value;

use super::*;
use crate::acme::tests::unurl;

/// The DER of a signature of 64 bytes, for the verifier of the provider.
fn der_of(fixed: &[u8]) -> Vec<u8> {
    let integer = |digits: &[u8]| {
        let mut digits = digits.to_vec();
        while digits.len() > 1 && digits[0] == 0 {
            digits.remove(0);
        }
        if digits[0] & 0x80 != 0 {
            digits.insert(0, 0);
        }
        [&[0x02, u8::try_from(digits.len()).unwrap()][..], &digits].concat()
    };
    let body = [integer(&fixed[..32]), integer(&fixed[32..])].concat();
    [&[0x30, u8::try_from(body.len()).unwrap()][..], &body].concat()
}

/// Whether `signature` (r and s) is a signature of `message` by the key with the public point `point`.
fn verifies(point: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let provider = default_provider();
    let (_, algorithms) = provider
        .signature_verification_algorithms
        .mapping
        .iter()
        .find(|(scheme, _)| *scheme == SignatureScheme::ECDSA_NISTP256_SHA256)
        .unwrap();
    let der = der_of(signature);
    algorithms
        .iter()
        .any(|algorithm| algorithm.verify_signature(point, message, &der).is_ok())
}

fn parts(message: &str) -> (Value, String, Vec<u8>, String) {
    let message: Value = serde_json::from_str(message).unwrap();
    let get = |name: &str| message[name].as_str().unwrap().to_owned();
    let (protected, payload, signature) = (get("protected"), get("payload"), get("signature"));
    let header = serde_json::from_slice(&unurl(&protected)).unwrap();
    let input = format!("{protected}.{payload}");
    (header, payload, unurl(&signature), input)
}

#[test]
fn a_message_is_signed_over_its_header_and_payload_and_has_the_members_of_its_signer() {
    let (key, _) = Key::generate().unwrap();
    let point = [&[4u8][..], key.x(), key.y()].concat();
    let (x, y) = (base64::url(key.x()), base64::url(key.y()));

    let message = sign(
        &key,
        Signer::Jwk,
        "nonce-1",
        "https://ca.example/new-account",
        b"{\"a\":1}",
    )
    .unwrap();
    let (header, payload, signature, input) = parts(&message);
    assert_eq!(
        header,
        serde_json::json!({
            "alg": "ES256",
            "jwk": {"crv": "P-256", "kty": "EC", "x": x, "y": y},
            "nonce": "nonce-1",
            "url": "https://ca.example/new-account",
        })
    );
    assert_eq!(unurl(&payload), b"{\"a\":1}");
    assert_eq!(signature.len(), 64);
    assert!(verifies(&point, input.as_bytes(), &signature));
    // A change of one byte of what was signed is caught.
    assert!(!verifies(
        &point,
        input.replacen('.', "-", 1).as_bytes(),
        &signature
    ));

    // With the account named by its URL, there is no key in the header; a request for a resource has an empty payload.
    let message = sign(
        &key,
        Signer::Kid("https://ca.example/acct/1"),
        "nonce-2",
        "https://ca.example/o/1",
        b"",
    )
    .unwrap();
    let (header, payload, signature, input) = parts(&message);
    assert_eq!(
        header,
        serde_json::json!({
            "alg": "ES256",
            "kid": "https://ca.example/acct/1",
            "nonce": "nonce-2",
            "url": "https://ca.example/o/1",
        })
    );
    assert_eq!(payload, "");
    assert!(input.ends_with('.'));
    assert!(verifies(&point, input.as_bytes(), &signature));
}

#[test]
fn the_thumbprint_and_the_key_authorization_of_a_fixed_key_are_the_ones_computed_without_this_code()
{
    // The coordinates are the bytes 0 to 31 and 32 to 63 (not a point of the curve, which the hash does not need). The
    // expected text is the SHA-256 of `{"crv":"P-256","kty":"EC","x":"AAEC..","y":"ICEi.."}` in base64url, made with
    // another implementation.
    let x: Vec<u8> = (0..32).collect();
    let y: Vec<u8> = (32..64).collect();
    assert_eq!(
        jwk_text(&x, &y),
        r#"{"crv":"P-256","kty":"EC","x":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","y":"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8"}"#
    );
    assert_eq!(
        thumbprint_of(&x, &y),
        "0r62zgBj277RicA3LnaBKQ5_9RCDIomrlbpWjO0QTG0"
    );
    let (key, _) = Key::generate().unwrap();
    assert_eq!(
        key_authorization("tok-1", &key),
        format!("tok-1.{}", thumbprint_of(key.x(), key.y()))
    );
}
