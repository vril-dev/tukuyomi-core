//! The signed messages of ACME (RFC 8555 section 6.2): the flattened JSON form of a JWS with the algorithm ES256
//! (RFC 7515, 7518), and the key authorization of a challenge.
//!
//! A message holds the protected header (`alg`, `nonce`, `url` and either `jwk` or `kid`), the payload and the
//! signature, each as base64 in the URL-safe alphabet without padding. The signature is over `protected "." payload`.
//! The message that makes the account holds the key as a JWK; all others name the account by its URL. A payload of
//! nothing (the empty string, not an encoded empty object) is a request for a resource: POST-as-GET.
//! The thumbprint of the key (RFC 7638) is the SHA-256 of its JWK with the members in order and no blanks; the
//! key authorization that a challenge is answered with is the token, a `.`, and the thumbprint.

use serde_json::json;
use sha2::{Digest, Sha256};

use super::key::Key;
use super::{Failure, base64};

/// How a message names its signer.
#[derive(Clone, Copy, Debug)]
pub enum Signer<'a> {
    /// The key itself: only the message that makes the account.
    Jwk,
    /// The URL of the account.
    Kid(&'a str),
}

/// The JWK of a key with the coordinates `x` and `y`, in the order that the thumbprint is made of.
fn jwk_text(x: &[u8], y: &[u8]) -> String {
    format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        base64::url(x),
        base64::url(y)
    )
}

/// The thumbprint of a key with the coordinates `x` and `y`.
pub fn thumbprint_of(x: &[u8], y: &[u8]) -> String {
    base64::url(&Sha256::digest(jwk_text(x, y).as_bytes()))
}

/// The key authorization for `token`: the content of the file that the CA asks for.
pub fn key_authorization(token: &str, key: &Key) -> String {
    format!("{token}.{}", thumbprint_of(key.x(), key.y()))
}

/// A message signed by `key`, as the body of a POST. `url` is the URL of the request, as the CA gave it.
pub fn sign(
    key: &Key,
    signer: Signer<'_>,
    nonce: &str,
    url: &str,
    payload: &[u8],
) -> Result<String, Failure> {
    let header = match signer {
        Signer::Jwk => json!({
            "alg": "ES256",
            "jwk": {
                "crv": "P-256",
                "kty": "EC",
                "x": base64::url(key.x()),
                "y": base64::url(key.y()),
            },
            "nonce": nonce,
            "url": url,
        }),
        Signer::Kid(kid) => json!({"alg": "ES256", "kid": kid, "nonce": nonce, "url": url}),
    };
    let protected = base64::url(header.to_string().as_bytes());
    let payload = base64::url(payload);
    let signature = key.sign_fixed(format!("{protected}.{payload}").as_bytes())?;
    Ok(json!({
        "protected": protected,
        "payload": payload,
        "signature": base64::url(&signature),
    })
    .to_string())
}

#[cfg(test)]
mod tests;
