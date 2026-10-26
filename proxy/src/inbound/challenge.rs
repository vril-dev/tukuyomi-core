//! The answer to the challenge of the CA that issues the certificates with `acme` (HTTP-01, RFC 8555 section 8.3).
//!
//! The CA asks for `/.well-known/acme-challenge/<token>` over plain HTTP, with the name it has to prove as the `Host`,
//! and expects the file `<token>` of `challenge_dir` as the body: the command `acme renew` puts it there while an order
//! waits. A plain listener and a listener that redirects answer such a request before anything else is done with it,
//! so before the route, the access lists, the inspection, the forwarding and the redirect. A listener that ends TLS
//! never does: the challenge is not asked for there.
//!
//! A request is a challenge when its method is `GET` or `HEAD`, its target is the path above and a token of 1 to 128
//! letters, digits, `-` and `_` and nothing after it (no query, no escape, no further `/`), and its `Host` names one
//! of the hosts of the certificates with `acme` (the same comparison as the one for the hosts of a certificate: case
//! ignored, a port and a trailing dot left out). The answer is the content of the file, with `200` and
//! `Content-Type: text/plain`, if it is a regular file of at most 1 KiB, else `404`. A link is never followed: the
//! command writes regular files, and a link in the directory could point at any file. The token can name no other
//! file than one in `challenge_dir`, and nothing else is looked at.

use std::path::PathBuf;

use crate::config::{AcmeConfig, ListenerConfig, ListenerKind};
use crate::inbound::head::Head;
use crate::inbound::transport::tls::host_name;
use crate::rules::file_store::read_regular;

/// The path in front of the token.
const PATH: &[u8] = b"/.well-known/acme-challenge/";
/// The longest token in bytes.
const MAX_TOKEN: usize = 128;
/// The longest file that is answered with, in bytes: a token, a `.` and the 43 characters of a thumbprint fit.
const MAX_PROOF: u64 = 1024;

/// Where the files of the challenges are, and the hosts they are answered for.
pub struct Challenge {
    dir: PathBuf,
    hosts: Vec<String>,
}

/// What a challenge request is answered with.
pub(super) enum Proof {
    /// The content of the file.
    Found(Vec<u8>),
    /// There is no usable file.
    Missing,
}

/// Whether `bytes` is a token: 1 to 128 of `A-Z a-z 0-9 - _`. The command `acme renew` holds the tokens of the CA to the
/// same rule before it makes a file name of one.
pub fn is_token(bytes: &[u8]) -> bool {
    (1..=MAX_TOKEN).contains(&bytes.len())
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
}

impl Challenge {
    /// The challenge for the hosts of the certificates with `acme` among those of `listeners`; none if the
    /// configuration has no `acme`.
    pub fn new(acme: Option<&AcmeConfig>, listeners: &[ListenerConfig]) -> Option<Challenge> {
        let acme = acme?;
        let hosts = listeners
            .iter()
            .filter_map(|listener| match &listener.kind {
                ListenerKind::Tls(tls) => Some(&tls.certificates),
                _ => None,
            })
            .flatten()
            .filter(|certificate| certificate.acme.is_some())
            .flat_map(|certificate| certificate.hosts.iter().cloned())
            .collect();
        Some(Challenge {
            dir: acme.challenge_dir.clone(),
            hosts,
        })
    }

    /// The answer to the request with `head` if it is a challenge, else `None`. The file is read here, and a read
    /// is a few bytes of one file.
    pub(super) fn proof(&self, head: &Head) -> Option<Proof> {
        if head.method() != b"GET" && head.method() != b"HEAD" {
            return None;
        }
        let token = head.target().strip_prefix(PATH)?;
        if !is_token(token) {
            return None;
        }
        let name = host_name(head.host())?;
        if !self.hosts.contains(&name) {
            return None;
        }
        let token = std::str::from_utf8(token).ok()?;
        Some(match read_regular(&self.dir.join(token), MAX_PROOF, None) {
            Ok(bytes) => Proof::Found(bytes),
            Err(_) => Proof::Missing,
        })
    }
}

/// The whole `200` answer of a listener that writes its answers to the socket itself, as the one that redirects does:
/// without the body for a `HEAD`, and with the number `id` of the request.
pub(super) fn found(body: &[u8], head_only: bool, id: &str) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nX-Request-ID: {id}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    if !head_only {
        out.extend_from_slice(body);
    }
    out
}

#[cfg(test)]
pub(in crate::inbound) mod tests;
