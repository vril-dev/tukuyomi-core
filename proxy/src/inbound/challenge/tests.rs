use std::fs::{self, DirBuilder};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use super::*;
use crate::config::{CertificateAcme, CertificateConfig, MinVersion, TlsConfig};
use crate::inbound::head::{Limits, parse};

static NEXT: AtomicU32 = AtomicU32::new(0);

/// A directory of a test, removed when it is dropped.
pub(in crate::inbound) struct Dir(pub(in crate::inbound) PathBuf);

impl Dir {
    pub(in crate::inbound) fn new() -> Dir {
        let dir = std::env::temp_dir().join(format!(
            "tukuyomi-challenge-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        DirBuilder::new().mode(0o700).create(&dir).unwrap();
        Dir(dir)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(in crate::inbound) fn head(request: &str) -> Head {
    let limits = Limits {
        max_head_bytes: 8192,
        max_body: 1024,
    };
    parse(request.as_bytes(), &limits).unwrap().unwrap()
}

fn request(method: &str, target: &str, host: &str) -> Head {
    head(&format!(
        "{method} {target} HTTP/1.1\r\nHost: {host}\r\n\r\n"
    ))
}

fn challenge(dir: &Path) -> Challenge {
    Challenge {
        dir: dir.to_path_buf(),
        hosts: vec!["a.test".to_owned()],
    }
}

fn content(proof: Option<Proof>) -> Option<Vec<u8>> {
    match proof {
        Some(Proof::Found(bytes)) => Some(bytes),
        _ => None,
    }
}

#[test]
fn a_token_is_1_to_128_letters_digits_hyphens_and_underscores() {
    assert!(is_token(b"a"));
    assert!(is_token(b"Tok_-9Zz"));
    assert!(is_token("a".repeat(128).as_bytes()));
    for bad in [
        "", "..", ".", "a/b", "a.b", "a b", "a%2e", "a?b", "a\u{e9}", "a\0",
    ] {
        assert!(!is_token(bad.as_bytes()), "{bad:?}");
    }
    assert!(!is_token("a".repeat(129).as_bytes()));
}

#[test]
fn a_token_file_is_answered_for_get_and_head_and_a_host_of_an_acme_certificate_and_for_nothing_else()
 {
    let dir = Dir::new();
    let longest = "a".repeat(128);
    for name in ["Tok_-1", longest.as_str(), &"b".repeat(129), "x.y"] {
        fs::write(dir.0.join(name), b"abc.def").unwrap();
    }
    let challenge = challenge(&dir.0);
    let path = "/.well-known/acme-challenge/";
    let answered = |method: &str, target: &str, host: &str| {
        content(challenge.proof(&request(method, target, host)))
    };
    // The token at its longest, in either method, with the host in another case, with a port, and with a dot after it.
    for host in ["a.test", "A.Test", "a.test:80", "a.test.", "A.TEST.:8080"] {
        assert_eq!(
            answered("GET", &format!("{path}Tok_-1"), host).as_deref(),
            Some(&b"abc.def"[..]),
            "{host}"
        );
    }
    assert!(answered("HEAD", &format!("{path}Tok_-1"), "a.test").is_some());
    assert!(answered("GET", &format!("{path}{longest}"), "a.test").is_some());
    // The same files are not answered when the request is not exactly for a token of a host of the certificates.
    for (method, target, host) in [
        ("GET", format!("{path}.."), "a.test"),
        ("GET", format!("{path}../Tok_-1"), "a.test"),
        ("GET", format!("{path}x.y"), "a.test"),
        ("GET", format!("{path}%54ok_-1"), "a.test"),
        ("GET", format!("{path}%2e%2e"), "a.test"),
        ("GET", format!("{path}Tok_-1/"), "a.test"),
        ("GET", format!("{path}Tok_-1/x"), "a.test"),
        ("GET", format!("{path}Tok_-1?x=1"), "a.test"),
        ("GET", format!("{path}{}", "b".repeat(129)), "a.test"),
        ("GET", path.to_owned(), "a.test"),
        ("GET", "/.well-known/acme-challenge".to_owned(), "a.test"),
        ("GET", format!("/x{path}Tok_-1"), "a.test"),
        ("GET", format!("//{path}Tok_-1"), "a.test"),
        ("POST", format!("{path}Tok_-1"), "a.test"),
        ("get", format!("{path}Tok_-1"), "a.test"),
        ("GET", format!("{path}Tok_-1"), "b.test"),
        ("GET", format!("{path}Tok_-1"), "sub.a.test"),
        ("GET", format!("{path}Tok_-1"), "127.0.0.1"),
        ("GET", format!("{path}Tok_-1"), "a.test:0"),
        ("GET", format!("{path}Tok_-1"), "a..test"),
    ] {
        assert!(
            challenge.proof(&request(method, &target, host)).is_none(),
            "{method} {target:.60} {host}"
        );
    }
}

#[test]
fn a_file_that_is_missing_too_large_a_link_or_not_a_regular_file_is_not_found_and_one_of_1_kib_is_answered()
 {
    let dir = Dir::new();
    let outside = Dir::new();
    fs::write(outside.0.join("secret"), b"private key").unwrap();
    std::os::unix::fs::symlink(outside.0.join("secret"), dir.0.join("link")).unwrap();
    fs::write(dir.0.join("big"), vec![b'x'; 1025]).unwrap();
    fs::write(dir.0.join("full"), vec![b'x'; 1024]).unwrap();
    fs::write(dir.0.join("empty"), b"").unwrap();
    fs::create_dir(dir.0.join("folder")).unwrap();
    let fifo = Command::new("mkfifo")
        .arg(dir.0.join("fifo"))
        .status()
        .unwrap();
    assert!(fifo.success());
    let challenge = challenge(&dir.0);
    let proof = |token: &str| {
        challenge
            .proof(&request(
                "GET",
                &format!("/.well-known/acme-challenge/{token}"),
                "a.test",
            ))
            .unwrap()
    };
    assert!(matches!(proof("full"), Proof::Found(bytes) if bytes.len() == 1024));
    assert!(matches!(proof("empty"), Proof::Found(bytes) if bytes.is_empty()));
    for token in ["big", "none", "folder", "fifo", "link"] {
        assert!(matches!(proof(token), Proof::Missing), "{token}");
    }
}

#[test]
fn the_hosts_are_those_of_the_certificates_with_acme_and_there_is_nothing_without_the_acme_object()
{
    let certificate = |hosts: &[&str], acme: Option<CertificateAcme>| CertificateConfig {
        cert_file: PathBuf::from("/c"),
        key_file: PathBuf::from("/k"),
        hosts: hosts.iter().map(|h| (*h).to_owned()).collect(),
        acme,
    };
    let listeners = vec![
        ListenerConfig {
            address: "127.0.0.1:1".parse().unwrap(),
            kind: ListenerKind::Tls(TlsConfig {
                min_version: MinVersion::Tls12,
                certificates: vec![
                    certificate(&["manual.test"], None),
                    certificate(
                        &["a.test", "b.test"],
                        Some(CertificateAcme {
                            renew_before_days: 30,
                        }),
                    ),
                ],
                http2: None,
            }),
        },
        ListenerConfig {
            address: "127.0.0.1:2".parse().unwrap(),
            kind: ListenerKind::Plain,
        },
    ];
    let acme = AcmeConfig {
        directory_url: "https://ca.example/dir".to_owned(),
        contact_email: "ops@example.test".to_owned(),
        account_key_file: PathBuf::from("/a"),
        challenge_dir: PathBuf::from("/challenges"),
        ca_file: PathBuf::from("/ca"),
        timeout: Duration::from_secs(1),
    };
    let made = Challenge::new(Some(&acme), &listeners).unwrap();
    assert_eq!(made.hosts, ["a.test", "b.test"]);
    assert_eq!(made.dir, Path::new("/challenges"));
    assert!(Challenge::new(None, &listeners).is_none());
}

#[test]
fn the_answer_of_a_listener_that_writes_it_itself_has_the_length_and_no_body_for_a_head() {
    let both = String::from_utf8(found(b"abc.def", false, "0123456789abcdef-1")).unwrap();
    assert!(both.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(both.contains("\r\nContent-Type: text/plain\r\n"));
    assert!(both.contains("\r\nContent-Length: 7\r\n"));
    assert!(both.contains("\r\nX-Request-ID: 0123456789abcdef-1\r\n"));
    assert!(both.contains("\r\nConnection: close\r\n"));
    assert!(both.ends_with("\r\n\r\nabc.def"));
    let only = String::from_utf8(found(b"abc.def", true, "0123456789abcdef-1")).unwrap();
    assert!(only.contains("\r\nContent-Length: 7\r\n"));
    assert!(only.ends_with("\r\n\r\n"));
}
