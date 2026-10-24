//! The `acme` object of the configuration: how the command `acme renew` (see `acme`) reaches the CA that issues the
//! certificates that have `acme`, and where it keeps its account key and the files of the challenges.
//!
//! The object is there if and only if some certificate of some TLS listener has `acme` (see `listeners`), and then
//! some listener has to be plain or to redirect, for the CA asks for the challenge over plain HTTP. Its keys are all
//! required: `directory_url` (an `https://` URL of at most 2048 bytes without blanks or control bytes),
//! `contact_email` (at most 254 bytes, `name@domain` of letters, digits and a few signs; the form only is checked),
//! `account_key_file`, `challenge_dir` and `ca_file` (each an absolute clean path of at most 3840 bytes; `ca_file` holds
//! the authorities that the CA's certificate is checked against, as the `ca_file` of an upstream group does) and
//! `timeout_ms` (1 ms to 600 s, the time the whole command may take). The account key file, `ca_file` and the cert and
//! key files of the certificates that have `acme` are all different files: the command replaces the cert and key
//! files, and the account key file is made by it. None of these files, and no cert or key file of any other
//! certificate, is directly inside `challenge_dir`: a listener answers a request with the content of a file of that
//! directory whose name is a token (see `inbound::challenge`). The paths are compared as they are written.

use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

use super::{
    CertificateConfig, ConfigError, ListenerConfig, ListenerKind, MAX_STORE_DIR, Object, clean_abs,
    ensure,
};

/// The longest `directory_url` in bytes.
const MAX_URL: usize = 2048;
/// The longest `contact_email` in bytes, and the longest part of it before the `@`.
const MAX_EMAIL: usize = 254;
const MAX_LOCAL: usize = 64;
const MAX_TIMEOUT_MS: u64 = 600_000;

/// The `acme` object, checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcmeConfig {
    pub directory_url: String,
    pub contact_email: String,
    pub account_key_file: PathBuf,
    pub challenge_dir: PathBuf,
    pub ca_file: PathBuf,
    /// The time the whole command may take.
    pub timeout: Duration,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawAcme {
    directory_url: String,
    contact_email: String,
    account_key_file: String,
    challenge_dir: String,
    ca_file: String,
    timeout_ms: u64,
}

/// `name@domain`: the name of 1 to 64 letters, digits and `.-_+`, and a domain of at least two labels of letters, digits
/// and `-` (not at the ends of a label), of at most 63 bytes each.
fn email_ok(text: &str) -> bool {
    let Some((name, domain)) = text.split_once('@') else {
        return false;
    };
    text.len() <= MAX_EMAIL
        && (1..=MAX_LOCAL).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-_+".contains(&b))
        && domain.contains('.')
        && domain.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

fn url_ok(text: &str) -> bool {
    text.len() <= MAX_URL
        && text.len() > "https://".len()
        && text.starts_with("https://")
        && text.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

fn path(text: String) -> Result<PathBuf, ConfigError> {
    let path = PathBuf::from(text);
    ensure(
        clean_abs(&path) && path.as_os_str().as_bytes().len() <= MAX_STORE_DIR,
        "an acme account_key_file, challenge_dir or ca_file is not an absolute clean path of at most 3840 bytes",
    )?;
    Ok(path)
}

/// The certificates of the TLS listeners.
fn certificates(listeners: &[ListenerConfig]) -> impl Iterator<Item = &CertificateConfig> {
    listeners
        .iter()
        .filter_map(|listener| match &listener.kind {
            ListenerKind::Tls(tls) => Some(&tls.certificates),
            _ => None,
        })
        .flatten()
}

/// The certificates of the TLS listeners that have `acme`.
fn issued(listeners: &[ListenerConfig]) -> impl Iterator<Item = &CertificateConfig> {
    certificates(listeners).filter(|certificate| certificate.acme.is_some())
}

/// Checks the object against the listeners: it is there if and only if a certificate has `acme`.
pub(super) fn check(
    raw: Option<Object<RawAcme>>,
    listeners: &[ListenerConfig],
) -> Result<Option<AcmeConfig>, ConfigError> {
    let Some(Object(raw)) = raw else {
        ensure(
            issued(listeners).next().is_none(),
            "a certificate has acme but the configuration has no acme object",
        )?;
        return Ok(None);
    };
    ensure(
        issued(listeners).next().is_some(),
        "the configuration has an acme object but no certificate has acme",
    )?;
    ensure(
        listeners
            .iter()
            .any(|l| matches!(l.kind, ListenerKind::Plain | ListenerKind::Redirect { .. })),
        "a certificate with acme needs a plain or a redirect listener for the challenge",
    )?;
    ensure(
        url_ok(&raw.directory_url),
        "acme directory_url is not an https URL of at most 2048 bytes",
    )?;
    ensure(
        email_ok(&raw.contact_email),
        "acme contact_email is not an address of at most 254 bytes",
    )?;
    ensure(
        (1..=MAX_TIMEOUT_MS).contains(&raw.timeout_ms),
        "acme timeout_ms is not 1 to 600000",
    )?;
    let account_key_file = path(raw.account_key_file)?;
    let challenge_dir = path(raw.challenge_dir)?;
    let ca_file = path(raw.ca_file)?;
    let mut files: Vec<&PathBuf> = vec![&account_key_file, &ca_file];
    for certificate in issued(listeners) {
        files.push(&certificate.cert_file);
        files.push(&certificate.key_file);
    }
    files.sort();
    ensure(
        files.windows(2).all(|pair| pair[0] != pair[1]),
        "the account key file, the ca_file and the cert and key files of the certificates with acme are not all different",
    )?;
    // The files of a certificate without acme are the operator's: the command neither takes one as its own key or CA nor
    // writes one.
    ensure(
        certificates(listeners)
            .filter(|certificate| certificate.acme.is_none())
            .flat_map(|certificate| [&certificate.cert_file, &certificate.key_file])
            .all(|file| !files.contains(&file)),
        "a cert or key file of a certificate without acme is a file of the command or of a certificate with acme",
    )?;
    ensure(
        [&account_key_file, &ca_file]
            .into_iter()
            .chain(certificates(listeners).flat_map(|c| [&c.cert_file, &c.key_file]))
            .all(|file| file.parent() != Some(challenge_dir.as_path())),
        "the account key file, the ca_file or a cert or key file of a certificate is directly inside challenge_dir",
    )?;
    Ok(Some(AcmeConfig {
        directory_url: raw.directory_url,
        contact_email: raw.contact_email,
        account_key_file,
        challenge_dir,
        ca_file,
        timeout: Duration::from_millis(raw.timeout_ms),
    }))
}
