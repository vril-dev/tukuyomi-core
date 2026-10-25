//! The command that issues and renews the certificates that have `acme`.
//!
//! ```text
//! tukuyomi-proxy acme renew <config>
//! ```
//!
//! A command is a short process of its own, apart from a running proxy, which does not notice what it does (the proxy
//! answers the challenge of the CA while the command waits for it, see `inbound::challenge`; it takes a new
//! certificate when it is sent SIGUSR2). The configuration is the one of the proxy, as an absolute clean path. Each
//! certificate of a TLS listener that has `acme` is looked at in the order of the configuration, and is due if its
//! certificate file or key file cannot be read, the key does not go with the certificate, the certificate does not
//! cover every host, or less than `renew_before_days` days are left until the end of its time of validity (exactly
//! that many days is not less). A certificate that is not due is `valid`. For the first that is due the account key
//! is read or made, and the account is made or found at the CA; then each due certificate is ordered in turn with a
//! new key (see `order`, `files`), the chain the CA made is checked as the proxy checks a chain when it reads it
//! (the key goes with it, and it covers the hosts), and the key and the chain are written. The whole command, the
//! CA's answers and its waiting included, takes at most `timeout_ms`; a certificate that is still due when the time
//! is gone is `failed`, and so is every one after it. SIGINT and SIGTERM end the command at once, with the files of
//! its challenges removed. However it ends, the command does not wait for the system to answer the lookup of the
//! name of the CA.
//!
//! The result is one line on the standard output for each certificate with `acme`: `<listener>.<certificate>`, both
//! counted from 1, a space, and `renewed`, `valid` or `failed`. A failed certificate keeps its files as they were.
//! Everything else goes to the standard error, a line each, and starts with the name of the command. What the CA sent
//! is written only as the `type` of its problem document, with every byte outside 0x20 to 0x7e as `\xNN`.
//!
//! The command does not run as root: when any user id of the process is 0, it writes a `host check refused` line and
//! ends before it reads the configuration. A key and a certificate that root wrote would not be read by the proxy
//! that runs as another user.
//!
//! The exit code is 0 if every certificate is `renewed` or `valid`, 1 if one is `failed` (or the command was stopped,
//! cannot run, or runs as root), and 2 for a wrong argument, a refused configuration, or a configuration with no
//! certificate that has `acme`.

use std::ffi::OsString;
use std::future::{Future, poll_fn};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::task::Poll;
use std::time::{SystemTime, UNIX_EPOCH};

use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use rustls::sign::CertifiedKey;
use tokio::runtime::Builder;
use tokio::signal::unix::{SignalKind, signal};
use tokio::time::{Instant, timeout_at};

use super::client::Client;
use super::files::{Challenges, account_key, install};
use super::key::Key;
use super::order::Session;
use super::{Failure, base64, der};
use crate::config::{self, AcmeConfig, CertificateConfig, ListenerConfig, ListenerKind};
use crate::host;
use crate::inbound::transport::tls::{Files, KeySource, check};

const USAGE: &str = "usage: tukuyomi-proxy acme renew <config>";
const NAME: &str = "acme renew";
/// The most certificates in a chain that is written (as the proxy reads at most).
const MAX_CHAIN: usize = 10;
const SECONDS_PER_DAY: i64 = 86_400;

/// How a command ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    Done,
    Failed,
    Usage,
}

/// Where a command writes.
struct Terminal<'a> {
    out: &'a mut dyn Write,
    err: &'a mut dyn Write,
}

impl Terminal<'_> {
    /// A result line. A write that fails does not change how the command ends.
    fn result(&mut self, line: &str) {
        let _ = writeln!(self.out, "{line}");
    }

    fn note(&mut self, line: &str) {
        let _ = writeln!(self.err, "{line}");
    }
}

/// A certificate with `acme`, and its number as the lines of the result name it.
struct Target<'a> {
    label: String,
    certificate: &'a CertificateConfig,
    renew_before_days: u32,
}

/// Runs the command that `args` (what follows `acme`) name.
pub fn run(args: &[OsString], out: &mut dyn Write, err: &mut dyn Write) -> Exit {
    let mut term = Terminal { out, err };
    match parse(args) {
        Ok(config) => renew(&config, &mut term),
        Err(why) => {
            term.note(&format!("acme: {why}"));
            term.note(USAGE);
            Exit::Usage
        }
    }
}

fn parse(args: &[OsString]) -> Result<PathBuf, &'static str> {
    let (name, rest) = args.split_first().ok_or("a command is missing")?;
    if name != "renew" {
        return Err("unknown command");
    }
    match rest {
        [] => Err("the configuration file is missing"),
        [config] if config::clean_abs(Path::new(config)) => Ok(PathBuf::from(config)),
        [_] => Err("the configuration file is not an absolute clean path"),
        _ => Err("renew takes one argument, the configuration file"),
    }
}

/// The certificates with `acme` of the TLS listeners, in the order of the configuration.
fn targets(listeners: &[ListenerConfig]) -> Vec<Target<'_>> {
    let mut found = Vec::new();
    for (at, listener) in listeners.iter().enumerate() {
        let ListenerKind::Tls(tls) = &listener.kind else {
            continue;
        };
        for (place, certificate) in tls.certificates.iter().enumerate() {
            if let Some(acme) = certificate.acme {
                found.push(Target {
                    label: format!("{}.{}", at + 1, place + 1),
                    certificate,
                    renew_before_days: acme.renew_before_days,
                });
            }
        }
    }
    found
}

/// The seconds since the epoch now.
fn unix_now() -> Option<i64> {
    let since = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    i64::try_from(since.as_secs()).ok()
}

/// Whether a certificate that ends at `not_after` is to be renewed at `now`: less than `days` days are left.
fn expires_soon(not_after: i64, now: i64, days: u32) -> bool {
    not_after.saturating_sub(now) < i64::from(days) * SECONDS_PER_DAY
}

/// Whether the certificate of `target` is to be made again at `now`, for any of the reasons in the head of this file.
fn due(target: &Target<'_>, now: i64) -> bool {
    let certificate = target.certificate;
    let Ok(key) = Files.load(&certificate.cert_file, &certificate.key_file) else {
        return true;
    };
    if check(&key, &certificate.hosts).is_err() {
        return true;
    }
    key.cert
        .first()
        .and_then(|leaf| der::not_after(leaf.as_ref()).ok())
        .is_none_or(|end| expires_soon(end, now, target.renew_before_days))
}

fn renew(config: &Path, term: &mut Terminal<'_>) -> Exit {
    if let Err(text) = host::not_root() {
        term.note(&format!("{NAME}: host check refused: {text}"));
        return Exit::Failed;
    }
    let loaded = match config::load(config) {
        Ok(loaded) => loaded,
        Err(e) => {
            term.note(&format!("{NAME}: configuration refused: {}", e.0));
            return Exit::Usage;
        }
    };
    let Some(acme) = &loaded.acme else {
        term.note(&format!(
            "{NAME}: no certificate of the configuration has acme"
        ));
        return Exit::Usage;
    };
    let Some(now) = unix_now() else {
        term.note(&format!("{NAME}: the clock is before 1970"));
        return Exit::Failed;
    };
    let targets = targets(&loaded.proxy.listeners);
    let runtime = match Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(_) => {
            term.note(&format!("{NAME}: cannot build the runtime"));
            return Exit::Failed;
        }
    };
    let ended = runtime.block_on(async {
        let (Ok(mut interrupt), Ok(mut terminate)) = (
            signal(SignalKind::interrupt()),
            signal(SignalKind::terminate()),
        ) else {
            return Err("cannot install the signal handlers");
        };
        // The signals are looked at first, and the work is dropped, with its files of challenges, when one comes.
        let mut work = pin!(renew_all(acme, &targets, now, term));
        poll_fn(|cx| {
            if interrupt.poll_recv(cx).is_ready() || terminate.poll_recv(cx).is_ready() {
                return Poll::Ready(Err("stopped by a signal"));
            }
            work.as_mut().poll(cx).map(Ok)
        })
        .await
    });
    // Dropping the runtime would wait for its blocking tasks. The lookup of a host name runs in one, the time it takes
    // is the system's, and it may take longer than the time of the command (see `Client`).
    runtime.shutdown_background();
    match ended {
        Ok(exit) => exit,
        Err(why) => {
            term.note(&format!("{NAME}: {why}"));
            Exit::Failed
        }
    }
}

/// The account at the CA, made when the first certificate needs it. A failure is kept, and every certificate after it
/// gets the same.
async fn session_of<'s>(
    slot: &'s mut Option<Result<Session, Failure>>,
    acme: &AcmeConfig,
    deadline: Instant,
) -> Result<&'s mut Session, Failure> {
    if slot.is_none() {
        *slot = Some(open(acme, deadline).await);
    }
    match slot {
        Some(Ok(session)) => Ok(session),
        Some(Err(failure)) => Err(failure.clone()),
        None => Err("the account is not there".into()),
    }
}

async fn open(acme: &AcmeConfig, deadline: Instant) -> Result<Session, Failure> {
    let client = Client::new(&acme.ca_file, deadline)?;
    let key = account_key(&acme.account_key_file)?;
    match timeout_at(
        deadline,
        Session::open(client, key, &acme.directory_url, &acme.contact_email),
    )
    .await
    {
        Ok(opened) => opened,
        Err(_) => Err("the time for the command is used up".into()),
    }
}

async fn renew_all(
    acme: &AcmeConfig,
    targets: &[Target<'_>],
    now: i64,
    term: &mut Terminal<'_>,
) -> Exit {
    let deadline = Instant::now()
        .checked_add(acme.timeout)
        .unwrap_or_else(Instant::now);
    let mut session = None;
    let mut exit = Exit::Done;
    for target in targets {
        if !due(target, now) {
            term.result(&format!("{} valid", target.label));
            continue;
        }
        let done = match session_of(&mut session, acme, deadline).await {
            Ok(session) => renew_one(session, acme, target, deadline).await,
            Err(failure) => Err(failure),
        };
        match done {
            Ok(()) => term.result(&format!("{} renewed", target.label)),
            Err(failure) => {
                term.note(&format!("{NAME}: {}: {failure}", target.label));
                term.result(&format!("{} failed", target.label));
                exit = Exit::Failed;
            }
        }
    }
    exit
}

/// Orders a new certificate for `target`, checks it, and writes it and its key.
async fn renew_one(
    session: &mut Session,
    acme: &AcmeConfig,
    target: &Target<'_>,
    deadline: Instant,
) -> Result<(), Failure> {
    let certificate = target.certificate;
    let (key, key_pem) = Key::generate()?;
    let csr = der::csr_text(&key, &certificate.hosts)?;
    // Dropped when this function ends, with the files of the order's challenges.
    let mut challenges = Challenges::new(&acme.challenge_dir);
    let ordered = timeout_at(
        deadline,
        session.issue(&certificate.hosts, &csr, &mut challenges),
    )
    .await
    .map_err(|_| Failure::Text("the time for the command is used up"))??;
    let chain = CertificateDer::pem_slice_iter(&ordered)
        .take(MAX_CHAIN + 1)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "the chain of the CA is not certificates in PEM")?;
    if chain.is_empty() || chain.len() > MAX_CHAIN {
        return Err("the chain of the CA does not hold 1 to 10 certificates".into());
    }
    let text: String = chain
        .iter()
        .map(|der| base64::pem("CERTIFICATE", der.as_ref()).to_string())
        .collect();
    check(
        &CertifiedKey::new(chain, key.signing_key()),
        &certificate.hosts,
    )
    .map_err(|_| "the chain of the CA does not go with the key or does not cover the hosts")?;
    install(
        &certificate.cert_file,
        &certificate.key_file,
        &key_pem,
        &text,
    )
}

#[cfg(test)]
mod tests;
