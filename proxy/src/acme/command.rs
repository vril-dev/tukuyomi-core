//! The command that issues and renews the certificates that have `acme`.
//!
//! ```text
//! tukuyomi-proxy acme renew <config>
//! ```
//!
//! A command is a short process of its own, apart from a running proxy, which does not notice what it does (the proxy
//! answers the challenge of the CA while the command waits for it, see `inbound::challenge`; it takes a new
//! certificate when it is sent SIGUSR2). The configuration is the one of the proxy, as an absolute clean path, read
//! whole as the proxy reads it: with `managed`, with the version that `current` names. The certificates with `acme`
//! are looked at in this order: those of the TLS listeners in the order of the configuration, then that of
//! `admin.route`, then the sites with `acme` of the version in its order. The cert and key files of a certificate of a
//! listener and of `admin.route` are the ones that the configuration names; those of a site are `chain` and `key` in
//! `acme/<64 digits>/` of the managed store, named by its hosts and read through the store (see `managed`). A
//! certificate is due if its files cannot be read, the key does not go with the certificate, the certificate does not
//! cover every host, or less than `renew_before_days` days are left until the end of its time of validity (exactly
//! that many days is not less). A certificate that is not due is `valid`. For a due site, `acme/` and its directory
//! are looked at, and made when they are not there, before anything is ordered: one that is a link or not a directory
//! makes the site `failed`, and nothing is asked of the CA for it. For the first certificate that is due the account
//! key is read or made, and the account is made or found at the CA; then each due certificate is ordered in turn with
//! a new key (see `order`, `files`), the chain the CA made is checked as the proxy checks a chain when it reads it
//! (the key goes with it, and it covers the hosts), and the key and the chain are written. The command takes no lock
//! of the managed store: it changes no version and not `current`, and two of it are not run on one configuration at
//! once. It holds the version that it read (see `managed::Hold`) until it ends, so that the version is not removed
//! meanwhile and the directories of `acme/` of its sites, which it writes, are not cleaned up. The whole command, the
//! CA's answers and its waiting included, takes at most `timeout_ms`; a certificate that is still due when the time is
//! gone is `failed`, and so is every one after it. SIGINT and SIGTERM end the command at once, with the files of its
//! challenges removed. However it ends, the command does not wait for the system to answer the lookup of the name of
//! the CA.
//!
//! The result is one line on the standard output for each certificate with `acme`: its place, a space, and
//! `renewed`, `valid` or `failed`. The place of a certificate of a listener is `<listener>.<certificate>`, both counted
//! from 1, that of `admin.route` is `admin route`, and that of a site `site <name>`. A failed certificate keeps its
//! files as they were. Everything else goes to the standard error, a line each, and starts with the name of the
//! command, then the place for a line about one certificate. What the CA sent is written only as the `type` of its
//! problem document, with every byte outside 0x20 to 0x7e as `\xNN`. A configuration with `managed` and the `acme`
//! object whose certificate of `admin.route` has no `acme` and whose version has no site with `acme` has nothing to
//! renew: no result line, one line on the standard error, and the exit code 0, so that a timer does not fail while
//! the sites with `acme` are not there yet.
//!
//! The command does not run as root: when any user id of the process is 0, it writes a `host check refused` line and
//! ends before it reads the configuration. A key and a certificate that root wrote would not be read by the proxy
//! that runs as another user.
//!
//! The exit code is 0 if every certificate is `renewed` or `valid`, 1 if one is `failed` (or the command was stopped,
//! cannot run, or runs as root), and 2 for a wrong argument, a refused configuration (with `managed`, a store, a
//! `current` or a version that the proxy would not start with as well), or a configuration without the `acme` object.

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
use crate::config::{self, AcmeConfig, CertificateConfig, ListenerKind, Loaded};
use crate::inbound::transport::tls::{Files, KeySource, certified, check};
use crate::managed::{SiteCertificate, Store, acme_name};
use crate::run::host;

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

/// Where the files of a certificate with `acme` are.
enum Kept<'a> {
    /// The cert and key files that the configuration names: of a certificate of a listener, or of `admin.route`.
    Named {
        cert_file: &'a Path,
        key_file: &'a Path,
    },
    /// `acme/<name>/` of the managed store, for a site with `acme`.
    Stored { store: &'a Store, name: [u8; 32] },
}

/// A certificate with `acme`: its place as the lines of the result name it, its hosts, and where its files are.
struct Target<'a> {
    label: String,
    hosts: &'a [String],
    renew_before_days: u32,
    kept: Kept<'a>,
}

impl<'a> Target<'a> {
    /// The target of a certificate whose files the configuration names, if it has `acme`.
    fn named(label: String, certificate: &'a CertificateConfig) -> Option<Target<'a>> {
        let acme = certificate.acme?;
        Some(Target {
            label,
            hosts: &certificate.hosts,
            renew_before_days: acme.renew_before_days,
            kept: Kept::Named {
                cert_file: &certificate.cert_file,
                key_file: &certificate.key_file,
            },
        })
    }

    /// The certificate and the key that are there now, as the proxy reads them; `None` for any fault.
    fn current(&self) -> Option<CertifiedKey> {
        match &self.kept {
            Kept::Named {
                cert_file,
                key_file,
            } => Files.load(cert_file, key_file).ok(),
            Kept::Stored { store, name } => match store.issued(*name) {
                Ok(Some((chain, key))) => certified(&chain, &key).ok(),
                Ok(None) | Err(_) => None,
            },
        }
    }

    /// Where the chain and the key are written, in that order. For a site the directories of the store are looked at,
    /// and made when they are not there; a refusal of the store is the failure of the target.
    fn places(&self) -> Result<(PathBuf, PathBuf), Failure> {
        match &self.kept {
            Kept::Named {
                cert_file,
                key_file,
            } => Ok((cert_file.to_path_buf(), key_file.to_path_buf())),
            Kept::Stored { store, name } => {
                store.issue_places(*name).map_err(|e| Failure::Text(e.0))
            }
        }
    }
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

/// The certificates with `acme` of the whole configuration `loaded`, in the order of the head of this file.
fn targets(loaded: &Loaded) -> Vec<Target<'_>> {
    let mut found = Vec::new();
    for (at, listener) in loaded.proxy.listeners.iter().enumerate() {
        let ListenerKind::Tls(tls) = &listener.kind else {
            continue;
        };
        for (place, certificate) in tls.certificates.iter().enumerate() {
            found.extend(Target::named(
                format!("{}.{}", at + 1, place + 1),
                certificate,
            ));
        }
    }
    if let Some(route) = &loaded.admin_route {
        found.extend(Target::named("admin route".to_owned(), &route.certificate));
    }
    if let Some(version) = &loaded.version {
        for site in &version.sites {
            if let SiteCertificate::Acme(acme) = site.certificate {
                found.push(Target {
                    label: format!("site {}", site.name),
                    hosts: &site.hosts,
                    renew_before_days: acme.renew_before_days,
                    kept: Kept::Stored {
                        store: &version.store,
                        name: acme_name(&site.hosts),
                    },
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
    let Some(key) = target.current() else {
        return true;
    };
    if check(&key, target.hosts).is_err() {
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
    // With `managed`, `loaded` holds the version it was read with until the command ends.
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
    let targets = targets(&loaded);
    // Only a file with `managed` has the object with no certificate with `acme`: its sites with `acme` may be to come.
    if targets.is_empty() {
        term.note(&format!(
            "{NAME}: no certificate has acme, neither that of admin route nor a site of the managed version"
        ));
        return Exit::Done;
    }
    let Some(now) = unix_now() else {
        term.note(&format!("{NAME}: the clock is before 1970"));
        return Exit::Failed;
    };
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
        // The places are made sure of before anything is asked of the CA.
        let done = match target.places() {
            Ok(places) => match session_of(&mut session, acme, deadline).await {
                Ok(session) => renew_one(session, acme, target, &places, deadline).await,
                Err(failure) => Err(failure),
            },
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

/// Orders a new certificate for `target`, checks it, and writes it and its key to `places` (the chain, the key).
async fn renew_one(
    session: &mut Session,
    acme: &AcmeConfig,
    target: &Target<'_>,
    places: &(PathBuf, PathBuf),
    deadline: Instant,
) -> Result<(), Failure> {
    let hosts = target.hosts;
    let (key, key_pem) = Key::generate()?;
    let csr = der::csr_text(&key, hosts)?;
    // Dropped when this function ends, with the files of the order's challenges.
    let mut challenges = Challenges::new(&acme.challenge_dir);
    let ordered = timeout_at(deadline, session.issue(hosts, &csr, &mut challenges))
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
    check(&CertifiedKey::new(chain, key.signing_key()), hosts)
        .map_err(|_| "the chain of the CA does not go with the key or does not cover the hosts")?;
    let (chain_file, key_file) = places;
    install(chain_file, key_file, &key_pem, &text)
}

#[cfg(test)]
mod tests;
