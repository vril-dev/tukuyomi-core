//! The certificates of the sites of a version as the managed store has them (`certificates`), which the admin process
//! shows: for each site, the form of its certificate, the state of its files in the store, and the DNS names and the
//! end of the time of validity of the certificate for the host (the first of the chain).
//!
//! The version is read as the route of the content of a version and the cleaning read it (`Store::version`, then
//! `version::parse`): without a main file, so an older version is read as well, and without the lock of its file, so
//! the reading keeps no removal and no saving from going on; a version that goes while it is read gives sites whose
//! files are not there, or the refusal of the store. A version of more than 64 sites is refused before a file of any
//! site is read: one that the check passed has no more, and one that was put in the store by hand could name the same
//! chain of 1 MiB from thousands of sites. The files are read one site at a time, each dropped before the next.
//!
//! A site whose certificate is in neither of the forms that the check takes (see `version::WrittenCertificate`) is
//! `Unreadable` with no form, and nothing is read. So is a site with `acme` with more than 64 hosts, or with a host that
//! is not 1 to 253 graphic ASCII bytes (`der::graphic_name`), and its hosts are not given: they name the directory of
//! its certificate, and the answer gives them. The hosts of a site of the files are neither looked at nor given. For
//! any other site the store is asked for the chain, read as the proxy reads it (`Store::file`, checked against its
//! name, or `Store::issued_chain`), and for the key only whether it is there (`Store::look_file`, `Store::issued_key`):
//! the key is never opened or read. A chain is read only if it holds 1 to 10 certificates in PEM, as the proxy takes
//! them. The state is the first of these that holds:
//! - `Unreadable`: the chain or the key cannot be read (a link, not a regular file of at most 1 MiB, another fault, or
//!   for the files, bytes that are not what the name says), which wins over the other not being there, as in the proxy.
//! - `Missing` for a site of the files, `Waiting` for one with `acme`: the chain or the key is not there (for `acme`,
//!   the directory of its hosts either).
//! - `Unparsed`: the reader of `der` takes no names or no end from the first certificate of the chain.
//! - `Present` for a site of the files, `Issued` for one with `acme`.
//!
//! Whatever the state, a chain that is read tells what is in it alone (`Leaf`) when the reader takes the end of its
//! first certificate: the end, and the names (at most 100, and the number of the others, see `der::dns_names`) when it
//! takes them as well; no name is a certificate without the extension or without a DNS name in it.
//! What is told stops there: whether the key goes with the chain, and whether the certificate covers the hosts, is not
//! looked at, so the proxy may still refuse a version whose sites are all present. A certificate is expired when its
//! end is not after the time of the reading, as an API token is at its end; the proxy does not look at the end, and
//! serves an expired certificate. Nothing of a key is told, and no refusal of the store for a site: only its state.

use super::store::{FILE_NOT_IN_STORE, ManagedError, Store, acme_name};
use super::version::{self, MAX_HOSTS, MAX_SITES, WrittenCertificate, WrittenSite};
use crate::acme::der::{self, Malformed};
use crate::inbound::transport::tls::chain_of;

/// The most DNS names of a certificate that are given: plenty for the names of one certificate, and few enough to keep
/// the answer small.
const MOST_NAMES: usize = 100;

/// The state of the files of the certificate of a site in the store (see the module documentation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// A site of the files: the chain is read, its first certificate gives its names and its end, and the key is
    /// there.
    Present,
    /// A site of the files: the chain or the key is not there.
    Missing,
    /// A site with `acme`: as `Present`.
    Issued,
    /// A site with `acme`: the directory of its hosts, the chain or the key is not there.
    Waiting,
    /// The site, the chain or the key cannot be read.
    Unreadable,
    /// The chain is read and the key is there, but the first certificate of the chain gives no names or no end.
    Unparsed,
}

impl State {
    /// The word of the state in the answer.
    pub const fn word(self) -> &'static str {
        match self {
            State::Present => "present",
            State::Missing => "missing",
            State::Issued => "issued",
            State::Waiting => "waiting",
            State::Unreadable => "unreadable",
            State::Unparsed => "unparsed",
        }
    }
}

/// The form of the certificate of a site.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// The files of the store that hold the chain and the private key, by their names.
    Files { chain: [u8; 32], key: [u8; 32] },
    /// Issued by the command `acme renew` for the hosts of the site, which are given as they are written when they
    /// are of the form (see the module documentation).
    Acme { hosts: Option<Vec<String>> },
}

impl Kind {
    /// The state of a certificate of this form that is read whole, and of one that is not there.
    fn states(&self) -> (State, State) {
        match self {
            Kind::Files { .. } => (State::Present, State::Missing),
            Kind::Acme { .. } => (State::Issued, State::Waiting),
        }
    }
}

/// The end of the time of validity of a certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Expiry {
    /// In seconds since the epoch.
    pub not_after: i64,
    /// Whether `not_after` is not after the time of the reading.
    pub expired: bool,
}

/// What the first certificate of a chain that is read tells, when the reader takes its end.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leaf {
    /// The DNS names, at most 100, and the number of the others; none when the reader takes no names.
    pub names: Option<(Vec<String>, usize)>,
    pub expiry: Expiry,
}

impl Leaf {
    /// What the reader took from the certificate (`names` and `not_after`), at `now`: nothing without the end.
    fn of(
        names: Result<(Vec<String>, usize), Malformed>,
        not_after: Result<i64, Malformed>,
        now: i64,
    ) -> Option<Leaf> {
        let not_after = not_after.ok()?;
        Some(Leaf {
            names: names.ok(),
            expiry: Expiry {
                not_after,
                expired: not_after <= now,
            },
        })
    }
}

/// The certificate of a site of a version, as the store has it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stored {
    /// The name of the site, as it is written.
    pub name: String,
    /// None for a certificate in neither form.
    pub kind: Option<Kind>,
    pub state: State,
    /// None when no chain is read, or the reader takes no end from it.
    pub leaf: Option<Leaf>,
}

/// The certificates of the sites of the version `name` of `store`, in the order of its sites, read at `now` (seconds
/// since the epoch) as the module documentation says. The refusals are those of the store and of `version::parse`, and
/// that of a version of more than 64 sites.
pub fn certificates(store: &Store, name: [u8; 32], now: i64) -> Result<Vec<Stored>, ManagedError> {
    let raw = version::parse(&store.version(name)?).map_err(|e| ManagedError(e.0))?;
    let sites = raw.site_certificates();
    if sites.len() > MAX_SITES {
        return Err(ManagedError("the managed version has more than 64 sites"));
    }
    Ok(sites.map(|site| stored(store, site, now)).collect())
}

/// The certificate of the site `site` (see the module documentation).
fn stored(store: &Store, site: WrittenSite<'_>, now: i64) -> Stored {
    let kind = match site.certificate {
        WrittenCertificate::Files { chain, key } => Some(Kind::Files { chain, key }),
        WrittenCertificate::Acme => {
            let sound = site.hosts.len() <= MAX_HOSTS
                && site
                    .hosts
                    .iter()
                    .all(|host| der::graphic_name(host.as_bytes()));
            Some(Kind::Acme {
                hosts: sound.then(|| site.hosts.to_vec()),
            })
        }
        WrittenCertificate::Unknown => None,
    };
    let (state, leaf) = match &kind {
        Some(kind) => read(store, kind, now),
        None => (State::Unreadable, None),
    };
    Stored {
        name: site.name.to_owned(),
        kind,
        state,
        leaf,
    }
}

/// The state of the certificate `kind` of a site, and what its chain tells when it is read, at `now` (see the module
/// documentation). Both the chain and the key are asked for before the state is told.
fn read(store: &Store, kind: &Kind, now: i64) -> (State, Option<Leaf>) {
    let (chain, key) = match kind {
        Kind::Files { chain, key } => (
            there(store.file(*chain)),
            there(store.look_file(*key)).map(|key| key.is_some()),
        ),
        Kind::Acme { hosts: Some(hosts) } => {
            let name = acme_name(hosts);
            (store.issued_chain(name), store.issued_key(name))
        }
        Kind::Acme { hosts: None } => return (State::Unreadable, None),
    };
    // A chain file that holds anything but 1 to 10 certificates in PEM cannot be read either.
    let chain = chain.map_err(drop).and_then(|bytes| {
        bytes
            .map(|bytes| chain_of(&bytes))
            .transpose()
            .map_err(drop)
    });
    let leaf = match &chain {
        Ok(Some(chain)) => chain.first(),
        _ => None,
    };
    let told = leaf.map(|leaf| (der::dns_names(leaf, MOST_NAMES), der::not_after(leaf)));
    let (whole, absent) = kind.states();
    let state = match (&chain, &key, &told) {
        (Err(()), ..) | (_, Err(_), _) => State::Unreadable,
        (Ok(None), ..) | (_, Ok(false), _) => absent,
        (.., Some((Ok(_), Ok(_)))) => whole,
        _ => State::Unparsed,
    };
    (
        state,
        told.and_then(|(names, not_after)| Leaf::of(names, not_after, now)),
    )
}

/// A file of `files/` as the store finds it: none when it is not there.
fn there<T>(found: Result<T, ManagedError>) -> Result<Option<T>, ManagedError> {
    match found {
        Ok(found) => Ok(Some(found)),
        Err(e) if e == FILE_NOT_IN_STORE => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
pub(crate) mod tests;
