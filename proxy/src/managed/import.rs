//! The import of a version into the store. Two ways in make the same `Import`, a version in its one written form and
//! the files that are to be put with it: the command `managed import`, from a document that names its files by their
//! paths (`from_document`), and the admin process, from a request that sends a version that names its files by their
//! SHA-256 and the content of the files that the store may not have yet (`from_request`). One way puts an `Import` in
//! the store (`place`).
//!
//! Both ways in check the version with the main file, and the files that it names as the proxy would, before anything
//! is written: the chain and the key of each site that has them go together and cover its hosts, and the file of the
//! authorities of each group holds 1 to 100 certificates that can be trust anchors. A refusal is the rest of a line
//! (`managed import` writes it after its name, the admin process answers it); a site or a group is named in it by the
//! name that the check of the version passed, which is letters, digits, `-` and `_` only.
//!
//! `from_document` reads each file of the document once, as the proxy reads a certificate file (a regular file of at
//! most 1 MiB; a link is followed), and makes the version that names them by their SHA-256. `from_request` takes at
//! most 192 files (the chains and the keys of 64 sites and the files of the authorities of 64 groups) of at most
//! 1 MiB each, none twice and none that the version does not name; a file that the version names and the request does
//! not bring is read from the store, and one that the store cannot give (it is not there, it is not what its name
//! says, it is a link) refuses the request, which may bring it. The bytes of the files are overwritten with zeros when
//! they are dropped.
//!
//! `place` takes the lock of the store and holds it until it ends: it puts the files (a file that is there already is
//! not written again), reads the main file with the version and the files of the store as the proxy would (see
//! `load`), the country database included or not (`Reading`), and puts the version. It does not choose it. A file that
//! was put in the store stays there if the reading refuses.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use zeroize::Zeroizing;

use super::load::{self, Choice, LoadError};
use super::store::{MAX_BYTES, ManagedError, Placed, Store};
use super::version::{self, SiteOf};
use crate::config::{Built, Routing};
use crate::forward::tls::{self, Authorities, Settings};
use crate::inbound::transport::tls::{Fault, certified, check, read_file};
use crate::log::escaped;
use crate::rules::bundle::sha256;

/// The most files of a request: the chains and the keys of 64 sites and the files of the authorities of 64 groups.
pub const MAX_FILES: usize = 192;
/// The refusals of a request with more files, or with a larger one.
pub const MANY_FILES: &str = "the request has more than 192 files";
pub const LARGE_FILE: &str = "a file of the request is over 1 MiB";

/// A version to put in the store, in its one written form, and the files to put with it.
pub struct Import {
    version: Vec<u8>,
    files: Vec<Zeroizing<Vec<u8>>>,
}

/// How `place` reads the version with the main file before it puts it in the store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reading {
    /// As the proxy reads it when it starts, the country database included (`managed import`).
    Whole,
    /// Without the country database, which the proxy reads when it takes the version (the admin process).
    WithoutCountries,
}

/// Why `place` refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placing {
    /// The store: its lock (held by another, `IN_USE`, or not to be taken), or a file or the version that cannot be
    /// put.
    Store(ManagedError),
    /// The reading of the main file with the version.
    Load(LoadError),
}

/// The import of the document `text` of `managed import`, checked with the main file `built` (which has `managed`),
/// with the files it names read from their paths.
pub fn from_document(built: &Built, text: &[u8]) -> Result<Import, String> {
    let document = load::document(built, text).map_err(|e| format!("document refused: {}", e.0))?;
    let files = read_files(&document)?;
    sound(&document.sites, &document.authorities, |path| {
        files.get(path).map(|bytes| bytes.as_slice())
    })?;
    let names: BTreeMap<PathBuf, [u8; 32]> = files
        .iter()
        .map(|(path, bytes)| (path.clone(), sha256(bytes)))
        .collect();
    let version =
        version::version_of(text, &names).map_err(|e| format!("document refused: {}", e.0))?;
    Ok(Import {
        version,
        files: files.into_values().collect(),
    })
}

/// The files that `document` names, each read once as the proxy reads a certificate file.
fn read_files(document: &load::Document) -> Result<BTreeMap<PathBuf, Zeroizing<Vec<u8>>>, String> {
    let sites = document
        .sites
        .iter()
        .filter_map(|site| site.certificate.files())
        .flat_map(|(chain, key)| [chain, key]);
    let authorities = document.authorities.iter().map(|(_, path)| path);
    let mut files = BTreeMap::new();
    for path in sites.chain(authorities) {
        if files.contains_key(path) {
            continue;
        }
        let bytes = read_file(path, MAX_BYTES).map_err(|fault| {
            let why = match fault {
                Fault::Missing => "a file of the document does not exist",
                Fault::TooLarge => "a file of the document is over 1 MiB",
                _ => "a file of the document cannot be read",
            };
            format!("{why}: \"{}\"", escaped(path.as_os_str().as_bytes()))
        })?;
        files.insert(path.clone(), bytes);
    }
    Ok(files)
}

/// The import of the version `version`, in its one written form (see `version::sent`), that a request sent with the
/// content of the files `files`, checked with the main file `built` (which has `managed`) and the files of `store`.
pub fn from_request(
    built: &Built,
    store: &Store,
    version: Vec<u8>,
    files: Vec<Zeroizing<Vec<u8>>>,
) -> Result<Import, String> {
    let refuse = |text: &str| Err(text.to_owned());
    if files.len() > MAX_FILES {
        return refuse(MANY_FILES);
    }
    if !files
        .iter()
        .all(|bytes| u64::try_from(bytes.len()).is_ok_and(|n| n <= MAX_BYTES))
    {
        return refuse(LARGE_FILE);
    }
    let Routing::Managed { resolve_timeout } = built.routing else {
        return refuse("the configuration has no managed object");
    };
    let checked = version::parse(&version)
        .and_then(|raw| {
            raw.check(
                &built.main,
                resolve_timeout,
                built.policy.geo.clone(),
                version::stored_tls,
            )
        })
        .map_err(|e| e.0.to_owned())?;
    let mut given = BTreeMap::new();
    for bytes in &files {
        if given.insert(sha256(bytes), bytes.as_slice()).is_some() {
            return refuse("two files of the request have the same content");
        }
    }
    let authorities: Vec<(String, [u8; 32])> = checked
        .forward
        .groups
        .iter()
        .filter_map(|group| match &group.tls {
            Some(Settings {
                authorities: Authorities::Stored(name),
                ..
            }) => Some((group.name.clone(), *name)),
            _ => None,
        })
        .collect();
    let named: BTreeSet<[u8; 32]> = checked
        .sites
        .iter()
        .filter_map(|site| site.certificate.files())
        .flat_map(|(chain, key)| [*chain, *key])
        .chain(authorities.iter().map(|(_, name)| *name))
        .collect();
    if given.keys().any(|name| !named.contains(name)) {
        return refuse("a file of the request is not named by the version");
    }
    let mut stored = BTreeMap::new();
    for name in named.iter().filter(|name| !given.contains_key(*name)) {
        stored.insert(*name, store.file(*name).map_err(|e| e.0.to_owned())?);
    }
    sound(&checked.sites, &authorities, |name| {
        given
            .get(name)
            .copied()
            .or_else(|| stored.get(name).map(|bytes| bytes.as_slice()))
    })?;
    Ok(Import { version, files })
}

/// Checks the files of `sites` and the files of the authorities of the groups of `authorities` as the proxy checks
/// them (see the module documentation). `bytes` gives the content of a file by what names it; a file it does not give
/// is empty, and refused.
fn sound<'a, F>(
    sites: &[SiteOf<F>],
    authorities: &[(String, F)],
    bytes: impl Fn(&F) -> Option<&'a [u8]>,
) -> Result<(), String> {
    let bytes = |file: &F| bytes(file).unwrap_or_default();
    for site in sites {
        let Some((chain, key)) = site.certificate.files() else {
            continue;
        };
        certified(bytes(chain), bytes(key))
            .and_then(|key| check(&key, &site.hosts))
            .map_err(|fault| format!("{} (site {})", fault.text(), site.name))?;
    }
    for (group, file) in authorities {
        tls::config_of(bytes(file))
            .map_err(|fault| format!("{} (upstream {group})", fault.text()))?;
    }
    Ok(())
}

/// Puts `import` in `store`, which the main file `built` names (see the module documentation). The name of the
/// version, and what its write found.
pub fn place(
    built: Built,
    store: &Store,
    import: &Import,
    reading: Reading,
) -> Result<([u8; 32], Placed), Placing> {
    let _lock = store.lock().map_err(Placing::Store)?;
    for bytes in &import.files {
        store.put_file(bytes).map_err(Placing::Store)?;
    }
    // The version is read with the main file as the proxy will read it, its files from the store.
    let choice = Choice::Given(import.version.clone());
    match reading {
        Reading::Whole => load::load_with(built, Some(store), &choice),
        Reading::WithoutCountries => load::without_countries(built, Some(store), &choice),
    }
    .map_err(Placing::Load)?;
    store.put_version(&import.version).map_err(Placing::Store)
}
