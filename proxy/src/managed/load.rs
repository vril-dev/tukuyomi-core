//! The whole reading of the configuration: the main file, and for a file with `managed` a version of the store and the
//! files it names, as one configuration that the proxy serves with.
//!
//! The order is the main file (see `config`; a refusal there ends the reading), then, for a file with `managed`, the
//! store, the version that is asked for (`Choice`), its check with the main file (see `version`), and every file that
//! it names, each read and checked against its name; last the country database of the main file. The bytes of the
//! files are not kept: whatever uses a file later reads it again through the store, which checks it again. The
//! certificate of a site with `acme` is not read here: it is in `acme/` of the store, may not be issued yet, and is
//! read with the other certificates (see `inbound::transport::tls`).
//!
//! The proxy starts with the version that `current` names, and so do `config check` and the reading of SIGHUP: with
//! no version chosen, or one that is refused, the proxy does not start, and SIGHUP changes nothing. A reload order of
//! the control socket reads the version it names, and one that is refused changes nothing either. `managed activate`
//! reads the version it is to choose, and `managed import` and the admin process the version they are to put in the
//! store, the admin process without the country database (see `import`).
//!
//! A version of the store (`Choice::Current`, `Choice::Named`) is read with a shared lock on its file (`Store::hold`)
//! before its files are read, and the lock lasts as long as the `Version` of the reading: the proxy keeps it while it
//! serves with the version (see `run`), `acme renew` to its end, and `config check` and `managed activate` while they
//! read. So the version is not removed, nor are its files cleaned up, while it is in use. A version that is given
//! (`Choice::Given`) is not in the store yet, and is not held.

use std::path::{Path, PathBuf};
use std::time::Duration;

use super::store::{Hold, ManagedError, Store};
use super::version::{self, Site, SiteOf};
use crate::config::{
    self, Built, ConfigError, ForwardSettings, GeoConfig, Loaded, MainFile, PolicyConfig, RawTls,
    Routing,
};
use crate::forward::tls::{Authorities, Settings};
use crate::rules::bundle::sha256;

/// Which version a file with `managed` is read with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Choice {
    /// The one `current` names.
    Current,
    /// The one of the store with this name.
    Named([u8; 32]),
    /// These bytes, which are not in the store yet; their name is their SHA-256.
    Given(Vec<u8>),
}

/// Why the whole reading refused, by the part that refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadError {
    /// The main file, or its country database.
    Main(ConfigError),
    /// The version, checked with the main file.
    Version(ConfigError),
    /// The store: it, its record of the chosen version, the version or a file cannot be read, or is not what its name
    /// says.
    Store(ManagedError),
}

impl LoadError {
    /// The sentence of the refusal, whatever part it is of.
    pub fn sentence(self) -> ConfigError {
        match self {
            LoadError::Main(e) | LoadError::Version(e) => e,
            LoadError::Store(e) => ConfigError(e.0),
        }
    }
}

/// The version that a whole configuration was read with: its name, the store it is in, its sites, and the shared lock
/// on its file for a version that was read from the store (`Choice::Current` and `Choice::Named`, see `Store::hold`),
/// which lasts as long as the version does (so it is not `Clone`).
#[derive(Debug)]
pub struct Version {
    pub name: [u8; 32],
    pub store: Store,
    pub sites: Vec<Site>,
    pub hold: Option<Hold>,
}

/// The main file `main` with its routing, and the version it was read with if the file has `managed`: the whole
/// configuration.
pub(crate) fn whole(
    main: MainFile,
    forward: ForwardSettings,
    policy: PolicyConfig,
    version: Option<Version>,
) -> Loaded {
    let MainFile {
        proxy,
        kernel,
        store,
        acme,
        status,
        records,
        admin,
        admin_route,
        managed,
        sha256,
    } = main;
    Loaded {
        proxy,
        forward,
        kernel,
        store,
        acme,
        status,
        records,
        policy,
        admin,
        admin_route,
        managed,
        version,
        sha256,
    }
}

/// Reads the configuration at `path` whole, a file with `managed` with the version of `choice`.
pub fn load(path: &Path, choice: &Choice) -> Result<Loaded, LoadError> {
    let bytes = config::read(path).map_err(LoadError::Main)?;
    let built = config::main_file(&bytes).map_err(LoadError::Main)?;
    let store = match &built.main.managed {
        Some(managed) => Some(Store::open(&managed.dir).map_err(LoadError::Store)?),
        None => None,
    };
    load_with(built, store.as_ref(), choice)
}

/// The same for the main file `built`, read already, and its store `store`, opened already: what a command reads, which
/// keeps the one main file and the one store that it opened for all it does. `store` is there for a file with
/// `managed` (else it is not looked at).
pub fn load_with(
    built: Built,
    store: Option<&Store>,
    choice: &Choice,
) -> Result<Loaded, LoadError> {
    let mut loaded = without_countries(built, store, choice)?;
    config::read_countries(&mut loaded).map_err(LoadError::Main)?;
    Ok(loaded)
}

/// `load_with` but for the country database, which is not read: the check of a version that the admin process puts in
/// the store (see `import`). What it gives is not served with; the proxy reads the database when it takes the version.
pub(super) fn without_countries(
    built: Built,
    store: Option<&Store>,
    choice: &Choice,
) -> Result<Loaded, LoadError> {
    let Built {
        main,
        policy,
        routing,
    } = built;
    match (routing, store) {
        (Routing::Own(forward), _) => Ok(whole(main, forward, policy, None)),
        (Routing::Managed { resolve_timeout }, Some(store)) => {
            with_version(main, resolve_timeout, policy.geo, store, choice)
        }
        // `config` gives the routing of `managed` only to a file that has it, and `load` opens its store.
        (Routing::Managed { .. }, None) => Err(LoadError::Main(ConfigError(
            "the configuration has no managed object",
        ))),
    }
}

/// The main file `main`, which has `managed`, with the version of `choice`, read from `store` and checked with it.
/// `resolve_timeout` and `geo` are the values of the main file that are not in `main`.
fn with_version(
    main: MainFile,
    resolve_timeout: Duration,
    geo: Option<GeoConfig>,
    store: &Store,
    choice: &Choice,
) -> Result<Loaded, LoadError> {
    // A version of the store is held from before its files are read, so that it is not removed, and they are not
    // cleaned up, while it is in use.
    let (name, bytes, hold) = match choice {
        Choice::Current => {
            let name = store
                .current()
                .map_err(LoadError::Store)?
                .ok_or(LoadError::Store(ManagedError(
                    "no managed version is chosen",
                )))?;
            let (bytes, hold) = store.hold(name).map_err(LoadError::Store)?;
            (name, bytes, Some(hold))
        }
        Choice::Named(name) => {
            let (bytes, hold) = store.hold(*name).map_err(LoadError::Store)?;
            (*name, bytes, Some(hold))
        }
        Choice::Given(bytes) => (sha256(bytes), bytes.clone(), None),
    };
    let checked = version::parse(&bytes)
        .and_then(|raw| raw.check(&main, resolve_timeout, geo, version::stored_tls))
        .map_err(LoadError::Version)?;
    // Each file is read once here, to be checked against its name; whatever uses it reads it again. A site with `acme`
    // names no file.
    for (chain, key) in checked
        .sites
        .iter()
        .filter_map(|site| site.certificate.files())
    {
        store.file(*chain).map_err(LoadError::Store)?;
        store.file(*key).map_err(LoadError::Store)?;
    }
    for group in &checked.forward.groups {
        if let Some(Settings {
            authorities: Authorities::Stored(name),
            ..
        }) = &group.tls
        {
            store.file(*name).map_err(LoadError::Store)?;
        }
    }
    let version = Version {
        name,
        store: store.clone(),
        sites: checked.sites,
        hold,
    };
    Ok(whole(main, checked.forward, checked.policy, Some(version)))
}

/// What a document names by paths: the sites, with the paths of their chains and keys, and the file of the authorities
/// of each group that has `tls`, with the name of the group.
pub struct Document {
    pub sites: Vec<SiteOf<PathBuf>>,
    pub authorities: Vec<(String, PathBuf)>,
}

/// The document of `managed import` in `bytes`, checked with the main file `built` (which has `managed`) as a version
/// is, but for its files, which are not read here.
pub fn document(built: &Built, bytes: &[u8]) -> Result<Document, ConfigError> {
    let Routing::Managed { resolve_timeout } = built.routing else {
        return Err(ConfigError("the configuration has no managed object"));
    };
    let checked = version::parse_document(bytes)?.check(
        &built.main,
        resolve_timeout,
        built.policy.geo.clone(),
        RawTls::split,
    )?;
    let authorities = checked
        .forward
        .groups
        .into_iter()
        .filter_map(|group| match group.tls?.authorities {
            Authorities::File(path) => Some((group.name, path)),
            Authorities::Stored(_) => None,
        })
        .collect();
    Ok(Document {
        sites: checked.sites,
        authorities,
    })
}

#[cfg(test)]
mod tests;
