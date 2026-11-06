//! The directories and the control socket of the configuration against each other: the rules store `dir`,
//! `records.dir`, `admin.store.dir` and the directory of `admin.control` (those that are there) are all different and
//! none is inside another, and `admin.control` itself is inside none of the first three. Else one part could replace
//! what another keeps: the rotation of the record files renames over a socket that has the name of a record file in
//! the same directory, for one. A path is inside another when it has the other as a prefix component by component, so `/var/ab` is not
//! inside `/var/a`. The paths are absolute and clean already. `managed.dir`, when it is there, is checked after them
//! against every one of them in the same way, with a sentence of its own.
//!
//! Then `challenge_dir` of `acme`, when it is there, is checked in the same way against every one of those places,
//! `managed.dir` included, with or without `managed`: the command `acme renew` renames files named by the tokens of the
//! CA into it and removes them at the end, and a token can have the name of a file of another place (`current`, for
//! one); and a listener answers a challenge with a file of that directory, which must not be a key that another place
//! keeps. Last, with `managed`, no other path of `acme` (`account_key_file`, `ca_file`) and no file of the certificate
//! of `admin.route` is inside `managed.dir`: the command never writes over a name of the managed store, and the way to
//! the admin process, which the main file keeps (see `admin`), never rests on a file of the store, which is the part
//! to be changed from the admin screens.

use std::path::Path;

use super::{
    AcmeConfig, AdminConfig, AdminRoute, AdminStoreConfig, ConfigError, ManagedConfig, Records,
    ensure,
};

/// Whether `a` and `b` are the same path or one is inside the other.
fn overlap(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

/// Checks the places against each other. `rules` is the rules store `dir`, and `route` the way to the admin process.
pub(super) fn separate(
    rules: &Path,
    records: Option<&Records>,
    admin: Option<&AdminConfig>,
    managed: Option<&ManagedConfig>,
    acme: Option<&AcmeConfig>,
    route: Option<&AdminRoute>,
) -> Result<(), ConfigError> {
    let mut places = vec![rules];
    places.extend(records.map(|records| records.dir.as_path()));
    if let Some(admin) = admin {
        let AdminStoreConfig::File { dir } = &admin.store;
        places.push(dir);
        ensure(
            !places.iter().any(|place| admin.control.starts_with(place)),
            "admin control is inside the rules store dir, the records dir or the admin store dir",
        )?;
        // A path with a file name has a directory; the root is the fallback that overlaps with every place.
        places.push(admin.control.parent().unwrap_or(Path::new("/")));
    }
    ensure(
        places
            .iter()
            .enumerate()
            .all(|(i, a)| places[i + 1..].iter().all(|b| !overlap(a, b))),
        "the rules store dir, the records dir, the admin store dir and the directory of admin control are the same or inside one another",
    )?;
    if let Some(managed) = managed {
        ensure(
            places.iter().all(|place| !overlap(&managed.dir, place)),
            "the managed dir is the same as, inside or around the rules store dir, the records dir, the admin store dir or the directory of admin control",
        )?;
        places.push(&managed.dir);
    }
    if let Some(acme) = acme {
        ensure(
            places
                .iter()
                .all(|place| !overlap(&acme.challenge_dir, place)),
            "acme challenge_dir is the same as, inside or around the rules store dir, the records dir, the admin store dir, the directory of admin control or the managed dir",
        )?;
    }
    let Some(managed) = managed else {
        return Ok(());
    };
    let commands = acme.map(|acme| [&acme.account_key_file, &acme.ca_file]);
    let route = route.map(|route| [&route.certificate.cert_file, &route.certificate.key_file]);
    ensure(
        commands
            .into_iter()
            .chain(route)
            .flatten()
            .all(|file| !file.starts_with(&managed.dir)),
        "the acme account_key_file or ca_file, or a cert or key file of admin route, is inside the managed dir",
    )
}
