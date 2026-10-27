//! The directories and the control socket of the configuration against each other: the rules store `dir`,
//! `records.dir`, `admin.store.dir` and the directory of `admin.control` (those that are there) are all different and
//! none is inside another, and `admin.control` itself is inside none of the first three. Else one part could replace
//! what another keeps: the rotation of the record files renames over a socket that has the name of a record file in
//! the same directory, for one. A path is inside another when it has the other as a prefix component by component, so `/var/ab` is not
//! inside `/var/a`. The paths are absolute and clean already.

use std::path::Path;

use super::{AdminConfig, AdminStoreConfig, ConfigError, RecordsConfig, ensure};

/// Whether `a` and `b` are the same path or one is inside the other.
fn overlap(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

/// Checks the places against each other. `rules` is the rules store `dir`.
pub(super) fn separate(
    rules: &Path,
    records: Option<&RecordsConfig>,
    admin: Option<&AdminConfig>,
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
    )
}
