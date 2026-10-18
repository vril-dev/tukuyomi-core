//! The bundle that `rules import` builds from the files an operator names.
//!
//! The inputs are read whole into memory before anything is written anywhere, so an input that is refused leaves
//! nothing behind. The bundle holds, in this order of loading: `crs/crs-setup.conf`, the `.conf` files of
//! `crs/rules/` by the bytes of their names (without those named by `crs_off`), then the operator's rule files in
//! the order they were given, as `rules/<name of the file>`. The data files of the CRS (`crs/rules/*.data`) and the
//! operator's data files (`rules/<name of the file>`) are in the bundle and are not loaded.
//!
//! The directory of the CRS must be what the fetch script leaves, and nothing else: `crs-setup.conf` and an optional
//! `crs-setup.conf.example` in its root, and the directory `rules` with `.conf`, `.data` and `.example` files. The
//! `.example` files are not taken into the bundle. Every other entry (a hidden file, another directory such as
//! `plugins`, another extension, a link, a special file) is refused, and so is a name that is not a path of a bundle.
//! Extensions are compared as they are written, with the case.
//!
//! Every file is read as a regular file that is not a link, of at most 2 MiB, and the bundle may have at most 128
//! files of at most 8 MiB in all. A directory is scanned for at most 1024 entries.
//!
//! The file of the routes, if one is named, is read like an input file. It is not a file of the bundle: its routes
//! are checked (`routes`) and go into the manifest, in the order they are written.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::rules::bundle::{Bundle, BundlePath, MAX_BUNDLE_BYTES, MAX_FILE_BYTES, MAX_FILES, Mode};
use crate::rules::file_store::read_regular;
use crate::rules::routes::Routes;

/// The most entries read from a directory of the CRS.
const MAX_ENTRIES: usize = 1024;

/// What the operator names.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Inputs {
    /// The directory of the CRS.
    pub crs: Option<PathBuf>,
    /// File names of the CRS `rules` directory whose `.conf` is not loaded.
    pub crs_off: Vec<OsString>,
    /// Rule files, in the order they are loaded.
    pub rules: Vec<PathBuf>,
    /// Data files that rules read.
    pub data: Vec<PathBuf>,
    /// What the rules do to a request they match.
    pub mode: Mode,
    /// The file of the routes: a JSON array of the requests that skip the inspection.
    pub routes: Option<PathBuf>,
}

/// Why the inputs were refused: a fixed English sentence, and the name or path of the input that it is about,
/// as the operator wrote it or as the file system listed it. The subject is not safe to print as it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectError {
    pub reason: &'static str,
    pub subject: Option<OsString>,
}

fn refuse<T>(reason: &'static str, subject: &Path) -> Result<T, CollectError> {
    Err(CollectError {
        reason,
        subject: Some(subject.as_os_str().to_owned()),
    })
}

/// The files read so far.
#[derive(Default)]
struct Collector {
    files: BTreeMap<BundlePath, Vec<u8>>,
    load: Vec<BundlePath>,
    total: u64,
}

impl Collector {
    /// Reads `source` into the bundle as `path`, and loads it when `loaded`.
    fn add(&mut self, path: &str, source: &Path, loaded: bool) -> Result<(), CollectError> {
        let Some(path) = BundlePath::parse(path) else {
            return refuse(
                "the name of an input file is not a name in a bundle",
                source,
            );
        };
        if self.files.len() >= MAX_FILES {
            return refuse("the bundle would have more than 128 files", source);
        }
        if self.files.contains_key(&path) {
            return refuse("two input files have the same name in the bundle", source);
        }
        let data = read_input(source)?;
        self.total = self
            .total
            .saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
        if self.total > MAX_BUNDLE_BYTES {
            return refuse("the input files add up to over 8 MiB", source);
        }
        if loaded {
            self.load.push(path.clone());
        }
        self.files.insert(path, data);
        Ok(())
    }
}

/// Reads the inputs into a bundle.
pub fn collect(inputs: &Inputs) -> Result<Bundle, CollectError> {
    let mut collector = Collector::default();
    match &inputs.crs {
        Some(dir) => add_crs(&mut collector, dir, &inputs.crs_off)?,
        None if !inputs.crs_off.is_empty() => {
            return Err(CollectError {
                reason: "a file of the CRS is turned off but no CRS is given",
                subject: None,
            });
        }
        None => {}
    }
    for (group, loaded) in [(&inputs.rules, true), (&inputs.data, false)] {
        for source in group {
            let Some(name) = source.file_name().and_then(OsStr::to_str) else {
                return refuse(
                    "the name of an input file is not a name in a bundle",
                    source,
                );
            };
            collector.add(&format!("rules/{name}"), source, loaded)?;
        }
    }
    if collector.load.is_empty() {
        return Err(CollectError {
            reason: "no rule file is given: name a CRS or a rule file",
            subject: None,
        });
    }
    let routes = match &inputs.routes {
        Some(source) => Routes::from_json(&read_input(source)?).or_else(|e| refuse(e.0, source))?,
        None => Routes::default(),
    };
    Bundle::new(
        inputs.mode,
        collector.files.into_iter().collect(),
        collector.load,
        routes,
    )
    .map_err(|e| CollectError {
        reason: e.0,
        subject: None,
    })
}

/// How an entry of a directory is listed.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    File,
    Dir,
    Other,
}

/// The entries of `dir` by the bytes of their names. A link is `Other`, whatever it leads to.
fn entries(dir: &Path) -> Result<Vec<(OsString, Kind)>, CollectError> {
    const CANNOT: &str = "a directory of the CRS cannot be read";
    let mut list = Vec::new();
    for entry in fs::read_dir(dir).or_else(|_| refuse(CANNOT, dir))? {
        let Ok(entry) = entry else {
            return refuse(CANNOT, dir);
        };
        if list.len() >= MAX_ENTRIES {
            return refuse("a directory of the CRS has more than 1024 entries", dir);
        }
        let kind = match entry.file_type() {
            Ok(t) if t.is_file() => Kind::File,
            Ok(t) if t.is_dir() => Kind::Dir,
            Ok(_) => Kind::Other,
            Err(_) => return refuse(CANNOT, &entry.path()),
        };
        list.push((entry.file_name(), kind));
    }
    list.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    Ok(list)
}

fn add_crs(collector: &mut Collector, dir: &Path, off: &[OsString]) -> Result<(), CollectError> {
    // The directory itself is not a link: what the operator names is what is read.
    if !fs::symlink_metadata(dir).is_ok_and(|meta| meta.file_type().is_dir()) {
        return refuse("the CRS directory is not a real directory", dir);
    }
    let (mut setup, mut rules) = (false, false);
    for (name, kind) in entries(dir)? {
        match (name.to_str(), kind) {
            (Some("crs-setup.conf"), Kind::File) => setup = true,
            (Some("crs-setup.conf.example"), Kind::File) => {}
            (Some("rules"), Kind::Dir) => rules = true,
            _ => {
                return refuse(
                    "the CRS directory holds an entry that is not part of it",
                    &dir.join(name),
                );
            }
        }
    }
    if !setup {
        return refuse("the CRS directory has no crs-setup.conf", dir);
    }
    if !rules {
        return refuse("the CRS directory has no rules directory", dir);
    }
    collector.add("crs/crs-setup.conf", &dir.join("crs-setup.conf"), true)?;

    let rules_dir = dir.join("rules");
    let (mut confs, mut data) = (Vec::new(), Vec::new());
    for (name, kind) in entries(&rules_dir)? {
        let path = rules_dir.join(&name);
        let text = match (name.to_str(), kind) {
            (Some(text), Kind::File) => text.to_owned(),
            _ => {
                return refuse(
                    "the CRS rules directory holds an entry that is not a file",
                    &path,
                );
            }
        };
        if BundlePath::parse(&format!("crs/rules/{text}")).is_none() {
            return refuse("the name of a CRS file is not a name in a bundle", &path);
        }
        if text.ends_with(".conf") {
            confs.push(text);
        } else if text.ends_with(".data") {
            data.push(text);
        } else if !text.ends_with(".example") {
            return refuse(
                "the CRS rules directory holds a file of another kind",
                &path,
            );
        }
    }
    for name in off {
        if !confs.iter().any(|conf| name == conf.as_str()) {
            return refuse(
                "a file that is turned off is not a .conf file of the CRS",
                Path::new(name),
            );
        }
    }
    let kept = confs
        .iter()
        .filter(|conf| !off.iter().any(|name| name == conf.as_str()))
        .map(|conf| (conf, true));
    for (name, loaded) in kept.chain(data.iter().map(|data| (data, false))) {
        collector.add(&format!("crs/rules/{name}"), &rules_dir.join(name), loaded)?;
    }
    Ok(())
}

/// The content of an input file: a regular file that is not a link, of at most 2 MiB, and the very file that
/// `lstat` showed.
fn read_input(source: &Path) -> Result<Vec<u8>, CollectError> {
    let seen = match fs::symlink_metadata(source) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return refuse("an input file is a link", source);
        }
        Ok(meta) if !meta.file_type().is_file() => {
            return refuse("an input file is not a regular file", source);
        }
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return refuse("an input file does not exist", source);
        }
        Err(_) => return refuse("an input file cannot be looked at", source),
    };
    read_regular(source, MAX_FILE_BYTES, Some((seen.dev(), seen.ino()))).or_else(|e| {
        refuse(
            if e.kind() == io::ErrorKind::InvalidData {
                "an input file is over 2 MiB, is not a regular file or changed while it was read"
            } else {
                "an input file cannot be read"
            },
            source,
        )
    })
}

#[cfg(test)]
mod tests;
