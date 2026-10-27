//! The `records` object of the configuration: where the proxy keeps a copy of its records, and how much of them (see
//! `log::sink`).
//!
//! The object may be left out, and then the records go to the standard error only. When it is there it has all
//! three keys: `dir` (an absolute clean path of at most 3840 bytes; the directory is looked at when the proxy starts,
//! not here), `file_bytes` (1 MiB to 1 GiB: a line that would take the file in use above it starts the next file) and
//! `files` (2 to 64: the files kept, the one in use included).

use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use serde::Deserialize;

use super::{ConfigError, GIB, MAX_STORE_DIR, MIB, Object, bytes, clean_abs, ensure, within};

/// The most files that `files` can keep.
pub(crate) const MAX_RECORD_FILES: usize = 64;

/// The `records` object, checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordsConfig {
    pub dir: PathBuf,
    /// The size above which the file in use is not given another line.
    pub file_bytes: u64,
    /// The files kept, the one in use included.
    pub files: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawRecords {
    dir: String,
    file_bytes: u64,
    files: usize,
}

/// Checks the object.
pub(super) fn check(raw: Option<Object<RawRecords>>) -> Result<Option<RecordsConfig>, ConfigError> {
    let Some(Object(raw)) = raw else {
        return Ok(None);
    };
    let dir = PathBuf::from(raw.dir);
    ensure(
        clean_abs(&dir) && dir.as_os_str().as_bytes().len() <= MAX_STORE_DIR,
        "records dir is not an absolute clean path of at most 3840 bytes",
    )?;
    ensure(
        (MIB..=GIB).contains(&raw.file_bytes),
        "records file_bytes is not 1 MiB to 1 GiB",
    )?;
    ensure(
        within(raw.files, 2, bytes(MAX_RECORD_FILES)),
        "records files is not 2 to 64",
    )?;
    Ok(Some(RecordsConfig {
        dir,
        file_bytes: raw.file_bytes,
        files: raw.files,
    }))
}
