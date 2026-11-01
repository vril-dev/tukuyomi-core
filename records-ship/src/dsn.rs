//! The connection string of the database, read from the file `db_dsn_file`.
//!
//! The string holds the password, so it is not in the configuration file (which may be readable by others) but in
//! a file of its own: a regular file owned by the user of this process without group or other permission bits, of
//! at most `MAX_DSN` bytes, holding UTF-8 text. The type, the owner and the mode are those of the file that was
//! opened, so a path that is changed after the open changes nothing. A refusal is a fixed sentence that does not
//! name the file and never holds a part of the string, and the string has no `Debug` form that shows it.

use std::fmt;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use crate::files;

/// The longest file in bytes.
const MAX_DSN: u64 = 16 * 1024;

/// The connection string. It has no `Display` and its `Debug` form is empty.
pub struct Dsn(String);

impl Dsn {
    /// The text, for the one place that gives it to the database client.
    pub fn text(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Dsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Dsn(..)")
    }
}

/// Reads the string from the file at `path`, which must be owned by `uid`. Spaces and line feeds around the string
/// are not part of it.
pub fn read(path: &Path, uid: u32) -> Result<Dsn, &'static str> {
    let file = files::open_followed(path).map_err(|_| "the db_dsn_file cannot be opened")?;
    let meta = file
        .metadata()
        .map_err(|_| "the db_dsn_file cannot be looked at")?;
    if !meta.is_file() {
        return Err("the db_dsn_file is not a regular file");
    }
    if meta.uid() != uid {
        return Err("the db_dsn_file is not owned by this user");
    }
    if meta.mode() & 0o077 != 0 {
        return Err("the db_dsn_file has group or other permission bits");
    }
    if meta.len() > MAX_DSN {
        return Err("the db_dsn_file is over 16 KiB");
    }
    let mut bytes = Vec::new();
    file.take(MAX_DSN + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "the db_dsn_file cannot be read")?;
    if u64::try_from(bytes.len()).is_ok_and(|n| n > MAX_DSN) {
        return Err("the db_dsn_file is over 16 KiB");
    }
    let text = String::from_utf8(bytes).map_err(|_| "the db_dsn_file does not hold UTF-8 text")?;
    let text = text.trim();
    if text.is_empty() {
        return Err("the db_dsn_file is empty");
    }
    Ok(Dsn(text.to_owned()))
}

#[cfg(test)]
mod tests;
