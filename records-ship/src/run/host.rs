//! Checks of the process and of the directory it works in: that it does not run as root, which user the file
//! system sees, that a directory is its own, and that its file system gives the birth time of a file.
//!
//! The proxy has the same checks (`run::host` of the proxy library), which are private to it. The user ids are
//! read from `/proc/self/status`, all four of them: the real, the effective, the saved and the file system id. Any
//! of them being 0 refuses the process, because a process whose saved id is 0 can return to root, and the file
//! system id owns what the process creates.

use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use tukuyomi_proxy::log::ship::Identity;

use crate::files;

/// The most that is read from `/proc/self/status`.
const STATUS_READ: u64 = 1 << 20;

/// The ids of the `Uid:` line of the status text: the real, effective, saved and file system id, exactly four
/// decimal numbers that each fit in a `u32`.
fn user_ids_of(status: &str) -> Result<[u32; 4], &'static str> {
    const BAD: &str = "the user ids are missing or malformed";
    let line = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .ok_or(BAD)?;
    let ids = line
        .split_ascii_whitespace()
        .map(|id| {
            if id.len() <= 10 && id.bytes().all(|b| b.is_ascii_digit()) {
                id.parse::<u32>().ok()
            } else {
                None
            }
        })
        .collect::<Option<Vec<u32>>>();
    match ids.as_deref() {
        Some(&[real, effective, saved, fs]) => Ok([real, effective, saved, fs]),
        _ => Err(BAD),
    }
}

fn status() -> Result<String, &'static str> {
    let mut bytes = Vec::new();
    fs::File::open("/proc/self/status")
        .and_then(|file| file.take(STATUS_READ).read_to_end(&mut bytes))
        .map_err(|_| "cannot read the process status")?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Refuses a process of which any of the four user ids is 0.
pub fn not_root() -> Result<(), &'static str> {
    if user_ids_of(&status()?)?.contains(&0) {
        return Err("the process runs as root");
    }
    Ok(())
}

/// The user id that the file system sees for this process, which owns what the process creates (std has no
/// `geteuid`).
pub fn fs_uid() -> Result<u32, &'static str> {
    user_ids_of(&status()?).map(|ids| ids[3])
}

/// Looks at `dir` with `lstat`: it must be a real directory (not a link) without group or other permission bits
/// and owned by `uid`.
pub fn private_dir(dir: &Path, uid: u32) -> Result<(), &'static str> {
    let meta = fs::symlink_metadata(dir).map_err(|_| "the directory cannot be read")?;
    if !meta.file_type().is_dir() {
        return Err("the directory is not a real directory");
    }
    if meta.mode() & 0o077 != 0 {
        return Err("the directory has group or other permission bits");
    }
    if meta.uid() != uid {
        return Err("the directory is not owned by this user");
    }
    Ok(())
}

/// Looks at `dir` and at the record files in it (at most `count` of them): each must give a birth time. The
/// shipper tells a record file from a later one with the same inode number by it, so a file system that gives none
/// cannot be followed safely. The directory is looked at as well, for it may hold no record file yet and its file
/// system is the one the record files will be on.
pub fn birth_times(dir: &Path, count: usize) -> Result<(), &'static str> {
    const NONE: &str = "the file system of the directory gives no birth time for its files";
    let meta = fs::metadata(dir).map_err(|_| "the directory cannot be read")?;
    if Identity::of(&meta).is_none() {
        return Err(NONE);
    }
    for path in files::record_paths(dir, count) {
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_file() && Identity::of(&meta).is_none() => return Err(NONE),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("a record file cannot be looked at"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
