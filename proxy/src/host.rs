//! Checks of the host process, made before it starts or runs a command: what the inspection kernel requires of it,
//! and that it does not run as root.
//!
//! The kernel waits for its inspector child itself, so the host must not ignore SIGCHLD. It starts the inspector
//! with `std::process::Command`, which closes nothing by itself, so every descriptor above 2 must be
//! close-on-exec. Both facts are read from `/proc`; a value that cannot be read or understood refuses the start.
//! A SIGCHLD disposition that only has `SA_NOCLDWAIT` is not visible there; the kernel then fails closed when it
//! cannot see its child exit.
//!
//! The process must not run as root. Its user ids are read from the same file: the real, the effective, the saved
//! and the file system id. Any of the four being 0 refuses it, not the effective id alone, because a process whose
//! saved id is 0 can return to root, and the file system id owns what the process creates. `check` makes this
//! refusal before the others, and a command that does not make the others makes this one alone (`not_root`). The
//! user id that the file system sees (`fs_uid`) is the fourth of the same four.

use std::fs::{self, File};
use std::io::{self, Read};

/// SIGCHLD on x86_64 and aarch64 Linux.
const SIGCHLD: u32 = 17;
/// `O_CLOEXEC` on x86_64 and aarch64 Linux, as printed in octal by `/proc/<pid>/fdinfo/<fd>`.
const O_CLOEXEC: u64 = 0o2_000_000;
/// The most that is read from `/proc/self/status`. The ignored-signal mask comes after the list of supplementary
/// groups, which can take about 700 KiB at the limit of 65536 groups.
const STATUS_READ: u64 = 1 << 20;
/// The most that is read from one `fdinfo` file; the flags come in the first lines.
const FDINFO_READ: u64 = 16 * 1024;

/// Refuses to start when a user id is 0, SIGCHLD is ignored or a descriptor above 2 lacks close-on-exec.
pub fn check() -> Result<(), &'static str> {
    let status = read_proc("/proc/self/status", STATUS_READ)
        .map_err(|_| "cannot read the process status")?;
    not_root_in(&status)?;
    if sigchld_ignored(&status)? {
        return Err("SIGCHLD is ignored");
    }
    for fd in open_descriptors()? {
        if fd < 3 {
            continue;
        }
        let info = match read_proc(&format!("/proc/self/fdinfo/{fd}"), FDINFO_READ) {
            Ok(info) => info,
            // Closed since the list was made. The descriptor of the directory listing itself ends up here too.
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => return Err("cannot read the flags of a descriptor"),
        };
        if lacks_cloexec(&info)? {
            return Err("a descriptor above 2 is not close-on-exec");
        }
    }
    Ok(())
}

/// Refuses a process that runs as root: any of its four user ids is 0. The commands that do not make the other
/// checks of `check` make this one.
pub fn not_root() -> Result<(), &'static str> {
    let status = read_proc("/proc/self/status", STATUS_READ)
        .map_err(|_| "cannot read the process status")?;
    not_root_in(&status)
}

/// The user id that the file system sees for this process, which owns what the process creates (std has no
/// `geteuid`). It is the fourth number of the `Uid:` line of `/proc/self/status`.
pub fn fs_uid() -> Result<u32, &'static str> {
    let status = read_proc("/proc/self/status", STATUS_READ)
        .map_err(|_| "cannot read the process status")?;
    user_ids_of(&status).map(|ids| ids[3])
}

/// At most `limit` bytes of a `/proc` file.
fn read_proc(path: &str, limit: u64) -> io::Result<String> {
    let mut bytes = Vec::new();
    File::open(path)?.take(limit).read_to_end(&mut bytes)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// The numbers of the open descriptors. The directory handle is closed before this returns, so its own
/// descriptor is not looked at again.
fn open_descriptors() -> Result<Vec<u32>, &'static str> {
    const LIST: &str = "cannot list the open descriptors";
    let mut fds = Vec::new();
    for entry in fs::read_dir("/proc/self/fd").map_err(|_| LIST)? {
        let name = entry.map_err(|_| LIST)?.file_name();
        fds.push(
            name.to_str()
                .and_then(fd_number)
                .ok_or("unexpected entry in the descriptor list")?,
        );
    }
    Ok(fds)
}

/// A descriptor number: decimal digits only, no sign, no space.
fn fd_number(name: &str) -> Option<u32> {
    digits(name, 10, 10).and_then(|n| u32::try_from(n).ok())
}

/// `text` as a number in `radix`: at least one and at most `max_digits` digits, nothing else (no sign, no space).
fn digits(text: &str, radix: u32, max_digits: usize) -> Option<u64> {
    if text.is_empty()
        || text.len() > max_digits
        || !text.bytes().all(|b| char::from(b).is_digit(radix))
    {
        return None;
    }
    u64::from_str_radix(text, radix).ok()
}

/// The value after `name` on the first line of `text` that starts with it.
fn field<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.lines()
        .find_map(|line| line.strip_prefix(name))
        .map(str::trim)
}

/// Whether the `SigIgn` mask of `/proc/<pid>/status` (16 hex digits, bit n - 1 for signal n) has SIGCHLD.
fn sigchld_ignored(status: &str) -> Result<bool, &'static str> {
    const BAD: &str = "the ignored-signal mask is missing or malformed";
    let mask = field(status, "SigIgn:")
        .and_then(|value| digits(value, 16, 16))
        .ok_or(BAD)?;
    Ok(mask & (1 << (SIGCHLD - 1)) != 0)
}

/// The ids of the `Uid:` line of `/proc/<pid>/status`: the real, effective, saved and file system id, exactly four
/// decimal numbers that each fit in a `u32`.
fn user_ids_of(status: &str) -> Result<[u32; 4], &'static str> {
    const BAD: &str = "the user ids are missing or malformed";
    let ids = field(status, "Uid:").and_then(|value| {
        value
            .split_ascii_whitespace()
            .map(|id| digits(id, 10, 10).and_then(|n| u32::try_from(n).ok()))
            .collect::<Option<Vec<u32>>>()
    });
    match ids.as_deref() {
        Some(&[real, effective, saved, fs]) => Ok([real, effective, saved, fs]),
        _ => Err(BAD),
    }
}

/// Refuses `/proc/<pid>/status` of a process of which any of the four user ids is 0.
fn not_root_in(status: &str) -> Result<(), &'static str> {
    if user_ids_of(status)?.contains(&0) {
        return Err("the process runs as root");
    }
    Ok(())
}

/// Whether the `flags` line of `/proc/<pid>/fdinfo/<fd>` (octal; the kernel adds `O_CLOEXEC` to what it prints)
/// lacks close-on-exec.
fn lacks_cloexec(fdinfo: &str) -> Result<bool, &'static str> {
    const BAD: &str = "the descriptor flags are missing or malformed";
    let flags = field(fdinfo, "flags:")
        .and_then(|value| digits(value, 8, 11))
        .ok_or(BAD)?;
    Ok(flags & O_CLOEXEC == 0)
}

#[cfg(test)]
mod tests;
