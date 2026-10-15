//! Start-up checks of what the inspection kernel requires of its host process.
//!
//! The kernel waits for its inspector child itself, so the host must not ignore SIGCHLD. It starts the inspector
//! with `std::process::Command`, which closes nothing by itself, so every descriptor above 2 must be
//! close-on-exec. Both facts are read from `/proc`; a value that cannot be read or understood refuses the start.
//! A SIGCHLD disposition that only has `SA_NOCLDWAIT` is not visible there; the kernel then fails closed when it
//! cannot see its child exit.

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

/// Refuses to start when SIGCHLD is ignored or a descriptor above 2 lacks close-on-exec.
pub fn check() -> Result<(), &'static str> {
    let status = read_proc("/proc/self/status", STATUS_READ)
        .map_err(|_| "cannot read the process status")?;
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
mod tests {
    use super::*;

    fn status(sig_ign: &str) -> String {
        format!(
            "Name:\tproxy\nSigPnd:\t0000000000000000\nSigIgn:\t{sig_ign}\nSigCgt:\t0000000000000000\n"
        )
    }

    #[test]
    fn sigchld_in_the_ignored_mask_is_refused() {
        // SIGCHLD is signal 17: bit 16.
        assert_eq!(sigchld_ignored(&status("0000000000010000")), Ok(true));
        assert_eq!(sigchld_ignored(&status("ffffffffffffffff")), Ok(true));
        assert_eq!(sigchld_ignored(&status("0000000000010001")), Ok(true));
    }

    #[test]
    fn other_ignored_signals_pass() {
        // The neighbours of bit 16, and the usual SIGPIPE-ignored mask.
        assert_eq!(sigchld_ignored(&status("0000000000008000")), Ok(false));
        assert_eq!(sigchld_ignored(&status("0000000000020000")), Ok(false));
        assert_eq!(sigchld_ignored(&status("0000000000001000")), Ok(false));
        assert_eq!(sigchld_ignored(&status("0000000000000000")), Ok(false));
        assert_eq!(sigchld_ignored(&status("fffffffffffeffff")), Ok(false));
    }

    #[test]
    fn a_missing_or_malformed_mask_is_an_error_not_a_pass() {
        let bad = "the ignored-signal mask is missing or malformed";
        assert_eq!(sigchld_ignored("Name:\tproxy\n"), Err(bad));
        assert_eq!(sigchld_ignored(&status("")), Err(bad));
        assert_eq!(sigchld_ignored(&status("+000000000010000")), Err(bad));
        assert_eq!(sigchld_ignored(&status("000000000001000g")), Err(bad));
        assert_eq!(sigchld_ignored(&status("00000000000100000")), Err(bad));
        assert_eq!(sigchld_ignored(&status("0x00000000010000")), Err(bad));
    }

    #[test]
    fn a_descriptor_without_the_close_on_exec_bit_is_refused() {
        let info = |flags: &str| format!("pos:\t0\nflags:\t{flags}\nmnt_id:\t12\nino:\t5\n");
        assert_eq!(lacks_cloexec(&info("0100002")), Ok(true));
        assert_eq!(lacks_cloexec(&info("00")), Ok(true));
        // Every bit below O_CLOEXEC set, the bit itself not.
        assert_eq!(lacks_cloexec(&info("01777777")), Ok(true));
        assert_eq!(lacks_cloexec(&info("37777777777")), Ok(false));
    }

    #[test]
    fn a_descriptor_with_the_close_on_exec_bit_passes() {
        let info = |flags: &str| format!("pos:\t0\nflags:\t{flags}\nmnt_id:\t12\n");
        assert_eq!(lacks_cloexec(&info("02000000")), Ok(false));
        assert_eq!(lacks_cloexec(&info("02100002")), Ok(false));
        assert_eq!(lacks_cloexec(&info("02000002")), Ok(false));
    }

    #[test]
    fn missing_or_malformed_flags_are_an_error_not_a_pass() {
        let bad = "the descriptor flags are missing or malformed";
        assert_eq!(lacks_cloexec("pos:\t0\n"), Err(bad));
        assert_eq!(lacks_cloexec("flags:\t\n"), Err(bad));
        assert_eq!(lacks_cloexec("flags:\t09\n"), Err(bad));
        assert_eq!(lacks_cloexec("flags:\t-1\n"), Err(bad));
        assert_eq!(lacks_cloexec("flags:\t020000000000\n"), Err(bad));
    }

    #[test]
    fn descriptor_names_are_plain_decimal_numbers() {
        assert_eq!(fd_number("0"), Some(0));
        assert_eq!(fd_number("3"), Some(3));
        assert_eq!(fd_number("4294967295"), Some(u32::MAX));
        assert_eq!(fd_number("4294967296"), None);
        assert_eq!(fd_number("+3"), None);
        assert_eq!(fd_number("-3"), None);
        assert_eq!(fd_number("3 "), None);
        assert_eq!(fd_number(""), None);
        assert_eq!(fd_number("0000000003"), Some(3));
        assert_eq!(fd_number("00000000003"), None);
    }
}
