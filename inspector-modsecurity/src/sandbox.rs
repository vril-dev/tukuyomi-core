//! The restrictions that the process puts on itself before it reads a request.
//!
//! `restrict` takes away what the inspector does not need any more, for the whole process and for good: it can then
//! reach no file outside `TMPDIR`, make no TCP connection, bind no TCP port, execute no program, and has no capability
//! left. The rules are built by then; `TMPDIR` holds the copy of the generation, so it is the one place that stays
//! reachable. The system calls are made through `libc` and carry the names of the Linux uapi headers
//! (`linux/landlock.h`, `linux/prctl.h`, `linux/capability.h`) in their comments, because `libc` has the numbers of the
//! three Landlock calls but none of their structures or rights.
//!
//! Landlock does not restrict UDP, unix sockets or MPTCP sockets (a socket made with `IPPROTO_MPTCP` is not a TCP
//! socket to it), so those stay open.
//!
//! It must run before a request is read. An error means the process is not (fully) restricted and must not go on: the
//! caller ends the start, with the exit code 14 for any error. A kernel without Landlock gives `Error::NoLandlock`,
//! and there is no way to run unrestricted.
//!
//! Landlock, `no_new_privs` and the capability sets belong to one thread, and this inspector runs on one thread. So
//! `restrict` first checks that the process has exactly one thread and refuses otherwise, before anything is
//! restricted: a second thread would be left as free as it was.
//!
//! The unsafe code of this crate is here and in `ffi`. Each block says why it is sound.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use libc::{c_int, c_long, c_ulong};

// The rights of a Landlock rule set. A right that the rule set handles is refused unless a rule allows it, and the
// kernel refuses a rule set that names a right it does not know (EINVAL), so the rights handled are chosen by the ABI
// version that the kernel reports (`handled_rights`).

/// ABI 1: bits 0 to 12, from EXECUTE through MAKE_SYM.
const ACCESS_FS_BASE: u64 = (1 << 13) - 1;
const ACCESS_FS_WRITE_FILE: u64 = 1 << 1; // LANDLOCK_ACCESS_FS_WRITE_FILE
const ACCESS_FS_READ_FILE: u64 = 1 << 2; // LANDLOCK_ACCESS_FS_READ_FILE
const ACCESS_FS_REMOVE_FILE: u64 = 1 << 5; // LANDLOCK_ACCESS_FS_REMOVE_FILE
const ACCESS_FS_MAKE_REG: u64 = 1 << 8; // LANDLOCK_ACCESS_FS_MAKE_REG
const ACCESS_FS_REFER: u64 = 1 << 13; // LANDLOCK_ACCESS_FS_REFER (ABI 2)
const ACCESS_FS_TRUNCATE: u64 = 1 << 14; // LANDLOCK_ACCESS_FS_TRUNCATE (ABI 3)
const ACCESS_FS_IOCTL_DEV: u64 = 1 << 15; // LANDLOCK_ACCESS_FS_IOCTL_DEV (ABI 5)
const ACCESS_NET_BIND_TCP: u64 = 1 << 0; // LANDLOCK_ACCESS_NET_BIND_TCP (ABI 4)
const ACCESS_NET_CONNECT_TCP: u64 = 1 << 1; // LANDLOCK_ACCESS_NET_CONNECT_TCP (ABI 4)

/// What the inspector may do in `TMPDIR`: the files that the engine makes there (create, write, read, truncate,
/// remove) and the file of a failed start. It may not make a directory, list one, link, rename out of it or execute
/// anything.
const TMP_DIR_ACCESS: u64 = ACCESS_FS_READ_FILE
    | ACCESS_FS_WRITE_FILE
    | ACCESS_FS_MAKE_REG
    | ACCESS_FS_REMOVE_FILE
    | ACCESS_FS_TRUNCATE;

const CREATE_RULESET_VERSION: c_long = 1; // LANDLOCK_CREATE_RULESET_VERSION
const RULE_PATH_BENEATH: c_long = 1; // LANDLOCK_RULE_PATH_BENEATH
const CAPABILITY_VERSION_3: u32 = 0x2008_0522; // _LINUX_CAPABILITY_VERSION_3
const NONE: c_long = 0;
const NO_ARGUMENT: c_ulong = 0;
const NO_NEW_PRIVS_ON: c_ulong = 1;
const AMBIENT_CLEAR_ALL: c_ulong = libc::PR_CAP_AMBIENT_CLEAR_ALL as c_ulong;

/// struct landlock_ruleset_attr: the file rights, the TCP rights and the scopes that a rule set handles, 24 bytes. A
/// kernel that knows fewer fields accepts the longer struct while the extra bytes are zero; `scoped` stays 0 (nothing
/// is scoped).
#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

/// struct landlock_path_beneath_attr, packed to 12 bytes.
#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// struct __user_cap_header_struct: the version and the thread (0 is the calling thread).
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

/// struct __user_cap_data_struct: 32 capabilities of the effective, permitted and inheritable sets. There are two of
/// them in version 3.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

unsafe extern "C" {
    /// The time zone is read from a file on first use (`TZ`, else `/etc/localtime`).
    fn tzset();
}

/// Why the process could not be restricted. The text holds no path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The process has more than one thread.
    Threads,
    /// The kernel has no Landlock: it is built without it, or has it switched off.
    NoLandlock,
    /// The kernel gave a Landlock version that makes no sense.
    Version(c_long),
    /// A system call failed: its name and its errno.
    Call { call: &'static str, errno: c_int },
}

impl Error {
    /// A failure of `call`, whose errno is read now: call it right after the system call that failed.
    fn call(call: &'static str) -> Error {
        Error::Call {
            call,
            errno: last_errno(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Threads => f.write_str("the process has more than one thread"),
            Error::NoLandlock => f.write_str("landlock is not available"),
            Error::Version(v) => write!(f, "landlock version: unexpected value {v}"),
            Error::Call { call, errno } => {
                write!(f, "{call}: {}", io::Error::from_raw_os_error(*errno))
            }
        }
    }
}

impl std::error::Error for Error {}

fn last_errno() -> c_int {
    io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

/// The proof that the process has restricted itself. Only `restrict` makes one (a test can make one for a process
/// that it does not restrict, see `assumed`), so what asks for it is called by a process that has restricted
/// itself, and the order of the start cannot be got wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Restricted(());

impl Restricted {
    /// For a test that calls what asks for the proof in a process that is not restricted.
    #[cfg(test)]
    pub(crate) fn assumed() -> Restricted {
        Restricted(())
    }
}

/// Restricts the process as the description of this module says: no file outside `tmp_dir`, no TCP connect or bind (on
/// a kernel of Landlock ABI 4 or later), no capability, `no_new_privs`. The order is: the check that there is one
/// thread, the time zone, the Landlock ABI, the rule set, its one rule for `tmp_dir`, the capabilities, `no_new_privs`
/// and the restriction. A process with other threads is refused before anything is changed. After that a call that
/// fails leaves the process partly restricted, and nothing is undone: the caller must not go on. The value that
/// comes back is the proof that it is done.
pub fn restrict(tmp_dir: &Path) -> Result<Restricted, Error> {
    one_thread()?;
    // The time zone is read from a file on first use, and the process that starts the inspector passes no `TZ`. Read
    // after the restriction it would silently be UTC, and the time variables of the rules would change.
    // SAFETY: `tzset` takes no argument, and with one thread nothing else reads or changes the environment at the
    // same time.
    unsafe { tzset() };

    let abi = landlock_abi()?;
    let (fs_rights, net_rights) = handled_rights(abi);
    let ruleset = create_ruleset(fs_rights, net_rights)?;
    allow_tmp_dir(&ruleset, tmp_dir, fs_rights & TMP_DIR_ACCESS)?;
    drop_capabilities()?;
    // Needed by landlock_restrict_self for a process without CAP_SYS_ADMIN, and it stops a later exec from gaining
    // capabilities.
    // SAFETY: PR_SET_NO_NEW_PRIVS takes plain integers, no pointer.
    let set = unsafe {
        libc::prctl(
            libc::PR_SET_NO_NEW_PRIVS,
            NO_NEW_PRIVS_ON,
            NO_ARGUMENT,
            NO_ARGUMENT,
            NO_ARGUMENT,
        )
    };
    if set != 0 {
        return Err(Error::call("no_new_privs"));
    }
    // SAFETY: `ruleset` is a live descriptor of a rule set; the flags are 0.
    let restricted = unsafe {
        libc::syscall(
            libc::SYS_landlock_restrict_self,
            c_long::from(ruleset.as_raw_fd()),
            NONE,
        )
    };
    if restricted != 0 {
        return Err(Error::call("landlock restrict"));
    }
    Ok(Restricted(()))
}

/// Requires that the process has no thread but the calling one: the Landlock rule set, `no_new_privs` and the
/// capability sets belong to the calling thread only. The threads are the entries of `/proc/self/task`; when they
/// cannot be counted the process is refused.
fn one_thread() -> Result<(), Error> {
    let count_error = |e: io::Error| Error::Call {
        call: "count the threads",
        errno: e.raw_os_error().unwrap_or(libc::EIO),
    };
    let mut threads = 0usize;
    for task in fs::read_dir("/proc/self/task").map_err(count_error)? {
        task.map_err(count_error)?;
        threads += 1;
    }
    if threads == 1 {
        Ok(())
    } else {
        Err(Error::Threads)
    }
}

/// Returns the highest Landlock ABI version of the kernel.
fn landlock_abi() -> Result<c_long, Error> {
    // SAFETY: with the version flag the call reads no attribute: the pointer is null and the size is 0.
    let version = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<RulesetAttr>(),
            NONE,
            CREATE_RULESET_VERSION,
        )
    };
    if version < 0 {
        return Err(abi_error(last_errno()));
    }
    if !(1..=1 << 16).contains(&version) {
        // The kernel gives a small positive number.
        return Err(Error::Version(version));
    }
    Ok(version)
}

/// Names the failure of the version query. ENOSYS is a kernel built without Landlock and EOPNOTSUPP one that has it
/// switched off at boot; any other errno (EPERM from a filter on system calls, for one) is reported as it is.
fn abi_error(errno: c_int) -> Error {
    if errno == libc::ENOSYS || errno == libc::EOPNOTSUPP {
        Error::NoLandlock
    } else {
        Error::Call {
            call: "landlock version",
            errno,
        }
    }
}

/// Returns the file and the TCP rights that a rule set handles on a kernel with the given ABI version: all that the
/// version knows, so that whatever a rule does not allow is refused. A version newer than the ones listed here adds
/// rights that this code does not know and so does not handle.
fn handled_rights(abi: c_long) -> (u64, u64) {
    let mut fs_rights = ACCESS_FS_BASE;
    let mut net_rights = 0;
    if abi >= 2 {
        fs_rights |= ACCESS_FS_REFER;
    }
    if abi >= 3 {
        fs_rights |= ACCESS_FS_TRUNCATE;
    }
    if abi >= 5 {
        fs_rights |= ACCESS_FS_IOCTL_DEV;
    }
    if abi >= 4 {
        net_rights = ACCESS_NET_BIND_TCP | ACCESS_NET_CONNECT_TCP;
    }
    (fs_rights, net_rights)
}

/// Makes a rule set that handles the given rights and returns its descriptor (close-on-exec). It has no TCP rule, so
/// a handled TCP right is refused for every port.
fn create_ruleset(fs_rights: u64, net_rights: u64) -> Result<OwnedFd, Error> {
    let attr = RulesetAttr {
        handled_access_fs: fs_rights,
        handled_access_net: net_rights,
        scoped: 0,
    };
    // SAFETY: `attr` is a live struct of the size that is passed.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &raw const attr,
            size_of::<RulesetAttr>(),
            NONE,
        )
    };
    if fd < 0 {
        return Err(Error::call("landlock ruleset"));
    }
    let Ok(fd) = c_int::try_from(fd) else {
        return Err(Error::Call {
            call: "landlock ruleset",
            errno: libc::EOVERFLOW,
        });
    };
    // SAFETY: the kernel returned `fd` as a new descriptor that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Adds the one rule of the rule set: the access of `allowed` to everything beneath `dir`. `dir` is opened as a
/// directory (`O_PATH`) and not through a link, and the descriptor is closed when the rule is added; the error is an
/// errno, so it holds no path.
fn allow_tmp_dir(ruleset: &OwnedFd, dir: &Path, allowed: u64) -> Result<(), Error> {
    // An O_PATH descriptor ignores the access mode that std asks for.
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(dir)
        .map_err(|e| Error::Call {
            call: "open TMPDIR",
            errno: e.raw_os_error().unwrap_or(libc::EIO),
        })?;
    let attr = PathBeneathAttr {
        allowed_access: allowed,
        parent_fd: dir.as_raw_fd(),
    };
    // SAFETY: `ruleset` and `dir` are live descriptors and `attr` is a live struct that holds the descriptor of `dir`.
    let added = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            c_long::from(ruleset.as_raw_fd()),
            RULE_PATH_BENEATH,
            &raw const attr,
            NONE,
        )
    };
    if added != 0 {
        return Err(Error::call("landlock rule"));
    }
    Ok(())
}

/// Empties the ambient set and then the effective, permitted and inheritable sets. The bounding set stays: changing
/// it needs CAP_SETPCAP, and with `no_new_privs` and an empty permitted set an exec cannot bring anything back.
fn drop_capabilities() -> Result<(), Error> {
    // SAFETY: PR_CAP_AMBIENT_CLEAR_ALL takes plain integers, no pointer.
    let cleared = unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            AMBIENT_CLEAR_ALL,
            NO_ARGUMENT,
            NO_ARGUMENT,
            NO_ARGUMENT,
        )
    };
    if cleared != 0 {
        return Err(Error::call("clear ambient capabilities"));
    }
    let header = CapHeader {
        version: CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [CapData::default(); 2];
    // SAFETY: `header` is a live struct and `data` has the two structs that version 3 reads.
    let dropped =
        unsafe { libc::syscall(libc::SYS_capset, &raw const header, data.as_ptr(), NONE) };
    if dropped != 0 {
        return Err(Error::call("drop capabilities"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
