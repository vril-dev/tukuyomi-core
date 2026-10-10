//! The operator's configuration of the kernel and its check.
//!
//! `check` looks at the values only, never at the file system (`start.rs` does that at each start). The limits
//! below (`MAX_WAIT`, `MAX_TICK`, `MAX_TMP_ROOT`) only stop a wrong setting; they are not recommended values and
//! there are no defaults.

use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::codec;

/// Longest accepted time. A guard against a wrong setting, not a recommendation.
pub(crate) const MAX_WAIT: Duration = Duration::from_secs(3600);
/// Longest accepted idle wait of one step.
pub(crate) const MAX_TICK: Duration = Duration::from_secs(1);
/// Longest accepted `tmp_root` in bytes: the per-start directory name and the inspector's own temporary file
/// names must stay inside the Linux `PATH_MAX`.
pub(crate) const MAX_TMP_ROOT: usize = 3840;

/// Everything the kernel needs. No `Default`: every value is chosen by the operator and checked by `check`.
#[derive(Clone, Debug)]
pub struct Config {
    /// Absolute clean path of the Go inspector executable.
    pub inspector: PathBuf,
    /// Absolute clean path of the rules file (the inspector's only argument).
    pub rules: PathBuf,
    /// SHA-256 of the rules file bytes; HELLO must report the same.
    pub rules_sha256: [u8; 32],
    /// Existing real directory, owned by this process's user, no group or other bits.
    pub tmp_root: PathBuf,
    pub gomaxprocs: u16,
    pub gomemlimit: u64,
    /// Concurrent transactions.
    pub slots: usize,
    /// Requests waiting for a slot (new intake).
    pub wait_queue: usize,
    /// Request records alive at once (undecided, decided but not delivered, delivered but slot held).
    pub records: usize,
    /// Discarded responses per incarnation before a connection fault.
    pub discard_limit: u32,
    /// Longest idle wait of one step.
    pub tick: Duration,
    /// From just before `Command::spawn` to the whole HELLO frame.
    pub hello_wait: Duration,
    /// One frame write; the rest of one frame read after its first byte.
    pub frame_io: Duration,
    /// From the writer's take of TX_BEGIN or BODY_END.
    pub verdict_wait: Duration,
    /// From submit to the writer's take of TX_BEGIN.
    pub wait_deadline: Duration,
    /// From writing TX_END to CLOSED.
    pub closed_wait: Duration,
    /// Stop threshold of a held transaction (state.rs `StopOrigin`).
    pub stop_after: Duration,
    /// From DRAIN to the whole BYE frame.
    pub drain_wait: Duration,
    /// The inspector's own exit after BYE or a lost connection, before SIGKILL.
    pub exit_wait: Duration,
    /// After SIGKILL, until the exit must have been seen.
    pub kill_grace: Duration,
    /// Restart budget for the Supervisor's whole life (0: never restart).
    pub restarts: u32,
}

/// The first rule of `Config::check` that a value breaks: a fixed short English text, never a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigError(pub &'static str);

/// A path argument or `TMPDIR` must be absolute and already clean: Go requires `filepath.Clean(p) == p`
/// (main.go `parseConfig`, `checkTmpDir`). No empty, `.` or `..` component, no trailing slash, no NUL, and
/// shorter than the Linux `PATH_MAX`.
pub(crate) fn clean_abs(p: &Path) -> bool {
    let b = p.as_os_str().as_bytes();
    b.len() > 1
        && b.len() < 4096
        && b[0] == b'/'
        && !b.contains(&0)
        && b[1..]
            .split(|&c| c == b'/')
            .all(|s| !s.is_empty() && s != b"." && s != b"..")
}

impl Config {
    /// Refuses what Go would refuse at start (exit 14) or what the start could not pass faithfully, and a time
    /// or a count outside its range. The first broken rule is returned, in the order of the checks below. It
    /// does not look at the file system.
    pub fn check(&self) -> Result<(), ConfigError> {
        if !clean_abs(&self.inspector) {
            return Err(ConfigError("inspector path is not an absolute clean path"));
        }
        if !clean_abs(&self.rules) {
            return Err(ConfigError("rules path is not an absolute clean path"));
        }
        if !clean_abs(&self.tmp_root) || self.tmp_root.to_str().is_none() {
            return Err(ConfigError("tmp_root is not an absolute clean UTF-8 path"));
        }
        if self.tmp_root.as_os_str().as_bytes().len() > MAX_TMP_ROOT {
            return Err(ConfigError("tmp_root is too long"));
        }
        if self.gomaxprocs == 0 {
            return Err(ConfigError("gomaxprocs is 0"));
        }
        if self.gomemlimit == 0 || i64::try_from(self.gomemlimit).is_err() {
            return Err(ConfigError("gomemlimit is out of range"));
        }
        if !(1..=usize::from(codec::MAX_CONCUR_TX)).contains(&self.slots) {
            return Err(ConfigError("slots is out of range"));
        }
        if self.wait_queue == 0 {
            return Err(ConfigError("wait_queue is 0"));
        }
        match self.slots.checked_add(self.wait_queue) {
            Some(n) if self.records >= n => {}
            _ => return Err(ConfigError("records is below slots plus wait_queue")),
        }
        // The engine counts discarded responses with a saturating add that stops at `u32::MAX` and compares
        // with `> discard_limit` afterwards: at `u32::MAX` that is never true.
        if self.discard_limit == u32::MAX {
            return Err(ConfigError("discard_limit must be below u32::MAX"));
        }
        let times = [
            ("tick is out of range", self.tick),
            ("hello_wait is out of range", self.hello_wait),
            ("frame_io is out of range", self.frame_io),
            ("verdict_wait is out of range", self.verdict_wait),
            ("wait_deadline is out of range", self.wait_deadline),
            ("closed_wait is out of range", self.closed_wait),
            ("stop_after is out of range", self.stop_after),
            ("drain_wait is out of range", self.drain_wait),
            ("exit_wait is out of range", self.exit_wait),
            ("kill_grace is out of range", self.kill_grace),
        ];
        for (msg, d) in times {
            if d.is_zero() || d > MAX_WAIT {
                return Err(ConfigError(msg));
            }
        }
        if self.tick > MAX_TICK {
            return Err(ConfigError("tick is above the longest tick"));
        }
        if times.iter().any(|&(_, d)| self.tick > d) {
            return Err(ConfigError("tick is above another time"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_abs_accepts_only_absolute_clean_paths() {
        for good in ["/w", "/w/tmp", "/w/a.b/c-d", "/..w"] {
            assert!(clean_abs(Path::new(good)), "{good:?}");
        }
        for bad in [
            "", "/", "w/x", "/w/", "/w//x", "/w/./x", "/w/../x", "/w/x\0y", "//w",
        ] {
            assert!(!clean_abs(Path::new(bad)), "{bad:?}");
        }
        let long = format!("/{}", "a".repeat(4094));
        assert!(clean_abs(Path::new(&long)));
        let long = format!("/{}", "a".repeat(4095));
        assert!(!clean_abs(Path::new(&long)));
    }
}
