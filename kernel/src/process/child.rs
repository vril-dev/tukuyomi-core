//! Direct start of the Go inspector as the host's own child, and its bounded stop.
//!
//! Start (`spawn`): `UnixStream::pair()` makes the socketpair, and `Command::spawn` starts the inspector itself, with
//! the child's end as fd 0. No shell, `timeout` or other middle process: the inspector's `SO_PEERCRED` check wants the
//! peer pid to be its parent (inspector/main.go `checkPeer`: uid equals the euid and pid equals `getppid()`), and an
//! `exec` by this process keeps that. The command is dropped right after `spawn`, because it holds its own copy of the
//! child's end until then; with that closed, the inspector's death is an EOF on our end. The environment is cleared and
//! set to exactly `child_env`; stdout and stderr are `/dev/null` (the product does not read the inspector's output).
//! The inspector gets its own process group (`CommandExt::process_group` is the stable std API; `setpgid` runs in the
//! direct child before `exec`, so the parent pid is unchanged). A signal sent to the host's group (for example by
//! `timeout`) then does not kill the inspector in the middle of a Close: it sees the EOF and closes down by itself
//! (exit 12 or 13).
//!
//! Stop (`kill`, `try_exit`): only this module's own `std::process::Child` is signalled or waited for, and only with
//! SIGKILL through `Child::kill`. No pid is given to another command, no process group or other pid is signalled. A
//! pid cannot be reused before the own child is reaped, so the signal always reaches the process that was started. The
//! exit is confirmed by one non-blocking `try_wait` per `try_exit` call; the caller decides when to ask and when to
//! kill. The result is kept, so a second `try_exit` returns the same `Exit` and neither waits nor kills again. `Drop`
//! reaps a child whose exit was never seen (an error path or a panic) once, with a bounded kill: SIGKILL, then
//! `try_wait` every `POLL` until `kill_grace`; the result is not reported.
//!
//! This module touches no file except `/dev/urandom`. The per-start `TMPDIR` is created, checked and removed by
//! `start.rs`; the inspector checks it itself (inspector/main.go `checkTmpDir`).
#![forbid(unsafe_code)]

use std::fs::File;
use std::io::{self, ErrorKind, Read};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Sleep between two `try_wait` calls of the `Drop` reap.
const POLL: Duration = Duration::from_millis(5);

/// `base + d`, or `base` itself when the sum does not fit in an `Instant` (an expired deadline: fail closed).
fn after(base: Instant, d: Duration) -> Instant {
    base.checked_add(d).unwrap_or(base)
}

/// What `spawn` needs. All paths are absolute and clean (checked by `Config::check`); `tmpdir` is the per-start
/// directory made by `start.rs`.
pub(crate) struct Spec<'a> {
    pub inspector: &'a Path,
    /// The rules file: the only argument of the inspector.
    pub rules: &'a Path,
    pub tmpdir: &'a Path,
    /// `GOMAXPROCS`; HELLO reports it.
    pub gomaxprocs: u16,
    /// `GOMEMLIMIT` in bytes; HELLO reports it as the memory limit.
    pub gomemlimit: u64,
    /// After SIGKILL, how long `Drop` tries to reap.
    pub kill_grace: Duration,
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(char::from(DIGITS[usize::from(b >> 4)]));
        s.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    s
}

/// The whole environment of the inspector, to be set after `env_clear` (nothing else is inherited). Formats are
/// exact, as in inspector/main.go `parseConfig`: lowercase hex of fixed width, big-endian (`TKV0_RUN_ID` 16 digits,
/// `TKV0_INCARNATION` 8, `TKV0_NONCE` 32), `TMPDIR` the per-start directory. `GOMEMLIMIT` is plain decimal bytes.
/// A `TMPDIR` that is not UTF-8 is an error: it could only be passed with replacement characters, which is another
/// directory.
pub(crate) fn child_env(
    spec: &Spec<'_>,
    run: u64,
    inc: u32,
    nonce: &[u8; 16],
) -> Result<Vec<(&'static str, String)>, &'static str> {
    let tmpdir = spec.tmpdir.to_str().ok_or("tmpdir is not UTF-8")?;
    Ok(vec![
        ("TKV0_RUN_ID", hex(&run.to_be_bytes())),
        ("TKV0_INCARNATION", hex(&inc.to_be_bytes())),
        ("TKV0_NONCE", hex(nonce)),
        ("TMPDIR", tmpdir.to_owned()),
        ("GOMAXPROCS", spec.gomaxprocs.to_string()),
        ("GOMEMLIMIT", spec.gomemlimit.to_string()),
    ])
}

fn urandom<const N: usize>() -> io::Result<[u8; N]> {
    let mut b = [0u8; N];
    File::open("/dev/urandom")?.read_exact(&mut b)?;
    Ok(b)
}

/// A new run identifier (`TKV0_RUN_ID`, and the `run` of every frame).
pub(crate) fn fresh_run() -> io::Result<u64> {
    Ok(u64::from_be_bytes(urandom::<8>()?))
}

/// A new nonce, for every spawn. It ties one start to its HELLO (it is not a secret: the same user can read the
/// environment).
pub(crate) fn fresh_nonce() -> io::Result<[u8; 16]> {
    urandom::<16>()
}

/// How the inspector ended, as confirmed by `Inspector::try_exit`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Exit {
    /// The status of the own child as returned by the wait. `ExitStatusExt::signal` tells a kill by signal.
    pub status: ExitStatus,
    /// This module sent SIGKILL to the child (`kill`). It says what was done, not why the child ended: `status`
    /// does (the child may have ended just before the signal).
    pub killed: bool,
}

/// The started inspector. Owns its `Child`; the caller owns the socket returned with it.
pub(crate) struct Inspector {
    child: Child,
    pid: u32,
    killed: bool,
    exit: Option<Exit>,
    kill_grace: Duration,
}

/// Starts the inspector directly with the socketpair's child end as fd 0 and returns it with our end of the pair.
/// May be called from any thread (the peer pid the inspector checks is the process id).
/// Ok: the process exists and is owned by the returned `Inspector`; nothing after `Command::spawn` can fail. Err: no
/// process was started and our end of the pair is closed.
pub(crate) fn spawn(
    spec: &Spec<'_>,
    run: u64,
    inc: u32,
    nonce: &[u8; 16],
) -> io::Result<(Inspector, UnixStream)> {
    // A bare name would be searched in this process's PATH: only an absolute path names one program.
    if !spec.inspector.is_absolute() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "inspector path is not absolute",
        ));
    }
    let env = child_env(spec, run, inc, nonce)
        .map_err(|why| io::Error::new(ErrorKind::InvalidInput, why))?;
    let (mine, theirs) = UnixStream::pair()?;
    let mut cmd = Command::new(spec.inspector);
    cmd.arg(spec.rules)
        .env_clear()
        .envs(env)
        .stdin(Stdio::from(OwnedFd::from(theirs)))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    let spawned = cmd.spawn();
    // The command still holds the child's end of the pair: close it whether or not the start worked.
    drop(cmd);
    let child = spawned?;
    let pid = child.id();
    Ok((
        Inspector {
            child,
            pid,
            killed: false,
            exit: None,
            kill_grace: spec.kill_grace,
        },
        mine,
    ))
}

impl Inspector {
    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }

    /// Sends SIGKILL to the own child. Does not wait. A no-op once the exit is known (the pid is no longer ours).
    /// Before that the pid cannot be reused, even if the child has already exited and is not reaped.
    pub(crate) fn kill(&mut self) -> io::Result<()> {
        if self.exit.is_some() {
            return Ok(());
        }
        self.child.kill()?;
        self.killed = true;
        Ok(())
    }

    /// One non-blocking `try_wait` of the own child: `None` while it runs. The exit is kept and returned again by
    /// every later call, without another wait.
    pub(crate) fn try_exit(&mut self) -> io::Result<Option<Exit>> {
        if self.exit.is_some() {
            return Ok(self.exit);
        }
        if let Some(status) = self.child.try_wait()? {
            self.exit = Some(Exit {
                status,
                killed: self.killed,
            });
        }
        Ok(self.exit)
    }
}

impl Drop for Inspector {
    fn drop(&mut self) {
        if self.exit.is_none() {
            // The exit was never seen (an error path or a panic): kill the own child and wait for it, bounded. A
            // failed kill is not a reason to skip the wait; the result is not reported.
            let _ = self.kill();
            let _ = poll_exit(&mut self.child, after(Instant::now(), self.kill_grace));
        }
    }
}

/// `try_wait` until the child has exited (`Some`) or `deadline` is reached (`None`). Always tries once.
fn poll_exit(child: &mut Child, deadline: Instant) -> io::Result<Option<ExitStatus>> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        let now = Instant::now();
        if now >= deadline {
            return Ok(None);
        }
        thread::sleep(POLL.min(deadline - now));
    }
}

#[cfg(test)]
mod tests;
