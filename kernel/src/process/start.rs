//! The per-start directory and the owned start and stop of one inspector process.
//!
//! `StartDir` is `<root>/insp-<run>-<inc>`, created by one `mkdir` of this call alone with mode 0700, identified by
//! `lstat` (device, inode, owner, a real directory) and removed only when the same `lstat` still says the same. There
//! is no `Drop` that removes it: a directory goes away only through `StartDir::remove`, which the owner calls after the
//! process exit was confirmed (`Stopping::step`) or when no process was started (`launch`). A `Start` or `Stopping`
//! that is dropped instead of being stopped kills and reaps its child (`Inspector`'s `Drop`) and leaves the directory.
//!
//! What is not checked, and is the operator's responsibility: the ancestors of the root (a root is a real directory
//! with no group or other bit, so no other user can create or replace a name inside it). What is left as a race:
//! std has no `mkdirat`, `fstatat` or `unlinkat` relative to the created directory's file descriptor, so the identity
//! is read by `lstat` after `mkdir` and again before the removal. Between the two a replacement of the name can only be
//! made by a process of the same uid or a privileged one, which could do the same damage without this race. A
//! replaced name is never removed (`remove` fails and hands the directory back); a name that cannot be identified
//! after `mkdir` is left alone for good (`LaunchError::Unidentified`). The operator's root must also not be
//! `setgid`: a directory made in it would inherit the bit, fail the mode check and be removed again, so every start
//! would fail closed with `Step::TmpDir`.
//!
//! The owner of the created directory is taken as this process's file system uid (std has no `geteuid`, and nothing
//! outside the file system is read for it); the root must be owned by the same uid. The inspector checks its
//! `TMPDIR` itself (inspector/main.go `checkTmpDir`).
//!
//! An inspector that refuses to start (exit code 10, 11 or 14) may leave one line in `start-failure` in its start
//! directory. `Stopping::step` reads it once, after the exit was seen and before the directory is removed
//! (`StartDir::read_failure`): the same identity checks as for the removal, `lstat` of a regular file, then the open
//! and `fstat` of that same file, at most `FAILURE_MAX` bytes. Anything else leaves no detail. std cannot open
//! without waiting (`O_NONBLOCK`) and this crate has no `unsafe`, so a process that was this inspector's user could
//! replace the name by a FIFO between its exit and this read and block the read; no other user can make a name in
//! the directory, and the same user could do much more damage.
#![forbid(unsafe_code)]

use std::fs::{self, File};
use std::io::Read;
use std::net::Shutdown;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::process::child::{self, Exit, Inspector, Spec};

/// The file of the start directory that an inspector which refuses to start may leave.
const FAILURE_FILE: &str = "start-failure";
/// The most bytes read from it; a longer file leaves no detail.
const FAILURE_MAX: u64 = 512;

/// The exit code of a refusal that is final (inspector/main.go: 10 the peer, 11 the rules, 14 the start-up input or a
/// sandbox that cannot be set up), or `None` for any other end, a signal included. The supervisor does not restart
/// after a refusal, and the inspector may have left `start-failure`.
pub(crate) fn refusal(exit: &Exit) -> Option<i32> {
    match exit.status.code() {
        code @ Some(10 | 11 | 14) => code,
        _ => None,
    }
}

/// A per-start directory this process created and can still identify.
pub(crate) struct StartDir {
    path: PathBuf,
    dev: u64,
    ino: u64,
    uid: u32,
}

/// Which step of `launch` an error belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    Random,
    TmpDir,
    Spawn,
}

pub(crate) enum LaunchError {
    /// No process exists and nothing created by this attempt is left.
    Clean { step: Step, why: &'static str },
    /// No process exists, but the directory this attempt created could not be removed: handed back.
    DirLeft {
        #[cfg_attr(
            not(test),
            expect(dead_code, reason = "the supervisor keeps the directory, not the step")
        )]
        step: Step,
        dir: StartDir,
        #[cfg_attr(
            not(test),
            expect(
                dead_code,
                reason = "the supervisor keeps the directory, not the reason"
            )
        )]
        why: &'static str,
    },
    /// No process exists. mkdir succeeded, but what is at the name could not be identified as the created
    /// directory (lstat failed, or not a real directory): nothing is removed, ever. Only from `StartDir::create`.
    Unidentified {
        #[cfg_attr(
            not(test),
            expect(dead_code, reason = "the supervisor keeps the fact, not the reason")
        )]
        why: &'static str,
    },
}

impl StartDir {
    /// `<root>/insp-<run 16 lowercase hex>-<inc 8 lowercase hex>`, mode 0700, created by this call alone.
    /// Err is always for `Step::TmpDir`: `Clean`, `DirLeft` (identified, handed back) or `Unidentified`.
    /// `root` is an absolute clean path (`Config::check`); its ancestors are not examined.
    pub(crate) fn create(root: &Path, run: u64, inc: u32) -> Result<StartDir, LaunchError> {
        let clean = |why: &'static str| LaunchError::Clean {
            step: Step::TmpDir,
            why,
        };
        // 1. The root: a real directory (not a link) without group or other bits. Nothing is created yet.
        let rm = fs::symlink_metadata(root).map_err(|_| clean("tmp root not accessible"))?;
        if !rm.file_type().is_dir() {
            return Err(clean("tmp root is not a real directory"));
        }
        if rm.mode() & 0o077 != 0 {
            return Err(clean("tmp root has group or other bits"));
        }
        // 2. One mkdir. Any error means nothing was created; whatever is at the name is not touched.
        let path = root.join(format!("insp-{run:016x}-{inc:08x}"));
        if let Err(e) = fs::DirBuilder::new()
            .recursive(false)
            .mode(0o700)
            .create(&path)
        {
            return Err(clean(if e.kind() == std::io::ErrorKind::AlreadyExists {
                "start dir already exists"
            } else {
                "start dir not created"
            }));
        }
        // 3. The identity, straight after the mkdir. If it cannot be established, the name is not removed.
        let dm = match fs::symlink_metadata(&path) {
            Err(_) => {
                return Err(LaunchError::Unidentified {
                    why: "start dir not identified after create",
                });
            }
            Ok(m) if !m.file_type().is_dir() => {
                return Err(LaunchError::Unidentified {
                    why: "start dir replaced after create",
                });
            }
            Ok(m) => m,
        };
        let dir = StartDir {
            path,
            dev: dm.dev(),
            ino: dm.ino(),
            uid: dm.uid(),
        };
        // 4. The identified directory must be exactly what was asked for (a umask or an inherited bit can change
        // the mode) and owned like the root.
        let why = if dm.mode() & 0o7777 != 0o700 {
            "start dir mode differs"
        } else if dm.uid() != rm.uid() {
            "start dir owner differs from tmp root"
        } else {
            return Ok(dir);
        };
        match dir.remove() {
            Ok(()) => Err(clean(why)),
            Err((dir, _)) => Err(LaunchError::DirLeft {
                step: Step::TmpDir,
                dir,
                why,
            }),
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// The bytes of `start-failure`, or `None` for anything else: the directory is no longer the one created, the
    /// name is absent, a link or not a regular file, it changes between the `lstat` and the open, it is over
    /// `FAILURE_MAX` bytes, empty, or changes its size while it is read.
    fn read_failure(&self) -> Option<Vec<u8>> {
        let dm = fs::symlink_metadata(&self.path).ok()?;
        if !(dm.file_type().is_dir()
            && dm.dev() == self.dev
            && dm.ino() == self.ino
            && dm.uid() == self.uid)
        {
            return None;
        }
        let path = self.path.join(FAILURE_FILE);
        let seen = fs::symlink_metadata(&path).ok()?;
        if !seen.file_type().is_file() {
            return None;
        }
        let file = File::open(&path).ok()?;
        let opened = file.metadata().ok()?;
        if !(opened.is_file()
            && opened.dev() == seen.dev()
            && opened.ino() == seen.ino()
            && opened.len() <= FAILURE_MAX)
        {
            return None;
        }
        let mut bytes = Vec::new();
        file.take(opened.len().saturating_add(1))
            .read_to_end(&mut bytes)
            .ok()?;
        if u64::try_from(bytes.len()).ok() != Some(opened.len()) {
            return None;
        }
        (!bytes.is_empty()).then_some(bytes)
    }

    /// Removes the directory and everything in it, only if it is still the one created. `remove_dir_all` does not
    /// follow links. Err hands the directory back, untouched when it changed or could not be identified, possibly
    /// partly emptied when the removal itself failed; a later call tries again.
    pub(crate) fn remove(self) -> Result<(), (StartDir, &'static str)> {
        match fs::symlink_metadata(&self.path) {
            Err(_) => return Err((self, "start dir not identified before removal")),
            Ok(m)
                if !(m.file_type().is_dir()
                    && m.dev() == self.dev
                    && m.ino() == self.ino
                    && m.uid() == self.uid) =>
            {
                return Err((self, "start dir changed before removal"));
            }
            Ok(_) => {}
        }
        match fs::remove_dir_all(&self.path) {
            Ok(()) => Ok(()),
            Err(_) => Err((self, "start dir removal failed")),
        }
    }
}

/// One started inspector with its per-start directory and our end of the connection. Has no `Drop` of its own:
/// dropping it kills and reaps the child (`Inspector`) and leaves the directory.
pub(crate) struct Start {
    pub(crate) inc: u32,
    pub(crate) nonce: [u8; 16],
    pub(crate) pid: u32,
    /// Just before `child::spawn`: the HELLO wait starts here. The socketpair and the environment are made inside
    /// `spawn` before `Command::spawn`, so the wait is only a little shorter than counted from the exec.
    pub(crate) started: Instant,
    pub(crate) stream: UnixStream,
    ins: Inspector,
    dir: StartDir,
    kill_grace: Duration,
}

/// Nonce, then directory, then process. Every failure hands back what it still owns; Ok owns the process.
pub(crate) fn launch(cfg: &Config, run: u64, inc: u32) -> Result<Start, LaunchError> {
    let nonce = child::fresh_nonce().map_err(|_| LaunchError::Clean {
        step: Step::Random,
        why: "nonce not available",
    })?;
    let dir = StartDir::create(&cfg.tmp_root, run, inc)?;
    let spec = Spec {
        inspector: &cfg.inspector,
        rules: &cfg.rules,
        tmpdir: dir.path(),
        gomaxprocs: cfg.gomaxprocs,
        gomemlimit: cfg.gomemlimit,
        kill_grace: cfg.kill_grace,
    };
    let started = Instant::now();
    let (ins, stream) = match child::spawn(&spec, run, inc, &nonce) {
        Ok(p) => p,
        Err(_) => {
            // No process exists, so the directory this call made is removed, or handed back if that fails.
            let why = "inspector not started";
            return Err(match dir.remove() {
                Ok(()) => LaunchError::Clean {
                    step: Step::Spawn,
                    why,
                },
                Err((dir, _)) => LaunchError::DirLeft {
                    step: Step::Spawn,
                    dir,
                    why,
                },
            });
        }
    };
    // Nothing after the spawn can fail: the process is owned by `ins` from here.
    let pid = ins.pid();
    Ok(Start {
        inc,
        nonce,
        pid,
        started,
        stream,
        ins,
        dir,
        kill_grace: cfg.kill_grace,
    })
}

impl Start {
    /// Shuts our end down and drops it (nothing of this start can be read after this), then stops:
    /// the own exit is awaited until `kill_at`, then SIGKILL, then until (kill time + kill_grace).
    pub(crate) fn stop(self, kill_at: Instant) -> Stopping {
        let Start {
            inc,
            stream,
            ins,
            dir,
            kill_grace,
            ..
        } = self;
        // Both directions: the inspector sees the EOF whatever it is doing. An error here changes nothing.
        let _ = stream.shutdown(Shutdown::Both);
        drop(stream);
        Stopping {
            inc,
            ins,
            dir,
            kill_at,
            give_up: None,
            kill_grace,
        }
    }

    /// Test seam: the owned SIGKILL (the process dies as if it were lost).
    #[cfg(test)]
    pub(crate) fn kill_now(&mut self) -> std::io::Result<()> {
        self.ins.kill()
    }
}

/// A stop in progress. Owns the child and the directory until `step` returns `Done` or `DirLeft`.
pub(crate) struct Stopping {
    inc: u32,
    ins: Inspector,
    dir: StartDir,
    kill_at: Instant,
    /// Set once SIGKILL was sent (by `step` or `again`): the end of the wait for the exit.
    give_up: Option<Instant>,
    kill_grace: Duration,
}

pub(crate) enum Stopped {
    Waiting(Stopping),
    /// Exit seen and directory removed. `detail` is the line the inspector left in `start-failure`, only after a
    /// refusal (`refusal`).
    Done {
        inc: u32,
        exit: Exit,
        detail: Option<Vec<u8>>,
    },
    /// Exit seen, directory kept.
    DirLeft {
        inc: u32,
        exit: Exit,
        detail: Option<Vec<u8>>,
        dir: StartDir,
        #[cfg_attr(
            not(test),
            expect(
                dead_code,
                reason = "the supervisor keeps the directory, not the reason"
            )
        )]
        why: &'static str,
    },
    /// Exit not seen: child and directory stay owned.
    Unreaped {
        left: Stopping,
        #[cfg_attr(
            not(test),
            expect(dead_code, reason = "the supervisor keeps the fact, not the reason")
        )]
        why: &'static str,
    },
}

impl Stopping {
    pub(crate) fn inc(&self) -> u32 {
        self.inc
    }

    /// One `try_exit`. Seen: the directory is removed (`Done`) or kept (`DirLeft`), and the `Stopping` is gone, so
    /// the exit is confirmed once. Not seen: SIGKILL once `now >= kill_at` (a failure is `Unreaped`, with the child
    /// still owned), then `give_up = now + kill_grace` (a sum that does not fit is `now`: due at once); `Unreaped`
    /// at `now >= give_up`. The exit check comes first, so a child that ended in time is `Done`, not `Unreaped`.
    /// Never calls `again`.
    pub(crate) fn step(mut self, now: Instant) -> Stopped {
        match self.ins.try_exit() {
            Ok(Some(exit)) => return self.finished(exit),
            Ok(None) => {}
            Err(_) => {
                return Stopped::Unreaped {
                    left: self,
                    why: "exit not seen: wait failed",
                };
            }
        }
        match self.give_up {
            None if now >= self.kill_at => {
                if self.ins.kill().is_err() {
                    return Stopped::Unreaped {
                        left: self,
                        why: "SIGKILL failed",
                    };
                }
                self.give_up = Some(now.checked_add(self.kill_grace).unwrap_or(now));
            }
            Some(at) if now >= at => {
                return Stopped::Unreaped {
                    left: self,
                    why: "exit not seen after SIGKILL",
                };
            }
            _ => {}
        }
        Stopped::Waiting(self)
    }

    /// The exit is seen: after a refusal `start-failure` is read, then the directory goes. `self.ins` is dropped here
    /// with its exit known (no kill, no wait).
    fn finished(self, exit: Exit) -> Stopped {
        let Stopping { inc, dir, .. } = self;
        let detail = refusal(&exit).and_then(|_| dir.read_failure());
        match dir.remove() {
            Ok(()) => Stopped::Done { inc, exit, detail },
            Err((dir, why)) => Stopped::DirLeft {
                inc,
                exit,
                detail,
                dir,
                why,
            },
        }
    }

    /// `kill_at`, or `give_up` after the kill.
    pub(crate) fn next_at(&self) -> Instant {
        self.give_up.unwrap_or(self.kill_at)
    }

    /// `kill_at = min(kill_at, at)`; no effect once SIGKILL was sent.
    pub(crate) fn kill_by(&mut self, at: Instant) {
        if self.give_up.is_none() {
            self.kill_at = self.kill_at.min(at);
        }
    }

    /// After `Unreaped`: SIGKILL again and `give_up = now + kill_grace` (a sum that does not fit is `now`). A failed
    /// kill is not reported here: the next `step` ends in `Unreaped` at `give_up` again.
    pub(crate) fn again(mut self, now: Instant) -> Stopping {
        let _ = self.ins.kill();
        self.give_up = Some(now.checked_add(self.kill_grace).unwrap_or(now));
        self
    }
}

#[cfg(test)]
mod tests;
