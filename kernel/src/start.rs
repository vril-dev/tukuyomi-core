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
#![forbid(unsafe_code)]

use std::fs;
use std::net::Shutdown;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::child::{self, Exit, Inspector, Spec};
use crate::config::Config;

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
    /// Exit seen and directory removed.
    Done {
        inc: u32,
        exit: Exit,
    },
    /// Exit seen, directory kept.
    DirLeft {
        inc: u32,
        exit: Exit,
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

    /// The exit is seen: the directory goes now. `self.ins` is dropped here with its exit known (no kill, no wait).
    fn finished(self, exit: Exit) -> Stopped {
        let Stopping { inc, dir, .. } = self;
        match dir.remove() {
            Ok(()) => Stopped::Done { inc, exit },
            Err((dir, why)) => Stopped::DirLeft {
                inc,
                exit,
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
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::os::unix::process::ExitStatusExt;
    use std::thread;

    /// A fresh 0700 directory under the temp directory (`TMPDIR`), removed with everything in it when dropped.
    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> TestDir {
            let nonce: String = child::fresh_nonce()
                .unwrap()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            let path = std::env::temp_dir().join(format!("tk-start-test-{nonce}"));
            assert!(path.is_absolute(), "the temp directory must be absolute");
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            // A umask can only remove bits; make the mode exactly 0700.
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            TestDir(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn names(&self) -> Vec<OsString> {
            let mut v: Vec<OsString> = fs::read_dir(&self.0)
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect();
            v.sort();
            v
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn describe(e: &LaunchError) -> String {
        match e {
            LaunchError::Clean { step, why } => format!("Clean {step:?}: {why}"),
            LaunchError::DirLeft { step, dir, why } => {
                format!("DirLeft {step:?}: {why} ({})", dir.path().display())
            }
            LaunchError::Unidentified { why } => format!("Unidentified: {why}"),
        }
    }

    fn created(r: Result<StartDir, LaunchError>) -> StartDir {
        match r {
            Ok(d) => d,
            Err(e) => panic!("create failed: {}", describe(&e)),
        }
    }

    /// The reason of a `Clean { step: TmpDir }` error; anything else fails the test.
    fn tmp_dir_refusal(r: Result<StartDir, LaunchError>) -> &'static str {
        match r {
            Ok(d) => panic!("create succeeded: {}", d.path().display()),
            Err(LaunchError::Clean {
                step: Step::TmpDir,
                why,
            }) => why,
            Err(e) => panic!("other error: {}", describe(&e)),
        }
    }

    fn config(root: &Path, inspector: &str, rules: &str) -> Config {
        let s = Duration::from_secs(1);
        Config {
            inspector: PathBuf::from(inspector),
            rules: PathBuf::from(rules),
            rules_sha256: [0; 32],
            tmp_root: root.to_path_buf(),
            gomaxprocs: 1,
            gomemlimit: 256 << 20,
            slots: 1,
            wait_queue: 1,
            records: 2,
            discard_limit: 1,
            tick: Duration::from_millis(10),
            hello_wait: s,
            frame_io: s,
            verdict_wait: s,
            wait_deadline: s,
            closed_wait: s,
            stop_after: s,
            drain_wait: s,
            exit_wait: s,
            kill_grace: Duration::from_secs(5),
            restarts: 0,
            restart_window: s,
        }
    }

    /// `sleep 60`: it ignores its stdin and ends only when killed. Fails (not skips) when the program is missing.
    fn sleeper(root: &Path) -> Config {
        assert!(
            Path::new("/bin/sleep").is_file(),
            "these tests need /bin/sleep"
        );
        config(root, "/bin/sleep", "60")
    }

    /// `/bin/sh <script>` with the script written into `fixtures`.
    fn script(root: &Path, fixtures: &TestDir, text: &str) -> Config {
        assert!(Path::new("/bin/sh").is_file(), "these tests need /bin/sh");
        let file = fixtures.path().join("script.sh");
        fs::write(&file, text).unwrap();
        config(root, "/bin/sh", file.to_str().unwrap())
    }

    fn launch_ok(cfg: &Config, run: u64, inc: u32) -> Start {
        match launch(cfg, run, inc) {
            Ok(s) => s,
            Err(e) => panic!("launch failed: {}", describe(&e)),
        }
    }

    fn launch_err(cfg: &Config, run: u64, inc: u32) -> LaunchError {
        match launch(cfg, run, inc) {
            Ok(_) => panic!("launch succeeded"),
            Err(e) => e,
        }
    }

    /// Steps every few ms until the stop ends; fails the test after 10 s.
    fn drive(mut st: Stopping) -> Stopped {
        let limit = Instant::now() + Duration::from_secs(10);
        loop {
            match st.step(Instant::now()) {
                Stopped::Waiting(s) => st = s,
                other => return other,
            }
            assert!(Instant::now() < limit, "the stop did not end in 10 s");
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn done(s: Stopped) -> (u32, Exit) {
        match s {
            Stopped::Done { inc, exit } => (inc, exit),
            Stopped::Waiting(_) => panic!("Waiting"),
            Stopped::DirLeft { why, .. } => panic!("DirLeft: {why}"),
            Stopped::Unreaped { why, .. } => panic!("Unreaped: {why}"),
        }
    }

    fn gone(p: &Path) -> bool {
        matches!(fs::symlink_metadata(p), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
    }

    fn uid_of(p: &Path) -> u32 {
        fs::symlink_metadata(p).unwrap().uid()
    }

    // ---- StartDir::create ----

    #[test]
    fn create_makes_a_0700_directory_with_the_name() {
        let root = TestDir::new();
        let dir = created(StartDir::create(root.path(), 0x0123_4567_89ab_cdef, 0xa1));
        assert_eq!(
            dir.path(),
            root.path().join("insp-0123456789abcdef-000000a1")
        );
        let m = fs::symlink_metadata(dir.path()).unwrap();
        assert!(m.file_type().is_dir());
        assert_eq!(m.mode() & 0o7777, 0o700);
        assert_eq!(m.uid(), uid_of(root.path()));
        assert_eq!((m.dev(), m.ino(), m.uid()), (dir.dev, dir.ino, dir.uid));
        assert_eq!(root.names().len(), 1);
        dir.remove().ok().unwrap();
        assert!(root.names().is_empty());
        // Fixed width, lowercase, whatever the values.
        let dir = created(StartDir::create(root.path(), 0, u32::MAX));
        assert!(dir.path().ends_with("insp-0000000000000000-ffffffff"));
        dir.remove().ok().unwrap();
    }

    #[test]
    fn create_refuses_what_is_at_the_name_and_leaves_it_alone() {
        let root = TestDir::new();
        let other = TestDir::new();
        fs::write(other.path().join("keep"), b"outside").unwrap();
        let name = |inc: u32| root.path().join(format!("insp-{:016x}-{inc:08x}", 5u64));

        // A directory with a file in it.
        fs::create_dir(name(1)).unwrap();
        fs::write(name(1).join("f"), b"inside").unwrap();
        // A regular file.
        fs::write(name(2), b"file").unwrap();
        // A link to a directory elsewhere, and a dangling link.
        symlink(other.path(), name(3)).unwrap();
        symlink(other.path().join("absent"), name(4)).unwrap();

        for inc in 1..=4 {
            assert_eq!(
                tmp_dir_refusal(StartDir::create(root.path(), 5, inc)),
                "start dir already exists",
                "inc {inc}"
            );
        }
        assert_eq!(fs::read(name(1).join("f")).unwrap(), b"inside");
        assert_eq!(fs::read(name(2)).unwrap(), b"file");
        assert_eq!(fs::read_link(name(3)).unwrap(), other.path());
        assert_eq!(fs::read_link(name(4)).unwrap(), other.path().join("absent"));
        assert_eq!(fs::read(other.path().join("keep")).unwrap(), b"outside");
        assert_eq!(other.names().len(), 1);
        assert_eq!(root.names().len(), 4);
    }

    #[test]
    fn create_refuses_a_bad_root_and_makes_nothing() {
        let holder = TestDir::new();
        let real = holder.path().join("real");
        fs::DirBuilder::new().mode(0o700).create(&real).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();

        // A link to a good directory.
        let link = holder.path().join("link");
        symlink(&real, &link).unwrap();
        assert_eq!(
            tmp_dir_refusal(StartDir::create(&link, 1, 1)),
            "tmp root is not a real directory"
        );
        // A regular file, and a name that is not there.
        let file = holder.path().join("file");
        fs::write(&file, b"x").unwrap();
        assert_eq!(
            tmp_dir_refusal(StartDir::create(&file, 1, 1)),
            "tmp root is not a real directory"
        );
        assert_eq!(
            tmp_dir_refusal(StartDir::create(&holder.path().join("absent"), 1, 1)),
            "tmp root not accessible"
        );
        // Group or other bits, one at a time and together.
        for mode in [0o755, 0o750, 0o710, 0o705, 0o701, 0o770] {
            fs::set_permissions(&real, fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                tmp_dir_refusal(StartDir::create(&real, 1, 1)),
                "tmp root has group or other bits",
                "mode {mode:o}"
            );
        }
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(fs::read_dir(&real).unwrap().next().is_none());
    }

    /// A root that passes the checks but cannot be written: the one mkdir fails, and nothing is made or touched.
    #[test]
    fn create_reports_a_failed_mkdir_and_makes_nothing() {
        let root = TestDir::new();
        assert_ne!(
            uid_of(root.path()),
            0,
            "this test needs a user that is not root"
        );
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o500)).unwrap();
        let why = tmp_dir_refusal(StartDir::create(root.path(), 1, 1));
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(why, "start dir not created");
        assert!(root.names().is_empty());
    }

    /// The mode check after the identification, reached through an inherited bit: a directory made in a `setgid`
    /// root gets `setgid` too, so its mode is not 0700 and it is removed again. (A umask cannot be changed with std.)
    #[test]
    fn create_removes_a_directory_whose_mode_differs() {
        let root = TestDir::new();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o2700)).unwrap();
        assert_eq!(
            fs::symlink_metadata(root.path()).unwrap().mode() & 0o7777,
            0o2700,
            "this test needs a file system that keeps setgid on a directory"
        );
        assert_eq!(
            tmp_dir_refusal(StartDir::create(root.path(), 1, 1)),
            "start dir mode differs"
        );
        assert!(root.names().is_empty());
    }

    // ---- StartDir::remove ----

    #[test]
    fn remove_deletes_the_contents_and_does_not_follow_links() {
        let root = TestDir::new();
        let outside = TestDir::new();
        fs::write(outside.path().join("keep"), b"outside").unwrap();
        let dir = created(StartDir::create(root.path(), 7, 1));
        let p = dir.path().to_path_buf();
        fs::create_dir_all(p.join("a/b/c")).unwrap();
        fs::write(p.join("a/b/c/f"), b"1").unwrap();
        fs::write(p.join("g"), b"2").unwrap();
        symlink(outside.path(), p.join("a/link")).unwrap();
        dir.remove().ok().unwrap();
        assert!(gone(&p));
        assert!(root.names().is_empty());
        assert_eq!(fs::read(outside.path().join("keep")).unwrap(), b"outside");
    }

    #[test]
    fn remove_refuses_a_replaced_name_and_hands_the_directory_back() {
        let root = TestDir::new();
        let dir = created(StartDir::create(root.path(), 8, 1));
        let p = dir.path().to_path_buf();
        fs::write(p.join("mine"), b"original").unwrap();
        // The original is moved away (so a new one cannot get its inode number), then something else is at the name.
        let moved = root.path().join("moved");
        fs::rename(&p, &moved).unwrap();

        // (a) a link to a directory with a file in it.
        let target = root.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("t"), b"target").unwrap();
        symlink(&target, &p).unwrap();
        let (dir, why) = dir.remove().err().unwrap();
        assert_eq!(why, "start dir changed before removal");
        assert_eq!(fs::read_link(&p).unwrap(), target);
        assert_eq!(fs::read(target.join("t")).unwrap(), b"target");

        // (b) another real directory (not the one created).
        fs::remove_file(&p).unwrap();
        fs::create_dir(&p).unwrap();
        fs::write(p.join("other"), b"other").unwrap();
        let (dir, why) = dir.remove().err().unwrap();
        assert_eq!(why, "start dir changed before removal");
        assert_eq!(fs::read(p.join("other")).unwrap(), b"other");

        // (c) a regular file.
        fs::remove_dir_all(&p).unwrap();
        fs::write(&p, b"file").unwrap();
        let (dir, why) = dir.remove().err().unwrap();
        assert_eq!(why, "start dir changed before removal");
        assert_eq!(fs::read(&p).unwrap(), b"file");

        // (d) nothing at the name: it cannot be identified, so it is not claimed as removed.
        fs::remove_file(&p).unwrap();
        let (dir, why) = dir.remove().err().unwrap();
        assert_eq!(why, "start dir not identified before removal");

        // The directory was handed back each time: once the original is back, the removal works.
        fs::rename(&moved, &p).unwrap();
        dir.remove().ok().unwrap();
        assert!(gone(&p));
        assert_eq!(fs::read(target.join("t")).unwrap(), b"target");
    }

    // ---- launch ----

    #[test]
    fn a_missing_or_unusable_inspector_leaves_no_directory() {
        let root = TestDir::new();
        let fixtures = TestDir::new();
        let missing = fixtures.path().join("missing");
        let notexec = fixtures.path().join("notexec");
        fs::write(&notexec, b"#!/bin/sh\n").unwrap();
        fs::set_permissions(&notexec, fs::Permissions::from_mode(0o600)).unwrap();
        for inspector in [
            missing.to_str().unwrap(),
            notexec.to_str().unwrap(),
            "relative",
        ] {
            let cfg = config(root.path(), inspector, "60");
            match launch_err(&cfg, 9, 2) {
                LaunchError::Clean {
                    step: Step::Spawn,
                    why,
                } => assert_eq!(why, "inspector not started"),
                e => panic!("{inspector}: {}", describe(&e)),
            }
            assert!(root.names().is_empty(), "{inspector}");
        }
    }

    #[test]
    fn launch_does_not_start_when_the_name_exists() {
        let root = TestDir::new();
        let cfg = sleeper(root.path());
        let taken = root.path().join("insp-0000000000000001-00000001");
        fs::create_dir(&taken).unwrap();
        fs::write(taken.join("f"), b"mine").unwrap();
        match launch_err(&cfg, 1, 1) {
            LaunchError::Clean {
                step: Step::TmpDir,
                why,
            } => assert_eq!(why, "start dir already exists"),
            e => panic!("{}", describe(&e)),
        }
        assert_eq!(fs::read(taken.join("f")).unwrap(), b"mine");
        assert_eq!(root.names().len(), 1);
    }

    #[test]
    fn launch_with_a_bad_root_is_a_clean_tmp_dir_error() {
        let holder = TestDir::new();
        let cfg = sleeper(&holder.path().join("absent"));
        match launch_err(&cfg, 1, 1) {
            LaunchError::Clean {
                step: Step::TmpDir,
                why,
            } => assert_eq!(why, "tmp root not accessible"),
            e => panic!("{}", describe(&e)),
        }
    }

    /// The shape of the start: the exact environment, fd 0 a socket, stdout and stderr the null device, the
    /// host as the direct parent, an own process group, and the per-start directory as `TMPDIR`.
    #[test]
    fn launch_starts_the_inspector_in_the_documented_shape() {
        assert!(Path::new("/usr/bin/ps").is_file(), "this test needs ps");
        assert!(
            std::env::var_os("HOME").is_some(),
            "this test needs HOME in its own environment, to see that it is not inherited"
        );
        let root = TestDir::new();
        let fixtures = TestDir::new();
        let cfg = script(
            root.path(),
            &fixtures,
            "o=\"${0%/*}/out\"\n\
             s=no; [ -S /dev/stdin ] && s=yes\n\
             c1=no; [ -c /dev/stdout ] && c1=yes\n\
             c2=no; [ -c /dev/stderr ] && c2=yes\n\
             g=$(ps -o pgid= -p $$); g=$(echo $g)\n\
             { echo \"RUN=$TKV0_RUN_ID\"; echo \"INC=$TKV0_INCARNATION\"; echo \"NONCE=$TKV0_NONCE\"\n\
             echo \"TMPDIR=$TMPDIR\"; echo \"GOMAXPROCS=$GOMAXPROCS\"; echo \"GOMEMLIMIT=$GOMEMLIMIT\"\n\
             echo \"HOME=${HOME-unset}\"; echo \"PPID=$PPID\"; echo \"PID=$$\"; echo \"PGID=$g\"\n\
             echo \"SOCKET=$s\"; echo \"STDOUT_NULL=$c1\"; echo \"STDERR_NULL=$c2\"; } > \"$o\"\n",
        );
        let before = Instant::now();
        let start = launch_ok(&cfg, 0x0102_0304_0506_0708, 9);
        assert!(start.started >= before && start.started <= Instant::now());
        assert_eq!(start.inc, 9);
        assert_eq!(start.pid, start.ins.pid());
        let dir_path = start.dir.path().to_path_buf();
        assert_eq!(dir_path, root.path().join("insp-0102030405060708-00000009"));
        assert_eq!(
            fs::symlink_metadata(&dir_path).unwrap().mode() & 0o7777,
            0o700
        );
        let nonce: String = start.nonce.iter().map(|b| format!("{b:02x}")).collect();
        let pid = start.pid;
        let (inc, exit) = done(drive(start.stop(Instant::now() + Duration::from_secs(30))));
        assert_eq!(inc, 9);
        assert!(exit.status.success() && !exit.killed);
        assert!(gone(&dir_path));
        assert!(root.names().is_empty());

        let text = fs::read_to_string(fixtures.path().join("out")).unwrap();
        let get = |k: &str| -> &str {
            text.lines()
                .find_map(|l| l.strip_prefix(k).and_then(|r| r.strip_prefix('=')))
                .unwrap_or_else(|| panic!("no {k} in {text:?}"))
        };
        assert_eq!(get("RUN"), "0102030405060708");
        assert_eq!(get("INC"), "00000009");
        assert_eq!(get("NONCE"), nonce);
        assert_eq!(get("TMPDIR"), dir_path.to_str().unwrap());
        assert_eq!(get("GOMAXPROCS"), "1");
        assert_eq!(get("GOMEMLIMIT"), "268435456");
        assert_eq!(get("HOME"), "unset");
        assert_eq!(get("SOCKET"), "yes");
        assert_eq!(get("STDOUT_NULL"), "yes");
        assert_eq!(get("STDERR_NULL"), "yes");
        assert_eq!(get("PPID"), std::process::id().to_string());
        assert_eq!(get("PID"), pid.to_string());
        assert_eq!(get("PGID"), pid.to_string());
    }

    // ---- Start::stop and Stopping ----

    #[test]
    fn stop_closes_our_end_and_a_natural_exit_is_done_without_a_kill() {
        let root = TestDir::new();
        let fixtures = TestDir::new();
        // Reads its stdin to the end and ends with 7: it only ends when our end is shut down.
        let cfg = script(root.path(), &fixtures, "cat > /dev/null\nexit 7\n");
        let start = launch_ok(&cfg, 1, 4);
        let p = start.dir.path().to_path_buf();
        assert!(p.is_dir());
        let st = start.stop(Instant::now() + Duration::from_secs(30));
        assert_eq!(st.inc(), 4);
        let (inc, exit) = done(drive(st));
        assert_eq!(inc, 4);
        assert_eq!(exit.status.code(), Some(7));
        assert!(!exit.killed);
        assert!(gone(&p));
        assert!(root.names().is_empty());
    }

    #[test]
    fn a_lost_process_is_done_with_the_kill_recorded_and_the_directory_removed() {
        let root = TestDir::new();
        let cfg = sleeper(root.path());
        let mut start = launch_ok(&cfg, 2, 5);
        let p = start.dir.path().to_path_buf();
        start.kill_now().unwrap();
        let (inc, exit) = done(drive(start.stop(Instant::now() + Duration::from_secs(30))));
        assert_eq!(inc, 5);
        assert!(exit.killed);
        assert_eq!(exit.status.signal(), Some(9));
        assert!(gone(&p));
        assert!(root.names().is_empty());
    }

    #[test]
    fn kill_by_only_moves_the_kill_earlier_and_not_after_the_kill() {
        let root = TestDir::new();
        let cfg = sleeper(root.path());
        let start = launch_ok(&cfg, 3, 6);
        let p = start.dir.path().to_path_buf();
        let t0 = Instant::now();
        let far = t0 + Duration::from_secs(600);
        let mut st = start.stop(far);
        assert_eq!(st.next_at(), far);
        // Later or equal: no change.
        st.kill_by(far + Duration::from_secs(10));
        st.kill_by(far);
        assert_eq!(st.next_at(), far);
        // Earlier: moved.
        let early = t0 + Duration::from_secs(300);
        st.kill_by(early);
        assert_eq!((st.kill_at, st.next_at()), (early, early));
        st.kill_by(far);
        assert_eq!(st.kill_at, early);
        // Before the kill time, a step neither kills nor gives up.
        st = match st.step(t0) {
            Stopped::Waiting(s) => s,
            _ => panic!("expected Waiting before the kill time"),
        };
        assert_eq!((st.kill_at, st.give_up), (early, None));
        // Moved to a time that has passed: the next step sends SIGKILL, and `give_up` is `now + kill_grace`.
        st.kill_by(t0);
        assert_eq!(st.next_at(), t0);
        let now = Instant::now();
        st = match st.step(now) {
            Stopped::Waiting(s) => s,
            _ => panic!("expected Waiting right after the kill"),
        };
        let grace = Duration::from_secs(5);
        assert_eq!(st.give_up, Some(now + grace));
        assert_eq!(st.next_at(), now + grace);
        // After the kill nothing moves: kill_at stays, give_up stays.
        let kept = st.kill_at;
        st.kill_by(t0 - Duration::from_millis(1));
        assert_eq!((st.kill_at, st.give_up), (kept, Some(now + grace)));
        assert_eq!(st.next_at(), now + grace);
        let (_, exit) = done(drive(st));
        assert!(exit.killed && exit.status.signal() == Some(9));
        assert!(gone(&p));
    }

    #[test]
    fn unreaped_keeps_the_child_and_the_directory_and_again_kills_once_more() {
        let root = TestDir::new();
        let cfg = sleeper(root.path());
        let start = launch_ok(&cfg, 4, 7);
        let p = start.dir.path().to_path_buf();
        let far = Instant::now() + Duration::from_secs(600);
        let mut st = start.stop(far);
        // The state after a SIGKILL whose exit was not seen in time (set directly; the process was not killed).
        let past = Instant::now() - Duration::from_millis(1);
        st.give_up = Some(past);
        let left = match st.step(Instant::now()) {
            Stopped::Unreaped { left, why } => {
                assert_eq!(why, "exit not seen after SIGKILL");
                left
            }
            _ => panic!("expected Unreaped"),
        };
        // `step` did not call `again`: nothing changed, and the child and the directory are still owned.
        assert_eq!(
            (left.inc(), left.kill_at, left.give_up),
            (7, far, Some(past))
        );
        assert!(p.is_dir());
        let now = Instant::now();
        let again = left.again(now);
        assert_eq!(again.give_up, Some(now + Duration::from_secs(5)));
        let (inc, exit) = done(drive(again));
        assert_eq!(inc, 7);
        assert!(exit.killed && exit.status.signal() == Some(9));
        assert!(gone(&p));
    }

    #[test]
    fn a_kill_grace_that_overflows_is_due_at_once() {
        let root = TestDir::new();
        let mut cfg = sleeper(root.path());
        cfg.kill_grace = Duration::MAX;
        let start = launch_ok(&cfg, 5, 8);
        let p = start.dir.path().to_path_buf();
        let st = start.stop(Instant::now());
        let now = Instant::now();
        let mut st = match st.step(now) {
            Stopped::Waiting(s) => s,
            _ => panic!("expected Waiting right after the kill"),
        };
        assert_eq!((st.give_up, st.next_at()), (Some(now), now));
        // Unless the exit is already seen, every later step is `Unreaped` at once; `again` retries until it is.
        let limit = Instant::now() + Duration::from_secs(10);
        let (inc, exit) = loop {
            match st.step(Instant::now()) {
                Stopped::Done { inc, exit } => break (inc, exit),
                Stopped::Unreaped { left, .. } => st = left.again(Instant::now()),
                Stopped::Waiting(_) => panic!("a due give_up cannot wait"),
                Stopped::DirLeft { why, .. } => panic!("DirLeft: {why}"),
            }
            assert!(Instant::now() < limit, "the exit was not seen in 10 s");
            thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(inc, 8);
        assert!(exit.killed);
        assert!(gone(&p));
    }

    /// The exit is seen but the directory cannot be removed: handed back with the exit, then removable later.
    #[test]
    fn a_directory_that_cannot_be_removed_is_handed_back_with_the_exit() {
        let root = TestDir::new();
        let cfg = sleeper(root.path());
        assert_ne!(
            uid_of(root.path()),
            0,
            "this test needs a user that is not root"
        );
        let mut start = launch_ok(&cfg, 6, 9);
        let p = start.dir.path().to_path_buf();
        // A subdirectory without write permission: its file cannot be unlinked.
        let sub = p.join("sub");
        fs::create_dir(&sub).unwrap();
        fs::write(sub.join("f"), b"x").unwrap();
        fs::set_permissions(&sub, fs::Permissions::from_mode(0o500)).unwrap();
        start.kill_now().unwrap();
        let stopped = drive(start.stop(Instant::now() + Duration::from_secs(30)));
        // Restored first, so a failed assertion does not leave an undeletable tree behind.
        fs::set_permissions(&sub, fs::Permissions::from_mode(0o700)).unwrap();
        let (inc, exit, dir) = match stopped {
            Stopped::DirLeft {
                inc,
                exit,
                dir,
                why,
            } => {
                assert_eq!(why, "start dir removal failed");
                (inc, exit, dir)
            }
            Stopped::Done { .. } => panic!("the directory was removed"),
            Stopped::Waiting(_) => panic!("Waiting"),
            Stopped::Unreaped { why, .. } => panic!("Unreaped: {why}"),
        };
        assert_eq!(inc, 9);
        assert!(exit.killed);
        assert_eq!(dir.path(), p);
        assert!(sub.join("f").is_file());
        dir.remove().ok().unwrap();
        assert!(gone(&p));
        assert!(root.names().is_empty());
    }
}
