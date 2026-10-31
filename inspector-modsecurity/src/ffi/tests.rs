use super::*;
use crate::sandbox::Restricted;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::Read;
use std::os::fd::FromRawFd;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Runs `body` in a process of its own: the test `test` (its full path, as `cargo test -- --list` gives it) is
/// started again in a child process, and `body` runs there.
///
/// The scanner of the library keeps state in static variables, and a read that fails can leave it in a
/// state that makes the next read in the same process fail for no reason of its own, whichever thread
/// makes it. So a test that makes the library refuse something runs in a process that nothing else
/// uses, and does its reads that must work before the read that is refused.
pub(crate) fn in_a_fresh_process(test: &str, body: impl FnOnce()) {
    const CHILD: &str = "TKV_TEST_CHILD_PROCESS";
    if std::env::var_os(CHILD).is_some() {
        body();
        return;
    }
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            test,
            "--exact",
            "--include-ignored",
            "--test-threads=1",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .output()
        .unwrap();
    // A name that no test has runs no test, and that is no pass.
    let report = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && report.contains("1 passed"),
        "{report}{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Runs `run` in a copy of the calling thread made by `fork`, and returns what `run` returned. The test program has
/// more threads than one, and a copy has only this one. Call it from a test that runs in a process of its own
/// (`in_a_fresh_process`) or that holds no lock that another thread of the test program could hold: nothing of
/// the other threads is there in the copy to release one. The library keeps state in static variables that
/// a read that failed can leave behind, and a copy that reads the rules leaves with it, so the process that
/// calls is never touched by it.
pub(crate) fn in_a_forked_process(run: impl FnOnce() -> String) -> String {
    let mut ends = [0 as libc::c_int; 2];
    // SAFETY: `ends` has room for the two descriptors that pipe2 writes.
    assert_eq!(
        unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    // SAFETY: the copy only runs `run` and leaves with `_exit`.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork: {}", std::io::Error::last_os_error());
    if pid == 0 {
        // A copy that hangs is ended by the kernel, and the parent sees the signal.
        // SAFETY: alarm takes a plain integer.
        unsafe { libc::alarm(120) };
        let report = catch_unwind(AssertUnwindSafe(run)).unwrap_or_else(|_| "panic".to_owned());
        let mut rest = report.as_bytes();
        while !rest.is_empty() {
            // SAFETY: `ends[1]` is the open write end and `rest` is a live slice of the length passed.
            let n = unsafe { libc::write(ends[1], rest.as_ptr().cast(), rest.len()) };
            let Ok(n) = usize::try_from(n) else { break };
            rest = &rest[n..];
        }
        // SAFETY: the copy leaves at once, without the exit handlers or the destructors of the test program.
        unsafe { libc::_exit(0) }
    }
    // SAFETY: `ends[1]` is open and only the copy writes to it from here on.
    unsafe { libc::close(ends[1]) };
    // SAFETY: `ends[0]` is the read end, a descriptor that nothing else owns.
    let mut reader = unsafe { File::from_raw_fd(ends[0]) };
    let mut report = String::new();
    reader.read_to_string(&mut report).unwrap();
    let mut status = 0;
    // SAFETY: `pid` is a child of this process and `status` is a live integer.
    assert_eq!(unsafe { libc::waitpid(pid, &raw mut status, 0) }, pid);
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "status {status}: {report}"
    );
    report
}

/// Runs `run` in a process that has restricted itself to `dir` (`sandbox::restrict`, which needs a process of
/// one thread), and returns what `run` returned; `run` is given the proof that the process is restricted. The
/// process is a copy made by `in_a_forked_process`: call it from a test that runs in a process of its own
/// (`in_a_fresh_process`).
pub(crate) fn in_a_restricted_process(
    dir: &Path,
    run: impl FnOnce(Restricted) -> String,
) -> String {
    in_a_forked_process(|| match crate::sandbox::restrict(dir) {
        Ok(restricted) => run(restricted),
        Err(e) => format!("restrict: {e}"),
    })
}

/// A directory under the temporary directory that is removed when it goes out of scope.
struct Dir(PathBuf);

impl Dir {
    fn new() -> Dir {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "tkv-ffi-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        Dir(dir)
    }

    fn file(&self, name: &str, text: &str) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, text).unwrap();
        path
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn the_version_is_the_one_of_the_headers() {
    assert_eq!(engine_version(), Ok("3.0.17"));
}

#[test]
fn a_small_rules_file_loads_and_a_broken_one_gives_the_fixed_error() {
    in_a_fresh_process(
        "ffi::tests::a_small_rules_file_loads_and_a_broken_one_gives_the_fixed_error",
        || {
            let dir = Dir::new();
            let good = dir.file(
                "good.conf",
                "SecRuleEngine On\nSecRule ARGS \"@contains attack\" \"id:1001,phase:2,deny,status:403,log\"\n",
            );
            // A rule without an id is wrong.
            let broken = dir.file(
                "broken.conf",
                "SecRule ARGS \"@contains attack\" \"phase:2,deny\"\n",
            );
            let _engine = Engine::new().unwrap();
            let mut rules = Rules::new().unwrap();
            assert_eq!(rules.add_file(&good), Ok(()));

            // The reads that are refused come last.
            let mut rules = Rules::new().unwrap();
            let err = rules.add_file(&broken).unwrap_err();
            assert_eq!(err, Error::Rules);
            assert!(!err.text().contains(dir.0.to_str().unwrap()));
            // A file that is not there is refused the same way.
            assert_eq!(
                rules.add_file(&dir.0.join("missing.conf")),
                Err(Error::Rules)
            );
        },
    );
}

#[test]
fn a_path_with_a_nul_byte_is_refused_before_the_library_sees_it() {
    let mut rules = Rules::new().unwrap();
    let path = Path::new(OsStr::from_bytes(b"a\0b.conf"));
    assert_eq!(rules.add_file(path), Err(Error::Path));
    assert_eq!(rules.check(&[path.to_path_buf()]), Err(Error::Path));
}

#[test]
fn a_text_loads_and_a_broken_one_gives_the_fixed_error() {
    in_a_fresh_process(
        "ffi::tests::a_text_loads_and_a_broken_one_gives_the_fixed_error",
        || {
            let mut rules = Rules::new().unwrap();
            let rule =
                "SecRule ARGS \"@contains attack\" \"id:1001,phase:2,deny,status:403,log\"\n";
            assert_eq!(rules.add_text(rule), Ok(()));
            assert_eq!(rules.add_text("a\0b"), Err(Error::Text));

            // The read that is refused comes last.
            let mut rules = Rules::new().unwrap();
            // A rule without an id is wrong.
            let err = rules
                .add_text("SecRule ARGS \"@contains attack\" \"phase:2,deny\"\n")
                .unwrap_err();
            assert_eq!(err, Error::Rules);
            assert_eq!(err.text(), "the engine library refused the rules");
        },
    );
}

#[test]
fn the_settings_are_read_back_and_the_first_addition_that_sets_one_keeps_it() {
    let mut rules = Rules::new().unwrap();
    assert_eq!(
        rules.settings(),
        Ok(Settings {
            engine: EngineState::NotSet,
            body_access: None,
            json_depth_limit: None
        })
    );
    rules
        .add_text("SecRuleEngine On\nSecRequestBodyAccess On\nSecRequestBodyJsonDepthLimit 64\n")
        .unwrap();
    rules
        .add_text(
            "SecRuleEngine Off\nSecRequestBodyAccess Off\nSecRequestBodyJsonDepthLimit 1000\n",
        )
        .unwrap();
    assert_eq!(
        rules.settings(),
        Ok(Settings {
            engine: EngineState::On,
            body_access: Some(true),
            json_depth_limit: Some(64)
        })
    );
    // Inside one text the later directive wins.
    let mut rules = Rules::new().unwrap();
    rules
        .add_text("SecRuleEngine Off\nSecRuleEngine DetectionOnly\n")
        .unwrap();
    assert_eq!(rules.settings().unwrap().engine, EngineState::DetectionOnly);
}
