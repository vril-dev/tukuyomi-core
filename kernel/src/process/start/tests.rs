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
        Stopped::Done { inc, exit, .. } => (inc, exit),
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
    for mode in [0o750, 0o705] {
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

    // (c) nothing at the name: it cannot be identified, so it is not claimed as removed.
    fs::remove_dir_all(&p).unwrap();
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
    for inspector in [missing.to_str().unwrap(), "relative"] {
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
    // Later: no change. Earlier: moved.
    st.kill_by(far + Duration::from_secs(10));
    assert_eq!(st.next_at(), far);
    st.kill_by(t0);
    assert_eq!(st.next_at(), t0);
    // A step at that time sends SIGKILL; after the kill nothing moves.
    let now = Instant::now();
    let Stopped::Waiting(mut st) = st.step(now) else {
        panic!("expected Waiting right after the kill");
    };
    let give_up = now + Duration::from_secs(5);
    assert_eq!(st.next_at(), give_up);
    st.kill_by(t0 - Duration::from_millis(1));
    assert_eq!(st.next_at(), give_up);
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
            ..
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

// ---- start-failure ----

/// The bytes of `start-failure`, by the checks of `StartDir::read_failure`, for what the test put at the name.
#[test]
fn start_failure_is_read_only_as_a_small_regular_file_of_the_directory() {
    let root = TestDir::new();
    let outside = TestDir::new();
    let dir = created(StartDir::create(root.path(), 11, 1));
    let name = dir.path().join(FAILURE_FILE);
    // Absent.
    assert_eq!(dir.read_failure(), None);
    // The limit and the first byte past it.
    fs::write(&name, vec![b'x'; 512]).unwrap();
    assert_eq!(dir.read_failure(), Some(vec![b'x'; 512]));
    fs::write(&name, vec![b'x'; 513]).unwrap();
    assert_eq!(dir.read_failure(), None);
    // Nothing to say.
    fs::write(&name, b"").unwrap();
    assert_eq!(dir.read_failure(), None);
    // A link is not followed, also to a file that is fine.
    fs::remove_file(&name).unwrap();
    fs::write(outside.path().join("line"), b"outside\n").unwrap();
    symlink(outside.path().join("line"), &name).unwrap();
    assert_eq!(dir.read_failure(), None);
    // Not a regular file.
    fs::remove_file(&name).unwrap();
    fs::create_dir(&name).unwrap();
    assert_eq!(dir.read_failure(), None);
    fs::remove_dir(&name).unwrap();
    // A directory that was replaced by another one is not read, whatever the new one holds.
    fs::write(&name, b"mine\n").unwrap();
    assert_eq!(dir.read_failure(), Some(b"mine\n".to_vec()));
    let moved = root.path().join("moved");
    fs::rename(dir.path(), &moved).unwrap();
    fs::create_dir(dir.path()).unwrap();
    fs::write(&name, b"other\n").unwrap();
    assert_eq!(dir.read_failure(), None);
    fs::remove_dir_all(dir.path()).unwrap();
    fs::rename(&moved, dir.path()).unwrap();
    dir.remove().ok().unwrap();
}

/// The read happens at the end of the stop, for a refusal only, and the directory goes either way.
#[test]
fn the_stop_hands_back_start_failure_after_a_refusal_only() {
    let root = TestDir::new();
    let fixtures = TestDir::new();
    for (code, want) in [(10, true), (11, true), (14, true), (0, false), (12, false)] {
        let cfg = script(
            root.path(),
            &fixtures,
            &format!(
                "printf 'tkv0-inspector: refused\\n' > \"$TMPDIR/start-failure\"\nexit {code}\n"
            ),
        );
        let start = launch_ok(&cfg, 12, 1);
        let p = start.dir.path().to_path_buf();
        let stopped = drive(start.stop(Instant::now() + Duration::from_secs(30)));
        let Stopped::Done { exit, detail, .. } = stopped else {
            panic!("exit {code}: the stop did not end with the directory removed");
        };
        assert_eq!(exit.status.code(), Some(code));
        let line = b"tkv0-inspector: refused\n".to_vec();
        assert_eq!(detail, want.then_some(line), "exit {code}");
        assert!(gone(&p) && root.names().is_empty(), "exit {code}");
    }
}
