use super::*;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;

const NONCE: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

/// A process that does nothing for a minute and ignores its stdin: `sleep 60`. The tests that start it fail
/// (not skip) when the program is missing.
fn sleeper(inspector: &'static str, rules: &'static str) -> Spec<'static> {
    assert!(
        Path::new("/bin/sleep").is_file(),
        "these tests need /bin/sleep"
    );
    Spec {
        inspector: Path::new(inspector),
        rules: Path::new(rules),
        tmpdir: Path::new("/tmp/x"),
        gomaxprocs: 1,
        gomemlimit: 256 << 20,
        kill_grace: Duration::from_secs(5),
    }
}

/// `try_exit` every few ms until the exit is seen; fails the test after 10 s.
fn wait_exit(ins: &mut Inspector) -> Exit {
    let limit = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(x) = ins.try_exit().unwrap() {
            return x;
        }
        assert!(Instant::now() < limit, "the exit was not seen in 10 s");
        thread::sleep(POLL);
    }
}

#[test]
fn child_env_has_the_exact_formats() {
    let spec = Spec {
        inspector: Path::new("/w/insp"),
        rules: Path::new("/w/r.conf"),
        tmpdir: Path::new("/w/tmp/x"),
        gomaxprocs: 1,
        gomemlimit: 256 << 20,
        kill_grace: Duration::from_secs(1),
    };
    let env = child_env(&spec, 0x0102_0304_0506_0708, 7, &NONCE).unwrap();
    let want = [
        ("TKV0_RUN_ID", "0102030405060708"),
        ("TKV0_INCARNATION", "00000007"),
        ("TKV0_NONCE", "000102030405060708090a0b0c0d0e0f"),
        ("TMPDIR", "/w/tmp/x"),
        ("GOMAXPROCS", "1"),
        ("GOMEMLIMIT", "268435456"),
    ];
    assert_eq!(env.len(), want.len());
    for ((k, v), (wk, wv)) in env.iter().zip(want) {
        assert_eq!((*k, v.as_str()), (wk, wv));
    }
}

#[test]
fn child_env_refuses_a_tmpdir_that_is_not_utf8() {
    let bad = PathBuf::from(std::ffi::OsStr::from_bytes(b"/w/tmp/\xff\xfe"));
    let spec = Spec {
        inspector: Path::new("/w/insp"),
        rules: Path::new("/w/r.conf"),
        tmpdir: &bad,
        gomaxprocs: 1,
        gomemlimit: 1,
        kill_grace: Duration::from_secs(1),
    };
    assert_eq!(
        child_env(&spec, 1, 1, &NONCE).err(),
        Some("tmpdir is not UTF-8")
    );
    // The same refusal reaches the caller of `spawn`, and no process is started.
    let err = spawn(&spec, 1, 1, &NONCE).err().unwrap();
    assert_eq!(err.kind(), ErrorKind::InvalidInput);
}

#[test]
fn random_values_differ() {
    assert_ne!(fresh_nonce().unwrap(), fresh_nonce().unwrap());
    assert_ne!(fresh_run().unwrap(), fresh_run().unwrap());
}

#[test]
fn after_fails_closed_when_the_sum_does_not_fit() {
    let base = Instant::now();
    assert_eq!(after(base, Duration::MAX), base);
    assert!(after(base, Duration::from_secs(1)) > base);
}

#[test]
fn spawn_refuses_a_relative_inspector_and_starts_nothing_for_a_missing_one() {
    let rel = sleeper("sleep", "60");
    assert_eq!(
        spawn(&rel, 1, 1, &NONCE).err().unwrap().kind(),
        ErrorKind::InvalidInput
    );
    let missing = sleeper("/nonexistent-inspector-dir/inspector", "60");
    assert_eq!(
        spawn(&missing, 1, 1, &NONCE).err().unwrap().kind(),
        ErrorKind::NotFound
    );
}

#[test]
fn kill_then_try_exit_keeps_the_exit() {
    let (mut ins, _mine) = spawn(&sleeper("/bin/sleep", "60"), 1, 1, &NONCE).unwrap();
    assert!(ins.pid() > 1);
    assert!(ins.try_exit().unwrap().is_none());
    ins.kill().unwrap();
    let x = wait_exit(&mut ins);
    assert!(x.killed);
    assert_eq!(x.status.signal(), Some(9));
    // The exit is kept: asked again, it is the same and nothing is waited for; a kill is a no-op.
    let again = ins.try_exit().unwrap().unwrap();
    assert!(again.killed && again.status == x.status);
    ins.kill().unwrap();
    assert_eq!(ins.try_exit().unwrap().unwrap().status, x.status);
}

#[test]
fn a_natural_exit_is_not_a_kill() {
    // `sleep 0` ends at once with status 0.
    let (mut ins, _mine) = spawn(&sleeper("/bin/sleep", "0"), 1, 1, &NONCE).unwrap();
    let x = wait_exit(&mut ins);
    assert!(!x.killed);
    assert!(x.status.success());
    // A kill after the exit was seen changes nothing.
    ins.kill().unwrap();
    assert!(!ins.try_exit().unwrap().unwrap().killed);
}

#[test]
fn drop_kills_and_ends_the_process() {
    let (ins, mine) = spawn(&sleeper("/bin/sleep", "60"), 1, 1, &NONCE).unwrap();
    mine.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let t = Instant::now();
    drop(ins);
    // The dead process closed its fd 0: our end reads EOF (the command was dropped in `spawn`, nothing else
    // holds the other end). A hang would end as a read timeout error instead.
    let mut buf = [0u8; 1];
    assert_eq!((&mine).read(&mut buf).unwrap(), 0);
    assert!(t.elapsed() < Duration::from_secs(5));
}
