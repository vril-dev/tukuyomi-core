//! The ModSecurity inspection process. The kernel starts it with the connection of the session as descriptor 0, the
//! directory of one generation of rules as its only argument, and a few variables in an otherwise empty environment.
//!
//! The start has one order, and a step that fails ends it with the exit code that is given and one line of
//! diagnostic (`diag`):
//!
//! 1. The signals are set (`sandbox::set_signals`), so that nothing below is ended by what the process was started
//!    with.
//! 2. Descriptor 0 is a unix stream connection whose peer is the parent (10).
//! 3. The working directory is `/` (14), so that a file that a rule names is not looked for in a directory of the
//!    parent's.
//! 4. The argument and the variables are checked (14), and the environment is then emptied (14): the rules can read
//!    none of it, and the rest of the start uses the values that were read.
//! 5. The engine library is the version that this inspector is pinned to (14).
//! 6. The generation is read, checked against its manifest, and copied below `TMPDIR` (11; 14 when the copy cannot
//!    be written).
//! 7. The process restricts itself (14).
//! 8. The rules are built from the copy (11; 14 when the environment fails).
//! 9. The engine is made (14).
//! 10. The connection is taken as a stream (10), HELLO is sent (14) and the session runs. It ends with 0 after BYE,
//!     12 when the connection was lost and every transaction was closed in time, and 13 when closing took longer
//!     (`CLOSE_WINDOW`).
//!
//! The first thing written to the connection is the HELLO, after the rules are built.
//!
//! `session` runs the order above from the signals (1) to the end of the session. It is given the window and `start`,
//! the steps in between: `run` gives it `CLOSE_WINDOW` and the real start, and the tests give it a short window and a
//! start of their own, so that they go through the same signals, the same alarm and the same order.
#![forbid(unsafe_code)]

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process;
use std::time::Duration;

use tukuyomi_inspector_modsecurity::bundle::Bundle;
use tukuyomi_inspector_modsecurity::codec::{Hello, encode_hello};
use tukuyomi_inspector_modsecurity::diag::Diag;
use tukuyomi_inspector_modsecurity::inspect::Inspector;
use tukuyomi_inspector_modsecurity::link;
use tukuyomi_inspector_modsecurity::owner::{Inspection, Table};
use tukuyomi_inspector_modsecurity::{ffi, rules, sandbox};

// Exit codes of a start that is refused (14: input that cannot be used, or an environment that cannot be set up). The
// codes of a generation and of rules that are refused are those of `bundle` and `rules`, and the codes of the end of
// a session are those of `link`.
const EXIT_PEER: i32 = 10;
const EXIT_STARTUP: i32 = 14;

/// The version of the engine library that this inspector is pinned to, and says in its HELLO.
const ENGINE_VERSION: &str = "v3.0.17";
/// The toolchain that built this inspector, and the hash of the source of the engine: fixed by `build.rs`.
const TOOLCHAIN: &str = env!("TKV_BUILD_TOOLCHAIN");
const ENGINE_SOURCE: &str = env!("TKV_BUILD_ENGINE_SOURCE");

/// The time that closing every open transaction may take after the connection was lost, all of them together: the
/// session ends with 12 when they were all closed in that time, and with 13 when they were not.
///
/// The process has one thread, and `link::serve` closes the transactions on it. It measures the time only when the
/// closing has ended, so it can answer 13 for a slow close but not for one that never returns, and the kernel's kill of
/// such a process leaves a signal and no exit code. So `serve` also sets an alarm for the closing and takes it off
/// when the closing is over. `session` gives it `sandbox::set_deadline` for that, and the handler that
/// `sandbox::set_signals` installs for the alarm ends the process at once with 13. The handler writes nothing, so the
/// last line of the diagnostics is not written then (the kernel gives the inspector a null standard error, so nothing
/// would read it). There is no alarm while the connection is alive: a close of one transaction then takes the time it
/// takes.
const CLOSE_WINDOW: Duration = Duration::from_secs(3);

fn main() {
    process::exit(run(env::args_os().skip(1).collect()));
}

fn run(args: Vec<OsString>) -> i32 {
    session(CLOSE_WINDOW, |d| start(&args, d))
}

/// What the session needs once the start is done.
struct Started<I: Inspection> {
    stream: UnixStream,
    run: u64,
    inc: u32,
    /// The encoded HELLO, the first thing that is written to the connection.
    hello: Vec<u8>,
    table: Table<I>,
}

/// Runs everything from the signals to the end of the session and returns the exit code of the process. `start` does
/// the steps in between: it returns what the session needs, or the exit code of a step that failed, after that step
/// wrote its line. `window` is the time that closing every open transaction may take after the connection was lost.
///
/// The product gives it `CLOSE_WINDOW` and `start`. A test gives it a shorter window and a start that makes its own
/// transactions, so the signals, the alarm that `link::serve` is given and the order of them are those of the product.
fn session<I: Inspection>(
    window: Duration,
    start: impl FnOnce(&mut Diag<io::Stderr>) -> Result<Started<I>, i32>,
) -> i32 {
    let mut d = Diag::new(io::stderr());
    // The signals come first: a write to a closed standard error must fail with an error and not end the process.
    if let Err(e) = sandbox::set_signals(link::EXIT_LOST_TIMEOUT) {
        return d.start_fail(EXIT_STARTUP, format_args!("start: signals: {e}"));
    }
    let started = match start(&mut d) {
        Ok(started) => started,
        Err(code) => return code,
    };
    let ended = link::serve(
        started.stream,
        started.run,
        started.inc,
        &started.hello,
        started.table,
        window,
        sandbox::set_deadline,
    );
    d.finish(&ended);
    ended.code
}

/// The steps of the start between the signals and the session. A failure of a step goes through `start_fail`, which
/// also writes the line to the file `start-failure` in `TMPDIR`, but only after the checks have accepted `TMPDIR`, so
/// that an earlier failure never writes to a path that was not checked.
fn start(args: &[OsString], d: &mut Diag<io::Stderr>) -> Result<Started<Inspector>, i32> {
    if let Err(e) = sandbox::check_peer(0) {
        return Err(d.start_fail(EXIT_PEER, format_args!("start: peer check failed: {e}")));
    }
    // The library looks for a file that a rule names in the working directory first. At "/" that is not a
    // directory of the parent's.
    if let Err(e) = env::set_current_dir("/") {
        return Err(d.start_fail(EXIT_STARTUP, format_args!("start: chdir: {e}")));
    }
    let cfg = match parse_config(args, |name| env::var_os(name)) {
        Ok(cfg) => cfg,
        Err(e) => return Err(d.start_fail(EXIT_STARTUP, format_args!("start: {e}"))),
    };
    d.set_tmp(cfg.tmp_dir.clone());
    if let Err(e) = sandbox::clear_environment() {
        return Err(d.start_fail(EXIT_STARTUP, format_args!("start: environment: {e}")));
    }
    let version = match ffi::engine_version() {
        Ok(version) => format!("v{version}"),
        Err(e) => return Err(d.start_fail(EXIT_STARTUP, format_args!("start: engine: {e}"))),
    };
    if version != ENGINE_VERSION {
        return Err(d.start_fail(
            EXIT_STARTUP,
            format_args!("start: engine: the library is not {ENGINE_VERSION}"),
        ));
    }
    let mut bundle = match Bundle::read(&cfg.generation, &cfg.tmp_dir) {
        Ok(bundle) => bundle,
        Err(e) => return Err(d.start_fail(e.exit_code(), format_args!("start: rules: {e}"))),
    };
    // The rules are built from the copy: restrict the process before it builds them or reads a request.
    let restricted = match sandbox::restrict(&cfg.tmp_dir) {
        Ok(restricted) => restricted,
        Err(e) => return Err(d.start_fail(EXIT_STARTUP, format_args!("start: sandbox: {e}"))),
    };
    let built = rules::build(bundle.root(), bundle.files(), bundle.load(), restricted);
    // The rules hold what they need of the files; the bytes are not kept.
    bundle.clear_files();
    let built = match built {
        Ok(built) => built,
        Err(e) => return Err(d.start_fail(e.exit, format_args!("start: rules rejected: {e}"))),
    };
    let inspector = match Inspector::new(built, bundle.detect()) {
        Ok(inspector) => inspector,
        Err(e) => return Err(d.start_fail(EXIT_STARTUP, format_args!("start: engine: {e}"))),
    };
    let stream = match sandbox::inherited_stream() {
        Ok(stream) => stream,
        Err(e) => return Err(d.start_fail(EXIT_PEER, format_args!("start: peer conn: {e}"))),
    };
    // `mem_limit` and `gomaxprocs` are what the parent passed. Nothing in this process uses them: it has one
    // thread and no collector.
    let hello = Hello {
        pid: process::id(),
        nonce: cfg.nonce,
        toolchain: TOOLCHAIN.as_bytes(),
        engine_version: version.as_bytes(),
        engine_source: ENGINE_SOURCE.as_bytes(),
        rules_sha256: bundle.fingerprint(),
        mem_limit: cfg.mem_limit,
        gomaxprocs: cfg.gomaxprocs,
    };
    let hello = match encode_hello(cfg.run, cfg.inc, &hello) {
        Ok(hello) => hello,
        Err(e) => return Err(d.start_fail(EXIT_STARTUP, format_args!("start: hello: {}", e.0))),
    };
    Ok(Started {
        stream,
        run: cfg.run,
        inc: cfg.inc,
        hello,
        table: Table::new(inspector, cfg.run, cfg.inc),
    })
}

/// What the argument and the environment say.
#[derive(Debug)]
struct Config {
    generation: PathBuf,
    /// Checked: see `check_tmp_dir`.
    tmp_dir: PathBuf,
    run: u64,
    inc: u32,
    nonce: [u8; 16],
    mem_limit: u64,
    gomaxprocs: u16,
}

const USAGE: &str = "usage: tukuyomi-inspector-modsecurity <absolute clean generation directory>";

/// Checks the argument and the variables that the parent passes. The formats are exact: the directory of the
/// generation is the one argument, lowercase hexadecimal of a fixed width for the run, the incarnation and the nonce,
/// decimal numbers within the range of the parent's configuration for the limits, and `TMPDIR`. A message holds the
/// name of the variable and never its value. `TMPDIR` is the last check: the first message that is returned for
/// `TMPDIR` or later is the one that is written to a file in it.
fn parse_config(
    args: &[OsString],
    getenv: impl Fn(&str) -> Option<OsString>,
) -> Result<Config, String> {
    let [generation] = args else {
        return Err(USAGE.to_owned());
    };
    if !clean_abs(Path::new(generation)) {
        return Err(USAGE.to_owned());
    }
    let var = |name: &str| getenv(name).unwrap_or_default();
    let run = parse_hex::<8>("TKV0_RUN_ID", &var("TKV0_RUN_ID"))?;
    let inc = parse_hex::<4>("TKV0_INCARNATION", &var("TKV0_INCARNATION"))?;
    let nonce = parse_hex::<16>("TKV0_NONCE", &var("TKV0_NONCE"))?;
    let gomaxprocs = parse_decimal("GOMAXPROCS", &var("GOMAXPROCS"), u64::from(u16::MAX))?;
    let mem_limit = parse_decimal("GOMEMLIMIT", &var("GOMEMLIMIT"), i64::MAX.unsigned_abs())?;
    let tmp_dir = var("TMPDIR");
    check_tmp_dir(&tmp_dir).map_err(|e| format!("TMPDIR: {e}"))?;
    Ok(Config {
        generation: PathBuf::from(generation),
        tmp_dir: PathBuf::from(tmp_dir),
        run: u64::from_be_bytes(run),
        inc: u32::from_be_bytes(inc),
        nonce,
        mem_limit,
        gomaxprocs: u16::try_from(gomaxprocs).map_err(|_| "GOMAXPROCS: out of range".to_owned())?,
    })
}

/// A path argument or `TMPDIR` must be absolute and already clean: no empty, `.` or `..` component, no trailing
/// slash, no NUL, and shorter than the Linux `PATH_MAX`.
fn clean_abs(p: &Path) -> bool {
    let b = p.as_os_str().as_bytes();
    b.len() > 1
        && b.len() < 4096
        && b[0] == b'/'
        && !b.contains(&0)
        && b[1..]
            .split(|&c| c == b'/')
            .all(|s| !s.is_empty() && s != b"." && s != b"..")
}

/// `N` bytes from exactly `2 * N` lowercase hexadecimal digits.
fn parse_hex<const N: usize>(name: &str, value: &OsStr) -> Result<[u8; N], String> {
    let digits = value.as_bytes();
    if digits.len() != 2 * N {
        return Err(format!("{name}: want {} lowercase hex digits", 2 * N));
    }
    let mut out = [0u8; N];
    for (byte, pair) in out.iter_mut().zip(digits.chunks_exact(2)) {
        let (Some(high), Some(low)) = (hex_value(pair[0]), hex_value(pair[1])) else {
            return Err(format!("{name}: not lowercase hex"));
        };
        *byte = high << 4 | low;
    }
    Ok(out)
}

fn hex_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// A decimal number from `1` to `max`, written as the parent writes it: digits only, no sign and no leading zero.
fn parse_decimal(name: &str, value: &OsStr, max: u64) -> Result<u64, String> {
    let digits = value.as_bytes();
    if digits.is_empty()
        || digits[0] == b'0'
        || !digits.iter().all(u8::is_ascii_digit)
        || digits.len() > 19
    {
        return Err(format!("{name}: want a decimal number from 1 to {max}"));
    }
    let number = digits
        .iter()
        .fold(0u64, |n, &c| n * 10 + u64::from(c - b'0'));
    if number > max {
        return Err(format!("{name}: want a decimal number from 1 to {max}"));
    }
    Ok(number)
}

/// Requires the per-start directory that the parent made: absolute and clean, a real directory (not a link), owned by
/// us, with no group or other permission bits. Whether it can be written is left to the copy of the generation.
fn check_tmp_dir(p: &OsStr) -> Result<(), String> {
    if !clean_abs(Path::new(p)) {
        return Err("must be an absolute clean path".to_owned());
    }
    let meta = fs::symlink_metadata(Path::new(p)).map_err(|e| e.to_string())?;
    if !meta.file_type().is_dir() {
        return Err("not a directory".to_owned());
    }
    if meta.uid() != sandbox::effective_uid() {
        return Err("not owned by this user".to_owned());
    }
    if meta.mode() & 0o077 != 0 {
        return Err("group or other permission bits set".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
    use std::process::{Command, ExitStatus};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::thread;
    use std::time::Instant;

    use tukuyomi_inspector_modsecurity::codec::{Header, KIND_TX_BEGIN, RuleDetail, TxBegin};
    use tukuyomi_inspector_modsecurity::owner::{Fault, Outcome, Stop, Transaction};

    /// A directory under the temporary directory, removed when it goes out of scope.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Scratch {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let dir = env::temp_dir().join(format!(
                "tkv-main-{}-{}",
                process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
            Scratch(dir)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn env_with(tmp: &Path, key: &str, value: &str) -> impl Fn(&str) -> Option<OsString> {
        let tmp = tmp.to_owned();
        let (key, value) = (key.to_owned(), value.to_owned());
        move |name| {
            if name == key {
                return Some(OsString::from(&value));
            }
            Some(OsString::from(match name {
                "TKV0_RUN_ID" => "0102030405060708",
                "TKV0_INCARNATION" => "00000007",
                "TKV0_NONCE" => "000102030405060708090a0b0c0d0e0f",
                "GOMAXPROCS" => "2",
                "GOMEMLIMIT" => "268435456",
                "TMPDIR" => tmp.to_str().unwrap(),
                _ => return None,
            }))
        }
    }

    fn generation() -> Vec<OsString> {
        vec![OsString::from("/r/generation")]
    }

    #[test]
    fn the_argument_and_the_variables_are_read_in_their_exact_formats() {
        let scratch = Scratch::new();
        let tmp = scratch.0.as_path();
        let c = parse_config(&generation(), env_with(tmp, "", "")).unwrap();
        assert_eq!(c.generation, Path::new("/r/generation"));
        assert_eq!(c.tmp_dir, tmp);
        assert_eq!(c.run, 0x0102_0304_0506_0708);
        assert_eq!(c.inc, 7);
        assert_eq!(c.nonce[15], 0x0f);
        assert_eq!((c.mem_limit, c.gomaxprocs), (268_435_456, 2));

        // The limits of the two numbers: the last value and the first past it.
        let max_procs = parse_config(&generation(), env_with(tmp, "GOMAXPROCS", "65535")).unwrap();
        assert_eq!(max_procs.gomaxprocs, u16::MAX);
        let max_mem = parse_config(
            &generation(),
            env_with(tmp, "GOMEMLIMIT", "9223372036854775807"),
        )
        .unwrap();
        assert_eq!(max_mem.mem_limit, i64::MAX.unsigned_abs());

        for (name, key, value) in [
            ("run in upper case", "TKV0_RUN_ID", "0102030405060A08"),
            ("run short", "TKV0_RUN_ID", "010203040506070"),
            ("incarnation short", "TKV0_INCARNATION", "7"),
            (
                "nonce not hex",
                "TKV0_NONCE",
                "g00102030405060708090a0b0c0d0e0",
            ),
            ("procs 0", "GOMAXPROCS", "0"),
            ("procs past the limit", "GOMAXPROCS", "65536"),
            ("procs with a sign", "GOMAXPROCS", "+2"),
            ("procs with a leading zero", "GOMAXPROCS", "02"),
            ("memory 0", "GOMEMLIMIT", "0"),
            ("memory past the limit", "GOMEMLIMIT", "9223372036854775808"),
            ("memory with a unit", "GOMEMLIMIT", "256MiB"),
            ("memory empty", "GOMEMLIMIT", ""),
            ("tmp empty", "TMPDIR", ""),
            ("tmp relative", "TMPDIR", "tmp"),
            ("tmp not clean", "TMPDIR", "/tmp/"),
            ("tmp missing", "TMPDIR", "/tkv-test-no-such-directory"),
        ] {
            let got = parse_config(&generation(), env_with(tmp, key, value));
            let message = got.expect_err(name);
            assert!(message.starts_with(key), "{name}: {message}");
            // A message names the variable and never holds its value (a short one could be a part of a number).
            assert!(
                value.len() < 5 || !message.contains(value),
                "{name}: {message}"
            );
        }
        for (name, args) in [
            ("none", vec![]),
            ("two", vec![OsString::from("/a"), OsString::from("/b")]),
            ("relative", vec![OsString::from("generation")]),
            ("not clean", vec![OsString::from("/r/../generation")]),
        ] {
            let got = parse_config(&args, env_with(tmp, "", ""));
            assert_eq!(got.expect_err(name), USAGE, "{name}");
        }
    }

    #[test]
    fn tmpdir_must_be_a_real_directory_of_ours_without_group_or_other_bits() {
        let scratch = Scratch::new();
        let dir = scratch.0.join("d");
        fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        for (mode, ok) in [(0o700, true), (0o500, true), (0o710, false), (0o701, false)] {
            fs::set_permissions(&dir, fs::Permissions::from_mode(mode)).unwrap();
            // Whether it can be written is left to the copy of the generation.
            assert_eq!(check_tmp_dir(dir.as_os_str()).is_ok(), ok, "mode {mode:o}");
        }
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let (link, file) = (scratch.0.join("link"), scratch.0.join("file"));
        symlink(&dir, &link).unwrap();
        fs::write(&file, "").unwrap();
        assert!(check_tmp_dir(link.as_os_str()).is_err());
        assert!(check_tmp_dir(file.as_os_str()).is_err());
    }

    /// Runs `child` in a process of its own: the test `test` (its full path, as `cargo test -- --list` gives it) is
    /// started again in a child process, and `child` runs there and ends that process with the exit code that it
    /// returns, the way `main` does. Returns how that process ended, how long it took, and what it wrote to its standard
    /// error. The signals and the alarm are the child's alone. A name that no test has runs no test, and that process
    /// ends with 0, which no caller accepts as an answer.
    fn in_a_fresh_process(
        test: &str,
        child: impl FnOnce() -> i32,
    ) -> (ExitStatus, Duration, String) {
        const CHILD: &str = "TKV_TEST_CHILD_PROCESS";
        if env::var_os(CHILD).is_some() {
            process::exit(child());
        }
        let began = Instant::now();
        let output = Command::new(env::current_exe().unwrap())
            .args([test, "--exact", "--test-threads=1", "--nocapture"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        (
            output.status,
            began.elapsed(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }

    /// An inspection whose transactions each take `close_takes` to close.
    struct Slow {
        close_takes: Duration,
    }

    struct SlowTx {
        close_takes: Duration,
    }

    impl Inspection for Slow {
        type Tx = SlowTx;

        fn start(&mut self) -> Result<SlowTx, Fault> {
            Ok(SlowTx {
                close_takes: self.close_takes,
            })
        }
    }

    impl Transaction for SlowTx {
        fn begin(&mut self, _: &TxBegin<'_>) -> Result<Outcome, Fault> {
            Ok(Outcome::Continue(RuleDetail::NONE))
        }

        fn body(&mut self, _: &[u8]) -> Result<Option<Stop>, Fault> {
            Ok(None)
        }

        fn end(&mut self) -> Result<Outcome, Fault> {
            Ok(Outcome::Continue(RuleDetail::NONE))
        }

        fn close(self) -> bool {
            thread::sleep(self.close_takes);
            false
        }
    }

    /// The payload of a TX_BEGIN for `GET /` with the header `Host` and no body.
    fn tx_begin_payload() -> Vec<u8> {
        fn string(p: &mut Vec<u8>, s: &[u8]) {
            p.extend_from_slice(&u16::try_from(s.len()).unwrap().to_be_bytes());
            p.extend_from_slice(s);
        }
        let mut p = Vec::new();
        string(&mut p, b"127.0.0.1");
        p.extend_from_slice(&40000u16.to_be_bytes());
        string(&mut p, b"127.0.0.1");
        p.extend_from_slice(&8080u16.to_be_bytes());
        string(&mut p, b"GET");
        string(&mut p, b"/");
        string(&mut p, b"HTTP/1.1");
        p.extend_from_slice(&0u64.to_be_bytes());
        p.extend_from_slice(&1u16.to_be_bytes());
        string(&mut p, b"Host");
        string(&mut p, b"example.test");
        p
    }

    const RUN: u64 = 1;
    const INC: u32 = 1;
    /// The window of these tests: the least that an alarm can be set to (it counts whole seconds).
    const WINDOW: Duration = Duration::from_secs(1);
    /// What a test allows on top of the window, for a host that is busy.
    const MARGIN: Duration = Duration::from_secs(1);

    /// What `run` does, with its start replaced, in a process of its own: `session` with `WINDOW` and a start that
    /// has `open` transactions open that each take `close_takes` to close, on a connection whose peer is gone. The
    /// process waits longer than the window after the session, which the alarm would not let it do, and ends with the
    /// exit code of the session. `test` is the name of the calling test.
    fn lose_the_connection(
        test: &str,
        open: u64,
        close_takes: Duration,
    ) -> (ExitStatus, Duration, String) {
        in_a_fresh_process(test, || {
            let code = session(WINDOW, |_| {
                let payload = tx_begin_payload();
                let mut table = Table::new(Slow { close_takes }, RUN, INC);
                for tx in 1..=open {
                    let begin = Header {
                        kind: KIND_TX_BEGIN,
                        cut: false,
                        len: u32::try_from(payload.len()).unwrap(),
                        run: RUN,
                        inc: INC,
                        tx,
                        msg: 1,
                    };
                    // The answer is the VERDICT of the first phase.
                    assert!(table.dispatch(&begin, &payload).is_some());
                }
                // The peer is gone, so the first read of a frame ends the session. The HELLO is empty here.
                let (stream, peer) = UnixStream::pair().unwrap();
                drop(peer);
                Ok(Started {
                    stream,
                    run: RUN,
                    inc: INC,
                    hello: Vec::new(),
                    table,
                })
            });
            thread::sleep(WINDOW + MARGIN / 2);
            code
        })
    }

    #[test]
    fn the_window_for_closing_after_a_loss_is_3_seconds() {
        assert_eq!(CLOSE_WINDOW, Duration::from_secs(3));
    }

    // Closing every open transaction has one window in total. Closes that are each shorter than the window, and
    // together longer, are ended by the alarm at the window, and not when the closing is over: with 13.
    #[test]
    fn closing_that_runs_over_the_window_in_total_is_ended_by_the_alarm_with_13() {
        let (status, took, stderr) = lose_the_connection(
            "tests::closing_that_runs_over_the_window_in_total_is_ended_by_the_alarm_with_13",
            4,
            Duration::from_millis(800),
        );
        assert_eq!(status.code(), Some(13), "{status:?} {stderr}");
        assert!((WINDOW..WINDOW + MARGIN).contains(&took), "took {took:?}");
    }

    // Closes that end well inside the window give 12, and the alarm is taken off after them: the process lives on
    // past the window.
    #[test]
    fn closing_that_ends_well_inside_the_window_gives_12_and_leaves_no_alarm() {
        let (status, _, stderr) = lose_the_connection(
            "tests::closing_that_ends_well_inside_the_window_gives_12_and_leaves_no_alarm",
            4,
            Duration::from_millis(50),
        );
        assert_eq!(status.code(), Some(12), "{status:?} {stderr}");
    }

    // The signals are set before the start, which builds the rules and can take seconds: a reload signal or a closed
    // standard error during the start must not end the process. The start of this test reads the signal masks of its
    // own process and answers 14 only when they are already set.
    #[test]
    fn the_signals_are_set_before_the_start() {
        let (status, _, stderr) =
            in_a_fresh_process("tests::the_signals_are_set_before_the_start", || {
                session::<Slow>(WINDOW, |_| {
                    let status = std::fs::read_to_string("/proc/self/status").unwrap();
                    let mask = |name: &str| {
                        let line = status.lines().find(|l| l.starts_with(name)).unwrap();
                        u64::from_str_radix(line[name.len()..].trim(), 16).unwrap()
                    };
                    // Bit n - 1 stands for the signal n: SIGUSR1 is 10, SIGUSR2 12 and SIGALRM 14.
                    let ignored = mask("SigIgn:");
                    let caught = mask("SigCgt:");
                    let set = ignored & (1 << 9) != 0
                        && ignored & (1 << 11) != 0
                        && caught & (1 << 13) != 0;
                    Err(if set { EXIT_STARTUP } else { 1 })
                })
            });
        assert_eq!(status.code(), Some(EXIT_STARTUP), "{status:?} {stderr}");
    }
}
