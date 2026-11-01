//! The start: the HELLO that it ends with, and the refusals, each with its exit code and its line.

use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::support::{Fields, INC, Input, KIND_BYE, KIND_DRAIN, NONCE, Options, RUN, frame, start};

/// The hash of the archive of the engine that the inspector is pinned to.
const ENGINE_SOURCE: &str = "f283b33d5c21130fd3a15c84a93a1abe12bd1949edaf44288b12af571b671a50";

// The HELLO holds every field, with the limits of the protocol, the numbers of the parent as they were passed,
// and the fingerprint of the generation; the process works from "/". A DRAIN is answered with BYE and the
// process ends with 0.
#[test]
fn the_hello_says_what_the_process_is_and_a_drain_ends_it_with_bye() {
    let mut p = start(
        Options::default()
            .env("GOMAXPROCS", "7")
            .env("GOMEMLIMIT", "123456789"),
    );
    let hello = p.hello();
    assert_eq!(&hello.bytes[..4], b"TKV0");
    assert_eq!((hello.flags(), hello.tx(), hello.msg()), (0, 0, 0));
    assert_eq!((hello.run(), hello.inc()), (RUN, INC));
    assert_eq!(usize::try_from(hello.len()).unwrap(), hello.payload().len());
    let mut f = Fields::new(hello.payload());
    assert_eq!(f.u16(), 1, "version of the protocol");
    assert_eq!(f.u32(), p.pid());
    assert_eq!(f.array::<16>(), NONCE);
    assert_eq!(f.u64(), RUN);
    assert_eq!(f.u32(), INC);
    let toolchain = f.string();
    assert_eq!(toolchain, env!("TKV_BUILD_TOOLCHAIN"));
    assert!(toolchain.starts_with("rustc "), "{toolchain}");
    assert_eq!(f.string(), "v3.0.17");
    assert_eq!(f.string(), ENGINE_SOURCE);
    let fingerprint: [u8; 32] = Sha256::digest(&p.manifest).into();
    assert_eq!(f.array::<32>(), fingerprint);
    assert_eq!(f.u32(), 1 << 20, "body limit");
    assert_eq!(f.u64(), 123_456_789, "memory limit as passed");
    assert_eq!(f.u16(), 7, "processes as passed");
    assert_eq!(f.u16(), 4, "concurrent transactions");
    assert_eq!(f.u16(), 17, "queue depth");
    assert!(f.is_empty());
    assert_eq!(
        fs::read_link(format!("/proc/{}/cwd", p.pid())).unwrap(),
        Path::new("/")
    );

    p.send(&frame(KIND_DRAIN, 0, 0, &[]));
    let bye = p.recv().expect("BYE");
    assert_eq!(bye.kind(), KIND_BYE);
    let mut f = Fields::new(bye.payload());
    assert_eq!((f.u64(), f.u64(), f.u64()), (0, 0, 0));
    assert!(f.is_empty());
    assert_eq!(p.code(), 0);
    let text = p.stderr_text();
    assert!(
        text.contains("exit=0 started=0 closed=0 close_errors=0"),
        "{text}"
    );
}

struct Refused {
    name: &'static str,
    options: Options,
    code: i32,
    /// The start of the text of the line, after the prefix.
    text: &'static str,
    /// Whether the line is also in `start-failure` in `TMPDIR`.
    file: bool,
}

fn refused(
    name: &'static str,
    options: Options,
    code: i32,
    text: &'static str,
    file: bool,
) -> Refused {
    Refused {
        name,
        options,
        code,
        text,
        file,
    }
}

// A start that is refused ends with its exit code, no frame on the connection, and one line that says why and holds
// no path of the test. The line is also in `start-failure` once `TMPDIR` was checked, and not before. The cases
// also show the order: the connection is checked before the argument, and the variables before the generation.
#[test]
fn a_refused_start_ends_with_its_code_and_a_line_that_says_why() {
    let cases = [
        refused(
            "stdin is a pipe",
            Options::default().input(Input::Pipe),
            10,
            "start: peer check failed: fd is not a socket",
            false,
        ),
        refused(
            "stdin is a datagram socket",
            Options::default().input(Input::Datagram),
            10,
            "start: peer check failed: fd is not a unix stream socket",
            false,
        ),
        refused(
            "the parent did not make the pair",
            Options::default().input(Input::PairOfAnotherParent),
            10,
            "start: peer check failed: peer pid is not the parent",
            false,
        ),
        refused(
            "the connection is checked before the argument",
            Options::default().input(Input::Pipe).args(&[]),
            10,
            "start: peer check failed",
            false,
        ),
        refused(
            "no argument",
            Options::default().args(&[]),
            14,
            "start: usage: ",
            false,
        ),
        refused(
            "run id in upper case",
            Options::default().env("TKV0_RUN_ID", "0102030405060A08"),
            14,
            "start: TKV0_RUN_ID: not lowercase hex",
            false,
        ),
        refused(
            "memory limit with a unit",
            Options::default().env("GOMEMLIMIT", "256MiB"),
            14,
            "start: GOMEMLIMIT: want a decimal number",
            false,
        ),
        refused(
            "the variables are checked before the generation",
            Options::default()
                .env("TKV0_NONCE", "00")
                .args(&["/tkv-test-no-such-generation"]),
            14,
            "start: TKV0_NONCE: want 32 lowercase hex digits",
            false,
        ),
        refused(
            "no TMPDIR",
            Options::default().without("TMPDIR"),
            14,
            "start: TMPDIR: must be an absolute clean path",
            false,
        ),
        refused(
            "TMPDIR open to the group",
            Options::default().prepare(|scratch| {
                fs::set_permissions(scratch.tmp(), Permissions::from_mode(0o750)).unwrap();
            }),
            14,
            "start: TMPDIR: group or other permission bits set",
            false,
        ),
        refused(
            "the copy of the generation cannot be made",
            Options::default().prepare(|scratch| {
                fs::create_dir(scratch.tmp().join("generation")).unwrap();
            }),
            14,
            "start: rules: the directory of the copy cannot be made",
            true,
        ),
        refused(
            "no generation",
            Options::default().args(&["/tkv-test-no-such-generation"]),
            11,
            "start: rules: the directory of the generation cannot be examined",
            true,
        ),
        refused(
            "a manifest that is not one",
            Options::default().prepare(|scratch| {
                fs::write(
                    scratch.generation().join("manifest.json"),
                    "not a manifest\n",
                )
                .unwrap();
            }),
            11,
            "start: rules: manifest.json: not a manifest of the expected types",
            true,
        ),
        refused(
            "a rule that is refused",
            Options::default().rules("Include other.conf\n"),
            11,
            "start: rules rejected: rules/rules.conf: ",
            true,
        ),
    ];
    for case in cases {
        let mut p = start(case.options);
        let code = p.code();
        let stderr = p.stderr_text();
        let name = case.name;
        assert_eq!(code, case.code, "{name}: {stderr}");
        assert!(
            stderr.starts_with(&format!("tkv0-inspector: {}", case.text)),
            "{name}: {stderr}"
        );
        assert_eq!(stderr.lines().count(), 1, "{name}: {stderr}");
        assert!(
            !stderr.contains(p.scratch.root().to_str().unwrap()),
            "{name}: a path of the test is in {stderr}"
        );
        match p.start_failure() {
            Some((bytes, mode)) => {
                assert!(case.file, "{name}: start-failure is there");
                assert_eq!(bytes, stderr.as_bytes(), "{name}");
                assert_eq!(mode, 0o600, "{name}");
            }
            None => assert!(!case.file, "{name}: no start-failure"),
        }
        if p.conn.is_some() {
            assert!(p.recv().is_none(), "{name}: a frame was sent");
        }
    }
}
