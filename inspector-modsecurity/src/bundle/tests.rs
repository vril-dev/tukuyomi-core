use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

// The manifests that the writer of a bundle has to produce, and the sha256 of the one of version 4.
const V1: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../inspector/testdata/manifest-v1-golden.json"
));
const V2: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../inspector/testdata/manifest-v2-golden.json"
));
const V3: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../inspector/testdata/manifest-v3-golden.json"
));
const V4: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../inspector/testdata/manifest-v4-golden.json"
));
const V4_SHA256: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../inspector/testdata/manifest-v4-golden.json.sha256"
));

const WRONG_ENGINE: &str = "not a manifest of version 4 for the engine of this inspector";
const NOT_CANONICAL: &str = "not in the canonical form";
const GOLDEN_ROUTES: &str = r#"[{"path":"/static/","action":"bypass"},{"host":"example.test","path":"/health","action":"bypass"}]"#;

/// A generation of two files in the byte order of their paths, and the order in which they are loaded.
const FILES: [(&str, &str); 2] = [
    ("crs/rules/b.conf", "SecRuleEngine On\n"),
    ("rules/a.conf", "SecRequestBodyAccess On\n"),
];
const LOAD: [&str; 2] = ["rules/a.conf", "crs/rules/b.conf"];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `src` with the first `from` written as `to`.
fn replaced(src: &[u8], from: &str, to: &str) -> Vec<u8> {
    let text = std::str::from_utf8(src).unwrap();
    assert!(text.contains(from), "{from} is not in the manifest");
    text.replacen(from, to, 1).into_bytes()
}

/// A directory under the temporary directory, removed when it goes out of scope. `bundle` in it is the generation and
/// `tmp` is the `TMPDIR` that the copy is made in.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Scratch {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "tkv-bundle-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        for sub in ["", "bundle", "tmp"] {
            DirBuilder::new().mode(0o700).create(dir.join(sub)).unwrap();
        }
        Scratch(dir)
    }

    fn bundle(&self) -> PathBuf {
        self.0.join("bundle")
    }

    fn tmp(&self) -> PathBuf {
        self.0.join("tmp")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn raw_file(path: &str, data: &[u8]) -> RawFile {
    RawFile {
        path: path.to_owned(),
        size: u64::try_from(data.len()).unwrap(),
        sha256: hex(&Sha256::digest(data)),
    }
}

fn raw_manifest(files: Vec<RawFile>, load: &[&str], mode: &str) -> RawManifest {
    RawManifest {
        version: VERSION,
        engine: ENGINE.to_owned(),
        mode: mode.to_owned(),
        files,
        load: load.iter().map(|p| (*p).to_owned()).collect(),
        routes: Vec::new(),
    }
}

/// Writes the files below `dir`, which must be given in the byte order of their paths, and the `manifest.json` for them
/// in the canonical form. Returns the bytes of the manifest.
fn write_generation(dir: &Path, files: &[(&str, &str)], load: &[&str], mode: &str) -> Vec<u8> {
    let mut raw = Vec::new();
    for (path, data) in files {
        let file = dir.join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, data).unwrap();
        raw.push(raw_file(path, data.as_bytes()));
    }
    let manifest = raw_manifest(raw, load, mode).encode();
    fs::write(dir.join(MANIFEST_NAME), &manifest).unwrap();
    manifest
}

/// A scratch directory with the generation of `FILES` in it, and the bytes of its manifest.
fn generation(mode: &str) -> (Scratch, Vec<u8>) {
    let scratch = Scratch::new();
    let manifest = write_generation(&scratch.bundle(), &FILES, &LOAD, mode);
    (scratch, manifest)
}

/// Checks that an error holds no absolute path, in particular not the directory of the test.
fn holds_no_path(scratch: &Scratch, err: &BundleError) {
    let shown = err.to_string();
    assert!(!shown.contains(scratch.0.to_str().unwrap()), "{shown}");
    assert!(
        err.path().is_none_or(|path| !path.starts_with('/')),
        "{shown}"
    );
}

/// Reads the generation of the scratch directory, which must be refused.
fn refused(scratch: &Scratch) -> BundleError {
    let err = Bundle::read(&scratch.bundle(), &scratch.tmp()).unwrap_err();
    holds_no_path(scratch, &err);
    err
}

/// The manifest of `count` files of `size` bytes each, the first of them loaded.
fn manifest_of(count: usize, size: u64) -> Vec<u8> {
    let sha256 = hex(&Sha256::digest(b"abc"));
    let files = (0..count)
        .map(|i| RawFile {
            path: format!("rules/f{i:03}.conf"),
            size,
            sha256: sha256.clone(),
        })
        .collect();
    raw_manifest(files, &["rules/f000.conf"], "block").encode()
}

#[test]
fn the_golden_manifest_of_version_4_is_read_and_has_the_fingerprint_of_its_file() {
    let manifest = Manifest::parse(V4).unwrap();
    assert_eq!(manifest.files.len(), 10);
    assert_eq!(manifest.load.len(), 7);
    assert!(!manifest.detect);
    // It is the form that the writer produces: written again, it is the same bytes.
    let raw: RawManifest = serde_json::from_slice(V4).unwrap();
    assert_eq!(raw.routes.len(), 2);
    assert_eq!(raw.encode(), V4);
    assert_eq!(V4_SHA256, format!("{}\n", hex(&Sha256::digest(V4))));
}

#[test]
fn the_goldens_of_versions_1_to_3_are_refused_with_exit_11_and_nothing_is_copied() {
    for golden in [V1, V2, V3] {
        let scratch = Scratch::new();
        fs::write(scratch.bundle().join(MANIFEST_NAME), golden).unwrap();
        let err = refused(&scratch);
        assert_eq!(err.exit_code(), EXIT_RULES);
        assert_eq!(err.path(), Some(MANIFEST_NAME));
        assert_eq!(err.text(), WRONG_ENGINE);
        assert!(!scratch.tmp().join(COPY_DIR).exists());
    }
}

#[test]
fn a_manifest_that_is_not_the_one_canonical_form_of_this_engine_is_refused() {
    let rows = [
        (
            "white space after a colon",
            replaced(V4, r#""version":4"#, r#""version": 4"#),
            NOT_CANONICAL,
        ),
        (
            "the engine of another inspector",
            replaced(V4, r#""engine":"modsecurity""#, r#""engine":"coraza""#),
            WRONG_ENGINE,
        ),
        (
            "a host that is given and empty",
            replaced(
                V4,
                r#"{"path":"/static/""#,
                r#"{"host":"","path":"/static/""#,
            ),
            NOT_CANONICAL,
        ),
    ];
    for (name, manifest, want) in rows {
        assert_eq!(Manifest::parse(&manifest).err(), Some(want), "{name}");
    }
}

#[test]
fn a_manifest_with_a_wrong_mode_load_or_file_order_is_refused_with_exit_11() {
    // Each manifest is in the canonical form and its file is on disk, so that only the value is refused.
    let file = || raw_file("rules/a.conf", b"abc");
    let rows = [
        (
            "a mode that is not block or detect",
            raw_manifest(vec![file()], &["rules/a.conf"], "Block"),
            "mode is not block or detect",
        ),
        (
            "a load that names a path that is not in files",
            raw_manifest(vec![file()], &["rules/b.conf"], "block"),
            "load names a path that is not in files",
        ),
        (
            "two files with the same path",
            raw_manifest(vec![file(), file()], &["rules/a.conf"], "block"),
            "paths are not in strictly increasing byte order",
        ),
    ];
    for (name, manifest, want) in rows {
        let scratch = Scratch::new();
        fs::create_dir(scratch.bundle().join("rules")).unwrap();
        fs::write(scratch.bundle().join("rules/a.conf"), "abc").unwrap();
        fs::write(scratch.bundle().join(MANIFEST_NAME), manifest.encode()).unwrap();
        let Err(err) = Bundle::read(&scratch.bundle(), &scratch.tmp()) else {
            panic!("{name}: the generation was read");
        };
        holds_no_path(&scratch, &err);
        assert_eq!(
            (err.exit_code(), err.path()),
            (EXIT_RULES, Some(MANIFEST_NAME)),
            "{name}"
        );
        assert_eq!(err.text(), want, "{name}");
        assert!(!scratch.tmp().join(COPY_DIR).exists(), "{name}");
    }
}

#[test]
fn the_limits_hold_at_the_limit_and_are_refused_one_past_it() {
    assert!(Manifest::parse(&manifest_of(MAX_FILES, 1)).is_ok());
    assert_eq!(
        Manifest::parse(&manifest_of(MAX_FILES + 1, 1)).err(),
        Some("too many files")
    );
    assert!(Manifest::parse(&manifest_of(1, MAX_FILE_BYTES)).is_ok());
    assert_eq!(
        Manifest::parse(&manifest_of(1, MAX_FILE_BYTES + 1)).err(),
        Some("a size is out of range")
    );
}

#[test]
fn the_routes_are_checked_in_the_form_the_proxy_writes_and_are_not_kept() {
    let many = |n: usize| {
        let routes: Vec<String> = (0..n)
            .map(|i| format!(r#"{{"path":"/r{i:03}","action":"bypass"}}"#))
            .collect();
        format!("[{}]", routes.join(","))
    };
    let rows = [
        ("no route", "[]".to_owned(), None),
        ("256 routes", many(MAX_ROUTES), None),
        ("257 routes", many(MAX_ROUTES + 1), Some("too many routes")),
        (
            "the path is /",
            r#"[{"path":"/","action":"bypass"}]"#.to_owned(),
            Some("a route path is malformed"),
        ),
        (
            "an escaped slash",
            r#"[{"path":"/a%2f","action":"bypass"}]"#.to_owned(),
            Some("a route path is malformed"),
        ),
        (
            "a host with a capital",
            r#"[{"host":"Example.test","path":"/a","action":"bypass"}]"#.to_owned(),
            Some("a route host is malformed"),
        ),
        (
            "an action that is not bypass",
            r#"[{"path":"/a","action":"deny"}]"#.to_owned(),
            Some("the action of a route is not bypass"),
        ),
        (
            "the same host and path twice",
            r#"[{"path":"/a","action":"bypass"},{"path":"/a","action":"bypass"}]"#.to_owned(),
            Some("routes name a host and path twice"),
        ),
    ];
    for (name, routes, want) in rows {
        let manifest = replaced(V4, GOLDEN_ROUTES, &routes);
        assert_eq!(Manifest::parse(&manifest).err(), want, "{name}");
    }
}

#[test]
fn a_generation_is_read_and_copied_with_the_checked_bytes_at_the_paths_of_the_manifest() {
    let (scratch, manifest) = generation("detect");
    let mut bundle = Bundle::read(&scratch.bundle(), &scratch.tmp()).unwrap();
    assert_eq!(bundle.root(), scratch.tmp().join(COPY_DIR));
    assert_eq!(bundle.load(), LOAD);
    assert!(bundle.detect());
    assert_eq!(
        bundle.fingerprint(),
        <[u8; 32]>::from(Sha256::digest(&manifest))
    );
    for (path, data) in FILES {
        assert_eq!(bundle.files()[path], data.as_bytes());
        // The copy has the bytes at the paths of the manifest, in files of 0600 in directories of 0700.
        let copied = bundle.root().join(path);
        assert_eq!(fs::read(&copied).unwrap(), data.as_bytes());
        assert_eq!(
            fs::metadata(&copied).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    for dir in ["", "crs", "crs/rules", "rules"] {
        let mode = fs::metadata(bundle.root().join(dir))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "{dir}");
    }
    assert!(!bundle.root().join(MANIFEST_NAME).exists());
    bundle.clear_files();
    assert!(bundle.files().is_empty());
    assert_eq!(bundle.load(), LOAD);
    assert!(bundle.root().join("rules/a.conf").is_file());
    // A manifest of the mode block is a generation that blocks.
    let (scratch, _) = generation("block");
    assert!(
        !Bundle::read(&scratch.bundle(), &scratch.tmp())
            .unwrap()
            .detect()
    );
}

#[test]
fn a_file_that_differs_from_the_manifest_is_refused_with_exit_11_before_anything_is_copied() {
    type Change = fn(&Path);
    let rows: [(&str, Change, &str); 4] = [
        (
            "sha256",
            |p| fs::write(p, "SecRequestBodyAccess Of\n").unwrap(),
            "sha256 differs from the manifest",
        ),
        (
            "a size that is smaller",
            |p| fs::write(p, "SecRequestBodyAccess O\n").unwrap(),
            "size differs from the manifest",
        ),
        (
            "a size that is larger",
            |p| fs::write(p, "SecRequestBodyAccess On\n\n").unwrap(),
            "too large",
        ),
        (
            "a file that is missing",
            |p| fs::remove_file(p).unwrap(),
            "no such file or directory",
        ),
    ];
    for (name, change, want) in rows {
        let (scratch, _) = generation("block");
        change(&scratch.bundle().join("rules/a.conf"));
        let err = refused(&scratch);
        assert_eq!(err.exit_code(), EXIT_RULES, "{name}");
        assert_eq!(err.path(), Some("rules/a.conf"), "{name}");
        assert_eq!(err.text(), want, "{name}");
        assert!(!scratch.tmp().join(COPY_DIR).exists(), "{name}");
    }
}

#[test]
fn a_link_in_place_of_a_file_or_of_a_directory_is_refused() {
    // The link leads to a file that has the very bytes of the manifest.
    let (scratch, _) = generation("block");
    let other = scratch.0.join("other");
    fs::create_dir_all(other.join("rules")).unwrap();
    fs::write(other.join("rules/a.conf"), FILES[1].1).unwrap();
    let file = scratch.bundle().join("rules/a.conf");
    fs::remove_file(&file).unwrap();
    symlink(other.join("rules/a.conf"), &file).unwrap();
    let err = refused(&scratch);
    assert_eq!(
        (err.exit_code(), err.path()),
        (EXIT_RULES, Some("rules/a.conf"))
    );
    assert_eq!(err.text(), "not a regular file");

    let dir = scratch.bundle().join("rules");
    fs::remove_dir_all(&dir).unwrap();
    symlink(other.join("rules"), &dir).unwrap();
    let err = refused(&scratch);
    assert_eq!(
        (err.exit_code(), err.path()),
        (EXIT_RULES, Some("rules/a.conf"))
    );
    assert_eq!(err.text(), "a directory above it is not a real directory");
    assert!(!scratch.tmp().join(COPY_DIR).exists());
}

#[test]
fn a_fifo_in_place_of_a_file_is_refused_without_waiting() {
    let (scratch, _) = generation("block");
    let fifo = scratch.bundle().join("rules/a.conf");
    fs::remove_file(&fifo).unwrap();
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let (bundle, tmp) = (scratch.bundle(), scratch.tmp());
    let (send, receive) = mpsc::channel();
    let reader = thread::spawn(move || {
        let _ = send.send(Bundle::read(&bundle, &tmp));
    });
    let Ok(result) = receive.recv_timeout(Duration::from_secs(5)) else {
        // Let a read that waits for a writer end, so that no thread is left.
        let _ = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&fifo);
        panic!("the generation was not refused: reading it waits on the FIFO");
    };
    reader.join().unwrap();
    let err = result.unwrap_err();
    holds_no_path(&scratch, &err);
    assert_eq!(
        (err.exit_code(), err.path()),
        (EXIT_RULES, Some("rules/a.conf"))
    );
    assert_eq!(err.text(), "not a regular file");
}

#[test]
fn a_copy_that_cannot_be_made_is_refused_with_exit_14() {
    // The name of the copy is taken: a stale directory is never reused.
    let (scratch, _) = generation("block");
    let taken = scratch.tmp().join(COPY_DIR);
    fs::create_dir(&taken).unwrap();
    let err = refused(&scratch);
    assert_eq!(err.exit_code(), EXIT_STARTUP);
    assert_eq!(err.text(), "the directory of the copy cannot be made");
    assert_eq!(fs::read_dir(&taken).unwrap().count(), 0);

    // The TMPDIR is not there.
    fs::remove_dir(&taken).unwrap();
    fs::remove_dir(scratch.tmp()).unwrap();
    let err = refused(&scratch);
    assert_eq!(err.exit_code(), EXIT_STARTUP);
    assert_eq!(err.path(), None);
}
