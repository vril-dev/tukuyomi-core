use super::*;
use crate::rules::bundle::BundlePath;
use crate::rules::routes::Route;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{RecvTimeoutError, channel};
use std::thread;
use std::time::Duration;

const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
/// How long a call that must not wait for a writer is given before the test fails.
const WAIT: Duration = Duration::from_secs(5);

/// A fresh 0700 directory under the temp directory (`TMPDIR`), removed with everything in it when dropped.
struct TestDir(PathBuf);

impl TestDir {
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn scratch() -> TestDir {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "tukuyomi-proxy-rules-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    // A umask can only remove bits; make the mode exactly 0700.
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    TestDir(dir)
}

fn generation() -> Fingerprint {
    Fingerprint::from_hex(HEX.as_bytes()).unwrap()
}

fn opened(dir: &Path) -> FileStore {
    match FileStore::open(dir) {
        Ok(store) => store,
        Err(e) => panic!("the store was refused: {}", e.0),
    }
}

fn refusal<T>(result: Result<T, StoreError>) -> &'static str {
    match result {
        Err(e) => e.0,
        Ok(_) => panic!("accepted"),
    }
}

fn make_dir(path: &Path) {
    fs::DirBuilder::new().mode(0o700).create(path).unwrap();
}

/// There is no `mkfifo` in std: the command of the system makes it.
fn make_fifo(path: &Path) {
    let status = Command::new("mkfifo")
        .arg("-m")
        .arg("600")
        .arg(path)
        .status()
        .unwrap();
    assert!(status.success());
}

/// Runs `call` on its own thread and gives it `WAIT`. A call that waits for a writer fails the test, and its
/// thread is left behind: joining it would hang the test instead of failing it.
fn within<T: Send + 'static>(call: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = channel();
    thread::spawn(move || {
        let _ = tx.send(call());
    });
    match rx.recv_timeout(WAIT) {
        Ok(value) => value,
        Err(RecvTimeoutError::Timeout) => panic!("the call waits for a writer"),
        Err(RecvTimeoutError::Disconnected) => panic!("the call panicked"),
    }
}

#[test]
fn a_missing_directory_is_refused() {
    let root = scratch();
    assert_eq!(
        refusal(FileStore::open(&root.path().join("absent"))),
        "the rules store directory cannot be read"
    );
}

#[test]
fn a_link_is_not_a_real_directory() {
    let root = scratch();
    // A real link to a private directory of this user is not that directory.
    let real = root.path().join("real");
    make_dir(&real);
    let link = root.path().join("link");
    symlink(&real, &link).unwrap();
    assert!(FileStore::open(&real).is_ok());
    assert_eq!(
        refusal(FileStore::open(&link)),
        "the rules store directory is not a real directory"
    );
}

#[test]
fn a_group_or_other_permission_bit_is_refused() {
    let root = scratch();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o750)).unwrap();
    assert_eq!(
        refusal(FileStore::open(root.path())),
        "the rules store directory has group or other permission bits"
    );
}

#[test]
fn a_relative_path_is_refused_before_anything_is_looked_at() {
    // The directory is absent as well: a look at it would give the sentence "cannot be read".
    assert_eq!(
        refusal(FileStore::open(Path::new("store"))),
        "the rules store directory is not an absolute clean path"
    );
}

#[test]
fn a_directory_of_another_owner_is_refused() {
    let root = scratch();
    let owner = fs::symlink_metadata(root.path()).unwrap().uid();
    assert!(FileStore::open_as(root.path(), owner).is_ok());
    assert_eq!(
        refusal(FileStore::open_as(root.path(), owner.wrapping_add(1))),
        "the rules store directory is not owned by this user"
    );
}

#[test]
fn without_a_record_no_generation_is_chosen() {
    let root = scratch();
    assert_eq!(opened(root.path()).current(), Ok(None));
}

#[test]
fn a_record_of_64_lowercase_digits_and_a_newline_names_the_generation() {
    let root = scratch();
    let store = opened(root.path());
    fs::write(root.path().join("current"), format!("{HEX}\n")).unwrap();
    assert_eq!(store.current(), Ok(Some(generation())));
}

#[test]
fn a_record_of_another_shape_is_broken() {
    let root = scratch();
    let store = opened(root.path());
    // 65 bytes, as long as a record, with capitals.
    fs::write(
        root.path().join("current"),
        format!("{}\n", HEX.to_uppercase()),
    )
    .unwrap();
    assert_eq!(
        refusal(store.current()),
        "the current generation record is broken"
    );
}

#[test]
fn a_record_of_66_bytes_cannot_be_read() {
    let root = scratch();
    let store = opened(root.path());
    fs::write(root.path().join("current"), format!("{HEX}\n\n")).unwrap();
    assert_eq!(
        refusal(store.current()),
        "the current generation record cannot be read"
    );
}

#[test]
fn a_link_as_the_record_cannot_be_read() {
    let root = scratch();
    // A link to a file with a right record is not followed, and is not "no record" either.
    let target = root.path().join("record");
    fs::write(&target, format!("{HEX}\n")).unwrap();
    symlink(&target, root.path().join("current")).unwrap();
    assert_eq!(
        refusal(opened(root.path()).current()),
        "the current generation record cannot be read"
    );
}

#[test]
fn a_fifo_as_the_record_is_refused_without_waiting_for_a_writer() {
    let root = scratch();
    make_fifo(&root.path().join("current"));
    let store = opened(root.path());
    assert_eq!(
        refusal(within(move || store.current())),
        "the current generation record cannot be read"
    );
}

#[test]
fn a_file_is_read_only_if_it_is_the_one_that_was_looked_at() {
    let root = scratch();
    let path = root.path().join("input");
    fs::write(&path, "x\n").unwrap();
    let seen = fs::symlink_metadata(&path).unwrap();
    let identity = (seen.dev(), seen.ino());
    assert_eq!(read_regular(&path, 2, Some(identity)).unwrap(), b"x\n");
    // Another inode on the same device is another file; so is the same inode number on another device.
    for other in [(identity.0, identity.1 + 1), (identity.0 + 1, identity.1)] {
        let e = read_regular(&path, 2, Some(other)).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    }
}

#[test]
fn a_generation_directory_is_the_generation_below_the_generations_directory() {
    let root = scratch();
    let store = opened(root.path());
    make_dir(&root.path().join("generations"));
    make_dir(&root.path().join("generations").join(HEX));
    let dir = store.generation_dir(generation()).unwrap();
    assert_eq!(dir, root.path().join("generations").join(HEX));
}

#[test]
fn a_missing_generations_directory_or_generation_is_refused() {
    let root = scratch();
    let store = opened(root.path());
    assert_eq!(
        refusal(store.generation_dir(generation())),
        "the generations directory is not a real directory"
    );
    make_dir(&root.path().join("generations"));
    assert_eq!(
        refusal(store.generation_dir(generation())),
        "the generation is not a real directory"
    );
}

#[test]
fn a_link_as_the_generation_is_not_a_real_directory() {
    let root = scratch();
    let store = opened(root.path());
    let generations = root.path().join("generations");
    make_dir(&generations);
    // The link leads to a real directory: only the link is wrong.
    let elsewhere = root.path().join("elsewhere");
    make_dir(&elsewhere);
    symlink(&elsewhere, generations.join(HEX)).unwrap();
    assert_eq!(
        refusal(store.generation_dir(generation())),
        "the generation is not a real directory"
    );
}

// ---- the write side ----

fn bundle(files: &[(&str, &str)], load: &[&str]) -> Bundle {
    let path = |text: &str| BundlePath::parse(text).unwrap();
    let files = files
        .iter()
        .map(|(name, data)| (path(name), data.as_bytes().to_vec()))
        .collect();
    Bundle::new(
        Mode::Block,
        files,
        load.iter().map(|name| path(name)).collect(),
        Routes::default(),
    )
    .unwrap()
}

fn rules() -> Bundle {
    bundle(
        &[
            ("crs/rules/a.conf", "SecRuleEngine On\n"),
            ("crs/rules/a.data", "one\ntwo\n"),
            ("rules/local.conf", "SecDebugLogLevel 0\n"),
        ],
        &["crs/rules/a.conf", "rules/local.conf"],
    )
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().mode() & 0o7777
}

#[test]
fn a_staged_bundle_becomes_a_generation_and_nothing_stays_staged() {
    let root = scratch();
    let mut store = opened(root.path());
    let bundle = rules();
    let staged = store.stage(&bundle).unwrap();
    assert_eq!(staged.fingerprint, bundle.fingerprint());
    assert_eq!(staged.dir.parent().unwrap(), root.path().join("staging"));
    assert!(staged.dir.join("manifest.json").is_file());
    assert_eq!(store.commit(), Ok(Committed::Created));

    let generation = root
        .path()
        .join("generations")
        .join(bundle.fingerprint().hex());
    assert_eq!(
        store.generation_dir(bundle.fingerprint()),
        Ok(generation.clone())
    );
    assert_eq!(
        fs::read(generation.join("manifest.json")).unwrap(),
        bundle.manifest()
    );
    assert_eq!(
        fs::read(generation.join("crs/rules/a.data")).unwrap(),
        b"one\ntwo\n"
    );
    assert_eq!(mode(&generation), 0o700);
    assert_eq!(mode(&generation.join("crs/rules")), 0o700);
    assert_eq!(mode(&generation.join("manifest.json")), 0o600);
    assert_eq!(mode(&generation.join("crs/rules/a.conf")), 0o600);
    assert!(names(&root.path().join("staging")).is_empty());
    assert_eq!(store.verify(bundle.fingerprint()), Ok(()));
    // Making a generation does not choose it.
    assert_eq!(store.current(), Ok(None));
    let listed = store.list().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].fingerprint, bundle.fingerprint());
}

#[test]
fn the_same_bundle_again_is_kept_and_a_broken_generation_is_made_again() {
    let root = scratch();
    let mut store = opened(root.path());
    let bundle = rules();
    store.stage(&bundle).unwrap();
    assert_eq!(store.commit(), Ok(Committed::Created));
    store.stage(&bundle).unwrap();
    assert_eq!(store.commit(), Ok(Committed::Existing));
    assert!(names(&root.path().join("staging")).is_empty());

    // A file that is not as the manifest says: the next import makes the generation again.
    let generation = root
        .path()
        .join("generations")
        .join(bundle.fingerprint().hex());
    fs::write(generation.join("rules/local.conf"), "SecDebugLogLevel 9\n").unwrap();
    assert_eq!(
        refusal(store.verify(bundle.fingerprint())),
        "a file of the generation differs from its manifest"
    );
    store.stage(&bundle).unwrap();
    assert_eq!(store.commit(), Ok(Committed::Repaired));
    assert_eq!(store.verify(bundle.fingerprint()), Ok(()));
    assert_eq!(
        fs::read(generation.join("rules/local.conf")).unwrap(),
        b"SecDebugLogLevel 0\n"
    );
    assert!(names(&root.path().join("staging")).is_empty());
    assert_eq!(store.list().unwrap().len(), 1);
}

#[test]
fn the_mode_and_the_routes_of_a_generation_are_read_from_its_manifest_and_a_manifest_that_is_not_sound_is_refused()
 {
    let root = scratch();
    let mut store = opened(root.path());
    let one = BundlePath::parse("rules/a.conf").unwrap();
    let table = Routes::new(vec![Route::new(None, "/static/").unwrap()]).unwrap();
    let make = |mode, routes| {
        Bundle::new(
            mode,
            vec![(one.clone(), b"SecRuleEngine On\n".to_vec())],
            vec![one.clone()],
            routes,
        )
        .unwrap()
    };
    let (block, detect) = (
        make(Mode::Block, Routes::default()),
        make(Mode::Detect, Routes::default()),
    );
    let routed = make(Mode::Detect, table.clone());
    for bundle in [&block, &detect, &routed] {
        store.stage(bundle).unwrap();
        store.commit().unwrap();
    }
    assert_eq!(store.mode(block.fingerprint()), Ok(Mode::Block));
    assert_eq!(store.mode(detect.fingerprint()), Ok(Mode::Detect));
    assert_eq!(store.mode(routed.fingerprint()), Ok(Mode::Detect));
    assert_eq!(store.routes(block.fingerprint()), Ok(Routes::default()));
    assert_eq!(store.routes(routed.fingerprint()), Ok(table));
    // A manifest that is not the one its name says (here the other one), and one that is not there, are refused.
    let manifest = |bundle: &Bundle| {
        root.path()
            .join("generations")
            .join(bundle.fingerprint().hex())
            .join("manifest.json")
    };
    fs::write(manifest(&block), detect.manifest()).unwrap();
    assert_eq!(
        refusal(store.mode(block.fingerprint())),
        "the manifest of the generation does not match its name"
    );
    fs::remove_file(manifest(&detect)).unwrap();
    assert_eq!(
        refusal(store.mode(detect.fingerprint())),
        "the manifest of the generation cannot be read"
    );
    assert_eq!(
        refusal(store.mode(generation())),
        "the generation is not a real directory"
    );
    assert_eq!(
        refusal(store.routes(generation())),
        "the generation is not a real directory"
    );
}

#[test]
fn one_command_at_a_time_changes_the_store() {
    let root = scratch();
    let (mut first, mut second) = (opened(root.path()), opened(root.path()));
    let bundle = rules();
    first.stage(&bundle).unwrap();
    let busy = "the rules store is in use by another command";
    assert_eq!(refusal(second.stage(&bundle)), busy);
    assert_eq!(refusal(second.activate(bundle.fingerprint())), busy);
    let expect = bundle.fingerprint();
    assert_eq!(refusal(second.activate_if_current(expect, expect)), busy);
    // Reading does not need the lock.
    assert_eq!(second.list(), Ok(Vec::new()));
    assert_eq!(refusal(first.stage(&bundle)), "a bundle is staged already");
    first.discard().unwrap();
    assert!(names(&root.path().join("staging")).is_empty());
    second.stage(&bundle).unwrap();
    assert_eq!(second.commit(), Ok(Committed::Created));
    assert_eq!(refusal(second.commit()), "no bundle is staged");
}

#[test]
fn activate_verifies_the_generation_before_it_replaces_the_record() {
    let root = scratch();
    let mut store = opened(root.path());
    let bundle = rules();
    let other = Fingerprint::from_hex(HEX.as_bytes()).unwrap();
    assert_eq!(
        refusal(store.activate(other)),
        "the generations directory is not a real directory"
    );
    store.stage(&bundle).unwrap();
    store.commit().unwrap();
    assert_eq!(
        refusal(store.activate(other)),
        "the generation is not a real directory"
    );

    // A `current.new` that was left behind, also a link, is replaced.
    let target = root.path().join("record");
    fs::write(&target, "x").unwrap();
    symlink(&target, root.path().join("current.new")).unwrap();
    assert_eq!(store.activate(bundle.fingerprint()), Ok(()));
    assert_eq!(store.current(), Ok(Some(bundle.fingerprint())));
    let record = fs::read(root.path().join("current")).unwrap();
    assert_eq!(
        record,
        format!("{}\n", bundle.fingerprint().hex()).as_bytes()
    );
    assert_eq!(fs::read(&target).unwrap(), b"x");
    assert!(!root.path().join("current.new").exists());

    // A generation that is broken is not chosen, and the record stays.
    let generation = root
        .path()
        .join("generations")
        .join(bundle.fingerprint().hex());
    fs::write(generation.join("crs/rules/a.data"), "three\n").unwrap();
    let before = fs::read(root.path().join("current")).unwrap();
    assert_eq!(
        refusal(store.activate(bundle.fingerprint())),
        "a file of the generation differs from its manifest"
    );
    assert_eq!(fs::read(root.path().join("current")).unwrap(), before);
}

#[test]
fn a_generation_is_chosen_only_if_the_chosen_one_is_the_one_expected() {
    let root = scratch();
    let mut store = opened(root.path());
    let first = made(&mut store, &rules());
    let second = made(&mut store, &other_rules());
    // Nothing is chosen yet, so nothing is expected.
    assert_eq!(
        refusal(store.activate_if_current(first, second)),
        NOT_EXPECTED.0
    );
    assert_eq!(store.current(), Ok(None));
    store.activate(first).unwrap();
    // Another command chose `second` after the caller saw `first`: that choice stays.
    opened(root.path()).activate(second).unwrap();
    assert_eq!(
        refusal(store.activate_if_current(first, first)),
        NOT_EXPECTED.0
    );
    assert_eq!(store.current(), Ok(Some(second)));
    // The generation that is chosen is the one expected: it is replaced, and the lock is free again.
    assert_eq!(store.activate_if_current(second, first), Ok(()));
    assert_eq!(store.current(), Ok(Some(first)));
    assert_eq!(store.activate(second), Ok(()));
    // A generation that is not sound is refused after the check, and the record stays.
    assert_eq!(
        refusal(store.activate_if_current(second, generation())),
        "the generation is not a real directory"
    );
    assert_eq!(store.current(), Ok(Some(second)));
}

#[test]
fn a_stage_removes_only_the_old_bundles_of_the_right_name_and_kind() {
    let root = scratch();
    let mut store = opened(root.path());
    store.stage(&rules()).unwrap();
    store.discard().unwrap();
    let staging = root.path().join("staging");
    let (old, other, link) = ("0".repeat(32), "not-ours".to_owned(), "1".repeat(32));
    make_dir(&staging.join(&old));
    fs::write(staging.join(&old).join("file"), "x").unwrap();
    make_dir(&staging.join(&other));
    symlink(root.path(), staging.join(&link)).unwrap();
    store.stage(&rules()).unwrap();
    let mut left = names(&staging);
    left.retain(|name| *name != store_stage_name(&store));
    assert_eq!(left, [link, other]);
    assert!(root.path().join("lock").is_file());
    store.discard().unwrap();
}

/// The name of the bundle that is staged now.
fn store_stage_name(store: &FileStore) -> String {
    let import = store.import.as_ref().unwrap();
    import.dir.file_name().unwrap().to_str().unwrap().to_owned()
}

#[test]
fn only_a_real_directory_under_a_fingerprint_is_a_generation() {
    let root = scratch();
    let store = opened(root.path());
    let generations = root.path().join("generations");
    make_dir(&generations);
    make_dir(&generations.join(HEX));
    make_dir(&generations.join("not-a-fingerprint"));
    fs::write(generations.join("1".repeat(64)), "x").unwrap();
    let listed = store.list().unwrap();
    assert_eq!(
        listed.iter().map(|g| g.fingerprint).collect::<Vec<_>>(),
        [generation()]
    );
    assert!(listed[0].made > 0);
}

// ---- the generations that a proxy uses ----

fn other_rules() -> Bundle {
    bundle(
        &[("rules/other.conf", "SecDebugLogLevel 1\n")],
        &["rules/other.conf"],
    )
}

/// Makes the bundle a generation of the store.
fn made(store: &mut FileStore, bundle: &Bundle) -> Fingerprint {
    store.stage(bundle).unwrap();
    store.commit().unwrap();
    bundle.fingerprint()
}

#[test]
fn a_generation_is_removed_unless_it_is_chosen_held_or_missing() {
    let root = scratch();
    let mut store = opened(root.path());
    let first = made(&mut store, &rules());
    let second = made(&mut store, &other_rules());
    store.activate(first).unwrap();

    assert_eq!(
        refusal(store.remove(first)),
        "the generation is the current one"
    );
    assert_eq!(
        refusal(store.remove(generation())),
        "the generation is not a real directory"
    );
    // Two holds can live together; the generation is in use as long as one of them does.
    let (hold, other) = (store.hold(second).unwrap(), store.hold(second).unwrap());
    let in_use = "the generation is used by a running proxy";
    assert_eq!(refusal(store.remove(second)), in_use);
    drop(hold);
    assert_eq!(refusal(store.remove(second)), in_use);
    drop(other);
    assert!(store.generation_dir(second).is_ok());

    assert_eq!(store.remove(second), Ok(()));
    assert_eq!(
        refusal(store.generation_dir(second)),
        "the generation is not a real directory"
    );
    assert_eq!(store.list().unwrap().len(), 1);
    // Nothing is left of it: no staged copy, no marker, and the lock of the store is free.
    assert!(names(&root.path().join("staging")).is_empty());
    assert!(names(&root.path().join("using")).is_empty());
    assert_eq!(store.activate(first), Ok(()));
}

#[test]
fn a_hold_taken_after_a_removal_is_found_out_by_the_generation_directory() {
    let root = scratch();
    let mut store = opened(root.path());
    let second = made(&mut store, &other_rules());
    store.remove(second).unwrap();
    // The hold itself is given: the caller asks for the directory next, as the proxy does.
    let _late = store.hold(second).unwrap();
    assert_eq!(
        refusal(store.generation_dir(second)),
        "the generation is not a real directory"
    );
}

#[test]
fn nothing_is_removed_when_the_chosen_generation_cannot_be_told() {
    let root = scratch();
    let mut store = opened(root.path());
    let first = made(&mut store, &rules());
    fs::write(root.path().join("current"), "not a record\n").unwrap();
    assert_eq!(
        refusal(store.remove(first)),
        "the current generation record is broken"
    );
    assert!(store.generation_dir(first).is_ok());
}

#[test]
fn a_link_or_a_fifo_in_place_of_the_marker_is_refused_without_waiting() {
    let root = scratch();
    let mut store = opened(root.path());
    let first = made(&mut store, &rules());
    let using = root.path().join("using");
    make_dir(&using);
    let marker = using.join(first.hex());
    symlink(root.path().join("lock"), &marker).unwrap();
    let cannot = "the usage lock of the generation cannot be opened";
    assert_eq!(refusal(store.hold(first)), cannot);
    assert_eq!(refusal(store.remove(first)), cannot);
    // A FIFO that nobody reads cannot be opened for writing without waiting, and the open does not wait.
    fs::remove_file(&marker).unwrap();
    make_fifo(&marker);
    let store = FileStore::open(root.path()).unwrap();
    assert_eq!(within(move || refusal(store.hold(first))), cannot);
}

#[test]
fn the_manifest_of_a_generation_lists_its_files_in_the_order_of_their_paths() {
    let root = scratch();
    let mut store = opened(root.path());
    let fingerprint = made(&mut store, &rules());
    let manifest = store.manifest(fingerprint).unwrap();
    let paths: Vec<&str> = manifest.files().iter().map(|f| f.path.as_str()).collect();
    assert_eq!(
        paths,
        ["crs/rules/a.conf", "crs/rules/a.data", "rules/local.conf"]
    );
    assert_eq!(manifest.load().len(), 2);
    assert_eq!(
        refusal(store.manifest(generation())),
        "the generation is not a real directory"
    );
}
