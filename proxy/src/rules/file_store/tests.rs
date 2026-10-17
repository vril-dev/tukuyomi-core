use super::*;
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
