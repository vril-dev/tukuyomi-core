//! The tests of the store, and the one helper of the tests of `managed` that makes a store, its versions and the main
//! file that names it (`Fixture`).

use super::*;
use serde_json::{Value, json};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::sync::atomic::{AtomicU32, Ordering};

/// The main file of the fixture without its `managed`: one plain listener, `forward` with its time only.
const MAIN: &str = r#"{"proxy":{"listeners":[{"address":"127.0.0.1:8080"}],"max_conns":1024,"max_head_bytes":8192,"max_body":1048576,"inspect_body":1048576,"max_body_wire":2097152,"max_buffered_bytes":8388608,"upstream_max_headers":100,"upstream_max_head_bytes":16384,"upstream_head_wire":65536,"drive_slice_ms":50,"ready_wait_ms":10000,"head_read_ms":10000,"body_read_ms":30000,"inspect_wait_ms":30000,"upstream_connect_ms":5000,"upstream_header_ms":30000,"request_total_ms":60000,"response_idle_ms":60000,"conn_total_ms":120000,"stop_inspect_ms":5000,"stop_wait_ms":10000,"keepalive_timeout_ms":75000,"keepalive_requests":1000,"keepalive_time_ms":60000,"lingering_time_ms":30000,"lingering_timeout_ms":5000,"lingering_bytes":262144,"trusted_proxies":[],"upstream_keepalive":32,"upstream_keepalive_timeout_ms":60000,"upstream_keepalive_requests":1000},"forward":{"resolve_timeout_ms":30000},"kernel":{"inspector":"/opt/tukuyomi/inspector","tmp_root":"/var/lib/tukuyomi/tmp","gomaxprocs":2,"gomemlimit":1073741824,"slots":4,"wait_queue":16,"records":20,"discard_limit":4,"tick_ms":100,"hello_wait_ms":5000,"frame_io_ms":1000,"verdict_wait_ms":2000,"wait_deadline_ms":3000,"closed_wait_ms":2000,"stop_after_ms":2000,"drain_wait_ms":1000,"exit_wait_ms":1000,"kill_grace_ms":1000,"restarts":3,"restart_window_ms":60000},"rules":{"store":{"kind":"file","dir":"/var/lib/tukuyomi/rules"}}}"#;

/// A directory of a test (`TMPDIR`), removed with everything in it when dropped, which holds a managed store
/// (`store/`, 0700) and the main file that names it (`config.json`).
pub(crate) struct Fixture {
    root: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

impl Fixture {
    pub(crate) fn new() -> Fixture {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "tukuyomi-proxy-managed-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        for dir in [root.clone(), root.join("store")] {
            DirBuilder::new().mode(0o700).create(&dir).unwrap();
            // A umask can only remove bits; make the mode exactly 0700.
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        Fixture { root }
    }

    /// The directory of the test, for the other files a test needs.
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    /// The directory of the store.
    pub(crate) fn dir(&self) -> PathBuf {
        self.root.join("store")
    }

    pub(crate) fn store(&self) -> Store {
        match Store::open(&self.dir()) {
            Ok(store) => store,
            Err(e) => panic!("the store was refused: {}", e.0),
        }
    }

    /// Puts `bytes` in the store as a file and gives its name.
    pub(crate) fn file(&self, bytes: &[u8]) -> [u8; 32] {
        self.store().put_file(bytes).unwrap().0
    }

    /// Puts `version` in the store in its written form and gives its name.
    pub(crate) fn version(&self, version: &Value) -> [u8; 32] {
        let bytes = serde_json::to_vec(version).unwrap();
        self.store().put_version(&bytes).unwrap().0
    }

    /// Puts `version` in the store and chooses it.
    pub(crate) fn current(&self, version: &Value) -> [u8; 32] {
        let name = self.version(version);
        self.store().choose(name).unwrap();
        name
    }

    /// Writes the main file with `managed` naming the store, after `edit`, and gives its path.
    pub(crate) fn main_file(&self, edit: impl FnOnce(&mut Value)) -> PathBuf {
        let mut main: Value = serde_json::from_str(MAIN).unwrap();
        main["managed"] = json!({ "dir": self.dir() });
        edit(&mut main);
        let path = self.root.join("config.json");
        fs::write(&path, main.to_string()).unwrap();
        path
    }

    /// A version with one site for `site.test` whose chain and key are files of the store with these bytes, and the
    /// group `app` at 127.0.0.1:9000, which serves every request.
    pub(crate) fn plain_version(&self, chain: &[u8], key: &[u8]) -> Value {
        json!({
            "sites": [{
                "name": "site",
                "hosts": ["site.test"],
                "certificate": {"chain": hex(&self.file(chain)), "key": hex(&self.file(key))},
            }],
            "upstreams": {"app": {"servers": [{
                "address": "127.0.0.1:9000", "weight": 1, "max_fails": 1, "fail_timeout_ms": 10000, "backup": false,
            }]}},
            "routes": [],
            "default_upstream": "app",
        })
    }
}

fn refusal<T>(result: Result<T, ManagedError>) -> &'static str {
    match result {
        Err(e) => e.0,
        Ok(_) => panic!("accepted"),
    }
}

#[test]
fn only_a_private_real_directory_of_this_user_is_a_store() {
    let fixture = Fixture::new();
    let dir = fixture.dir();
    let owner = fs::metadata(&dir).unwrap().uid();
    assert!(Store::open_as(&dir, owner).is_ok());
    assert_eq!(
        refusal(Store::open_as(&dir, owner.wrapping_add(1))),
        "the directory is not owned by this user"
    );
    let link = fixture.root().join("link");
    symlink(&dir, &link).unwrap();
    assert_eq!(
        refusal(Store::open(&link)),
        "the directory is not a real directory"
    );
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o750)).unwrap();
    assert_eq!(
        refusal(Store::open(&dir)),
        "the directory has group or other permission bits"
    );
    assert_eq!(
        refusal(Store::open(Path::new("store"))),
        "the managed store directory is not an absolute clean path"
    );
}

#[test]
fn a_file_is_written_once_under_its_sha256_and_a_broken_copy_is_written_again() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let (name, placed) = store.put_file(b"chain").unwrap();
    assert_eq!((name, placed), (sha256(b"chain"), Placed::Created));
    assert_eq!(store.put_file(b"chain").unwrap().1, Placed::Existing);
    assert_eq!(&*store.file(name).unwrap(), b"chain");
    let path = store.file_path(name);
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
    fs::write(&path, b"other").unwrap();
    assert_eq!(
        refusal(store.file(name)),
        "a managed file does not match its name"
    );
    assert_eq!(store.put_file(b"chain").unwrap().1, Placed::Recreated);
    assert_eq!(&*store.file(name).unwrap(), b"chain");
    // Nothing but the file is left in the directory.
    let entries: Vec<_> = fs::read_dir(path.parent().unwrap()).unwrap().collect();
    assert_eq!(entries.len(), 1);
}

#[test]
fn a_version_or_a_file_that_is_a_link_or_too_large_is_refused() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let name = fixture.version(&json!({"a": 1}));
    let outside = fixture.root().join("outside.json");
    fs::write(&outside, br#"{"a":1}"#).unwrap();
    let path = fixture
        .dir()
        .join("versions")
        .join(format!("{}.json", hex(&name)));
    fs::remove_file(&path).unwrap();
    symlink(&outside, &path).unwrap();
    assert_eq!(
        refusal(store.version(name)),
        "the managed version cannot be read, or is a link"
    );
    let limit = vec![b' '; usize::try_from(MAX_BYTES).unwrap()];
    assert!(store.put_file(&limit).is_ok());
    let over = vec![b' '; usize::try_from(MAX_BYTES).unwrap() + 1];
    assert_eq!(
        refusal(store.put_file(&over)),
        "a managed file is over 1 MiB"
    );
    assert_eq!(
        refusal(store.version(sha256(b"absent"))),
        "the managed version is not in the store"
    );
    // The directory of the files is not followed either.
    let files = fixture.dir().join("files");
    fs::rename(&files, fixture.root().join("files")).unwrap();
    symlink(fixture.root().join("files"), &files).unwrap();
    assert_eq!(
        refusal(store.file(sha256(&limit))),
        "a directory of the managed store is not a real directory"
    );
}

#[test]
fn a_version_is_chosen_only_if_it_is_sound_and_current_names_it() {
    let fixture = Fixture::new();
    let store = fixture.store();
    assert_eq!(store.current(), Ok(None));
    let first = fixture.current(&json!({"a": 1}));
    assert_eq!(store.current(), Ok(Some(first)));
    let record = fs::read(fixture.dir().join("current")).unwrap();
    assert_eq!(record, format!("{}\n", hex(&first)).into_bytes());
    // A version that is not there, or does not match its name, is not chosen.
    assert_eq!(
        refusal(store.choose(sha256(b"absent"))),
        "the managed version is not in the store"
    );
    let second = fixture.version(&json!({"a": 2}));
    let path = fixture
        .dir()
        .join("versions")
        .join(format!("{}.json", hex(&second)));
    fs::write(&path, b"{}").unwrap();
    assert_eq!(
        refusal(store.choose(second)),
        "the managed version does not match its name"
    );
    assert_eq!(store.current(), Ok(Some(first)));
    assert!(!fixture.dir().join("current.new").exists());
    fs::write(fixture.dir().join("current"), b"not a name\n").unwrap();
    assert_eq!(
        refusal(store.current()),
        "the current managed version record is broken"
    );
}

#[test]
fn one_command_at_a_time_holds_the_lock() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let held = store.lock().unwrap();
    assert_eq!(
        refusal(store.lock()),
        "the managed store is in use by another command"
    );
    drop(held);
    assert!(store.lock().is_ok());
}

#[test]
fn the_list_has_the_versions_only() {
    let fixture = Fixture::new();
    let store = fixture.store();
    assert_eq!(store.versions(), Ok(Vec::new()));
    let name = fixture.version(&json!({"a": 1}));
    let versions = fixture.dir().join("versions");
    fs::write(versions.join("notes.json"), b"{}").unwrap();
    symlink(
        versions.join(format!("{}.json", hex(&name))),
        versions.join(format!("{}.json", "ab".repeat(32))),
    )
    .unwrap();
    let listed: Vec<[u8; 32]> = store
        .versions()
        .unwrap()
        .iter()
        .map(|listed| listed.name)
        .collect();
    assert_eq!(listed, [name]);
}

#[test]
fn the_directory_of_a_site_with_acme_is_named_by_its_hosts_in_any_order() {
    let hosts = |list: &[&str]| -> Vec<String> { list.iter().map(|h| (*h).to_owned()).collect() };
    let name = acme_name(&hosts(&["b.test", "a.test"]));
    assert_eq!(name, acme_name(&hosts(&["a.test", "b.test"])));
    assert_eq!(name, sha256(b"a.test\nb.test\n"));
    assert_ne!(name, acme_name(&hosts(&["a.test"])));
}

#[test]
fn a_certificate_of_a_site_with_acme_is_missing_only_when_a_directory_or_a_file_is_not_there() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let name = acme_name(&["a.test".to_owned()]);
    assert!(matches!(store.issued(name), Ok(None)));
    let (chain, key) = store.issue_places(name).unwrap();
    let dir = fixture.dir().join("acme").join(hex(&name));
    assert_eq!(
        (chain.clone(), key.clone()),
        (dir.join("chain"), dir.join("key"))
    );
    for made in [fixture.dir().join("acme"), dir.clone()] {
        assert_eq!(fs::symlink_metadata(&made).unwrap().mode() & 0o777, 0o700);
    }
    assert!(matches!(store.issued(name), Ok(None)));
    // Between the two renames of the command: the key is there, the chain not yet.
    fs::write(&key, b"key").unwrap();
    assert!(matches!(store.issued(name), Ok(None)));
    fs::write(&chain, b"chain").unwrap();
    let (read_chain, read_key) = store.issued(name).unwrap().unwrap();
    assert_eq!(
        (&read_chain[..], &read_key[..]),
        (&b"chain"[..], &b"key"[..])
    );
    // A link in the place of a file is a fault, not a certificate that is not issued yet.
    let outside = fixture.root().join("chain");
    fs::write(&outside, b"chain").unwrap();
    fs::remove_file(&chain).unwrap();
    symlink(&outside, &chain).unwrap();
    assert_eq!(
        refusal(store.issued(name)),
        "an issued certificate or key cannot be read, or is a link"
    );
}

#[test]
fn a_link_in_the_place_of_a_directory_of_a_site_with_acme_is_refused_for_reading_and_writing() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let name = acme_name(&["a.test".to_owned()]);
    let elsewhere = fixture.root().join("elsewhere");
    DirBuilder::new().mode(0o700).create(&elsewhere).unwrap();
    fs::write(elsewhere.join("chain"), b"chain").unwrap();
    fs::write(elsewhere.join("key"), b"key").unwrap();
    store
        .issue_places(acme_name(&["b.test".to_owned()]))
        .unwrap();
    let site = fixture.dir().join("acme").join(hex(&name));
    symlink(&elsewhere, &site).unwrap();
    let not_real = "a directory of the managed store is not a real directory";
    assert_eq!(refusal(store.issued(name)), not_real);
    assert_eq!(refusal(store.issue_places(name)), not_real);
    // The same for `acme/` itself, which is looked at first.
    let acme = fixture.dir().join("acme");
    fs::rename(&acme, fixture.root().join("acme")).unwrap();
    symlink(fixture.root().join("acme"), &acme).unwrap();
    assert_eq!(refusal(store.issued(name)), not_real);
    assert_eq!(refusal(store.issue_places(name)), not_real);
    // Nothing was made or changed through the links.
    let mut entries: Vec<_> = fs::read_dir(&elsewhere)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    entries.sort();
    assert_eq!(entries, ["chain", "key"]);
    assert_eq!(fs::read(elsewhere.join("chain")).unwrap(), b"chain");
}

#[test]
fn a_held_version_is_its_file_in_the_store_and_a_broken_one_that_is_held_is_not_replaced() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let version = fixture.plain_version(b"chain", b"key");
    let bytes = serde_json::to_vec(&version).unwrap();
    let name = fixture.version(&version);
    let path = store.path(Kind::Version, name);
    // A lock taken on a file that was removed after it was opened holds nothing.
    let opened = store.open_version(name).unwrap();
    fs::remove_file(&path).unwrap();
    assert_eq!(
        refusal(store.hold_opened(name, opened)),
        "the managed version is not in the store"
    );
    assert_eq!(fixture.version(&version), name);
    // A version that is held and then broken where it is is not replaced by the same bytes.
    let (read, hold) = store.hold(name).unwrap();
    assert_eq!(read, bytes);
    fs::write(&path, b"broken").unwrap();
    assert_eq!(
        refusal(store.put_version(&bytes)),
        "the managed version is in use"
    );
    assert_eq!(fs::read(&path).unwrap(), b"broken");
    drop(hold);
}

#[test]
fn the_chain_is_read_and_the_key_only_looked_at_for_the_admin_process() {
    let fixture = Fixture::new();
    let store = fixture.store();
    // A key of a site of the files that is broken and cannot be opened is there all the same, for it is not read.
    let key = fixture.file(b"key");
    let path = store.file_path(key);
    fs::write(&path, b"broken").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
    assert_eq!(store.look_file(key), Ok(()));
    assert!(store.file(key).is_err());
    // A file of 1 MiB is there, and one a byte over it is not a file of the store.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let file = File::options().write(true).open(&path).unwrap();
    file.set_len(MAX_BYTES).unwrap();
    assert_eq!(store.look_file(key), Ok(()));
    file.set_len(MAX_BYTES + 1).unwrap();
    assert_eq!(
        refusal(store.look_file(key)),
        "a managed file is not a regular file of at most 1 MiB"
    );
    // Nothing there is told by its sentence, which a link is not.
    fs::remove_file(&path).unwrap();
    assert_eq!(store.look_file(key), Err(FILE_NOT_IN_STORE));
    symlink(fixture.root().join("elsewhere"), &path).unwrap();
    assert_eq!(
        refusal(store.look_file(key)),
        "a managed file cannot be read, or is a link"
    );
    // The same for a site with acme: its chain is read, and its key only looked at.
    let name = acme_name(&["a.test".to_owned()]);
    assert!(matches!(store.issued_chain(name), Ok(None)));
    assert_eq!(store.issued_key(name), Ok(false));
    let (chain, key) = store.issue_places(name).unwrap();
    fs::write(&chain, b"chain").unwrap();
    fs::write(&key, b"broken").unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o000)).unwrap();
    let read = store.issued_chain(name).unwrap();
    assert_eq!(read.as_deref().map(Vec::as_slice), Some(&b"chain"[..]));
    assert_eq!(store.issued_key(name), Ok(true));
    assert!(store.issued(name).is_err());
    fs::remove_file(&key).unwrap();
    assert_eq!(store.issued_key(name), Ok(false));
    // A link in the place of the key is a fault, not a key that is not there.
    symlink(fixture.root().join("elsewhere"), &key).unwrap();
    assert_eq!(
        refusal(store.issued_key(name)),
        "an issued certificate or key cannot be read, or is a link"
    );
}
