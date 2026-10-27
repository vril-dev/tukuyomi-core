use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::SystemTime;

use super::*;
use crate::admin::password::Hash;
use crate::admin::users::Role;
use crate::admin::waf::history::{Ended, Kind};
use crate::rules::bundle::Fingerprint;

/// A fresh 0700 directory under the temp directory, removed with everything in it when dropped.
pub(crate) struct TestDir(PathBuf);

impl TestDir {
    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(crate) fn scratch() -> TestDir {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "tukuyomi-proxy-admin-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    DirBuilder::new().mode(0o700).create(&dir).unwrap();
    // A umask can only remove bits; make the mode exactly 0700.
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    TestDir(dir)
}

fn mode_of(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn user(name: &str, password: &str, changed: u64) -> User {
    let mut user = User::new(name, Role::Viewer, Hash::new(password, 1000).unwrap(), 5);
    user.changed = changed;
    user
}

#[test]
fn the_store_makes_its_directories_and_refuses_a_directory_that_others_can_reach() {
    let dir = scratch();
    FileAdminStore::open(dir.path()).unwrap();
    assert_eq!(mode_of(&dir.path().join("users")), 0o700);
    assert_eq!(mode_of(&dir.path().join("audit")), 0o700);
    // Opened again, it takes what is there.
    FileAdminStore::open(dir.path()).unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o750)).unwrap();
    assert!(FileAdminStore::open(dir.path()).is_err());
    assert!(FileAdminStore::open(Path::new("relative/dir")).is_err());
}

#[test]
fn a_user_is_replaced_only_when_it_is_the_one_that_was_read() {
    let dir = scratch();
    let store = FileAdminStore::open(dir.path()).unwrap();
    store
        .create_first(&user("alice", "first password", 10))
        .unwrap();
    let file = dir.path().join("users").join("alice.json");
    assert_eq!(mode_of(&file), 0o600);
    let read = store.user("alice").unwrap().unwrap();
    assert!(read.password.verify("first password"));
    store
        .replace(10, &user("alice", "second password", 11))
        .unwrap();
    // The first write was read at 10: a second write that still says so is refused, and changes nothing.
    assert_eq!(
        store.replace(10, &user("alice", "third password", 12)),
        Err(CONFLICT)
    );
    let now = store.user("alice").unwrap().unwrap();
    assert_eq!(now.changed, 11);
    assert!(now.password.verify("second password"));
    assert!(
        store
            .replace(11, &user("bob", "other password", 12))
            .is_err()
    );
    // Nothing but the user file is left in `users`.
    let names: Vec<_> = fs::read_dir(dir.path().join("users"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(names, [std::ffi::OsString::from("alice.json")]);
}

#[test]
fn a_name_that_no_user_can_have_is_not_looked_up_and_a_broken_file_is_a_refusal() {
    let dir = scratch();
    let store = FileAdminStore::open(dir.path()).unwrap();
    assert_eq!(store.user("../alice").unwrap(), None);
    assert_eq!(store.user("").unwrap(), None);
    assert_eq!(store.user("nobody").unwrap(), None);
    fs::write(dir.path().join("users").join("alice.json"), b"{").unwrap();
    assert!(store.user("alice").is_err());
    // A broken file is a user all the same: the first user is not made beside it.
    assert!(
        store
            .create_first(&user("bob", "some password", 1))
            .is_err()
    );
}

#[test]
fn a_write_waits_for_nobody_and_is_refused_while_another_process_holds_the_lock() {
    let dir = scratch();
    let store = FileAdminStore::open(dir.path()).unwrap();
    let other = FileAdminStore::open(dir.path()).unwrap();
    let held = other.lock().unwrap();
    assert_eq!(
        store.create_first(&user("alice", "first password", 1)),
        Err(BUSY)
    );
    drop(held);
    store
        .create_first(&user("alice", "first password", 1))
        .unwrap();
}

fn activation(actor: &str, result: Ended) -> Activation {
    let (from, to) = (Fingerprint::of(b"a"), Fingerprint::of(b"b"));
    Activation::new(SystemTime::now(), actor, (from, to), Kind::Activate, result)
}

#[test]
fn the_history_is_appended_whole_and_read_back_newest_first() {
    let dir = scratch();
    let store = FileAdminStore::open(dir.path()).unwrap();
    assert!(store.activations(10).unwrap().is_empty());
    for (i, ended) in [Ended::Switched, Ended::Refused, Ended::Failed]
        .into_iter()
        .enumerate()
    {
        store
            .record_activation(&activation(&format!("user{i}"), ended))
            .unwrap();
    }
    let file = dir.path().join("activations.log");
    assert_eq!(mode_of(&file), 0o600);
    let newest = store.activations(2).unwrap();
    let actors: Vec<&str> = newest.iter().map(|a| a.actor.as_str()).collect();
    assert_eq!(actors, ["user2", "user1"]);
    // A line that a crash cut off is left out, and the next line starts a line of its own.
    let mut text = fs::read(&file).unwrap();
    text.extend_from_slice(b"{\"ts\":\"cut");
    fs::write(&file, text).unwrap();
    assert_eq!(store.activations(10).unwrap().len(), 3);
    store
        .record_activation(&activation("user3", Ended::Switched))
        .unwrap();
    let all = store.activations(10).unwrap();
    assert_eq!(all.len(), 4);
    assert_eq!(all[0].actor, "user3");
    // A link in the place of the file is not followed.
    fs::remove_file(&file).unwrap();
    std::os::unix::fs::symlink(dir.path().join("elsewhere"), &file).unwrap();
    assert!(
        store
            .record_activation(&activation("user4", Ended::Failed))
            .is_err()
    );
    assert!(store.activations(10).is_err());
}
