use std::fs;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use super::*;

struct TestDir(PathBuf);

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn scratch() -> TestDir {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "tukuyomi-ship-dsn-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    TestDir(dir)
}

/// A file with `bytes` and the mode `mode`.
fn file(dir: &TestDir, bytes: &[u8], mode: u32) -> PathBuf {
    let path = dir.0.join("dsn");
    fs::write(&path, bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    path
}

fn uid(path: &Path) -> u32 {
    fs::metadata(path).unwrap().uid()
}

const TEXT: &[u8] = b"host=db.example port=5432 user=ship password=s3cret dbname=records\n";

#[test]
fn a_file_of_the_owner_is_read_without_the_spaces_around() {
    let dir = scratch();
    let path = file(&dir, TEXT, 0o600);
    let dsn = read(&path, uid(&path)).unwrap();
    assert_eq!(
        dsn.text(),
        "host=db.example port=5432 user=ship password=s3cret dbname=records"
    );
    // The text is not in the debug form.
    assert!(!format!("{dsn:?}").contains("s3cret"));
    // A mode of 0400 does as well.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(read(&path, uid(&path)).is_ok());
}

#[test]
fn a_file_with_group_or_other_bits_is_refused() {
    let dir = scratch();
    for mode in [0o640, 0o604, 0o660, 0o644, 0o601] {
        let path = file(&dir, TEXT, mode);
        let e = read(&path, uid(&path)).unwrap_err();
        assert_eq!(
            e, "the db_dsn_file has group or other permission bits",
            "{mode:o}"
        );
    }
}

#[test]
fn a_file_of_another_user_is_refused() {
    let dir = scratch();
    let path = file(&dir, TEXT, 0o600);
    let e = read(&path, uid(&path).wrapping_add(1)).unwrap_err();
    assert_eq!(e, "the db_dsn_file is not owned by this user");
}

#[test]
fn what_is_not_a_good_file_is_refused_with_no_part_of_it() {
    let dir = scratch();
    let me = uid(&dir.0);
    assert!(read(&dir.0.join("none"), me).is_err());
    assert_eq!(
        read(&dir.0, me).unwrap_err(),
        "the db_dsn_file is not a regular file"
    );
    for (bytes, words) in [
        (&b""[..], "the db_dsn_file is empty"),
        (&b" \n\n"[..], "the db_dsn_file is empty"),
        (
            &b"host=a password=\xff\xfe"[..],
            "the db_dsn_file does not hold UTF-8 text",
        ),
    ] {
        let path = file(&dir, bytes, 0o600);
        assert_eq!(read(&path, me).unwrap_err(), words);
    }
    // The limit and the first byte over it.
    let path = file(&dir, &vec![b'a'; 16 * 1024], 0o600);
    assert!(read(&path, me).is_ok());
    let path = file(&dir, &vec![b'a'; 16 * 1024 + 1], 0o600);
    assert_eq!(
        read(&path, me).unwrap_err(),
        "the db_dsn_file is over 16 KiB"
    );
}

#[test]
fn a_link_to_a_good_file_is_followed() {
    let dir = scratch();
    let path = file(&dir, TEXT, 0o600);
    let link = dir.0.join("link");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(read(&link, uid(&path)).is_ok());
}
