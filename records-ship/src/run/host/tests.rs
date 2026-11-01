use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

use super::*;

const STATUS: &str = "Name:\tx\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n";

#[test]
fn the_four_ids_are_read() {
    assert_eq!(user_ids_of(STATUS), Ok([1000, 1000, 1000, 1000]));
    assert_eq!(user_ids_of("Uid:\t1\t2\t3\t4\n"), Ok([1, 2, 3, 4]));
}

#[test]
fn a_missing_or_odd_line_is_refused() {
    for status in [
        "",
        "Uid:\t1000\t1000\t1000\n",
        "Uid:\t1000\t1000\t1000\t1000\t1000\n",
        "Uid:\t1000\t-1\t1000\t1000\n",
        "Uid:\t1000\t4294967296\t1000\t1000\n",
        "Uid:\t1000\t+5\t1000\t1000\n",
    ] {
        assert!(user_ids_of(status).is_err(), "{status:?}");
    }
}

#[test]
fn this_process_is_not_root_in_the_tests() {
    // The tests are not run as root; a root user ids line is what `not_root` refuses.
    assert!(not_root().is_ok());
    assert!(
        user_ids_of("Uid:\t1000\t0\t1000\t1000\n")
            .unwrap()
            .contains(&0)
    );
}

#[test]
fn a_directory_must_be_a_real_private_directory_of_the_user() {
    let base = std::env::temp_dir().join(format!("tukuyomi-ship-host-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
    let me = fs_uid().unwrap();
    assert_eq!(private_dir(&base, me), Ok(()));
    assert_eq!(
        private_dir(&base, me.wrapping_add(1)),
        Err("the directory is not owned by this user")
    );
    fs::set_permissions(&base, fs::Permissions::from_mode(0o750)).unwrap();
    assert_eq!(
        private_dir(&base, me),
        Err("the directory has group or other permission bits")
    );
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
    let link = base.join("link");
    std::os::unix::fs::symlink(&base, &link).unwrap();
    assert_eq!(
        private_dir(&link, me),
        Err("the directory is not a real directory")
    );
    assert_eq!(
        private_dir(&base.join("none"), me),
        Err("the directory cannot be read")
    );
    fs::remove_dir_all(&base).unwrap();
}

#[test]
fn the_files_of_a_directory_must_give_a_birth_time() {
    let base = std::env::temp_dir().join(format!("tukuyomi-ship-born-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
    // An empty directory, and one with a record file, on the file system of the tests.
    assert_eq!(birth_times(&base, 4), Ok(()));
    fs::write(base.join("records.log"), "x\n").unwrap();
    assert_eq!(birth_times(&base, 4), Ok(()));
    assert_eq!(
        birth_times(&base.join("none"), 4),
        Err("the directory cannot be read")
    );
    fs::remove_dir_all(&base).unwrap();
    // The file system of `/proc` gives no birth time for any of its files.
    assert_eq!(
        birth_times(Path::new("/proc"), 4),
        Err("the file system of the directory gives no birth time for its files")
    );
}
