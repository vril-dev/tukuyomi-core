use super::*;

fn status(sig_ign: &str) -> String {
    format!(
        "Name:\tproxy\nSigPnd:\t0000000000000000\nSigIgn:\t{sig_ign}\nSigCgt:\t0000000000000000\n"
    )
}

#[test]
fn sigchld_in_the_ignored_mask_is_refused() {
    // SIGCHLD is signal 17: bit 16.
    assert_eq!(sigchld_ignored(&status("0000000000010000")), Ok(true));
    assert_eq!(sigchld_ignored(&status("ffffffffffffffff")), Ok(true));
}

#[test]
fn other_ignored_signals_pass() {
    // The neighbours of bit 16.
    assert_eq!(sigchld_ignored(&status("0000000000008000")), Ok(false));
    assert_eq!(sigchld_ignored(&status("0000000000020000")), Ok(false));
    assert_eq!(sigchld_ignored(&status("fffffffffffeffff")), Ok(false));
}

#[test]
fn a_missing_or_malformed_mask_is_an_error_not_a_pass() {
    let bad = "the ignored-signal mask is missing or malformed";
    assert_eq!(sigchld_ignored("Name:\tproxy\n"), Err(bad));
    assert_eq!(sigchld_ignored(&status("+000000000010000")), Err(bad));
    assert_eq!(sigchld_ignored(&status("00000000000100000")), Err(bad));
}

#[test]
fn a_descriptor_without_the_close_on_exec_bit_is_refused() {
    let info = |flags: &str| format!("pos:\t0\nflags:\t{flags}\nmnt_id:\t12\nino:\t5\n");
    assert_eq!(lacks_cloexec(&info("0100002")), Ok(true));
    // Every bit below O_CLOEXEC set, the bit itself not.
    assert_eq!(lacks_cloexec(&info("01777777")), Ok(true));
    assert_eq!(lacks_cloexec(&info("37777777777")), Ok(false));
}

#[test]
fn a_descriptor_with_the_close_on_exec_bit_passes() {
    let info = |flags: &str| format!("pos:\t0\nflags:\t{flags}\nmnt_id:\t12\n");
    assert_eq!(lacks_cloexec(&info("02000000")), Ok(false));
    assert_eq!(lacks_cloexec(&info("02100002")), Ok(false));
}

#[test]
fn missing_or_malformed_flags_are_an_error_not_a_pass() {
    let bad = "the descriptor flags are missing or malformed";
    assert_eq!(lacks_cloexec("pos:\t0\n"), Err(bad));
    assert_eq!(lacks_cloexec("flags:\t09\n"), Err(bad));
    assert_eq!(lacks_cloexec("flags:\t020000000000\n"), Err(bad));
}

#[test]
fn descriptor_names_are_plain_decimal_numbers() {
    assert_eq!(fd_number("3"), Some(3));
    assert_eq!(fd_number("4294967295"), Some(u32::MAX));
    assert_eq!(fd_number("4294967296"), None);
    assert_eq!(fd_number("+3"), None);
    assert_eq!(fd_number(""), None);
}

fn uids(ids: &str) -> String {
    format!("Name:\tproxy\nUmask:\t0022\nUid:\t{ids}\nGid:\t1\t2\t3\t4\n")
}

#[test]
fn the_user_ids_are_exactly_four_numbers_in_the_order_of_the_status_file() {
    assert_eq!(
        user_ids_of(&uids("1000\t1001\t1002\t1003")),
        Ok([1000, 1001, 1002, 1003])
    );
    let bad = "the user ids are missing or malformed";
    assert_eq!(user_ids_of(&uids("1\t2\t3")), Err(bad));
    assert_eq!(user_ids_of(&uids("1\t2\t3\t4\t5")), Err(bad));
    assert_eq!(user_ids_of(&uids("a\t2\t3\t4")), Err(bad));
    assert_eq!(user_ids_of("Name:\tproxy\n"), Err(bad));
}

#[test]
fn a_zero_in_any_of_the_four_user_ids_is_refused() {
    let root = "the process runs as root";
    // Each place alone, then all of them: the saved id lets a process return to root, the file system id owns
    // what it creates.
    for ids in [
        "0\t1\t2\t3",
        "1\t0\t2\t3",
        "1\t2\t0\t3",
        "1\t2\t3\t0",
        "0\t0\t0\t0",
    ] {
        assert_eq!(not_root_in(&uids(ids)), Err(root), "{ids}");
    }
}

#[test]
fn user_ids_that_are_all_above_zero_pass_and_ids_that_cannot_be_read_do_not() {
    // 1 passes in every place, and so does the largest id.
    assert_eq!(not_root_in(&uids("1\t1\t1\t1")), Ok(()));
    assert_eq!(not_root_in(&uids("1000\t1001\t1002\t4294967295")), Ok(()));
    let bad = "the user ids are missing or malformed";
    // One past the largest id does not fit.
    assert_eq!(not_root_in(&uids("1000\t1001\t1002\t4294967296")), Err(bad));
    assert_eq!(not_root_in("Name:\tproxy\n"), Err(bad));
    assert_eq!(not_root_in(&uids("0\t1\t2")), Err(bad));
}

#[test]
fn a_private_directory_is_a_real_directory_of_the_user_closed_to_group_and_others() {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};

    let root = std::env::temp_dir().join(format!("tukuyomi-proxy-host-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let uid = fs_uid().unwrap();
    assert_eq!(private_dir(&root, uid), Ok(()));
    // The user id of another owner: a directory of another owner cannot be made without privilege.
    assert_eq!(
        private_dir(&root, uid.wrapping_add(1)),
        Err("the directory is not owned by this user")
    );
    for mode in [0o750, 0o705] {
        fs::set_permissions(&root, fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(
            private_dir(&root, uid),
            Err("the directory has group or other permission bits")
        );
    }
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(root.join("file"), b"").unwrap();
    symlink(&root, root.join("link")).unwrap();
    assert_eq!(
        private_dir(&root.join("file"), uid),
        Err("the directory is not a real directory")
    );
    assert_eq!(
        private_dir(&root.join("link"), uid),
        Err("the directory is not a real directory")
    );
    assert_eq!(
        private_dir(&root.join("absent"), uid),
        Err("the directory cannot be read")
    );
    fs::remove_dir_all(&root).unwrap();
}
