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
    assert_eq!(sigchld_ignored(&status("0000000000010001")), Ok(true));
}

#[test]
fn other_ignored_signals_pass() {
    // The neighbours of bit 16, and the usual SIGPIPE-ignored mask.
    assert_eq!(sigchld_ignored(&status("0000000000008000")), Ok(false));
    assert_eq!(sigchld_ignored(&status("0000000000020000")), Ok(false));
    assert_eq!(sigchld_ignored(&status("0000000000001000")), Ok(false));
    assert_eq!(sigchld_ignored(&status("0000000000000000")), Ok(false));
    assert_eq!(sigchld_ignored(&status("fffffffffffeffff")), Ok(false));
}

#[test]
fn a_missing_or_malformed_mask_is_an_error_not_a_pass() {
    let bad = "the ignored-signal mask is missing or malformed";
    assert_eq!(sigchld_ignored("Name:\tproxy\n"), Err(bad));
    assert_eq!(sigchld_ignored(&status("")), Err(bad));
    assert_eq!(sigchld_ignored(&status("+000000000010000")), Err(bad));
    assert_eq!(sigchld_ignored(&status("000000000001000g")), Err(bad));
    assert_eq!(sigchld_ignored(&status("00000000000100000")), Err(bad));
    assert_eq!(sigchld_ignored(&status("0x00000000010000")), Err(bad));
}

#[test]
fn a_descriptor_without_the_close_on_exec_bit_is_refused() {
    let info = |flags: &str| format!("pos:\t0\nflags:\t{flags}\nmnt_id:\t12\nino:\t5\n");
    assert_eq!(lacks_cloexec(&info("0100002")), Ok(true));
    assert_eq!(lacks_cloexec(&info("00")), Ok(true));
    // Every bit below O_CLOEXEC set, the bit itself not.
    assert_eq!(lacks_cloexec(&info("01777777")), Ok(true));
    assert_eq!(lacks_cloexec(&info("37777777777")), Ok(false));
}

#[test]
fn a_descriptor_with_the_close_on_exec_bit_passes() {
    let info = |flags: &str| format!("pos:\t0\nflags:\t{flags}\nmnt_id:\t12\n");
    assert_eq!(lacks_cloexec(&info("02000000")), Ok(false));
    assert_eq!(lacks_cloexec(&info("02100002")), Ok(false));
    assert_eq!(lacks_cloexec(&info("02000002")), Ok(false));
}

#[test]
fn missing_or_malformed_flags_are_an_error_not_a_pass() {
    let bad = "the descriptor flags are missing or malformed";
    assert_eq!(lacks_cloexec("pos:\t0\n"), Err(bad));
    assert_eq!(lacks_cloexec("flags:\t\n"), Err(bad));
    assert_eq!(lacks_cloexec("flags:\t09\n"), Err(bad));
    assert_eq!(lacks_cloexec("flags:\t-1\n"), Err(bad));
    assert_eq!(lacks_cloexec("flags:\t020000000000\n"), Err(bad));
}

#[test]
fn descriptor_names_are_plain_decimal_numbers() {
    assert_eq!(fd_number("0"), Some(0));
    assert_eq!(fd_number("3"), Some(3));
    assert_eq!(fd_number("4294967295"), Some(u32::MAX));
    assert_eq!(fd_number("4294967296"), None);
    assert_eq!(fd_number("+3"), None);
    assert_eq!(fd_number("-3"), None);
    assert_eq!(fd_number("3 "), None);
    assert_eq!(fd_number(""), None);
    assert_eq!(fd_number("0000000003"), Some(3));
    assert_eq!(fd_number("00000000003"), None);
}
