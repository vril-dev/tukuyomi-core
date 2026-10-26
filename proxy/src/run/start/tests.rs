use super::*;
use crate::log;

fn os_args(list: &[&str]) -> Vec<OsString> {
    list.iter().map(OsString::from).collect()
}

#[test]
fn config_check_refuses_a_wrong_argument_with_exit_code_2() {
    let log = log::start_logger(log::Format::Json).unwrap();
    let wrong: [&[&str]; 5] = [
        &[],
        &["check"],
        &["check", "/etc/a.json", "/etc/b.json"],
        &["check", "etc/a.json"],
        &["verify", "/etc/a.json"],
    ];
    for list in wrong {
        assert_eq!(config_check(&os_args(list), &log), EXIT_USAGE, "{list:?}");
    }
    assert_eq!(
        check_path(&os_args(&["check", "/etc/a.json"])),
        Ok(PathBuf::from("/etc/a.json"))
    );
}
