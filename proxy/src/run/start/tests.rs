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

#[test]
fn admin_takes_a_configuration_file_or_bootstrap_or_reset_with_a_file_and_a_name() {
    let path = |text: &str| PathBuf::from(text);
    assert_eq!(
        admin_args(&os_args(&["/etc/a.json"])),
        Ok(AdminArgs::Run(path("/etc/a.json")))
    );
    assert_eq!(
        admin_args(&os_args(&["bootstrap", "/etc/a.json", "alice"])),
        Ok(AdminArgs::Bootstrap {
            config: path("/etc/a.json"),
            name: "alice".to_owned()
        })
    );
    assert_eq!(
        admin_args(&os_args(&["reset", "/etc/a.json", "alice"])),
        Ok(AdminArgs::Reset {
            config: path("/etc/a.json"),
            name: "alice".to_owned()
        })
    );
    let wrong: [&[&str]; 10] = [
        &[],
        &["etc/a.json"],
        &["/etc/a.json", "/etc/b.json"],
        &["bootstrap"],
        &["bootstrap", "/etc/a.json"],
        &["bootstrap", "etc/a.json", "alice"],
        &["bootstrap", "/etc/a.json", "alice", "bob"],
        &["reset"],
        &["reset", "/etc/a.json"],
        &["reset", "etc/a.json", "alice"],
    ];
    for list in wrong {
        assert!(admin_args(&os_args(list)).is_err(), "{list:?}");
    }
    let log = log::start_logger(log::Format::Json).unwrap();
    assert_eq!(admin_command(&os_args(&["etc/a.json"]), &log), EXIT_USAGE);
}
