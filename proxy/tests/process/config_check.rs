//! The command `config check` in a real process, on a configuration and a rules store that no proxy uses. A
//! configuration that the start would take gives exit code 0 and `accepted` on the standard output, the lines of the
//! start on the standard error, each headed `config check:`; one that breaks a rule between two of its values gives 2,
//! and a rules store without a chosen generation gives 1. Nothing is started: no process listens on the port of the
//! configuration afterwards, and no directory of a kernel is in the root. The hold on the generation is taken as at
//! the start, so the store may have the file that marks the generation as used afterwards; the tests look at no more
//! of the store than that it is there.

use std::fs;
use std::process::{Command, Stdio};

use crate::support::*;

/// How the command ended, and what it wrote.
struct Ran {
    code: Option<i32>,
    out: String,
    err: String,
}

/// Runs `tukuyomi-proxy config check <the configuration of the root>` and waits for it.
fn config_check(idle: &Idle) -> Ran {
    let output = Command::new(env!("CARGO_BIN_EXE_tukuyomi-proxy"))
        .arg("config")
        .arg("check")
        .arg(idle.root().join("config.json"))
        .stdin(Stdio::null())
        .output()
        .expect("run the command");
    Ran {
        code: output.status.code(),
        out: String::from_utf8_lossy(&output.stdout).into_owned(),
        err: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// Checks that the root holds the configuration and the store, which are what the test put there, and that no
/// process listens on the port of the configuration.
fn assert_nothing_started(idle: &Idle) {
    let mut left: Vec<String> = fs::read_dir(idle.root())
        .expect("the test root is readable")
        .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect::<Result<_, _>>()
        .expect("list the test root");
    left.sort();
    assert_eq!(left, ["config.json", STORE]);
    assert_turned_away(idle.port);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_configuration_that_breaks_a_relation_is_refused_with_exit_code_2() {
    // The time to read a head is one millisecond above the time of a request, which is 60 s.
    let knobs = Knobs {
        head_read_ms: 60_001,
        ..Knobs::quick()
    };
    let idle = Idle::new("check_refused", &knobs, |_| {});
    let ran = config_check(&idle);
    assert_eq!(ran.code, Some(2), "{}", ran.err);
    assert_eq!(ran.out, "");
    assert_eq!(
        ran.err,
        "config check: configuration refused: head_read_ms is above request_total_ms\n"
    );
    assert_nothing_started(&idle);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_configuration_that_the_start_would_take_is_accepted_and_nothing_is_started() {
    let idle = Idle::new("check_accepted", &Knobs::quick(), |_| {});
    let ran = config_check(&idle);
    assert_eq!(ran.code, Some(0), "{}", ran.err);
    assert_eq!(ran.out, "accepted\n");
    assert_eq!(
        ran.err,
        format!(
            "config check: configuration accepted\nconfig check: rules generation {}\nconfig check: rules mode block\nconfig check: rules routes 0\n",
            generation()
        )
    );
    assert_nothing_started(&idle);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_store_without_a_chosen_generation_is_refused_with_exit_code_1() {
    let idle = Idle::new("check_no_generation", &Knobs::quick(), |root| {
        fs::remove_file(root.join(STORE).join("current")).expect("remove the record");
    });
    let ran = config_check(&idle);
    assert_eq!(ran.code, Some(1), "{}", ran.err);
    assert_eq!(ran.out, "");
    assert_eq!(
        ran.err,
        "config check: configuration accepted\nconfig check: rules store refused: no generation is chosen\n"
    );
    assert_nothing_started(&idle);
}
