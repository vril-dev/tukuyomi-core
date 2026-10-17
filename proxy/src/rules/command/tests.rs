use super::*;
use crate::rules::trial::Accepted;

const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn args(text: &[&str]) -> Vec<OsString> {
    text.iter().map(OsString::from).collect()
}

fn import(text: &[&str]) -> (Inputs, bool) {
    let mut all = vec!["import", "/etc/tukuyomi.json"];
    all.extend_from_slice(text);
    match parse(&args(&all)) {
        Ok(Command::Import {
            config,
            inputs,
            accept_block,
        }) => {
            assert_eq!(config, Path::new("/etc/tukuyomi.json"));
            (inputs, accept_block)
        }
        other => panic!("{text:?}: {other:?}"),
    }
}

fn refusal(text: &[&str]) -> &'static str {
    parse(&args(text)).unwrap_err()
}

#[test]
fn the_options_of_import_are_read_in_the_order_they_are_given() {
    let (inputs, accept_block) = import(&[
        "--crs",
        "crs",
        "--rules",
        "z.conf",
        "--crs-off",
        "A.conf",
        "--rules",
        "a.conf",
        "--data",
        "list.data",
        "--crs-off",
        "B.conf",
        "--accept-block",
    ]);
    assert!(accept_block);
    assert_eq!(inputs.crs, Some(PathBuf::from("crs")));
    assert_eq!(inputs.crs_off, args(&["A.conf", "B.conf"]));
    assert_eq!(
        inputs.rules,
        [PathBuf::from("z.conf"), PathBuf::from("a.conf")]
    );
    assert_eq!(inputs.data, [PathBuf::from("list.data")]);
    assert!(!import(&["--rules", "a.conf"]).1);
}

#[test]
fn a_wrong_argument_is_a_usage_error() {
    let config = "/etc/tukuyomi.json";
    assert_eq!(refusal(&[]), "a command is missing");
    assert_eq!(refusal(&["delete", config]), "unknown command");
    assert_eq!(refusal(&["list"]), "the configuration file is missing");
    for relative in ["tukuyomi.json", "/etc/../tukuyomi.json", "/etc/"] {
        assert_eq!(
            refusal(&["list", relative]),
            "the configuration file is not an absolute clean path"
        );
    }
    assert_eq!(
        refusal(&["list", config, "x"]),
        "list takes no argument after the configuration file"
    );
    assert_eq!(
        refusal(&["activate", config]),
        "activate takes one fingerprint"
    );
    assert_eq!(
        refusal(&["activate", config, HEX, HEX]),
        "activate takes one fingerprint"
    );
    let digits = "the fingerprint is not 64 lowercase hexadecimal digits";
    assert_eq!(refusal(&["activate", config, &HEX.to_uppercase()]), digits);
    assert_eq!(refusal(&["activate", config, &HEX[1..]]), digits);
    assert!(matches!(
        parse(&args(&["activate", config, HEX])),
        Ok(Command::Activate { .. })
    ));
    assert_eq!(refusal(&["remove", config]), "remove takes one fingerprint");
    assert_eq!(
        refusal(&["remove", config, HEX, HEX]),
        "remove takes one fingerprint"
    );
    assert_eq!(refusal(&["remove", config, &HEX[1..]]), digits);
    assert!(matches!(
        parse(&args(&["remove", config, HEX])),
        Ok(Command::Remove { .. })
    ));

    let import = |text: &[&str]| {
        let mut all = vec!["import", config];
        all.extend_from_slice(text);
        refusal(&all)
    };
    let value = "an option needs a value that does not start with --";
    assert_eq!(import(&["--rules"]), value);
    assert_eq!(import(&["--rules", "--data"]), value);
    assert_eq!(
        import(&["--crs", "a", "--crs", "b"]),
        "--crs is given twice"
    );
    assert_eq!(import(&["--crs-off", "A.conf"]), "--crs-off needs --crs");
    assert_eq!(
        import(&["--rules", "a.conf", "stray"]),
        "an option needs a value that does not start with --"
    );
    assert_eq!(import(&["--unknown", "x"]), "unknown option");
}

#[test]
fn what_came_from_outside_is_written_with_every_byte_outside_ascii_escaped() {
    assert_eq!(
        escaped(b"tkv0-inspector: start: rules \"x\" 1/2"),
        "tkv0-inspector: start: rules \"x\" 1/2"
    );
    // Escape, carriage return, line feed, DEL, a NUL, the C1 control CSI (U+009B), the right-to-left override.
    assert_eq!(
        escaped(b"\x1b[31m\r\n\x7f\0 \xc2\x9b \xe2\x80\xae"),
        "\\x1b[31m\\x0d\\x0a\\x7f\\x00 \\xc2\\x9b \\xe2\\x80\\xae"
    );
}

/// The lines that `report` writes for a trial that ended as `finish` says.
fn reported(finish: &Finish) -> Vec<String> {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    report(
        finish,
        &mut Terminal {
            out: &mut out,
            err: &mut err,
        },
    );
    assert!(out.is_empty(), "nothing is a result of a trial");
    String::from_utf8(err)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
fn the_end_of_a_trial_is_reported_with_the_rule_the_exit_and_the_escaped_line() {
    let blocked = Finish {
        result: Err(Failed::Blocked {
            probe: "GET /",
            phase: 1,
            rule_id: 949110,
            status: 403,
        }),
        detail: None,
        clean: true,
    };
    assert_eq!(
        reported(&blocked),
        ["rules import: the trial failed: GET /: blocked by rule 949110 in phase 1, status 403"]
    );
    let refused = Finish {
        result: Err(Failed::Start(Failure::Exit(11))),
        detail: Some(b"tkv0-inspector: start: rules: \x1b]0;x\x07\xe2\x80\xae\n".to_vec()),
        clean: false,
    };
    assert_eq!(
        reported(&refused),
        [
            "rules import: the trial failed: the inspector refused to start (exit code 11)",
            "rules import: the inspector said: \"tkv0-inspector: start: rules: \\x1b]0;x\\x07\\xe2\\x80\\xae\"",
            "rules import: the inspector did not stop cleanly; a process or a directory may be left behind",
        ]
    );
    let accepted = Finish {
        result: Ok(vec![Accepted {
            probe: "GET /",
            phase: 2,
            rule_id: 9202,
            status: 403,
        }]),
        detail: None,
        clean: true,
    };
    assert_eq!(
        reported(&accepted),
        ["rules import: accepted a block: GET /: rule 9202 in phase 2, status 403"]
    );
}
