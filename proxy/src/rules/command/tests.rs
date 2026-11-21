use super::*;
use crate::managed::store::tests::Fixture;
use crate::rules::file_store::FileStore;
use serde_json::json;

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
    assert_eq!(inputs.mode, Mode::Block);
    assert!(!import(&["--rules", "a.conf"]).1);
}

#[test]
fn detect_only_makes_a_detect_bundle_wherever_it_stands() {
    for text in [
        ["--detect-only", "--rules", "a.conf"],
        ["--rules", "a.conf", "--detect-only"],
    ] {
        let (inputs, accept_block) = import(&text);
        assert_eq!((inputs.mode, accept_block), (Mode::Detect, false));
        assert_eq!(inputs.rules, [PathBuf::from("a.conf")]);
    }
}

#[test]
fn routes_names_one_file_wherever_it_stands() {
    for text in [
        ["--routes", "r.json", "--rules", "a.conf"],
        ["--rules", "a.conf", "--routes", "r.json"],
    ] {
        let (inputs, _) = import(&text);
        assert_eq!(inputs.routes, Some(PathBuf::from("r.json")));
    }
    assert_eq!(import(&["--rules", "a.conf"]).0.routes, None);
    let config = "/etc/tukuyomi.json";
    assert_eq!(
        refusal(&["import", config, "--routes", "a.json", "--routes", "b.json"]),
        "--routes is given twice"
    );
    assert_eq!(
        refusal(&["import", config, "--routes"]),
        "an option needs a value that does not start with --"
    );
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
fn deactivate_takes_the_lowercase_name_of_one_engine() {
    let config = "/etc/tukuyomi.json";
    for (name, engine) in [
        ("coraza", Engine::Coraza),
        ("modsecurity", Engine::ModSecurity),
    ] {
        assert_eq!(
            parse(&args(&["deactivate", config, name])),
            Ok(Command::Deactivate {
                config: PathBuf::from(config),
                engine
            })
        );
    }
    let wrong = "the engine is not the name of an engine (coraza or modsecurity)";
    for name in ["Coraza", ""] {
        assert_eq!(refusal(&["deactivate", config, name]), wrong, "{name:?}");
    }
    let one = "deactivate takes one engine";
    assert_eq!(refusal(&["deactivate", config]), one);
    assert_eq!(
        refusal(&["deactivate", config, "coraza", "modsecurity"]),
        one
    );
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
        result: Ok(vec![
            Accepted::Block {
                probe: "GET /",
                phase: 2,
                rule_id: 9202,
                status: 403,
            },
            Accepted::Detected {
                probe: "POST / with a JSON body",
                rule_id: 949110,
                status: 403,
            },
        ]),
        detail: None,
        clean: true,
    };
    assert_eq!(
        reported(&accepted),
        [
            "rules import: accepted a block: GET /: rule 9202 in phase 2, status 403",
            "rules import: detected: POST / with a JSON body: rule 949110, status 403",
        ]
    );
}

#[test]
fn engine_names_the_engine_of_the_bundle_wherever_it_stands_and_is_coraza_when_left_out() {
    assert_eq!(import(&["--rules", "a.conf"]).0.engine, Engine::Coraza);
    for text in [
        ["--engine", "modsecurity", "--rules", "a.conf"],
        ["--rules", "a.conf", "--engine", "modsecurity"],
    ] {
        let (inputs, _) = import(&text);
        assert_eq!(inputs.engine, Engine::ModSecurity);
        assert_eq!(inputs.rules, [PathBuf::from("a.conf")]);
    }
    let (inputs, _) = import(&["--engine", "coraza", "--rules", "a.conf"]);
    assert_eq!(inputs.engine, Engine::Coraza);
    let config = "/etc/tukuyomi.json";
    assert_eq!(
        refusal(&["import", config, "--engine", "coraza", "--engine", "coraza"]),
        "--engine is given twice"
    );
    for name in ["", "Coraza", "mod_security", "modsecurity "] {
        assert_eq!(
            refusal(&["import", config, "--engine", name]),
            "--engine is not the name of an engine (coraza or modsecurity)",
            "{name:?}"
        );
    }
    assert_eq!(
        refusal(&["import", config, "--engine"]),
        "an option needs a value that does not start with --"
    );
}

/// Runs the command `text` and gives how it ended, the standard output and the standard error.
fn command(text: &[&str]) -> (Exit, String, String) {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let exit = run(&args(text), &mut out, &mut err);
    (
        exit,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

/// The main file of `fixture` without `managed`, which has an inspector for ModSecurity and the one group `app`, which
/// names `engine` if there is one and has the default engine if there is none. Gives its path.
fn main_with(fixture: &Fixture, engine: Option<&str>) -> String {
    let path = fixture.main_file(|m| {
        m.as_object_mut().unwrap().remove("managed");
        let mut group = json!({"servers": [{
            "address": "127.0.0.1:9000", "weight": 1, "max_fails": 1, "fail_timeout_ms": 1000, "backup": false,
        }]});
        if let Some(engine) = engine {
            group["engine"] = json!(engine);
        }
        m["forward"] = json!({
            "resolve_timeout_ms": 1000, "upstreams": {"app": group}, "routes": [], "default_upstream": "app",
        });
        m["kernel"]["engines"] =
            json!({"modsecurity": {"inspector": "/opt/tukuyomi/inspector-modsecurity"}});
    });
    path.to_str().unwrap().to_owned()
}

/// The fingerprints that `rules list` marks as chosen.
fn marked(main: &str) -> Vec<String> {
    let (exit, out, err) = command(&["list", main]);
    assert_eq!(exit, Exit::Done, "{err}");
    out.lines()
        .filter(|line| line.ends_with(" current"))
        .map(|line| line.split(' ').next().unwrap().to_owned())
        .collect()
}

#[test]
fn each_engine_has_the_generation_chosen_for_it_and_deactivate_leaves_an_engine_with_none() {
    let fixture = Fixture::new();
    let main = main_with(&fixture, None);
    // The rules store has a generation chosen for Coraza, and one chosen for ModSecurity: the list marks both.
    fixture.choose_rules(Engine::ModSecurity);
    let store = FileStore::open(&fixture.rules()).unwrap();
    let chosen = |engine| store.current(engine).unwrap().unwrap().hex();
    let (coraza, modsecurity) = (chosen(Engine::Coraza), chosen(Engine::ModSecurity));
    assert_ne!(coraza, modsecurity);
    let mut both = vec![coraza.clone(), modsecurity.clone()];
    both.sort();
    let mut seen = marked(&main);
    seen.sort();
    assert_eq!(seen, both);

    // The default engine is Coraza and no group names ModSecurity: ModSecurity can be left with none.
    let (exit, out, err) = command(&["deactivate", &main, "modsecurity"]);
    assert_eq!(
        (exit, out, err),
        (
            Exit::Done,
            format!("{modsecurity} deactivated\n"),
            String::new()
        )
    );
    assert_eq!(marked(&main), std::slice::from_ref(&coraza));
    // The default engine is used by the group `app`, and an engine with none chosen has nothing to leave.
    let (exit, out, err) = command(&["deactivate", &main, "coraza"]);
    let uses = "rules deactivate: the configuration uses the engine\n";
    assert_eq!((exit, out.as_str(), err.as_str()), (Exit::Failed, "", uses));
    assert_eq!(marked(&main), std::slice::from_ref(&coraza));
    let (exit, out, err) = command(&["deactivate", &main, "modsecurity"]);
    let none = "rules deactivate: no generation is chosen\n";
    assert_eq!((exit, out.as_str(), err.as_str()), (Exit::Failed, "", none));
    // `activate` chooses a generation for its engine again, and a group that names the engine uses it.
    let (exit, out, err) = command(&["activate", &main, &modsecurity]);
    assert_eq!(
        (exit, out, err),
        (
            Exit::Done,
            format!("{modsecurity} current\n"),
            String::new()
        )
    );
    let main = main_with(&fixture, Some("modsecurity"));
    let (exit, out, err) = command(&["deactivate", &main, "modsecurity"]);
    assert_eq!((exit, out.as_str(), err.as_str()), (Exit::Failed, "", uses));
    assert_eq!(chosen(Engine::ModSecurity), modsecurity);
}
