//! A generation of an engine that this build cannot use, met by the real binary: the commands that make or choose it,
//! `config check` and the start. The rules store of a test is given a generation of the engine ModSecurity, made from
//! the files of the test generation with a manifest of version 4, and the configuration is given an inspector for
//! that engine, so that what refuses the generation is the missing pinned build of the kernel. The inspector that the
//! configuration names is never started. The admin tests use the helpers that make such a store.

use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::{Value, json};
use tukuyomi_proxy::rules::bundle::Fingerprint;

use crate::rules::{assert_start_refused, rules};
use crate::support::*;

pub(crate) const NOT_PINNED: &str = "the inspector build of the engine is not pinned";
const NOT_NAMED: &str = "kernel.engines has no inspector for the engine of the generation";

/// Puts a generation of the engine ModSecurity in the store of the test root, beside the one of the test, and
/// returns its name. It has the files of the test generation, so only the engine differs.
pub(crate) fn add_generation(root: &Path) -> String {
    let old = generation_dir(root);
    let manifest = fs::read_to_string(old.join("manifest.json")).expect("read the manifest");
    let body = manifest
        .strip_prefix(r#"{"version":1,"files":"#)
        .and_then(|rest| rest.strip_suffix("]}\n"))
        .expect("the manifest of the test rules is of version 1");
    let text = format!(
        r#"{{"version":4,"engine":"modsecurity","mode":"block","files":{body}],"routes":[]}}{}"#,
        "\n"
    );
    let name = Fingerprint::of(text.as_bytes()).hex();
    let dir = root.join(STORE).join("generations").join(&name);
    fs::DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(dir.join("rules"))
        .expect("make the generation");
    let file = Path::new("rules").join("basic.conf");
    fs::copy(old.join(&file), dir.join(&file)).expect("copy the rule file");
    fs::write(dir.join("manifest.json"), text).expect("write the manifest");
    name
}

/// Lets the configuration of the test root name an inspector for the engine ModSecurity: the one of Coraza, a file
/// that exists.
pub(crate) fn name_inspector(root: &Path) {
    let path = root.join("config.json");
    let text = fs::read_to_string(&path).expect("read the configuration");
    let mut config: Value = serde_json::from_str(&text).expect("parse the configuration");
    let inspector = config["kernel"]["inspector"].clone();
    config["kernel"]["engines"] = json!({"modsecurity": {"inspector": inspector}});
    fs::write(&path, config.to_string()).expect("write the configuration");
}

pub(crate) fn current(root: &Path) -> String {
    fs::read_to_string(root.join(STORE).join("current")).expect("read the chosen generation")
}

/// The store chooses `name`, as a build that could use its engine would have let it.
fn choose(root: &Path, name: &str) {
    fs::write(root.join(STORE).join("current"), format!("{name}\n"))
        .expect("choose the generation");
}

#[test]
#[ignore = "needs a built inspector"]
fn a_chosen_generation_of_an_engine_with_no_pinned_build_ends_config_check_and_the_start_with_exit_code_1()
 {
    let idle = Idle::new("engine_check", &Knobs::quick(), |root| {
        name_inspector(root);
        let name = add_generation(root);
        choose(root, &name);
    });
    let output = Command::new(env!("CARGO_BIN_EXE_tukuyomi-proxy"))
        .arg("config")
        .arg("check")
        .arg(idle.root().join("config.json"))
        .stdin(Stdio::null())
        .output()
        .expect("run the command");
    let err = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(output.status.code(), Some(1), "{err}");
    assert!(output.stdout.is_empty());
    assert_eq!(
        err,
        format!(
            "config check: configuration accepted\nconfig check: rules generation refused: {NOT_PINNED}\n"
        )
    );

    assert_start_refused(
        "engine_start",
        |root| {
            name_inspector(root);
            let name = add_generation(root);
            choose(root, &name);
        },
        &[STORE],
        &format!("start: rules generation refused: {NOT_PINNED}"),
    );
}

#[test]
#[ignore = "needs a built inspector"]
fn the_commands_refuse_an_engine_with_no_pinned_build_before_they_change_the_store() {
    let idle = Idle::new("engine_commands", &Knobs::quick(), name_inspector);
    let root = idle.root();
    let other = add_generation(root);
    let chosen = current(root);
    let refused = |command: &str, sentence: &str| {
        format!("rules {command}: configuration refused: {sentence}\n")
    };

    let ran = rules(root, "activate", &[OsStr::new(&other)]);
    assert_eq!((ran.code, ran.out.as_str()), (Some(2), ""));
    assert_eq!(ran.err, refused("activate", NOT_PINNED));
    assert_eq!(current(root), chosen);

    let file = rules_file();
    let import = [
        OsStr::new("--rules"),
        file.as_os_str(),
        OsStr::new("--engine"),
        OsStr::new("modsecurity"),
    ];
    let ran = rules(root, "import", &import);
    assert_eq!((ran.code, ran.out.as_str()), (Some(2), ""));
    assert_eq!(ran.err, refused("import", NOT_PINNED));
    // A name that is no engine is a wrong argument.
    let wrong = [
        OsStr::new("--rules"),
        file.as_os_str(),
        OsStr::new("--engine"),
        OsStr::new("Coraza"),
    ];
    let ran = rules(root, "import", &wrong);
    assert_eq!((ran.code, ran.out.as_str()), (Some(2), ""));
    assert!(
        ran.err
            .starts_with("rules: --engine is not the name of an engine (coraza or modsecurity)\n"),
        "{}",
        ran.err
    );

    // The list shows the engine of each generation.
    let listed = rules(root, "list", &[]);
    assert_eq!(listed.code, Some(0), "{}", listed.err);
    let line = |name: &str| {
        listed
            .out
            .lines()
            .find(|l| l.starts_with(name))
            .unwrap_or_else(|| panic!("{name} is not listed in {:?}", listed.out))
            .split_whitespace()
            .skip(2)
            .collect::<Vec<_>>()
            .join(" ")
    };
    assert_eq!(line(&other), "block modsecurity");
    assert_eq!(line(&generation()), "block coraza current");

    // With no inspector for the engine in the configuration, the sentence is the other one.
    let bare = Idle::new("engine_unnamed", &Knobs::quick(), |_| {});
    let other = add_generation(bare.root());
    let ran = rules(bare.root(), "activate", &[OsStr::new(&other)]);
    assert_eq!((ran.code, ran.out.as_str()), (Some(2), ""));
    assert_eq!(ran.err, refused("activate", NOT_NAMED));
    let ran = rules(bare.root(), "import", &import);
    assert_eq!(ran.code, Some(2), "{}", ran.err);
    assert_eq!(ran.err, refused("import", NOT_NAMED));
}
