//! A generation of an engine that the configuration has no inspector for, met by the real binary: the commands that
//! make or choose it, `config check` and the start. The rules store of a test is given a generation of the engine
//! ModSecurity, made from the files of the test generation with a manifest of version 4, and the configuration is not
//! given an inspector for that engine in `kernel.engines`, so that what refuses the generation is that missing entry.
//! The helpers that make such a store are used by the tests of the engine and of the admin process too.

use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;

use tukuyomi_proxy::rules::bundle::Fingerprint;

use crate::config_check::config_check;
use crate::rules::{assert_start_refused, rules};
use crate::support::*;

pub(crate) const NOT_NAMED: &str =
    "kernel.engines has no inspector for the engine of the generation";

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

pub(crate) fn current(root: &Path) -> String {
    fs::read_to_string(root.join(STORE).join("current")).expect("read the chosen generation")
}

/// The store chooses `name`, as `rules activate` would have it, without the checks of the command.
pub(crate) fn choose(root: &Path, name: &str) {
    fs::write(root.join(STORE).join("current"), format!("{name}\n"))
        .expect("choose the generation");
}

#[test]
#[ignore = "needs a built inspector"]
fn a_chosen_generation_of_an_engine_with_no_inspector_in_the_configuration_ends_config_check_and_the_start_with_exit_code_1()
 {
    let idle = Idle::new("engine_check", &Knobs::quick(), |root| {
        let name = add_generation(root);
        choose(root, &name);
    });
    let ran = config_check(&idle);
    assert_eq!(ran.code, Some(1), "{}", ran.err);
    assert!(ran.out.is_empty());
    assert_eq!(
        ran.err,
        format!(
            "config check: configuration accepted\nconfig check: rules generation refused: {NOT_NAMED}\n"
        )
    );

    assert_start_refused(
        "engine_start",
        |root| {
            let name = add_generation(root);
            choose(root, &name);
        },
        &[STORE],
        &format!("start: rules generation refused: {NOT_NAMED}"),
    );
}

#[test]
#[ignore = "needs a built inspector"]
fn the_commands_refuse_an_engine_with_no_inspector_in_the_configuration_before_they_change_the_store()
 {
    let idle = Idle::new("engine_commands", &Knobs::quick(), |_| {});
    let root = idle.root();
    let other = add_generation(root);
    let chosen = current(root);
    let refused = |command: &str| format!("rules {command}: configuration refused: {NOT_NAMED}\n");

    let ran = rules(root, "activate", &[OsStr::new(&other)]);
    assert_eq!((ran.code, ran.out.as_str()), (Some(2), ""));
    assert_eq!(ran.err, refused("activate"));
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
    assert_eq!(ran.err, refused("import"));
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
}
