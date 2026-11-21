//! The engines in real processes. The rules store of a test holds a generation of the engine ModSecurity too, made
//! from the files of the test generation with a manifest of version 4, and a group of the configuration can name that
//! engine. The tests show that a request goes to the inspector of the engine of its upstream group, whose generation
//! gives the mode, that a start and `config check` refuse an engine that a group names and the store does not choose
//! a generation for, and that the commands refuse a generation of an engine that the configuration has no inspector
//! for. The helpers that make such a store are used by the tests of the engine and of the admin process too.

use std::ffi::OsStr;
use std::fs;
use std::net::SocketAddr;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;

use serde_json::{Value, json};
use tukuyomi_proxy::rules::bundle::Fingerprint;

use crate::config_check::config_check;
use crate::rules::{assert_start_refused, rules};
use crate::support::*;
use crate::upstreams::get_for;

pub(crate) const NOT_NAMED: &str =
    "kernel.engines has no inspector for the engine of the generation";

/// Puts a generation of the engine ModSecurity in the store of the test root, beside the one of the test, and
/// returns its name. It has the files of the test generation, so only the engine differs.
pub(crate) fn add_generation(root: &Path) -> String {
    add_generation_of(root, "modsecurity", "block")
}

/// The same for the engine `engine` and the mode `mode` (`block` or `detect`).
pub(crate) fn add_generation_of(root: &Path, engine: &str, mode: &str) -> String {
    let old = generation_dir(root);
    let manifest = fs::read_to_string(old.join("manifest.json")).expect("read the manifest");
    let body = manifest
        .strip_prefix(r#"{"version":1,"files":"#)
        .and_then(|rest| rest.strip_suffix("]}\n"))
        .expect("the manifest of the test rules is of version 1");
    let text = format!(
        r#"{{"version":4,"engine":"{engine}","mode":"{mode}","files":{body}],"routes":[]}}{}"#,
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

/// The store chooses `name` for the engine `engine`, as `rules activate` would have it, without the checks of the
/// command.
pub(crate) fn choose(root: &Path, engine: &str, name: &str) {
    fs::write(
        root.join(STORE).join(format!("current.{engine}")),
        format!("{name}\n"),
    )
    .expect("choose the generation");
}

/// Two groups: `plain` for the host `example.test`, with the engine that names none, and `second` for
/// `m.example.test`, whose engine is ModSecurity. The first upstream is the server of `plain` and the second the
/// server of `second`.
pub(crate) fn two_engines(addresses: &[SocketAddr]) -> Value {
    json!({
        "resolve_timeout_ms": RESOLVE_TIMEOUT_MS,
        "upstreams": {
            "plain": {"servers": [server(addresses[0])]},
            "second": {"engine": "modsecurity", "servers": [server(addresses[1])]},
        },
        "routes": [
            {"host": "m.example.test", "upstream": "second"},
            {"host": "example.test", "upstream": "plain"},
        ],
        "default_upstream": "",
    })
}

#[test]
#[ignore = "needs a built inspector"]
fn an_upstream_whose_engine_has_no_generation_chosen_ends_config_check_and_the_start_with_exit_code_1()
 {
    // A generation of ModSecurity is in the store and the configuration names its inspector, but the store does not
    // choose it, and a group uses that engine.
    let edit = |root: &Path| {
        name_modsecurity_inspector(root);
        use_modsecurity(root, "main");
        add_generation(root);
    };
    let idle = Idle::new("engine_check", &Knobs::quick(), edit);
    let ran = config_check(&idle);
    assert_eq!(ran.code, Some(1), "{}", ran.err);
    assert!(ran.out.is_empty());
    assert_eq!(
        ran.err,
        "config check: configuration accepted\nconfig check: rules store refused: no generation is chosen\n"
    );

    assert_start_refused(
        "engine_start",
        edit,
        &[STORE],
        "start: rules store refused: no generation is chosen",
    );
}

#[test]
#[ignore = "needs a built inspector"]
fn a_request_goes_to_the_inspector_of_the_engine_of_its_upstream_and_follows_the_mode_of_that_generation()
 {
    let knobs = Knobs {
        upstreams: 2,
        forward: two_engines,
        ..Knobs::quick()
    };
    let proxy = Proxy::start_with("engine_routing", knobs, |root| {
        name_modsecurity_inspector(root);
        let name = add_generation_of(root, "modsecurity", "detect");
        choose(root, "modsecurity", &name);
    });
    let lines = proxy.records.lines();
    for line in [
        "start: rules engine coraza",
        "start: rules mode block",
        "start: rules engine modsecurity",
        "start: rules mode detect",
        "start: upstream second: engine modsecurity, mode detect",
    ] {
        assert!(lines.iter().any(|l| l == line), "records: {lines:#?}");
    }
    // The rule on the URI stops the probe of the group whose engine is Coraza, which blocks.
    assert_empty_answer(
        &exchange(proxy.port, &get_for("example.test", "/block-probe/x")),
        403,
    );
    proxy.records.conn("the record of Coraza", |l| {
        blocked_by(l, 9201) && l["engine"] == "coraza" && l["mode"] == "block"
    });
    // The same request to the group of ModSecurity goes through: the generation of that engine only detects.
    let reply = exchange(proxy.port, &get_for("m.example.test", "/block-probe/x"));
    assert_eq!(reply.status(), 200, "answer: {:?}", reply.text());
    let record = proxy
        .records
        .conn("the detection record of ModSecurity", |l| {
            is_answer(l, "forwarded", 200, "detected by a rule") && l["rule"] == 9201
        });
    assert_eq!(
        (&record["engine"], &record["mode"], &record["upstream"]),
        (&json!("modsecurity"), &json!("detect"), &json!("second"))
    );
    // A request that no rule matches goes through in both, and its record names the engine of its group.
    for (host, engine) in [
        ("example.test", "coraza"),
        ("m.example.test", "modsecurity"),
    ] {
        let reply = exchange(proxy.port, &get_for(host, "/ok"));
        assert_eq!(reply.status(), 200, "answer: {:?}", reply.text());
        proxy
            .records
            .conn(&format!("the forwarded record of {engine}"), |l| {
                is_answer(l, "forwarded", 200, "forwarded") && l["engine"] == engine
            });
    }
    assert_eq!(proxy.upstream.requests().len(), 1);
    assert_eq!(proxy.others[0].requests().len(), 2);
    proxy.finish(1);
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
