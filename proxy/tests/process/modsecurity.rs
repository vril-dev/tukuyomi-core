//! The engine ModSecurity in real processes: the configuration names the built inspector of that engine in
//! `kernel.engines`, a group of the configuration names that engine, and the rules store holds a generation of it. The
//! generation of a test is made from the test rules with a manifest of version 4 (`engines::add_generation`), or by
//! `rules import --engine modsecurity`, which tries it with the real inspector. The tests show that the engine can be
//! chosen, started, blocking or only detecting, switched with SIGUSR1 one engine after the other, and imported. The
//! last one is the acceptance run of the engine with the Core Rule Set, which needs `TUKUYOMI_TEST_CRS`.

use std::ffi::OsStr;
use std::fs;
use std::path::Path;

use serde_json::{Value, json};

use crate::config_check::config_check;
use crate::engines::{add_generation, choose, two_engines};
use crate::rules::rules;
use crate::support::*;
use crate::upstreams::get_for;

/// The built inspector of ModSecurity is named in the configuration of the test root `root`, its one group uses that
/// engine, and a generation of that engine is added to the store, beside the one of the test. Returns the name of the
/// generation.
fn add_modsecurity(root: &Path) -> String {
    name_modsecurity_inspector(root);
    use_modsecurity(root, "main");
    add_generation(root)
}

/// Imports the rules `args` for the engine ModSecurity, chooses the generation that the import makes, and returns its
/// name.
fn import_and_choose(root: &Path, args: &[&OsStr]) -> String {
    import_and_choose_for(root, "modsecurity", args)
}

/// The same for the engine `engine`.
fn import_and_choose_for(root: &Path, engine: &str, args: &[&OsStr]) -> String {
    let mut all = vec![OsStr::new("--engine"), OsStr::new(engine)];
    all.extend_from_slice(args);
    let imported = rules(root, "import", &all);
    assert_eq!(imported.code, Some(0), "{}", imported.err);
    let created = imported
        .out
        .strip_suffix(" created\n")
        .unwrap_or_else(|| panic!("unexpected output {:?}", imported.out))
        .to_owned();
    let chosen = rules(root, "activate", &[OsStr::new(&created)]);
    assert_eq!(chosen.code, Some(0), "{}", chosen.err);
    created
}

/// Whether `record` is the record of an answer from the engine `engine`.
fn from_engine(record: &Value, engine: &str) -> bool {
    record["engine"] == engine
}

#[test]
#[ignore = "needs a built inspector"]
fn a_chosen_generation_of_modsecurity_passes_config_check_and_the_proxy_blocks_with_it() {
    let idle = Idle::new("modsec_check", &Knobs::quick(), |root| {
        let name = add_modsecurity(root);
        choose(root, "modsecurity", &name);
    });
    let ran = config_check(&idle);
    assert_eq!(ran.code, Some(0), "{}", ran.err);
    assert_eq!(ran.out, "accepted\n");
    assert!(
        ran.err.contains("config check: rules engine modsecurity\n"),
        "{}",
        ran.err
    );

    let proxy = Proxy::start_with("modsec_block", Knobs::quick(), |root| {
        let name = add_modsecurity(root);
        choose(root, "modsecurity", &name);
    });
    let lines = proxy.records.lines();
    for line in ["start: rules engine modsecurity", "start: rules mode block"] {
        assert!(lines.iter().any(|l| l == line), "records: {lines:#?}");
    }
    // The rule on the URI stops the probe in phase 1, and the rule on the body in phase 2; the record names the
    // engine. A request that no rule matches goes on to the upstream.
    assert_empty_answer(&exchange(proxy.port, &get("/block-probe/x")), 403);
    proxy.records.conn("the record of the URI rule", |l| {
        blocked_by(l, 9201) && from_engine(l, "modsecurity")
    });
    let body = post_form("/submit", &padded_form("block", 64));
    assert_empty_answer(&exchange(proxy.port, &body), 403);
    proxy.records.conn("the record of the body rule", |l| {
        blocked_by(l, 9202) && from_engine(l, "modsecurity")
    });
    assert_eq!(exchange(proxy.port, &get("/ok")).status(), 200);
    proxy.records.conn("the forwarded record", |l| {
        is_answer(l, "forwarded", 200, "forwarded") && from_engine(l, "modsecurity")
    });
    proxy.finish(1);
}

#[test]
#[ignore = "needs a built inspector"]
fn sigusr1_switches_the_engines_one_after_the_other_and_each_group_follows_the_generation_of_its_engine()
 {
    let knobs = Knobs {
        upstreams: 2,
        forward: two_engines,
        ..Knobs::quick()
    };
    let proxy = Proxy::start_with("modsec_switch", knobs, |root| {
        name_modsecurity_inspector(root);
        let name = add_generation(root);
        choose(root, "modsecurity", &name);
    });
    // Both engines have a generation that blocks.
    for (host, engine) in [
        ("example.test", "coraza"),
        ("m.example.test", "modsecurity"),
    ] {
        assert_empty_answer(&exchange(proxy.port, &get_for(host, "/block-probe/x")), 403);
        proxy.records.conn(&format!("the record of {engine}"), |l| {
            blocked_by(l, 9201) && from_engine(l, engine)
        });
    }

    // The store chooses a generation that only detects for each engine, and SIGUSR1 switches them: the default engine
    // first, and the other when the switch of the first has ended.
    let root = proxy.root().to_path_buf();
    let conf = rules_file();
    let args = [
        OsStr::new("--rules"),
        conf.as_os_str(),
        OsStr::new("--detect-only"),
    ];
    let coraza = import_and_choose_for(&root, "coraza", &args);
    let modsecurity = import_and_choose_for(&root, "modsecurity", &args);
    proxy.signal("USR1");
    for name in [&coraza, &modsecurity] {
        let switched = format!("reload: generation {name} is ready, switched");
        proxy
            .records
            .wait_lines("the switch", 1, |l| l == switched.as_str());
    }
    let lines = proxy.records.lines();
    let at = |line: String| {
        lines
            .iter()
            .position(|l| *l == line)
            .unwrap_or_else(|| panic!("no {line:?} in {lines:#?}"))
    };
    assert!(
        at(format!("reload: generation {coraza} is ready, switched"))
            < at(format!("reload: starting generation {modsecurity}")),
        "records: {lines:#?}"
    );

    // Each group is now judged by the generation of its engine, which only detects.
    for (host, engine, generation) in [
        ("example.test", "coraza", &coraza),
        ("m.example.test", "modsecurity", &modsecurity),
    ] {
        let reply = exchange(proxy.port, &get_for(host, "/block-probe/x"));
        assert_eq!(reply.status(), 200, "answer: {:?}", reply.text());
        let record = proxy
            .records
            .conn(&format!("the detection record of {engine}"), |l| {
                is_answer(l, "forwarded", 200, "detected by a rule") && from_engine(l, engine)
            });
        assert_eq!(record["generation"], generation[..16], "{record}");
    }
    proxy.finish(1);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_detect_only_generation_of_modsecurity_lets_a_matched_request_through_and_the_record_names_the_rule()
 {
    let mut detect = String::new();
    let proxy = Proxy::start_with("modsec_detect", Knobs::quick(), |root| {
        name_modsecurity_inspector(root);
        use_modsecurity(root, "main");
        let conf = rules_file();
        detect = import_and_choose(
            root,
            &[
                OsStr::new("--rules"),
                conf.as_os_str(),
                OsStr::new("--detect-only"),
            ],
        );
    });
    let lines = proxy.records.lines();
    for line in [
        format!("start: rules generation {detect}"),
        "start: rules engine modsecurity".to_owned(),
        "start: rules mode detect".to_owned(),
    ] {
        assert!(lines.contains(&line), "records: {lines:#?}");
    }
    // The URI rule would block the probe; the request goes to the upstream, and the record names the rule.
    let reply = exchange(proxy.port, &get("/block-probe/x"));
    assert_eq!(reply.status(), 200, "answer: {:?}", reply.text());
    assert_eq!(reply.message().body, UPSTREAM_BODY.as_bytes());
    let record = proxy.records.conn("the detection record", |l| {
        is_answer(l, "forwarded", 200, "detected by a rule") && l["rule"] == 9201
    });
    assert_eq!(
        (&record["engine"], &record["mode"]),
        (&json!("modsecurity"), &json!("detect"))
    );
    proxy.finish(1);
}

#[test]
#[ignore = "needs a built inspector"]
fn an_import_for_modsecurity_is_tried_by_its_inspector_and_a_rule_that_its_reader_refuses_makes_no_generation()
 {
    let idle = Idle::new("modsec_import", &Knobs::quick(), name_modsecurity_inspector);
    let root = idle.root();
    let conf = rules_file();
    let imported = rules(
        root,
        "import",
        &[
            OsStr::new("--engine"),
            OsStr::new("modsecurity"),
            OsStr::new("--rules"),
            conf.as_os_str(),
        ],
    );
    assert_eq!(imported.code, Some(0), "{}", imported.err);
    assert!(imported.err.is_empty(), "{}", imported.err);
    let made = imported
        .out
        .strip_suffix(" created\n")
        .unwrap_or_else(|| panic!("unexpected output {:?}", imported.out))
        .to_owned();
    let listed = rules(root, "list", &[]);
    assert!(
        listed
            .out
            .lines()
            .any(|l| l.starts_with(&made) && l.ends_with(" block modsecurity")),
        "{}",
        listed.out
    );

    // A rule that denies and is not logged: Coraza takes it, and the reader of ModSecurity refuses it, since a block
    // that leaves no message would not name its rule. The refusal ends the trial, and nothing is made.
    let silent = root.join("silent.conf");
    fs::write(
        &silent,
        "SecRule REQUEST_URI \"@beginsWith /silent\" \"id:9401,phase:1,deny,status:403,nolog\"\n",
    )
    .expect("write the rule file");
    let with = |engine: &'static str| {
        rules(
            root,
            "import",
            &[
                OsStr::new("--engine"),
                OsStr::new(engine),
                OsStr::new("--rules"),
                silent.as_os_str(),
            ],
        )
    };
    let refused = with("modsecurity");
    assert_eq!(refused.code, Some(1), "{}", refused.err);
    assert!(refused.out.is_empty(), "{}", refused.out);
    assert!(
        refused
            .err
            .contains("the inspector refused to start (exit code 11)"),
        "{}",
        refused.err
    );
    assert!(
        !refused.err.contains("did not stop cleanly"),
        "{}",
        refused.err
    );
    // Nothing is left: no other generation, and no staged bundle.
    let listed = rules(root, "list", &[]);
    assert_eq!(listed.out.lines().count(), 2, "{}", listed.out);
    let staging = fs::read_dir(root.join(STORE).join("staging")).expect("the staging directory");
    assert_eq!(staging.count(), 0);
    let taken = with("coraza");
    assert_eq!(taken.code, Some(0), "{}", taken.err);
}

#[test]
#[ignore = "needs a built inspector"]
fn an_import_that_names_no_engine_is_for_the_default_engine_of_the_configuration() {
    let idle = Idle::new("modsec_default", &Knobs::quick(), |root| {
        name_modsecurity_inspector(root);
        make_modsecurity_default(root);
    });
    let root = idle.root();
    let conf = rules_file();
    // The store has the generation of the test, which is one of Coraza. Without `--engine` the import is for the
    // default engine, ModSecurity; with `--engine` it is for the engine that is named, whatever the default is.
    let import_for = |args: &[&OsStr], engine: &str| {
        let mut all = args.to_vec();
        all.extend([OsStr::new("--rules"), conf.as_os_str()]);
        let imported = rules(root, "import", &all);
        assert_eq!(imported.code, Some(0), "{}", imported.err);
        let made = imported.out.split(' ').next().unwrap();
        let listed = rules(root, "list", &[]);
        assert!(
            listed
                .out
                .lines()
                .any(|l| l.starts_with(made) && l.contains(&format!(" block {engine}"))),
            "{}",
            listed.out
        );
    };
    import_for(&[], "modsecurity");
    import_for(&[OsStr::new("--engine"), OsStr::new("coraza")], "coraza");
}

/// A request as the trial of an import sends it: with a name as `Host`, and a `User-Agent` and an `Accept`, which the
/// Core Rule Set looks for. A body has its type and its length.
fn browser_request(start: &str, body: Option<(&str, &[u8])>) -> Vec<u8> {
    let mut head = format!(
        "{start} HTTP/1.1\r\nHost: example.test\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64)\r\nAccept: */*\r\n"
    );
    if let Some((kind, body)) = body {
        head.push_str(&format!(
            "Content-Type: {kind}\r\nContent-Length: {}\r\n",
            body.len()
        ));
    }
    head.push_str("\r\n");
    let mut request = head.into_bytes();
    request.extend_from_slice(body.map_or(&[][..], |(_, body)| body));
    request
}

#[test]
#[ignore = "needs a built inspector and the Core Rule Set"]
fn the_core_rule_set_imported_for_modsecurity_forwards_the_requests_of_the_trial_and_blocks_an_sql_injection()
 {
    let mut crs = String::new();
    let proxy = Proxy::start_with("modsec_crs", Knobs::quick(), |root| {
        name_modsecurity_inspector(root);
        use_modsecurity(root, "main");
        let dir = crs_dir();
        crs = import_and_choose(root, &[OsStr::new("--crs"), dir.as_os_str()]);
    });
    let lines = proxy.records.lines();
    for line in [
        format!("start: rules generation {crs}"),
        "start: rules engine modsecurity".to_owned(),
    ] {
        assert!(lines.contains(&line), "records: {lines:#?}");
    }

    // The three requests of the trial of the import go on to the upstream.
    let trial = [
        browser_request("GET /", None),
        browser_request(
            "POST /",
            Some(("application/x-www-form-urlencoded", b"a=b".as_slice())),
        ),
        browser_request(
            "POST /",
            Some(("application/json", br#"{"a":"b"}"#.as_slice())),
        ),
    ];
    for request in &trial {
        let reply = exchange(proxy.port, request);
        assert_eq!(reply.status(), 200, "answer: {:?}", reply.text());
    }
    // An SQL injection in an argument is stopped by the rule that adds up the score.
    let injection = browser_request("GET /?q=1%27%20or%20%271%27%3D%271", None);
    assert_empty_answer(&exchange(proxy.port, &injection), 403);
    let record = proxy
        .records
        .conn("the blocked record", |l| blocked_by(l, 949110));
    assert_eq!(record["engine"], "modsecurity", "{record}");
    assert!(record["score"].as_i64().is_some_and(|s| s >= 5), "{record}");
    assert!(
        record["rules"].as_array().is_some_and(|r| !r.is_empty()),
        "{record}"
    );
    proxy.finish(3);
}
