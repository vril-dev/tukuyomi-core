//! The engine ModSecurity in real processes: the configuration names the built inspector of that engine in
//! `kernel.engines`, and the rules store holds a generation of that engine. The generation of a test is made from the
//! test rules with a manifest of version 4 (`engines::add_generation`), or by `rules import --engine modsecurity`,
//! which tries it with the real inspector. The tests show that the engine can be chosen, started, blocking or only
//! detecting, switched to and from Coraza, and imported. The last one is the acceptance run of the engine with the
//! Core Rule Set, which needs `TUKUYOMI_TEST_CRS`.

use std::ffi::OsStr;
use std::fs;
use std::path::Path;

use serde_json::{Value, json};

use crate::config_check::config_check;
use crate::engines::{add_generation, choose};
use crate::rules::rules;
use crate::support::*;

/// The built inspector of ModSecurity is named in the configuration of the test root `root`, and a generation of that
/// engine is added to the store, beside the one of the test. Returns the name of the generation.
fn add_modsecurity(root: &Path) -> String {
    name_modsecurity_inspector(root);
    add_generation(root)
}

/// Imports the rules `args` for the engine ModSecurity, chooses the generation that the import makes, and returns its
/// name.
fn import_and_choose(root: &Path, args: &[&OsStr]) -> String {
    let mut all = vec![OsStr::new("--engine"), OsStr::new("modsecurity")];
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
        choose(root, &name);
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
        choose(root, &name);
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

/// Chooses the generation `to`, tells the proxy to switch to it from `from`, and waits until the inspector of `engine`
/// runs and the one of `from` is retired: a proxy ignores the signal while a switch is going on.
fn switch_to(proxy: &mut Proxy, from: &str, to: &str, engine: &str) {
    let root = proxy.root().to_path_buf();
    let chosen = rules(&root, "activate", &[OsStr::new(to)]);
    assert_eq!(chosen.code, Some(0), "{}", chosen.err);
    let before = proxy.inspector();
    proxy.signal("USR1");
    let switched = format!("reload: generation {to} is ready, switched");
    proxy
        .records
        .wait_lines("the switch", 1, |l| l == switched.as_str());
    proxy.wait_inspector(Some(before));
    let line = format!("reload: rules engine {engine}");
    proxy
        .records
        .wait_lines("the engine of the switch", 1, |l| l == line.as_str());
    let retired = format!("reload: generation {from} retired, clean true");
    proxy
        .records
        .wait_lines("the old generation to retire", 1, |l| l == retired.as_str());
}

#[test]
#[ignore = "needs a built inspector"]
fn the_proxy_switches_from_coraza_to_modsecurity_and_back_and_the_records_name_the_engine() {
    let mut other = String::new();
    let mut proxy = Proxy::start_with("modsec_switch", Knobs::quick(), |root| {
        other = add_modsecurity(root);
    });
    // The store chooses the generation of Coraza.
    assert_empty_answer(&exchange(proxy.port, &get("/block-probe/x")), 403);
    proxy.records.conn("the record of Coraza", |l| {
        blocked_by(l, 9201) && from_engine(l, "coraza")
    });

    // The same rules, in the generation of ModSecurity: the switch replaces the inspector, and the record says so.
    switch_to(&mut proxy, &generation(), &other, "modsecurity");
    assert_empty_answer(&exchange(proxy.port, &get("/block-probe/x")), 403);
    proxy.records.conn("the record of ModSecurity", |l| {
        blocked_by(l, 9201) && from_engine(l, "modsecurity")
    });

    // The way back is the same switch.
    switch_to(&mut proxy, &other, &generation(), "coraza");
    assert_empty_answer(&exchange(proxy.port, &get("/block-probe/x")), 403);
    proxy.records.conns("the records of Coraza", 2, |l| {
        blocked_by(l, 9201) && from_engine(l, "coraza")
    });
    proxy.finish(0);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_detect_only_generation_of_modsecurity_lets_a_matched_request_through_and_the_record_names_the_rule()
 {
    let mut detect = String::new();
    let proxy = Proxy::start_with("modsec_detect", Knobs::quick(), |root| {
        name_modsecurity_inspector(root);
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
