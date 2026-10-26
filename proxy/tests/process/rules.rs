use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;

use crate::support::*;

/// Where a test moves the store to, so that a link in its place can lead to a store that is good in every other
/// way.
const MOVED: &str = "store-moved";

/// A case of a refused store: the name of the test root, the change that it makes to the root, what the root holds
/// besides the configuration, and the sentence of the refusal.
type Case = (
    &'static str,
    fn(&Path),
    &'static [&'static str],
    &'static str,
);

/// Starts the proxy on a root that `edit` has changed and checks that the rules store refuses the start: exit code
/// 1, a proxy that is gone long before any wait of the kernel could end, no listener, and nothing in the records
/// but the line of the accepted configuration and the line of the refusal, so that neither the kernel nor an
/// inspector was started. `rest` names what the root holds besides the configuration.
fn assert_store_refused(test: &str, edit: impl FnOnce(&Path), rest: &[&str], sentence: &str) {
    let mut proxy = Proxy::spawn_with(test, Knobs::quick(), edit);
    let started = proxy.started;
    let (status, _) = proxy.wait_exit(started, MARGIN);
    let lines = proxy.records.lines();
    assert_eq!(
        status.code(),
        Some(1),
        "exit status {status}; records: {lines:#?}"
    );
    let refusal = format!("start: rules store refused: {sentence}");
    assert_eq!(lines, ["start: configuration accepted", refusal.as_str()]);
    assert_turned_away(proxy.port);
    let mut files = vec!["config.json"];
    files.extend_from_slice(rest);
    proxy.clear_root(&files);
    proxy.upstream.stop();
    assert_eq!(proxy.upstream.connections(), 0);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_start_records_the_chosen_generation() {
    let proxy = Proxy::start("rules_generation", Knobs::quick());
    let lines = proxy.records.lines();
    let chosen = format!("start: rules generation {}", generation());
    assert!(lines.contains(&chosen), "records: {lines:#?}");
    assert!(
        lines.iter().any(|l| l == "start: rules mode block"),
        "records: {lines:#?}"
    );
    proxy.finish(0);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_store_that_is_refused_ends_the_start_with_exit_code_1_and_its_sentence() {
    let cases: [Case; 3] = [
        (
            "store_mode_750",
            |root| {
                fs::set_permissions(root.join(STORE), fs::Permissions::from_mode(0o750))
                    .expect("change the mode of the store");
            },
            &[STORE],
            "the rules store directory has group or other permission bits",
        ),
        (
            "store_link",
            |root| {
                // The link leads to a store that is good in every other way: only the link is wrong.
                fs::rename(root.join(STORE), root.join(MOVED)).expect("move the store");
                symlink(root.join(MOVED), root.join(STORE)).expect("link the store");
            },
            &[STORE, MOVED],
            "the rules store directory is not a real directory",
        ),
        (
            // A start that waited for a writer would not end: the proxy has `MARGIN` to be gone.
            "current_fifo",
            |root| {
                let current = root.join(STORE).join("current");
                fs::remove_file(&current).expect("remove the record");
                let made = Command::new("mkfifo")
                    .arg(&current)
                    .status()
                    .expect("run mkfifo");
                assert!(made.success(), "mkfifo failed: {made}");
            },
            &[STORE],
            "the current generation record cannot be read",
        ),
    ];
    for (test, edit, rest, sentence) in cases {
        assert_store_refused(test, edit, rest, sentence);
    }
}

/// How a command of the binary ended, and what it wrote.
struct Ran {
    code: Option<i32>,
    out: String,
    err: String,
}

/// Runs `tukuyomi-proxy rules <command> <the configuration of the test root> <rest>` and waits for it.
fn rules(root: &Path, command: &str, rest: &[&OsStr]) -> Ran {
    let output = Command::new(env!("CARGO_BIN_EXE_tukuyomi-proxy"))
        .arg("rules")
        .arg(command)
        .arg(root.join("config.json"))
        .args(rest)
        .stdin(Stdio::null())
        .output()
        .expect("run the command");
    Ran {
        code: output.status.code(),
        out: String::from_utf8_lossy(&output.stdout).into_owned(),
        err: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// An empty store of mode 0700 in place of the store of the test root: the commands make what they need in it.
fn empty_store(root: &Path) {
    fs::remove_dir_all(root.join(STORE)).expect("remove the store of the test");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(root.join(STORE))
        .expect("make the empty store");
}

#[test]
#[ignore = "needs a built inspector"]
fn a_bundle_that_is_imported_and_chosen_is_the_generation_the_proxy_starts_with() {
    let mut proxy = Proxy::spawn_with("rules_commands", Knobs::quick(), |root| {
        empty_store(root);
        let conf = rules_file();
        let import =
            |root: &Path| rules(root, "import", &[OsStr::new("--rules"), conf.as_os_str()]);
        // The trial starts the inspector on the bundle; the bundle of one file is the test rules, so the
        // fingerprint is the one of their manifest.
        let first = import(root);
        assert_eq!(
            (first.code, first.out.as_str(), first.err.as_str()),
            (Some(0), format!("{} created\n", generation()).as_str(), "")
        );
        let again = import(root);
        assert_eq!(
            (again.code, again.out),
            (Some(0), format!("{} already exists\n", generation()))
        );

        // A generation is not chosen by making it.
        let listed = rules(root, "list", &[]);
        let fields: Vec<&str> = listed.out.split_whitespace().collect();
        assert_eq!(
            (listed.code, fields.len(), fields[0], fields[2]),
            (Some(0), 3, generation().as_str(), "block")
        );
        let chosen = rules(root, "activate", &[OsStr::new(&generation())]);
        assert_eq!(
            (chosen.code, chosen.out),
            (Some(0), format!("{} current\n", generation()))
        );
        let listed = rules(root, "list", &[]);
        assert!(listed.out.ends_with(" block current\n"), "{}", listed.out);

        // A generation that is not there is refused, and so is a fingerprint of the wrong form.
        let missing = "f".repeat(64);
        assert_eq!(
            rules(root, "activate", &[OsStr::new(&missing)]).code,
            Some(1)
        );
        assert_eq!(rules(root, "activate", &[OsStr::new("F")]).code, Some(2));
    });
    proxy
        .records
        .wait_lines("the proxy to listen", 1, |l| l == "start: listening");
    proxy.wait_inspector(None);
    let lines = proxy.records.lines();
    let chosen = format!("start: rules generation {}", generation());
    assert!(lines.contains(&chosen), "records: {lines:#?}");
    let reply = exchange(proxy.port, &get("/ok"));
    assert_eq!(reply.status(), 200, "answer: {:?}", reply.text());
    proxy.finish(1);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_rule_file_that_the_inspector_refuses_makes_no_generation() {
    assert_store_refused(
        "rules_refused",
        |root| {
            empty_store(root);
            let bad = root.join("bad.conf");
            fs::write(&bad, "SecRule\n").expect("write the rule file");
            let ran = rules(root, "import", &[OsStr::new("--rules"), bad.as_os_str()]);
            fs::remove_file(&bad).expect("remove the rule file");
            assert_eq!(ran.code, Some(1), "{}", ran.err);
            assert!(ran.out.is_empty(), "{}", ran.out);
            assert!(
                ran.err
                    .contains("the inspector refused to start (exit code 11)"),
                "{}",
                ran.err
            );
            assert!(!ran.err.contains("did not stop cleanly"), "{}", ran.err);
            // Nothing is left: no generation, no staged bundle, and the trial's directory is gone (the root holds
            // the configuration and the store only).
            assert!(rules(root, "list", &[]).out.is_empty());
            let staging =
                fs::read_dir(root.join(STORE).join("staging")).expect("the staging directory");
            assert_eq!(staging.count(), 0);
        },
        &[STORE],
        "no generation is chosen",
    );
}

/// The mode word of the generation `fingerprint` in the output of `rules list`.
fn listed_mode(out: &str, fingerprint: &str) -> String {
    out.lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        .find(|fields| fields[0] == fingerprint)
        .unwrap_or_else(|| panic!("{fingerprint} is not listed in {out:?}"))[2]
        .to_owned()
}

#[test]
#[ignore = "needs a built inspector"]
fn a_detect_only_generation_lets_a_matched_request_through_and_a_blocking_one_of_the_same_rules_stops_it()
 {
    let mut detect = String::new();
    let mut proxy = Proxy::spawn_with("rules_detect", Knobs::quick(), |root| {
        // The rules of the generation in the store, imported as a detect bundle: another manifest, so another
        // generation, which the trial of the import lets pass.
        let conf = rules_file();
        let imported = rules(
            root,
            "import",
            &[
                OsStr::new("--rules"),
                conf.as_os_str(),
                OsStr::new("--detect-only"),
            ],
        );
        assert_eq!(imported.code, Some(0), "{}", imported.err);
        assert!(imported.err.is_empty(), "{}", imported.err);
        detect = imported
            .out
            .strip_suffix(" created\n")
            .unwrap_or_else(|| panic!("unexpected output {:?}", imported.out))
            .to_owned();
        assert_ne!(detect, generation());
        let chosen = rules(root, "activate", &[OsStr::new(&detect)]);
        assert_eq!(chosen.code, Some(0), "{}", chosen.err);

        // The list gives the mode of each generation; one without a readable manifest is unknown and ends the
        // command with 1 after the whole list.
        let listed = rules(root, "list", &[]);
        assert_eq!(listed.code, Some(0), "{}", listed.err);
        assert_eq!(listed_mode(&listed.out, &generation()), "block");
        assert_eq!(listed_mode(&listed.out, &detect), "detect");
        assert!(
            listed
                .out
                .lines()
                .any(|l| l.starts_with(&detect) && l.ends_with(" detect current")),
            "{}",
            listed.out
        );
        let broken = "f".repeat(64);
        let dir = root.join(STORE).join("generations").join(&broken);
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .expect("make a generation without a manifest");
        let listed = rules(root, "list", &[]);
        assert_eq!(listed.code, Some(1), "{}", listed.out);
        assert_eq!(listed_mode(&listed.out, &broken), "unknown");
        assert_eq!(listed_mode(&listed.out, &detect), "detect");
        let sentence =
            format!("rules list: {broken}: the manifest of the generation cannot be read");
        assert!(listed.err.contains(&sentence), "{}", listed.err);
        fs::remove_dir(&dir).expect("remove the generation without a manifest");
    });
    proxy
        .records
        .wait_lines("the proxy to listen", 1, |l| l == "start: listening");
    proxy.wait_inspector(None);
    let lines = proxy.records.lines();
    for line in [
        format!("start: rules generation {detect}"),
        "start: rules mode detect".to_owned(),
    ] {
        assert!(lines.contains(&line), "records: {lines:#?}");
    }

    // The URI rule would block this request; in the detect generation it goes to the upstream, and the record
    // names the rule. A request that no rule matches is recorded as before.
    let reply = exchange(proxy.port, &get("/block-probe/x"));
    assert_eq!(reply.status(), 200, "answer: {:?}", reply.text());
    assert_eq!(reply.message().body, UPSTREAM_BODY.as_bytes());
    proxy.records.conn("the detection record", |l| {
        is_answer(l, "forwarded", 200, "detected by a rule") && l["rule"] == 9201
    });
    let seen = Message::parse(&proxy.upstream.requests()[0]);
    assert_eq!(seen.start, "GET /block-probe/x HTTP/1.1");
    assert_eq!(exchange(proxy.port, &get("/ok")).status(), 200);
    proxy.records.conn("the forwarded record", |l| {
        is_answer(l, "forwarded", 200, "forwarded") && no(l, "rule")
    });

    // The same rules in a blocking generation stop the request that the detect generation let through.
    let root = proxy.root().to_path_buf();
    let chosen = rules(&root, "activate", &[OsStr::new(&generation())]);
    assert_eq!(chosen.code, Some(0), "{}", chosen.err);
    let before = proxy.inspector();
    proxy.signal("USR1");
    let switched = format!("reload: generation {} is ready, switched", generation());
    proxy
        .records
        .wait_lines("the switch", 1, |l| l == switched.as_str());
    proxy.wait_inspector(Some(before));
    let lines = proxy.records.lines();
    assert!(
        lines.iter().any(|l| l == "reload: rules mode block"),
        "records: {lines:#?}"
    );
    assert_empty_answer(&exchange(proxy.port, &get("/block-probe/x")), 403);
    proxy
        .records
        .conn("the blocked record", |l| blocked_by(l, 9201));
    proxy.finish(2);
}

#[test]
#[ignore = "needs a built inspector"]
fn a_request_under_a_route_is_forwarded_without_inspection_and_an_ambiguous_one_is_inspected() {
    let mut routed = String::new();
    let mut proxy = Proxy::spawn_with("rules_routes", Knobs::quick(), |root| {
        // The routes lie under /block-probe, which the URI rule of the test rules blocks, so that a request that
        // is forwarded under a route shows that the inspection was skipped and not that no rule matched. The
        // import makes another manifest (with routes), so another generation, and its trial starts the inspector
        // on it, which reads the manifest in its one form: the third route holds every character that a path may
        // hold, and the second one a host with a port.
        let table = root.join("routes.json");
        fs::write(
            &table,
            r#"[{"path":"/block-probe/pass/","action":"bypass"},{"host":"other.test:8080","path":"/block-probe/other/","action":"bypass"},{"path":"/block-probe/%41-._~!$&'()*+,=:@/","action":"bypass"}]"#,
        )
        .expect("write the routes file");
        let conf = rules_file();
        let imported = rules(
            root,
            "import",
            &[
                OsStr::new("--rules"),
                conf.as_os_str(),
                OsStr::new("--routes"),
                table.as_os_str(),
            ],
        );
        fs::remove_file(&table).expect("remove the routes file");
        assert_eq!(imported.code, Some(0), "{}", imported.err);
        assert!(imported.err.is_empty(), "{}", imported.err);
        routed = imported
            .out
            .strip_suffix(" created\n")
            .unwrap_or_else(|| panic!("unexpected output {:?}", imported.out))
            .to_owned();
        assert_ne!(routed, generation());
        let chosen = rules(root, "activate", &[OsStr::new(&routed)]);
        assert_eq!(chosen.code, Some(0), "{}", chosen.err);
        // The list gives the number of routes after the mode and before `current`, and nothing for a generation
        // without routes.
        let listed = rules(root, "list", &[]);
        let line = |fingerprint: &str| {
            listed
                .out
                .lines()
                .find(|l| l.starts_with(fingerprint))
                .unwrap_or_else(|| panic!("{fingerprint} is not listed in {:?}", listed.out))
        };
        assert!(
            line(&routed).ends_with(" block routes 3 current"),
            "{}",
            line(&routed)
        );
        assert!(
            line(&generation()).ends_with(" block"),
            "{}",
            line(&generation())
        );
    });
    proxy
        .records
        .wait_lines("the proxy to listen", 1, |l| l == "start: listening");
    proxy.wait_inspector(None);
    let lines = proxy.records.lines();
    for line in [
        format!("start: rules generation {routed}"),
        "start: rules mode block".to_owned(),
        "start: rules routes 3".to_owned(),
    ] {
        assert!(lines.contains(&line), "records: {lines:#?}");
    }

    // Without a route the URI rule blocks the probe.
    assert_empty_answer(&exchange(proxy.port, &get("/block-probe/x")), 403);
    // Under the route it is not inspected: the request goes to the upstream and the record says why.
    let reply = exchange(proxy.port, &get("/block-probe/pass/x"));
    assert_eq!(reply.status(), 200, "answer: {:?}", reply.text());
    assert_eq!(reply.message().body, UPSTREAM_BODY.as_bytes());
    proxy.records.conn("the bypass record", |l| {
        is_answer(l, "forwarded", 200, "bypassed by a route") && no(l, "rule")
    });
    let seen = Message::parse(&proxy.upstream.requests()[0]);
    assert_eq!(seen.start, "GET /block-probe/pass/x HTTP/1.1");
    // A path that can be read in two ways does not match the route, so it is inspected and blocked. So is one
    // that is escaped twice.
    assert_empty_answer(&exchange(proxy.port, &get("/block-probe/pass/..%2fx")), 403);
    assert_empty_answer(
        &exchange(proxy.port, &get("/block-probe/pass/%252e%252e/x")),
        403,
    );
    // A route with a host holds for that host, in any case of its letters, and for no other.
    assert_empty_answer(&exchange(proxy.port, &get("/block-probe/other/x")), 403);
    let other = b"GET /block-probe/other/x HTTP/1.1\r\nHost: Other.Test:8080\r\n\r\n";
    assert_eq!(exchange(proxy.port, other).status(), 200);
    // A path with every character that a route may hold.
    let marks = get("/block-probe/%41-._~!$&'()*+,=:@/x");
    assert_eq!(exchange(proxy.port, &marks).status(), 200);
    proxy.records.conns("the bypass records", 3, |l| {
        is_answer(l, "forwarded", 200, "bypassed by a route") && no(l, "rule")
    });
    proxy
        .records
        .conns("the blocked records", 4, |l| blocked_by(l, 9201));
    proxy.finish(3);
}

#[test]
#[ignore = "needs a built inspector"]
fn sigusr1_switches_to_the_chosen_generation_and_a_generation_in_use_is_not_removed() {
    let mut proxy = Proxy::start("rules_switch", Knobs::quick());
    let root = proxy.root().to_path_buf();
    // The second generation has the rules of the first and one more, which blocks /reload-probe.
    let extra = root.join("extra.conf");
    fs::write(
        &extra,
        "SecRule REQUEST_URI \"@beginsWith /reload-probe\" \"id:9204,phase:1,deny,status:403,log,msg:'reload probe'\"\n",
    )
    .expect("write the rule file");
    let basic = rules_file();
    let imported = rules(
        &root,
        "import",
        &[
            OsStr::new("--rules"),
            basic.as_os_str(),
            OsStr::new("--rules"),
            extra.as_os_str(),
        ],
    );
    assert_eq!(imported.code, Some(0), "{}", imported.err);
    let second = imported
        .out
        .strip_suffix(" created\n")
        .unwrap_or_else(|| panic!("unexpected output {:?}", imported.out))
        .to_owned();
    let first = generation();
    assert_ne!(second, first);
    fs::remove_file(&extra).expect("remove the rule file");

    // Choosing the generation does not change the one that runs, and the one that runs cannot be removed.
    let chosen = rules(&root, "activate", &[OsStr::new(&second)]);
    assert_eq!(chosen.code, Some(0), "{}", chosen.err);
    assert_eq!(exchange(proxy.port, &get("/reload-probe")).status(), 200);
    let in_use = "the generation is used by a running proxy";
    let refused = rules(&root, "remove", &[OsStr::new(&first)]);
    assert_eq!(refused.code, Some(1), "{}", refused.out);
    assert!(refused.err.contains(in_use), "{}", refused.err);

    let before = proxy.inspector();
    proxy.signal("USR1");
    let switched = format!("reload: generation {second} is ready, switched");
    proxy
        .records
        .wait_lines("the switch", 1, |l| l == switched.as_str());
    proxy.wait_inspector(Some(before));
    assert_eq!(exchange(proxy.port, &get("/reload-probe")).status(), 403);
    assert_eq!(exchange(proxy.port, &get("/ok")).status(), 200);

    // The proxy lets go of the first generation when its inspector is stopped and the driver has said so, which
    // is a moment after the record of the stop.
    let retired = format!("reload: generation {first} retired, clean true");
    proxy
        .records
        .wait_lines("the old generation to retire", 1, |l| l == retired.as_str());
    let mut removed = rules(&root, "remove", &[OsStr::new(&first)]);
    for _ in 0..200 {
        if removed.code == Some(0) {
            break;
        }
        assert!(removed.err.contains(in_use), "{}", removed.err);
        thread::sleep(25 * MS);
        removed = rules(&root, "remove", &[OsStr::new(&first)]);
    }
    assert_eq!(
        (removed.code, removed.out.as_str(), removed.err.as_str()),
        (Some(0), format!("{first} removed\n").as_str(), "")
    );
    let current = rules(&root, "remove", &[OsStr::new(&second)]);
    assert_eq!(current.code, Some(1), "{}", current.out);
    assert!(
        current.err.contains("is the current one"),
        "{}",
        current.err
    );
    let listed = rules(&root, "list", &[]);
    assert!(listed.out.starts_with(&second), "{}", listed.out);
    assert_eq!(listed.out.lines().count(), 1, "{}", listed.out);
    proxy.finish(2);
}
