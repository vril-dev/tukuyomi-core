use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::process::Command;

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
