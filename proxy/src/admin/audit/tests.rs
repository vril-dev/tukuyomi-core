use std::fs;
use std::net::Ipv4Addr;

use super::*;
use crate::admin::file_store::FileAdminStore;
use crate::admin::file_store::tests::scratch;
use crate::log;

const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));

/// A sink that takes no line.
pub(crate) struct Refuses;

impl Append for Refuses {
    fn append(&mut self, _: &[u8]) -> bool {
        false
    }
}

#[test]
fn a_line_has_its_fields_and_the_same_line_goes_to_the_standard_error_after_the_file() {
    let dir = scratch();
    FileAdminStore::open(dir.path()).unwrap();
    let (log, lines) = log::recording();
    let audit = AuditLog::open(&dir.path().join("audit"), log).unwrap();
    let event = Event::new("0123456789abcdef-1a", CLIENT, "password", Outcome::Ok)
        .actor("alice")
        .session("0a1b2c3d")
        .target("bob")
        .change("viewer", "operator");
    audit.write(&event).unwrap();
    audit
        .write(
            &Event::new("0123456789abcdef-1b", CLIENT, "login", Outcome::Denied).reason("locked"),
        )
        .unwrap();
    let text = fs::read_to_string(dir.path().join("audit").join("audit.log")).unwrap();
    let written: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(written.len(), 2);
    let first = &written[0];
    assert_eq!(first["type"], "audit");
    assert_eq!(first["ts"].as_str().unwrap().len(), 24);
    for (key, value) in [
        ("id", "0123456789abcdef-1a"),
        ("actor", "alice"),
        ("session", "0a1b2c3d"),
        ("client", "192.0.2.7"),
        ("action", "password"),
        ("target", "bob"),
        ("result", "ok"),
        ("before", "viewer"),
        ("after", "operator"),
    ] {
        assert_eq!(first[key], value, "{key}");
    }
    assert!(first.get("reason").is_none());
    // A field that has no value is left out; the actor of a login that failed is not known.
    let second = &written[1];
    assert_eq!(
        (second["result"].as_str(), second["reason"].as_str()),
        (Some("denied"), Some("locked"))
    );
    assert!(second.get("actor").is_none() && second.get("target").is_none());
    // The logger got the same lines.
    assert_eq!(lines.take(), written);
}

#[test]
fn the_newest_lines_come_first_and_no_more_than_the_limit() {
    let dir = scratch();
    FileAdminStore::open(dir.path()).unwrap();
    let audit = AuditLog::open(&dir.path().join("audit"), log::recording().0).unwrap();
    let ids: Vec<String> = (0..5).map(|n| format!("0123456789abcdef-{n}")).collect();
    for id in &ids {
        audit
            .write(&Event::new(id, CLIENT, "logout", Outcome::Ok))
            .unwrap();
    }
    let recent: Vec<String> = audit
        .recent(3)
        .unwrap()
        .iter()
        .map(|entry| entry["id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(recent, [ids[4].clone(), ids[3].clone(), ids[2].clone()]);
    assert_eq!(audit.recent(200).unwrap().len(), 5);
}

#[test]
fn a_line_that_the_file_does_not_take_is_an_error_and_is_not_written_to_the_standard_error() {
    let (log, lines) = log::recording();
    let audit = AuditLog::with_sink(Box::new(Refuses), Path::new("/nonexistent"), log);
    let event = Event::new("0123456789abcdef-1", CLIENT, "login", Outcome::Ok);
    assert_eq!(
        audit.write(&event),
        Err(AdminError("the audit log cannot be written"))
    );
    let seen = lines.take();
    assert!(
        seen.iter().all(|record| record["type"] == "line"),
        "{seen:?}"
    );
}

#[test]
fn a_newest_file_that_is_missing_for_a_moment_is_read_as_empty_and_the_older_files_are_read() {
    let dir = scratch();
    FileAdminStore::open(dir.path()).unwrap();
    let audit_dir = dir.path().join("audit");
    let audit = AuditLog::open(&audit_dir, log::recording().0).unwrap();
    for n in 0..3 {
        let id = format!("0123456789abcdef-{n}");
        audit
            .write(&Event::new(&id, CLIENT, "logout", Outcome::Ok))
            .unwrap();
    }
    // A rotation has renamed `audit.log` and has not made the new one yet.
    fs::rename(audit_dir.join("audit.log"), audit_dir.join("audit.1.log")).unwrap();
    let recent = audit.recent(200).unwrap();
    assert_eq!(recent.len(), 3);
    assert_eq!(recent[0]["id"], "0123456789abcdef-2");
    // With no file at all there are no lines, and that is no failure either.
    fs::remove_file(audit_dir.join("audit.1.log")).unwrap();
    assert!(audit.recent(200).unwrap().is_empty());
}
