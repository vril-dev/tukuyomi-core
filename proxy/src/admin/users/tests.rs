use std::fs;

use super::*;
use crate::admin::audit::tests::Refuses;
use crate::admin::file_store::FileAdminStore;
use crate::admin::file_store::tests::scratch;
use crate::log;

/// The audit log of the store in `dir`.
fn audit_log(dir: &Path) -> AuditLog {
    AuditLog::open(&dir.join("audit"), log::recording().0).unwrap()
}

fn read(text: &[u8]) -> Result<String, &'static str> {
    let mut input = text;
    read_password(&mut input).map(|secret| secret.as_str().to_owned())
}

#[test]
fn the_password_is_the_first_line_and_only_one_of_the_right_size_is_taken() {
    assert_eq!(read(b"correct horse\n").unwrap(), "correct horse");
    assert_eq!(read(b"correct horse\r\nmore\n").unwrap(), "correct horse");
    assert_eq!(read(b"correct horse").unwrap(), "correct horse");
    let longest = "p".repeat(128);
    assert_eq!(read(format!("{longest}\n").as_bytes()).unwrap(), longest);
    assert_eq!(read(format!("{longest}\r\n").as_bytes()).unwrap(), longest);
    let too_long = "the password is not 12 to 128 bytes";
    assert_eq!(read(format!("{longest}p\n").as_bytes()), Err(too_long));
    assert_eq!(read(b"eleven char\n"), Err(too_long));
    assert_eq!(read(b""), Err(too_long));
    assert_eq!(
        read("p".repeat(400).as_bytes()),
        Err("the password line is too long")
    );
    assert_eq!(
        read(b"\xff\xfeabcdefghijkl\n"),
        Err("the password is not UTF-8")
    );
}

#[test]
fn the_first_owner_is_made_only_in_a_store_that_has_no_user() {
    let dir = scratch();
    let store = FileAdminStore::open(dir.path()).unwrap();
    let audit = audit_log(dir.path());
    create_owner(&store, &audit, "alice", "correct horse battery", 1000).unwrap();
    let alice = store.user("alice").unwrap().unwrap();
    assert_eq!(alice.role, Role::Owner);
    assert!(!alice.disabled);
    assert!(alice.password.verify("correct horse battery"));
    assert_eq!(
        create_owner(&store, &audit, "bob", "another password", 1000),
        Err(AdminError("the store has a user already"))
    );
    assert_eq!(store.user("bob").unwrap(), None);
}

#[test]
fn a_user_file_is_read_back_and_one_that_is_not_the_user_of_its_name_is_not_read() {
    let hash = Hash::new("correct horse battery", 1000).unwrap();
    let user = User::new("alice", Role::Operator, hash, 42);
    let bytes = user.encode().unwrap();
    assert_eq!(User::decode(&bytes, "alice").unwrap(), user);
    assert!(User::decode(&bytes, "bob").is_err());
    let mut object: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    object["mfa"] = serde_json::json!("later");
    assert!(User::decode(object.to_string().as_bytes(), "alice").is_err());
    let mut object: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    object["role"] = serde_json::json!("root");
    assert!(User::decode(object.to_string().as_bytes(), "alice").is_err());
    object["role"] = serde_json::json!("owner");
    object["password"]["iterations"] = serde_json::json!(0);
    assert!(User::decode(object.to_string().as_bytes(), "alice").is_err());
}

#[test]
fn the_first_owner_is_audited_before_it_is_made_and_is_not_made_when_the_audit_log_refuses() {
    let dir = scratch();
    let store = FileAdminStore::open(dir.path()).unwrap();
    let audit = audit_log(dir.path());
    create_owner(&store, &audit, "alice", "correct horse battery", 1000).unwrap();
    // A second try is refused by the store after its line, and a line that says so follows.
    assert!(create_owner(&store, &audit, "bob", "another password", 1000).is_err());
    let text = fs::read_to_string(dir.path().join("audit").join("audit.log")).unwrap();
    let lines: Vec<serde_json::Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines.len(), 3);
    for (key, value) in [
        ("type", "audit"),
        ("action", "create"),
        ("result", "ok"),
        ("target", "alice"),
        ("auth", "bootstrap"),
        ("after", "owner"),
    ] {
        assert_eq!(lines[0][key], value, "{key}");
    }
    // No request and no client, no actor and no session.
    for key in ["id", "client", "actor", "session", "before", "reason"] {
        assert!(lines[0].get(key).is_none(), "{key}");
    }
    assert_eq!(
        (lines[2]["result"].as_str(), lines[2]["reason"].as_str()),
        (Some("failed"), Some("store"))
    );
    // An audit log that takes no line: no user is made.
    let other = scratch();
    let empty = FileAdminStore::open(other.path()).unwrap();
    let refusing = AuditLog::with_sink(
        Box::new(Refuses),
        &other.path().join("audit"),
        log::recording().0,
    );
    assert_eq!(
        create_owner(&empty, &refusing, "carol", "correct horse battery", 1000),
        Err(AdminError("the audit log cannot be written"))
    );
    assert_eq!(empty.user("carol").unwrap(), None);
    create_owner(
        &empty,
        &audit_log(other.path()),
        "dave",
        "correct horse battery",
        1000,
    )
    .unwrap();
}
