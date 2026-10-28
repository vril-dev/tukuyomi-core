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
fn a_user_file_of_the_previous_version_is_read_and_the_second_factor_is_kept_when_written() {
    // The keys that the files had before the second factor, the password change and the tokens.
    let old = serde_json::json!({
        "name": "alice", "role": "operator", "disabled": false,
        "password": {"iterations": 1000, "salt": "00".repeat(16), "hash": "11".repeat(32)},
        "created": 5, "changed": 9,
    });
    let user = User::decode(old.to_string().as_bytes(), "alice").unwrap();
    assert!(user.mfa.is_none() && user.recovery.is_empty() && !user.must_change);
    assert_eq!((user.created, user.changed, user.tokens_after), (5, 9, 5));
    // With the new keys: they come back as they were written.
    let next = User {
        mfa: Some(Totp {
            seed: Seed::from_bytes([9; SEED_LEN]),
            last_step: 77,
        }),
        recovery: vec![[1; 32], [2; 32]],
        must_change: true,
        tokens_after: 8,
        ..user
    };
    let bytes = next.encode().unwrap();
    assert_eq!(User::decode(&bytes, "alice").unwrap(), next);
    // Not read: a seed or a hash of the wrong form, more than 10 recovery codes, a key that is not known.
    let object = || serde_json::from_slice::<serde_json::Value>(&bytes).unwrap();
    let mut seed = object();
    seed["mfa"]["secret"] = serde_json::json!("00");
    let mut hash = object();
    hash["recovery"][1] = serde_json::json!("zz");
    let mut many = object();
    many["recovery"] = serde_json::json!(vec!["22".repeat(32); 11]);
    let mut extra = object();
    extra["mfa"]["later"] = serde_json::json!(1);
    for broken in [seed, hash, many, extra] {
        assert!(User::decode(broken.to_string().as_bytes(), "alice").is_err());
    }
}

#[test]
fn a_reset_sets_the_password_takes_the_second_factor_away_voids_the_tokens_and_is_audited_first() {
    let dir = scratch();
    let store = FileAdminStore::open(dir.path()).unwrap();
    let audit = audit_log(dir.path());
    create_owner(&store, &audit, "alice", "correct horse battery", 1000).unwrap();
    let mut alice = store.user("alice").unwrap().unwrap();
    alice.mfa = Some(Totp {
        seed: Seed::from_bytes([9; SEED_LEN]),
        last_step: 3,
    });
    alice.recovery = vec![[1; 32]];
    store.replace(alice.changed, &alice).unwrap();
    reset_password(&store, &audit, "alice", "another password", 1000).unwrap();
    let after = store.user("alice").unwrap().unwrap();
    assert!(after.password.verify("another password"));
    assert_eq!(after.role, Role::Owner);
    assert!(after.mfa.is_none() && after.recovery.is_empty() && after.must_change);
    // The sessions end (`changed` goes up) and the tokens made so far are void (`tokens_after` is the same time).
    assert!(after.changed > alice.changed && after.tokens_after == after.changed);
    let text = fs::read_to_string(dir.path().join("audit").join("audit.log")).unwrap();
    let lines: Vec<serde_json::Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    for (key, value) in [
        ("action", "reset"),
        ("result", "ok"),
        ("target", "alice"),
        ("auth", "reset"),
    ] {
        assert_eq!(lines[1][key], value, "{key}");
    }
    for key in ["id", "client", "actor", "session", "reason"] {
        assert!(lines[1].get(key).is_none(), "{key}");
    }
    // A user that is not in the store is refused, and nothing is written.
    assert_eq!(
        reset_password(&store, &audit, "nobody", "another password", 1000),
        Err(AdminError("the user is not in the store"))
    );
    assert_eq!(
        fs::read_to_string(dir.path().join("audit").join("audit.log")).unwrap(),
        text
    );
    // An audit log that takes no line: the user is as it was.
    let refusing = AuditLog::with_sink(
        Box::new(Refuses),
        &dir.path().join("audit"),
        log::recording().0,
    );
    assert_eq!(
        reset_password(&store, &refusing, "alice", "third password!!", 1000),
        Err(AdminError("the audit log cannot be written"))
    );
    assert_eq!(store.user("alice").unwrap().unwrap(), after);
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
