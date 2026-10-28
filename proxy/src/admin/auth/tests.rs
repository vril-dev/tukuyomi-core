use std::net::Ipv4Addr;

use super::*;
use crate::admin::server::tests::{PASSWORD, rig};

const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
/// The `changed` of the users of the tests.
const CHANGED: u64 = 1000;

fn later(base: Instant, secs: u64) -> Instant {
    base + Duration::from_secs(secs)
}

#[test]
fn five_failures_in_a_row_lock_a_user_for_fifteen_minutes_and_a_try_while_locked_starts_it_again() {
    let guard = Guard::new();
    let t0 = Instant::now();
    for n in 1..=4 {
        assert!(!guard.failed("alice", CHANGED, later(t0, n)), "failure {n}");
        assert!(!guard.locked("alice", CHANGED, later(t0, n)));
    }
    // The fifth locks, and only the fifth reports that it did.
    assert!(guard.failed("alice", CHANGED, later(t0, 5)));
    assert!(guard.locked("alice", CHANGED, later(t0, 6)));
    assert!(!guard.locked("bob", CHANGED, later(t0, 6)));
    // A try during the lock is a failure and the lock runs 15 minutes from it.
    assert!(!guard.failed("alice", CHANGED, later(t0, 600)));
    assert!(guard.locked("alice", CHANGED, later(t0, 600 + 899)));
    assert!(!guard.locked("alice", CHANGED, later(t0, 600 + 900)));
    // After the lock has run out the count starts again.
    assert!(!guard.failed("alice", CHANGED, later(t0, 2000)));
    assert!(!guard.locked("alice", CHANGED, later(t0, 2001)));
    for n in 1..=3 {
        assert!(!guard.failed("alice", CHANGED, later(t0, 2000 + n)));
    }
    assert!(guard.failed("alice", CHANGED, later(t0, 2004)));
    // A success clears the count.
    guard.succeeded("alice");
    assert!(!guard.locked("alice", CHANGED, later(t0, 2005)));
    assert!(!guard.failed("alice", CHANGED, later(t0, 2006)));
}

#[test]
fn failures_counted_before_the_user_was_changed_do_not_count_and_the_count_starts_again() {
    let guard = Guard::new();
    let t0 = Instant::now();
    for n in 1..=5 {
        guard.failed("alice", CHANGED, later(t0, n));
    }
    assert!(guard.locked("alice", CHANGED, later(t0, 6)));
    // The user was changed, as a password set again by another process does: the lock is gone, and so is the count.
    assert!(!guard.locked("alice", CHANGED + 1, later(t0, 6)));
    for n in 1..=4 {
        assert!(
            !guard.failed("alice", CHANGED + 1, later(t0, 10 + n)),
            "failure {n}"
        );
    }
    assert!(!guard.locked("alice", CHANGED + 1, later(t0, 15)));
    assert!(guard.failed("alice", CHANGED + 1, later(t0, 16)));
    // A request that read the user before the change does not take the later time away.
    assert!(!guard.failed("alice", CHANGED, later(t0, 17)));
    assert!(guard.locked("alice", CHANGED + 1, later(t0, 18)));
}

#[test]
fn a_right_password_is_refused_when_the_tries_of_a_burst_locked_the_user_while_it_was_checked() {
    let rig = rig();
    let auth = &rig.app.auth;
    let user = rig.user("vera");
    let who = auth.who(&user, user.role);
    let cx = Cx {
        id: "0123456789abcdef-1",
        client: CLIENT,
    };
    let now = Instant::now();
    let check = |verified| auth.password_checked(&who, &user, verified, "password", &cx, now);
    // Nothing is counted yet: a right password passes.
    assert_eq!(check(true), Ok(()));
    // Five tries of a burst were past the first look when they were checked, and all were wrong.
    for n in 1..=LOCK_AFTER {
        assert_eq!(check(false), Err(Refusal::Password), "try {n}");
    }
    // The next one had a right password and had looked at the lock before it was set: it is refused all the same,
    // with the answer of a wrong password, as a try while the user is locked.
    assert_eq!(check(true), Err(Refusal::Password));
    let last = rig.audit().pop().unwrap();
    assert_eq!(
        (last["result"].as_str(), last["reason"].as_str()),
        (Some("denied"), Some("locked"))
    );
    // A later try is refused before the hash.
    let right = Secret::new(PASSWORD.to_owned());
    assert_eq!(
        auth.confirm_password(&who, &user, &right, "password", &cx, now),
        Err(Refusal::Password)
    );
}

#[test]
fn a_client_is_taken_thirty_times_in_a_minute_and_not_the_thirty_first() {
    let guard = Guard::new();
    let t0 = Instant::now();
    for n in 0..30 {
        assert!(guard.allow_client(CLIENT, later(t0, n)), "try {n}");
    }
    assert!(!guard.allow_client(CLIENT, later(t0, 59)));
    // A refused try is not counted: the first try leaves the window at 60 s, and one place is free.
    assert!(guard.allow_client(CLIENT, later(t0, 60)));
    assert!(!guard.allow_client(CLIENT, later(t0, 60)));
    // Another client has its own count.
    let other = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 8));
    assert!(guard.allow_client(other, later(t0, 60)));
}
