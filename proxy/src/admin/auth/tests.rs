use std::net::Ipv4Addr;

use super::*;

const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));

fn later(base: Instant, secs: u64) -> Instant {
    base + Duration::from_secs(secs)
}

#[test]
fn five_failures_in_a_row_lock_a_user_for_fifteen_minutes_and_a_try_while_locked_starts_it_again() {
    let guard = Guard::new();
    let t0 = Instant::now();
    for n in 1..=4 {
        assert!(!guard.failed("alice", later(t0, n)), "failure {n}");
        assert!(!guard.locked("alice", later(t0, n)));
    }
    // The fifth locks, and only the fifth reports that it did.
    assert!(guard.failed("alice", later(t0, 5)));
    assert!(guard.locked("alice", later(t0, 6)));
    assert!(!guard.locked("bob", later(t0, 6)));
    // A try during the lock is a failure and the lock runs 15 minutes from it.
    assert!(!guard.failed("alice", later(t0, 600)));
    assert!(guard.locked("alice", later(t0, 600 + 899)));
    assert!(!guard.locked("alice", later(t0, 600 + 900)));
    // After the lock has run out the count starts again.
    assert!(!guard.failed("alice", later(t0, 2000)));
    assert!(!guard.locked("alice", later(t0, 2001)));
    for n in 1..=3 {
        assert!(!guard.failed("alice", later(t0, 2000 + n)));
    }
    assert!(guard.failed("alice", later(t0, 2004)));
    // A success clears the count.
    guard.succeeded("alice");
    assert!(!guard.locked("alice", later(t0, 2005)));
    assert!(!guard.failed("alice", later(t0, 2006)));
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
