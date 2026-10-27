use super::*;

const IDLE: Duration = Duration::from_secs(60);
const TOTAL: Duration = Duration::from_secs(600);

fn secs(base: Instant, s: u64) -> Instant {
    base + Duration::from_secs(s)
}

#[test]
fn a_session_ends_when_it_is_not_used_for_the_idle_time() {
    let sessions = Sessions::new(IDLE, TOTAL);
    let t0 = Instant::now();
    let opened = sessions.open("alice", 7, t0).unwrap();
    assert_eq!(
        (opened.cookie.len(), opened.csrf.len(), opened.handle.len()),
        (43, 43, 8)
    );
    assert_ne!(opened.cookie, opened.csrf);
    let found = sessions.find(&opened.cookie, secs(t0, 59)).unwrap();
    assert_eq!((found.name.as_str(), found.changed), ("alice", 7));
    assert_eq!(found.csrf, opened.csrf);
    assert_eq!(found.handle, opened.handle);
    // The use at 59 s counts: 59 s later the session is alive, and 60 s after the last use it is over.
    assert!(sessions.find(&opened.cookie, secs(t0, 118)).is_some());
    assert!(sessions.find(&opened.cookie, secs(t0, 178)).is_none());
    assert!(sessions.find(&opened.cookie, secs(t0, 179)).is_none());
}

#[test]
fn a_session_ends_at_the_total_time_however_often_it_is_used() {
    let sessions = Sessions::new(IDLE, TOTAL);
    let t0 = Instant::now();
    let opened = sessions.open("alice", 7, t0).unwrap();
    for step in 1..=11 {
        assert!(sessions.find(&opened.cookie, secs(t0, step * 50)).is_some());
    }
    let last = sessions.find(&opened.cookie, secs(t0, 599)).unwrap();
    assert_eq!(last.total_left, Duration::from_secs(1));
    assert!(sessions.find(&opened.cookie, secs(t0, 600)).is_none());
}

#[test]
fn a_text_that_is_not_an_id_names_no_session_and_closing_ends_the_sessions_asked() {
    let sessions = Sessions::new(IDLE, TOTAL);
    let t0 = Instant::now();
    let one = sessions.open("alice", 1, t0).unwrap();
    let two = sessions.open("alice", 1, t0).unwrap();
    let other = sessions.open("bob", 1, t0).unwrap();
    for text in [
        "",
        "short",
        &"A".repeat(44),
        &format!("{}!", "A".repeat(42)),
    ] {
        assert!(sessions.find(text, t0).is_none(), "{text:?}");
    }
    sessions.close(&one.cookie);
    assert!(sessions.find(&one.cookie, t0).is_none());
    assert!(sessions.find(&two.cookie, t0).is_some());
    sessions.close_user("alice");
    assert!(sessions.find(&two.cookie, t0).is_none());
    assert!(sessions.find(&other.cookie, t0).is_some());
}

#[test]
fn a_user_keeps_sixteen_sessions_and_one_more_closes_the_oldest_of_that_user() {
    let sessions = Sessions::new(IDLE, TOTAL);
    let t0 = Instant::now();
    let other = sessions.open("bob", 1, t0).unwrap();
    let alice: Vec<Opened> = (0..16)
        .map(|n| sessions.open("alice", 1, secs(t0, n)).unwrap())
        .collect();
    assert!(alice.iter().all(|opened| opened.closed.is_none()));
    // The oldest is the one made first, however lately it was used.
    assert!(sessions.find(&alice[0].cookie, secs(t0, 20)).is_some());
    let next = sessions.open("alice", 1, secs(t0, 21)).unwrap();
    assert_eq!(next.closed.as_deref(), Some(alice[0].handle.as_str()));
    assert!(sessions.find(&alice[0].cookie, secs(t0, 21)).is_none());
    for opened in alice[1..].iter().chain([&next, &other]) {
        assert!(sessions.find(&opened.cookie, secs(t0, 21)).is_some());
    }
    // Sessions that have run out are dropped first, and then nothing is closed.
    let later = sessions.open("alice", 1, secs(t0, 500)).unwrap();
    assert!(later.closed.is_none());
}
