use std::cell::RefCell;
use std::collections::VecDeque;

use serde_json::json;

use super::*;
use crate::log::recording;
use crate::managed::command::{self, Exit};
use crate::managed::store::tests::Fixture;
use crate::rules::bundle::hex;

/// A proxy whose looks and answers are given by the test, one after the other; it keeps the orders it was given, and
/// runs `during` while it is ordered (the lock of the store is held then).
struct Fake {
    looks: RefCell<VecDeque<Look>>,
    answers: RefCell<VecDeque<Answered>>,
    orders: RefCell<Vec<(Instant, [u8; 32], Duration)>>,
    during: Box<dyn Fn()>,
}

impl Fake {
    fn new(looks: Vec<Look>, answers: Vec<Answered>) -> Fake {
        Fake {
            looks: RefCell::new(looks.into()),
            answers: RefCell::new(answers.into()),
            orders: RefCell::new(Vec::new()),
            during: Box::new(|| {}),
        }
    }

    /// The test gave every look and every answer, and the proxy was asked for each.
    fn spent(&self) -> bool {
        self.looks.borrow().is_empty() && self.answers.borrow().is_empty()
    }
}

impl Proxy for Fake {
    fn status(&self) -> Look {
        self.looks
            .borrow_mut()
            .pop_front()
            .expect("a look that the test did not give")
    }

    fn reload(&self, to: [u8; 32], wait: Duration) -> Answered {
        self.orders.borrow_mut().push((Instant::now(), to, wait));
        (self.during)();
        self.answers
            .borrow_mut()
            .pop_front()
            .expect("an answer that the test did not give")
    }
}

/// The SHA-256 of the main file of the proxy.
const CONFIG: [u8; 32] = [0xc0; 32];

/// A proxy with `managed` in force, whose readings replaced its configuration `replaced` times, and whose names may take
/// 100 ms to be looked up.
fn seen(managed: [u8; 32], replaced: u64) -> State {
    State {
        config: Some(CONFIG),
        managed: Some(managed),
        reloading: Some(false),
        resolve_timeout: Some(Duration::from_millis(100)),
        replaced: Some(replaced),
    }
}

fn state(managed: [u8; 32], replaced: u64) -> Look {
    Look::State(seen(managed, replaced))
}

/// A store that chooses `from`, and has `to` as well.
fn store() -> (Fixture, [u8; 32], [u8; 32]) {
    let fixture = Fixture::new();
    let from = fixture.current(&json!({"n": 1}));
    let to = fixture.version(&json!({"n": 2}));
    (fixture, from, to)
}

fn order(fixture: &Fixture, proxy: &Fake, from: [u8; 32], to: [u8; 32]) -> Outcome<&'static str> {
    apply(
        &fixture.store(),
        proxy,
        from,
        to,
        Duration::from_secs(30),
        |_| Ok(()),
    )
}

fn current(fixture: &Fixture) -> Option<[u8; 32]> {
    fixture.store().current().unwrap()
}

#[test]
fn a_version_that_the_proxy_takes_is_chosen_and_one_that_it_refuses_is_not() {
    let (fixture, from, to) = store();
    let refused = Answered::Refused {
        reason: "store",
        detail: "a managed file does not match its name".to_owned(),
    };
    let proxy = Fake::new(vec![state(from, 0)], vec![refused]);
    assert_eq!(
        order(&fixture, &proxy, from, to),
        Outcome::Refused {
            reason: "store",
            detail: "a managed file does not match its name".to_owned()
        }
    );
    assert_eq!(current(&fixture), Some(from));
    // Ordered once, for the version, as long as the proxy says its names may take and 7 s.
    let orders = proxy.orders.borrow().clone();
    assert_eq!(
        orders.iter().map(|o| (o.1, o.2)).collect::<Vec<_>>(),
        [(to, Duration::from_millis(7_100))]
    );
    assert!(proxy.spent());

    let replaced = Answered::Replaced {
        config: [0xc1; 32],
        managed: Some(to),
    };
    let proxy = Fake::new(vec![state(from, 0)], vec![replaced]);
    assert_eq!(
        order(&fixture, &proxy, from, to),
        Outcome::Applied {
            before: Some(CONFIG),
            after: Some([0xc1; 32])
        }
    );
    assert_eq!(current(&fixture), Some(to));
    assert!(proxy.spent());
}

#[test]
fn nothing_is_ordered_or_changed_before_the_store_and_the_proxy_are_found_ready() {
    let (fixture, from, to) = store();
    let none = |looks: Vec<Look>| Fake::new(looks, vec![]);
    // The proxy cannot be reached, has no place, has no `managed`, or reads its configuration again already.
    let reading = Look::State(State {
        reloading: Some(true),
        ..seen(from, 0)
    });
    let unmanaged = Look::State(State {
        managed: None,
        ..seen(from, 0)
    });
    for (look, outcome) in [
        (Look::Unreachable, Outcome::Unreachable),
        (Look::Busy, Outcome::Busy("proxy busy")),
        (unmanaged, Outcome::Unmanaged),
        (reading, Outcome::Busy("reload under way")),
    ] {
        let proxy = none(vec![look]);
        let called = RefCell::new(false);
        let ended = apply(
            &fixture.store(),
            &proxy,
            from,
            to,
            Duration::from_secs(30),
            |_| {
                *called.borrow_mut() = true;
                Ok::<(), &str>(())
            },
        );
        assert_eq!(ended, outcome);
        assert!(!*called.borrow() && proxy.orders.borrow().is_empty());
        assert!(proxy.spent());
    }
    // `before` is given the state of the proxy, the SHA-256 of its main file with it, and what it refuses is the end.
    let proxy = none(vec![state(from, 0)]);
    let given = RefCell::new(None);
    let ended = apply(
        &fixture.store(),
        &proxy,
        from,
        to,
        Duration::from_secs(30),
        |state: &State| {
            *given.borrow_mut() = Some(*state);
            Err("audit")
        },
    );
    assert_eq!(ended, Outcome::Before("audit"));
    assert_eq!(*given.borrow(), Some(seen(from, 0)));
    assert!(proxy.orders.borrow().is_empty());
    // The store does not choose what the caller saw, or has no such version: the proxy is not asked.
    assert_eq!(
        order(&fixture, &none(vec![]), to, from),
        Outcome::CurrentChanged
    );
    assert_eq!(
        order(&fixture, &none(vec![]), from, [0x33; 32]),
        Outcome::NoVersion
    );
    assert_eq!(current(&fixture), Some(from));
}

#[test]
fn an_order_without_an_answer_is_looked_after_and_advances_only_with_the_version_and_a_grown_count()
{
    let (fixture, from, to) = store();
    // No answer; then the proxy has no place, is still reading, and then serves the version after one more reading.
    let reading = Look::State(State {
        reloading: Some(true),
        ..seen(from, 3)
    });
    let proxy = Fake::new(
        vec![state(from, 3), Look::Busy, reading, state(to, 4)],
        vec![Answered::Nothing],
    );
    assert_eq!(
        order(&fixture, &proxy, from, to),
        Outcome::Applied {
            before: Some(CONFIG),
            after: Some(CONFIG)
        }
    );
    assert_eq!(current(&fixture), Some(to));
    assert!(proxy.spent());

    // The proxy has the version in force already (the store fell behind it) and its reading of it is refused: it
    // shows the version, but no reading replaced anything, so the order failed.
    let (fixture, from, to) = store();
    let proxy = Fake::new(
        vec![state(to, 3), state(to, 3)],
        vec![Answered::Busy("reload under way")],
    );
    assert_eq!(order(&fixture, &proxy, from, to), Outcome::Failed);
    assert_eq!(current(&fixture), Some(from));

    // An answer that the configuration was replaced with another version than `to` is no answer to this order: the
    // looks find `to` not in force, and the order failed, though a reading replaced the configuration.
    let proxy = Fake::new(
        vec![state(from, 3), state(from, 4)],
        vec![Answered::Replaced {
            config: CONFIG,
            managed: Some(from),
        }],
    );
    assert_eq!(order(&fixture, &proxy, from, to), Outcome::Failed);
    assert_eq!(current(&fixture), Some(from));
    assert!(proxy.spent());

    // A proxy that goes away leaves it unknown.
    let proxy = Fake::new(
        vec![state(from, 3), Look::Unreachable],
        vec![Answered::Nothing],
    );
    assert_eq!(order(&fixture, &proxy, from, to), Outcome::Unconfirmed);
    assert_eq!(current(&fixture), Some(from));
    assert!(proxy.spent());
}

#[test]
fn a_refused_certificate_is_asked_again_once_after_a_second() {
    let (fixture, from, to) = store();
    let tls = || Answered::Refused {
        reason: "tls",
        detail: "a certificate and a private key are not a pair (site a)".to_owned(),
    };
    let replaced = Answered::Replaced {
        config: CONFIG,
        managed: Some(to),
    };
    let proxy = Fake::new(vec![state(from, 0)], vec![tls(), replaced]);
    assert!(matches!(
        order(&fixture, &proxy, from, to),
        Outcome::Applied { .. }
    ));
    let orders = proxy.orders.borrow().clone();
    assert_eq!(orders.len(), 2);
    assert!(orders[1].0.duration_since(orders[0].0) >= AGAIN);
    // Refused again: that is the answer, and there is no third ask.
    let (fixture, from, to) = store();
    let proxy = Fake::new(vec![state(from, 0)], vec![tls(), tls()]);
    assert!(matches!(
        order(&fixture, &proxy, from, to),
        Outcome::Refused { reason: "tls", .. }
    ));
    assert_eq!(current(&fixture), Some(from));
    assert!(proxy.spent());
}

#[test]
fn the_store_is_held_through_the_order_so_managed_activate_is_refused_meanwhile() {
    let (fixture, from, to) = store();
    let main = fixture.main_file(|_| {});
    let (log, lines) = recording();
    let mut proxy = Fake::new(
        vec![state(from, 0)],
        vec![Answered::Replaced {
            config: CONFIG,
            managed: Some(to),
        }],
    );
    let exits = std::rc::Rc::new(RefCell::new(Vec::new()));
    let seen = exits.clone();
    let args: Vec<std::ffi::OsString> =
        vec!["activate".into(), main.into_os_string(), hex(&from).into()];
    proxy.during = Box::new(move || {
        let exit = command::run(&args, &mut Vec::<u8>::new(), &log);
        seen.borrow_mut().push(exit);
    });
    assert!(matches!(
        order(&fixture, &proxy, from, to),
        Outcome::Applied { .. }
    ));
    assert_eq!(*exits.borrow(), [Exit::Failed]);
    assert!(
        lines
            .texts()
            .contains(&format!("managed activate: {}", IN_USE.0)),
        "{:?}",
        lines.texts()
    );
    // Another order while one holds the store is busy, and changes nothing.
    let lock = fixture.store().lock().unwrap();
    let proxy = Fake::new(vec![], vec![]);
    assert_eq!(
        order(&fixture, &proxy, to, from),
        Outcome::Busy("store in use")
    );
    drop(lock);
    assert_eq!(current(&fixture), Some(to));
}

#[test]
fn a_version_that_the_store_does_not_choose_after_the_proxy_took_it_is_not_recorded() {
    let (fixture, from, to) = store();
    let other = fixture.version(&json!({"n": 3}));
    let mut proxy = Fake::new(
        vec![state(from, 0)],
        vec![Answered::Replaced {
            config: CONFIG,
            managed: Some(to),
        }],
    );
    // `current` changed by hand while the proxy read the version.
    let store = fixture.store();
    proxy.during = Box::new(move || store.choose(other).unwrap());
    assert_eq!(
        order(&fixture, &proxy, from, to),
        Outcome::NotRecorded {
            why: Unrecorded::CurrentChanged,
            before: Some(CONFIG),
            after: Some(CONFIG)
        }
    );
    assert_eq!(current(&fixture), Some(other));
}
