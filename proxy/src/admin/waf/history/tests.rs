use super::*;

fn fp(n: u8) -> Fingerprint {
    Fingerprint::of(&[n])
}

/// Every generation is of Coraza.
fn coraza(_: Fingerprint) -> Option<Engine> {
    Some(Engine::Coraza)
}

fn line(from: u8, to: u8, result: Ended) -> Activation {
    Activation::new(
        SystemTime::UNIX_EPOCH,
        "ola",
        (fp(from), fp(to)),
        Kind::Activate,
        result,
    )
}

#[test]
fn a_line_is_read_back_as_it_was_written_and_a_line_of_another_form_is_not_read() {
    let activation = line(1, 2, Ended::Switched);
    let text = activation.encode().unwrap();
    assert!(
        text.starts_with(r#"{"ts":"1970-01-01T00:00:00.000Z","actor":"ola","from":""#),
        "{text}"
    );
    assert_eq!(Activation::decode(text.as_bytes()), Some(activation));
    for (from, to) in [
        (r#""result":"switched""#, r#""result":"done""#),
        (r#""kind":"activate""#, r#""kind":"other""#),
        (r#""ola""#, r#""OLA""#),
        (r#""ola""#, r#""ola","extra":1"#),
        ("1970-01-01T00:00:00.000Z", "1970-01-01"),
    ] {
        assert_eq!(
            Activation::decode(text.replace(from, to).as_bytes()),
            None,
            "{to}"
        );
    }
    assert_eq!(Activation::decode(b"{"), None);
}

#[test]
fn every_result_is_read_back_by_its_word() {
    for result in [
        Ended::Switched,
        Ended::Unchanged,
        Ended::Refused,
        Ended::Failed,
        Ended::Unreachable,
        Ended::Unconfirmed,
    ] {
        let activation = line(1, 2, result);
        let text = activation.encode().unwrap();
        assert_eq!(Activation::decode(text.as_bytes()), Some(activation));
    }
}

#[test]
fn a_rollback_goes_to_the_from_of_the_last_switch_if_it_ended_at_the_chosen_generation() {
    let nothing = "there is no switch to go back from";
    assert_eq!(
        rollback_target(&[], fp(2), Engine::Coraza, coraza),
        Err(nothing)
    );
    let newest_first = [
        line(5, 6, Ended::Failed),
        line(4, 4, Ended::Switched),
        line(3, 4, Ended::Unchanged),
        line(2, 3, Ended::Switched),
        line(1, 2, Ended::Switched),
    ];
    assert_eq!(
        rollback_target(&newest_first, fp(3), Engine::Coraza, coraza),
        Ok(fp(2))
    );
    // The history ends at another generation than the chosen one: after a switch that failed (6 is chosen), or after
    // a choice that a command made.
    let elsewhere = "the history does not end at the chosen generation";
    assert_eq!(
        rollback_target(&newest_first, fp(6), Engine::Coraza, coraza),
        Err(elsewhere)
    );
    assert_eq!(
        rollback_target(&newest_first, fp(2), Engine::Coraza, coraza),
        Err(elsewhere)
    );
    let none = [
        line(1, 2, Ended::Refused),
        line(1, 2, Ended::Unreachable),
        line(1, 2, Ended::Unconfirmed),
    ];
    assert_eq!(
        rollback_target(&none, fp(2), Engine::Coraza, coraza),
        Err(nothing)
    );
}

#[test]
fn a_rollback_looks_only_at_the_lines_of_its_engine() {
    let nothing = "there is no switch to go back from";
    // 1 and 2 are of Coraza, 3 and 4 of ModSecurity. The line of ModSecurity is the newest, and a rollback of Coraza
    // is not drawn to it, nor the other way round.
    let engine_of = |generation: Fingerprint| {
        Some(if generation == fp(3) || generation == fp(4) {
            Engine::ModSecurity
        } else {
            Engine::Coraza
        })
    };
    let newest_first = [
        line(3, 4, Ended::Switched).of(Engine::ModSecurity),
        line(1, 2, Ended::Switched).of(Engine::Coraza),
    ];
    let target = |chosen: u8, engine| rollback_target(&newest_first, fp(chosen), engine, engine_of);
    assert_eq!(target(2, Engine::Coraza), Ok(fp(1)));
    assert_eq!(target(4, Engine::ModSecurity), Ok(fp(3)));
    assert_eq!(
        target(4, Engine::Coraza),
        Err("the history does not end at the chosen generation")
    );
    assert_eq!(
        target(2, Engine::ModSecurity),
        Err("the history does not end at the chosen generation")
    );
    // A line that names no engine is of an engine only if both its generations are: a switch from a generation of
    // one engine to a generation of the other is of neither.
    let old = [line(3, 2, Ended::Switched), line(1, 2, Ended::Switched)];
    let of = |engine| rollback_target(&old, fp(2), engine, engine_of);
    assert_eq!(of(Engine::Coraza), Ok(fp(1)));
    assert_eq!(of(Engine::ModSecurity), Err(nothing));
    // A generation whose engine cannot be told is of no engine.
    assert_eq!(
        rollback_target(&old, fp(2), Engine::Coraza, |_| None),
        Err(nothing)
    );
}

#[test]
fn the_engine_is_written_in_a_new_line_and_a_line_of_an_older_version_has_none() {
    let new = line(1, 2, Ended::Switched).of(Engine::ModSecurity);
    let text = new.encode().unwrap();
    assert!(text.ends_with(r#""engine":"modsecurity"}"#), "{text}");
    assert_eq!(Activation::decode(text.as_bytes()), Some(new));
    let old = line(1, 2, Ended::Switched);
    let text = old.encode().unwrap();
    assert!(!text.contains("engine"), "{text}");
    assert_eq!(Activation::decode(text.as_bytes()), Some(old));
    // The name is an engine, exactly.
    let new = line(1, 2, Ended::Switched)
        .of(Engine::Coraza)
        .encode()
        .unwrap();
    assert_eq!(
        Activation::decode(new.replace("coraza", "Coraza").as_bytes()),
        None
    );
}
