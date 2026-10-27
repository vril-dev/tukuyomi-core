use super::*;

fn fp(n: u8) -> Fingerprint {
    Fingerprint::of(&[n])
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
    assert_eq!(rollback_target(&[], fp(2)), Err(nothing));
    let newest_first = [
        line(5, 6, Ended::Failed),
        line(4, 4, Ended::Switched),
        line(3, 4, Ended::Unchanged),
        line(2, 3, Ended::Switched),
        line(1, 2, Ended::Switched),
    ];
    assert_eq!(rollback_target(&newest_first, fp(3)), Ok(fp(2)));
    // The history ends at another generation than the chosen one: after a switch that failed (6 is chosen), or after
    // a choice that a command made.
    let elsewhere = "the history does not end at the chosen generation";
    assert_eq!(rollback_target(&newest_first, fp(6)), Err(elsewhere));
    assert_eq!(rollback_target(&newest_first, fp(2)), Err(elsewhere));
    let none = [
        line(1, 2, Ended::Refused),
        line(1, 2, Ended::Unreachable),
        line(1, 2, Ended::Unconfirmed),
    ];
    assert_eq!(rollback_target(&none, fp(2)), Err(nothing));
}
