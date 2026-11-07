use super::*;

fn change(from: u8, to: u8, result: &'static str) -> Change {
    Change {
        ts: "1970-01-01T00:00:00.000Z".to_owned(),
        actor: "ola".to_owned(),
        kind: Kind::Activate,
        from: [from; 32],
        to: [to; 32],
        result,
        reason: None,
        config_before: Some([7; 32]),
        config_after: None,
    }
}

#[test]
fn a_line_is_read_back_as_it_was_written_and_a_line_of_another_form_is_not_read() {
    let mut refused = change(1, 2, "refused");
    refused.reason = Some("upstream");
    for line in [change(1, 2, "applied"), refused] {
        let text = line.encode().unwrap();
        assert_eq!(Change::decode(text.as_bytes()), Some(line));
    }
    let text = change(1, 2, "applied").encode().unwrap();
    for (from, to) in [
        (r#""result":"applied""#, r#""result":"done""#),
        (r#""kind":"activate""#, r#""kind":"other""#),
        (r#""ola""#, r#""OLA""#),
        (r#""ola""#, r#""ola","reason":"some word""#),
        (r#""ola""#, r#""ola","extra":1"#),
    ] {
        let other = text.replacen(from, to, 1);
        assert_ne!(other, text);
        assert_eq!(Change::decode(other.as_bytes()), None, "{other}");
    }
}

#[test]
fn the_target_of_a_rollback_is_the_version_before_the_last_applied_change_to_the_chosen_one() {
    // Newest first: a refused change, a change to itself, and the change from 1 to 2.
    let lines = [
        change(2, 3, "refused"),
        change(2, 2, "applied"),
        change(1, 2, "applied"),
    ];
    assert_eq!(rollback_target(&lines, [2; 32]), Ok([1; 32]));
    assert!(rollback_target(&lines, [3; 32]).is_err());
    assert!(rollback_target(&lines[..2], [2; 32]).is_err());
}
