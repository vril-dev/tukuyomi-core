use super::*;

fn message(id: i64, severity: Option<i32>) -> Message {
    Message {
        id,
        severity,
        disruptive: false,
    }
}

#[test]
fn the_ids_come_in_order_and_the_deciding_rule_is_left_out_but_its_severity_counts() {
    let messages = [
        message(10, Some(4)),
        message(11, None),
        message(12, Some(2)),
        message(13, Some(9)),
        message(14, Some(-1)),
    ];
    let detail = detail(&messages, 12, None);
    assert_eq!(detail.ids, [10, 11, 13, 14]);
    assert!(!detail.more);
    // The deciding rule's 2 counts; a severity that the protocol cannot carry (9, -1) is skipped.
    assert_eq!(detail.severity, 2);
    assert_eq!(detail.score, -1);
    // No rule has a severity: none.
    assert_eq!(super::detail(&[message(1, None)], 0, None).severity, 255);
}

#[test]
fn only_the_first_sixteen_ids_are_listed_and_more_is_set_by_the_seventeenth() {
    let sixteen: Vec<Message> = (1..=16).map(|id| message(id, Some(3))).collect();
    let detail16 = detail(&sixteen, 0, None);
    assert_eq!((detail16.ids.len(), detail16.more), (16, false));
    let mut seventeen = sixteen;
    seventeen.push(message(17, Some(0)));
    let detail17 = detail(&seventeen, 0, None);
    assert_eq!(detail17.ids, (1..=16).collect::<Vec<i64>>());
    // The seventeenth is not listed, and its severity counts.
    assert_eq!((detail17.more, detail17.severity), (true, 0));
}

#[test]
fn a_message_with_an_id_the_protocol_cannot_carry_leaves_the_detail_empty() {
    let detail = detail(&[message(5, Some(1)), message(0, Some(1))], 0, Some(b"7"));
    assert_eq!(detail, RuleDetail::NONE);
}

#[test]
fn the_score_is_read_as_digits_only() {
    assert_eq!(parse_score(b"0"), 0);
    assert_eq!(parse_score(b"005"), 5);
    assert_eq!(parse_score(b"2147483647"), i32::MAX);
    // More than an i32 holds is the largest i32, however long the digits go on.
    assert_eq!(parse_score(b"99999999999999999999999999"), i32::MAX);
    for text in [
        &b""[..],
        b"-3",
        b"+3",
        b"12a",
        b" 5",
        b"5 ",
        b"1.5",
        b"\xd9\xa5",
    ] {
        assert_eq!(parse_score(text), -1, "{text:?}");
    }
    assert_eq!(detail(&[], 0, Some(b"12")).score, 12);
}
