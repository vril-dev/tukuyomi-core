use super::*;

#[test]
fn the_answer_table() {
    use Reason::*;
    let answer = |outcome| match decide(outcome) {
        Decision::Answer(reply) => reply,
        Decision::Pass(_) => panic!("not an answer"),
    };
    assert_eq!(
        decide(Outcome::Verdict(Verdict::Allow)),
        Decision::Pass(Passed::Allowed)
    );
    // A detection goes on like an allow, whatever status the rule would have blocked with.
    for status in [0, 403, 600] {
        let detected = Outcome::Verdict(Verdict::Detected {
            rule_id: 9201,
            status,
        });
        assert_eq!(
            decide(detected),
            Decision::Pass(Passed::Detected { rule: 9201 }),
            "{status}"
        );
    }
    let block = |status| {
        Outcome::Verdict(Verdict::Block {
            phase: 1,
            rule_id: 9201,
            status,
        })
    };
    for status in [200, 403, 599] {
        let reply = answer(block(status));
        assert_eq!(
            (reply.status, reply.class, reply.rule, reply.internal),
            (status, Class::Blocked, Some(9201), false)
        );
    }
    for status in [0, 199, 600] {
        let reply = answer(block(status));
        assert_eq!(
            (reply.status, reply.class, reply.rule, reply.internal),
            (500, Class::Failed, Some(9201), true),
            "{status}"
        );
    }
    let uninspectable = |reason| answer(Outcome::Verdict(Verdict::Uninspectable(reason)));
    for reason in [Invalid, Cancelled] {
        let reply = uninspectable(reason);
        assert_eq!((reply.status, reply.internal), (500, true), "{reason:?}");
    }
    for reason in [
        QueueFull,
        Reason::Unavailable,
        WaitDeadline,
        VerdictDeadline,
        InspectorLost,
        Protocol,
        InspectorError { code: 7 },
        NotCreated { code: 8 },
    ] {
        let reply = uninspectable(reason);
        assert_eq!(
            (reply.status, reply.class, reply.internal),
            (503, Class::Failed, false),
            "{reason:?}"
        );
    }
    let invalid = answer(Outcome::Refused(Refused::Invalid(
        "header count out of range",
    )));
    assert_eq!((invalid.status, invalid.internal), (500, true));
    assert_eq!(invalid.reason, "header count out of range");
    for refused in [Refused::Full, Refused::IdsExhausted] {
        let reply = answer(Outcome::Refused(refused));
        assert_eq!(
            (reply.status, reply.class, reply.internal),
            (503, Class::Failed, false),
            "{refused:?}"
        );
    }
    let reply = answer(Outcome::Unavailable);
    assert_eq!((reply.status, reply.internal), (503, false));
}

#[test]
fn an_answer_is_empty_with_a_length_of_0_and_close() {
    let response = answer(403);
    assert_eq!(response.status().as_u16(), 403);
    assert_eq!(response.headers().get(CONTENT_LENGTH).unwrap(), "0");
    assert_eq!(response.headers().get(CONNECTION).unwrap(), "close");
    assert!(response.body().is_end_stream());
    let response = answer(204);
    assert!(response.headers().get(CONTENT_LENGTH).is_none());
    assert_eq!(response.headers().get(CONNECTION).unwrap(), "close");
}

#[test]
fn the_record_has_numbers_and_fixed_texts_only() {
    let blocked = Reply {
        status: 403,
        class: Class::Blocked,
        reason: "blocked by a rule",
        rule: Some(9201),
        internal: false,
    };
    assert_eq!(
        record(7, &blocked, Duration::from_millis(12)),
        "conn 7: blocked 403 blocked by a rule rule 9201 12 ms"
    );
    assert_eq!(
        record(8, &Reply::NONE, Duration::from_micros(1999)),
        "conn 8: closed 0 no answer rule - 1 ms"
    );
    assert_eq!(
        record(
            9,
            &Reply::forwarded(200, Passed::Allowed),
            Duration::from_millis(3)
        ),
        "conn 9: forwarded 200 forwarded rule - 3 ms"
    );
    assert_eq!(
        record(
            10,
            &Reply::forwarded(200, Passed::Detected { rule: 9201 }),
            Duration::from_millis(3)
        ),
        "conn 10: forwarded 200 detected by a rule rule 9201 3 ms"
    );
    assert_eq!(
        record(
            11,
            &Reply::forwarded(200, Passed::Bypassed),
            Duration::from_millis(3)
        ),
        "conn 11: forwarded 200 bypassed by a route rule - 3 ms"
    );
}
