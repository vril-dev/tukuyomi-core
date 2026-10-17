use super::*;

#[test]
fn the_answer_table() {
    use Reason::*;
    let answer = |outcome| match decide(outcome) {
        Decision::Answer(reply) => reply,
        Decision::Allow => panic!("not an answer"),
    };
    assert_eq!(decide(Outcome::Verdict(Verdict::Allow)), Decision::Allow);
    let block = |status| {
        Outcome::Verdict(Verdict::Block {
            phase: 1,
            rule_id: 9201,
            status,
        })
    };
    for status in [200, 204, 302, 304, 403, 418, 503, 599] {
        let reply = answer(block(status));
        assert_eq!(
            (reply.status, reply.class, reply.rule, reply.internal),
            (status, Class::Blocked, Some(9201), false)
        );
    }
    for status in [0, 1, 99, 100, 199, 600, 999, 1000, u16::MAX] {
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
    let others = [
        QueueFull,
        Reason::Unavailable,
        WaitDeadline,
        VerdictDeadline,
        InspectorLost,
        Protocol,
        InspectorError { code: 7 },
        NotCreated { code: 8 },
    ];
    for reason in others {
        let reply = uninspectable(reason);
        assert_eq!(
            (reply.status, reply.class, reply.internal),
            (503, Class::Failed, false),
            "{reason:?}"
        );
    }
    for refused in [
        Refused::Invalid("header count out of range"),
        Refused::Unsupported("content-type"),
    ] {
        let reply = answer(Outcome::Refused(refused));
        assert_eq!((reply.status, reply.internal), (500, true), "{refused:?}");
    }
    assert_eq!(
        answer(Outcome::Refused(Refused::Invalid(
            "header count out of range"
        )))
        .reason,
        "header count out of range"
    );
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
    for status in [200, 400, 403, 413, 500, 503, 599] {
        let response = answer(status);
        assert_eq!(response.status().as_u16(), status);
        assert_eq!(response.headers().get(CONTENT_LENGTH).unwrap(), "0");
        assert_eq!(response.headers().get(CONNECTION).unwrap(), "close");
        assert_eq!(response.headers().len(), 2);
        assert!(response.body().is_end_stream());
        assert_eq!(response.body().size_hint().exact(), Some(0));
    }
    for status in [204, 304] {
        let response = answer(status);
        assert!(response.headers().get(CONTENT_LENGTH).is_none());
        assert_eq!(response.headers().get(CONNECTION).unwrap(), "close");
    }
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
    let negative = Reply {
        rule: Some(-1),
        ..blocked
    };
    assert!(record(1, &negative, Duration::ZERO).contains("rule -1 0 ms"));
}
