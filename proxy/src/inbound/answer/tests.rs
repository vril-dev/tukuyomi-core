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
fn an_answer_is_empty_with_a_length_of_0_and_close_after_marks_the_last_one() {
    let mut response = answer(403);
    assert_eq!(response.status().as_u16(), 403);
    assert_eq!(response.headers().get(CONTENT_LENGTH).unwrap(), "0");
    assert!(response.headers().get(CONNECTION).is_none());
    assert!(response.body().is_end_stream());
    close_after(&mut response);
    assert_eq!(response.headers().get(CONNECTION).unwrap(), "close");
    let response = answer(204);
    assert!(response.headers().get(CONTENT_LENGTH).is_none());
}

#[test]
fn the_replies_show_their_class_status_reason_and_rule() {
    let blocked = Reply {
        status: 403,
        class: Class::Blocked,
        reason: "blocked by a rule",
        rule: Some(9201),
        internal: false,
    };
    let shown = |reply: Reply| (reply.class.name(), reply.status, reply.reason, reply.rule);
    assert_eq!(
        shown(blocked),
        ("blocked", 403, "blocked by a rule", Some(9201))
    );
    assert_eq!(shown(Reply::NONE), ("closed", 0, "no answer", None));
    assert_eq!(
        shown(Reply::forwarded(200, Passed::Allowed)),
        ("forwarded", 200, "forwarded", None)
    );
    assert_eq!(
        shown(Reply::forwarded(200, Passed::Detected { rule: 9201 })),
        ("forwarded", 200, "detected by a rule", Some(9201))
    );
    assert_eq!(
        shown(Reply::forwarded(200, Passed::Bypassed)),
        ("forwarded", 200, "bypassed by a route", None)
    );
    assert_eq!(
        shown(Reply::failed(502, "upstream unavailable")),
        ("failed", 502, "upstream unavailable", None)
    );
}

#[test]
fn a_body_is_shown_by_its_length() {
    assert_eq!(Sizes::whole(Some(0), 0).lengths(), None);
    assert_eq!(Sizes::whole(None, 12).lengths(), Some((12, None)));
    assert_eq!(Sizes::whole(Some(30), 12).lengths(), Some((30, None)));
}
