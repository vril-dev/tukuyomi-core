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
fn the_record_has_numbers_and_fixed_texts_and_the_address_of_the_client_only() {
    let blocked = Reply {
        status: 403,
        class: Class::Blocked,
        reason: "blocked by a rule",
        rule: Some(9201),
        internal: false,
    };
    let client: IpAddr = "203.0.113.9".parse().unwrap();
    assert_eq!(
        record(7, &blocked, Duration::from_millis(12), client),
        "conn 7: blocked 403 blocked by a rule rule 9201 12 ms client 203.0.113.9"
    );
    assert_eq!(
        record(8, &Reply::NONE, Duration::from_micros(1999), client),
        "conn 8: closed 0 no answer rule - 1 ms client 203.0.113.9"
    );
    assert_eq!(
        record(
            9,
            &Reply::forwarded(200, Passed::Allowed),
            Duration::from_millis(3),
            client
        ),
        "conn 9: forwarded 200 forwarded rule - 3 ms client 203.0.113.9"
    );
    assert_eq!(
        record(
            10,
            &Reply::forwarded(200, Passed::Detected { rule: 9201 }),
            Duration::from_millis(3),
            client
        ),
        "conn 10: forwarded 200 detected by a rule rule 9201 3 ms client 203.0.113.9"
    );
    assert_eq!(
        record(
            11,
            &Reply::forwarded(200, Passed::Bypassed),
            Duration::from_millis(3),
            client
        ),
        "conn 11: forwarded 200 bypassed by a route rule - 3 ms client 203.0.113.9"
    );
    // An IPv6 address, and an IPv4 address in its mapped form, are written in the canonical form.
    let v6: IpAddr = "2001:db8::1".parse().unwrap();
    let mapped: IpAddr = "::ffff:203.0.113.9".parse().unwrap();
    assert!(record(12, &Reply::NONE, Duration::ZERO, v6).ends_with(" client 2001:db8::1"));
    assert!(record(13, &Reply::NONE, Duration::ZERO, mapped).ends_with(" client 203.0.113.9"));
}
