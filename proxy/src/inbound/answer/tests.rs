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
fn only_a_reply_that_a_rule_decided_is_a_rule_hit() {
    let blocked = |status| match decide(Outcome::Verdict(Verdict::Block {
        phase: 1,
        rule_id: 9201,
        status,
    })) {
        Decision::Answer(reply) => reply,
        Decision::Pass(_) => panic!("not an answer"),
    };
    assert_eq!(blocked(403).hit(), Some(RuleHit::Block));
    assert_eq!(
        Reply::forwarded(200, Passed::Detected { rule: 9201 }).hit(),
        Some(RuleHit::Detect)
    );
    // A block status that no response can have is a fault of ours with the rule's number, and no hit.
    assert_eq!(blocked(99).hit(), None);
    for reply in [
        Reply::forwarded(200, Passed::Allowed),
        Reply::forwarded(200, Passed::Bypassed),
        Reply::failed(502, "upstream unavailable"),
        Reply::rejected(400, "malformed request head"),
        Reply::NONE,
    ] {
        assert_eq!(reply.hit(), None);
    }
}

#[test]
fn a_body_is_shown_by_its_length() {
    assert_eq!(Sizes::whole(Some(0), 0).lengths(), None);
    assert_eq!(Sizes::whole(None, 12).lengths(), Some((12, None)));
    assert_eq!(Sizes::whole(Some(30), 12).lengths(), Some((30, None)));
}

#[test]
fn a_route_with_security_keeps_what_a_rule_the_inspection_or_a_policy_decided() {
    use crate::rules::bundle::{Fingerprint, Mode};
    use tukuyomi_kernel::{Engine, Matched};

    // `stopped` tells that the inspection did not let the request through (see `conn::keep`).
    let noted = |reply: Reply, verdict: Option<Verdict>, stopped: bool| {
        let mut noted = Noted::new("id".to_string(), reply, "203.0.113.9".parse().unwrap());
        noted.keeping.stopped = stopped;
        noted.judged = verdict.map(|verdict| Judge {
            generation: Fingerprint::from_hex(&[b'a'; 64]).unwrap(),
            engine: Engine::Coraza,
            mode: Mode::Block,
            verdict,
            matched: Matched::NONE,
        });
        noted
    };
    let block = Verdict::Block {
        phase: 1,
        rule_id: 9201,
        status: 403,
    };
    let wild = Verdict::Block {
        phase: 1,
        rule_id: 9201,
        status: 99,
    };
    let detected = Verdict::Detected {
        rule_id: 9201,
        status: 403,
    };
    let answer = |verdict| match decide(Outcome::Verdict(verdict)) {
        Decision::Answer(reply) => reply,
        Decision::Pass(_) => panic!("not an answer"),
    };
    let lost = Verdict::Uninspectable(Reason::InspectorLost);
    for (what, kept) in [
        (noted(answer(block), Some(block), true), true),
        // A block whose status is out of range is answered with 500, and a rule decided it all the same.
        (noted(answer(wild), Some(wild), true), true),
        // A detection goes on to the upstream, and its record is kept whatever the upstream answers.
        (
            noted(
                Reply::forwarded(200, Passed::Detected { rule: 9201 }),
                Some(detected),
                false,
            ),
            true,
        ),
        (
            noted(
                Reply::failed(502, "upstream unavailable"),
                Some(detected),
                false,
            ),
            true,
        ),
        (
            noted(
                Reply::failed(503, "request time used up"),
                Some(detected),
                false,
            ),
            true,
        ),
        (
            noted(Reply::failed(503, "inspector lost"), Some(lost), true),
            true,
        ),
        // The inspection could not be asked or did not answer: there is no verdict.
        (
            noted(Reply::failed(503, "no inspection permit"), None, true),
            true,
        ),
        (
            noted(Reply::failed(503, "inspection unavailable"), None, true),
            true,
        ),
        (noted(Reply::refused(Refusal::Access), None, false), true),
        (
            noted(Reply::refused(Refusal::RateLimit(3)), None, false),
            true,
        ),
        (
            noted(Reply::rejected(403, "denied by route access"), None, false),
            true,
        ),
        (
            noted(
                Reply::forwarded(200, Passed::Allowed),
                Some(Verdict::Allow),
                false,
            ),
            false,
        ),
        (
            noted(
                Reply::failed(502, "upstream unavailable"),
                Some(Verdict::Allow),
                false,
            ),
            false,
        ),
        (
            noted(Reply::forwarded(200, Passed::Bypassed), None, false),
            false,
        ),
        (
            noted(Reply::failed(502, "upstream unavailable"), None, false),
            false,
        ),
        (
            noted(Reply::rejected(400, "malformed request head"), None, false),
            false,
        ),
        (
            noted(Reply::rejected(413, "body over the limit"), None, false),
            false,
        ),
        (noted(Reply::NONE, None, false), false),
    ] {
        assert_eq!(what.security(), kept, "{:?}", what.reply);
    }
}
