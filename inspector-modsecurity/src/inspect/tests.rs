use super::arguments::{LIMIT, Parts, json_over};
use super::*;
use crate::codec::{RuleDetail, TxBegin};
use crate::ffi::tests::{in_a_fresh_process, in_a_restricted_process};
use crate::ffi::{Processor, Rules};
use crate::owner::{Fault, Inspection, Outcome, Stop, Transaction};
use crate::rules;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

/// What the rules of every generation start with.
const FIXED: &str = "SecRuleEngine On\nSecRequestBodyAccess On\nSecRequestBodyJsonDepthLimit 64\n";

/// A rule that stops a request with `attack` in an argument, in phase 2.
const DENY_ATTACK: &str =
    "SecRule ARGS \"@contains attack\" \"id:1001,phase:2,deny,status:418,log,severity:2\"\n";

fn inspector(rules_text: &str, detect: bool) -> Inspector {
    let mut rules = Rules::new().unwrap();
    rules.add_text(FIXED).unwrap();
    if !rules_text.is_empty() {
        rules.add_text(rules_text).unwrap();
    }
    Inspector::new(rules, detect).unwrap()
}

/// A request as the proxy would hand it over.
struct Request {
    method: &'static str,
    uri: String,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
    cut: bool,
}

impl Request {
    fn get(uri: &str) -> Request {
        Request {
            method: "GET",
            uri: uri.to_string(),
            headers: vec![
                ("Host", "example.test".to_string()),
                ("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)".to_string()),
                ("Accept", "*/*".to_string()),
            ],
            body: Vec::new(),
            cut: false,
        }
    }

    fn post(uri: &str, content_type: &str, body: &[u8]) -> Request {
        let mut request = Request::get(uri);
        request.method = "POST";
        request
            .headers
            .push(("Content-Type", content_type.to_string()));
        request
            .headers
            .push(("Content-Length", body.len().to_string()));
        request.body = body.to_vec();
        request
    }

    fn cut(mut self) -> Request {
        self.cut = true;
        self
    }
}

/// What the inspection of a request answered in phase 1 and, when the request was not stopped there, in phase 2.
type Answers = Result<(Outcome, Option<Outcome>), Fault>;

/// Drives the inspection of one request the way the table does: begin, the body in parts of 64 KiB, end, close.
fn run(inspector: &mut Inspector, request: &Request) -> Answers {
    let mut tx = inspector.start().unwrap();
    let headers: Vec<(&[u8], &[u8])> = request
        .headers
        .iter()
        .map(|(name, value)| (name.as_bytes(), value.as_bytes()))
        .collect();
    let begin = TxBegin {
        client_addr: b"192.0.2.10",
        client_port: 49152,
        server_addr: b"192.0.2.1",
        server_port: 80,
        method: request.method.as_bytes(),
        uri: request.uri.as_bytes(),
        proto: b"HTTP/1.1",
        declared: request.body.len() as u64,
        headers,
        cut: request.cut,
    };
    let answers = (|| {
        let first = tx.begin(&begin)?;
        if matches!(first, Outcome::Block(_)) {
            return Ok((first, None));
        }
        for part in request.body.chunks(64 * 1024) {
            assert_eq!(tx.body(part)?, None);
        }
        Ok((first, Some(tx.end()?)))
    })();
    assert!(!tx.close(), "the logging phase failed");
    answers
}

/// A short form of an answer: what it was, and which rule and status.
fn word(outcome: &Outcome) -> String {
    match outcome {
        Outcome::Continue(_) => "continue".to_string(),
        Outcome::Block(stop) => format!("block {} {}", stop.rule_id, stop.status),
        Outcome::Detected(stop) => format!("detected {} {}", stop.rule_id, stop.status),
    }
}

/// The two answers of a request, as words; `fault N` for an inspection that failed with code N.
fn words(answers: &Answers) -> String {
    match answers {
        Ok((first, None)) => word(first),
        Ok((first, Some(second))) => format!("{} / {}", word(first), word(second)),
        Err(fault) => format!("fault {}", u16::from(fault.code)),
    }
}

/// The rules that an answer says matched.
fn rules_of(outcome: &Outcome) -> &RuleDetail {
    match outcome {
        Outcome::Continue(rules) => rules,
        Outcome::Block(stop) | Outcome::Detected(stop) => &stop.rules,
    }
}

fn stop_of(outcome: &Outcome) -> &Stop {
    match outcome {
        Outcome::Block(stop) | Outcome::Detected(stop) => stop,
        Outcome::Continue(_) => panic!("not a stop: {outcome:?}"),
    }
}

/// A query of `count` arguments, each `a`.
fn arguments(count: usize) -> String {
    vec!["a"; count].join("&")
}

#[test]
fn a_request_that_no_rule_matches_goes_on_in_both_phases() {
    let mut inspector = inspector(DENY_ATTACK, false);
    let answers = run(&mut inspector, &Request::get("/index?q=fine")).unwrap();
    assert_eq!(
        answers,
        (
            Outcome::Continue(RuleDetail::NONE),
            Some(Outcome::Continue(RuleDetail::NONE))
        )
    );
}

#[test]
fn a_rule_of_the_operator_that_stops_blocks_or_is_detected_by_the_mode() {
    let request = Request::get("/?q=attack");
    let blocked = run(&mut inspector(DENY_ATTACK, false), &request);
    assert_eq!(words(&blocked), "continue / block 1001 418");
    // The rule that decided is not in the list, and its severity counts.
    let (_, second) = blocked.unwrap();
    let second = second.unwrap();
    let rules = &stop_of(&second).rules;
    assert_eq!((rules.ids.is_empty(), rules.severity), (true, 2));

    // A generation that only detects reinterprets the stop: the same rule and status, as a detection.
    let detected = run(&mut inspector(DENY_ATTACK, true), &request);
    assert_eq!(words(&detected), "continue / detected 1001 418");
}

#[test]
fn a_stop_of_phase_1_blocks_in_phase_1_or_is_carried_to_phase_2_by_a_generation_that_detects() {
    let rules = "\
SecRule REQUEST_URI \"@contains attack\" \"id:1002,phase:1,deny,status:403,log\"\n\
SecRule ARGS \"@contains attack\" \"id:1003,phase:2,pass,log,severity:5\"\n";
    let request = Request::get("/?q=attack");
    assert_eq!(
        words(&run(&mut inspector(rules, false), &request)),
        "block 1002 403"
    );
    let answers = run(&mut inspector(rules, true), &request);
    assert_eq!(words(&answers), "continue / detected 1002 403");
    // The rules of phase 2 went on running after the stop of phase 1 was taken, and the stop is not listed.
    let (first, second) = answers.unwrap();
    let Outcome::Continue(first) = first else {
        panic!("{first:?}")
    };
    assert_eq!(first.ids, [1002]);
    assert_eq!(stop_of(&second.unwrap()).rules.ids, [1003]);
}

#[test]
fn a_generation_that_detects_keeps_the_first_stop_and_not_a_later_one() {
    // Both rules stop the request, in phase 1 and again in phase 2, with another status.
    let rules = format!(
        "SecRule REQUEST_URI \"@contains attack\" \"id:1002,phase:1,deny,status:403,log\"\n{DENY_ATTACK}"
    );
    let answers = run(&mut inspector(&rules, true), &Request::get("/?q=attack"));
    assert_eq!(words(&answers), "continue / detected 1002 403");
    // The rule of phase 2 ran, and what it matched is listed with the stop that was kept left out.
    let (_, second) = answers.unwrap();
    assert_eq!(stop_of(&second.unwrap()).rules.ids, [1001]);
}

#[test]
fn a_block_of_the_inspector_comes_after_the_stop_of_a_rule_when_blocking_and_before_a_detection() {
    // More arguments than the limit, and a rule of the operator that stops the request.
    let request = Request::get(&format!("/?q=attack&{}", arguments(LIMIT + 1)));
    assert_eq!(
        words(&run(&mut inspector(DENY_ATTACK, false), &request)),
        "continue / block 1001 418"
    );
    assert_eq!(
        words(&run(&mut inspector(DENY_ATTACK, true), &request)),
        "continue / block 4000002 403"
    );
}

#[test]
fn an_intervention_that_no_message_names_is_not_inspected() {
    // A rule that stops and logs nothing: nothing says which rule it was.
    let nolog = "SecRule ARGS \"@contains attack\" \"id:1012,phase:2,deny,nolog\"\n";
    let request = Request::get("/?q=attack");
    for detect in [false, true] {
        assert_eq!(
            words(&run(&mut inspector(nolog, detect), &request)),
            "fault 25"
        );
    }
    // After a stop that was logged, in phase 1: the message of that stop does not name the later one.
    let both = format!(
        "SecRule REQUEST_URI \"@contains attack\" \"id:1002,phase:1,deny,status:403,log\"\n{nolog}"
    );
    assert_eq!(
        words(&run(&mut inspector(&both, true), &request)),
        "fault 25"
    );
}

#[test]
fn the_arguments_of_a_query_and_of_a_form_are_counted_apart_and_a_thousand_is_the_most() {
    let mut inspector = inspector("", false);
    let ok = run(
        &mut inspector,
        &Request::get(&format!("/?{}", arguments(LIMIT))),
    );
    assert_eq!(words(&ok), "continue / continue");
    let over = run(
        &mut inspector,
        &Request::get(&format!("/?{}", arguments(LIMIT + 1))),
    );
    assert_eq!(words(&over), "continue / block 4000002 403");
    // Empty parts between the `&` are not arguments.
    let padded = format!("/?&&{}&&", arguments(LIMIT).replace('&', "&&"));
    let padded = run(&mut inspector, &Request::get(&padded));
    assert_eq!(words(&padded), "continue / continue");

    // A thousand in the query and a thousand in the form are two counts, not one.
    let form = |count| {
        let mut request = Request::post(
            &format!("/?{}", arguments(LIMIT)),
            "application/x-www-form-urlencoded",
            arguments(count).as_bytes(),
        );
        request.method = "POST";
        request
    };
    assert_eq!(
        words(&run(&mut inspector, &form(LIMIT))),
        "continue / continue"
    );
    assert_eq!(
        words(&run(&mut inspector, &form(LIMIT + 1))),
        "continue / block 4000002 403"
    );
}

#[test]
fn the_arguments_of_a_form_that_was_cut_are_counted_too() {
    let cut_form = |count| {
        Request::post(
            "/",
            "application/x-www-form-urlencoded",
            arguments(count).as_bytes(),
        )
        .cut()
    };
    let mut inspector = inspector("", false);
    assert_eq!(
        words(&run(&mut inspector, &cut_form(LIMIT))),
        "continue / continue"
    );
    assert_eq!(
        words(&run(&mut inspector, &cut_form(LIMIT + 1))),
        "continue / block 4000002 403"
    );
}

#[test]
fn the_values_of_a_json_body_are_counted_with_the_arrays_of_their_own() {
    let numbers = |count: usize| format!("[{}]", vec!["0"; count].join(","));
    assert!(!json_over(numbers(LIMIT).as_bytes()));
    assert!(json_over(numbers(LIMIT + 1).as_bytes()));
    // Each array that is not empty counts once, apart from the values; the outer one too.
    let arrays = |count: usize| format!("[{}]", vec!["[0]"; count].join(","));
    assert!(!json_over(arrays(LIMIT - 1).as_bytes()));
    assert!(json_over(arrays(LIMIT).as_bytes()));
    // A body that does not parse is counted as far as it goes.
    assert!(!json_over(b"{\"a\":"));
    // Objects are values by their members.
    assert!(!json_over(br#"{"a":{"b":[1,2],"c":null},"d":"e"}"#));

    let mut parts = Parts::default();
    parts.feed(b"a=1&&b");
    parts.feed(b"c&");
    parts.feed(b"&d=");
    assert!(!parts.over());
    // The count goes on across pieces: a part that is cut in two is one.
    let mut parts = Parts::default();
    for _ in 0..LIMIT {
        parts.feed(b"a&");
    }
    assert!(!parts.over());
    parts.feed(b"b");
    assert!(parts.over());
}

#[test]
fn a_target_that_cannot_be_parsed_blocks() {
    let mut inspector = inspector("", false);
    let answers = run(&mut inspector, &Request::get("/a%zz?x=1"));
    assert_eq!(words(&answers), "continue / block 4000003 403");
    // The case at the limit goes on, and so does a bad escape after the `?` and after the `#`.
    for target in ["/a%41", "/a?b=%zz", "/a#%zz", "*"] {
        let answers = run(&mut inspector, &Request::get(target));
        assert_eq!(words(&answers), "continue / continue", "{target}");
    }
    for target in ["/a%4", "foo", "/a\tb"] {
        let answers = run(&mut inspector, &Request::get(target));
        assert_eq!(words(&answers), "continue / block 4000003 403", "{target}");
    }
}

#[test]
fn a_body_that_does_not_parse_blocks_unless_it_was_cut() {
    let mut inspector = inspector("", false);
    let json = |body: &[u8]| Request::post("/", "application/json", body);
    assert_eq!(
        words(&run(&mut inspector, &json(br#"{"a":"b"}"#))),
        "continue / continue"
    );
    assert_eq!(
        words(&run(&mut inspector, &json(b"{\"a\":"))),
        "continue / block 4000001 403"
    );
    // The same body, cut by the proxy: its failure is no reason to block.
    assert_eq!(
        words(&run(&mut inspector, &json(b"{\"a\":").cut())),
        "continue / continue"
    );
}

#[test]
fn what_cannot_be_confirmed_to_have_run_to_the_end_is_not_let_through() {
    let form = |body: &[u8]| Request::post("/", "application/x-www-form-urlencoded", body);
    let rule =
        |actions: &str| format!("SecRule REQUEST_URI \"@rx .\" \"id:1010,{actions},pass,nolog\"\n");
    // The rule engine of the request is switched off, or the body is no longer read, in phase 1.
    for actions in [
        "phase:1,ctl:ruleEngine=Off",
        "phase:1,ctl:requestBodyAccess=Off",
    ] {
        let mut inspector = inspector(&rule(actions), false);
        assert_eq!(words(&run(&mut inspector, &form(b"a=b"))), "fault 25");
    }
    // The processor is replaced after the body was parsed.
    let mut replaced = inspector(&rule("phase:2,ctl:requestBodyProcessor=XML"), false);
    assert_eq!(words(&run(&mut replaced, &form(b"a=b"))), "fault 25");
    // And that holds when the generation has a detection to report: the answer is still no inspection.
    let rules = format!(
        "SecRule REQUEST_URI \"@contains attack\" \"id:1002,phase:1,deny,log\"\n{}",
        rule("phase:2,ctl:requestBodyProcessor=XML")
    );
    let mut detecting = inspector(&rules, true);
    let mut request = form(b"a=b");
    request.uri = "/?q=attack".to_string();
    assert_eq!(words(&run(&mut detecting, &request)), "fault 25");

    // A body whose Content-Type is none of the three processors was not parsed.
    let mut plain = inspector("", false);
    let text = Request::post("/", "text/plain", b"a=b");
    assert_eq!(words(&run(&mut plain, &text)), "fault 25");
    // A request with no body has no processor and needs none.
    assert_eq!(
        words(&run(&mut plain, &Request::get("/"))),
        "continue / continue"
    );
}

#[test]
fn a_regular_expression_that_gave_up_is_not_let_through() {
    // The limit is set low through the library directly: the reader of the rules refuses the directive.
    let rules = "\
SecPcreMatchLimit 100\n\
SecRule ARGS \"@rx ^(a|aa)+$\" \"id:1004,phase:2,pass,nolog\"\n";
    let mut inspector = inspector(rules, false);
    let ok = run(&mut inspector, &Request::get("/?q=aaaa"));
    assert_eq!(words(&ok), "continue / continue");
    let spent = run(
        &mut inspector,
        &Request::get("/?q=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"),
    );
    assert_eq!(words(&spent), "fault 25");
}

#[test]
fn a_regular_expression_that_failed_is_not_let_through() {
    // The pattern of the second rule is made from a header. One that is not a regular expression does not match
    // anything, which is not the same as a request that the rule looked at and let go.
    let rules = "\
SecRule REQUEST_HEADERS:X-Re \"@rx .\" \"id:1030,phase:1,pass,nolog,setvar:tx.re=%{MATCHED_VAR}\"\n\
SecRule ARGS \"@rx %{tx.re}\" \"id:1031,phase:2,deny,status:403,log\"\n";
    let with = |pattern: &str| {
        let mut request = Request::get("/?q=attack");
        request.headers.push(("X-Re", pattern.to_string()));
        request
    };
    for detect in [false, true] {
        let mut inspector = inspector(rules, detect);
        let answers = run(&mut inspector, &with("attack("));
        assert_eq!(words(&answers), "fault 25", "detect: {detect}");
    }
    // A pattern that works is matched, and the rule stops the request.
    let answers = run(&mut inspector(rules, false), &with("attack"));
    assert_eq!(words(&answers), "continue / block 1031 403");
}

#[test]
fn a_multipart_body_is_parsed_with_the_processor_put_in_place_after_phase_1() {
    // A rule of phase 1 asks for another processor; the one of the Content-Type is put in place after phase 1, so
    // the request of the rule has no effect.
    let rules = "\
SecRule REQUEST_URI \"@rx .\" \"id:1020,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON\"\n\
SecRule ARGS_POST \"@contains attack\" \"id:1021,phase:2,deny,status:403,log\"\n";
    let multipart = |field: &str| {
        let body = format!(
            "--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n{field}\r\n\
--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x.txt\"\r\nContent-Type: text/plain\r\n\r\nhello\r\n\
--B--\r\n"
        );
        Request::post("/", "multipart/form-data; boundary=B", body.as_bytes())
    };
    let mut inspector = inspector(rules, false);
    assert_eq!(
        words(&run(&mut inspector, &multipart("fine"))),
        "continue / continue"
    );
    assert_eq!(
        words(&run(&mut inspector, &multipart("attack"))),
        "continue / block 1021 403"
    );
}

#[test]
fn a_body_with_more_than_one_content_type_is_not_let_through() {
    // The parts are cut by `A` inside a part that `B` cuts: read with the boundary of the last Content-Type, the
    // body is one part and the value `attack` is not shown to any rule; read with the first, the rule stops it.
    let body = "\
--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x.txt\"\r\nContent-Type: text/plain\r\n\r\n\
--A\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\nattack\r\n--A--\r\n\r\n--B--\r\n";
    let with_boundaries = |boundaries: &[&str]| {
        let types: Vec<String> = boundaries
            .iter()
            .map(|boundary| format!("multipart/form-data; boundary={boundary}"))
            .collect();
        let mut request = Request::post("/", &types[0], body.as_bytes());
        for content_type in &types[1..] {
            request.headers.push(("Content-Type", content_type.clone()));
        }
        request
    };
    for detect in [false, true] {
        let mut inspector = inspector(DENY_ATTACK, detect);
        let answers = run(&mut inspector, &with_boundaries(&["A", "B"]));
        assert_eq!(words(&answers), "fault 25", "detect: {detect}");
    }
    // One Content-Type gives the same body to the same rule, which stops it.
    let one = with_boundaries(&["A"]);
    assert_eq!(
        words(&run(&mut inspector(DENY_ATTACK, false), &one)),
        "continue / block 1001 418"
    );
    assert_eq!(
        words(&run(&mut inspector(DENY_ATTACK, true), &one)),
        "continue / detected 1001 418"
    );
    // A request with no body has no processor and needs none, however many Content-Type headers it has.
    let mut get = Request::get("/?q=fine");
    for _ in 0..2 {
        get.headers.push((
            "Content-Type",
            "multipart/form-data; boundary=A".to_string(),
        ));
    }
    assert_eq!(
        words(&run(&mut inspector(DENY_ATTACK, false), &get)),
        "continue / continue"
    );
}

#[test]
fn a_multipart_body_that_the_library_skips_is_not_let_through() {
    // With an empty boundary the library parses nothing and raises no flag, so the part below, which the rule
    // stops when it is read, is never shown to any rule. Quoted or not, in either mode, that is no inspection.
    let body = "--A\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\nattack\r\n--A--\r\n";
    let post = |content_type: &str| Request::post("/", content_type, body.as_bytes());
    for content_type in [
        "multipart/form-data; boundary=",
        "multipart/form-data; boundary=\"\"",
        // The library reads the value as a C string, so a NUL byte ends the boundary.
        "multipart/form-data; boundary=\0A",
    ] {
        for detect in [false, true] {
            let answers = run(&mut inspector(DENY_ATTACK, detect), &post(content_type));
            assert_eq!(
                words(&answers),
                "fault 25",
                "{content_type:?} detect: {detect}"
            );
        }
    }
    // With a boundary the same body is parsed and the rule stops it.
    let one = post("multipart/form-data; boundary=A");
    assert_eq!(
        words(&run(&mut inspector(DENY_ATTACK, false), &one)),
        "continue / block 1001 418"
    );
    assert_eq!(
        words(&run(&mut inspector(DENY_ATTACK, true), &one)),
        "continue / detected 1001 418"
    );
    // A header that the library refuses with an error is not a skipped body: its flag blocks the request. Here the
    // boundary holds nothing once the text after `;` is cut off, and the name of the parameter is not in lower case.
    for content_type in [
        "multipart/form-data; boundary=;",
        "multipart/form-data; Boundary=\"\"",
    ] {
        for detect in [false, true] {
            let answers = run(&mut inspector(DENY_ATTACK, detect), &post(content_type));
            assert_eq!(
                words(&answers),
                "continue / block 4000001 403",
                "{content_type:?} detect: {detect}"
            );
        }
    }
}

#[test]
fn the_processor_is_the_one_of_the_content_type_and_none_when_there_are_several() {
    let chosen = |headers: &[(&str, &str)]| {
        let headers: Vec<(&[u8], &[u8])> = headers
            .iter()
            .map(|(name, value)| (name.as_bytes(), value.as_bytes()))
            .collect();
        processor::choose(&headers)
    };
    assert_eq!(
        chosen(&[(
            "content-type",
            " Application/X-WWW-Form-Urlencoded; charset=utf-8"
        )]),
        Processor::UrlEncoded
    );
    assert_eq!(
        chosen(&[("Content-Type", "multipart/form-data; boundary=x")]),
        Processor::Multipart
    );
    for json in ["application/json", "application/vnd.api+json; v=1"] {
        assert_eq!(chosen(&[("Content-Type", json)]), Processor::Json, "{json}");
    }
    // A multipart type whose boundary is empty is not parsed by the library, and picks none.
    for empty in [
        "multipart/form-data; boundary=",
        "multipart/form-data; boundary=\"\"",
    ] {
        assert_eq!(
            chosen(&[("Content-Type", empty)]),
            Processor::None,
            "{empty}"
        );
    }
    // More than one picks none, in either order, even when they say the same, and however the name is written.
    for headers in [
        [
            ("Content-Type", "text/plain"),
            ("Content-Type", "application/json"),
        ],
        [
            ("Content-Type", "application/json"),
            ("Content-Type", "text/plain"),
        ],
        [
            ("Content-Type", "application/json"),
            ("content-type", "application/json"),
        ],
    ] {
        assert_eq!(chosen(&headers), Processor::None, "{headers:?}");
    }
    // A type that is none of them picks none, and so does a request that has no Content-Type.
    assert_eq!(chosen(&[("Content-Type", "text/plain")]), Processor::None);
    assert_eq!(chosen(&[("Accept", "application/json")]), Processor::None);
}

#[test]
fn a_target_is_read_as_a_request_target() {
    for target in [
        "/",
        "/a%41?x",
        "*",
        "http://example.test:8080/p?q",
        "http://[::1]:80/x",
    ] {
        assert!(uri::parses(target.as_bytes()), "{target}");
    }
    for target in [
        "",
        "/a%4",
        "/a\0b",
        "a/b",
        ":x",
        "http://a:b:c/",
        "http://[::1/x",
        "http://[1.2.3.4]/x",
        "http://us er@host/",
    ] {
        assert!(!uri::parses(target.as_bytes()), "{target:?}");
    }
    assert_eq!(uri::query(b"/a?b=1&c#d?e"), b"b=1&c");
    assert_eq!(uri::query(b"/a#d?e"), b"");
}

/// A directory under the temporary directory, removed when it goes out of scope.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Scratch {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "tkv-inspect-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Writes the files of a generation at their paths under `root`.
fn write_copy(root: &Path, files: &BTreeMap<String, Vec<u8>>) {
    for (path, bytes) in files {
        let file = root.join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, bytes).unwrap();
    }
}

/// The inspector that a restricted process makes from the files of a generation, which it builds the rules from
/// as the start of the process does: restrict, build, make the engine.
fn restricted_inspector(
    scratch: &Path,
    files: &BTreeMap<String, Vec<u8>>,
    load: &[String],
    detect: bool,
    run: impl FnOnce(&mut Inspector) -> String,
) -> String {
    let root = scratch.join("copy");
    write_copy(&root, files);
    in_a_restricted_process(scratch, |restricted| {
        let rules = match rules::build(&root, files, load, restricted) {
            Ok(rules) => rules,
            Err(refusal) => return format!("build refused: {refusal}"),
        };
        match Inspector::new(rules, detect) {
            Ok(mut inspector) => run(&mut inspector),
            Err(error) => format!("inspector refused: {error}"),
        }
    })
}

// The engine object is made after the process has restricted itself, so this is the test that it can be: a fresh
// process restricts itself, builds rules, makes the inspector and inspects a request.
#[test]
fn the_engine_can_be_made_in_a_process_that_has_restricted_itself() {
    in_a_fresh_process(
        "inspect::tests::the_engine_can_be_made_in_a_process_that_has_restricted_itself",
        || {
            let scratch = Scratch::new();
            let inside = scratch.0.join("inside");
            fs::create_dir_all(&inside).unwrap();
            let path = "rules/a.conf".to_string();
            let files = BTreeMap::from([(path.clone(), DENY_ATTACK.as_bytes().to_vec())]);
            let report = restricted_inspector(&inside, &files, &[path], false, |inspector| {
                let ok = run(inspector, &Request::get("/?q=fine"));
                let attack = run(inspector, &Request::get("/?q=attack"));
                format!("{} | {}", words(&ok), words(&attack))
            });
            assert_eq!(report, "continue / continue | continue / block 1001 418");
        },
    );
}

/// The directory of the Core Rule Set that the test is given.
fn crs_dir() -> PathBuf {
    match std::env::var("TUKUYOMI_TEST_CRS") {
        Ok(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => panic!(
            "TUKUYOMI_TEST_CRS is not set: this test needs the Core Rule Set and is never skipped"
        ),
    }
}

/// The files of the Core Rule Set in `dir` as a generation holds them: the setup file, then the rule files by the
/// bytes of their names; the data files are present and are not loaded.
fn crs_files(dir: &Path) -> (BTreeMap<String, Vec<u8>>, Vec<String>) {
    let mut files = BTreeMap::new();
    let mut load = vec!["crs/crs-setup.conf".to_string()];
    files.insert(
        load[0].clone(),
        fs::read(dir.join("crs-setup.conf")).unwrap(),
    );
    let mut names: Vec<OsString> = fs::read_dir(dir.join("rules"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    names.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    for name in names {
        let text = name.to_str().unwrap().to_string();
        let path = format!("crs/rules/{text}");
        if text.ends_with(".conf") || text.ends_with(".data") {
            files.insert(
                path.clone(),
                fs::read(dir.join("rules").join(&text)).unwrap(),
            );
        }
        if text.ends_with(".conf") {
            load.push(path);
        }
    }
    (files, load)
}

/// The Core Rule Set in a restricted process: the three requests of the trial of an import go on, and a request
/// with an SQL injection is stopped by the rule that adds up the score (949110), or detected.
fn crs_report(detect: bool) -> String {
    let scratch = Scratch::new();
    let inside = scratch.0.join("inside");
    fs::create_dir_all(&inside).unwrap();
    let (files, load) = crs_files(&crs_dir());
    restricted_inspector(&inside, &files, &load, detect, |inspector| {
        let trial = [
            Request::get("/"),
            Request::post("/", "application/x-www-form-urlencoded", b"a=b"),
            Request::post("/", "application/json", br#"{"a":"b"}"#),
        ];
        let mut report = Vec::new();
        for request in &trial {
            let answers = run(inspector, request);
            let mut line = words(&answers);
            // What matched, if the request did not go on as the trial wants, is the finding.
            if line != "continue / continue"
                && let Ok((first, second)) = &answers
            {
                for outcome in std::iter::once(first).chain(second) {
                    line.push_str(&format!(" {:?}", rules_of(outcome)));
                }
            }
            report.push(line);
        }
        let injection = run(inspector, &Request::get("/?q=1%27%20or%20%271%27%3D%271"));
        let (_, second) = injection.unwrap();
        let second = second.unwrap();
        let rules = rules_of(&second);
        // The score was read from the transaction, and rules that matched are listed.
        report.push(format!(
            "{} score>=5:{} listed:{}",
            word(&second),
            rules.score >= 5,
            !rules.ids.is_empty()
        ));
        report.join("\n")
    })
}

#[test]
#[ignore = "needs the Core Rule Set"]
fn the_core_rule_set_lets_the_trial_requests_go_on_and_blocks_an_sql_injection() {
    in_a_fresh_process(
        "inspect::tests::the_core_rule_set_lets_the_trial_requests_go_on_and_blocks_an_sql_injection",
        || {
            let report = crs_report(false);
            assert_eq!(
                report,
                "continue / continue\ncontinue / continue\ncontinue / continue\n\
block 949110 403 score>=5:true listed:true",
                "{report}"
            );
        },
    );
}

#[test]
#[ignore = "needs the Core Rule Set"]
fn the_core_rule_set_detects_an_sql_injection_in_a_generation_that_only_detects() {
    in_a_fresh_process(
        "inspect::tests::the_core_rule_set_detects_an_sql_injection_in_a_generation_that_only_detects",
        || {
            let report = crs_report(true);
            assert_eq!(
                report,
                "continue / continue\ncontinue / continue\ncontinue / continue\n\
detected 949110 403 score>=5:true listed:true",
                "{report}"
            );
        },
    );
}
