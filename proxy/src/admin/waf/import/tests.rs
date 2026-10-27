use super::*;
use crate::rules::trial::Failed;

fn body(text: &str) -> Body {
    serde_json::from_str(text).unwrap()
}

fn refusal(text: &str, crs_dir: Option<&Path>) -> (&'static str, Option<OsString>) {
    match body(text).request(crs_dir) {
        Err(e) => (e.reason, e.subject),
        Ok(_) => panic!("accepted"),
    }
}

#[test]
fn the_body_makes_the_uploads_and_the_options_of_rules_import() {
    let request = body(
        r#"{"rules":[{"name":"a.conf","data":"YQo="}],"data":[{"name":"l.data","data":"b25lCg=="}],
            "crs":true,"crs_off":["X.conf"],"routes":[{"path":"/api/generations","action":"bypass"}],
            "detect_only":true,"accept_block":true}"#,
    )
    .request(Some(Path::new("/crs")))
    .unwrap();
    assert!(request.accept_block);
    let uploads = request.uploads;
    assert_eq!(uploads.crs.as_deref(), Some(Path::new("/crs")));
    assert_eq!(uploads.crs_off, [OsString::from("X.conf")]);
    assert_eq!(
        uploads.rules,
        [Upload {
            name: "a.conf".to_owned(),
            data: b"a\n".to_vec()
        }]
    );
    assert_eq!(uploads.data[0].data, b"one\n");
    assert_eq!(uploads.mode, Mode::Detect);
    let routes: Value = serde_json::from_slice(&uploads.routes.unwrap()).unwrap();
    assert_eq!(routes[0]["path"], "/api/generations");
    // Every key may be left out.
    let empty = body("{}").request(None).unwrap();
    assert!(!empty.accept_block);
    assert_eq!((empty.uploads.crs, empty.uploads.mode), (None, Mode::Block));
}

#[test]
fn a_body_is_refused_for_a_key_it_may_not_have_a_crs_that_is_not_configured_or_a_file_that_is_not_base64()
 {
    assert!(serde_json::from_str::<Body>(r#"{"crs_dir":"/etc"}"#).is_err());
    assert!(
        serde_json::from_str::<Body>(r#"{"rules":[{"name":"a","data":"","path":"/x"}]}"#).is_err()
    );
    assert_eq!(
        refusal(r#"{"crs":true}"#, None).0,
        "the CRS is asked for but admin.crs_dir is not set"
    );
    assert_eq!(
        refusal(r#"{"rules":[{"name":"a.conf","data":"YQo"}]}"#, None),
        (
            "an input file is not base64 (the standard alphabet, with padding)",
            Some(OsString::from("a.conf"))
        )
    );
    let big = "A".repeat(ENCODED_MAX + 4);
    assert_eq!(
        refusal(
            &format!(r#"{{"rules":[{{"name":"big.conf","data":"{big}"}}]}}"#),
            None
        )
        .0,
        "an input file is over 2 MiB"
    );
    let part = r#"{"name":"a.conf","data":""}"#;
    let parts = vec![part; 129].join(",");
    assert_eq!(
        refusal(&format!(r#"{{"rules":[{parts}]}}"#), None).0,
        "the request has more than 128 files"
    );
    let off = vec![r#""X.conf""#; 129].join(",");
    assert_eq!(
        refusal(&format!(r#"{{"crs_off":[{off}]}}"#), None).0,
        "the request turns off more than 128 files of the CRS"
    );
}

#[test]
fn the_report_of_a_trial_shows_what_it_accepted_or_why_it_failed_and_what_the_inspector_said() {
    let accepted = Finish {
        result: Ok(vec![Accepted::Block {
            probe: "GET /",
            phase: 2,
            rule_id: 942_100,
            status: 403,
        }]),
        detail: Some(b"bad\xff\n".to_vec()),
        clean: true,
    };
    let shown = report(&accepted);
    assert_eq!(shown["passed"], true);
    assert_eq!(shown["accepted"][0]["kind"], "block");
    assert_eq!(shown["accepted"][0]["rule"], 942_100);
    assert_eq!(shown["detail"], escaped(b"bad\xff"));
    assert_ne!(shown["detail"], "bad\u{fffd}");
    let failed = Finish {
        result: Err(Failed::NotReady),
        detail: None,
        clean: true,
    };
    let shown = report(&failed);
    assert_eq!(shown["passed"], false);
    assert_eq!(shown["failure"], describe(&Failed::NotReady));
    let unclean = Finish {
        result: Ok(Vec::new()),
        detail: None,
        clean: false,
    };
    assert_eq!(report(&unclean)["passed"], false);
}
