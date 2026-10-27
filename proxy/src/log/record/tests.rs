use super::*;
use std::net::{Ipv4Addr, Ipv6Addr};

fn text(value: &[u8], limit: usize) -> (String, bool) {
    Raw::copy(value, limit).text(limit)
}

#[test]
fn bytes_that_can_hurt_the_reader_become_percent_escapes_and_a_percent_stays() {
    for (value, want) in [
        (&b"/a-b_c.d~z"[..], "/a-b_c.d~z"),
        (&[0x00][..], "%00"),
        (&[b' '][..], "%20"),
        (&[0x7f][..], "%7F"),
        (&[0x80][..], "%80"),
        (&[b'"'][..], "%22"),
        (&[b'\\'][..], "%5C"),
        // The bytes of a bidirectional override are three bytes of a character; none of them survives.
        (&[0xe2, 0x80, 0xae][..], "%E2%80%AE"),
        (&[b'\n', b'\r', 0x1b][..], "%0A%0D%1B"),
        // A received escape is the same text as the byte it stands for, so a `%` is not escaped again.
        (&b"/a%20b%80"[..], "/a%20b%80"),
        (&b"100%"[..], "100%"),
        (&b"%zz%4"[..], "%zz%4"),
    ] {
        assert_eq!(text(value, 1024), (want.to_string(), false), "{value:?}");
    }
}

#[test]
fn a_value_at_the_limit_is_whole_and_one_byte_more_is_cut() {
    let path = "/".repeat(PATH_MAX);
    assert_eq!(
        Raw::copy(path.as_bytes(), PATH_MAX).text(PATH_MAX),
        (path.clone(), false)
    );
    let more = format!("{path}/");
    assert_eq!(
        Raw::copy(more.as_bytes(), PATH_MAX).text(PATH_MAX),
        (path, true)
    );
    // The copy keeps at most the limit of the received bytes, not the whole value.
    assert_eq!(Raw::copy(&[b'a'; 5000], PATH_MAX).bytes.len(), PATH_MAX);
}

#[test]
fn a_cut_never_goes_through_a_percent_escape() {
    // 1022 plain bytes and a byte that needs three: it would end at 1025.
    let mut value = vec![b'a'; 1022];
    value.push(0x80);
    assert_eq!(text(&value, 1024), ("a".repeat(1022), true));
    // A received escape is held to the same rule.
    let mut value = vec![b'a'; 1022];
    value.extend_from_slice(b"%41");
    assert_eq!(text(&value, 1024), ("a".repeat(1022), true));
    // It fits exactly one byte later.
    let mut value = vec![b'a'; 1021];
    value.push(0x80);
    let (out, cut) = text(&value, 1024);
    assert_eq!((out.len(), cut), (1024, false));
    // The copy ended inside what may be an escape: nothing of it is written, and the field is cut.
    let mut value = vec![b'a'; 1022];
    value.extend_from_slice(b"%4");
    value.extend_from_slice(b"1zz");
    assert_eq!(text(&value, 1024), ("a".repeat(1022), true));
}

fn request(seen: Option<Seen>) -> Request {
    Request {
        id: "0123456789abcdef-ffffffffffffffff".to_string(),
        conn: u64::MAX,
        listener: 7,
        proto: "h2",
        tls: true,
        client: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        seen,
        class: "forwarded",
        status: 200,
        reason: "forwarded",
        ms: 12,
        upstream: Some(Arc::from("web")),
        server: Some("192.0.2.7:8080".parse().unwrap()),
        mode: Some("block"),
        generation: Some([0xab; 32]),
        rule: None,
        matched: Matched::NONE,
        body: Some(10),
        inspected: None,
        sent: 5,
    }
}

/// The rules that matched: these ids, the flag for more of them, the severity and the score.
fn matched(ids: &[i64], more: bool, severity: u8, score: i32) -> Matched {
    let mut all = [0; 16];
    all[..ids.len()].copy_from_slice(ids);
    Matched {
        count: ids.len() as u8,
        ids: all,
        more,
        severity,
        score,
    }
}

#[test]
fn a_request_record_has_its_fields_in_order_and_leaves_out_what_it_does_not_have() {
    let seen = Seen::of(b"GET", Some(b"Example.test"), b"/a b?q=\"1\"");
    let line = encode(
        SystemTime::UNIX_EPOCH,
        &Record::Request(Box::new(request(Some(seen)))),
    )
    .unwrap();
    assert_eq!(
        line,
        concat!(
            "{\"ts\":\"1970-01-01T00:00:00.000Z\",\"type\":\"request\",",
            "\"id\":\"0123456789abcdef-ffffffffffffffff\",\"conn\":18446744073709551615,\"listener\":7,",
            "\"proto\":\"h2\",\"tls\":true,\"client\":\"2001:db8::1\",",
            "\"method\":\"GET\",\"host\":\"Example.test\",\"path\":\"/a%20b\",",
            "\"class\":\"forwarded\",\"status\":200,\"reason\":\"forwarded\",\"ms\":12,",
            "\"upstream\":\"web\",\"server\":\"192.0.2.7:8080\",\"mode\":\"block\",",
            "\"generation\":\"abababababababab\",\"body\":10,\"sent\":5}"
        )
    );
    // A request whose head did not pass has no method, host or path; an address in its mapped form is written as v4.
    let mut bare = request(None);
    bare.client = IpAddr::V6(Ipv4Addr::new(203, 0, 113, 9).to_ipv6_mapped());
    bare.upstream = None;
    bare.server = None;
    bare.mode = None;
    bare.generation = None;
    bare.body = None;
    let line = encode(SystemTime::UNIX_EPOCH, &Record::Request(Box::new(bare))).unwrap();
    assert!(
        line.contains("\"client\":\"203.0.113.9\",\"class\":\"forwarded\""),
        "{line}"
    );
    for name in [
        "method",
        "host",
        "path",
        "cut",
        "upstream",
        "server",
        "mode",
        "generation",
        "rule",
        "rules",
        "rules_more",
        "severity",
        "score",
        "body",
        "inspected",
    ] {
        assert!(!line.contains(&format!("\"{name}\"")), "{name} in {line}");
    }
}

#[test]
fn the_rules_that_matched_come_after_the_rule_and_what_is_none_is_left_out() {
    let line = |rule, matched| {
        let mut r = request(None);
        (r.rule, r.matched) = (rule, matched);
        encode(SystemTime::UNIX_EPOCH, &Record::Request(Box::new(r))).unwrap()
    };
    // The ids, the severity and the score are written after the rule that decided, and before the size of the body.
    let two = matched(&[942100, 941100], false, 2, 10);
    let shown = line(Some(949110), two);
    let want = "\"rule\":949110,\"rules\":[942100,941100],\"severity\":2,\"score\":10,\"body\":10";
    assert!(shown.contains(want), "{shown}");
    // A list with more matches behind it says so, and only then.
    let sixteen: Vec<i64> = (1..=16).collect();
    let more = line(None, matched(&sixteen, true, 7, 80));
    assert!(
        more.contains("\"rules_more\":true,\"severity\":7,\"score\":80"),
        "{more}"
    );
    let full = line(None, matched(&sixteen, false, 7, 80));
    assert!(!full.contains("rules_more"), "{full}");
    // Severity 0 is a value; 255 is none. A score of 0 and of -1 are left out, one above 0 is not.
    assert!(line(None, matched(&[1], false, 0, 0)).contains("\"severity\":0,\"body\""));
    for none in [matched(&[], false, 255, 0), matched(&[], false, 255, -1)] {
        let bare = line(None, none);
        for name in ["rules", "rules_more", "severity", "score"] {
            assert!(!bare.contains(&format!("\"{name}\"")), "{name} in {bare}");
        }
    }
    assert!(line(None, matched(&[], false, 255, 1)).contains("\"score\":1,"));
}

#[test]
fn the_largest_request_record_is_a_json_line_under_the_limit() {
    // Every field at its limit, and every byte of the received text one that is escaped.
    let seen = Seen::of(&[0x80; 100], Some(&[0x01; 400]), &[0x7f; 3000]);
    let mut largest = request(Some(seen));
    largest.client = IpAddr::V6(Ipv6Addr::new(
        0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xfffe,
    ));
    // The longest name of an upstream group in the configuration.
    largest.upstream = Some(Arc::from("g".repeat(64).as_str()));
    largest.server = Some(
        "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe]:65535"
            .parse()
            .unwrap(),
    );
    largest.reason = "upstream failed while the body was sent on";
    largest.ms = u64::MAX;
    largest.rule = Some(i64::MIN);
    // The most ids, each of the most digits (a rule id is above 0), and the flag, a severity and a score.
    largest.matched = matched(&[i64::MAX; 16], true, 7, i32::MAX);
    largest.body = Some(u64::MAX);
    largest.inspected = Some(u64::MAX);
    largest.sent = u64::MAX;
    let line = encode(SystemTime::now(), &Record::Request(Box::new(largest))).unwrap();
    assert!(line.len() < RECORD_MAX, "{}", line.len());
    assert!(line.is_ascii());
    let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(parsed["cut"], serde_json::json!(["method", "host", "path"]));
    assert_eq!(parsed["rules"].as_array().map(Vec::len), Some(16));
    assert_eq!(parsed["rules"][15], i64::MAX);
    assert_eq!(parsed["rules_more"], true);
    assert_eq!(
        parsed["method"].as_str().unwrap().len(),
        METHOD_MAX - METHOD_MAX % 3
    );
    assert_eq!(
        parsed["path"].as_str().unwrap().len(),
        PATH_MAX - PATH_MAX % 3
    );
}

#[test]
fn a_connection_and_a_tunnel_record_have_their_fields_in_order() {
    let connection = Record::Connection(Connection {
        conn: 4,
        listener: 1,
        client: "203.0.113.9".parse().unwrap(),
        class: "closed",
        status: 0,
        reason: "h2 connection ended",
        ms: 30,
        streams: Some(5),
    });
    assert_eq!(
        encode(SystemTime::UNIX_EPOCH, &connection).unwrap(),
        concat!(
            "{\"ts\":\"1970-01-01T00:00:00.000Z\",\"type\":\"connection\",\"conn\":4,\"listener\":1,",
            "\"client\":\"203.0.113.9\",\"class\":\"closed\",\"status\":0,",
            "\"reason\":\"h2 connection ended\",\"ms\":30,\"streams\":5}"
        )
    );
    let tunnel = Record::Tunnel(Tunnel {
        id: "00-1".to_string(),
        conn: 4,
        client: "203.0.113.9".parse().unwrap(),
        upstream: Some(Arc::from("web")),
        server: Some("192.0.2.7:8080".parse().unwrap()),
        end: "closed",
        ms: 1500,
        to_upstream: 16,
        from_upstream: 17,
    });
    assert_eq!(
        encode(SystemTime::UNIX_EPOCH, &tunnel).unwrap(),
        concat!(
            "{\"ts\":\"1970-01-01T00:00:00.000Z\",\"type\":\"tunnel\",\"id\":\"00-1\",\"conn\":4,",
            "\"client\":\"203.0.113.9\",\"upstream\":\"web\",\"server\":\"192.0.2.7:8080\",",
            "\"end\":\"closed\",\"ms\":1500,\"to_upstream\":16,\"from_upstream\":17}"
        )
    );
}
