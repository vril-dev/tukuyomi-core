use super::*;

fn row(text: &str) -> Row {
    Row::of(text.as_bytes())
}

const REQUEST: &str = r#"{"ts":"2026-10-25T08:00:00.123Z","type":"request","id":"9f3a51c0e2b47d18-2a","conn":7,"listener":0,"proto":"h1","tls":false,"client":"::ffff:192.0.2.10","method":"GET","host":"example.test","path":"/a%20b","class":"blocked","status":403,"reason":"rule","ms":12,"upstream":"main","mode":"block","engine":"coraza","generation":"0123456789abcdef","rule":942100,"rules":[942100,942110],"severity":2,"score":5,"body":10,"sent":0}"#;

#[test]
fn a_request_gives_its_columns() {
    let row = row(REQUEST);
    assert_eq!(row.ts.as_deref(), Some("2026-10-25T08:00:00.123Z"));
    assert_eq!(row.kind, "request");
    assert_eq!(row.request_id.as_deref(), Some("9f3a51c0e2b47d18-2a"));
    assert_eq!(row.client.as_deref(), Some("192.0.2.10"));
    assert_eq!(row.method.as_deref(), Some("GET"));
    assert_eq!(row.host.as_deref(), Some("example.test"));
    assert_eq!(row.path.as_deref(), Some("/a%20b"));
    assert_eq!(row.class.as_deref(), Some("blocked"));
    assert_eq!(row.status, Some(403));
    assert_eq!(row.reason.as_deref(), Some("rule"));
    assert_eq!(row.ms, Some(12));
    assert_eq!(row.upstream.as_deref(), Some("main"));
    assert_eq!(row.mode.as_deref(), Some("block"));
    assert_eq!(row.engine.as_deref(), Some("coraza"));
    assert_eq!(row.generation.as_deref(), Some("0123456789abcdef"));
    assert_eq!(row.rule, Some(942100));
    assert_eq!(row.rules.as_deref(), Some("[942100,942110]"));
    assert_eq!(row.score, Some(5));
    assert_eq!(row.body, Some(10));
    assert_eq!(row.sent, Some(0));
    assert_eq!(row.raw, REQUEST);
    assert_eq!(row.line_hash.len(), 32);
}

#[test]
fn a_tunnel_keeps_the_number_of_its_request() {
    let row = row(
        r#"{"ts":"2026-10-25T08:00:00.123Z","type":"tunnel","id":"aa-1","conn":1,"client":"2001:db8::1","end":"closed","ms":5,"to_upstream":1,"from_upstream":2}"#,
    );
    assert_eq!(row.kind, "tunnel");
    assert_eq!(row.request_id.as_deref(), Some("aa-1"));
    assert_eq!(row.client.as_deref(), Some("2001:db8::1"));
    assert_eq!(row.ms, Some(5));
    assert_eq!(row.status, None);
}

#[test]
fn a_line_that_is_not_a_record_is_stored_with_its_text() {
    for text in ["not json", "[1,2]", "{\"type\":5}", ""] {
        let row = row(text);
        assert_eq!(row.kind, UNKNOWN, "{text}");
        assert_eq!(row.raw, text);
        assert_eq!(row.ts, None);
        assert_eq!(row.request_id, None);
    }
}

#[test]
fn an_object_of_another_type_keeps_its_time_only() {
    let row = row(r#"{"ts":"2026-10-25T08:00:00.123Z","type":"other","id":"x","status":200}"#);
    assert_eq!(row.kind, UNKNOWN);
    assert_eq!(row.ts.as_deref(), Some("2026-10-25T08:00:00.123Z"));
    assert_eq!(row.request_id, None);
    assert_eq!(row.status, None);
}

#[test]
fn a_value_that_would_stop_a_batch_is_left_out() {
    // A time the database would refuse, in each way it can be wrong.
    for ts in [
        "2026-13-25T08:00:00.123Z",
        "2026-02-30T08:00:00.123Z",
        "0000-01-01T00:00:00.000Z",
        "2026-10-25T24:00:00.123Z",
        "2026-10-25 08:00:00.123Z",
        "2026-10-25T08:00:00Z",
        "2026-10-25T08:00:00.123+09:00",
    ] {
        let row = row(&format!(r#"{{"ts":"{ts}","type":"line","line":"x"}}"#));
        assert_eq!(row.ts, None, "{ts}");
        assert_eq!(row.kind, "line");
    }
    assert!(timestamp("2024-02-29T23:59:59.999Z").is_some());
    assert!(timestamp("2023-02-29T00:00:00.000Z").is_none());
    let row = row(
        r#"{"type":"request","client":"not an address","status":99999999999,"ms":-1,"rule":1.5,"rules":[1,"2"],"score":2147483648,"id":7,"path":"/a\u0000b"}"#,
    );
    assert_eq!(row.client, None);
    assert_eq!(row.status, None);
    assert_eq!(row.ms, Some(-1));
    assert_eq!(row.rule, None);
    assert_eq!(row.rules, None);
    assert_eq!(row.score, None);
    assert_eq!(row.request_id, None);
    // A NUL cannot be in a text column.
    assert_eq!(row.path.as_deref(), Some("/a\u{fffd}b"));
}

#[test]
fn the_texts_that_have_a_limit_are_cut_at_it_and_the_line_stays_whole_in_raw() {
    // The limit itself stays, the first byte past it goes.
    for (key, max) in [
        ("id", ID_MAX),
        ("method", METHOD_MAX),
        ("host", HOST_MAX),
        ("path", PATH_MAX),
    ] {
        let at = |length: usize| {
            let line = format!(
                "{{\"type\":\"request\",\"{key}\":\"{}\"}}",
                "a".repeat(length)
            );
            let row = Row::of(line.as_bytes());
            let value = match key {
                "id" => row.request_id,
                "method" => row.method,
                "host" => row.host,
                _ => row.path,
            };
            (value.unwrap(), row.raw, line)
        };
        let (value, raw, line) = at(max);
        assert_eq!((value.len(), raw), (max, line), "{key}");
        let (value, raw, line) = at(max + 1);
        assert_eq!((value.len(), raw), (max, line), "{key}");
    }
    // A cut does not end inside a character: a two-byte character at the limit goes whole or not at all.
    let id = format!("{}\u{e9}", "a".repeat(ID_MAX - 1));
    let row = row(&format!("{{\"type\":\"request\",\"id\":\"{id}\"}}"));
    assert_eq!(
        row.request_id.as_deref(),
        Some("a".repeat(ID_MAX - 1).as_str())
    );
}

#[test]
fn the_hash_is_that_of_the_bytes() {
    let bytes = b"{\"type\":\"line\",\"line\":\"\xff\"}";
    let row = Row::of(bytes);
    assert_eq!(row.kind, UNKNOWN);
    assert!(row.raw.contains('\u{fffd}'));
    let hash: [u8; 32] = Sha256::digest(bytes).into();
    assert_eq!(row.line_hash, hash);
    assert_ne!(Row::of(b"a").line_hash, Row::of(b"b").line_hash);
    assert_eq!(Row::of(b"a").line_hash, Row::of(b"a").line_hash);
}
