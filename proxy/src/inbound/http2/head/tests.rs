use http::Request;

use super::*;

const LIM: Limits = Limits {
    max_head_bytes: 8192,
    max_body: 1 << 20,
};

/// The parts of a request as h2 makes them: `uri` has the scheme and the name in front of the path when the stream
/// has an `:authority`.
fn parts(method: &str, uri: &str, fields: &[(&str, &str)]) -> Parts {
    let mut request = Request::builder().method(method).uri(uri);
    for (name, value) in fields {
        request = request.header(*name, *value);
    }
    request.body(()).unwrap().into_parts().0
}

fn get(uri: &str, fields: &[(&str, &str)]) -> Result<Head, Reject> {
    build(&parts("GET", uri, fields), true, &LIM)
}

fn host_of(head: &Head) -> String {
    String::from_utf8(head.host().unwrap().to_vec()).unwrap()
}

#[test]
fn the_name_of_the_request_is_the_authority_and_a_host_field_may_only_say_the_same() {
    // The authority alone, the same name in a host field (the case of the letters does not matter), a host field
    // alone.
    for (uri, fields, want) in [
        ("https://a.example/x", &[][..], "a.example"),
        ("https://a.example:8443/x", &[][..], "a.example:8443"),
        (
            "https://A.example/x",
            &[("host", "a.EXAMPLE")][..],
            "A.example",
        ),
        ("/x", &[("host", "b.example")][..], "b.example"),
    ] {
        let head = get(uri, fields).unwrap_or_else(|e| panic!("{uri} {fields:?}: {e:?}"));
        assert_eq!(host_of(&head), want, "{uri} {fields:?}");
        assert_eq!(head.proto(), b"HTTP/2.0");
        assert_eq!(head.target(), b"/x");
    }
    // A host field that is not the authority, no name at all, two host fields, and a user information are 400.
    for (uri, fields) in [
        ("https://a.example/x", &[("host", "b.example")][..]),
        ("https://a.example/x", &[("host", "a.example:80")][..]),
        ("/x", &[][..]),
        ("/x", &[("host", "a.example"), ("host", "a.example")][..]),
        (
            "https://a.example/x",
            &[("host", "a.example"), ("host", "a.example")][..],
        ),
        ("https://user@a.example/x", &[][..]),
        ("https://user:pw@a.example/x", &[("host", "a.example")][..]),
    ] {
        assert_eq!(
            get(uri, fields).unwrap_err(),
            Reject::BadRequest,
            "{uri} {fields:?}"
        );
    }
}

#[test]
fn cookie_fields_are_one_line_and_the_other_fields_are_copied() {
    let head = get(
        "https://a.example/x",
        &[
            ("cookie", "a=1"),
            ("x-one", "1"),
            ("cookie", "b=2"),
            ("cookie", "c=3"),
            ("x-one", "2"),
        ],
    )
    .unwrap();
    let fields: Vec<(&[u8], &[u8])> = head.fields().collect();
    let cookies: Vec<&[u8]> = fields
        .iter()
        .filter(|(name, _)| *name == b"cookie")
        .map(|(_, value)| *value)
        .collect();
    assert_eq!(cookies, [&b"a=1; b=2; c=3"[..]]);
    let ones: Vec<&[u8]> = fields
        .iter()
        .filter(|(name, _)| *name == b"x-one")
        .map(|(_, value)| *value)
        .collect();
    assert_eq!(ones, [&b"1"[..], &b"2"[..]]);
}

#[test]
fn the_length_of_the_body_is_kept_and_a_body_of_unknown_length_is_chunked() {
    let json = [("content-type", "application/json")];
    let with_length = [json[0], ("content-length", "5")];
    let head = build(
        &parts("POST", "https://a.example/x", &with_length),
        false,
        &LIM,
    )
    .unwrap();
    assert_eq!((head.content_length(), head.chunked()), (Some(5), false));
    // The stream is not ended by its head and says no length: the body is read until its end.
    let head = build(&parts("POST", "https://a.example/x", &json), false, &LIM).unwrap();
    assert_eq!((head.content_length(), head.chunked()), (None, true));
    // The stream is ended by its head: there is no body.
    let head = build(&parts("POST", "https://a.example/x", &json), true, &LIM).unwrap();
    assert_eq!((head.content_length(), head.chunked()), (None, false));
    // The rules of every head hold: a body that is too long, or of a type that is not read, is refused before it
    // is read.
    let long = [json[0], ("content-length", "1048577")];
    assert_eq!(
        build(&parts("POST", "https://a.example/x", &long), false, &LIM).unwrap_err(),
        Reject::ContentTooLarge
    );
    let text = [("content-type", "text/plain"), ("content-length", "5")];
    assert_eq!(
        build(&parts("POST", "https://a.example/x", &text), false, &LIM).unwrap_err(),
        Reject::UnsupportedMedia
    );
    let twice = [json[0], ("content-length", "5"), ("content-length", "5")];
    assert_eq!(
        build(&parts("POST", "https://a.example/x", &twice), false, &LIM).unwrap_err(),
        Reject::BadRequest
    );
}

#[test]
fn a_connect_and_an_asterisk_are_refused_like_on_every_connection() {
    let connect = parts("CONNECT", "a.example:443", &[]);
    assert_eq!(build(&connect, true, &LIM).unwrap_err(), Reject::BadRequest);
    // The method is refused also when a path is there.
    let connect = parts("CONNECT", "https://a.example/x", &[]);
    assert_eq!(build(&connect, true, &LIM).unwrap_err(), Reject::BadRequest);
    // h2 gives `OPTIONS *` a `uri` with the asterisk as its path.
    let asterisk = Uri::builder()
        .scheme("https")
        .authority("a.example")
        .path_and_query("*")
        .build()
        .unwrap();
    let mut options = parts("OPTIONS", "/x", &[]);
    options.uri = asterisk;
    assert_eq!(build(&options, true, &LIM).unwrap_err(), Reject::BadRequest);
}

#[test]
fn a_head_is_refused_with_431_one_byte_over_the_size_and_passes_at_the_size() {
    let fields = [("x-a", "1234567890"), ("x-b", "abc")];
    let head = get("https://a.example/x", &fields).unwrap();
    let size = head.len;
    let at = Limits {
        max_head_bytes: size,
        ..LIM
    };
    assert!(build(&parts("GET", "https://a.example/x", &fields), true, &at).is_ok());
    let under = Limits {
        max_head_bytes: size - 1,
        ..LIM
    };
    assert_eq!(
        build(&parts("GET", "https://a.example/x", &fields), true, &under).unwrap_err(),
        Reject::FieldsTooLarge
    );
}

#[test]
fn the_upstream_is_sent_the_target_alone_without_the_scheme_and_the_name() {
    let head = get("https://a.example/p/q?x=1&y=%41", &[]).unwrap();
    let uri = upstream_uri(&head).unwrap();
    assert_eq!((uri.scheme(), uri.authority()), (None, None));
    assert_eq!(uri.to_string(), "/p/q?x=1&y=%41");
    // Two slashes are a path, not the start of a name.
    let head = get("https://a.example//evil.example/x", &[]).unwrap();
    let uri = upstream_uri(&head).unwrap();
    assert_eq!((uri.authority(), uri.path()), (None, "//evil.example/x"));
}
