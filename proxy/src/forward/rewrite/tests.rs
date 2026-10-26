use http::HeaderName;

use super::*;

fn strings(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_string()).collect()
}

fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
    list.iter()
        .map(|(n, v)| ((*n).to_string(), (*v).to_string()))
        .collect()
}

fn query(remove: &[&str], prefixes: &[&str], set: &[(&str, &str)], add: &[(&str, &str)]) -> Query {
    Query::new(strings(remove), strings(prefixes), pairs(set), pairs(add)).unwrap()
}

fn of_query(query: Query) -> Rewrite {
    Rewrite::new(
        None,
        None,
        None,
        query,
        Headers::default(),
        Headers::default(),
    )
    .unwrap()
}

fn of_path(route: &str, to: &str) -> Rewrite {
    Rewrite::new(
        Some(route),
        None,
        Some(to),
        Query::default(),
        Headers::default(),
        Headers::default(),
    )
    .unwrap()
}

fn fields(list: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in list {
        map.append(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    map
}

fn values(map: &HeaderMap, name: &str) -> Vec<String> {
    map.get_all(name)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect()
}

/// The target the upstream gets for the target `received`.
fn sent(rewrite: &Rewrite, received: &str) -> String {
    let (_, uri) = rewrite
        .request(HeaderMap::new(), received.parse().unwrap())
        .unwrap();
    uri.to_string()
}

// ---- the path ----

#[test]
fn a_prefix_path_is_replaced_and_the_rest_of_the_target_is_kept_byte_for_byte() {
    let rewrite = of_path("/api/", "/v2/");
    for (received, want) in [
        ("/api/a/b?x=1&&y=%41+z;w", "/v2/a/b?x=1&&y=%41+z;w"),
        ("/api/", "/v2/"),
        ("/api/?q", "/v2/?q"),
        ("/api/a%41b/c", "/v2/a%41b/c"),
    ] {
        assert_eq!(sent(&rewrite, received), want);
    }
    assert_eq!(sent(&of_path("/", "/v2/"), "/x?y"), "/v2/x?y");
    // A target that the route does not hold for is not sent at all.
    for received in ["/apix", "/api", "/other/api/"] {
        let failed = rewrite.request(HeaderMap::new(), received.parse().unwrap());
        assert!(failed.is_err(), "{received}");
    }
}

#[test]
fn an_exact_path_is_replaced_and_the_query_is_kept() {
    let rewrite = of_path("/old", "/new/x");
    assert_eq!(sent(&rewrite, "/old?a=1&b"), "/new/x?a=1&b");
    assert_eq!(sent(&rewrite, "/old"), "/new/x");
    assert!(
        rewrite
            .request(HeaderMap::new(), "/old/".parse().unwrap())
            .is_err()
    );
}

#[test]
fn a_path_edit_needs_a_route_path_and_a_replacement_that_fits_it() {
    let make = |route: Option<&str>, to: &str| {
        Rewrite::new(
            route,
            None,
            Some(to),
            Query::default(),
            Headers::default(),
            Headers::default(),
        )
    };
    assert!(make(Some("/api/"), "/v2/").is_ok());
    assert!(make(Some("/api"), "/v2").is_ok());
    assert!(make(Some("/api"), "/v2/").is_ok());
    assert!(make(None, "/v2/").is_err());
    // A route path that ends in a slash needs a replacement that does too.
    assert!(make(Some("/api/"), "/v2").is_err());
    for to in ["", "v2/", "/a/../b/", "/a//b/", "/a b/", "/%2e/"] {
        assert!(make(Some("/api/"), to).is_err(), "{to:?}");
    }
}

#[test]
fn the_host_is_a_name_and_a_port_without_a_wildcard_and_replaces_the_one_of_the_request() {
    let make = |host: &str| {
        Rewrite::new(
            None,
            Some(host),
            None,
            Query::default(),
            Headers::default(),
            Headers::default(),
        )
    };
    for good in ["inner.test", "inner.test:8080", "a"] {
        assert!(make(good).is_ok(), "{good}");
    }
    for bad in [
        "",
        "*.test",
        "Inner.test",
        "inner.test:0",
        "inner.test:08",
        "inner.test:65536",
        "inner..test",
        "inner.test.",
        "a b",
    ] {
        assert!(make(bad).is_err(), "{bad:?}");
    }
    let rewrite = make("inner.test:8080").unwrap();
    for before in [
        fields(&[("host", "app.test"), ("x-a", "1")]),
        fields(&[("x-a", "1")]),
    ] {
        let (after, uri) = rewrite.request(before, "/p?q".parse().unwrap()).unwrap();
        assert_eq!(values(&after, "host"), ["inner.test:8080"]);
        assert_eq!(values(&after, "x-a"), ["1"]);
        assert_eq!(uri.to_string(), "/p?q");
    }
}

// ---- the query ----

#[test]
fn a_name_written_with_escapes_is_taken_out_and_the_other_items_keep_their_bytes_and_order() {
    let rewrite = of_query(query(&["a"], &[], &[], &[]));
    // `%61` is `a` and so is `A`; `a+b` is the name `a b`; a bad escape stays as it is.
    assert_eq!(
        sent(&rewrite, "/p?%61=1&b=%7e&&c&A=2&a+b=3&a%zz=4&a=5"),
        "/p?b=%7e&&c&a+b=3&a%zz=4"
    );
    assert_eq!(
        sent(&of_query(query(&["A"], &[], &[], &[])), "/p?%41=1&k"),
        "/p?k"
    );
    // Only `&` separates items: `a=1;b=2` is one item, named `a`, and `b=1;a=2` one named `b`.
    assert_eq!(sent(&rewrite, "/p?a=1;b=2&c"), "/p?c");
    assert_eq!(sent(&rewrite, "/p?b=1;a=2"), "/p?b=1;a=2");
}

#[test]
fn a_name_that_starts_with_a_listed_beginning_is_taken_out() {
    let rewrite = of_query(query(&[], &["utm_"], &[], &[]));
    // The case of a letter does not matter, and a name that is only the beginning without its last byte stays.
    assert_eq!(
        sent(
            &rewrite,
            "/p?utm_source=a&utm_x&keep=1&Utm_y=2&utm%5fz=3&utm=4"
        ),
        "/p?keep=1&utm=4"
    );
}

#[test]
fn the_case_of_a_name_does_not_matter_and_a_name_with_a_bracket_after_it_is_the_same_name() {
    let rewrite = of_query(query(&["debug"], &[], &[], &[]));
    // Taken out: another case, an array of the name (also with the brackets in escapes), and the name itself.
    assert_eq!(
        sent(
            &rewrite,
            "/p?Debug=1&debug[]=1&DEBUG[x]=1&%64ebug%5B%5D=1&debug&k=1"
        ),
        "/p?k=1"
    );
    // Kept: a longer name, a bracket in front of it, a name that holds it, a shorter name.
    let kept = "/p?debugx=1&[debug]=1&x_debug=1&debu=1";
    assert_eq!(sent(&rewrite, kept), kept);
    // The beginnings and the names of `set` do not care about the case either, and neither about a bracket.
    let rewrite = of_query(query(&[], &["utm_"], &[("Src", "edge")], &[]));
    assert_eq!(
        sent(&rewrite, "/p?UTM_x=1&Utm_y[]=2&src=1&SRC[]=2&k"),
        "/p?k&Src=edge"
    );
    // A `?` that ends the target has no items, so what is put does not follow an empty item.
    let rewrite = of_query(query(&[], &[], &[], &[("src", "edge")]));
    assert_eq!(sent(&rewrite, "/x?"), "/x?src=edge");
}

#[test]
fn set_takes_out_the_old_items_and_both_set_and_add_put_theirs_at_the_end_in_that_order() {
    let rewrite = of_query(query(
        &[],
        &[],
        &[("s", "new")],
        &[("k", "v1"), ("k2", "v2")],
    ));
    assert_eq!(
        sent(&rewrite, "/p?s=old&t=1&s=older"),
        "/p?t=1&s=new&k=v1&k2=v2"
    );
    assert_eq!(sent(&rewrite, "/p"), "/p?s=new&k=v1&k2=v2");
    // A `?` that ends the target has no items.
    assert_eq!(sent(&rewrite, "/p?"), "/p?s=new&k=v1&k2=v2");
}

#[test]
fn the_question_mark_goes_when_every_item_goes_and_nothing_is_put_and_stays_otherwise() {
    let rewrite = of_query(query(&["a"], &[], &[], &[]));
    assert_eq!(sent(&rewrite, "/p?a=1&a=2"), "/p");
    let rewrite = of_query(query(&["a"], &[], &[], &[("k", "v")]));
    assert_eq!(sent(&rewrite, "/p?a=1&a=2"), "/p?k=v");
    // Nothing taken out and nothing put: the target is as it was.
    let rewrite = of_query(query(&["z"], &["zz"], &[], &[]));
    for received in ["/p", "/p?", "/p?a=1", "/p?a=1&&b"] {
        assert_eq!(sent(&rewrite, received), received);
    }
}

#[test]
fn a_target_that_the_edits_make_longer_than_a_target_may_be_fails_the_request() {
    let long = format!("/{}", "a".repeat(limits::URI - 11));
    let with = |n: usize| of_query(query(&[], &[], &[], &[("k", &"v".repeat(n))]));
    // The target gets `?k=` and the value: this fills the limit exactly, and one byte more does not fit.
    assert_eq!(sent(&with(7), &long).len(), limits::URI);
    let failed = with(8).request(HeaderMap::new(), long.parse().unwrap());
    assert!(failed.is_err());
}

#[test]
fn query_edits_are_checked_at_their_limits_and_one_past() {
    let make = |remove: Vec<String>, prefixes: Vec<String>, set: Vec<(String, String)>| {
        Query::new(remove, prefixes, set, Vec::new())
    };
    let names = |n: usize| (0..n).map(|i| format!("n{i}")).collect::<Vec<_>>();
    // 32 items in all, then 33.
    assert!(make(names(32), vec![], vec![]).is_ok());
    assert!(make(names(33), vec![], vec![]).is_err());
    assert!(make(names(16), names(16), vec![]).is_ok());
    assert!(make(names(16), names(16), pairs(&[("x", "1")])).is_err());
    // A name is 1 to 256 bytes of letters, digits and - . _ ~.
    assert!(make(vec!["a".repeat(256)], vec![], vec![]).is_ok());
    assert!(make(vec!["a".repeat(257)], vec![], vec![]).is_err());
    assert!(make(vec!["A-b.c_d~9".into()], vec![], vec![]).is_ok());
    for bad in ["", "a&b", "a=b", "a+b", "a b", "a%41", "a#", "é"] {
        assert!(make(vec![bad.into()], vec![], vec![]).is_err(), "{bad:?}");
        assert!(make(vec![], vec![bad.into()], vec![]).is_err(), "{bad:?}");
    }
    // A value is 0 to 4096 bytes without & = + # or a blank, and every % has two hexadecimal digits after it.
    let value = |v: &str| make(vec![], vec![], pairs(&[("k", v)])).is_ok();
    assert!(value(""));
    assert!(value(&"v".repeat(4096)));
    assert!(!value(&"v".repeat(4097)));
    assert!(value("a-b._~!$'()*,:@/?%41%aF"));
    for bad in [
        "%", "%4", "%zz", "%4g", "a&b", "a=b", "a+b", "a#b", "a b", "a\r\nb", "é",
    ] {
        assert!(!value(bad), "{bad:?}");
    }
    // A name is taken by one of remove, set and add, once.
    assert!(Query::new(strings(&["a"]), vec![], pairs(&[("a", "1")]), vec![]).is_err());
    assert!(Query::new(vec![], vec![], pairs(&[("a", "1")]), pairs(&[("a", "2")])).is_err());
    assert!(Query::new(strings(&["a", "a"]), vec![], vec![], vec![]).is_err());
    // The case of a letter does not make another name.
    assert!(Query::new(strings(&["a"]), vec![], pairs(&[("A", "1")]), vec![]).is_err());
    assert!(Query::new(strings(&["a"]), strings(&["a"]), vec![], vec![]).is_ok());
}

// ---- the fields ----

#[test]
fn request_fields_are_taken_out_set_and_added_in_that_order_and_the_response_the_same_way() {
    let request = Headers::request(
        strings(&["c"]),
        pairs(&[("a", "S")]),
        pairs(&[("e", "new"), ("f", "1")]),
    )
    .unwrap();
    let response = Headers::response(
        strings(&["Server"]),
        vec![],
        pairs(&[("X-Frame-Options", "DENY")]),
    )
    .unwrap();
    let rewrite = Rewrite::new(None, None, None, Query::default(), request, response).unwrap();
    let before = fields(&[("a", "1"), ("a", "2"), ("b", "x"), ("c", "y"), ("e", "old")]);
    let (after, uri) = rewrite.request(before, "/p?q=1".parse().unwrap()).unwrap();
    assert_eq!(values(&after, "a"), ["S"]);
    assert_eq!(values(&after, "b"), ["x"]);
    assert!(after.get("c").is_none());
    assert_eq!(values(&after, "e"), ["old", "new"]);
    assert_eq!(values(&after, "f"), ["1"]);
    assert_eq!(uri.to_string(), "/p?q=1");

    let mut head = fields(&[("server", "up"), ("x-keep", "k")]);
    rewrite.respond(&mut head);
    assert!(head.get("server").is_none());
    assert_eq!(values(&head, "x-keep"), ["k"]);
    assert_eq!(values(&head, "x-frame-options"), ["DENY"]);
}

#[test]
fn a_field_the_proxy_owns_cannot_be_edited_in_remove_set_or_add() {
    let request = |name: &str| {
        [
            Headers::request(strings(&[name]), vec![], vec![]),
            Headers::request(vec![], pairs(&[(name, "v")]), vec![]),
            Headers::request(vec![], vec![], pairs(&[(name, "v")])),
        ]
    };
    for name in [
        "Host",
        "x-forwarded-for",
        "X-Forwarded-Host",
        "X-Forwarded-Proto",
        "X-Request-ID",
        "X-Real-IP",
        "Forwarded",
        "CF-Connecting-IP",
        "Content-Length",
        "Content-Type",
        "Content-Encoding",
        "Expect",
        "Connection",
        "Transfer-Encoding",
        "Upgrade",
        "TE",
        "Proxy-Authorization",
        "x_real",
    ] {
        for made in request(name) {
            assert!(made.is_err(), "{name}");
        }
    }
    for name in ["Cookie", "Authorization", "X-App"] {
        for made in request(name) {
            assert!(made.is_ok(), "{name}");
        }
    }
    let response = |name: &str| {
        [
            Headers::response(strings(&[name]), vec![], vec![]),
            Headers::response(vec![], pairs(&[(name, "v")]), vec![]),
            Headers::response(vec![], vec![], pairs(&[(name, "v")])),
        ]
    };
    for name in [
        "Set-Cookie",
        "X-Request-ID",
        "Content-Length",
        "Content-Type",
        "Content-Encoding",
        "Content-Range",
        "Connection",
        "Keep-Alive",
        "Transfer-Encoding",
        "Proxy-Authenticate",
        "Upgrade",
        "Trailer",
        "TE",
    ] {
        for made in response(name) {
            assert!(made.is_err(), "{name}");
        }
    }
    for name in ["Server", "X-Frame-Options", "Cache-Control", "X_App"] {
        for made in response(name) {
            assert!(made.is_ok(), "{name}");
        }
    }
}

#[test]
fn a_field_value_is_visible_ascii_with_blanks_inside_and_at_most_4096_bytes() {
    let one = |v: &str| Headers::request(vec![], pairs(&[("x-a", v)]), vec![]);
    for good in ["", "v", "a b\tc", &"v".repeat(4096)] {
        assert!(one(good).is_ok(), "{good:.20?}");
    }
    for bad in [
        "a\r\nb: c",
        "a\nb",
        "a\rb",
        "a\0b",
        "é",
        "\u{7f}",
        " a",
        "a ",
        "\ta",
        "a\t",
        &"v".repeat(4097),
    ] {
        assert!(one(bad).is_err(), "{bad:.20?}");
    }
}

#[test]
fn a_field_name_is_1_to_256_name_characters_taken_once_and_at_most_32_items_are_edited() {
    let add = |name: &str| Headers::request(vec![], vec![], pairs(&[(name, "v")]));
    assert!(add(&"x".repeat(256)).is_ok());
    for bad in [&"x".repeat(257), "", "a b", "a:b", "a\r\nb", "é"] {
        assert!(add(bad).is_err(), "{bad:.20?}");
    }
    // The same name twice, in any case, in one list or in two.
    assert!(Headers::request(strings(&["X-A"]), pairs(&[("x-a", "1")]), vec![]).is_err());
    assert!(Headers::request(vec![], pairs(&[("x-a", "1")]), pairs(&[("X-A", "2")])).is_err());
    assert!(Headers::request(strings(&["x-a", "X-A"]), vec![], vec![]).is_err());
    let items = |n: usize| {
        (0..n)
            .map(|i| (format!("x-{i}"), "v".to_string()))
            .collect::<Vec<_>>()
    };
    assert!(Headers::request(vec![], vec![], items(32)).is_ok());
    assert!(Headers::request(vec![], vec![], items(33)).is_err());
}
