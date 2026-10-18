use super::*;

fn route(host: Option<&str>, path: &str) -> Route {
    Route::new(host, path).unwrap_or_else(|e| panic!("{path}: {}", e.0))
}

fn table(list: &[(Option<&str>, &str)]) -> Routes {
    Routes::new(list.iter().map(|&(host, path)| route(host, path)).collect()).unwrap()
}

/// Whether a request for `target` with this `Host` is let through.
fn hit(routes: &Routes, host: &str, target: &str) -> bool {
    routes.matches(Some(host.as_bytes()), target.as_bytes())
}

fn refused(host: Option<&str>, path: &str) -> &'static str {
    Route::new(host, path).unwrap_err().0
}

#[test]
fn a_path_is_equal_or_below_a_route_that_ends_in_a_slash_and_the_query_is_not_looked_at() {
    let routes = table(&[(None, "/static/"), (None, "/admin")]);
    for target in [
        "/static/",
        "/static/a/b.css",
        "/static/x?q=1",
        "/static/?q=/x",
    ] {
        assert!(hit(&routes, "h", target), "{target}");
    }
    // Not `/static`, not `/staticx`, not another case, not a path that only holds the route inside.
    for target in [
        "/static",
        "/staticx",
        "/Static/a",
        "/other/static/",
        "/?x=/static/",
    ] {
        assert!(!hit(&routes, "h", target), "{target}");
    }
    // A route that does not end in a slash holds for that path only.
    assert!(hit(&routes, "h", "/admin"));
    assert!(hit(&routes, "h", "/admin?x=1"));
    for target in ["/admin/", "/admin/x", "/administrator"] {
        assert!(!hit(&routes, "h", target), "{target}");
    }
    assert!(!Routes::default().matches(Some(b"h"), b"/static/"));
}

#[test]
fn a_target_that_can_be_read_in_more_than_one_way_matches_no_route() {
    let routes = table(&[(None, "/static/")]);
    let ambiguous = [
        "/static/..%2fx",
        "/static/a%2Fb",
        "/static/%2e%2e/x",
        "/static/%2E/x",
        "/static/a%5cb",
        "/static/a%5Cb",
        "/static/a%00b",
        "/static/%252e%252e/x",
        "/static/a%25",
        "/static/../x",
        "/static/./x",
        "/static/a/..",
        "//static/x",
        "/static//x",
        "/static/a\\b",
        "/static/a;b",
    ];
    for target in ambiguous {
        assert!(!hit(&routes, "h", target), "{target}");
    }
    // Only the part before the `?` counts, and a name that holds dots is not a segment of dots.
    for target in [
        "/static/a?x=..%2f;\\//%252e",
        "/static/.hidden",
        "/static/a..b",
        "/static/a%41",
    ] {
        assert!(hit(&routes, "h", target), "{target}");
    }
}

#[test]
fn a_route_with_a_host_holds_for_that_host_in_any_case_and_for_no_other() {
    let routes = table(&[
        (Some("example.test:8080"), "/api/"),
        (Some("example.test"), "/health"),
    ]);
    for host in ["example.test:8080", "Example.TEST:8080"] {
        assert!(hit(&routes, host, "/api/x"), "{host}");
    }
    for host in [
        "example.test",
        "example.test:80",
        "xexample.test:8080",
        "example.test:8080 ",
    ] {
        assert!(!hit(&routes, host, "/api/x"), "{host}");
    }
    assert!(hit(&routes, "EXAMPLE.test", "/health"));
    assert!(!hit(&routes, "example.test.", "/health"));
    assert!(!routes.matches(None, b"/api/x"));
    // A route without a host holds for every host, and for a request that has none.
    let any = table(&[(None, "/s/")]);
    assert!(any.matches(None, b"/s/x"));
    assert!(hit(&any, "whatever.test", "/s/x"));
}

#[test]
fn a_path_is_checked_at_its_limits_and_for_what_it_holds() {
    let long = |n: usize| format!("/{}", "a".repeat(n - 1));
    let length = "a route path is not 2 to 255 bytes";
    assert!(Route::new(None, "/a").is_ok());
    assert!(Route::new(None, &long(255)).is_ok());
    assert_eq!(refused(None, &long(256)), length);
    assert_eq!(refused(None, ""), length);
    assert!(refused(None, "/").contains("/ alone"));
    assert_eq!(refused(None, "a/b"), "a route path does not start with /");
    assert!(Route::new(None, "/Az09-._~!$&'()*+,=:@/%4F").is_ok());
    for path in [
        "/a b", "/a?b", "/a#b", "/a\"b", "/a<b", "/a\\b", "/a;b", "/é", "/a\u{0}",
    ] {
        assert_eq!(
            refused(None, path),
            "a route path has a character that is not allowed",
            "{path:?}"
        );
    }
    for path in ["/a%", "/a%4", "/a%4g", "/a%g4", "/a%%41"] {
        assert_eq!(
            refused(None, path),
            "a % in a route path is not followed by two hexadecimal digits",
            "{path}"
        );
    }
    let ambiguous = [
        "/a/./b", "/a/../b", "/a/..", "/a/.", "/.", "/..", "/a//b", "//a", "/a%2e", "/a%2E",
        "/a%2f", "/a%2F", "/a%5c", "/a%5C", "/a%00", "/a%25", "/a%252e",
    ];
    for path in ambiguous {
        assert_eq!(
            refused(None, path),
            "a route path can be read in more than one way",
            "{path}"
        );
    }
    for path in ["/.hidden", "/a/..b", "/a/b.", "/a..b/"] {
        assert!(Route::new(None, path).is_ok(), "{path}");
    }
}

#[test]
fn a_host_is_checked_at_its_limits_and_for_what_it_holds() {
    assert!(Route::new(Some(&"a".repeat(253)), "/x").is_ok());
    let length = "a route host is not 1 to 253 bytes";
    assert_eq!(refused(Some(&"a".repeat(254)), "/x"), length);
    assert_eq!(refused(Some(""), "/x"), length);
    for host in ["a", "a.b-c.d1", "example.test:8080", "h:1", "h:65535"] {
        assert!(Route::new(Some(host), "/x").is_ok(), "{host}");
    }
    let bad = [
        "Example.test",
        "a_b",
        "a b",
        "a.",
        "a.:80",
        ":80",
        "a:",
        "a:0",
        "a:00",
        "a:080",
        "a:65536",
        "a:123456",
        "a:+80",
        "a:80:90",
        "[::1]",
        "é",
    ];
    for host in bad {
        assert_eq!(
            refused(Some(host), "/x"),
            "a route host is malformed",
            "{host}"
        );
    }
}

#[test]
fn a_table_has_at_most_256_routes_and_no_two_alike() {
    let many =
        |n: usize| -> Vec<Route> { (0..n).map(|i| route(None, &format!("/r{i}"))).collect() };
    assert_eq!(Routes::new(many(256)).unwrap().len(), 256);
    assert_eq!(
        Routes::new(many(257)).unwrap_err().0,
        "there are more than 256 routes"
    );
    let same = "two routes have the same host and path";
    let twice = vec![route(None, "/a"), route(None, "/a")];
    assert_eq!(Routes::new(twice).unwrap_err().0, same);
    let twice = vec![route(Some("h"), "/a"), route(Some("h"), "/a")];
    assert_eq!(Routes::new(twice).unwrap_err().0, same);
    // Another host, or none, makes another route.
    let apart = vec![
        route(None, "/a"),
        route(Some("h"), "/a"),
        route(Some("g"), "/a"),
    ];
    assert!(Routes::new(apart).is_ok());
}

#[test]
fn the_file_of_an_import_is_a_json_array_of_routes_and_the_order_is_kept() {
    let good = r#"[{"path":"/static/","action":"bypass"},{"host":"example.test","path":"/health","action":"bypass"}]"#;
    let routes = Routes::from_json(good.as_bytes()).unwrap();
    assert_eq!(
        routes,
        table(&[(None, "/static/"), (Some("example.test"), "/health")])
    );
    // A file may have white space and another order of keys: only the manifest has the one form.
    let loose = br#" [ {"action": "bypass", "path": "/a/"} ] "#;
    assert_eq!(Routes::from_json(loose).unwrap(), table(&[(None, "/a/")]));
    let bad = [
        "",
        "{}",
        "[]",
        "[1]",
        r#"[{"path":"/a/"}]"#,
        r#"[{"action":"bypass"}]"#,
        r#"[{"path":"/a/","action":"allow"}]"#,
        r#"[{"path":"/a/","action":"Bypass"}]"#,
        r#"[{"path":"/a/","action":"bypass","extra":1}]"#,
        r#"[{"path":"/a/","path":"/b/","action":"bypass"}]"#,
        r#"[{"path":1,"action":"bypass"}]"#,
        r#"[{"path":"","action":"bypass"}]"#,
        r#"[{"path":"/","action":"bypass"}]"#,
        r#"[{"path":"/a/../b","action":"bypass"}]"#,
        r#"[{"host":"H","path":"/a/","action":"bypass"}]"#,
        r#"[{"path":"/a/","action":"bypass"},{"path":"/a/","action":"bypass"}]"#,
    ];
    for text in bad {
        assert!(Routes::from_json(text.as_bytes()).is_err(), "{text}");
    }
    // 256 routes are read, and the 257th is refused before any of them is made.
    let list = |n: usize| -> String {
        let items: Vec<String> = (0..n)
            .map(|i| format!(r#"{{"path":"/r{i}","action":"bypass"}}"#))
            .collect();
        format!("[{}]", items.join(","))
    };
    assert_eq!(Routes::from_json(list(256).as_bytes()).unwrap().len(), 256);
    assert_eq!(
        Routes::from_json(list(257).as_bytes()).unwrap_err().0,
        "there are more than 256 routes"
    );
}
