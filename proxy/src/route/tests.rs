use super::*;

fn rule(host: Option<&str>, path: Option<&str>) -> Rule {
    Rule::forward(host, path).unwrap_or_else(|e| panic!("{host:?} {path:?}: {}", e.0))
}

/// A table whose targets are the positions of the rules.
fn table(rules: &[(Option<&str>, Option<&str>)]) -> Table<usize> {
    let entries = rules
        .iter()
        .enumerate()
        .map(|(i, &(host, path))| (rule(host, path), i))
        .collect();
    Table::new(entries).unwrap()
}

fn find(table: &Table<usize>, host: &str, target: &str) -> Option<usize> {
    table
        .find(Some(host.as_bytes()), target.as_bytes())
        .copied()
}

#[test]
fn a_path_is_exact_or_a_prefix_that_ends_in_a_slash_and_the_longest_prefix_wins() {
    let t = table(&[
        (None, Some("/static/")),
        (None, Some("/static/img/")),
        (None, Some("/static/logo")),
        (None, Some("/")),
    ]);
    // The boundary: `/static` and `/staticx` are not below `/static/`; they fall to the rule for `/`.
    assert_eq!(find(&t, "h", "/static/a.css"), Some(0));
    assert_eq!(find(&t, "h", "/static/"), Some(0));
    assert_eq!(find(&t, "h", "/static"), Some(3));
    assert_eq!(find(&t, "h", "/staticx"), Some(3));
    // The longest prefix, and the exact path over a prefix; a path that only starts like the exact one is not it.
    assert_eq!(find(&t, "h", "/static/img/x.png?w=1"), Some(1));
    assert_eq!(find(&t, "h", "/static/logo"), Some(2));
    assert_eq!(find(&t, "h", "/static/logo2"), Some(0));
    assert_eq!(find(&t, "h", "/static/logo/"), Some(0));
    // Without a rule for `/`, a path that nothing holds for has no target.
    let t = table(&[(None, Some("/static/"))]);
    assert_eq!(find(&t, "h", "/other"), None);
    assert_eq!(Table::<usize>::default().find(Some(b"h"), b"/"), None);
}

#[test]
fn a_rule_without_a_port_holds_for_every_port_and_one_with_a_port_for_that_port_only() {
    let t = table(&[
        (Some("example.test"), None),
        (Some("example.test:8080"), None),
    ]);
    assert_eq!(find(&t, "example.test", "/"), Some(0));
    assert_eq!(find(&t, "EXAMPLE.test:80", "/"), Some(0));
    assert_eq!(find(&t, "example.test:8080", "/"), Some(1));
    // Not a name with more in front or behind it, nor a Host that cannot be read.
    for host in [
        "xexample.test",
        "example.test:",
        "example.test:0",
        "example.test:65536",
        "example.test:08080",
        "example.test:80:80",
        "example.test ",
        "[::1]",
    ] {
        assert_eq!(find(&t, host, "/"), None, "{host}");
    }
    assert_eq!(t.find(None, b"/"), None);
    // A rule without a host holds for a Host that cannot be read, and for none.
    let any = table(&[(None, Some("/s/"))]);
    assert_eq!(find(&any, "a b", "/s/x"), Some(0));
    assert_eq!(any.find(None, b"/s/x"), Some(&0));
}

#[test]
fn a_wildcard_holds_for_one_label_or_more_and_a_name_is_stronger_than_a_wildcard() {
    let t = table(&[
        (Some("*.example.test"), None),
        (Some("*.api.example.test"), None),
        (Some("www.example.test"), None),
        (Some("*.example.test:8080"), None),
    ]);
    assert_eq!(find(&t, "a.example.test", "/"), Some(0));
    assert_eq!(find(&t, "a.b.EXAMPLE.test", "/"), Some(0));
    // A name before a wildcard, a longer wildcard before a shorter one, a port before none.
    assert_eq!(find(&t, "www.example.test", "/"), Some(2));
    assert_eq!(find(&t, "v1.api.example.test", "/"), Some(1));
    assert_eq!(find(&t, "a.example.test:8080", "/"), Some(3));
    // The wildcard needs a label in front of the rest.
    for host in [
        "example.test",
        "xexample.test",
        ".example.test",
        "example.test.",
    ] {
        assert_eq!(find(&t, host, "/"), None, "{host}");
    }
}

#[test]
fn one_trailing_dot_of_the_host_is_dropped_and_an_empty_label_holds_for_no_rule_with_a_host() {
    let t = table(&[
        (Some("app.test"), None),
        (Some("*.app.test"), None),
        (None, Some("/s/")),
    ]);
    // `app.test.` is `app.test`, with a port and under a wildcard as well.
    assert_eq!(find(&t, "app.test.", "/"), Some(0));
    assert_eq!(find(&t, "app.test.:80", "/"), Some(0));
    assert_eq!(find(&t, "APP.test.:8080", "/"), Some(0));
    assert_eq!(find(&t, "a.app.test.", "/"), Some(1));
    // The boundary is the second dot. An empty label at the end, the start or the middle is the same: the host
    // holds for no rule that has a host, and still for a rule that has none.
    for host in [
        "app.test..",
        ".app.test",
        "app..test",
        "..app.test",
        "a..app.test",
        "a.app.test..",
        ".",
        "..",
    ] {
        assert_eq!(find(&t, host, "/"), None, "{host}");
        assert_eq!(find(&t, host, "/s/x"), Some(2), "{host}");
    }
}

#[test]
fn the_host_decides_before_the_path() {
    let t = table(&[(None, Some("/api/")), (Some("a.test"), None)]);
    assert_eq!(find(&t, "a.test", "/api/x"), Some(1));
    assert_eq!(find(&t, "b.test", "/api/x"), Some(0));
    let t = table(&[
        (None, Some("/api/")),
        (Some("a.test"), Some("/api/")),
        (Some("a.test"), None),
    ]);
    assert_eq!(find(&t, "a.test", "/api/x"), Some(1));
    assert_eq!(find(&t, "a.test", "/other"), Some(2));
}

#[test]
fn a_target_that_can_be_read_in_more_than_one_way_holds_for_no_path_but_for_a_rule_without_one() {
    let t = table(&[
        (None, Some("/static/")),
        (Some("h.test"), None),
        (Some("other.test"), Some("/")),
    ]);
    for target in [
        "/static/..%2fx",
        "/static/%2e%2e/x",
        "/static/../x",
        "//static/x",
        "/static/a;b",
        "/static/a\\b",
        "/static/%252e/x",
    ] {
        assert_eq!(find(&t, "h.test", target), Some(1), "{target}");
        assert_eq!(find(&t, "g.test", target), None, "{target}");
        assert_eq!(find(&t, "other.test", target), None, "{target}");
    }
    // Only the part before the `?` counts.
    assert_eq!(find(&t, "g.test", "/static/a?x=..%2f;\\//"), Some(0));
}

#[test]
fn a_rule_that_chooses_an_upstream_may_be_wider_than_one_that_skips_the_inspection() {
    for path in ["/", "/a"] {
        assert!(Rule::forward(None, Some(path)).is_ok());
    }
    assert!(Rule::forward(None, None).is_ok());
    assert!(Rule::forward(Some("*.a.test:80"), None).is_ok());
    assert_eq!(
        Rule::bypass(None, "/").unwrap_err().0,
        "a route path of / alone would skip the inspection of every request"
    );
    assert_eq!(
        Rule::bypass(Some("*.a.test"), "/a/").unwrap_err().0,
        "a route host is malformed"
    );
    assert!(Rule::bypass(Some("a.test"), "/a/").is_ok());
    // The wildcard is `*.` and a name.
    for host in [
        "*",
        "*.",
        "*a.test",
        "**.a.test",
        "*.a.test.",
        "*.A.test",
        "a.*.test",
    ] {
        assert_eq!(
            Rule::forward(Some(host), None).unwrap_err().0,
            "a route host is malformed",
            "{host}"
        );
    }
}

#[test]
fn two_rules_with_the_same_host_and_path_are_refused() {
    let same = "two routes have the same host and path";
    let twice = vec![
        (rule(Some("h"), Some("/a")), 0),
        (rule(Some("h"), Some("/a")), 1),
    ];
    assert_eq!(Table::new(twice).unwrap_err().0, same);
    let twice = vec![(rule(None, None), 0), (rule(None, None), 1)];
    assert_eq!(Table::new(twice).unwrap_err().0, same);
    let apart = vec![
        (rule(None, Some("/a")), 0),
        (rule(Some("h"), Some("/a")), 1),
        (rule(Some("h"), None), 2),
        (rule(Some("h:80"), Some("/a")), 3),
    ];
    assert!(Table::new(apart).is_ok());
}
