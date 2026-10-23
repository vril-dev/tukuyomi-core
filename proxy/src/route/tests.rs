use super::path::{ambiguous, canonical};
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

fn canonical_of(path: &str) -> Option<String> {
    canonical(path.as_bytes()).map(|spelt| String::from_utf8(spelt.into_owned()).unwrap())
}

#[test]
fn the_canonical_form_writes_each_escape_one_way_and_keeps_the_case_of_letters() {
    // The escape of a byte that a rule path holds as it is becomes the byte; any other escape has uppercase digits.
    for (path, want) in [
        ("/priv%61te/x", "/private/x"),
        ("/%41%5a%7E/%40%2C%3A%2b", "/AZ~/@,:+"),
        ("/%e3%81%82/", "/%E3%81%82/"),
        ("/a%20b/%7b/%3b/%3F", "/a%20b/%7B/%3B/%3F"),
        // Already canonical, a `%` that is no escape, and the case of letters.
        ("/a/%20/%E3%81%82", "/a/%20/%E3%81%82"),
        ("/a/%zz/%4/50%", "/a/%zz/%4/50%"),
        ("/PRIV%61TE/x", "/PRIVaTE/x"),
        ("/", "/"),
        // A byte that a request holds as it is and a rule path only writes as an escape: one spelling for both.
        ("/a[b/", "/a%5Bb/"),
        ("/a%5bb/x", "/a%5Bb/x"),
        ("/a%5Bb/x", "/a%5Bb/x"),
        ("/\"[]^{|}", "/%22%5B%5D%5E%7B%7C%7D"),
        ("/{\"k\":1}|", "/%7B%22k%22:1%7D%7C"),
        // A `%` in front of such a byte stays, and the escape of the byte starts after it.
        ("/%[", "/%%5B"),
    ] {
        assert_eq!(canonical_of(path).as_deref(), Some(want), "{path}");
    }
    // A rule path is its own canonical form or it is not.
    for (path, want) in [
        ("/api/", true),
        ("/a%20b/", true),
        ("/%E3%81%82/", true),
        ("/%e3%81%82/", false),
        ("/%61dmin/", false),
        ("/%7E/", false),
        ("/a%5Bb/", true),
        ("/a%5bb/", false),
    ] {
        assert_eq!(rule(None, Some(path)).canonical(), want, "{path}");
    }
    assert!(rule(None, None).canonical());
}

#[test]
fn a_path_that_is_ambiguous_or_changes_again_when_respelled_has_no_canonical_form() {
    for path in [
        "//a", "/a/./b", "/a/../b", "/a;b", "/a\\b", "/%2e", "/%2F", "/%5c", "/%00", "/%25",
    ] {
        assert_eq!(canonical_of(path), None, "{path}");
        assert!(ambiguous(path.as_bytes()), "{path}");
    }
    // Not ambiguous as received, but the escapes after a `%` that is no escape make an ambiguous path or another
    // escape once they are replaced.
    for path in ["/%2%65", "/%%32e", "/%5%63", "/%0%30", "/%%34%31"] {
        assert!(!ambiguous(path.as_bytes()), "{path}");
        assert_eq!(canonical_of(path), None, "{path}");
    }
}

#[test]
fn the_canonical_form_of_a_path_that_is_not_ambiguous_is_not_ambiguous_and_is_its_own() {
    // Every string of up to 5 of these bytes, which can make the escapes of a dot, a slash and a percent sign, with
    // a `%` in front of digits that may or may not start one, and the bytes that are written as an escape.
    const RAW: &[u8] = b"\"[]^{|}";
    let bytes = [b"%2e56EF/.;".as_slice(), RAW].concat();
    let (mut seen, mut none) = (0, 0);
    for len in 0..=5 {
        for mut n in 0..bytes.len().pow(len) {
            let mut path = Vec::new();
            for _ in 0..len {
                path.push(bytes[n % bytes.len()]);
                n /= bytes.len();
            }
            seen += 1;
            match canonical(&path) {
                Some(spelt) => {
                    assert!(!ambiguous(&path), "{path:?}");
                    assert!(!ambiguous(&spelt), "{path:?}");
                    assert!(!spelt.iter().any(|b| RAW.contains(b)), "{path:?}");
                    assert_eq!(
                        canonical(&spelt).as_deref(),
                        Some(spelt.as_ref()),
                        "{path:?}"
                    );
                }
                None => none += 1,
            }
        }
    }
    assert!(none > 0 && none < seen);
}

fn could_hold(table: &Table<usize>, host: Option<&str>, target: &str) -> Vec<usize> {
    table
        .could_hold(host.map(str::as_bytes), target.as_bytes())
        .copied()
        .collect()
}

#[test]
fn a_request_could_be_taken_for_the_rules_of_its_path_as_received_and_in_canonical_form() {
    let t = table(&[
        (Some("a.test"), Some("/private/")),
        (None, Some("/pub/")),
        (None, Some("/")),
        (Some("a.test"), Some("/exact")),
        (None, Some("/a%5Bb/")),
    ]);
    // As received, each way gives its most exact rule: a plain `/pub/x` is `/pub/` and not `/`.
    assert_eq!(could_hold(&t, Some("a.test"), "/pub/x"), [1]);
    assert_eq!(
        could_hold(&t, Some("A.TEST:80"), "/private/x?a=%2e%2e/"),
        [0]
    );
    assert_eq!(could_hold(&t, Some("b.test"), "/private/x"), [2]);
    // Another spelling of a path meets the rule of the path it spells.
    assert_eq!(could_hold(&t, Some("a.test"), "/priv%61te/x"), [0, 2]);
    assert_eq!(could_hold(&t, Some("a.test"), "/%70ub/x"), [1, 2]);
    // A path that ends before the `/` of a prefix: `/private` meets `/private/`.
    assert_eq!(could_hold(&t, Some("a.test"), "/private"), [0, 2]);
    assert_eq!(could_hold(&t, Some("a.test"), "/private?x=1"), [0, 2]);
    // A path that a rule is for itself is not taken for the path with a `/` after it: `/exact` meets its own rule
    // only, but `/exac%74`, which the rule for `/` holds for as received, meets `/exact` and the rule for `/`.
    assert_eq!(could_hold(&t, Some("a.test"), "/exact"), [3]);
    assert_eq!(could_hold(&t, Some("a.test"), "/exact?x=1"), [3]);
    assert_eq!(could_hold(&t, Some("a.test"), "/exac%74"), [2, 3]);
    assert_eq!(could_hold(&t, Some("a.test"), "/exact/x"), [2]);
    // A byte that a rule path writes as an escape meets the rule whether a request writes the byte or its escape.
    assert_eq!(could_hold(&t, Some("a.test"), "/a%5Bb/x"), [4]);
    assert_eq!(could_hold(&t, Some("a.test"), "/a[b/x"), [2, 4]);
    assert_eq!(could_hold(&t, Some("a.test"), "/a%5bb/x"), [2, 4]);
    // Upper and lower case letters are different paths.
    assert_eq!(could_hold(&t, Some("a.test"), "/PRIV%61TE/x"), [2]);
    // A table without a rule that holds has none.
    let t = table(&[(Some("a.test"), Some("/private/"))]);
    assert!(could_hold(&t, Some("a.test"), "/other").is_empty());
    assert!(could_hold(&t, Some("b.test"), "/private/x").is_empty());
}

#[test]
fn a_request_that_cannot_be_told_by_its_path_could_be_taken_for_every_rule_its_host_holds_for() {
    let t = table(&[
        (Some("a.test"), Some("/private/")),
        (Some("b.test"), None),
        (None, Some("/pub/")),
        (Some("*.c.test"), Some("/x")),
    ]);
    // An ambiguous path, or one with no canonical form: the host decides and the path does not.
    assert_eq!(could_hold(&t, Some("a.test"), "/private/./x"), [0, 2]);
    assert_eq!(could_hold(&t, Some("b.test"), "//x"), [1, 2]);
    assert_eq!(could_hold(&t, Some("d.c.test"), "/a/./b"), [2, 3]);
    assert_eq!(could_hold(&t, Some("b.test"), "/%2%65"), [1, 2]);
    // A `Host` that cannot be read could be any: every rule, whatever the path.
    for host in [None, Some("a..test"), Some("a b")] {
        for target in ["/private/x", "/other", "/priv%61te/x", "//x"] {
            assert_eq!(
                could_hold(&t, host, target),
                [0, 1, 2, 3],
                "{host:?} {target}"
            );
        }
    }
}
