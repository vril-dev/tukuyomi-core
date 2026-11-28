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

/// A rule with a path (or none) and a priority.
fn by_path(host: Option<&str>, path: Option<&str>, priority: i64) -> Rule {
    Rule::forward_with(host, path, None, priority)
        .unwrap_or_else(|e| panic!("{host:?} {path:?} {priority}: {}", e.0))
}

/// A rule with a path regex and a priority.
fn by_regex(host: Option<&str>, regex: &str, priority: i64) -> Rule {
    Rule::forward_with(host, None, Some(regex), priority)
        .unwrap_or_else(|e| panic!("{host:?} {regex:?} {priority}: {}", e.0))
}

/// A table of these rules, whose targets are their positions.
fn table_of(rules: Vec<Rule>) -> Table<usize> {
    let entries = rules.into_iter().enumerate().map(|(i, r)| (r, i));
    Table::new(entries.collect()).unwrap()
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

#[test]
fn a_path_regex_is_matched_anywhere_in_the_path_as_received_and_not_in_the_query() {
    let t = table_of(vec![
        by_regex(None, "^/api/v[0-9]+/", 0),
        by_regex(None, r"/files/.*\.pdf$", 0),
        by_regex(None, "(?i)^/Doc/", 0),
        by_path(None, Some("/"), 0),
    ]);
    assert_eq!(find(&t, "h", "/api/v2/x"), Some(0));
    assert_eq!(find(&t, "h", "/api/vx/x"), Some(3));
    // An expression that is not anchored holds in the middle of the path, one that is anchored does not.
    assert_eq!(find(&t, "h", "/a/files/b/c.pdf"), Some(1));
    assert_eq!(find(&t, "h", "/x/api/v2/"), Some(3));
    // The query is not looked at, and `$` is the end of the path: a path with a `/` after it is another one.
    assert_eq!(find(&t, "h", "/files/c.pdf?x=1"), Some(1));
    assert_eq!(find(&t, "h", "/files/c?x=.pdf"), Some(3));
    assert_eq!(find(&t, "h", "/files/c.pdf/"), Some(3));
    // The case of letters counts, unless the expression says it does not.
    assert_eq!(find(&t, "h", "/API/v2/x"), Some(3));
    assert_eq!(find(&t, "h", "/doc/x"), Some(2));
}

#[test]
fn a_path_regex_holds_for_no_target_that_can_be_read_in_more_than_one_way() {
    let t = table_of(vec![
        by_regex(None, "admin", 0),
        by_path(Some("h.test"), None, 0),
    ]);
    assert_eq!(find(&t, "g.test", "/admin/x"), Some(0));
    for target in [
        "/admin/../x",
        "/a/%2e%2e/admin",
        "//admin",
        "/admin;x",
        "/admin%2Fx",
        "/admin\\x",
        "/%252e/admin",
    ] {
        assert_eq!(find(&t, "g.test", target), None, "{target}");
        assert_eq!(find(&t, "h.test", target), Some(1), "{target}");
    }
    // Only the part before the `?` counts.
    assert_eq!(find(&t, "g.test", "/admin?x=..%2f;\\//"), Some(0));
}

#[test]
fn the_host_decides_first_then_the_smaller_priority_then_the_kind_of_path() {
    // A rule with a host holds before one without, whatever their priorities.
    let t = table_of(vec![
        by_path(None, Some("/"), -1000),
        by_path(Some("a.test"), Some("/"), 1000),
    ]);
    assert_eq!(find(&t, "a.test", "/x"), Some(1));
    assert_eq!(find(&t, "b.test", "/x"), Some(0));
    // In a host the smaller priority is first, whatever the path: also for a rule that has no path.
    let t = table_of(vec![
        by_path(None, Some("/x"), 0),
        by_path(None, Some("/"), -1),
    ]);
    assert_eq!(find(&t, "h", "/x"), Some(1));
    let t = table_of(vec![
        by_path(None, Some("/x"), 1),
        by_path(None, Some("/"), 2),
    ]);
    assert_eq!(find(&t, "h", "/x"), Some(0));
    let t = table_of(vec![
        by_path(Some("h"), None, -1),
        by_path(Some("h"), Some("/x"), 0),
    ]);
    assert_eq!(find(&t, "h", "/x"), Some(0));
    // With the same priority: the path itself, then a path regex, then a prefix (whatever its length).
    let t = table_of(vec![
        by_path(None, Some("/a/b/"), 0),
        by_regex(None, "^/a/b", 0),
        by_path(None, Some("/a/bc"), 0),
    ]);
    assert_eq!(find(&t, "h", "/a/bc"), Some(2));
    assert_eq!(find(&t, "h", "/a/bd"), Some(1));
    assert_eq!(find(&t, "h", "/a/b/c"), Some(1));
    // A priority above that of a prefix puts the path regex after it.
    let t = table_of(vec![
        by_path(None, Some("/a/"), 0),
        by_regex(None, "^/a", 1),
    ]);
    assert_eq!(find(&t, "h", "/a/x"), Some(0));
    // Of two path regexes with the same host and priority, the one that was given first.
    for (first, second) in [("^/a", "^/a/b"), ("^/a/b", "^/a")] {
        let t = table_of(vec![by_regex(None, first, 0), by_regex(None, second, 0)]);
        assert_eq!(find(&t, "h", "/a/b"), Some(0), "{first} {second}");
    }
}

#[test]
fn two_rules_with_the_same_host_and_path_or_path_regex_are_refused_whatever_their_priority() {
    let same = "two routes have the same host and path";
    let refused = |rules: Vec<Rule>| {
        let entries = rules.into_iter().enumerate().map(|(i, r)| (r, i));
        Table::new(entries.collect()).unwrap_err().0
    };
    let twice = vec![by_regex(Some("h"), "^/a", 0), by_regex(Some("h"), "^/a", 5)];
    assert_eq!(refused(twice), same);
    let twice = vec![
        by_path(None, Some("/a/"), 0),
        by_path(None, Some("/a/"), -3),
    ];
    assert_eq!(refused(twice), same);
    // A path and a path regex of the same text, a path regex of another text, and the same one at another host.
    let apart = vec![
        by_path(None, Some("/a/"), 0),
        by_regex(None, "/a/", 0),
        by_regex(None, "/a", 0),
        by_regex(Some("h"), "/a/", 0),
    ];
    assert!(Table::new(apart.into_iter().map(|r| (r, 0)).collect()).is_ok());
}

#[test]
fn a_path_regex_has_1_to_255_visible_ascii_bytes_and_is_made_into_a_dfa_within_limits() {
    let refused = |regex: &str| {
        Rule::forward_with(None, None, Some(regex), 0)
            .unwrap_err()
            .0
    };
    let length = "a route path regex is not 1 to 255 bytes";
    assert_eq!(refused(""), length);
    assert!(Rule::forward_with(None, None, Some(&"a".repeat(255)), 0).is_ok());
    assert_eq!(refused(&"a".repeat(256)), length);
    let chars = "a route path regex has a character that is not allowed";
    for bad in ["a b", "a\u{7f}"] {
        assert_eq!(refused(bad), chars, "{bad:?}");
    }
    // The syntax stage: an error of syntax, a construct that is not in the syntax (look-around), the class `\p`, and
    // Unicode switched on by its flag, in each kind of place that a flag may be (`(?-u)` and `(?i-u)` switch it off,
    // and are taken).
    let invalid = "a route path regex is not a valid regular expression";
    for bad in ["(", "(?=a)", r"\pL", r"(?u)\w", r"(?iu)a", r"a(?u:b)"] {
        assert_eq!(refused(bad), invalid, "{bad}");
    }
    for good in [r"(?-u)\w", r"(?i-u)a", r"(?-u:\w)"] {
        assert!(
            Rule::forward_with(None, None, Some(good), 0).is_ok(),
            "{good}"
        );
    }
    // The stages that make the NFA and the DFA: a short text whose NFA is over its limit, and one whose DFA is (the
    // last 13 bytes of a path that are told apart, 2^13 states).
    let large = "a route path regex is too large";
    for bad in ["(a{100}){100}", "[ab]*a[ab]{13}c", r"[^/]{1,255}\.php"] {
        assert_eq!(refused(bad), large, "{bad}");
    }
    // What an operator writes is within the limits: anchored, with counted repetitions, and `(?i)`.
    for good in [
        "^/servicea/(users|orders)/[0-9]+$",
        "^/api/v[0-9]+/(users|orders|items)/[0-9]{1,12}(/[a-z_]{1,32})?$",
        "(?i)^/api/v[0-9]+/",
    ] {
        assert!(
            Rule::forward_with(None, None, Some(good), 0).is_ok(),
            "{good}"
        );
    }
}

#[test]
fn a_priority_is_from_minus_1000_to_1000_and_a_rule_has_a_path_or_a_path_regex_not_both() {
    for good in [-1000, 0, 1000] {
        assert_eq!(
            by_path(None, Some("/a"), good).priority(),
            i16::try_from(good).unwrap()
        );
    }
    for bad in [-1001, 1001, i64::from(i16::MAX) + 1, i64::MIN, i64::MAX] {
        let refused = Rule::forward_with(None, Some("/a"), None, bad)
            .unwrap_err()
            .0;
        assert_eq!(refused, "a route priority is not -1000 to 1000", "{bad}");
    }
    assert_eq!(
        Rule::forward_with(None, Some("/a"), Some("a"), 0)
            .unwrap_err()
            .0,
        "a route has both a path and a path regex"
    );
    // A rule that lets a request through without inspection has neither, as it is written.
    let bypass = Rule::bypass(Some("a.test"), "/a/").unwrap();
    assert_eq!((bypass.path_regex(), bypass.priority()), (None, 0));
}

#[test]
fn the_rules_a_request_could_be_taken_for_are_those_of_the_ranks_and_those_of_the_paths_alone() {
    // A path regex is before a prefix, though the path alone chooses the prefix: the lists of both are asked.
    let t = table_of(vec![
        by_path(None, Some("/admin/"), 0),
        by_regex(None, "^/admin", 0),
    ]);
    assert_eq!(could_hold(&t, Some("h"), "/admin/x"), [0, 1]);
    // So is a smaller priority, on a rule for a whole host.
    let t = table_of(vec![
        by_path(None, Some("/admin/"), 0),
        by_path(None, Some("/"), -1),
    ]);
    assert_eq!(could_hold(&t, Some("h"), "/admin/x"), [0, 1]);
    assert_eq!(could_hold(&t, Some("h"), "/pub/x"), [1]);
    // Another spelling of the path meets the same two, for each of its forms.
    let t = table_of(vec![
        by_path(None, Some("/private/"), 0),
        by_path(None, Some("/"), -1),
    ]);
    assert_eq!(could_hold(&t, Some("h"), "/priv%61te/x"), [0, 1]);
    assert_eq!(could_hold(&t, Some("h"), "/private"), [0, 1]);
    // The path with a `/` after it is left out for each way on its own: where the path alone chooses the path itself,
    // the ranks may choose a path regex, and then the prefix that it finds with the `/` is asked too.
    let t = table_of(vec![
        by_path(None, Some("/admin"), 0),
        by_regex(None, "^/admin$", -1),
        by_path(None, Some("/admin/"), 0),
    ]);
    assert_eq!(could_hold(&t, Some("h"), "/admin"), [0, 1, 2]);
    // A table with neither a path regex nor a priority gives what the paths alone give.
    let t = table_of(vec![
        by_path(None, Some("/admin"), 0),
        by_path(None, Some("/admin/"), 0),
    ]);
    assert_eq!(could_hold(&t, Some("h"), "/admin"), [0]);
}
