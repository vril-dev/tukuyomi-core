//! The shipper reads the configuration file with the library of the proxy (`config::load_main`), so the routes of the
//! file are checked here as they are by the proxy. Its database client brings in the `regex` crates with the tables of
//! Unicode, which the proxy is built without: an expression that needs them has to be refused all the same.
use tukuyomi_proxy::route::Rule;

#[test]
fn a_path_regex_that_turns_unicode_on_is_refused_here_as_by_the_proxy() {
    let refused = |regex: &str| {
        Rule::forward_with(None, None, Some(regex), 0)
            .unwrap_err()
            .0
    };
    let invalid = "a route path regex is not a valid regular expression";
    for bad in [r"(?u)\w", r"(?iu)a", r"a(?u:b)", r"\pL", r"[\P{Greek}]"] {
        assert_eq!(refused(bad), invalid, "{bad}");
    }
    for good in [r"(?-u)\w", r"^/a/\w+$"] {
        assert!(
            Rule::forward_with(None, None, Some(good), 0).is_ok(),
            "{good}"
        );
    }
}
