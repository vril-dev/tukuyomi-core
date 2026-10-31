//! The reader of the rule files: the spellings that the scanner of the library cuts in another place than a
//! plain reading does, and the characters and forms that the reader refuses.

use super::*;
use crate::ffi::tests::{in_a_forked_process, in_a_fresh_process};

/// What the library describes for the rules that it builds from `text`.
pub(super) fn described(text: &str) -> String {
    let (rules, _) = Copy::one(text).read_by_the_library();
    String::from_utf8_lossy(&rules.describe().unwrap()).into_owned()
}

/// A text that the reader accepts, and that builds.
fn builds(text: &str) {
    if let Err(refusal) = Copy::one(text).build() {
        panic!("refused ({refusal}): {text:?}");
    }
}

pub(super) fn refused_as_a_form(text: &str) {
    let refusal = refused(text);
    assert_eq!(refusal.exit, EXIT_RULES, "{text:?}");
    assert!(refusal.reason().contains("form"), "{text:?}: {refusal}");
}

// The library cuts the name of a marker off after the first blank that follows the directive and keeps what
// follows, so with a second blank the name has a blank in front of it, and no `skipAfter` names it: the rules
// after the `skipAfter` (the one that stops a request here) are skipped without a word.
#[test]
fn a_second_blank_after_secmarker_is_refused() {
    let skipped = "SecRule ARGS \"@rx x\" \"id:1,phase:2,pass,log,skipAfter:END-X\"\nSecRule ARGS \"@rx x\" \"id:2,phase:2,pass,log\"\nSecMarker  END-X\nSecRule ARGS \"@rx attack\" \"id:3,phase:2,deny,log\"\n";
    // The library builds it, with the marker named ` END-X`.
    assert!(described(skipped).contains("\n6: END-X\n"));
    refused_as_a_form(skipped);
    for marker in [
        "SecMarker \tEND-X",
        "SecMarker\t END-X",
        "SecMarker  \"END-X\"",
        "SecMarker \t\"END-X\"",
    ] {
        refused_as_a_form(&skipped.replace("SecMarker  END-X", marker));
    }
    // One blank or one tab, and blanks after the name.
    for marker in [
        "SecMarker END-X",
        "SecMarker\tEND-X",
        "SecMarker END-X  ",
        "SecMarker \"END-X\"",
    ] {
        builds(&skipped.replace("SecMarker  END-X", marker));
    }
}

// The scanner cuts the text of an operator by the longest match of its units, not by a scan from the left: a
// `%` and the byte after it are one unit, and a quote is escaped only by backslashes that follow a byte of
// the same token. So in `a%b\"` the quote closes the string, where a reader that sees a backslash before a
// quote takes it for an escaped quote and the text after it for the text of the operator. What follows the
// quote is then an action of the chained rule for the scanner (the chained rule has no id, so it needs no
// list of actions to open with).
#[test]
fn an_operator_string_is_cut_where_the_scanner_cuts_it() {
    let chained = |operator: &str| {
        format!(
            "SecRule REQUEST_URI \"@contains /x\" \"id:1,phase:2,pass,log,chain\"\n    SecRule ARGS \"@contains {operator}\" skipAfter:NOWHERE # \" \"pass\"\nSecRule ARGS \"@rx attack\" \"id:2,phase:2,deny,log\"\n"
        )
    };
    // The text of the operator ends with a backslash, and the quote after it closes the string.
    for operator in ["a%b\\", "a%%\\", "a%%%%\\", "a%%\\\\\\"] {
        let text = chained(operator);
        // The library takes the text, and `skipAfter:NOWHERE` is an action of the second rule.
        assert!(
            described(&text).contains("9:skipafter\n7:NOWHERE\n"),
            "{operator}"
        );
        refused_as_a_form(&text);
    }
    // A `%` alone before the quote makes an escaped quote for both: the string goes on to the next quote.
    for operator in [
        "a%\\\"b",
        "%\\\"",
        "a\\\"b%{tx.c}d",
        "%{tx.a}%\\\"x",
        "a\\\\\\\"b",
    ] {
        builds(&format!(
            "SecRule ARGS \"@contains {operator}\" \"id:1,phase:2,pass,log\"\n"
        ));
    }
    // After a macro the scanner takes a `%` with the `}` (and the quote after it closes the string), unless
    // a `{` follows.
    builds("SecRule ARGS \"@contains %{tx.a}%\" \"id:1,phase:2,pass,log\"\n");
    builds("SecRule ARGS \"@contains %{tx.a}%{tx.b}\" \"id:1,phase:2,pass,log\"\n");
    // A blank before the operator makes the whole string a regular expression for the scanner.
    let blank = "SecRule ARGS \" @contains x\" \"id:1,phase:2,pass,log\"\n";
    assert!(described(blank).contains("rule\n2:rx\n"));
    refused_as_a_form(blank);
    refused_as_a_form("SecRule ARGS \"! @streq a\" \"id:1,phase:2,pass,log\"\n");
    // A regular expression with no operator is cut in the same way, and a string with a line break is refused.
    refused_as_a_form("SecRule ARGS \"a%b\\\" \" \"id:1,phase:2,pass\"\n");
    refused_as_a_form("SecRule ARGS \"@rx a\nb\" \"id:1,phase:2,pass\"\n");
}

#[test]
fn the_environment_is_not_a_variable_a_rule_reads() {
    for variable in [
        "ENV:HOME",
        "env:home",
        "Env",
        "!ENV:HOME",
        "&ENV",
        "ARGS|ENV.HOME",
        "ENV:/^A/",
    ] {
        refused_as_a_form(&format!(
            "SecRule {variable} \"@rx x\" \"id:1,phase:1,pass,log\"\n"
        ));
    }
    // A macro reads the same collection.
    refused_as_a_form("SecAction \"id:1,phase:1,pass,msg:'%{ENV.HOME}'\"\n");
    refused_as_a_form("SecRule ARGS \"@rx %{env.x}\" \"id:1,phase:1,pass\"\n");
    builds("SecRule ARGS|REQUEST_HEADERS:User-Agent \"@rx x\" \"id:1,phase:1,pass,log\"\n");
}

// The scanner reads `phase:'request'` as `allow` (the pattern of `allow` comes first), a rule that lets
// the request through and skips the rules that follow it.
#[test]
fn a_phase_in_quotes_is_refused() {
    let text = "SecRule ARGS \"@contains zzz\" \"id:1,phase:'request',log\"\nSecRule ARGS \"@contains attack\" \"id:2,phase:2,deny,log\"\n";
    assert!(described(text).contains("\ndisruptive\n5:phase\n"));
    refused_as_a_form(text);
    refused_as_a_form("SecAction \"id:1,phase:'2',pass\"\n");
    builds("SecAction \"id:1,phase:request,pass\"\nSecAction \"id:2,phase:2,pass\"\n");
}

// The scanner reads the lines after a commented-out `SecRule` or `SecAction` that ends in a backslash as the
// rest of the comment. They are a comment for this reader only if they start with a `#` too; the setup file
// of the Core Rule Set has such examples, all of whose lines are comments.
#[test]
fn a_comment_that_the_scanner_continues_is_refused_when_a_statement_follows() {
    let statement = "SecAction \"id:1,phase:1,pass,log\"\n";
    for comment in [
        "# SecRule ARGS \\\n",
        "#SecAction \\\n",
        "  #   secrule x \\ \t\n",
        "# SECACTION \\\n# more \\\n",
    ] {
        // The scanner takes the next line (`statement`) as part of the comment: no rule.
        let text = format!("{comment}{statement}");
        refused_as_a_form(&text);
    }
    // The same after a statement on its line.
    refused_as_a_form(&format!("SecMarker X # SecRule ARGS \\\n{statement}"));
    // A comment that goes on over comment lines only, as the Core Rule Set has them, and one that is not
    // a commented-out rule, are accepted.
    builds(&format!(
        "#SecAction \\\n#    \"id:900110,\\\n#    phase:1,\\\n#    pass\"\n{statement}"
    ));
    builds(&format!("# a note \\\n# more\n{statement}"));
    // A name that ends its line takes the next line with it, when that ends in a backslash.
    refused_as_a_form(&format!("# SecRule\n#\\\n{statement}"));
    refused_as_a_form(&format!("# SecAction\n#\\\n{statement}"));
    // Empty lines are read over by the scanner after such a comment, and what comes after them is a line of it.
    refused_as_a_form(&format!("# SecRule ARGS \\\n\n{statement}"));
    builds(&format!("# SecRule ARGS x\n{statement}"));
}

// The library takes the rest of the line as the argument of some directives, a comment and a tab included
// (`#` is no comment there), where the reader would see the argument and a comment. A directive that has
// anything but spaces after its argument is refused.
#[test]
fn a_directive_that_the_library_reads_to_the_end_of_the_line_has_nothing_after_its_argument() {
    assert!(described("SecRuleRemoveByTag x # note\n").contains("\n8:x # note\n"));
    for text in [
        "SecRuleRemoveByTag x # note\n",
        "SecRuleRemoveByTag x\t\n",
        "SecRuleRemoveById 1 5 # note\n",
        "SecResponseBodyMimeType text/plain # note\n",
        "SecResponseBodyMimeType text/plain\t\n",
    ] {
        refused_as_a_form(text);
    }
    for text in [
        "SecRuleRemoveByTag x   \n",
        "SecRuleRemoveByTag \"x\" # note\n",
        "SecRuleRemoveById 1 5  \n",
        "SecResponseBodyMimeType text/plain   \n",
        "SecResponseBodyLimit 5 # note\n",
    ] {
        builds(text);
    }
}

// A carriage return and a NUL byte are refused wherever they are, though nothing else of the reader looks at
// them in a comment. The reason is the one of the reader: the library would build another set of rules from
// the text, and that alone would be a refusal of its own kind.
#[test]
fn a_carriage_return_and_a_nul_byte_are_refused_wherever_they_are() {
    let rule = "SecAction \"id:1,phase:1,pass,log\"\n";
    for (text, fragment) in [
        (format!("# a\rb\n{rule}"), "carriage return"),
        (format!("# a\0b\n{rule}"), "NUL byte"),
        (format!("{rule}# a\0b\n"), "NUL byte"),
    ] {
        let refusal = refused(&text);
        assert_eq!(refusal.exit, EXIT_RULES, "{text:?}");
        assert!(refusal.reason().contains(fragment), "{text:?}: {refusal}");
    }
}

// The library keeps a tab after the first blank as a part of the argument, so a second blank, or a tab after a
// space, is not the blank that this reader skips: one blank, and then the argument.
#[test]
fn the_argument_of_a_directive_that_reads_to_the_end_of_the_line_follows_exactly_one_blank() {
    assert!(described("SecRuleRemoveByMsg \t\"a b\"\n").contains("\t\"a b\""));
    for text in [
        "SecRuleRemoveByTag  x\n",
        "SecRuleRemoveByTag \tx\n",
        "SecRuleRemoveByTag\t x\n",
        "SecRuleRemoveByMsg  x\n",
        "SecRuleRemoveByMsg \t\"a b\"\n",
        "SecRuleUpdateTargetByMsg \t\"m\" REQUEST_HEADERS:Host\n",
        "SecRuleUpdateTargetByTag  t ARGS\n",
        "SecRuleUpdateTargetById  1 ARGS\n",
        "SecRuleRemoveById  1\n",
        "SecResponseBodyMimeType  text/plain\n",
    ] {
        refused_as_a_form(text);
    }
    for text in [
        "SecRuleRemoveByTag x\n",
        "SecRuleRemoveByTag\tx\n",
        "SecRuleRemoveByMsg \"a b\"\n",
        "SecRuleUpdateTargetByMsg \"m\" REQUEST_HEADERS:Host\n",
        "SecRuleUpdateTargetById 1 ARGS\n",
        "SecRuleRemoveById 1\n",
        "SecResponseBodyMimeType text/plain\n",
    ] {
        builds(text);
    }
}

// The scanner reads a variable by the longest name that its list has, a selector up to a comma, a `|` or a `}`
// (or as a regular expression to the last slash), and a `,` like a `|`. These forms are read as it reads them, and
// every other form of a variable is refused.
#[test]
fn a_variable_is_cut_where_the_scanner_cuts_it() {
    for variable in [
        "ARGS",
        "args_get_names:a",
        "REQUEST_HEADERS:User-Agent|!REQUEST_HEADERS:Referer",
        "&ARGS|ARGS:/a,b/|!REQUEST_COOKIES:/\\x22?\\x24Version/",
        "XML:/*|XML://@*",
        "XML:/^a/|REQUEST_COOKIES:/^b/",
        "TX:/^header_name_920451_/",
        "ARGS,ARGS_GET",
        "ARGS:/a/|ARGS:/b/",
        "Time_Day|rule.id|TX.a",
    ] {
        builds(&format!(
            "SecRule {variable} \"@rx x\" \"id:1,phase:2,pass,log\"\n"
        ));
    }
    for variable in [
        // A name that is not one of the scanner's, one that has something glued to it, and a selector where
        // there can be none.
        "NOSUCH",
        "ARGSx",
        "ARGS_GETx:a",
        "REQUEST_URI:a",
        "ARGS:",
        "ARGS:|ARGS",
        "ARGS|",
        "|ARGS",
        // Two modifiers, a modifier alone, a selector that has a backslash or a quote, a `}` that ends it.
        "!&ARGS",
        "!",
        "ARGS:a\\b",
        "ARGS:'a'",
        "ARGS:a}b",
    ] {
        refused_as_a_form(&format!(
            "SecRule {variable} \"@rx x\" \"id:1,phase:2,pass,log\"\n"
        ));
    }
}

// The library gives each variable of a list the keys of every exclusion of the list, so the text that compares what
// it built with what the reader read grows with the product of the two numbers. A list holds at most 256 entries:
// the variables, the counts and the ones that are taken out together, in a rule and in an update of a target.
#[test]
fn a_list_of_more_than_256_variables_is_refused() {
    let rule = |plain: usize, counted: usize, taken_out: usize| {
        let list = (0..plain)
            .map(|n| format!("ARGS:a{n}"))
            .chain((0..counted).map(|n| format!("&ARGS:c{n}")))
            .chain((0..taken_out).map(|n| format!("!ARGS:x{n}")))
            .collect::<Vec<_>>()
            .join("|");
        format!("SecRule {list} \"@rx x\" \"id:1,phase:2,pass,log\"\n")
    };
    let update = |entries: usize| {
        let list: Vec<String> = (0..entries).map(|n| format!("ARGS:a{n}")).collect();
        format!("SecRuleUpdateTargetById 1 {}\n", list.join("|"))
    };
    for (limit, past) in [
        (rule(256, 0, 0), rule(257, 0, 0)),
        (rule(100, 100, 56), rule(100, 101, 56)),
        (rule(100, 100, 56), rule(100, 100, 57)),
        (update(256), update(257)),
    ] {
        builds(&limit);
        let refusal = refused(&past);
        assert_eq!(
            (refusal.exit, refusal.file()),
            (EXIT_RULES, Some("rules/a.conf"))
        );
        assert!(refusal.reason().contains("256 entries"), "{refusal}");
    }
}

// The reader reads the same variables as the library for every name that the scanner has, written in capitals and
// in lower case, with no selector and with one, in a list and in a macro. (The library refuses one name, which it
// does not support.) Each text is read by the library in a process of its own.
#[test]
fn every_name_of_the_scanner_is_read_as_the_library_reads_it() {
    in_a_fresh_process(
        "rules::tests::reader::every_name_of_the_scanner_is_read_as_the_library_reads_it",
        every_name_is_read_as_the_library_reads_it,
    );
}

fn every_name_is_read_as_the_library_reads_it() {
    let mut refused_by_the_library = Vec::new();
    let mut differences = Vec::new();
    for (name, selectable, _) in crate::rules::reader::NAMES {
        let upper = name.to_ascii_uppercase();
        let mixed: String = name
            .chars()
            .enumerate()
            .map(|(at, c)| {
                if at % 2 == 0 {
                    c.to_ascii_uppercase()
                } else {
                    c
                }
            })
            .collect();
        let mut variables = vec![upper.clone(), mixed.clone()];
        if *selectable {
            variables.extend([format!("{upper}:a"), format!("{mixed}.b-c")]);
        }
        for variable in variables {
            for (macro_, text) in [
                (
                    false,
                    format!("SecRule {variable} \"@rx x\" \"id:1,phase:2,pass,log\"\n"),
                ),
                (
                    true,
                    format!("SecRule ARGS \"@rx x\" \"id:1,phase:2,pass,msg:'%{{{variable}}}'\"\n"),
                ),
            ] {
                // The reader refuses the environment, and the macro of a whole collection that can be written to.
                let whole = macro_ && !variable.contains([':', '.']);
                let refused =
                    *name == "env" || (whole && crate::rules::reader::WRITABLE.contains(name));
                match compared(&text).as_str() {
                    "equal" => {}
                    "refused by the reader" if refused => {}
                    "refused by the library" => refused_by_the_library.push(variable.clone()),
                    other => differences.push(format!("{variable}: {other}")),
                }
            }
        }
    }
    assert!(differences.is_empty(), "{differences:?}");
    refused_by_the_library.dedup();
    assert!(
        refused_by_the_library
            .iter()
            .all(|name| name.eq_ignore_ascii_case("webserver_error_log")),
        "{refused_by_the_library:?}"
    );
}

/// What the reader and the library make of `text`, each in a process of its own: `equal`, `refused by the reader`,
/// `refused by the library` or `differ`.
pub(super) fn compared(text: &str) -> String {
    in_a_forked_process(|| {
        if crate::rules::reader::read(text.as_bytes()).is_err() {
            return "refused by the reader".to_owned();
        }
        let copy = Copy::one(text);
        let mut rules = Rules::new().unwrap();
        rules.add_text(load::FIXED_DIRECTIVES).unwrap();
        for path in &copy.load {
            if rules.add_file(&copy.root.join(path)).is_err() {
                return "refused by the library".to_owned();
            }
        }
        match load::compare(&rules, &model_of(&copy)) {
            Ok(()) => "equal".to_owned(),
            Err(_) => "differ".to_owned(),
        }
    })
}

// The library keeps the blanks that stand before the comma, or before the quote, that ends a text with no quotes.
#[test]
fn a_blank_that_ends_a_text_without_quotes_belongs_to_the_text() {
    let text = "SecAction \"id:1,phase:1,pass,tag:abc ,msg:def \"\n";
    let built = described(text);
    assert!(built.contains("text\n4:abc \n") && built.contains("text\n4:def \n"));
    builds(text);
}

// The parser takes the text that follows the macro of a whole collection that a rule can write to as the selector of that
// collection, so such a macro is refused, with the text after it or without.
#[test]
fn a_macro_of_a_whole_collection_that_can_be_written_to_is_refused() {
    for name in ["tx", "TX", "ip", "global", "resource", "session", "user"] {
        for text in [format!("%{{{name}}}.a}}"), format!("%{{{name}}}")] {
            refused_as_a_form(&format!("SecAction \"id:1,phase:1,pass,msg:'{text}'\"\n"));
        }
    }
    builds("SecAction \"id:1,phase:1,pass,msg:'%{tx.a} %{request_headers.host}'\"\n");
}
