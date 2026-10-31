use super::*;
use crate::ffi::tests::in_a_fresh_process;
use crate::ffi::{EngineState, Finding, Rules, Settings};
use crate::sandbox::Restricted;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

mod built;
mod reader;

/// A copy of a generation on the disk, in a directory of its own under the temporary directory that is
/// removed when it goes out of scope.
struct Copy {
    root: PathBuf,
    files: BTreeMap<String, Vec<u8>>,
    load: Vec<String>,
}

impl Copy {
    fn new(files: BTreeMap<String, Vec<u8>>, load: Vec<String>) -> Copy {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "tkv-rules-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        Copy::in_dir(root, files, load)
    }

    /// The same, with its root at `root`.
    fn in_dir(root: PathBuf, files: BTreeMap<String, Vec<u8>>, load: Vec<String>) -> Copy {
        for (path, bytes) in &files {
            let file = root.join(path);
            fs::create_dir_all(file.parent().unwrap()).unwrap();
            fs::write(file, bytes).unwrap();
        }
        Copy { root, files, load }
    }

    /// The files `(path, text)`; the paths ending in `.conf` are loaded in the order given.
    fn of(files: &[(&str, &str)]) -> Copy {
        let load = (files.iter())
            .filter(|(path, _)| path.ends_with(".conf"))
            .map(|(path, _)| path.to_string())
            .collect();
        let files = (files.iter())
            .map(|(path, text)| (path.to_string(), text.as_bytes().to_vec()))
            .collect();
        Copy::new(files, load)
    }

    /// One rule file.
    fn one(text: &str) -> Copy {
        Copy::of(&[("rules/a.conf", text)])
    }

    /// The rules built in a process that is not restricted (see `build_with`).
    fn build(&self) -> Result<Rules, Refusal> {
        self.build_with(Restricted::assumed())
    }

    fn build_with(&self, restricted: Restricted) -> Result<Rules, Refusal> {
        build(&self.root, &self.files, &self.load, restricted)
    }

    /// The rules that the library builds from the files of the copy that are loaded, with none of the
    /// checks of the text, and the paths that it was given.
    fn read_by_the_library(&self) -> (Rules, Vec<PathBuf>) {
        let mut rules = Rules::new().unwrap();
        let paths: Vec<PathBuf> = self.load.iter().map(|path| self.root.join(path)).collect();
        for path in &paths {
            rules
                .add_file(path)
                .unwrap_or_else(|e| panic!("the library refuses {}: {e}", path.display()));
        }
        (rules, paths)
    }
}

impl Drop for Copy {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// What the reader reads of the copy, with none of the checks of the guard (the refusals of the reader
/// itself stay): the model that the checks would give if they let the text through.
fn model_of(copy: &Copy) -> model::Model {
    let mut model = model::Model::default();
    for path in &copy.load {
        // Where the reader refuses the text there is no model, and the library is still given the text.
        let Ok(statements) = crate::rules::reader::read(&copy.files[path]) else {
            return model::Model::default();
        };
        for statement in statements {
            model.statement(&statement).unwrap();
        }
        model.end_of_file();
    }
    model
}

/// The working directory, read while no build changes it.
fn working_directory() -> PathBuf {
    let _held = load::WORKING_DIRECTORY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    std::env::current_dir().unwrap()
}

/// The refusal of the text as the only rule file, or a panic if it builds.
fn refused(text: &str) -> Refusal {
    match Copy::one(text).build() {
        Ok(_) => panic!("accepted: {text:?}"),
        Err(refusal) => refusal,
    }
}

/// What the look at the built rules finds when the library reads `text` as a rule file. The library has to
/// take the text.
fn library_finds(text: &str) -> Option<Finding> {
    let (rules, paths) = Copy::one(text).read_by_the_library();
    rules.check(&paths).unwrap()
}

/// Whether the engine library reads `text` and ends with the rule engine off. Every text that is used
/// ends in a `SecRuleEngine Off` that a reader of lines does not see as a directive.
fn library_turns_the_engine_off(text: &str) -> bool {
    let mut rules = Rules::new().unwrap();
    rules.add_text(text).is_ok() && rules.settings().unwrap().engine == EngineState::Off
}

const RULE: &str = "SecRule ARGS \"@contains attack\" \"id:1001,phase:2,deny,status:403,log\"\n";

#[test]
fn a_rules_file_builds_with_the_fixed_settings_whatever_it_sets() {
    let copy = Copy::one(&format!(
        "SecRuleEngine Off\nSecRequestBodyAccess Off\nSecRequestBodyJsonDepthLimit 1000\n{RULE}"
    ));
    let rules = copy.build().unwrap();
    assert_eq!(
        rules.settings(),
        Ok(Settings {
            engine: EngineState::On,
            body_access: Some(true),
            json_depth_limit: Some(64)
        })
    );
    assert_eq!(working_directory(), PathBuf::from("/"));
}

#[test]
fn what_rule_files_are_written_in_is_accepted() {
    let accepted = [
        "# comment\n\n  # indented\nSecRuleEngine DetectionOnly # a comment\n",
        "SecAction \\\n    \"id:1,\\\n    phase:1,\\\n    pass,\\\n    nolog,\\\n    msg:'a \\\n    b',\\\n    setvar:'tx.a=+%{tx.b}'\"\n",
        "SecRule REQUEST_HEADERS:User-Agent|ARGS|XML:/* \\\n  \"@rx a\\\"b%{tx.c}\" \\\n  \"id:2,phase:2,pass,t:none,t:lowercase,msg:'a \\\" b, c',ctl:ruleRemoveById=900000\"\n",
        "SecRule ARGS \"!@contains x\" \"id:3,phase:1,deny,log,chain\"\n    SecRule ARGS \"@rx y\"\n\n",
        "SecMarker \"A.B-c\"\nSecMarker 'D'\nSecRuleRemoveById 1 5 10-20\nSecRuleRemoveByTag attack-sqli\n",
        "SecRuleUpdateTargetById 1001 \"!REQUEST_COOKIES:/^_ga(?:_\\w+)?$/\"\n",
        "SecDefaultAction \"phase:1,log,auditlog,pass\"\nSecComponentSignature \"X/1\"\nSecAuditEngine Off\n",
        "SecRule ARGS \"@rx x\" \"id:4,phase:1,pass,ctl:forceRequestBodyVariable=On,ctl:auditEngine=Off\"\n",
        // The ids next to the reserved ones.
        "SecAction \"id:4000000,phase:1,pass\"\nSecAction \"id:4000012,phase:1,pass\"\n",
        "SecRule ARGS \"@rx x\" \"id:5,phase:1,pass,skipAfter:END-X\"\nSecMarker END-X\n",
        // What the Core Rule Set writes: an escaped quote and a continuation in a text in quotes, and the
        // processor of the body.
        "SecAction \"id:6,phase:1,pass,msg:'a \\'UP\\' b \\\"x\\\" c',logdata:'%{tx.a}',ctl:requestBodyProcessor=URLENCODED\"\n",
        "SecAction \"id:7,phase:1,pass,msg:'Scores: \\\n(In %{tx.a}) - \\\n(Out)',ctl:requestBodyProcessor=JSON,ctl:requestBodyProcessor=XML\"\n",
        "SecAction \"id:8,phase:1,pass,nolog,severity:'CRITICAL',ver:'V/1',rev:'2',accuracy:'9',maturity:'8',initcol:ip=%{remote_addr}_%{tx.h},setvar:!tx.a,setvar:'tx.b=1'\"\n",
    ];
    for text in accepted {
        if let Err(refusal) = Copy::one(text).build() {
            panic!("refused ({refusal}): {text:?}");
        }
    }
}

#[test]
fn directives_that_reach_outside_or_change_the_limits_are_refused() {
    let rows: [(&str, &str); 22] = [
        ("Include /etc/x.conf\n", "Include"),
        ("include /etc/x.conf\n", "Include"),
        (
            "SecRemoteRules key https://example.com/rules\n",
            "SecRemoteRules",
        ),
        (
            "SecIgnoreRuleCompilationErrors Off\n",
            "SecIgnoreRuleCompilationErrors",
        ),
        ("SecAuditLog /x\n", "SecAuditLog, SecDebugLog and SecUpload"),
        (
            "SecDebugLogLevel 0\n",
            "SecAuditLog, SecDebugLog and SecUpload",
        ),
        (
            "SecUploadDir /x\n",
            "SecAuditLog, SecDebugLog and SecUpload",
        ),
        ("SecAuditEngine On\n", "form"),
        ("SecDataDir /x\n", "SecDataDir and SecTmpDir"),
        ("SecTmpDir /x\n", "SecDataDir and SecTmpDir"),
        ("SecRequestBodyLimit 1\n", "limit"),
        ("SecRequestBodyNoFilesLimit 1\n", "limit"),
        ("SecRequestBodyLimitAction ProcessPartial\n", "limit"),
        ("SecArgumentsLimit 1\n", "limit"),
        ("SecUnicodeMapFile unicode.mapping 20127\n", "not allowed"),
        ("SecRuleUpdateActionById 1 \"nolog\"\n", "not allowed"),
        ("SecNoSuchDirective 1\n", "not known"),
        ("SecRuleEngine Maybe\n", "form"),
        (
            "SecRule ARGS \"@rx x\" \"id:1,phase:1,pass,noSuchAction\"\n",
            "action",
        ),
        ("SecRule ARGS \"@rx x\" \"id:1,phase:1,pause\"\n", "action"),
        (
            "SecRule ARGS \"@rx x\" \"id:1,phase:1,pass,ctl:noSuchCtl=1\"\n",
            "action",
        ),
        ("SecAction \"id:1,phase:1,pass,exec:/bin/true\"\n", "exec"),
    ];
    for (text, fragment) in rows {
        let refusal = refused(text);
        assert_eq!(refusal.exit, EXIT_RULES, "{text:?}");
        assert!(refusal.reason().contains(fragment), "{text:?}: {refusal}");
        assert_eq!(refusal.file(), Some("rules/a.conf"));
    }
}

#[test]
fn what_changes_the_engine_or_the_body_for_one_transaction_is_refused() {
    let act = "SecAction \"id:1,phase:1,pass,";
    let rows = [
        format!("{act}ctl:ruleEngine=Off\"\n"),
        format!("{act}CTL:RuleEngine=DetectionOnly\"\n"),
        format!("{act}ctl:requestBodyAccess=Off\"\n"),
        format!("{act}ctl:requestBodyLimit=1\"\n"),
        // Split by a continuation: the scanner reads no such action, but a reader that joined the lines would.
        format!("{act}ctl:rule\\\nEngine=Off\"\n"),
        format!("{act}setenv:A=B\"\n"),
        format!("{act}set\\\nenv:A=B\"\n"),
        "SecRule ARGS \"@inspectFile /bin/true\" \"id:1,phase:1,pass\"\n".to_string(),
        "SecRule ARGS \"@rbl sbl.example.net\" \"id:1,phase:1,pass\"\n".to_string(),
        "SecRule ARGS \"@validateDTD x.dtd\" \"id:1,phase:1,pass\"\n".to_string(),
        "SecRule ARGS \"@validateSchema x.xsd\" \"id:1,phase:1,pass\"\n".to_string(),
        "SecRule ARGS \"@fuzzyHash x.hash 1\" \"id:1,phase:1,pass\"\n".to_string(),
        "SecRule ARGS \"@noSuchOperator x\" \"id:1,phase:1,pass\"\n".to_string(),
        // The name is glued to its argument: the scanner skips a character and reads an operator.
        "SecRule ARGS \"@rxx x\" \"id:1,phase:1,pass\"\n".to_string(),
    ];
    for text in rows {
        assert_eq!(refused(&text).exit, EXIT_RULES, "{text:?}");
    }
}

#[test]
fn a_rule_that_stops_a_request_has_to_log() {
    for text in [
        "SecRule ARGS \"@rx x\" \"id:1,phase:2,deny,nolog\"\n",
        "SecRule ARGS \"@rx x\" \"id:1,phase:2,nolog,redirect:/x\"\n",
        "SecRule ARGS \"@rx x\" \"id:1,phase:2,block,nolog\"\n",
        // The library drops the message of a rule that has noauditlog as it does for nolog.
        "SecRule ARGS \"@rx x\" \"id:1,phase:2,deny,noauditlog\"\n",
        "SecDefaultAction \"phase:2,log,deny,nolog\"\n",
    ] {
        assert!(refused(text).reason().contains("nolog"), "{text:?}");
    }
    // A rule that does not stop a request may have nolog.
    assert!(
        Copy::one("SecAction \"id:1,phase:1,pass,nolog\"\n")
            .build()
            .is_ok()
    );
}

// The actions of a default action are taken by the rules after it: a rule that stops a request would stop
// it with no message, so the default action may not have nolog, whatever else it has.
#[test]
fn a_default_action_with_nolog_is_refused_whatever_else_it_has() {
    for text in [
        "SecDefaultAction \"phase:2,log,pass,nolog\"\n",
        "SecDefaultAction \"phase:2,pass,noauditlog\"\n",
        "SecDefaultAction \"phase:1,NoLog\"\n",
    ] {
        let refusal = refused(text);
        assert!(
            refusal.reason().contains("SecDefaultAction"),
            "{text:?}: {refusal}"
        );
    }
    assert!(
        Copy::one("SecDefaultAction \"phase:2,log,auditlog,pass\"\n")
            .build()
            .is_ok()
    );
}

#[test]
fn the_ids_of_the_inspector_are_reserved() {
    for id in ["4000001", "4000011", "'4000001'", "04000005"] {
        let text = format!("SecAction \"id:{id},phase:1,pass\"\n");
        assert!(refused(&text).reason().contains("reserved"), "{text:?}");
    }
}

#[test]
fn a_skip_after_needs_a_marker_after_it() {
    let skip = "SecRule ARGS \"@rx x\" \"id:1,phase:1,pass,skipAfter:X\"\n";
    let one = |text: &str| Copy::one(text).build().err();
    assert!(one(skip).unwrap().reason().contains("marker"));
    assert!(
        one(&format!("SecMarker X\n{skip}"))
            .unwrap()
            .reason()
            .contains("marker")
    );
    assert!(
        one("SecDefaultAction \"phase:1,log,pass,skipAfter:X\"\nSecMarker X\n")
            .unwrap()
            .reason()
            .contains("SecDefaultAction")
    );
    assert!(one(&format!("{skip}SecMarker X\n")).is_none());
    // The marker may be in a later file; the refusal names the file of the skipAfter.
    let later = Copy::of(&[("rules/a.conf", skip), ("rules/b.conf", "SecMarker X\n")]);
    assert!(later.build().is_ok());
    let wrong_order = Copy::new(
        later.files.clone(),
        vec!["rules/b.conf".to_string(), "rules/a.conf".to_string()],
    );
    assert_eq!(
        wrong_order.build().err().unwrap().file(),
        Some("rules/a.conf")
    );
}

/// A spelling that the engine library reads as a directive, and that a reader which cuts the text by lines or
/// does not know the continuation would take for the text of something else: the library reads it (the
/// engine ends off) and the check refuses it.
#[test]
fn what_the_library_reads_as_a_directive_does_not_pass() {
    let rows = [
        // Two directives on one line, as an argument, after a rule and after a marker.
        "SecMarker X SecRuleEngine Off\n",
        "SecRule ARGS \"@rx a\" \"id:1,phase:1,pass\" SecRuleEngine Off\n",
        "SecRuleEngine On SecRuleEngine Off\n",
        // A name glued to its argument is read as the name and the argument.
        "SecRuleEngineOff\n",
        // A continuation between two directives joins nothing for the library.
        "SecMarker X \\\nSecRuleEngine Off\n",
        // A carriage return before the line break.
        "SecMarker X\r\nSecRuleEngine Off\r\n",
    ];
    for text in rows {
        assert!(
            library_turns_the_engine_off(text),
            "the library does not read {text:?} so"
        );
        assert!(refused(text).exit == EXIT_RULES, "{text:?}");
    }
}

/// Spellings where the check reads more than the library does: what it reads as a directive is refused,
/// though the library skips it.
#[test]
fn a_hidden_directive_that_the_library_skips_is_refused_too() {
    let rows = [
        // The operator runs over the line break: the library reads the line as part of the operator.
        "SecRule ARGS \"@rx a\nSecRuleEngine Off\n\" \"id:1,phase:1,pass\"\n",
        // The library reads the line after a commented-out rule that ends in a backslash as a comment.
        "# SecRule ARGS \\\nSecRequestBodyLimit 1\n",
        // A % before the closing quote of the operator takes the quote in the library.
        "SecRule ARGS \"@rx 100%\" \"id:1,phase:1,pass\"\n",
    ];
    for text in rows {
        assert_eq!(refused(text).exit, EXIT_RULES, "{text:?}");
    }
    // A comment that is not a commented-out rule does not continue: the next line is a directive.
    assert!(library_turns_the_engine_off(
        "# note \\\nSecRuleEngine Off\n"
    ));
    assert!(
        refused("# note \\\nSecRequestBodyLimit 1\n")
            .reason()
            .contains("limit")
    );
    // NUL ends the text for the library, so it is refused with all that follows.
    assert!(refused("SecRuleEngine On\n\0SecRequestBodyLimit 1\n").exit == EXIT_RULES);
}

/// A text for which the library reads an action or a directive that the checks must have seen, and that the
/// reader refuses because it does not cut the text where the library does. For each text: what the library
/// finds in the rules that it builds, and the refusal.
fn the_library_reads_more_than_the_text_shows(rows: &[(&str, Finding)]) {
    for (text, finding) in rows {
        assert_eq!(library_finds(text), Some(*finding), "{text:?}");
        let refusal = refused(text);
        assert_eq!(refusal.exit, EXIT_RULES, "{text:?}");
        assert!(refusal.reason().contains("form"), "{text:?}: {refusal}");
    }
}

// The scanner takes a `%` and the byte after it into the value, so `%"` does not close the list and `%,` does
// not end the value: what looks like a comment, or like the text after the list, is more actions of the same
// list, or a directive.
#[test]
fn a_percent_in_a_value_takes_the_byte_after_it() {
    the_library_reads_more_than_the_text_shows(&[
        (
            "SecRule REQUEST_URI \"@contains /x\" \"id:1,phase:1,pass,msg:100%\" # ,ctl:ruleEngine=Off\nSecRule ARGS \"@rx attack\" \"id:2,phase:2,deny,log\"\n",
            Finding::Ctl,
        ),
        (
            "SecRule REQUEST_URI \"@contains /x\" \"id:1,phase:1,pass,msg:100%\" # ,deny,nolog\n",
            Finding::NoLog,
        ),
        (
            "SecAction \"id:1,phase:1,pass,msg:100%\" # ,pass\" SecRequestBodyLimit 1\n",
            Finding::Setting,
        ),
    ]);
}

// A backslash does not protect a comma: the scanner ends the value there and reads what follows as actions.
#[test]
fn a_backslash_before_a_comma_does_not_protect_it() {
    the_library_reads_more_than_the_text_shows(&[
        (
            "SecRule ARGS \"@rx x\" \"id:1,phase:2,pass,msg:a\\,deny,nolog\"\n",
            Finding::NoLog,
        ),
        (
            "SecRule ARGS \"@rx x\" \"id:1,phase:2,pass,tag:a\\,ctl:ruleEngine=Off\"\n",
            Finding::Ctl,
        ),
    ]);
}

// Without quotes, the value of `rev` takes a double quote and a line break: the quote that looks like the end of
// the list is part of the value, and the actions after it are in the list.
#[test]
fn a_rev_without_quotes_takes_the_quote_that_closes_the_list() {
    the_library_reads_more_than_the_text_shows(&[
        (
            "SecRule REQUEST_URI \"@contains /x\" \"id:1,phase:2,pass,rev:1\" # ,deny,nolog\"\n",
            Finding::NoLog,
        ),
        (
            "SecRule REQUEST_URI \"@contains /x\" \"id:1,phase:2,pass,rev:1\" # ,ctl:ruleEngine=Off\"\n",
            Finding::Ctl,
        ),
    ]);
}

// In a `setvar` in quotes the value ends at a comma or a double quote, though they are inside the quotes.
#[test]
fn a_setvar_in_quotes_ends_at_a_comma_or_a_double_quote() {
    the_library_reads_more_than_the_text_shows(&[
        (
            "SecAction \"id:1,phase:1,pass,setvar:'tx.a=b,deny,nolog,msg:',pass\"\n",
            Finding::NoLog,
        ),
        (
            "SecAction \"id:1,phase:1,pass,setvar:'tx.a=b\" SecRequestBodyLimit 1 #'\"\n",
            Finding::Setting,
        ),
    ]);
}

// The scanner ends a word where the word ends, with no comma: `Off` and `deny` side by side are two tokens. The
// parser of the library needs a comma between two actions, so it refuses these texts, but they must not get to
// it: the reader refuses them, as it refuses every value that is not in the form of its action.
#[test]
fn a_value_that_is_not_in_the_form_of_its_action_is_refused_by_the_checks() {
    let act = "SecAction \"id:1,phase:1,pass,";
    for (tail, fragment) in [
        ("ctl:auditEngine=Offdeny,nolog\"\n", "form"),
        ("ctl:requestBodyProcessor=JSONdeny,nolog\"\n", "form"),
        ("ctl:auditLogParts=+abc\"\n", "form"),
        ("t:nonepause\"\n", "not one of the actions"),
        ("accuracy:'\\',deny,nolog,msg:'x'\"\n", "form"),
        ("severity:CRITICALpass\"\n", "form"),
        ("phase:2pass\"\n", "form"),
    ] {
        let text = format!("{act}{tail}");
        let refusal = refused(&text);
        // The library refuses these texts as well, and is not the one that has to.
        assert!(
            !refusal.reason().contains("did not read"),
            "{text:?}: {refusal}"
        );
        assert!(refusal.reason().contains(fragment), "{text:?}: {refusal}");
    }
}

// With two backslashes before a quote the quote is no longer escaped: the text ends there for the library,
// which reads what follows as actions.
#[test]
fn a_quote_after_two_backslashes_closes_the_text() {
    the_library_reads_more_than_the_text_shows(&[(
        "SecAction \"id:1,phase:1,pass,msg:'a\\\\',deny,nolog,msg:x'\"\n",
        Finding::NoLog,
    )]);
}

// The scanner has other patterns for an escaped quote at the start of a text, after a macro and after another
// escaped quote than for one after a byte of the text, and this reader follows only the last: for the others it
// refuses, though the library reads each of these texts as one message.
#[test]
fn an_escaped_quote_is_accepted_only_after_a_byte_of_the_text() {
    for text in [
        "SecAction \"id:1,phase:1,pass,msg:'a\\'\\',ctl:ruleEngine=Off,msg:x'\"\n",
        "SecAction \"id:1,phase:1,pass,msg:'\\'x'\"\n",
        "SecAction \"id:1,phase:1,pass,msg:'%{tx.a}\\'x'\"\n",
    ] {
        assert_eq!(library_finds(text), None, "{text:?}");
        let refusal = refused(text);
        assert!(refusal.reason().contains("form"), "{text:?}: {refusal}");
    }
    // After a byte of the text it is read as an escape by both.
    let text = "SecAction \"id:1,phase:1,pass,msg:'a\\'b',tag:'c'\"\n";
    assert_eq!(library_finds(text), None);
    assert!(Copy::one(text).build().is_ok());
}

/// A backslash in the variables ends them for the library, and the next string is the actions: the id in it is
/// the id of a rule. (The second rule has the same id, so the library refuses the text.)
#[test]
fn a_backslash_in_the_variables_does_not_make_the_next_string_a_set_of_actions() {
    in_a_fresh_process(
        "rules::tests::a_backslash_in_the_variables_does_not_make_the_next_string_a_set_of_actions",
        || {
            // In a regular expression of a selector a backslash is part of it, and the variables stay variables.
            let selector = "SecRule ARGS:/^a\\d$/|!REQUEST_COOKIES:/^_ga\\w*/ \"@rx x\" \"id:6,phase:1,pass\"\n";
            assert!(Copy::one(selector).build().is_ok());
            let twice = "SecRule ARGS\\x \"id:5,phase:1,pass\"\n\nSecRule ARGS \"@rx a\" \"id:5,phase:1,pass\"\n";
            let reserved = "SecRule ARGS\\x \"id:4000001,phase:1,deny,nolog\"\n\n";
            assert_eq!(refused(twice).exit, EXIT_RULES);
            assert_eq!(refused(reserved).exit, EXIT_RULES);
            // The read that the library refuses comes last.
            assert!(Rules::new().unwrap().add_text(twice).is_err());
        },
    );
}

#[test]
fn a_file_that_a_rule_reads_has_to_be_a_file_of_the_generation() {
    let rule = |arg: &str| format!("SecRule ARGS \"@pmFromFile {arg}\" \"id:1,phase:1,pass\"\n");
    let data = [
        ("rules/words.data", "attack\n"),
        ("crs/rules/more.data", "x\n"),
        ("flat.data", "y\n"),
    ];
    let build = |arg: &str| {
        let mut files = vec![("rules/a.conf", rule(arg))];
        files.extend(data.iter().map(|(p, t)| (*p, t.to_string())));
        let files: Vec<(&str, &str)> = files.iter().map(|(p, t)| (*p, t.as_str())).collect();
        Copy::of(&files).build()
    };
    // The directory of the rule file in front, as written, and several files.
    assert!(build("words.data").is_ok());
    assert!(build("crs/rules/more.data").is_ok());
    assert!(build("flat.data").is_ok());
    assert!(build("words.data  flat.data").is_ok());
    // A name that the generation does not have, or that is not a plain path, is refused, and so is one of
    // many.
    for arg in [
        "missing.data",
        "words.data missing.data",
        "/etc/passwd",
        "../words.data",
        "rules/../rules/words.data",
        "./words.data",
        "$HOME/words.data",
        "*.data",
        "~/words.data",
        "https://example.com/words.data",
        "a/b/c/d/e.data",
        "manifest.json",
        "",
    ] {
        let refusal = build(arg)
            .err()
            .unwrap_or_else(|| panic!("{arg:?} is accepted"));
        assert!(
            refusal.reason().contains("file of the generation"),
            "{arg:?}: {refusal}"
        );
    }
    // @ipMatchFromFile reads the whole argument as one file.
    let ip = |arg: &str| {
        let text =
            format!("SecRule REMOTE_ADDR \"@ipMatchFromFile {arg}\" \"id:1,phase:1,pass\"\n");
        Copy::of(&[
            ("rules/a.conf", &text),
            ("rules/ips.data", "10.0.0.1\n"),
            ("rules/b.data", "x\n"),
        ])
        .build()
    };
    assert!(ip("ips.data").is_ok());
    assert!(ip("ips.data b.data").is_err());
}

// The library looks at the name from the working directory first, and a directory opens without an error and
// reads nothing: `etc` would be the directory `etc` of the generation, and not the file `rules/etc` that the
// rule file's directory in front of the name makes of it.
#[test]
fn a_name_that_is_a_directory_of_the_generation_is_refused() {
    let rule = "SecRule ARGS \"@pmFromFile etc\" \"id:1,phase:1,pass\"\n";
    let with_directory = Copy::of(&[
        ("rules/a.conf", rule),
        ("rules/etc", "attack\n"),
        ("etc/passwd", "root\n"),
    ]);
    let refusal = with_directory.build().err().unwrap();
    assert!(
        refusal.reason().contains("file of the generation"),
        "{refusal}"
    );
    // The same names with no directory of that name are read.
    let without = Copy::of(&[("rules/a.conf", rule), ("rules/etc", "attack\n")]);
    assert!(without.build().is_ok());
}

// The scanner keeps state between two files, and a file that stops inside a directive can leave it in a state
// that makes the next file be read wrongly. Every file of the Core Rule Set ends with a line break.
#[test]
fn a_file_that_does_not_end_with_a_line_break_is_refused() {
    for text in [
        "SecAction \"id:1,phase:1,pass\"",
        "SecRuleUpdateTargetById 1 ARGS",
        "# a comment",
    ] {
        let refusal = refused(text);
        assert!(
            refusal.reason().contains("line break"),
            "{text:?}: {refusal}"
        );
    }
    assert!(
        Copy::one("SecAction \"id:1,phase:1,pass\"\n")
            .build()
            .is_ok()
    );
}

#[test]
fn the_working_directory_is_the_root_while_the_library_reads_and_slash_after() {
    in_a_fresh_process(
        "rules::tests::the_working_directory_is_the_root_while_the_library_reads_and_slash_after",
        || {
            // The data file is named as it is at the root of the copy, so it is found only because the library
            // reads with the working directory there.
            let copy = Copy::of(&[
                (
                    "rules/a.conf",
                    "SecRule ARGS \"@pmFromFile root.data\" \"id:1,phase:1,pass\"\n",
                ),
                ("root.data", "attack\n"),
            ]);
            assert!(copy.build().is_ok());
            assert_eq!(working_directory(), PathBuf::from("/"));
            // The library refuses a rule that the checks accept (no such variable). This read comes last.
            let broken = Copy::one("SecRule NOSUCHVARIABLE \"@rx x\" \"id:1,phase:1,pass\"\n");
            let refusal = broken.build().err().unwrap();
            assert_eq!(
                (refusal.exit, refusal.file()),
                (EXIT_RULES, Some("rules/a.conf"))
            );
            assert!(!refusal.to_string().contains(broken.root.to_str().unwrap()));
            assert_eq!(working_directory(), PathBuf::from("/"));
        },
    );
}

#[test]
fn a_root_that_is_not_there_is_a_failure_of_the_environment() {
    let files = BTreeMap::from([("rules/a.conf".to_string(), RULE.as_bytes().to_vec())]);
    let load = vec!["rules/a.conf".to_string()];
    for root in ["relative", "/nonexistent-tkv-root"] {
        let refusal = build(
            std::path::Path::new(root),
            &files,
            &load,
            Restricted::assumed(),
        )
        .err()
        .unwrap();
        assert_eq!(refusal.exit, EXIT_ENVIRONMENT, "{root}");
    }
    assert_eq!(working_directory(), PathBuf::from("/"));
    // A rule file that the generation does not hold, and a load of no file, are refused.
    let root = std::env::temp_dir();
    assert_eq!(
        build(
            &root,
            &files,
            &["rules/b.conf".to_string()],
            Restricted::assumed()
        )
        .err()
        .unwrap()
        .exit,
        EXIT_RULES
    );
    assert_eq!(
        build(&root, &files, &[], Restricted::assumed())
            .err()
            .unwrap()
            .exit,
        EXIT_RULES
    );
}

// The rules that the library built are looked at once more, with no help from the text. Each text here is
// refused by the checks of the text, and the library is given it directly (so that those checks are not
// between), as if they had missed it: the look at the built rules finds it, and `verify` refuses.
#[test]
fn the_built_rules_are_looked_at_whatever_the_checks_of_the_text_read() {
    let rows = [
        (
            "SecAction \"id:4000001,phase:1,pass\"\n",
            Finding::ReservedId,
        ),
        (
            "SecAction \"id:1,phase:1,pass,setenv:A=B\"\n",
            Finding::SetEnv,
        ),
        (
            "SecAction \"id:1,phase:1,pass,CTL:RuleEngine=Off\"\n",
            Finding::Ctl,
        ),
        (
            "SecAction \"id:1,phase:1,pass,ctl:requestBodyAccess=Off\"\n",
            Finding::Ctl,
        ),
        // In the rule that is chained to a rule.
        (
            "SecRule ARGS \"@rx x\" \"id:1,phase:2,pass,chain\"\n    SecRule ARGS \"@rx y\" \"ctl:ruleEngine=Off\"\n",
            Finding::Ctl,
        ),
        (
            "SecRule ARGS \"@rx x\" \"id:1,phase:2,NOLOG,Deny\"\n",
            Finding::NoLog,
        ),
        (
            "SecRule ARGS \"@rx x\" \"id:1,phase:2,block,noauditlog\"\n",
            Finding::NoLog,
        ),
        // The library calls the action that it builds for redirect by another name.
        (
            "SecRule ARGS \"@rx x\" \"id:1,phase:2,redirect:/x,nolog\"\n",
            Finding::NoLog,
        ),
        (
            "SecDefaultAction \"phase:2,log,pass,nolog\"\n",
            Finding::NoLog,
        ),
        // The upper end of the reserved ids; the id after it is not reserved (below).
        (
            "SecAction \"id:4000011,phase:1,pass\"\n",
            Finding::ReservedId,
        ),
        // A default action is looked at as a rule is: one that holds an action that is not allowed.
        (
            "SecDefaultAction \"phase:2,log,pass,setenv:A=B\"\n",
            Finding::SetEnv,
        ),
        (
            "SecDefaultAction \"phase:2,log,pass,ctl:ruleEngine=Off\"\n",
            Finding::Ctl,
        ),
        (
            "SecDefaultAction \"phase:2,log,pass,ctl:requestBodyAccess=Off\"\n",
            Finding::Ctl,
        ),
        ("SecRequestBodyLimit 1\n", Finding::Setting),
        ("SecArgumentsLimit 1\n", Finding::Setting),
        ("SecUploadDir /nonexistent\n", Finding::Setting),
        ("SecAuditLog /nonexistent/audit.log\n", Finding::Setting),
        (
            "SecAction \"id:1,phase:1,pass\"\nSecRuleUpdateActionById 1 \"nolog\"\n",
            Finding::Other,
        ),
    ];
    for (text, finding) in rows {
        let copy = Copy::one(text);
        let (rules, paths) = copy.read_by_the_library();
        assert_eq!(rules.check(&paths), Ok(Some(finding)), "{text:?}");
        let refusal = load::check_kinds(&rules, &copy.root, &copy.load).unwrap_err();
        assert_eq!(
            (refusal.exit, refusal.file()),
            (EXIT_RULES, None),
            "{text:?}"
        );
        assert!(refusal.reason().contains("differ"), "{text:?}: {refusal}");
        assert_eq!(
            refused(text).exit,
            EXIT_RULES,
            "the checks of the text accept {text:?}"
        );
    }
    // A rule that none of the loaded files holds: here the second file, which is not among the paths.
    let copy = Copy::of(&[
        ("rules/a.conf", RULE),
        ("rules/b.conf", "SecAction \"id:2,phase:1,pass,nolog\"\n"),
    ]);
    let (rules, paths) = copy.read_by_the_library();
    assert_eq!(rules.check(&paths), Ok(None));
    assert_eq!(rules.check(&paths[..1]), Ok(Some(Finding::Foreign)));
    // A marker counts as well.
    let copy = Copy::of(&[("rules/a.conf", RULE), ("rules/b.conf", "SecMarker X\n")]);
    let (rules, paths) = copy.read_by_the_library();
    assert_eq!(rules.check(&paths), Ok(None));
    assert_eq!(rules.check(&paths[..1]), Ok(Some(Finding::Foreign)));
    // What is allowed is not found: the processor of the body, a rule that does not stop a request and has
    // no message, and the ids next to the reserved ones.
    for text in [
        "SecAction \"id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON\"\n",
        "SecAction \"id:4000000,phase:1,pass,nolog\"\nSecAction \"id:4000012,phase:1,pass\"\n",
        "SecRule ARGS \"@rx x\" \"id:1,phase:2,deny,log,chain\"\n    SecRule ARGS \"@rx y\" \"nolog\"\n",
        "SecDefaultAction \"phase:2,log,auditlog,pass\"\n",
    ] {
        assert_eq!(library_finds(text), None, "{text:?}");
    }
}

// The second look at the text: the words that the checks by name refuse are looked for in the text of a rule with
// its blanks and quotes taken out, so a word in a place where it does no harm (a message, a tag, an argument) is
// refused as well, and so is one that a spelling of the reader's could hide from the checks by name.
#[test]
fn a_word_that_must_not_be_there_is_refused_wherever_it_stands() {
    for text in [
        "SecAction \"id:1,phase:1,pass,msg:'see ctl:ruleEngine'\"\n",
        "SecAction \"id:1,phase:1,pass,msg:'e x e c : y'\"\n",
        "SecRule ARGS \"@rx x\" \"id:1,phase:1,pass,tag:'@rbl'\"\n",
        "SecRule ARGS \"@rx setenv:a\" \"id:1,phase:1,pass\"\n",
    ] {
        let refusal = refused(text);
        assert!(refusal.reason().contains("word"), "{text:?}: {refusal}");
    }
    assert!(
        Copy::one("SecAction \"id:1,phase:1,pass,msg:'see the rule engine'\"\n")
            .build()
            .is_ok()
    );
}

// What the library holds of the fixed settings is read back once it has read the files: a set that does not hold
// them is refused as that, and not as a difference between the rules.
#[test]
fn the_settings_that_the_library_holds_are_read_back_once_it_has_built() {
    let root = std::env::temp_dir();
    let mut off = Rules::new().unwrap();
    off.add_text("SecRuleEngine Off\n").unwrap();
    let refusal = load::settle(off, &root, &[], &model::Model::default())
        .err()
        .unwrap();
    assert_eq!((refusal.exit, refusal.file()), (EXIT_RULES, None));
    assert!(refusal.reason().contains("read back"), "{refusal}");
    // The set that holds the fixed settings is taken.
    let mut fixed = Rules::new().unwrap();
    fixed.add_text(load::FIXED_DIRECTIVES).unwrap();
    assert!(load::settle(fixed, &root, &[], &model::Model::default()).is_ok());
}

/// The directory of the Core Rule Set that the test is given.
fn crs_dir() -> PathBuf {
    match std::env::var("TUKUYOMI_TEST_CRS") {
        Ok(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => panic!(
            "TUKUYOMI_TEST_CRS is not set: this test needs the Core Rule Set and is never skipped"
        ),
    }
}

/// The files of the Core Rule Set in the directory `dir`, and the ones that are loaded.
fn crs_files(dir: &std::path::Path) -> (BTreeMap<String, Vec<u8>>, Vec<String>) {
    // The files as a bundle of the Core Rule Set holds them: the setup file, then the rule files by the
    // bytes of their names; the data files are present and are not loaded.
    let mut files = BTreeMap::new();
    let mut load = vec!["crs/crs-setup.conf".to_string()];
    files.insert(
        load[0].clone(),
        fs::read(dir.join("crs-setup.conf")).unwrap(),
    );
    let mut names: Vec<OsString> = fs::read_dir(dir.join("rules"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    names.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    for name in names {
        let text = name.to_str().unwrap().to_string();
        let path = format!("crs/rules/{text}");
        if text.ends_with(".conf") || text.ends_with(".data") {
            files.insert(
                path.clone(),
                fs::read(dir.join("rules").join(&text)).unwrap(),
            );
        }
        if text.ends_with(".conf") {
            load.push(path);
        }
    }
    (files, load)
}

#[test]
#[ignore = "needs the Core Rule Set"]
fn the_core_rule_set_builds() {
    let (files, load) = crs_files(&crs_dir());
    let copy = Copy::new(files, load);
    let rules = copy
        .build()
        .unwrap_or_else(|r| panic!("the Core Rule Set is refused: {r}"));
    assert_eq!(
        rules.settings(),
        Ok(Settings {
            engine: EngineState::On,
            body_access: Some(true),
            json_depth_limit: Some(64)
        })
    );
    assert_eq!(working_directory(), PathBuf::from("/"));
}
