//! What the library built from the rule files is compared with what the reader read, and the process
//! restricts itself before it builds.

use super::reader::{compared, described, refused_as_a_form};
use super::*;
use crate::ffi::tests::in_a_restricted_process;
use std::fs::DirBuilder;
use std::os::unix::fs::DirBuilderExt;

/// What the library builds from `built` when `read` is what the reader read: the part of `build` that follows
/// the checks of the text.
pub(super) fn assembled(read: &str, built: &str) -> Result<(), Refusal> {
    let of = |text: &str| Copy::of(&[("rules/a.conf", text), ("rules/a.data", "x\n")]);
    let model = model_of(&of(read));
    let building = of(built);
    load::assemble(&building.root, &building.load, &model).map(drop)
}

const A: &str = "SecRule ARGS \"@contains a\" \"id:1,phase:2,pass,log\"\n";
const B: &str = "SecRule ARGS \"@contains b\" \"id:2,phase:2,deny,log,status:403\"\n";
const C: &str = "SecRule ARGS \"@contains c\" \"id:3,phase:2,log\"\n";
const DEFAULTS: &str = "SecDefaultAction \"phase:2,log,auditlog,pass\"\n";

// A text that the reader and the library cut in two ways builds as another set of rules than the reader read,
// whichever way it differs: a rule that the library does not make is a rule less, a name with a blank in front
// of it is another name, and an action that it finds in a value is an action more. Here the reader read `read`
// and the library read `built`.
#[test]
fn a_set_is_taken_only_when_it_is_what_the_reader_read() {
    let rich = format!(
        "{DEFAULTS}SecMarker M\n{A}{B}SecRule ARGS \"!@rx x\" \"id:3,phase:1,pass,log,chain,msg:'m',tag:'t',tag:'u',setvar:tx.a=1,t:lowercase,t:none,severity:'CRITICAL',rev:'1',ver:'v',accuracy:'2',maturity:'3',capture,multiMatch,ctl:auditEngine=On,ctl:ruleRemoveById=9,skip:1,status:403\"\n    SecRule ARGS \"@pmFromFile a.data\" \"t:none\"\nSecAction \"id:4,phase:request,pass,nolog,setvar:tx.b=2\"\nSecMarker N\nSecComponentSignature \"X/1\"\nSecResponseBodyAccess On\nSecResponseBodyMimeType text/plain\nSecRuleRemoveById 1 5-9\nSecRuleRemoveByTag t\nSecRuleRemoveByMsg \"a b\"\nSecRuleUpdateTargetById 3 \"!ARGS:x\"\nSecAuditEngine Off\n"
    );
    let rows: Vec<(&str, String, String)> = vec![
        ("a rule more", A.into(), format!("{A}{B}")),
        ("a rule less", format!("{A}{B}"), A.into()),
        ("another order", format!("{A}{B}"), format!("{B}{A}")),
        ("another phase", A.into(), A.replace("phase:2", "phase:1")),
        ("another id", A.into(), A.replace("id:1", "id:3")),
        ("another operator", A.into(), A.replace("@contains", "@rx")),
        (
            "another disruptive action",
            B.into(),
            B.replace("deny", "drop"),
        ),
        ("a disruptive action less", B.into(), B.replace("deny,", "")),
        (
            "an action more",
            A.into(),
            A.replace("pass,log", "pass,log,nolog"),
        ),
        (
            "a skipAfter that the reader did not see",
            format!("{A}SecMarker X\n"),
            format!(
                "{}SecMarker X\n",
                A.replace("pass,log", "pass,log,skipAfter:X")
            ),
        ),
        (
            "another skipAfter name",
            format!(
                "{}SecMarker X\nSecMarker Y\n",
                A.replace("pass,log", "pass,log,skipAfter:X")
            ),
            format!(
                "{}SecMarker X\nSecMarker Y\n",
                A.replace("pass,log", "pass,log,skipAfter:Y")
            ),
        ),
        (
            "another skip number",
            A.replace("pass,log", "pass,log,skip:1"),
            A.replace("pass,log", "pass,log,skip:2"),
        ),
        (
            "another ctl value",
            A.replace("pass,log", "pass,log,ctl:ruleRemoveById=1"),
            A.replace("pass,log", "pass,log,ctl:ruleRemoveById=2"),
        ),
        (
            "a chain that the reader did not see",
            format!("{A}{C}"),
            format!("{}{C}", A.replace("pass,log", "pass,log,chain")),
        ),
        (
            "a marker with a blank in front of its name",
            "SecMarker X\n".into(),
            "SecMarker  X\n".into(),
        ),
        (
            "a marker more",
            "SecMarker X\n".into(),
            "SecMarker X\nSecMarker X\n".into(),
        ),
        (
            "another default action",
            DEFAULTS.into(),
            DEFAULTS.replace("pass", "pass,t:lowercase"),
        ),
        (
            "another phase of a default action",
            DEFAULTS.into(),
            DEFAULTS.replace("phase:2", "phase:1"),
        ),
        (
            "a tag more",
            A.replace("log", "log,tag:'a'"),
            A.replace("log", "log,tag:'a',tag:'b'"),
        ),
        (
            "a setvar more",
            A.replace("log", "log,setvar:tx.a=1"),
            A.replace("log", "log,setvar:tx.a=1,setvar:tx.b=1"),
        ),
        (
            "a transformation more",
            A.replace("log", "log,t:none"),
            A.replace("log", "log,t:none,t:lowercase"),
        ),
        ("a message less", A.replace("log", "log,msg:'x'"), A.into()),
        (
            "another severity",
            A.replace("log", "log,severity:'CRITICAL'"),
            A.replace("log", "log,severity:'ERROR'"),
        ),
        (
            "another rev",
            A.replace("log", "log,rev:'1'"),
            A.replace("log", "log,rev:'2'"),
        ),
        (
            "another maturity",
            A.replace("log", "log,maturity:'1'"),
            A.replace("log", "log,maturity:'2'"),
        ),
        ("a capture less", A.replace("log", "log,capture"), A.into()),
        (
            "another component",
            "SecComponentSignature \"a\"\n".into(),
            "SecComponentSignature \"b\"\n".into(),
        ),
        (
            "a setting that the reader did not read",
            String::new(),
            "SecResponseBodyAccess On\n".into(),
        ),
        (
            "another removed id",
            "SecRuleRemoveById 1\n".into(),
            "SecRuleRemoveById 2\n".into(),
        ),
        (
            "another removed tag",
            "SecRuleRemoveByTag a\n".into(),
            "SecRuleRemoveByTag b\n".into(),
        ),
        (
            "another audit engine",
            String::new(),
            "SecAuditEngine Off\n".into(),
        ),
    ];
    for (what, read, built) in rows.iter().chain(&parts_that_are_compared()) {
        assert!(
            crate::rules::reader::read(read.as_bytes()).is_ok(),
            "{what}: the reader refuses what it should have read"
        );
        let refusal = match assembled(read, built) {
            Ok(()) => panic!("{what}: taken"),
            Err(refusal) => refusal,
        };
        assert_eq!(refusal.exit, EXIT_RULES, "{what}");
        assert!(refusal.reason().contains("differ"), "{what}: {refusal}");
    }
    // The same text is taken, whatever it holds. The values that the library keeps in a form of its own are
    // read in that form: the name that a `skipAfter` in quotes holds (the first and the last byte are cut
    // off), and the text of the `ctl` actions that the parser makes from fixed words.
    let ctl = |action: &str| format!("SecAction \"id:1,phase:1,pass,ctl:{action}\"\n");
    let controls = [
        "SecAction \"id:1,phase:1,pass,skipAfter:''\"\nSecMarker X\n".to_owned(),
        "SecAction \"id:1,phase:1,pass,skipAfter:'ab\"\nSecMarker a\n".to_owned(),
        "SecAction \"id:1,phase:1,pass,skipAfter:'ab'\"\nSecMarker ab\n".to_owned(),
        ctl("parseXmlIntoArgs=OnlyArgs"),
        ctl("forceRequestBodyVariable=On"),
        ctl("auditEngine=RelevantOnly"),
        ctl("requestBodyProcessor=JSON"),
        ctl("ruleRemoveByTag=attack-sqli"),
    ];
    for text in [A.to_owned(), format!("{A}{B}"), rich, VARIETY.to_owned()]
        .into_iter()
        .chain(controls)
    {
        if let Err(refusal) = assembled(&text, &text) {
            panic!("refused ({refusal}): {text:?}");
        }
    }
}

/// Rules that use every part that is compared, as the reader reads them and the library builds them.
const VARIETY: &str = "SecDefaultAction \"phase:2,log,auditlog,pass,msg:'d %{tx.m}',tag:'dt',setvar:tx.d=+1\"\nSecRule ARGS|!ARGS:a|&REQUEST_COOKIES|REQUEST_HEADERS:User-Agent|ARGS:/^b+$/|XML:/*|!REQUEST_COOKIES:/__utm/ \"!@rx a%{tx.x}b%c\" \"id:5,phase:2,pass,log,msg:'m %{tx.1} x',logdata:'%{MATCHED_VAR_NAME}',tag:'a',tag:'%{rule.id}',setvar:tx.a=1,setvar:'tx.b=+%{tx.c}',setvar:'tx.%{rule.id}-%{MATCHED_VAR_NAME}=%{tx.0}',setvar:!tx.e,setvar:tx.f=-2,setvar:ip.g\"\nSecRuleUpdateTargetById 5 \"ARGS:a|!ARGS:b|&ARGS:c|ARGS:/d/\"\nSecRuleUpdateTargetByTag t REQUEST_HEADERS:Host\nSecRuleUpdateTargetByMsg \"m\" ARGS\n";

/// Each part of a rule that is compared with what the library built, once changed and nothing else: the text that
/// the reader read, and the text that the library read instead.
fn parts_that_are_compared() -> Vec<(&'static str, String, String)> {
    const V: &str = "SecRule ARGS:a \"@contains a\" \"id:1,phase:2,pass,log\"\n";
    const D: &str = "SecDefaultAction \"phase:2,log,pass,";
    let var = |from: &str, to: &str| (V.replace("ARGS:a", from), V.replace("ARGS:a", to));
    let action = |from: &str, to: &str| {
        (
            V.replace("pass,log", &format!("pass,log,{from}")),
            V.replace("pass,log", &format!("pass,log,{to}")),
        )
    };
    let default = |from: &str, to: &str| (format!("{D}{from}\"\n"), format!("{D}{to}\"\n"));
    let update = |from: &str, to: &str| {
        (
            format!("SecRuleUpdateTarget{from}\n"),
            format!("SecRuleUpdateTarget{to}\n"),
        )
    };
    let mut rows = Vec::new();
    let mut row =
        |what: &'static str, (read, built): (String, String)| rows.push((what, read, built));
    row("another collection", var("ARGS:a", "ARGS_GET:a"));
    row("another selector", var("ARGS:a", "ARGS:b"));
    row("a variable more", var("ARGS:a", "ARGS:a|ARGS:b"));
    row("a count", var("&ARGS:a", "ARGS:a"));
    row("another excluded name", var("ARGS|!ARGS:a", "ARGS|!ARGS:b"));
    row(
        "another excluded expression",
        var("ARGS|!ARGS:/a/", "ARGS|!ARGS:/b/"),
    );
    row("an expression for a name", var("ARGS:/a/", "ARGS:a"));
    row(
        "a negated operator",
        (V.into(), V.replace("\"@contains", "\"!@contains")),
    );
    row(
        "another argument",
        (V.into(), V.replace("contains a", "contains b")),
    );
    row(
        "another macro in the argument",
        (
            V.replace("contains a", "rx %{tx.a}"),
            V.replace("contains a", "rx %{tx.b}"),
        ),
    );
    row(
        "a macro for text in the argument",
        (
            V.replace("contains a", "rx a"),
            V.replace("contains a", "rx %{tx.a}"),
        ),
    );
    row("another message", action("msg:'x'", "msg:'y'"));
    row(
        "another macro in a message",
        action("msg:'x %{tx.a}'", "msg:'x %{tx.b}'"),
    );
    row("another log data", action("logdata:'x'", "logdata:'y'"));
    row(
        "another macro in the log data",
        action("logdata:'%{tx.a}'", "logdata:'%{tx.b}'"),
    );
    row("another tag", action("tag:'a'", "tag:'b'"));
    row(
        "another macro in a tag",
        action("tag:'%{tx.a}'", "tag:'%{tx.b}'"),
    );
    row(
        "another value of a setvar",
        action("setvar:tx.a=1", "setvar:tx.a=2"),
    );
    row(
        "another variable of a setvar",
        action("setvar:tx.a=1", "setvar:tx.b=1"),
    );
    row(
        "another collection of a setvar",
        action("setvar:tx.a=1", "setvar:ip.a=1"),
    );
    row(
        "another operation of a setvar",
        action("setvar:tx.a=+1", "setvar:tx.a=-1"),
    );
    row(
        "a removal for a setting to one",
        action("setvar:!tx.a", "setvar:tx.a"),
    );
    row(
        "another macro in the value of a setvar",
        action("setvar:tx.a=%{tx.b}", "setvar:tx.a=%{tx.c}"),
    );
    row(
        "another macro in the selector of a setvar",
        action("setvar:tx.%{rule.id}=1", "setvar:tx.%{matched_var_name}=1"),
    );
    row(
        "another message in a default action",
        default("msg:'a'", "msg:'b'"),
    );
    row(
        "another tag in a default action",
        default("tag:'a'", "tag:'b'"),
    );
    row(
        "another setvar in a default action",
        default("setvar:tx.a=1", "setvar:tx.a=2"),
    );
    row(
        "another variable in an update of a target by id",
        update("ById 3 ARGS:x", "ById 3 ARGS:y"),
    );
    row(
        "another variable in an update of a target by tag",
        update("ByTag t ARGS:x", "ByTag t ARGS:y"),
    );
    row(
        "another variable in an update of a target by message",
        update("ByMsg m ARGS:x", "ByMsg m ARGS:y"),
    );
    row(
        "another modifier in an update of a target",
        update("ById 3 &ARGS", "ById 3 ARGS"),
    );
    rows
}

// The environment of the process is not for a rule to read, and the scanner reads it where a reader that cuts a
// name by its letters, or a selector up to the next `|`, does not look: after a comma that ends a selector, glued to
// another name, and in a macro. The library builds each of these texts and reads the environment in them. The reader
// refuses them, and when a reader that does not see the environment has read them (the text under it) what the
// library built is refused as not being what was read.
#[test]
fn the_environment_is_refused_where_the_scanner_reads_it() {
    let rule = |variables: &str, operator: &str, actions: &str| {
        format!("SecRule {variables} \"{operator}\" \"{actions}\"\n")
    };
    let pass = "id:1,phase:2,pass,log";
    let rows = [
        // A selector ends at a comma, and the next variable starts there.
        (
            rule("ARGS:a,ENV:x", "@rx x", pass),
            rule("ARGS:a", "@rx x", pass),
        ),
        (
            rule("ARGS:/a/,ENV:x", "@rx x", pass),
            rule("ARGS:/a/", "@rx x", pass),
        ),
        // A name is glued to another.
        (
            rule("ARGS|ARGSENV:x", "a%b", pass),
            rule("ARGS|ARGS", "a%b", pass),
        ),
        (rule("ARGSENV", "a%b", pass), rule("ARGS", "a%b", pass)),
        // A macro, in each place that the library keeps its text.
        (
            rule("ARGS", "@rx x", "id:1,phase:2,pass,msg:'%{ARGSenv.x}'"),
            rule("ARGS", "@rx x", "id:1,phase:2,pass,msg:'%{ARGS.x}'"),
        ),
        (
            rule("ARGS", "@rx x", "id:1,phase:2,pass,logdata:'%{ARGSenv.x}'"),
            rule("ARGS", "@rx x", "id:1,phase:2,pass,logdata:'%{ARGS.x}'"),
        ),
        (
            rule("ARGS", "@rx x", "id:1,phase:2,pass,tag:'%{ARGSenv.x}'"),
            rule("ARGS", "@rx x", "id:1,phase:2,pass,tag:'%{ARGS.x}'"),
        ),
        (
            rule(
                "ARGS",
                "@rx x",
                "id:1,phase:2,pass,setvar:tx.a=%{ARGSenv.x}",
            ),
            rule("ARGS", "@rx x", "id:1,phase:2,pass,setvar:tx.a=%{ARGS.x}"),
        ),
        (
            rule("ARGS", "@rx %{ARGSenv.x}", pass),
            rule("ARGS", "@rx %{ARGS.x}", pass),
        ),
        (
            rule("ARGS", "@rx %{ARGSENV:ENV.x}", pass),
            rule("ARGS", "@rx %{ARGS:x}", pass),
        ),
        // The actions that keep their text in a member of their own: the one that stops the rule, and the ones
        // that run when it matches.
        (
            rule("ARGS", "@rx x", "id:1,phase:2,log,redirect:%{ARGSenv.x}"),
            rule("ARGS", "@rx x", "id:1,phase:2,log,redirect:%{ARGS.x}"),
        ),
        (
            rule("ARGS", "@rx x", "id:1,phase:2,pass,log,setsid:%{ARGSenv.x}"),
            rule("ARGS", "@rx x", "id:1,phase:2,pass,log,setsid:%{ARGS.x}"),
        ),
        (
            rule(
                "ARGS",
                "@rx x",
                "id:1,phase:2,pass,log,setuid:'%{ARGSenv.x}'",
            ),
            rule("ARGS", "@rx x", "id:1,phase:2,pass,log,setuid:'%{ARGS.x}'"),
        ),
        (
            rule("ARGS", "@rx x", "id:1,phase:2,pass,log,setrsc:%{ARGSENV:x}"),
            rule("ARGS", "@rx x", "id:1,phase:2,pass,log,setrsc:%{ARGS:x}"),
        ),
        (
            rule(
                "ARGS",
                "@rx x",
                "id:1,phase:2,pass,log,expirevar:tx.a=%{ARGSenv.x}",
            ),
            rule(
                "ARGS",
                "@rx x",
                "id:1,phase:2,pass,log,expirevar:tx.a=%{ARGS.x}",
            ),
        ),
        (
            rule(
                "ARGS",
                "@rx x",
                "id:1,phase:2,pass,log,initcol:ip=%{ARGSenv.x}",
            ),
            rule(
                "ARGS",
                "@rx x",
                "id:1,phase:2,pass,log,initcol:ip=%{ARGS.x}",
            ),
        ),
        // An update of a target takes the same list.
        (
            "SecRuleUpdateTargetById 1 ARGS:a,ENV:x\n".to_owned(),
            "SecRuleUpdateTargetById 1 ARGS:a\n".to_owned(),
        ),
    ];
    for (hidden, plain) in &rows {
        assert!(described(hidden).contains("3:env\n"), "{hidden:?}");
        refused_as_a_form(hidden);
        assert!(Copy::one(plain).build().is_ok(), "{plain:?}");
        let refusal = assembled(plain, hidden).unwrap_err();
        assert!(refusal.reason().contains("differ"), "{hidden:?}: {refusal}");
        assert_eq!(compared(hidden), "refused by the reader");
    }
}

// The library drops a chain by a recursion as long as the chain, which overflows the stack of a thread with a
// small one when the chain is long, so a chain holds at most 64 rules, the rule that starts it included.
#[test]
fn a_chain_of_more_than_64_rules_is_refused() {
    let chain = |rules: usize| {
        let mut text = String::from("SecRule ARGS \"@rx x\" \"id:1,phase:2,pass,chain\"\n");
        for _ in 2..rules {
            text.push_str("SecRule ARGS \"@rx x\" \"chain\"\n");
        }
        text.push_str("SecRule ARGS \"@rx x\"\n");
        text
    };
    if let Err(refusal) = Copy::one(&chain(64)).build() {
        panic!("refused ({refusal})");
    }
    let refusal = refused(&chain(65));
    assert_eq!(
        (refusal.exit, refusal.file()),
        (EXIT_RULES, Some("rules/a.conf"))
    );
    assert!(refusal.reason().contains("chain"), "{refusal}");
}

// A rule that follows a rule with `chain` is in the phase of the rule that starts the chain, whatever its own
// actions say. Here that is the phase of the library for `phase:2`, where the phase of a rule that says none is
// another one.
#[test]
fn a_chained_rule_is_in_the_phase_of_the_rule_that_starts_the_chain() {
    let chain =
        "SecRule ARGS \"@rx x\" \"id:1,phase:2,pass,log,chain\"\n    SecRule ARGS \"@rx y\"\n";
    if let Err(refusal) = Copy::one(chain).build() {
        panic!("refused ({refusal})");
    }
}

// The files are read each by itself: a rule that follows a rule with `chain` is its child only in its own file,
// and the settings that the files hold are merged in the order of the files, the first value staying.
#[test]
fn what_the_files_set_is_merged_as_the_library_merges_it() {
    let copy = Copy::of(&[
        (
            "rules/a.conf",
            "SecRule ARGS \"@contains a\" \"id:1,phase:2,pass,log,chain\"\nSecResponseBodyAccess On\nSecResponseBodyLimit 5\nSecResponseBodyLimitAction Reject\nSecResponseBodyMimeType text/plain\nSecComponentSignature \"A\"\nSecRuleRemoveById 1 5-9\n",
        ),
        (
            "rules/b.conf",
            "SecRule ARGS \"@contains b\" \"id:2,phase:2,pass,log\"\nSecResponseBodyAccess Off\nSecResponseBodyLimit 9\nSecResponseBodyLimitAction ProcessPartial\nSecResponseBodyMimeType text/html\nSecComponentSignature \"B\"\nSecRuleRemoveById 2\nSecAuditEngine Off\n",
        ),
        (
            "rules/c.conf",
            "SecResponseBodyMimeTypesClear\nSecResponseBodyMimeType x/y\nSecResponseBodyAccess Off\nSecRuleRemoveByMsg \"m\"\n",
        ),
    ]);
    if let Err(refusal) = copy.build() {
        panic!("refused: {refusal}");
    }
}

/// A set of rules that the library holds after the fixed directives and `text`, as `build` makes it, with
/// the library reading the text itself (`text` may hold a directive that the reader refuses).
fn library_reads(text: &str) -> Rules {
    let mut rules = Rules::new().unwrap();
    rules.add_text(load::FIXED_DIRECTIVES).unwrap();
    rules
        .add_text(text)
        .unwrap_or_else(|e| panic!("the library refuses {text:?}: {e}"));
    rules
}

/// A directory with `inside` and `outside` in it, under the temporary directory, removed when it goes out of
/// scope.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Scratch {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "tkv-restricted-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        for sub in ["", "inside", "outside"] {
            DirBuilder::new().mode(0o700).create(dir.join(sub)).unwrap();
        }
        Scratch(dir)
    }

    fn inside(&self) -> PathBuf {
        self.0.join("inside")
    }

    fn outside(&self) -> PathBuf {
        self.0.join("outside")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// Every setting that the library holds is part of what is compared. Each row is a directive (that the reader
// refuses, or reads and takes for a setting that it keeps) that sets one setting; the rules set with it is not
// what an empty reading gives. (The empty reading is the control: the fixed directives alone are.) No
// directive sets the upload temporary directory, and none sets what to do when remote rules fail (the library
// does not merge it into the rules set), and the audit engine turned on by a `ctl` action is a part of the
// text of a rule (see the first test of this file).
#[test]
fn every_setting_that_the_library_holds_is_compared() {
    in_a_fresh_process(
        "rules::tests::built::every_setting_that_the_library_holds_is_compared",
        || {
            let scratch = Scratch::new();
            let inside = scratch.inside().display().to_string();
            fs::write(
                scratch.inside().join("unicode.mapping"),
                "20127 (US-ASCII)\n0041:0041\n",
            )
            .unwrap();
            let rows: Vec<(&str, String)> = vec![
                ("response_body_access", "SecResponseBodyAccess On".into()),
                ("xml_external_entity", "SecXmlExternalEntity On".into()),
                ("xml_parse_into_args", "SecParseXmlIntoArgs On".into()),
                (
                    "tmp_save_uploaded_files",
                    "SecTmpSaveUploadedFiles On".into(),
                ),
                ("upload_keep_files", "SecUploadKeepFiles On".into()),
                (
                    "request_body_limit_action",
                    "SecRequestBodyLimitAction Reject".into(),
                ),
                (
                    "response_body_limit_action",
                    "SecResponseBodyLimitAction Reject".into(),
                ),
                ("arguments_limit", "SecArgumentsLimit 1".into()),
                ("request_body_limit", "SecRequestBodyLimit 1".into()),
                (
                    "request_body_no_files_limit",
                    "SecRequestBodyNoFilesLimit 1".into(),
                ),
                ("response_body_limit", "SecResponseBodyLimit 1".into()),
                ("pcre_match_limit", "SecPcreMatchLimit 1".into()),
                ("upload_file_limit", "SecUploadFileLimit 1".into()),
                ("upload_file_mode", "SecUploadFileMode 0600".into()),
                ("http_bl_key", "SecHttpBlKey x".into()),
                ("upload_directory", format!("SecUploadDir {inside}")),
                ("argument_separator", "SecArgumentSeparator ;".into()),
                ("web_app_id", "SecWebAppId x".into()),
                (
                    "unicode_map",
                    format!("SecUnicodeMapFile {inside}/unicode.mapping 20127"),
                ),
                (
                    "response_body_types",
                    "SecResponseBodyMimeType text/plain".into(),
                ),
                (
                    "response_body_types (cleared)",
                    "SecResponseBodyMimeTypesClear".into(),
                ),
                ("components", "SecComponentSignature \"x\"".into()),
                ("removed_numbers", "SecRuleRemoveById 1".into()),
                ("removed_ranges", "SecRuleRemoveById 1-5".into()),
                ("removed_by_msg", "SecRuleRemoveByMsg x".into()),
                ("removed_by_tag", "SecRuleRemoveByTag x".into()),
                (
                    "update_target_by_id",
                    "SecRuleUpdateTargetById 1 ARGS".into(),
                ),
                (
                    "update_target_by_tag",
                    "SecRuleUpdateTargetByTag x ARGS".into(),
                ),
                (
                    "update_target_by_msg",
                    "SecRuleUpdateTargetByMsg x ARGS".into(),
                ),
                (
                    "action_updates",
                    "SecRuleUpdateActionById 1 \"nolog\"".into(),
                ),
                ("audit path", format!("SecAuditLog {inside}/a.log")),
                ("audit path 2", format!("SecAuditLog2 {inside}/b.log")),
                (
                    "audit storage dir",
                    format!("SecAuditLogStorageDir {inside}"),
                ),
                ("audit prefix", "SecAuditLogPrefix x".into()),
                ("audit format", "SecAuditLogFormat JSON".into()),
                ("audit status", "SecAuditEngine Off".into()),
                ("audit type", "SecAuditLogType Serial".into()),
                (
                    "audit relevant status",
                    "SecAuditLogRelevantStatus ^4".into(),
                ),
                ("audit parts", "SecAuditLogParts ABZ".into()),
                ("audit file mode", "SecAuditLogFileMode 0600".into()),
                ("audit directory mode", "SecAuditLogDirMode 0700".into()),
                ("debug log file", format!("SecDebugLog {inside}/d.log")),
                ("debug log level", "SecDebugLogLevel 3".into()),
            ];
            // The control: the fixed directives alone are what an empty reading gives.
            assert!(load::compare(&library_reads(""), &model::Model::default()).is_ok());
            for (member, text) in &rows {
                let rules = library_reads(&format!("{text}\n"));
                assert!(
                    load::compare(&rules, &model::Model::default()).is_err(),
                    "{member}: {text}"
                );
            }
            // The three that the inspector sets first: a set that was not given them is not the one that is
            // wanted, whatever the files say.
            for text in [
                "SecRuleEngine Off\n",
                "SecRequestBodyAccess Off\n",
                "SecRequestBodyJsonDepthLimit 1000\n",
            ] {
                let mut rules = Rules::new().unwrap();
                rules.add_text(text).unwrap();
                assert!(
                    load::compare(&rules, &model::Model::default()).is_err(),
                    "{text}"
                );
            }
        },
    );
}

// A set that the reader read is compared inside `build` too, with the checks of the text out of the way: a text
// of rules that the checks of the text refuse, handed to the library as it is, is refused by what is built.
// Each text is one that the reader reads whole; the model is what it read, and only the kind of what was
// built is refused.
#[test]
fn what_is_built_is_looked_at_inside_build_too() {
    for text in [
        "SecAction \"id:4000001,phase:1,pass\"\n",
        "SecAction \"id:4000011,phase:1,pass\"\n",
        "SecRule ARGS \"@rx x\" \"id:1,phase:2,deny,nolog\"\n",
        "SecAction \"id:1,phase:1,pass,ctl:ruleEngine=Off\"\n",
        "SecDefaultAction \"phase:2,log,pass,nolog\"\n",
        "SecDefaultAction \"phase:2,log,pass,ctl:requestBodyAccess=Off\"\n",
    ] {
        let copy = Copy::one(text);
        let refusal = match load::assemble(&copy.root, &copy.load, &model_of(&copy)) {
            Ok(_) => panic!("taken: {text:?}"),
            Err(refusal) => refusal,
        };
        assert_eq!(refusal.exit, EXIT_RULES, "{text:?}");
        assert!(refusal.reason().contains("differ"), "{text:?}: {refusal}");
    }
    let copy = Copy::one(RULE);
    assert!(load::assemble(&copy.root, &copy.load, &model_of(&copy)).is_ok());
}

// The process restricts itself to the directory that holds the copy before it builds the rules, so the Core
// Rule Set has to build in a process that has done that: the library opens only the files of the copy.
#[test]
#[ignore = "needs the Core Rule Set"]
fn the_core_rule_set_builds_in_a_process_that_has_restricted_itself() {
    in_a_fresh_process(
        "rules::tests::built::the_core_rule_set_builds_in_a_process_that_has_restricted_itself",
        || {
            let (files, load) = crs_files(&crs_dir());
            let scratch = Scratch::new();
            let copy = Copy::in_dir(scratch.inside().join("copy"), files, load);
            let report = in_a_restricted_process(&scratch.inside(), |restricted| {
                match copy.build_with(restricted) {
                    Ok(rules) => format!("built {:?}", rules.settings()),
                    Err(refusal) => format!("refused: {refusal}"),
                }
            });
            assert!(report.starts_with("built "), "{report}");
        },
    );
}

// Whatever gets past the checks of the text, once the process has restricted itself the library cannot open
// a file outside the copy, to read or to write: the text is handed to the library with no check, a file
// that it names outside is not opened, and nothing is created there.
#[test]
fn a_text_that_names_a_file_outside_is_refused_by_the_library_once_the_process_has_restricted_itself()
 {
    in_a_fresh_process(
        "rules::tests::built::a_text_that_names_a_file_outside_is_refused_by_the_library_once_the_process_has_restricted_itself",
        || {
            let scratch = Scratch::new();
            let (outside, inside) = (scratch.outside(), scratch.inside());
            let rules_file = outside.join("rules.conf");
            fs::write(&rules_file, "SecAction \"id:7,phase:1,pass\"\n").unwrap();
            let include = format!("Include {}\n", rules_file.display());
            let debug_log = outside.join("debug.log");
            let debug = format!("SecDebugLog {}\nSecDebugLogLevel 3\n", debug_log.display());

            // Without the restriction the library takes both: it opens the file and it creates the log.
            let control_log = outside.join("control.log");
            Rules::new().unwrap().add_text(&include).unwrap();
            Rules::new()
                .unwrap()
                .add_text(&debug.replace("debug.log", "control.log"))
                .unwrap();
            assert!(control_log.exists());

            // After it the library refuses them (the reads that are refused come last), and creates nothing.
            for text in [include, debug] {
                let report = in_a_restricted_process(&inside, |_| {
                    format!("{:?}", Rules::new().unwrap().add_text(&text))
                });
                assert_eq!(report, "Err(Rules)", "{text}");
            }
            assert!(!debug_log.exists());
        },
    );
}
