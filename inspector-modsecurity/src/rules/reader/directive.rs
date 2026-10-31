//! The directives of the rule language that a rule file may use, and in what form.
//!
//! The list is the one that the scanner of libmodsecurity 3.0.17 knows. A directive is allowed when it is
//! needed to write rules and cannot make the engine read or write a file, reach out to another machine, run
//! a program, or change what the inspector decides about the request body. The others are refused by name,
//! with the reason that is nearest. A name that the scanner does not know is refused too: the library would
//! not read it.

use super::scan::Reason;

pub(in crate::rules) const INCLUDE: Reason = "the Include directive is not allowed";
pub(in crate::rules) const REMOTE_RULES: Reason = "the SecRemoteRules directives are not allowed";
pub(in crate::rules) const IGNORE_ERRORS: Reason =
    "the SecIgnoreRuleCompilationErrors directive is not allowed";
pub(in crate::rules) const OUTPUT_FILES: Reason =
    "the SecAuditLog, SecDebugLog and SecUpload directives are not allowed";
pub(in crate::rules) const DIRECTORIES: Reason =
    "the SecDataDir and SecTmpDir directives are not allowed";
pub(in crate::rules) const LIMITS: Reason =
    "a directive that sets a limit of the request body or of the arguments is not allowed";
pub(in crate::rules) const NOT_ALLOWED: Reason = "a directive that is not allowed is used";
pub(in crate::rules) const UNKNOWN: Reason = "a directive is not known to the engine library";

/// How the text after the name of a directive is read.
pub(in crate::rules) enum Shape {
    /// `SecRule`: variables, an operator and actions.
    Rule,
    /// `SecAction` and `SecDefaultAction`: actions.
    Actions,
    /// `SecMarker`: a name.
    Marker,
    /// `SecRuleUpdateTargetById`, `...ByTag` and `...ByMsg`: what to update and the variables.
    Targets,
    /// A directive with one argument of a plain form, on its own line.
    Argument(Form),
}

/// The forms of the argument of a plain directive.
#[derive(Clone, Copy)]
pub(in crate::rules) enum Form {
    /// `On`, `Off` or `DetectionOnly`.
    Engine,
    /// `On` or `Off`.
    Switch,
    /// `Off`: turning the audit engine on would open a log that the rules cannot place.
    AuditOff,
    /// Digits.
    Number,
    /// `ProcessPartial` or `Reject`.
    BodyLimitAction,
    /// A string in double quotes.
    Quoted,
    /// A word or a string in double quotes: a tag or a message.
    Selector,
    /// Rule ids and ranges of ids: digits, `-` and blanks.
    Ids,
    /// MIME types: letters, digits, `/ + . _ * - ; =` and blanks.
    Words,
    /// No argument.
    Nothing,
}

/// The shape of the directive with the (lower case) name `keyword`, or the reason it is refused.
pub(in crate::rules) fn shape(keyword: &str) -> Result<Shape, Reason> {
    use Form::*;
    Ok(match keyword {
        "secrule" => Shape::Rule,
        // The actions of a SecDefaultAction are checked as those of any rule (see `guard`).
        "secaction" | "secdefaultaction" => Shape::Actions,
        "secmarker" => Shape::Marker,
        "secruleupdatetargetbyid" | "secruleupdatetargetbytag" | "secruleupdatetargetbymsg" => {
            Shape::Targets
        }
        // A rule engine and a body access that these set are not the ones that stay: the settings that
        // the inspector adds are added first, and the library keeps the first value of a setting (see
        // `load`).
        "secruleengine" => Shape::Argument(Engine),
        "secrequestbodyaccess" | "secresponsebodyaccess" => Shape::Argument(Switch),
        "secrequestbodyjsondepthlimit" | "secresponsebodylimit" => Shape::Argument(Number),
        "secresponsebodylimitaction" => Shape::Argument(BodyLimitAction),
        "secresponsebodymimetype" => Shape::Argument(Words),
        "secresponsebodymimetypesclear" => Shape::Argument(Nothing),
        "seccomponentsignature" => Shape::Argument(Quoted),
        "secauditengine" => Shape::Argument(AuditOff),
        // What an operator uses to take rules out or to add a variable to a rule is the operator's policy.
        "secruleremovebyid" => Shape::Argument(Ids),
        "secruleremovebytag" | "secruleremovebymsg" => Shape::Argument(Selector),

        "include" => return Err(INCLUDE),
        "secignorerulecompilationerrors" => return Err(IGNORE_ERRORS),
        k if k.starts_with("secremoterules") => return Err(REMOTE_RULES),
        // SecAuditLog*, SecDebugLog*, SecUpload*: files are created or written, or the audit log is sent to
        // another machine. SecTmpSaveUploadedFiles keeps uploaded files.
        k if k.starts_with("secauditlog")
            || k.starts_with("secdebuglog")
            || k.starts_with("secupload")
            || k == "sectmpsaveuploadedfiles" =>
        {
            return Err(OUTPUT_FILES);
        }
        "secdatadir" | "sectmpdir" => return Err(DIRECTORIES),
        // The inspector counts the body and the arguments itself. A limit that an operator sets would
        // make the engine inspect a part of the body, or drop the arguments that come after a limit.
        "secrequestbodylimit"
        | "secrequestbodynofileslimit"
        | "secrequestbodylimitaction"
        | "secrequestbodyinmemorylimit"
        | "secargumentslimit" => return Err(LIMITS),
        // Known to the scanner and not needed: directives that read a file (SecUnicodeMapFile,
        // SecGeoLookupDb, SecGsbLookupDb, SecRuleScript), run or reach out (SecChrootDir, SecHttpBlKey,
        // SecXmlExternalEntity), rewrite another rule (SecRuleUpdateActionById), change how the arguments
        // are cut (SecArgumentSeparator, SecCookieFormat, SecCookieV0Separator), are only parsed to say
        // that they are not supported, or have nothing to do with what the inspector reads.
        "secserversignature"
        | "secwebappid"
        | "seccachetransformations"
        | "secchrootdir"
        | "secconnengine"
        | "sechashengine"
        | "sechashkey"
        | "sechashparam"
        | "sechashmethodrx"
        | "sechashmethodpm"
        | "seccontentinjection"
        | "secargumentseparator"
        | "secgeolookupdb"
        | "secgsblookupdb"
        | "secguardianlog"
        | "secinterceptonerror"
        | "secconnreadstatelimit"
        | "secconnwritestatelimit"
        | "secsensorid"
        | "secruleinheritance"
        | "secruleperftime"
        | "secstreaminbodyinspection"
        | "secstreamoutbodyinspection"
        | "secpcrematchlimit"
        | "secpcrematchlimitrecursion"
        | "secdisablebackendcompression"
        | "secunicodemapfile"
        | "seccollectiontimeout"
        | "sechttpblkey"
        | "secruleupdateactionbyid"
        | "secxmlexternalentity"
        | "secparsexmlintoargs"
        | "seccookieformat"
        | "seccookiev0separator"
        | "secstatusengine"
        | "secrulescript" => return Err(NOT_ALLOWED),
        _ => return Err(UNKNOWN),
    })
}
