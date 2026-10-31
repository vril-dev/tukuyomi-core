//! The start-up checks of one rule file of the operator.
//!
//! The rules are not trusted. A rule can reach outside the process (`exec`, `setenv`, `@inspectFile`, `@rbl`, a
//! file it reads), change what the inspector decides about the request body or the engine for one
//! transaction (`ctl`), stop a request without leaving a record of the rule that stopped it
//! (`deny` with `nolog`), take the number that is reserved for a rule of the inspector, or skip the
//! rules after it silently (`skipAfter` with no marker). This file turns such a rule down before the
//! library reads it, because reading is already acting: a directive can open a file when it is read.
//!
//! The file is read by the reader (`reader`), which refuses what it cannot read as the scanner of the library reads it.
//! What it reads is checked here, by name, and then once more as plain text (`NEEDLES`): the text of the
//! rule with its blanks and quotes taken out and its capitals folded, which is how an unforeseen spelling
//! would still show a word that must not be there.
//!
//! It is a check of strings, not a parser of everything. A false refusal is accepted: a refused text may
//! be harmless, for example the word of a `ctl` action inside the argument of an operator or in a message.
//! What is left to the engine at run time: the actions of a chain of rules (a `deny` in the first rule and a
//! `nolog` in another), a rule that is removed or skipped by a `ctl` or a `skipAfter` that names a
//! marker of another phase. The rules that the library built are looked at once more after it has built
//! them (`load::verify`), which does not depend on how this file reads the text.

use std::collections::BTreeMap;

use super::files;
use super::markers::Markers;
use super::model::Model;
use super::reader::{self, ACTION_UNKNOWN, Action, Body, Operator, Reason, Statement};

const CTL: Reason = "ctl of the rule engine or of the request body access is not allowed";
const OPERATOR_NOT_ALLOWED: Reason = "an operator that is not allowed is used";
const NOLOG_DENY: Reason =
    "a rule that stops a request has nolog or noauditlog: nothing would say which rule stopped it";
const NOLOG_DEFAULT: Reason = "SecDefaultAction has nolog or noauditlog: a rule that stops a request \
                               would take it, and nothing would say which rule stopped it";
const RESERVED_ID: Reason =
    "a rule uses an id that is reserved for the inspector (4000001 to 4000011)";
const ID_UNREADABLE: Reason = "a rule id cannot be read";
const SKIP_AFTER_UNREADABLE: Reason = "a skipAfter cannot be read";
const SKIP_AFTER_IN_DEFAULT: Reason = "skipAfter in SecDefaultAction is not allowed";
const WORD: Reason = "a rule holds a word that is not allowed";

/// The ids that the inspector keeps for its own rules.
const RESERVED_IDS: std::ops::RangeInclusive<u64> = 4_000_001..=4_000_011;

/// Words that must not be in a rule, looked for in the text of a statement with blanks and quotes taken out and
/// capitals folded. Each is the start of something that the checks by name refuse; the text is a second look
/// for a spelling that the reading missed.
const NEEDLES: &[&str] = &[
    "ctl:ruleengine",
    "ctl:requestbodyaccess",
    "ctl:requestbodylimit",
    "exec:",
    "setenv:",
    "@inspectfile",
    "@rbl",
    "@validatedtd",
    "@validateschema",
    "@fuzzyhash",
];

/// Checks the rule file `file` (its text is `text`), records its markers and its `skipAfter` names, and
/// adds what it says to `model`. `files` are all the files of the generation.
pub(super) fn check_file(
    file: &str,
    text: &[u8],
    files: &BTreeMap<String, Vec<u8>>,
    markers: &mut Markers,
    model: &mut Model,
) -> Result<(), Reason> {
    for statement in reader::read(text)? {
        let at = markers.next();
        match &statement.body {
            Body::Marker(name) => markers.marker(name, at),
            Body::Rule(rule) => {
                check_operator(&rule.operator, file, files)?;
                check_actions(&statement, &rule.actions, file, markers, at)?;
            }
            Body::Actions(actions) => check_actions(&statement, actions, file, markers, at)?,
            Body::Argument(_) | Body::Targets { .. } | Body::Plain => {}
        }
        model.statement(&statement)?;
    }
    model.end_of_file();
    Ok(())
}

fn check_operator(
    operator: &Operator,
    file: &str,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<(), Reason> {
    match operator.name {
        // Reading a file: only a file of the generation (see `files`).
        Some(name @ ("pmfromfile" | "pmf" | "ipmatchfromfile" | "ipmatchf")) => {
            files::check_argument(name, &operator.argument, file, files)
        }
        // @inspectFile runs a program, @rbl asks a DNS server, @validateDTD, @validateSchema and
        // @fuzzyHash read a file that the library finds by its own rules, @geoLookup needs a database file,
        // and @gsbLookup, @rsub and @validateHash are not supported by the library.
        Some(
            "inspectfile" | "rbl" | "validatedtd" | "validateschema" | "fuzzyhash" | "geolookup"
            | "gsblookup" | "rsub" | "validatehash",
        ) => Err(OPERATOR_NOT_ALLOWED),
        _ => Ok(()),
    }
}

/// The checks on the actions of `SecRule`, `SecAction` and `SecDefaultAction`.
fn check_actions(
    statement: &Statement<'_>,
    actions: &[Action],
    file: &str,
    markers: &mut Markers,
    at: usize,
) -> Result<(), Reason> {
    let mut stops = false;
    let mut nolog = false;
    for action in actions {
        match action.name.as_str() {
            "ctl" => check_ctl(&action.value)?,
            "id" => check_id(&action.value)?,
            "skipafter" => {
                if statement.keyword == "secdefaultaction" {
                    return Err(SKIP_AFTER_IN_DEFAULT);
                }
                let name = std::str::from_utf8(&action.value)
                    .ok()
                    .filter(|name| reader::is_name(name.as_bytes()))
                    .ok_or(SKIP_AFTER_UNREADABLE)?;
                markers.skip_after(name, file, at);
            }
            // block takes the disruptive action of the default actions, which may be a deny.
            "deny" | "drop" | "redirect" | "block" => stops = true,
            // noauditlog drops the message of the rule in the library as nolog does.
            "nolog" | "noauditlog" => nolog = true,
            "accuracy" | "allow" | "auditlog" | "capture" | "chain" | "expirevar" | "initcol"
            | "log" | "logdata" | "maturity" | "msg" | "multimatch" | "pass" | "phase" | "rev"
            | "setrsc" | "setsid" | "setuid" | "setvar" | "severity" | "skip" | "status"
            | "tag" | "t" | "ver" | "xmlns" => {}
            // append, deprecatevar, pause, prepend, proxy and sanitise*, which the library reads and then
            // refuses, and what it does not know.
            _ => return Err(ACTION_UNKNOWN),
        }
    }
    // A rule that stops a request and does not log leaves no message with the id of the rule: the inspector
    // would see a stop and not know which rule it was. (`log` together with `nolog` is refused as well:
    // the later of the two decides, and it is not worth working out which that is.) The actions of a
    // `SecDefaultAction` are taken by the rules after it, so one with `nolog` is refused whatever else it
    // has.
    if nolog && statement.keyword == "secdefaultaction" {
        return Err(NOLOG_DEFAULT);
    }
    if stops && nolog {
        return Err(NOLOG_DENY);
    }
    check_words(statement.text)
}

/// The `ctl` actions that change the engine or the body access of one transaction. The others (the removal of
/// rules and of targets, the audit engine and parts, and what the engine does with an XML body) are the
/// operator's policy. So is the processor of the body: the inspection checks the processor of every
/// transaction against the one that the Content-Type gives, and a transaction whose processor differs, as
/// it does when a rule changes it, cannot be inspected.
fn check_ctl(value: &[u8]) -> Result<(), Reason> {
    let name = value.split(|b| *b == b'=').next().unwrap_or_default();
    match String::from_utf8_lossy(name).to_ascii_lowercase().as_str() {
        "ruleengine" | "requestbodyaccess" | "requestbodylimit" => Err(CTL),
        "auditengine"
        | "auditlogparts"
        | "forcerequestbodyvariable"
        | "parsexmlintoargs"
        | "requestbodyprocessor"
        | "ruleremovebyid"
        | "ruleremovebytag"
        | "ruleremovetargetbyid"
        | "ruleremovetargetbytag" => Ok(()),
        _ => Err(ACTION_UNKNOWN),
    }
}

/// The library reads the id as a number and then compares its text with the number, so an id with a zero in
/// front is refused by it; here a zero in front is skipped, which refuses more. An id that is not digits is
/// not one that the library would read.
fn check_id(value: &[u8]) -> Result<(), Reason> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return Err(ID_UNREADABLE);
    }
    let number = value.iter().fold(0u64, |n, d| {
        n.saturating_mul(10).saturating_add(u64::from(d - b'0'))
    });
    if RESERVED_IDS.contains(&number) {
        return Err(RESERVED_ID);
    }
    Ok(())
}

/// The second look: `NEEDLES` in the text without blanks and quotes, in lower case.
fn check_words(text: &[u8]) -> Result<(), Reason> {
    let folded: Vec<u8> = text
        .iter()
        .filter(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'"' | b'\'' | b'\\'))
        .map(u8::to_ascii_lowercase)
        .collect();
    for needle in NEEDLES {
        let needle = needle.as_bytes();
        if folded.windows(needle.len()).any(|w| w == needle) {
            return Err(WORD);
        }
    }
    Ok(())
}
