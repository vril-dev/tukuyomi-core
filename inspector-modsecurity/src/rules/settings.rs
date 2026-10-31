//! The settings of the rules set, as the library holds them once it has read the rule files, written from
//! what the reader read (see `model`).
//!
//! Every member of the properties of the rules set is described. The three directives that the inspector adds
//! before the files (`FIXED_DIRECTIVES` in `load`) set the rule engine, the body access and the depth of a JSON body, and the
//! library keeps the value that a setting had first, so what the files say about those three changes nothing.
//! The directives that a file may use to set something else are the ones below, and each member that none
//! of them sets is at the default that the library gives it. A directive that the checks refuse (a limit, an
//! upload directory, an audit log, a debug log, the data directory, ...) sets a member that is not at its
//! default in the library, and shows as a difference.
//!
//! A file is read by one parser that keeps the last directive of each kind, and the settings of the files are
//! merged in the order they are loaded: the first file that sets a value keeps it; the lists (the removals
//! of rules, the components) grow; the audit state is the last one that is set.

use std::collections::BTreeSet;

use super::describe::{self, Out};
use super::model::number;
use super::reader::{Action, Body, FORM, Listed, Reason};

/// The defaults that the library gives the audit log (`AuditLog` in `audit_log.h`): the parts A, B, C, F, H
/// and Z, the mode of a file (0640) and of a directory (0750).
const AUDIT_PARTS: i64 = 4430;
const AUDIT_FILE_MODE: i64 = 0o640;
const AUDIT_DIRECTORY_MODE: i64 = 0o750;

/// What a file holds, or what all the files hold together.
#[derive(Default)]
struct Held {
    response_body_access: Option<bool>,
    response_body_limit: Option<u64>,
    response_body_limit_action: Option<&'static str>,
    /// `SecResponseBodyMimeType` and `SecResponseBodyMimeTypesClear`.
    types_set: bool,
    types_clear: bool,
    types: BTreeSet<Vec<u8>>,
    audit_off: bool,
    audit_ctl: bool,
    components: Vec<Vec<u8>>,
    numbers: Vec<i64>,
    ranges: Vec<(i64, i64)>,
    removed_msgs: Vec<Vec<u8>>,
    removed_tags: Vec<Vec<u8>>,
    /// What each update of a target names, with one of its variables.
    target_ids: Vec<(i64, Listed)>,
    target_tags: Vec<(Vec<u8>, Listed)>,
    target_msgs: Vec<(Vec<u8>, Listed)>,
}

#[derive(Default)]
pub(super) struct Settings {
    all: Held,
    file: Held,
}

/// What `parserSanitizer` makes of a text: the spaces at its ends are cut off, then a pair of double quotes,
/// then a pair of single quotes.
fn sanitize(text: &[u8]) -> Vec<u8> {
    let mut text = text;
    while text.len() > 1 && text[0] == b' ' {
        text = &text[1..];
    }
    while text.len() > 1 && text[text.len() - 1] == b' ' {
        text = &text[..text.len() - 1];
    }
    for quote in [b'"', b'\''] {
        if text.len() > 1 && text[0] == quote && text[text.len() - 1] == quote {
            text = &text[1..text.len() - 1];
        }
    }
    text.to_vec()
}

/// `std::stoi`: spaces, and then the digits that are there; a text with none is an error, and so is a number
/// that does not fit.
fn leading_int(text: &[u8]) -> Result<i64, Reason> {
    let text = text.trim_ascii_start();
    let digits = text.iter().take_while(|b| b.is_ascii_digit()).count();
    let value = number(&text[..digits]);
    if digits == 0 || value > i64::from(i32::MAX) {
        return Err(FORM);
    }
    Ok(value)
}

/// `SecRuleRemoveById`: the ids and ranges in the text, cut at the spaces.
fn removed_ids(held: &mut Held, argument: &[u8]) -> Result<(), Reason> {
    let mut found = false;
    for token in argument.split(|b| *b == b' ') {
        let token = sanitize(token);
        if token.is_empty() {
            continue;
        }
        match token.iter().position(|b| *b == b'-') {
            Some(dash) => {
                let (first, second) = (&token[..dash], &token[dash + 1..]);
                let range = (leading_int(first)?, leading_int(second)?);
                // The library compares the two texts, and not the numbers.
                if first > second {
                    return Err(FORM);
                }
                held.ranges.push(range);
            }
            None => held.numbers.push(leading_int(&token)?),
        }
        found = true;
    }
    if found { Ok(()) } else { Err(FORM) }
}

impl Settings {
    /// A `ctl` action that turns the audit engine on is noted by the parser of the file.
    pub(super) fn actions(&mut self, actions: &[Action]) {
        for action in actions.iter().filter(|action| action.name == "ctl") {
            let lower = action.value.to_ascii_lowercase();
            if lower == b"auditengine=on" || lower == b"auditengine=relevantonly" {
                self.file.audit_ctl = true;
            }
        }
    }

    /// A directive that takes an argument, or none.
    pub(super) fn directive(&mut self, keyword: &str, body: &Body) -> Result<(), Reason> {
        let file = &mut self.file;
        match (keyword, body) {
            // The inspector sets these three first, and the first value stays.
            ("secruleengine" | "secrequestbodyaccess" | "secrequestbodyjsondepthlimit", _) => {}
            ("secresponsebodyaccess", Body::Argument(on)) => {
                file.response_body_access = Some(on.eq_ignore_ascii_case(b"on"));
            }
            ("secresponsebodylimit", Body::Argument(digits)) => {
                let limit = std::str::from_utf8(digits)
                    .ok()
                    .and_then(|n| n.parse().ok());
                file.response_body_limit = Some(limit.ok_or(FORM)?);
            }
            ("secresponsebodylimitaction", Body::Argument(action)) => {
                file.response_body_limit_action = Some(if action.eq_ignore_ascii_case(b"reject") {
                    "reject"
                } else {
                    "processpartial"
                });
            }
            ("secresponsebodymimetype", Body::Argument(words)) => {
                file.types_set = true;
                file.types.extend(
                    words
                        .split(|b| *b == b' ')
                        .filter(|word| !word.is_empty())
                        .map(<[u8]>::to_vec),
                );
            }
            ("secresponsebodymimetypesclear", _) => {
                file.types_set = true;
                file.types_clear = true;
                file.types.clear();
            }
            // The library keeps the quote that closes the text.
            ("seccomponentsignature", Body::Argument(quoted)) => {
                file.components.push(quoted[1..].to_vec());
            }
            ("secauditengine", _) => file.audit_off = true,
            ("secruleremovebyid", Body::Argument(ids)) => removed_ids(file, ids)?,
            ("secruleremovebytag", Body::Argument(tag)) => file.removed_tags.push(sanitize(tag)),
            ("secruleremovebymsg", Body::Argument(msg)) => file.removed_msgs.push(sanitize(msg)),
            (
                "secruleupdatetargetbyid",
                Body::Targets {
                    selector,
                    variables,
                },
            ) => {
                // The library reads the id as a number that may have more after it; only a whole number
                // that is written as one is taken.
                let id = sanitize(selector);
                if id.is_empty()
                    || !id.iter().all(u8::is_ascii_digit)
                    || number(&id) >= 9_000_000_000_000_000
                {
                    return Err(FORM);
                }
                file.target_ids
                    .extend(variables.iter().map(|one| (number(&id), one.clone())));
            }
            (
                "secruleupdatetargetbytag",
                Body::Targets {
                    selector,
                    variables,
                },
            ) => {
                let tag = sanitize(selector);
                file.target_tags
                    .extend(variables.iter().map(|one| (tag.clone(), one.clone())));
            }
            (
                "secruleupdatetargetbymsg",
                Body::Targets {
                    selector,
                    variables,
                },
            ) => {
                let msg = sanitize(selector);
                file.target_msgs
                    .extend(variables.iter().map(|one| (msg.clone(), one.clone())));
            }
            _ => return Err(FORM),
        }
        Ok(())
    }

    /// The end of a file: what it holds is merged into what the files before it held.
    pub(super) fn end_of_file(&mut self) {
        let file = std::mem::take(&mut self.file);
        let all = &mut self.all;
        all.response_body_access = all.response_body_access.or(file.response_body_access);
        all.response_body_limit = all.response_body_limit.or(file.response_body_limit);
        all.response_body_limit_action = all
            .response_body_limit_action
            .or(file.response_body_limit_action);
        if file.types_set {
            // A file that cleared the types takes all the types away, those of its own after the clear too.
            if file.types_clear {
                all.types.clear();
            } else {
                all.types.extend(file.types);
            }
            all.types_set = true;
        }
        all.audit_off |= file.audit_off;
        all.audit_ctl |= file.audit_ctl;
        all.components.extend(file.components);
        all.numbers.extend(file.numbers);
        all.ranges.extend(file.ranges);
        all.removed_msgs.extend(file.removed_msgs);
        all.removed_tags.extend(file.removed_tags);
        all.target_ids.extend(file.target_ids);
        all.target_tags.extend(file.target_tags);
        all.target_msgs.extend(file.target_msgs);
    }

    /// Every member, in the order in which `describe_settings` in `bridge.cc` writes them.
    pub(super) fn encode(&self, out: &mut Out) {
        let all = &self.all;
        let word = |out: &mut Out, label: &str, value: &str| {
            out.word(label);
            out.word(value);
        };
        let number = |out: &mut Out, label: &str, value: Option<u64>| {
            out.word(label);
            out.flag(value.is_some());
            // The library holds the value in a field that is the same width, and the text writes it signed.
            out.num(value.unwrap_or(0) as i64);
        };
        let string = |out: &mut Out, label: &str| {
            out.word(label);
            out.flag(false);
            out.str(b"");
        };
        let boolean = |value: Option<bool>| match value {
            Some(true) => "true",
            Some(false) => "false",
            None => "unset",
        };
        let sorted = |out: &mut Out, label: &str, list: &[Vec<u8>]| {
            let mut list = list.to_vec();
            list.sort();
            out.word(label);
            out.count(list.len());
            for one in &list {
                out.str(one);
            }
        };
        out.word("settings");
        word(out, "engine", "on");
        word(out, "request_body_access", "true");
        word(
            out,
            "response_body_access",
            boolean(all.response_body_access),
        );
        word(out, "xml_external_entity", "unset");
        word(out, "xml_parse_into_args", "unset");
        word(out, "tmp_save_uploaded_files", "unset");
        word(out, "upload_keep_files", "unset");
        word(out, "request_body_limit_action", "unset");
        word(
            out,
            "response_body_limit_action",
            all.response_body_limit_action.unwrap_or("unset"),
        );
        number(out, "arguments_limit", None);
        number(out, "json_depth_limit", Some(64));
        number(out, "request_body_limit", None);
        number(out, "request_body_no_files_limit", None);
        number(out, "response_body_limit", all.response_body_limit);
        number(out, "pcre_match_limit", None);
        number(out, "upload_file_limit", None);
        number(out, "upload_file_mode", None);
        string(out, "http_bl_key");
        string(out, "upload_directory");
        string(out, "upload_tmp_directory");
        string(out, "argument_separator");
        string(out, "web_app_id");
        out.word("unicode_map");
        out.flag(false);
        word(out, "remote_rules_action", "unset");
        out.word("response_body_types");
        out.flag(all.types_set);
        out.flag(false);
        out.count(all.types.len());
        for one in &all.types {
            out.str(one);
        }
        out.word("components");
        out.count(all.components.len());
        for one in &all.components {
            out.str(one);
        }
        out.word("removed_numbers");
        out.count(all.numbers.len());
        for one in &all.numbers {
            out.num(*one);
        }
        out.word("removed_ranges");
        out.count(all.ranges.len());
        for (first, second) in &all.ranges {
            out.num(*first);
            out.num(*second);
        }
        sorted(out, "removed_by_msg", &all.removed_msgs);
        sorted(out, "removed_by_tag", &all.removed_tags);
        // An update of a target is one entry for each of its variables: what it names and the variable.
        let updates = |out: &mut Out, label: &str, mut entries: Vec<Vec<u8>>| {
            entries.sort();
            out.word(label);
            out.count(entries.len());
            for one in &entries {
                out.str(one);
            }
        };
        let entry = |key: &dyn Fn(&mut Out), one: &Listed| {
            let mut entry = Out::default();
            key(&mut entry);
            entry.str(&describe::listed(one.modifier, &one.variable, &[]));
            entry.text()
        };
        updates(
            out,
            "update_target_by_id",
            (all.target_ids.iter())
                .map(|(id, one)| entry(&|e| e.num(*id), one))
                .collect(),
        );
        updates(
            out,
            "update_target_by_tag",
            (all.target_tags.iter())
                .map(|(tag, one)| entry(&|e| e.str(tag), one))
                .collect(),
        );
        updates(
            out,
            "update_target_by_msg",
            (all.target_msgs.iter())
                .map(|(msg, one)| entry(&|e| e.str(msg), one))
                .collect(),
        );
        out.word("action_updates");
        out.count(0);
        out.count(0);
        out.word("audit");
        for _ in 0..4 {
            out.str(b"");
        }
        out.word("unset");
        out.word(if all.audit_off { "off" } else { "unset" });
        out.word("unset");
        out.str(b"");
        out.num(AUDIT_PARTS);
        out.num(AUDIT_FILE_MODE);
        out.num(AUDIT_DIRECTORY_MODE);
        out.flag(all.audit_ctl);
        out.word("debug");
        out.flag(false);
        out.flag(false);
    }
}
