//! The variables of the rule language, cut as the scanner of libmodsecurity cuts them.
//!
//! A variable is written in four places: in the list of a `SecRule` (and in the list that an update of a
//! target takes), in a macro (`%{tx.a}`, in the text of an action and in the argument of an operator), and as the
//! target of a `setvar` (see `action`). The scanner reads a name from its own list of names by the longest match
//! and needs no separator after it: `ARGSENV` is the variable `ARGS` and then the variable `ENV`, and
//! `ARGS:a,ENV:x` is two variables, for a selector ends at a comma. A reader that took a name by its letters,
//! or a selector up to the next `|`, would see one variable where the scanner reads two, and would not see
//! the second. So this reader cuts as the scanner does: a name is one name of the scanner (`NAMES`) with
//! nothing glued to it, a selector ends where the scanner ends it, and `|` and `,` both separate two variables.
//!
//! The environment of the inspector is not for a rule to read: the variable `ENV` is refused wherever the
//! cut finds it. What the reader cuts here is also what the library built (the model of `model` is compared
//! with the library, variables included), so a cut that differs from the scanner's is a refusal, and never a
//! variable that is not seen.
//!
//! A selector is read in the forms below and every other form is refused: in a macro, letters, digits and
//! `_ . : -`; in a list, the bytes up to the end that the scanner gives it (no backslash or single quote in
//! it), or a regular expression between two slashes. A list is refused when it holds more than `MAX_LISTED`
//! entries.

use super::scan::{Cursor, FORM, Reason};

/// The names of the variables that the scanner has a token for, in lower case. The first flag says whether a `:`
/// or a `.` may follow the name and start a selector, the second whether the library keeps the name as it is
/// written (the build, the duration, the highest severity, the remote user and the time variables) and not in
/// capitals.
pub(in crate::rules) const NAMES: &[(&str, bool, bool)] = &[
    ("args", true, false),
    ("args_combined_size", false, false),
    ("args_get", true, false),
    ("args_get_names", true, false),
    ("args_names", true, false),
    ("args_post", true, false),
    ("args_post_names", true, false),
    ("auth_type", false, false),
    ("duration", false, true),
    ("env", true, false),
    ("files", true, false),
    ("files_combined_size", false, false),
    ("files_names", true, false),
    ("files_sizes", true, false),
    ("files_tmp_content", true, false),
    ("files_tmpnames", true, false),
    ("full_request", false, false),
    ("full_request_length", false, false),
    ("geo", true, false),
    ("global", true, false),
    ("highest_severity", false, true),
    ("inbound_data_error", false, false),
    ("ip", true, false),
    ("matched_var", false, false),
    ("matched_var_name", false, false),
    ("matched_vars", true, false),
    ("matched_vars_names", true, false),
    ("modsec_build", false, true),
    ("msc_pcre_error", false, false),
    ("msc_pcre_limits_exceeded", false, false),
    ("multipart_boundary_quoted", false, false),
    ("multipart_boundary_whitespace", false, false),
    ("multipart_crlf_lf_lines", false, false),
    ("multipart_data_after", false, false),
    ("multipart_data_before", false, false),
    ("multipart_duplicate_part_header", false, false),
    ("multipart_file_limit_exceeded", false, false),
    ("multipart_filename", true, false),
    ("multipart_filename_charset", true, false),
    ("multipart_filename_language", true, false),
    ("multipart_header_folding", false, false),
    ("multipart_invalid_header_folding", false, false),
    ("multipart_invalid_part", false, false),
    ("multipart_invalid_quoting", false, false),
    ("multipart_lf_line", false, false),
    ("multipart_missing_semicolon", false, false),
    ("multipart_name", true, false),
    ("multipart_part_headers", true, false),
    ("multipart_semicolon_missing", false, false),
    ("multipart_strict_error", false, false),
    ("multipart_unmatched_boundary", false, false),
    ("outbound_data_error", false, false),
    ("path_info", false, false),
    ("query_string", false, false),
    ("remote_addr", false, false),
    ("remote_host", false, false),
    ("remote_port", false, false),
    ("remote_user", false, true),
    ("reqbody_error", false, false),
    ("reqbody_error_msg", false, false),
    ("reqbody_processor", false, false),
    ("reqbody_processor_error", false, false),
    ("reqbody_processor_error_msg", false, false),
    ("request_basename", false, false),
    ("request_body", false, false),
    ("request_body_length", false, false),
    ("request_cookies", true, false),
    ("request_cookies_names", true, false),
    ("request_filename", false, false),
    ("request_headers", true, false),
    ("request_headers_names", true, false),
    ("request_line", false, false),
    ("request_method", false, false),
    ("request_protocol", false, false),
    ("request_uri", false, false),
    ("request_uri_raw", false, false),
    ("resource", true, false),
    ("response_body", false, false),
    ("response_content_length", false, false),
    ("response_content_type", false, false),
    ("response_headers", true, false),
    ("response_headers_names", true, false),
    ("response_protocol", false, false),
    ("response_status", false, false),
    ("rule", true, false),
    ("server_addr", false, false),
    ("server_name", false, false),
    ("server_port", false, false),
    ("session", true, false),
    ("sessionid", false, false),
    ("status", false, false),
    ("status_line", false, false),
    ("time", false, true),
    ("time_day", false, true),
    ("time_epoch", false, true),
    ("time_hour", false, true),
    ("time_min", false, true),
    ("time_mon", false, true),
    ("time_sec", false, true),
    ("time_wday", false, true),
    ("time_year", false, true),
    ("tx", true, false),
    ("unique_id", false, false),
    ("urlencoded_error", false, false),
    ("user", true, false),
    ("userid", false, false),
    ("webappid", false, false),
    ("webserver_error_log", false, false),
    ("xml", true, false),
];

/// What follows the name of a variable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::rules) enum Kind {
    /// Nothing: the whole collection.
    Bare,
    /// A name in the collection (for `XML`, an expression of the path language, which the library keeps as a
    /// name as well).
    Element(Vec<u8>),
    /// A regular expression, without its two slashes.
    Regex(Vec<u8>),
    /// The selector of the target of a `setvar`: text and macros.
    Dynamic(Vec<Piece>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::rules) struct Variable {
    /// The name of the collection as the library holds it: in capitals, except for the few variables whose name
    /// it keeps as it is written.
    pub(in crate::rules) collection: String,
    pub(in crate::rules) kind: Kind,
}

/// A part of a text that has macros: bytes, or a variable that a macro names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::rules) enum Piece {
    Text(Vec<u8>),
    Var(Variable),
}

/// What is in front of a variable in a list: nothing, `&` (the number of values) or `!` (taken out).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::rules) enum Modifier {
    Plain,
    Count,
    Exclusion,
}

/// A variable of a list with what is in front of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::rules) struct Listed {
    pub(in crate::rules) modifier: Modifier,
    pub(in crate::rules) variable: Variable,
}

impl Variable {
    /// The name that the library gives the variable inside its collection.
    pub(in crate::rules) fn name(&self) -> Vec<u8> {
        match &self.kind {
            Kind::Bare => Vec::new(),
            Kind::Element(name) => name.clone(),
            Kind::Regex(regex) => [b"regex(".as_slice(), regex, b")"].concat(),
            Kind::Dynamic(_) => b"dynamic".to_vec(),
        }
    }
}

type Name = (&'static str, bool, bool);

/// The collections that a rule can write to, in lower case: a `setvar` writes to one of them, and the parser
/// reads the text that follows the macro of one of them, with no selector, as its selector.
pub(in crate::rules) const WRITABLE: [&str; 6] =
    ["global", "ip", "resource", "session", "tx", "user"];

/// The name that the library gives the collection of a variable whose class it names otherwise than the
/// scanner does (two names for one variable, and one that is another variable's).
fn library_name(name: &str) -> &str {
    match name {
        "multipart_semicolon_missing" => "multipart_missing_semicolon",
        "reqbody_processor_error_msg" => "processor_error_msg",
        "status_line" => "status",
        "unique_id" => "uniqueid",
        _ => name,
    }
}

/// The name that the longest match gives at the start of `run`, if there is one.
fn longest(run: &[u8]) -> Option<&'static Name> {
    NAMES
        .iter()
        .filter(|(name, _, _)| {
            run.len() >= name.len() && run[..name.len()].eq_ignore_ascii_case(name.as_bytes())
        })
        .max_by_key(|(name, _, _)| name.len())
}

/// The name at the start of `bytes` by the longest match, the collection that the library makes of it and
/// its length. What stands after the name is read by the caller: a name that has more letters after it is
/// followed by the next token for the scanner, which no caller takes for a separator.
fn name_at(bytes: &[u8]) -> Result<(&'static Name, String, usize), Reason> {
    let run = bytes
        .iter()
        .take_while(|b| b.is_ascii_alphanumeric() || **b == b'_')
        .count();
    let entry = longest(&bytes[..run]).ok_or(FORM)?;
    let length = entry.0.len();
    let collection = if entry.2 {
        String::from_utf8_lossy(&bytes[..length]).into_owned()
    } else {
        library_name(entry.0).to_ascii_uppercase()
    };
    Ok((entry, collection, length))
}

/// The end of a regular expression selector at the start of `rest` (which starts after the `:` or the `.`), or
/// `None`. The scanner takes the longest text that starts with a slash, holds none of ` =|"` and a tab, and ends
/// with a slash that has at least one byte before it.
fn regex_end(rest: &[u8]) -> Option<usize> {
    if rest.first() != Some(&b'/') {
        return None;
    }
    let run = rest
        .iter()
        .position(|b| matches!(b, b'=' | b'|' | b' ' | b'\t' | b'"'))
        .unwrap_or(rest.len());
    let slash = rest[..run].iter().rposition(|b| *b == b'/')?;
    (slash >= 2).then_some(slash + 1)
}

/// The selector of a variable of a list at the start of `rest`, and how many bytes it takes. The scanner takes
/// the longer of a regular expression and a name that ends at `| , }`, a quote, a blank or a line break; the
/// regular expression wins a tie.
fn selector(collection: &str, rest: &[u8]) -> Result<(Kind, usize), Reason> {
    let plain = rest
        .iter()
        .position(|b| matches!(b, b'|' | b',' | b'}' | b'"' | b'\n' | b' ' | b'\t'))
        .unwrap_or(rest.len());
    match regex_end(rest) {
        Some(end) if end >= plain => {
            let inside = rest[1..end - 1].to_vec();
            // The library keeps the expression of these two as a plain name.
            let kind = if matches!(collection, "XML" | "ENV") {
                Kind::Element(inside)
            } else {
                Kind::Regex(inside)
            };
            Ok((kind, end))
        }
        _ => {
            let name = &rest[..plain];
            // A backslash and a single quote make the scanner read the selector in other forms.
            if name.is_empty() || name.iter().any(|b| matches!(b, b'\\' | b'\'')) {
                return Err(FORM);
            }
            Ok((Kind::Element(name.to_vec()), plain))
        }
    }
}

/// The most entries that a list of variables holds: the variables, the ones that are taken out (`!`) and the
/// counts (`&`) all count. The library gives each variable of a list the keys of every exclusion of the list, so
/// the text that compares what it built grows with the product of the two numbers.
const MAX_LISTED: usize = 256;
const LIST_TOO_LONG: Reason = "a list of variables holds more than 256 entries";

/// The variables of a list: of a `SecRule`, or of an update of a target. The list holds no blank and no
/// line break.
pub(in crate::rules) fn read_list(list: &[u8]) -> Result<Vec<Listed>, Reason> {
    let mut listed = Vec::new();
    let mut rest = list;
    loop {
        let modifier = match rest.first() {
            Some(b'!') => Modifier::Exclusion,
            Some(b'&') => Modifier::Count,
            _ => Modifier::Plain,
        };
        if modifier != Modifier::Plain {
            rest = &rest[1..];
        }
        let (entry, collection, length) = name_at(rest)?;
        rest = &rest[length..];
        let kind = if matches!(rest.first(), Some(b':' | b'.')) {
            if !entry.1 {
                return Err(FORM);
            }
            let (kind, used) = selector(&collection, &rest[1..])?;
            rest = &rest[1 + used..];
            kind
        } else {
            Kind::Bare
        };
        if entry.0 == "env" {
            return Err(FORM);
        }
        if listed.len() == MAX_LISTED {
            return Err(LIST_TOO_LONG);
        }
        listed.push(Listed {
            modifier,
            variable: Variable { collection, kind },
        });
        match rest.first() {
            None => return Ok(listed),
            Some(b'|' | b',') => rest = &rest[1..],
            Some(_) => return Err(FORM),
        }
    }
}

/// The variable of the macro `%{...}` that starts at `bytes[0]`, and the length of the macro with its `}`.
pub(in crate::rules) fn macro_at(bytes: &[u8]) -> Result<(Variable, usize), Reason> {
    let inside = bytes.get(2..).ok_or(FORM)?;
    let (entry, collection, mut at) = name_at(inside)?;
    let kind = if matches!(inside.get(at), Some(b':' | b'.')) {
        if !entry.1 {
            return Err(FORM);
        }
        at += 1;
        let length = inside[at..]
            .iter()
            .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-'))
            .count();
        if length == 0 {
            return Err(FORM);
        }
        at += length;
        Kind::Element(inside[at - length..at].to_vec())
    } else {
        Kind::Bare
    };
    if inside.get(at) != Some(&b'}') || entry.0 == "env" {
        return Err(FORM);
    }
    if kind == Kind::Bare && WRITABLE.contains(&entry.0) {
        return Err(FORM);
    }
    Ok((Variable { collection, kind }, 2 + at + 1))
}

/// The macro at the cursor (a `%{`); the cursor is left after the `}`.
pub(in crate::rules) fn read_macro(c: &mut Cursor<'_>) -> Result<Variable, Reason> {
    let (variable, length) = macro_at(&c.bytes[c.at..])?;
    c.at += length;
    Ok(variable)
}
