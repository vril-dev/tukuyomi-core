//! The actions of a rule, between double quotes, read as the scanner of libmodsecurity reads them.
//!
//! The scanner has a pattern for each action and takes the longest text that one of them matches, with no
//! separator needed after it: `pass` and `deny` side by side are two actions. Where a value ends is set by
//! the pattern of its own action, and the patterns do not agree. In a message, a tag or a `setvar` a value
//! ends at a comma or a double quote, but a `%` takes the byte after it (so `%,` and `%"` end nothing) and a
//! backslash before a comma does not protect it. `rev` without quotes takes a double quote and a line break
//! into its value, `accuracy` and `maturity` without quotes take everything up to the next single quote, a
//! quoted `setvar` ends at a comma or a double quote inside its quotes, and a few actions end where their
//! words end: the scanner reads `ctl:auditEngine=Offdeny` as the tokens `ctl:auditEngine=Off` and `deny`, and
//! leaves it to the parser, which wants a comma between two actions, to refuse that.
//!
//! A reader with one rule for every value would cut an action, or the whole list, at another place than the
//! scanner does, and what it takes for the text of a value the scanner reads as actions, or as directives. So
//! this reader has one form for each action that the checks accept, and each form is a part of what the
//! pattern of that action matches, chosen so that the scanner and this reader cut the text at the same
//! place:
//!
//! * An action with no value (`pass`, `deny`, `nolog`, ...) takes no colon.
//! * `id` and `severity` take digits or one of their words, with single quotes around it or not. `phase`
//!   takes the same without quotes (the scanner reads `phase:'request'` as `allow`). `status` and `skip`
//!   take digits. `accuracy` and `maturity` take digits in single quotes. `ver` and `rev`
//!   take a plain text in single quotes: no quote, backslash, comma, double quote or line break inside.
//! * `skipAfter` and `xmlns` take the run of bytes up to a blank, a comma, a double quote or a line break,
//!   which is how the scanner cuts them.
//! * A text with macros (`msg`, `logdata`, `tag`, `redirect`, `setsid`, `setuid`, `setrsc`, `expirevar`,
//!   `initcol` after its `=`, and `setvar`) is in single quotes, or has no quote and ends at a comma or a
//!   double quote. It holds no line break, and a `%` only opens a macro `%{name}` (see
//!   `variable::macro_at`), which makes a piece of its own: the text is kept as a series of pieces, bytes and
//!   variables. A `setvar` holds no comma or double quote even inside its quotes, and no text
//!   without quotes holds a single quote. A text without quotes and a `setvar` hold no backslash. A text in
//!   quotes may hold a backslash, but not two in a row and not before a `%`: with two before a quote the quote
//!   closes the text. A backslash is followed by a line break, which continues the line; or by a quote, but
//!   only after a byte of the text (the scanner has other patterns for an escaped quote at the start of a
//!   text, after a macro and after another escaped quote, which this reader does not follow); or by any
//!   other byte.
//! * `setvar` takes, in its text, an optional `!`, a collection that can be written to, `.` or `:`, a selector of
//!   bytes and macros, and then either nothing, or `=`, `=+` or `=-` and a value (which holds no `=`).
//! * `ctl` takes the name of one of the `ctl` actions, `=`, and a value in the form of that action: one of
//!   its words, the audit parts, or the characters that a rule id or tag is made of.
//! * `t` takes the name of one transformation, in any case.
//!
//! Every other spelling is refused, though the scanner may read it. The actions `exec` and `setenv`, and the
//! names that are not the name of an action that the checks accept, are refused by name.

use super::scan::{Cursor, FORM, Reason};
use super::variable::{self, Piece};

pub(in crate::rules) const EXEC: Reason = "the exec action is not allowed";
pub(in crate::rules) const SETENV: Reason = "the setenv action is not allowed";
pub(in crate::rules) const ACTION_UNKNOWN: Reason =
    "an action is not one of the actions of the engine library";

/// The transformations that the scanner has a token for, in lower case.
const TRANSFORMATIONS: &[&str] = &[
    "base64decode",
    "base64decodeext",
    "base64encode",
    "cmdline",
    "compresswhitespace",
    "cssdecode",
    "escapeseqdecode",
    "hexdecode",
    "hexencode",
    "htmlentitydecode",
    "jsdecode",
    "length",
    "lowercase",
    "md5",
    "none",
    "normalisepath",
    "normalisepathwin",
    "normalizepath",
    "normalizepathwin",
    "parityeven7bit",
    "parityodd7bit",
    "parityzero7bit",
    "removecomments",
    "removecommentschar",
    "removenulls",
    "removewhitespace",
    "replacecomments",
    "replacenulls",
    "sha1",
    "sqlhexdecode",
    "trim",
    "trimleft",
    "trimright",
    "uppercase",
    "urldecode",
    "urldecodeuni",
    "urlencode",
    "utf8tounicode",
];

pub(in crate::rules) struct Action {
    /// The name, in lower case.
    pub(in crate::rules) name: String,
    /// What follows the colon, in the form of the action; empty when there is no colon, and for the actions
    /// that hold a text with macros. For `ctl` it is the name of the `ctl` action, `=` and its value.
    pub(in crate::rules) value: Vec<u8>,
    /// The text of an action that holds a text with macros (`msg`, `logdata`, `tag`, ...), in pieces.
    pub(in crate::rules) text: Vec<Piece>,
    /// What a `setvar` sets.
    pub(in crate::rules) set_var: Option<SetVar>,
}

/// A `setvar` action as the library holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::rules) struct SetVar {
    /// What it does, in the numbers of the library: 0 set, 1 add, 2 subtract, 3 set to one, 4 remove.
    pub(in crate::rules) operation: u8,
    /// The collection, in capitals.
    pub(in crate::rules) collection: String,
    /// The selector: text and macros.
    pub(in crate::rules) target: Vec<Piece>,
    /// The value, when the operation has one.
    pub(in crate::rules) value: Option<Vec<Piece>>,
}

/// The actions between double quotes.
pub(in crate::rules) fn read_actions(c: &mut Cursor<'_>) -> Result<Vec<Action>, Reason> {
    c.expect(b'"')?;
    let mut actions = Vec::new();
    loop {
        c.gap();
        let name = c.take_while(|b| b.is_ascii_alphanumeric() || b == b'_');
        if name.is_empty() {
            return Err(FORM);
        }
        let name = String::from_utf8_lossy(name).to_ascii_lowercase();
        let mut action = Action {
            name,
            value: Vec::new(),
            text: Vec::new(),
            set_var: None,
        };
        match action.name.as_str() {
            "msg" | "logdata" | "tag" | "redirect" | "setsid" | "setuid" | "setrsc"
            | "expirevar" => {
                c.expect(b':')?;
                action.text = read_text(c, false)?;
            }
            "setvar" => {
                c.expect(b':')?;
                action.set_var = Some(split_set_var(read_text(c, true)?)?);
            }
            "initcol" => {
                c.expect(b':')?;
                if c.take_while(|b| b.is_ascii_alphabetic()).is_empty() {
                    return Err(FORM);
                }
                c.expect(b'=')?;
                // The scanner reads a value that starts with a quote in another way than one that does not.
                if c.peek() == Some(b'\'') {
                    return Err(FORM);
                }
                action.text = read_text(c, false)?;
            }
            other => action.value = read_value(other, c)?,
        }
        actions.push(action);
        c.gap();
        match c.peek() {
            Some(b',') => c.at += 1,
            Some(b'"') => {
                c.at += 1;
                return Ok(actions);
            }
            _ => return Err(FORM),
        }
    }
}

/// The value of the action `name`, in the form of that action.
fn read_value(name: &str, c: &mut Cursor<'_>) -> Result<Vec<u8>, Reason> {
    match name {
        "allow" | "auditlog" | "block" | "capture" | "chain" | "deny" | "drop" | "log"
        | "multimatch" | "noauditlog" | "nolog" | "pass" => {
            if c.peek() == Some(b':') {
                Err(FORM)
            } else {
                Ok(Vec::new())
            }
        }
        "exec" => Err(EXEC),
        "setenv" => Err(SETENV),
        "id" => {
            c.expect(b':')?;
            maybe_quoted(c, |c| word(c, &[], true))
        }
        // The scanner reads `phase:'request'` as the action `allow`, and nothing here needs a phase in
        // quotes: only a phase without quotes is read.
        "phase" => {
            c.expect(b':')?;
            if c.peek() == Some(b'\'') {
                return Err(FORM);
            }
            word(c, &["request", "response", "logging"], true)
        }
        "severity" => {
            c.expect(b':')?;
            maybe_quoted(c, |c| word(c, &SEVERITIES, true))
        }
        "status" | "skip" => {
            c.expect(b':')?;
            word(c, &[], true)
        }
        "accuracy" | "maturity" => {
            c.expect(b':')?;
            c.expect(b'\'')?;
            let value = word(c, &[], true)?;
            c.expect(b'\'')?;
            Ok(value)
        }
        "ver" | "rev" => {
            c.expect(b':')?;
            c.expect(b'\'')?;
            let value = c.take_while(|b| !matches!(b, b'\'' | b'\\' | b',' | b'"' | b'\n'));
            c.expect(b'\'')?;
            if value.is_empty() {
                return Err(FORM);
            }
            Ok(value.to_vec())
        }
        "skipafter" | "xmlns" => {
            c.expect(b':')?;
            let token = c.take_while(|b| !matches!(b, b',' | b' ' | b'\t' | b'"' | b'\n' | b'\r'));
            if token.is_empty() {
                return Err(FORM);
            }
            // The library takes the first and the last byte off the text of an action that is more than two
            // bytes and starts with a single quote, whatever the last byte is.
            Ok(match token {
                [b'\'', inside @ .., _] if token.len() > 2 => inside.to_vec(),
                _ => token.to_vec(),
            })
        }
        "ctl" => {
            c.expect(b':')?;
            read_ctl(c)
        }
        "t" => {
            c.expect(b':')?;
            let word = c.take_while(|b| b.is_ascii_alphanumeric());
            let lower = String::from_utf8_lossy(word).to_ascii_lowercase();
            if TRANSFORMATIONS.contains(&lower.as_str()) {
                Ok(word.to_vec())
            } else {
                Err(ACTION_UNKNOWN)
            }
        }
        _ => Err(ACTION_UNKNOWN),
    }
}

const SEVERITIES: [&str; 8] = [
    "emergency",
    "alert",
    "critical",
    "error",
    "warning",
    "notice",
    "info",
    "debug",
];

/// `read` between single quotes, or without them.
fn maybe_quoted(
    c: &mut Cursor<'_>,
    read: impl FnOnce(&mut Cursor<'_>) -> Result<Vec<u8>, Reason>,
) -> Result<Vec<u8>, Reason> {
    if c.peek() == Some(b'\'') {
        c.at += 1;
        let value = read(c)?;
        c.expect(b'\'')?;
        Ok(value)
    } else {
        read(c)
    }
}

/// A run of letters and digits that is one of `words` (in any case), or, when `digits` is set, digits
/// only.
fn word(c: &mut Cursor<'_>, words: &[&str], digits: bool) -> Result<Vec<u8>, Reason> {
    let word = c.take_while(|b| b.is_ascii_alphanumeric());
    let all_digits = !word.is_empty() && word.iter().all(u8::is_ascii_digit);
    let lower = String::from_utf8_lossy(word).to_ascii_lowercase();
    if (digits && all_digits) || words.contains(&lower.as_str()) {
        Ok(word.to_vec())
    } else {
        Err(FORM)
    }
}

/// A text with macros: in single quotes, or without any and ending at a comma or a double quote. With
/// `strict` it holds no comma or double quote inside the quotes either, and no backslash. The text comes back
/// in pieces: the bytes between two macros, and the variable of each macro. The blanks before the comma that
/// ends a text with no quotes are a part of it, as the library keeps them.
fn read_text(c: &mut Cursor<'_>, strict: bool) -> Result<Vec<Piece>, Reason> {
    let quoted = c.peek() == Some(b'\'');
    if quoted {
        c.at += 1;
    }
    let mut pieces = Vec::new();
    let mut text = Vec::new();
    // Whether the byte before is an ordinary one of the text: not a quote, a backslash, or the end of a macro.
    let mut ordinary = false;
    loop {
        match c.peek() {
            None | Some(b'\n') => return Err(FORM),
            Some(b'\'') if quoted => {
                c.at += 1;
                break;
            }
            Some(b'\'') => return Err(FORM),
            Some(b',' | b'"') if !quoted => break,
            Some(b',' | b'"') if strict => return Err(FORM),
            Some(b'\\') if quoted && !strict => {
                match c.peek_at(1) {
                    // A continuation of the line.
                    Some(b'\n') => {
                        text.extend_from_slice(b"\\\n");
                        c.at += 2;
                        ordinary = false;
                    }
                    // An escaped quote, which the scanner reads only after an ordinary byte.
                    Some(b'\'') if ordinary => {
                        text.extend_from_slice(b"\\'");
                        c.at += 2;
                        ordinary = false;
                    }
                    None | Some(b'\'' | b'\\' | b'%') => return Err(FORM),
                    Some(_) => {
                        text.push(b'\\');
                        c.at += 1;
                    }
                }
            }
            Some(b'\\') => return Err(FORM),
            Some(b'%') if c.peek_at(1) == Some(b'{') => {
                if !text.is_empty() {
                    pieces.push(Piece::Text(std::mem::take(&mut text)));
                }
                pieces.push(Piece::Var(variable::read_macro(c)?));
                ordinary = false;
            }
            Some(b'%') => return Err(FORM),
            Some(b) => {
                text.push(b);
                c.at += 1;
                ordinary = true;
            }
        }
    }
    if !text.is_empty() {
        pieces.push(Piece::Text(text));
    }
    if pieces.is_empty() {
        return Err(FORM);
    }
    Ok(pieces)
}

/// What a `setvar` holds, from the pieces of its text: `[!]collection.selector`, and `=`, `=+` or `=-` with a
/// value, or nothing more. The selector is text and macros up to the `=`.
fn split_set_var(pieces: Vec<Piece>) -> Result<SetVar, Reason> {
    let mut pieces = pieces.into_iter();
    let Some(Piece::Text(first)) = pieces.next() else {
        return Err(FORM);
    };
    let (remove, head) = match first.strip_prefix(b"!") {
        Some(rest) => (true, rest),
        None => (false, first.as_slice()),
    };
    let separator = head
        .iter()
        .position(|b| matches!(b, b'.' | b':'))
        .ok_or(FORM)?;
    let collection = String::from_utf8_lossy(&head[..separator]).to_ascii_lowercase();
    if !variable::WRITABLE.contains(&collection.as_str()) {
        return Err(FORM);
    }
    let mut rest = Vec::new();
    if separator + 1 < head.len() {
        rest.push(Piece::Text(head[separator + 1..].to_vec()));
    }
    rest.extend(pieces);
    let mut target = Vec::new();
    let mut operation = None;
    let mut value = Vec::new();
    for piece in rest {
        match piece {
            Piece::Text(text) if operation.is_none() => {
                match text.iter().position(|b| *b == b'=') {
                    None => target.push(Piece::Text(text)),
                    Some(at) => {
                        if at > 0 {
                            target.push(Piece::Text(text[..at].to_vec()));
                        }
                        let after = &text[at + 1..];
                        let (number, skip) = match after.first() {
                            Some(b'+') => (1, 1),
                            Some(b'-') => (2, 1),
                            _ => (0, 0),
                        };
                        operation = Some(number);
                        if after.len() > skip {
                            value.push(Piece::Text(after[skip..].to_vec()));
                        }
                    }
                }
            }
            // The scanner ends a value at a second `=`.
            Piece::Text(text) if text.contains(&b'=') => return Err(FORM),
            piece if operation.is_none() => target.push(piece),
            piece => value.push(piece),
        }
    }
    if target.is_empty() {
        return Err(FORM);
    }
    let (operation, value) = match (remove, operation) {
        (true, None) => (4, None),
        (false, None) => (3, None),
        (false, Some(number)) if !value.is_empty() => (number, Some(value)),
        _ => return Err(FORM),
    };
    Ok(SetVar {
        operation,
        collection: collection.to_ascii_uppercase(),
        target,
        value,
    })
}

/// The rest of a `ctl` action: the name of the action, `=`, and the value that the scanner has for it.
fn read_ctl(c: &mut Cursor<'_>) -> Result<Vec<u8>, Reason> {
    let name = c.take_while(|b| b.is_ascii_alphabetic());
    let lower = String::from_utf8_lossy(name).to_ascii_lowercase();
    let value = match lower.as_str() {
        "auditengine" => ctl_value(c, |c| word(c, &["on", "off", "relevantonly"], false))?,
        "forcerequestbodyvariable" | "requestbodyaccess" => {
            ctl_value(c, |c| word(c, &["on", "off"], false))?
        }
        "parsexmlintoargs" => ctl_value(c, |c| word(c, &["on", "off", "onlyargs"], false))?,
        "requestbodyprocessor" => ctl_value(c, |c| word(c, &["json", "xml", "urlencoded"], false))?,
        "ruleengine" => ctl_value(c, |c| word(c, &["on", "off", "detectiononly"], false))?,
        // A sign, and then capital letters only.
        "auditlogparts" => ctl_value(c, |c| {
            let sign = c.take_while(|b| matches!(b, b'+' | b'|' | b'-'));
            let parts = c.take_while(|b| b"ABCDEFGHJKIZ".contains(&b));
            if sign.len() != 1 || parts.is_empty() {
                return Err(FORM);
            }
            Ok([sign, parts].concat())
        })?,
        // A rule id, or a tag, with the characters that the scanner allows in it.
        "ruleremovebyid" | "ruleremovebytag" | "ruleremovetargetbyid" | "ruleremovetargetbytag" => {
            ctl_value(c, |c| {
                let id =
                    c.take_while(|b| b.is_ascii_alphanumeric() || b"_-.*/:;$@=()[]'".contains(&b));
                if id.is_empty() {
                    return Err(FORM);
                }
                Ok(id.to_vec())
            })?
        }
        _ => return Err(ACTION_UNKNOWN),
    };
    let mut ctl = name.to_vec();
    ctl.push(b'=');
    ctl.extend(value);
    Ok(ctl)
}

/// The `=` of a `ctl` action and then its value.
fn ctl_value(
    c: &mut Cursor<'_>,
    read: impl FnOnce(&mut Cursor<'_>) -> Result<Vec<u8>, Reason>,
) -> Result<Vec<u8>, Reason> {
    c.expect(b'=')?;
    read(c)
}
