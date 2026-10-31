//! The operator of a `SecRule`: the string in double quotes that holds an optional `!`, then either an
//! operator name (`@rx`) with its argument, or only a regular expression.
//!
//! The scanner of the library cuts the argument by patterns, not by looking for the closing quote. It takes
//! the longest text that a series of units matches, and what follows that text decides what happens: a `"`
//! closes the string, a `%{` opens a macro, and anything else is an error. The units are:
//!
//! * a byte that is neither `"` nor `%`;
//! * a `%` and the byte after it, if that is not `{` (so a `%` takes a `"` that follows it);
//! * a byte that is not a backslash, then an odd number of backslashes, then a `"` or a `%{` (so a quote
//!   is escaped only when a byte of the same token stands before the backslashes, and that byte may be a
//!   `"` or a `%` as well).
//!
//! The first token of a text may also begin with an odd number of backslashes and a `"`, and so may a token
//! that follows a macro. After the `}` of a macro the scanner takes a `%` too, unless a `{` follows it.
//!
//! The longest match is not what a scan from left to right finds: `a%b\"` is the units `a`, `%b` and `\`
//! before the quote that closes the string, and not an escaped quote. So this reads the units as the scanner
//! does and finds, for every token, the longest end that they reach. A string that has a line break in it is
//! refused, as a backslash and a line break (the scanner takes them as a continuation) are.
//!
//! The argument is kept as the pieces that the scanner gives the library: the text of each token, and the variable
//! of each macro (see `variable`). The `%` that the scanner takes with the `}` of a macro is in no piece.

use super::scan::{Cursor, FORM, Reason};
use super::variable::{self, Piece, Variable};

pub(in crate::rules) const UNKNOWN_OPERATOR: Reason =
    "an operator is not one of the operators of the engine library";

/// The operators that the scanner has a token for, in lower case without the `@`, and whether they take an
/// argument.
const OPERATORS: &[(&str, bool)] = &[
    ("beginswith", true),
    ("contains", true),
    ("containsword", true),
    ("detectsqli", false),
    ("detectxss", false),
    ("endswith", true),
    ("eq", true),
    ("fuzzyhash", true),
    ("ge", true),
    ("geolookup", false),
    ("gsblookup", true),
    ("gt", true),
    ("inspectfile", true),
    ("ipmatch", true),
    ("ipmatchf", true),
    ("ipmatchfromfile", true),
    ("le", true),
    ("lt", true),
    ("pm", true),
    ("pmf", true),
    ("pmfromfile", true),
    ("rbl", true),
    ("rsub", true),
    ("rx", true),
    ("rxglobal", true),
    ("streq", true),
    ("strmatch", true),
    ("unconditionalmatch", false),
    ("validatebyterange", true),
    ("validatedtd", true),
    ("validatehash", true),
    ("validateschema", true),
    ("validateurlencoding", false),
    ("validateutf8encoding", false),
    ("verifycc", true),
    ("verifycpf", true),
    ("verifyssn", true),
    ("verifysvnr", true),
    ("within", true),
];

pub(in crate::rules) struct Operator {
    /// The name of the operator, as in `OPERATORS`; `None` for a regular expression with no operator.
    pub(in crate::rules) name: Option<&'static str>,
    /// Whether the operator is negated with a `!`.
    pub(in crate::rules) negated: bool,
    /// The text of the argument as written, macros and escapes included.
    pub(in crate::rules) argument: Vec<u8>,
    /// The argument in pieces; `None` for an operator that takes none.
    pub(in crate::rules) pieces: Option<Vec<Piece>>,
}

/// The operator between double quotes. The cursor is left after the closing quote.
pub(in crate::rules) fn read_operator_string(c: &mut Cursor<'_>) -> Result<Operator, Reason> {
    c.expect(b'"')?;
    let negated = c.peek() == Some(b'!');
    if negated {
        c.at += 1;
    }
    // A blank before the operator is refused: the scanner skips two blanks or more, but one blank is read as
    // the start of a regular expression (its pattern for any byte comes before the one for blanks, and wins
    // a tie), so `" @contains x"` is the expression ` @contains x`.
    if matches!(c.peek(), Some(b' ' | b'\t')) {
        return Err(FORM);
    }
    if c.peek() != Some(b'@') {
        // A regular expression with no operator: the text is the argument.
        if matches!(c.peek(), None | Some(b'"' | b'\n')) {
            return Err(FORM);
        }
        let (argument, pieces) = free_text(c)?;
        return Ok(Operator {
            name: None,
            negated,
            argument,
            pieces: Some(pieces),
        });
    }
    let rest = &c.bytes[c.at..];
    // The scanner takes the longest name that fits (`@pmFromFile` before `@pm`), in any case.
    let (name, takes_argument) = OPERATORS
        .iter()
        .filter(|(name, _)| {
            rest.len() > name.len() && rest[1..=name.len()].eq_ignore_ascii_case(name.as_bytes())
        })
        .max_by_key(|(name, _)| name.len())
        .copied()
        .ok_or(UNKNOWN_OPERATOR)?;
    c.at += 1 + name.len();
    let (argument, pieces) = if takes_argument {
        // One space, and then the argument: the scanner skips anything else.
        c.expect(b' ')?;
        let (argument, pieces) = free_text(c)?;
        (argument, Some(pieces))
    } else {
        // An operator with no argument is followed by spaces and the closing quote.
        c.take_while(|b| b == b' ');
        c.expect(b'"')?;
        (Vec::new(), None)
    };
    Ok(Operator {
        name: Some(name),
        negated,
        argument,
        pieces,
    })
}

/// Reads the free text of an argument up to the quote that closes it, and leaves the cursor after that quote.
/// Returns the bytes between, as written, and the same in pieces.
fn free_text(c: &mut Cursor<'_>) -> Result<(Vec<u8>, Vec<Piece>), Reason> {
    let start = c.at;
    let line_end = c.bytes[start..]
        .iter()
        .position(|b| *b == b'\n')
        .map_or(c.bytes.len(), |n| start + n);
    // A line break inside the string is refused, so nothing past the line is read.
    let line = &c.bytes[..line_end];
    let mut at = start;
    let mut pieces = Vec::new();
    loop {
        let rest = &line[at..];
        let quote = usize::from(rest.first() == Some(&b'"'));
        let leading = leading_escape(rest);
        let free = free_len(rest);
        let open = if rest.starts_with(b"%{") { 2 } else { 0 };
        // The longest match wins, and the pattern that comes first in the scanner wins a tie.
        let longest = quote.max(leading).max(free).max(open);
        if longest == 0 {
            return Err(FORM);
        }
        if longest == quote {
            c.at = at + 1;
            return Ok((line[start..at].to_vec(), pieces));
        }
        if longest == leading || longest == free {
            pieces.push(Piece::Text(line[at..at + longest].to_vec()));
            at += longest;
        } else {
            let (variable, end) = macro_end(line, at)?;
            pieces.push(Piece::Var(variable));
            at = end;
        }
    }
}

/// An odd number of backslashes and a quote, which begin a token, and the units that follow the quote.
fn leading_escape(rest: &[u8]) -> usize {
    let run = rest.iter().take_while(|b| **b == b'\\').count();
    if run % 2 == 1 && rest.get(run) == Some(&b'"') {
        run + 1 + free_len(&rest[run + 1..])
    } else {
        0
    }
}

/// The length of the longest series of units at the start of `rest` (0 when none matches).
fn free_len(rest: &[u8]) -> usize {
    // `reached[i]` is whether the first `i` bytes are a series of units. It grows as far as the units reach,
    // so a token costs its own length and no more.
    let mut reached = vec![true];
    let mark = |reached: &mut Vec<bool>, at: usize| {
        if reached.len() <= at {
            reached.resize(at + 1, false);
        }
        reached[at] = true;
    };
    let mut longest = 0;
    let mut i = 0;
    while i < reached.len() {
        if reached[i] {
            longest = i;
            if let Some(&b) = rest.get(i) {
                if b != b'"' && b != b'%' {
                    mark(&mut reached, i + 1);
                }
                if b == b'%' && rest.get(i + 1).is_some_and(|next| *next != b'{') {
                    mark(&mut reached, i + 2);
                }
                if b != b'\\' {
                    let run = rest[i + 1..].iter().take_while(|b| **b == b'\\').count();
                    if run % 2 == 1 {
                        match rest.get(i + 1 + run) {
                            Some(b'"') => mark(&mut reached, i + run + 2),
                            Some(b'%') if rest.get(i + run + 2) == Some(&b'{') => {
                                mark(&mut reached, i + run + 3);
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        i += 1;
    }
    longest
}

/// The macro that opens at `at` (a `%{`) and where it ends: its name, a `}`, and a `%` that the scanner takes with
/// the `}` unless a `{` follows it. The name is one of the variables that the scanner knows, and the
/// scanner refuses every other, and the library with it.
fn macro_end(line: &[u8], at: usize) -> Result<(Variable, usize), Reason> {
    let (variable, length) = variable::macro_at(&line[at..])?;
    let end = at + length;
    Ok((
        variable,
        match (line.get(end), line.get(end + 1)) {
            (Some(b'%'), next) if next != Some(&b'{') => end + 1,
            _ => end,
        },
    ))
}
