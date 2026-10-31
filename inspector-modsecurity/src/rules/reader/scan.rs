//! Reads a rule file the way the scanner of libmodsecurity reads it, in the forms that rule files are
//! written in, and refuses every other form.
//!
//! The scanner of libmodsecurity does not work by lines. It reads a stream of tokens, and after a directive
//! is complete the next token starts a new directive, on the same line or not: `SecMarker X
//! SecRequestBodyLimit 1` is two directives, and so is a rule followed by another directive after its last
//! quote. An operator and its argument, and an action list, may run over several lines. Text that no rule
//! of a state of the scanner matches is skipped, and a few spellings are cut at another place than the
//! eye expects (a `%` before the closing quote of an operator takes the quote). So a reader that cuts by
//! lines could take a directive for the text of a string, or the text of a string for a directive.
//!
//! This reader instead recognises only the forms below and refuses the rest. What it accepts, the scanner
//! reads in the same way; what the scanner reads and this does not accept is a false refusal, which the
//! guard accepts, as it accepts one for any harmless text it cannot tell from a harmful one.
//!
//! * A rule file is a series of statements. Between statements: blanks, empty lines and comment lines
//!   (`#` to the end of the line). A comment is not continued on the next line, except one that looks like a
//!   commented-out `SecRule` or `SecAction` ending in a backslash, which the scanner continues (see
//!   `Cursor::comment`). A statement ends at the end of its line, or before a `#` that starts a comment
//!   after it.
//! * A directive name is a run of letters and digits, in any case. A name that is glued to its argument, as
//!   `SecRuleEngineOn`, is a name that is not known.
//! * `SecRule`, then blanks, variables (see `variable`), blanks, the operator in
//!   double quotes, a gap, and the actions in double quotes. A gap is blanks and backslash-newline pairs.
//!   The operator is `[!]`, `@name`, one space and the argument; or only a regular expression. The
//!   argument is cut as the scanner cuts it (see `operator`), and has no line break.
//! * The actions are separated by commas, with gaps around them. What an action is, and where its value
//!   ends, is set by the form of that action (see `action`).
//! * `SecAction` and `SecDefaultAction`: a gap and the actions in double quotes.
//! * `SecMarker`: one blank and a name, which may be in quotes.
//! * The directives that say one thing: blanks and the argument, by the form of the directive. A directive that
//!   the library reads to the end of the line (the ones with ids, with words and with a selector, and the updates
//!   of a target) has exactly one blank in front of its argument: the library takes what follows the first blank,
//!   so a second blank, or a tab after a space, would be a part of the argument.
//!
//! A carriage return and a NUL byte are refused wherever they are: the scanner ignores the first outside
//! strings and the library stops reading at the second. So is a file that does not end with a line break:
//! the scanner keeps state between two reads, and a file that stops inside a directive can leave it in a
//! state that makes the next file be read wrongly.

use super::action::{Action, read_actions};
use super::directive::{self, Form, Shape};
use super::operator::{Operator, read_operator_string};
use super::variable::{self, Listed};

/// A fixed sentence that says why a text is refused.
pub(in crate::rules) type Reason = &'static str;

pub(in crate::rules) const NUL_BYTE: Reason = "a rules file holds a NUL byte";
pub(in crate::rules) const CARRIAGE_RETURN: Reason = "a rules file holds a carriage return";
pub(in crate::rules) const NO_LINE_BREAK: Reason = "a rules file does not end with a line break";
pub(in crate::rules) const FORM: Reason = "a directive is not written in a form that is checked";
/// One statement of a rule file.
pub(in crate::rules) struct Statement<'a> {
    /// The directive name, in lower case.
    pub(in crate::rules) keyword: String,
    pub(in crate::rules) body: Body,
    /// The text of the statement, from the name to the end of the last token.
    pub(in crate::rules) text: &'a [u8],
}

pub(in crate::rules) enum Body {
    Rule(Rule),
    /// `SecAction` and `SecDefaultAction`.
    Actions(Vec<Action>),
    /// `SecMarker`, with the name as the library reads it.
    Marker(String),
    /// A directive with one argument, as written (with its quotes, if it has them).
    Argument(Vec<u8>),
    /// `SecRuleUpdateTargetBy...`: what to update, as written, and the variables.
    Targets {
        selector: Vec<u8>,
        variables: Vec<Listed>,
    },
    /// A directive with no argument.
    Plain,
}

pub(in crate::rules) struct Rule {
    pub(in crate::rules) variables: Vec<Listed>,
    pub(in crate::rules) operator: Operator,
    pub(in crate::rules) actions: Vec<Action>,
}

/// Reads the statements of a rule file, or says why it cannot.
pub(in crate::rules) fn read(text: &[u8]) -> Result<Vec<Statement<'_>>, Reason> {
    if text.contains(&0) {
        return Err(NUL_BYTE);
    }
    if text.contains(&b'\r') {
        return Err(CARRIAGE_RETURN);
    }
    if text.last().is_some_and(|last| *last != b'\n') {
        return Err(NO_LINE_BREAK);
    }
    let mut c = Cursor { bytes: text, at: 0 };
    let mut statements = Vec::new();
    loop {
        while matches!(c.peek(), Some(b' ' | b'\t' | b'\n')) {
            c.at += 1;
        }
        match c.peek() {
            None => return Ok(statements),
            Some(b'#') => {
                c.comment()?;
                continue;
            }
            Some(_) => {}
        }
        let start = c.at;
        let name = c.take_while(|b| b.is_ascii_alphanumeric());
        if name.is_empty() {
            return Err(FORM);
        }
        let keyword = String::from_utf8_lossy(name).to_ascii_lowercase();
        let body = match directive::shape(&keyword)? {
            Shape::Rule => read_rule(&mut c)?,
            Shape::Actions => read_actions_directive(&mut c)?,
            Shape::Marker => read_marker(&mut c)?,
            Shape::Targets => read_targets(&mut c)?,
            Shape::Argument(form) => read_argument(&mut c, form)?,
        };
        let end = c.tail()?;
        statements.push(Statement {
            keyword,
            body,
            text: &text[start..end],
        });
    }
}

pub(in crate::rules) struct Cursor<'a> {
    pub(in crate::rules) bytes: &'a [u8],
    pub(in crate::rules) at: usize,
}

impl<'a> Cursor<'a> {
    pub(in crate::rules) fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    pub(in crate::rules) fn peek_at(&self, offset: usize) -> Option<u8> {
        self.bytes.get(self.at + offset).copied()
    }

    /// Takes the bytes while `f` holds.
    pub(in crate::rules) fn take_while(&mut self, f: impl Fn(u8) -> bool) -> &'a [u8] {
        let start = self.at;
        while self.peek().is_some_and(&f) {
            self.at += 1;
        }
        &self.bytes[start..self.at]
    }

    /// Skips spaces and tabs; whether there were any.
    pub(in crate::rules) fn blanks(&mut self) -> bool {
        !self.take_while(|b| matches!(b, b' ' | b'\t')).is_empty()
    }

    /// Skips one blank and refuses a second one.
    fn one_blank(&mut self) -> Result<(), Reason> {
        if !matches!(self.peek(), Some(b' ' | b'\t')) {
            return Err(FORM);
        }
        self.at += 1;
        if matches!(self.peek(), Some(b' ' | b'\t')) {
            return Err(FORM);
        }
        Ok(())
    }

    /// Skips blanks and backslash-newline pairs; whether there were any.
    pub(in crate::rules) fn gap(&mut self) -> bool {
        let start = self.at;
        loop {
            self.blanks();
            if self.peek() == Some(b'\\') && self.peek_at(1) == Some(b'\n') {
                self.at += 2;
            } else {
                return self.at > start;
            }
        }
    }

    pub(in crate::rules) fn expect(&mut self, byte: u8) -> Result<(), Reason> {
        if self.peek() == Some(byte) {
            self.at += 1;
            Ok(())
        } else {
            Err(FORM)
        }
    }

    /// Whether nothing but spaces is left of the line. The library takes the rest of the line as the argument
    /// of some directives, a comment and a tab included, so a statement that has more there is not read in the
    /// same way.
    fn only_spaces_left(&self) -> bool {
        self.line().iter().all(|b| *b == b' ')
    }

    /// Skips to the end of the line and past it.
    fn skip_line(&mut self) {
        self.take_while(|b| b != b'\n');
        if self.peek().is_some() {
            self.at += 1;
        }
    }

    /// The rest of the line from the cursor, without its line break.
    fn line(&self) -> &'a [u8] {
        let rest = &self.bytes[self.at..];
        &rest[..rest.iter().position(|b| *b == b'\n').unwrap_or(rest.len())]
    }

    /// Skips a comment, which starts at the cursor, to the end of its line and past it.
    ///
    /// The scanner reads a comment that is a commented-out `SecRule` or `SecAction` (after the `#` and
    /// blanks, in any case) and ends in a backslash as a comment that goes on in the lines after it (so does
    /// one that ends with the name, when the next line ends in a backslash: the line break is the byte that
    /// the scanner wants after the name, and the next line is the rest of the comment), while
    /// they end in a backslash, and the first line that does not is a line of that comment as well (an empty
    /// line is read over, or ends the comment, as the form of the first line decides). Those lines are
    /// comments for this reader only if they start with a `#` too, and the empty lines among them are
    /// skipped; a statement in one of them is one the scanner does not read, and the text is refused. (The
    /// Core Rule Set holds such examples in its setup file, every line of which is a comment.)
    fn comment(&mut self) -> Result<(), Reason> {
        let line = self.line();
        let blank = |b: &u8| matches!(b, b' ' | b'\t');
        let text = line[1..]
            .iter()
            .position(|b| !blank(b))
            .map_or(&[][..], |n| &line[1 + n..]);
        let name =
            |word: &[u8]| text.len() >= word.len() && text[..word.len()].eq_ignore_ascii_case(word);
        let ends_in_backslash = |line: &[u8]| {
            line.iter()
                .rposition(|b| !blank(b))
                .is_some_and(|n| line[n] == b'\\')
        };
        let keyword = if name(b"secrule") {
            7
        } else if name(b"secaction") {
            9
        } else {
            0
        };
        let mut continued = keyword > 0 && ends_in_backslash(line);
        self.skip_line();
        if keyword > 0 && text.len() == keyword && ends_in_backslash(self.line()) {
            continued = true;
        }
        while continued && self.at < self.bytes.len() {
            let line = self.line();
            match line.iter().find(|b| !blank(b)) {
                None => {
                    self.skip_line();
                    continue;
                }
                Some(b'#') => {}
                Some(_) => return Err(FORM),
            }
            continued = ends_in_backslash(line);
            self.skip_line();
        }
        Ok(())
    }

    /// The end of a statement: blanks, then the end of the line or the end of the text, or a comment.
    /// Returns where the text of the statement ended.
    fn tail(&mut self) -> Result<usize, Reason> {
        let end = self.at;
        self.blanks();
        match self.peek() {
            None => {}
            Some(b'\n') => self.at += 1,
            Some(b'#') => self.comment()?,
            Some(_) => return Err(FORM),
        }
        Ok(end)
    }

    /// A string in double quotes with no line break and no `"` inside; returns what is inside.
    fn quoted(&mut self) -> Result<&'a [u8], Reason> {
        self.expect(b'"')?;
        let inside = self.take_while(|b| b != b'"' && b != b'\n');
        self.expect(b'"')?;
        Ok(inside)
    }
}

/// `SecRule`: variables, the operator and the actions.
fn read_rule(c: &mut Cursor<'_>) -> Result<Body, Reason> {
    if !c.blanks() {
        return Err(FORM);
    }
    // The variables never hold a blank or a quote: a regular expression in them has no room for one.
    let variables = c.take_while(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'"'));
    let variables = variable::read_list(variables)?;
    if !c.gap() {
        return Err(FORM);
    }
    let operator = read_operator_string(c)?;
    let after_operator = c.at;
    let actions = if c.gap() && c.peek() == Some(b'"') {
        read_actions(c)?
    } else {
        // A rule with no actions, as the last rule of a chain is written. The scanner reads the actions of
        // such a rule from the next line unless that line is empty, so only an empty line (or the end of
        // the text) may follow.
        c.at = after_operator;
        c.blanks();
        if c.peek() == Some(b'\n') {
            c.at += 1;
            c.blanks();
        }
        if c.at == after_operator || !matches!(c.peek(), None | Some(b'\n')) {
            return Err(FORM);
        }
        Vec::new()
    };
    Ok(Body::Rule(Rule {
        variables,
        operator,
        actions,
    }))
}

/// `SecAction` and `SecDefaultAction`.
fn read_actions_directive(c: &mut Cursor<'_>) -> Result<Body, Reason> {
    if !c.gap() {
        return Err(FORM);
    }
    Ok(Body::Actions(read_actions(c)?))
}

/// Whether `name` is a name of a marker: one or more letters, digits, `.`, `_` and `-`.
pub(in crate::rules) fn is_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// `SecMarker`.
fn read_marker(c: &mut Cursor<'_>) -> Result<Body, Reason> {
    // The library cuts the name off after the first blank and keeps what follows, so a second blank would
    // stay in front of the name: the marker would be one that no `skipAfter` names. Exactly one blank.
    if !matches!(c.peek(), Some(b' ' | b'\t')) {
        return Err(FORM);
    }
    c.at += 1;
    let in_quotes = c.peek() == Some(b'"');
    if in_quotes {
        c.at += 1;
    }
    let token = c.take_while(|b| !matches!(b, b',' | b' ' | b'\t' | b'"' | b'\n'));
    if in_quotes {
        c.expect(b'"')?;
    }
    // The library takes a pair of double quotes off, and then a pair of single quotes.
    let mut name = token;
    for quote in [b'"', b'\''] {
        if let [first, inside @ .., last] = name
            && *first == quote
            && *last == quote
        {
            name = inside;
        }
    }
    if !is_name(name) {
        return Err(FORM);
    }
    Ok(Body::Marker(String::from_utf8_lossy(name).into_owned()))
}

/// `SecRuleUpdateTargetBy...`: what to update, a word of plain bytes or a string in double quotes, and the
/// variables, a word or a string in double quotes.
fn read_targets(c: &mut Cursor<'_>) -> Result<Body, Reason> {
    c.one_blank()?;
    let selector = if c.peek() == Some(b'"') {
        in_quotes(c.quoted()?)
    } else {
        c.take_while(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':' | b'/' | b'*')
        })
        .to_vec()
    };
    if selector.is_empty() || !c.blanks() {
        return Err(FORM);
    }
    let variables = if c.peek() == Some(b'"') {
        c.quoted()?
    } else {
        c.take_while(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'"'))
    };
    Ok(Body::Targets {
        selector,
        variables: variable::read_list(variables)?,
    })
}

/// A text with the double quotes that it was written in.
fn in_quotes(inside: &[u8]) -> Vec<u8> {
    [b"\"", inside, b"\""].concat()
}

/// The next word, as written, if it is one of `allowed` (in any case).
fn word_in(c: &mut Cursor<'_>, allowed: &[&str]) -> Option<Vec<u8>> {
    let word = c.take_while(|b| b.is_ascii_alphabetic());
    allowed
        .contains(&String::from_utf8_lossy(word).to_ascii_lowercase().as_str())
        .then(|| word.to_vec())
}

/// A directive with one argument.
fn read_argument(c: &mut Cursor<'_>, form: Form) -> Result<Body, Reason> {
    if matches!(form, Form::Nothing) {
        return Ok(Body::Plain);
    }
    // The scanner cuts the string of SecComponentSignature at the first space of the token, and the
    // library fails with a tab in its place: only one space is accepted before it.
    if matches!(form, Form::Quoted) {
        c.expect(b' ')?;
    } else if matches!(form, Form::Ids | Form::Words | Form::Selector) {
        c.one_blank()?;
    } else if !c.blanks() {
        return Err(FORM);
    }
    let some = |text: &[u8]| (!text.is_empty()).then(|| text.to_vec());
    let read = match form {
        Form::Engine => word_in(c, &["on", "off", "detectiononly"]),
        Form::Switch => word_in(c, &["on", "off"]),
        Form::AuditOff => word_in(c, &["off"]),
        Form::BodyLimitAction => word_in(c, &["processpartial", "reject"]),
        Form::Number => some(c.take_while(|b| b.is_ascii_digit())),
        // These three are read by the library to the end of the line, so nothing may follow but spaces.
        Form::Ids => some(c.take_while(|b| b.is_ascii_digit() || matches!(b, b'-' | b' ' | b'\t')))
            .filter(|_| c.only_spaces_left()),
        Form::Words => some(c.take_while(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'/' | b'+' | b'.' | b'_' | b'*' | b'-' | b';' | b'=' | b' '
                )
        }))
        .filter(|_| c.only_spaces_left()),
        Form::Quoted => c.quoted().ok().map(in_quotes),
        Form::Selector if c.peek() == Some(b'"') => c.quoted().ok().map(in_quotes),
        Form::Selector => {
            some(c.take_while(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'"' | b'|' | b'#' | b'\\')))
                .filter(|_| c.only_spaces_left())
        }
        Form::Nothing => Some(Vec::new()),
    };
    read.map(Body::Argument).ok_or(FORM)
}
