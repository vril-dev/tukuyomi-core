//! The text in which what the reader read is compared with what the library built.
//!
//! `Out` writes it, one item to a line: a word, a number, or a string as its length, a colon and its bytes.
//! `Out` in `bridge.cc` writes the same, and for a text that the reader read as the scanner does the two come out
//! the same to the byte. The functions here write the parts that are alike wherever they occur: a variable, a text
//! with macros, a `setvar`, the variables of a list.

use super::reader::{Kind, Listed, Modifier, Piece, SetVar, Variable};

/// The text that is compared.
#[derive(Default)]
pub(super) struct Out(Vec<u8>);

impl Out {
    pub(super) fn word(&mut self, word: &str) {
        self.0.extend_from_slice(word.as_bytes());
        self.0.push(b'\n');
    }

    pub(super) fn num(&mut self, number: i64) {
        self.word(&number.to_string());
    }

    pub(super) fn flag(&mut self, flag: bool) {
        self.num(i64::from(flag));
    }

    pub(super) fn count(&mut self, count: usize) {
        self.num(i64::try_from(count).unwrap_or(i64::MAX));
    }

    pub(super) fn str(&mut self, text: &[u8]) {
        self.0.extend_from_slice(text.len().to_string().as_bytes());
        self.0.push(b':');
        self.0.extend_from_slice(text);
        self.0.push(b'\n');
    }

    pub(super) fn text(self) -> Vec<u8> {
        self.0
    }
}

/// A variable: its collection in lower case and what follows it.
pub(super) fn variable(variable: &Variable) -> Vec<u8> {
    let mut out = Out::default();
    out.str(variable.collection.to_ascii_lowercase().as_bytes());
    match &variable.kind {
        Kind::Bare => out.word("bare"),
        Kind::Element(name) => {
            out.word("element");
            out.str(name);
        }
        Kind::Regex(regex) => {
            out.word("regex");
            out.str(regex);
        }
        Kind::Dynamic(parts) => {
            out.word("dynamic");
            out.str(&pieces(parts));
        }
    }
    out.text()
}

/// A text with macros: the number of its pieces, and each piece.
pub(super) fn pieces(parts: &[Piece]) -> Vec<u8> {
    let mut out = Out::default();
    out.count(parts.len());
    for part in parts {
        match part {
            Piece::Text(text) => {
                out.word("text");
                out.str(text);
            }
            Piece::Var(var) => {
                out.word("var");
                out.str(&variable(var));
            }
        }
    }
    out.text()
}

/// A text with macros that a rule may not have.
pub(super) fn optional_pieces(out: &mut Out, parts: Option<&[Piece]>) {
    out.flag(parts.is_some());
    out.str(&parts.map(pieces).unwrap_or_default());
}

/// A `setvar`: what it does, its variable and its value.
pub(super) fn set_var(set_var: &SetVar) -> Vec<u8> {
    let mut out = Out::default();
    out.num(i64::from(set_var.operation));
    out.str(&variable(&Variable {
        collection: set_var.collection.clone(),
        kind: Kind::Dynamic(set_var.target.clone()),
    }));
    optional_pieces(&mut out, set_var.value.as_deref());
    out.text()
}

/// What to leave out of a variable: a regular expression, or a name (in capitals).
pub(super) type Key = (bool, Vec<u8>);

/// A variable of a list, as the library holds it: what is in front of it, the variable and what is to be
/// left out of it.
pub(super) fn listed(modifier: Modifier, variable_: &Variable, keys: &[Key]) -> Vec<u8> {
    let mut out = Out::default();
    out.word(match modifier {
        Modifier::Plain => "plain",
        Modifier::Count => "count",
        Modifier::Exclusion => "exclusion",
    });
    out.str(&variable(variable_));
    out.count(keys.len());
    for (regex, text) in keys {
        out.word(if *regex { "regex" } else { "string" });
        out.str(text);
    }
    out.text()
}

/// A variable of the list of a rule once the library has read it.
pub(super) struct Held {
    modifier: Modifier,
    variable: Variable,
    keys: Vec<Key>,
}

impl Held {
    pub(super) fn encode(&self) -> Vec<u8> {
        listed(self.modifier, &self.variable, &self.keys)
    }
}

/// The list of a rule as the library keeps it: the variables with `!` are taken out, and so is a variable that
/// one of them names; each variable that is left of the same collection as an excluded one keeps what that one
/// says to leave out. The library works from the back of the list.
pub(super) fn held(list: &[Listed]) -> Vec<Held> {
    let excluded: Vec<&Variable> = list
        .iter()
        .rev()
        .filter(|one| one.modifier == Modifier::Exclusion)
        .map(|one| &one.variable)
        .collect();
    list.iter()
        .filter(|one| one.modifier != Modifier::Exclusion)
        .filter(|one| {
            !excluded
                .iter()
                .any(|e| e.collection == one.variable.collection && e.name() == one.variable.name())
        })
        .map(|one| Held {
            modifier: one.modifier,
            variable: one.variable.clone(),
            keys: excluded
                .iter()
                .filter(|e| same_collection(&e.collection, &one.variable.collection))
                .map(|e| key(e))
                .collect(),
        })
        .collect()
}

/// The library compares the collection of the excluded variable in capitals with the other as it is.
fn same_collection(excluded: &str, other: &str) -> bool {
    excluded.len() == other.len()
        && excluded
            .bytes()
            .zip(other.bytes())
            .all(|(a, b)| a.to_ascii_uppercase() == b)
}

fn key(excluded: &Variable) -> Key {
    match &excluded.kind {
        Kind::Regex(regex) => (true, regex.clone()),
        _ => (false, excluded.name().to_ascii_uppercase()),
    }
}
