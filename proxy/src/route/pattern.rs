//! The path of a rule that is a regular expression.
//!
//! The expression is made into a complete DFA when the configuration is read, so that matching a path takes one
//! look-up in a table for each byte, whatever the expression is, and there is no slower way for a path to take. An
//! expression that would need more than the limits below is refused then (`a route path regex is too large`), not
//! run in a slower way later: the expression is the operator's, but the path that makes a matcher slow is the
//! client's to choose.

use std::fmt;
use std::sync::Arc;

use regex_automata::dfa::{Automaton, StartKind, dense};
use regex_automata::nfa::thompson;
use regex_automata::{Input, MatchError};
use regex_syntax::ast::{self, Ast, Flag, FlagsItemKind, GroupKind};
use regex_syntax::hir::translate::TranslatorBuilder;

use super::path::{PathRank, Target};
use super::rule::RouteError;

const MAX_PATTERN_BYTES: usize = 255;

/// The most bytes that the NFA of the expression may take.
const NFA_LIMIT: usize = 64 * 1024;

/// The most bytes that the DFA may take, and that the work of making it may take.
const DFA_LIMIT: usize = 256 * 1024;

const INVALID: RouteError = RouteError("a route path regex is not a valid regular expression");
const TOO_LARGE: RouteError = RouteError("a route path regex is too large");

/// The path of a rule as a regular expression: the rule holds for every path that the expression matches somewhere
/// in it. The DFA is shared by the copies of the rule, which a reading of the configuration makes of its table.
#[derive(Clone)]
pub(super) struct PathPattern {
    /// As it was given.
    text: String,
    dfa: Arc<dense::DFA<Vec<u32>>>,
}

/// The expression is made of its text alone, so two with the same text are the same.
impl PartialEq for PathPattern {
    fn eq(&self, other: &PathPattern) -> bool {
        self.text == other.text
    }
}

impl Eq for PathPattern {}

/// The text only: a DFA is a table of many bytes.
impl fmt::Debug for PathPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PathPattern").field(&self.text).finish()
    }
}

/// Finds an expression that switches Unicode on: `(?u)`, `(?iu)` or `(?u:..)`, the flag `u` not after a `-`. The
/// path is matched as bytes, with Unicode off. What Unicode would add (`\w`, `\d`, `\b`, the case of letters
/// beyond ASCII and the classes `\p` and `\P`) needs tables that a build of this crate may or may not have, as
/// another program of the same tree, with its own features, may have them: the same expression would then be taken
/// by one program and refused by another. With Unicode off `\p` and `\P` are refused by the translation, in all
/// builds, so the flag is the only way in.
struct Unicode;

impl ast::Visitor for Unicode {
    type Output = ();
    type Err = ();

    fn finish(self) -> Result<(), ()> {
        Ok(())
    }

    fn visit_pre(&mut self, node: &Ast) -> Result<(), ()> {
        let flags = match node {
            Ast::Flags(set) => &set.flags,
            Ast::Group(group) => match &group.kind {
                GroupKind::NonCapturing(flags) => flags,
                _ => return Ok(()),
            },
            _ => return Ok(()),
        };
        let mut negated = false;
        for item in &flags.items {
            match item.kind {
                FlagsItemKind::Negation => negated = true,
                FlagsItemKind::Flag(Flag::Unicode) if !negated => return Err(()),
                FlagsItemKind::Flag(_) => {}
            }
        }
        Ok(())
    }
}

impl PathPattern {
    /// The text is 1 to 255 bytes of the visible ASCII characters (`\xNN` writes any other byte), and an expression of
    /// the syntax of the `regex` crate with Unicode off. The syntax stage (the expression is not valid) is told
    /// from the stages that make the NFA and the DFA, which only fail for their size (the expression is too large).
    pub(super) fn new(text: &str) -> Result<PathPattern, RouteError> {
        if !(1..=MAX_PATTERN_BYTES).contains(&text.len()) {
            return Err(RouteError("a route path regex is not 1 to 255 bytes"));
        }
        if !text.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(RouteError(
                "a route path regex has a character that is not allowed",
            ));
        }
        let parsed = ast::parse::Parser::new().parse(text).map_err(|_| INVALID)?;
        ast::visit(&parsed, Unicode).map_err(|()| INVALID)?;
        let hir = TranslatorBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .translate(text, &parsed)
            .map_err(|_| INVALID)?;
        // The NFA of an expression that has passed the syntax stage fails for its size only.
        let nfa = thompson::Compiler::new()
            .configure(
                thompson::Config::new()
                    .utf8(false)
                    .nfa_size_limit(Some(NFA_LIMIT)),
            )
            .build_from_hir(&hir)
            .map_err(|_| TOO_LARGE)?;
        let dfa = dense::Builder::new()
            .configure(
                dense::Config::new()
                    .start_kind(StartKind::Unanchored)
                    .dfa_size_limit(Some(DFA_LIMIT))
                    .determinize_size_limit(Some(DFA_LIMIT)),
            )
            .build_from_nfa(&nfa)
            .map_err(|e| {
                if e.is_size_limit_exceeded() {
                    TOO_LARGE
                } else {
                    INVALID
                }
            })?;
        if !runs_without_error(&dfa) {
            return Err(INVALID);
        }
        Ok(PathPattern {
            text: text.to_owned(),
            dfa: Arc::new(dfa),
        })
    }

    pub(super) fn as_str(&self) -> &str {
        &self.text
    }

    /// How well the rule holds for the target; `None` if it does not, and for every ambiguous target. A search that
    /// fails finds no match, and a DFA made by `new` cannot fail (see `runs_without_error`).
    pub(super) fn rank(&self, target: &Target) -> Option<PathRank> {
        let path = target.unambiguous()?;
        let found = self.dfa.try_search_fwd(&Input::new(path).earliest(true));
        matches!(found, Ok(Some(_))).then_some(PathRank::Pattern)
    }
}

/// Whether a search of any path by `dfa`, which is unanchored, ends in a match or in none and never in an error. A
/// DFA can fail in a search for three reasons: it does not run the kind of search that is asked for, it meets a byte
/// that it was made to quit at, and it gives up (only a lazy DFA does). It was made for unanchored searches (and
/// the search is one), and no byte quits it unless the configuration says so, as that of `new` does not; the checks
/// are that the start state of such a search is there, and that no byte takes the DFA from it to a quit state (a byte
/// that quits does so in every state).
fn runs_without_error(dfa: &dense::DFA<Vec<u32>>) -> bool {
    let start: Result<_, MatchError> = dfa.start_state_forward(&Input::new(b""));
    match start {
        Ok(start) => (0..=u8::MAX).all(|byte| !dfa.is_quit_state(dfa.next_state(start, byte))),
        Err(_) => false,
    }
}
