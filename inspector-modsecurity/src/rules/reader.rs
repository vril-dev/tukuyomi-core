//! The reader of the rule files: what the scanner of libmodsecurity reads of a text, in the forms that rule
//! files are written in. Each part of it is a file of its own: `scan` (the statements of a file and the
//! directives that take one argument), `directive` (which directives there are and in what form), `operator`
//! (the operator string of a rule), `action` (the actions of a rule) and `variable` (the variables, in a list and in
//! a macro). What a part does not read in the scanner's way it refuses.

mod action;
mod directive;
mod operator;
mod scan;
mod variable;

pub(super) use action::{ACTION_UNKNOWN, Action, SetVar};
pub(super) use operator::Operator;
pub(super) use scan::{Body, FORM, Reason, Statement, is_name, read};
pub(super) use variable::{Kind, Listed, Modifier, Piece, Variable};

#[cfg(test)]
pub(super) use variable::{NAMES, WRITABLE};
