//! Why a step of the command failed.

use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    /// A fixed sentence.
    Text(&'static str),
    /// The CA refused with a problem document; this is its `type` with the bytes outside 0x20 to 0x7e escaped.
    Problem(String),
}

impl From<&'static str> for Failure {
    fn from(text: &'static str) -> Failure {
        Failure::Text(text)
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Failure::Text(text) => f.write_str(text),
            Failure::Problem(kind) => write!(f, "the CA refused with the problem \"{kind}\""),
        }
    }
}
