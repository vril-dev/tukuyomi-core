//! Why a set of rules is not built.

use std::fmt;

/// The exit code for a set of rules that the checks refuse or that the engine library cannot read.
pub const EXIT_RULES: i32 = 11;
/// The exit code for a failure of the environment: the working directory, or an object that the
/// engine library cannot make.
pub const EXIT_ENVIRONMENT: i32 = 14;

/// The reason a set of rules is not built. It is a fixed sentence and, at most, the path of the rule
/// file in the generation: never an absolute path and never a value from the rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// The exit code of the inspector.
    pub exit: i32,
    reason: &'static str,
    file: Option<String>,
}

impl Refusal {
    /// A refused or failing set of rules. `file` is a path of the generation that has passed the check
    /// of its form.
    pub(super) fn rules(reason: &'static str, file: Option<&str>) -> Refusal {
        Refusal {
            exit: EXIT_RULES,
            reason,
            file: file.map(str::to_owned),
        }
    }

    /// A failure of the environment.
    pub(super) fn environment(reason: &'static str) -> Refusal {
        Refusal {
            exit: EXIT_ENVIRONMENT,
            reason,
            file: None,
        }
    }

    pub fn reason(&self) -> &'static str {
        self.reason
    }

    /// The path of the rule file that the reason is about.
    pub fn file(&self) -> Option<&str> {
        self.file.as_deref()
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.file {
            Some(file) => write!(f, "{file}: {}", self.reason),
            None => f.write_str(self.reason),
        }
    }
}

impl std::error::Error for Refusal {}
