//! A table of rules, each with a target.

use std::collections::BTreeSet;

use super::host::RequestHost;
use super::path::Target;
use super::rule::{RouteError, Rule};

/// The rules in the order they were given, each with its target. The table is valid: no two of its rules have the
/// same host and path. How many rules a table may hold is for the caller to bound.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Table<T> {
    entries: Vec<(Rule, T)>,
}

impl<T> Default for Table<T> {
    fn default() -> Table<T> {
        Table {
            entries: Vec::new(),
        }
    }
}

impl<T> Table<T> {
    pub fn new(entries: Vec<(Rule, T)>) -> Result<Table<T>, RouteError> {
        let mut seen = BTreeSet::new();
        for (rule, _) in &entries {
            if !seen.insert((rule.host(), rule.path())) {
                return Err(RouteError("two routes have the same host and path"));
            }
        }
        Ok(Table { entries })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The rules, in the order they were given.
    pub fn rules(&self) -> impl Iterator<Item = &Rule> {
        self.entries.iter().map(|(rule, _)| rule)
    }

    /// The target of the most exact rule that holds for a request, if one does. `host` is the value of its `Host`
    /// field, and `target` its request target as it was received.
    pub fn find(&self, host: Option<&[u8]>, target: &[u8]) -> Option<&T> {
        if self.entries.is_empty() {
            return None;
        }
        let host = host.and_then(RequestHost::parse);
        let target = Target::new(target);
        let mut best = None;
        for (rule, found) in &self.entries {
            if let Some(rank) = rule.rank(host.as_ref(), &target)
                && best.is_none_or(|(most, _)| rank > most)
            {
                best = Some((rank, found));
            }
        }
        best.map(|(_, found)| found)
    }
}
