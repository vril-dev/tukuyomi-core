//! A table of rules, each with a target.

use std::collections::BTreeSet;

use super::host::RequestHost;
use super::path::Target;
use super::rule::{Rank, RouteError, Rule};

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

    /// The targets, in the order the rules were given.
    pub fn targets(&self) -> impl Iterator<Item = &T> {
        self.entries.iter().map(|(_, found)| found)
    }

    /// The most exact rule that holds for a request, as its rank and the position of its entry.
    fn best(&self, host: Option<&RequestHost>, target: &Target) -> Option<(Rank, usize)> {
        let mut best = None;
        for (at, (rule, _)) in self.entries.iter().enumerate() {
            if let Some(rank) = rule.rank(host, target)
                && best.is_none_or(|(most, _)| rank > most)
            {
                best = Some((rank, at));
            }
        }
        best
    }

    /// The target of the most exact rule that holds for a request, if one does. `host` is the value of its `Host`
    /// field, and `target` its request target as it was received.
    pub fn find(&self, host: Option<&[u8]>, target: &[u8]) -> Option<&T> {
        if self.entries.is_empty() {
            return None;
        }
        let host = host.and_then(RequestHost::parse);
        let (_, at) = self.best(host.as_ref(), &Target::new(target))?;
        self.entries.get(at).map(|(_, found)| found)
    }

    /// The most exact rule for the path as received, for its canonical form `canonical` and for `canonical` with a `/`
    /// added at the end, as the positions of their entries. The second is left out if `canonical` is the path as
    /// received, and the third if `canonical` ends in a `/`: they would be the rules of the first and the second. The
    /// third is also left out if the first is for the path as received itself and not a prefix of it: its operator
    /// wrote a rule for that path, and the path with a `/` after it is another one.
    fn ways(&self, host: &RequestHost, target: &Target, canonical: &[u8]) -> [Option<usize>; 3] {
        let host = Some(host);
        let received = self.best(host, target);
        let spelt = if target.path_is(canonical) {
            None
        } else {
            self.best(host, &Target::new(canonical))
        };
        let slashed = if canonical.ends_with(b"/")
            || received.is_some_and(|(rank, _)| rank.by_exact_path())
        {
            None
        } else {
            let mut path = canonical.to_vec();
            path.push(b'/');
            self.best(host, &Target::new(&path))
        };
        [received, spelt, slashed].map(|way| way.map(|(_, at)| at))
    }

    /// The targets of the rules that a request could be taken for, however its target is written, each once and in
    /// the order the rules were given. If the `Host` can be read and the path of the target has a canonical form,
    /// these are the rule that is the most exact for the path as received, for its canonical form, and, if that does
    /// not end in `/` and the rule for the path as received is not for that path itself, for the canonical form with
    /// a `/` added (an application may answer for `/private` with what it has for `/private/`); the query is not part
    /// of any of them. Otherwise they are the rules whose host holds for the request, whatever their path, and every
    /// rule if the `Host` cannot be read.
    pub fn could_hold<'a>(
        &'a self,
        host: Option<&'a [u8]>,
        target: &'a [u8],
    ) -> impl Iterator<Item = &'a T> {
        let host = host.and_then(RequestHost::parse);
        let target = Target::new(target);
        let ways = host
            .as_ref()
            .zip(target.canonical())
            .map(|(host, canonical)| self.ways(host, &target, &canonical));
        self.entries
            .iter()
            .enumerate()
            .filter(move |(at, (rule, _))| match &ways {
                Some(ways) => ways.contains(&Some(*at)),
                None => rule.could_hold(host.as_ref()),
            })
            .map(|(_, (_, found))| found)
    }
}
