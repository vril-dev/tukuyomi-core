//! One rule: a host, a path or a path regex, any of them or none, a priority, and how well it holds for a request.

use std::cmp::Reverse;

use super::host::{HostRank, HostRule, RequestHost};
use super::path::{PathRank, PathRule, Target};
use super::pattern::PathPattern;

/// The greatest priority of a rule, and the least one is its opposite.
const MAX_PRIORITY: i16 = 1000;

/// Why a rule was refused: a fixed English sentence, never a value that was read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteError(pub &'static str);

/// How well a rule holds for a request: the host decides first, then the priority (the smaller number is the more
/// exact), then the path. A greater rank is a rule that is more exact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Rank {
    host: HostRank,
    priority: Reverse<i16>,
    path: PathRank,
}

impl Rank {
    /// Whether the rule holds by its path being the path of the request, and not a prefix of it or absent.
    pub(super) fn by_exact_path(self) -> bool {
        self.path == PathRank::Exact
    }
}

/// What a rule holds for in the path of a request: a path, or a regular expression.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Matcher {
    Path(PathRule),
    Pattern(PathPattern),
}

/// A rule that has passed its checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    host: Option<HostRule>,
    matcher: Option<Matcher>,
    priority: i16,
}

impl Rule {
    /// A rule that chooses an upstream. It may have no host and no path (it then holds for every request), the path
    /// may be `/` (every path), and the host may be a wildcard. Its priority is 0.
    pub fn forward(host: Option<&str>, path: Option<&str>) -> Result<Rule, RouteError> {
        Rule::build(host, path, None, 0, true)
    }

    /// A rule that chooses an upstream, with a `path_regex` in place of the `path` (not both), and a `priority` from
    /// -1000 to 1000: of the rules that hold, the one with the smaller number is the more exact, after the host and
    /// before the path.
    pub fn forward_with(
        host: Option<&str>,
        path: Option<&str>,
        path_regex: Option<&str>,
        priority: i64,
    ) -> Result<Rule, RouteError> {
        Rule::build(host, path, path_regex, priority, true)
    }

    /// A rule that lets a request through without inspection. It has a path, which is not `/` alone, for that would
    /// skip the inspection of every request, and its host is not a wildcard (the rules of a bundle are written to its
    /// manifest, which the inspector checks in this form). It has neither a path regex nor a priority: a mistake in
    /// either would let a request through that has to be inspected.
    pub fn bypass(host: Option<&str>, path: &str) -> Result<Rule, RouteError> {
        Rule::build(host, Some(path), None, 0, false)
    }

    fn build(
        host: Option<&str>,
        path: Option<&str>,
        path_regex: Option<&str>,
        priority: i64,
        open: bool,
    ) -> Result<Rule, RouteError> {
        let host = host.map(|host| HostRule::new(host, open)).transpose()?;
        let matcher = match (path, path_regex) {
            (Some(_), Some(_)) => {
                return Err(RouteError("a route has both a path and a path regex"));
            }
            (Some(path), None) => Some(Matcher::Path(PathRule::new(path, open)?)),
            (None, Some(text)) => Some(Matcher::Pattern(PathPattern::new(text)?)),
            (None, None) => None,
        };
        let priority = i16::try_from(priority)
            .ok()
            .filter(|priority| (-MAX_PRIORITY..=MAX_PRIORITY).contains(priority))
            .ok_or(RouteError("a route priority is not -1000 to 1000"))?;
        Ok(Rule {
            host,
            matcher,
            priority,
        })
    }

    pub fn host(&self) -> Option<&str> {
        self.host.as_ref().map(HostRule::as_str)
    }

    /// The path of the rule, if it has one: not its path regex.
    pub fn path(&self) -> Option<&str> {
        match &self.matcher {
            Some(Matcher::Path(path)) => Some(path.as_str()),
            _ => None,
        }
    }

    pub fn path_regex(&self) -> Option<&str> {
        match &self.matcher {
            Some(Matcher::Pattern(pattern)) => Some(pattern.as_str()),
            _ => None,
        }
    }

    pub fn priority(&self) -> i16 {
        self.priority
    }

    /// What tells the rule from the others of a table: its host, its path and its path regex, of which one at most is
    /// there. A path and a path regex of the same text are two places. The priority is not part of it, so two rules
    /// that differ in it only are the same place.
    pub fn place(&self) -> (Option<&str>, Option<&str>, Option<&str>) {
        (self.host(), self.path(), self.path_regex())
    }

    /// The port that the host of the rule names, if it has a host with a port.
    pub fn port(&self) -> Option<u16> {
        self.host.as_ref().and_then(HostRule::port)
    }

    /// How well the rule holds for a request with this host (`None`: it cannot be read) and this target, or `None`
    /// if it does not hold.
    pub(super) fn rank(&self, host: Option<&RequestHost>, target: &Target) -> Option<Rank> {
        let host = match &self.host {
            Some(rule) => rule.rank(host?)?,
            None => HostRank::ANY,
        };
        let path = match &self.matcher {
            Some(Matcher::Path(rule)) => rule.rank(target)?,
            Some(Matcher::Pattern(rule)) => rule.rank(target)?,
            None => PathRank::Any,
        };
        Some(Rank {
            host,
            priority: Reverse(self.priority),
            path,
        })
    }

    /// How well the rule would hold in a table of rules that have no path regex and whose priorities are all 0: not
    /// at all for a rule with a path regex, and without its priority for another one. The path regex is not run.
    pub(super) fn plain_rank(&self, host: Option<&RequestHost>, target: &Target) -> Option<Rank> {
        if self.path_regex().is_some() {
            return None;
        }
        let rank = self.rank(host, target)?;
        Some(Rank {
            priority: Reverse(0),
            ..rank
        })
    }

    /// Whether the rule has neither a path regex nor a priority, so that only its host and its path rank it.
    pub(super) fn is_plain(&self) -> bool {
        self.path_regex().is_none() && self.priority == 0
    }

    /// Whether the path of the rule, if it has one, is its own canonical form (see `path::canonical`). A path regex
    /// is not a path, and has none to be.
    pub fn canonical(&self) -> bool {
        match &self.matcher {
            Some(Matcher::Path(path)) => path.is_canonical(),
            _ => true,
        }
    }

    /// Whether the host of the rule holds for a request with this host, or there is no telling because the `Host`
    /// cannot be read (`None`). A rule without a host holds for every host. The path is not looked at.
    pub(super) fn could_hold(&self, host: Option<&RequestHost>) -> bool {
        match (&self.host, host) {
            (Some(rule), Some(host)) => rule.rank(host).is_some(),
            _ => true,
        }
    }
}
