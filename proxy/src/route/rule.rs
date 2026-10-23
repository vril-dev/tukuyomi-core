//! One rule: a host, a path, both or neither, and how well it holds for a request.

use super::host::{HostRank, HostRule, RequestHost};
use super::path::{PathRank, PathRule, Target};

/// Why a rule was refused: a fixed English sentence, never a value that was read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteError(pub &'static str);

/// How well a rule holds for a request: the host decides first, then the path. A greater rank is a rule that is more
/// exact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Rank {
    host: HostRank,
    path: PathRank,
}

impl Rank {
    /// Whether the rule holds by its path being the path of the request, and not a prefix of it or absent.
    pub(super) fn by_exact_path(self) -> bool {
        self.path == PathRank::Exact
    }
}

/// A rule that has passed its checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    host: Option<HostRule>,
    path: Option<PathRule>,
}

impl Rule {
    /// A rule that chooses an upstream. It may have no host and no path (it then holds for every request), the path
    /// may be `/` (every path), and the host may be a wildcard.
    pub fn forward(host: Option<&str>, path: Option<&str>) -> Result<Rule, RouteError> {
        Rule::build(host, path, true)
    }

    /// A rule that lets a request through without inspection. It has a path, which is not `/` alone, for that would
    /// skip the inspection of every request, and its host is not a wildcard (the rules of a bundle are written to its
    /// manifest, which the inspector checks in this form).
    pub fn bypass(host: Option<&str>, path: &str) -> Result<Rule, RouteError> {
        Rule::build(host, Some(path), false)
    }

    fn build(host: Option<&str>, path: Option<&str>, open: bool) -> Result<Rule, RouteError> {
        let host = host.map(|host| HostRule::new(host, open)).transpose()?;
        let path = path.map(|path| PathRule::new(path, open)).transpose()?;
        Ok(Rule { host, path })
    }

    pub fn host(&self) -> Option<&str> {
        self.host.as_ref().map(HostRule::as_str)
    }

    pub fn path(&self) -> Option<&str> {
        self.path.as_ref().map(PathRule::as_str)
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
        let path = match &self.path {
            Some(rule) => rule.rank(target)?,
            None => PathRank::Any,
        };
        Some(Rank { host, path })
    }

    /// Whether the path of the rule, if it has one, is its own canonical form (see `path::canonical`).
    pub fn canonical(&self) -> bool {
        self.path.as_ref().is_none_or(PathRule::is_canonical)
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
