//! The routes of a rule bundle: the requests that are let through without being inspected.
//!
//! A route has a path and, if it is to hold for one host only, a host. Its action is always `bypass`: a request
//! that a route matches is not handed to the inspector, and goes on to the upstream. What the proxy itself checks
//! (the head, the type of the body and the limit on its size) is done before the request goes on. Its body is held
//! only if it ends within the bytes that are inspected on other routes; a longer one is passed on as the client sends
//! it, with the framing the client used. A gzip body is never decoded, whatever its length. The routes
//! are in the manifest of the bundle, so they are part of its fingerprint, and a running proxy
//! changes them only by switching to another generation.
//!
//! A route is checked when it is made, whether it comes from the file of `rules import` or from a manifest, so the
//! same rules hold on both ways in. They are the rules of `route` for a rule that has a path, and these:
//! - The path is not `/` alone, which would skip the inspection of every request, and has 2 to 255 bytes.
//! - The host is not a wildcard.
//! - A table has at most 256 routes, and no two of them have the same host and path.
//!
//! A request matches a route as `route` says. The table is only asked whether one route holds, for every route has
//! the same action.

use std::sync::{Arc, PoisonError, RwLock};

use serde::Deserialize;

use crate::route::{RouteError, Rule, Table};
use crate::rules::bundle::BundleError;

/// The most routes in a table.
pub const MAX_ROUTES: usize = 256;
const TOO_MANY: BundleError = BundleError("there are more than 256 routes");

impl From<RouteError> for BundleError {
    fn from(e: RouteError) -> BundleError {
        BundleError(e.0)
    }
}

/// One route. The action is always `bypass`, so it is not stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route(Rule);

impl Route {
    /// A route for `path`, and for `host` only if one is given, if both pass the checks above.
    pub fn new(host: Option<&str>, path: &str) -> Result<Route, BundleError> {
        Ok(Route(Rule::bypass(host, path)?))
    }

    pub fn host(&self) -> Option<&str> {
        self.0.host()
    }

    pub fn path(&self) -> &str {
        self.0.path().unwrap_or_default()
    }
}

/// A route as the file of `rules import` and the manifest write it. Any other key is refused.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawRoute {
    #[serde(default, deserialize_with = "crate::config::present")]
    host: Option<String>,
    path: String,
    action: String,
}

/// The routes of a bundle, in the order they were given. The table is valid: every route passed its checks, and
/// there are at most 256 with no two alike.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Routes(Table<()>);

impl Routes {
    pub fn new(routes: Vec<Route>) -> Result<Routes, BundleError> {
        if routes.len() > MAX_ROUTES {
            return Err(TOO_MANY);
        }
        let entries = routes.into_iter().map(|route| (route.0, ())).collect();
        Ok(Routes(Table::new(entries)?))
    }

    /// The table of the raw routes of a manifest or of a file.
    pub(super) fn from_raw(raw: Vec<RawRoute>) -> Result<Routes, BundleError> {
        // Before any route is made, so that a long list costs no more than its parse.
        if raw.len() > MAX_ROUTES {
            return Err(TOO_MANY);
        }
        let routes = raw
            .iter()
            .map(|route| {
                if route.action != "bypass" {
                    return Err(BundleError("the action of a route is not bypass"));
                }
                Route::new(route.host.as_deref(), &route.path)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Routes::new(routes)
    }

    /// The table of the file that `rules import` takes: a JSON array of `{"host"?, "path", "action":"bypass"}`
    /// with at least one route.
    pub fn from_json(bytes: &[u8]) -> Result<Routes, BundleError> {
        let raw: Vec<RawRoute> = serde_json::from_slice(bytes).map_err(|_| {
            BundleError("the routes file is not a JSON array of routes of the expected form")
        })?;
        if raw.is_empty() {
            return Err(BundleError("the routes file has no route"));
        }
        Routes::from_raw(raw)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The routes, in the order they were given.
    pub fn iter(&self) -> impl Iterator<Item = &Rule> {
        self.0.rules()
    }

    /// Whether the request is let through without being inspected. `host` is the value of its `Host` field, and
    /// `target` its request target as it was received.
    pub fn matches(&self, host: Option<&[u8]>, target: &[u8]) -> bool {
        self.0.find(host, target).is_some()
    }

    /// Appends `,"routes":[...]` in the one form of the manifest, or nothing for an empty table.
    pub(super) fn write_to(&self, out: &mut String) {
        if self.0.is_empty() {
            return;
        }
        out.push_str(r#","routes":["#);
        for (i, rule) in self.0.rules().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push('{');
            if let Some(host) = rule.host() {
                out.push_str(r#""host":""#);
                out.push_str(host);
                out.push_str(r#"","#);
            }
            out.push_str(r#""path":""#);
            out.push_str(rule.path().unwrap_or_default());
            out.push_str(r#"","action":"bypass"}"#);
        }
        out.push(']');
    }
}

/// The routes of the generation that serves. A connection reads them once for each request, and the driver
/// replaces them at the moment it makes another generation the one that serves, so the routes and the generation
/// that inspects change together. A switch that fails does not touch them.
#[derive(Clone, Debug)]
pub struct SharedRoutes(Arc<RwLock<Arc<Routes>>>);

impl SharedRoutes {
    pub fn new(routes: Routes) -> SharedRoutes {
        SharedRoutes(Arc::new(RwLock::new(Arc::new(routes))))
    }

    /// The table as it is now. A request keeps this one, whatever is put in its place afterwards.
    pub fn current(&self) -> Arc<Routes> {
        Arc::clone(&self.0.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Makes `routes` the table from now on.
    pub fn replace(&self, routes: Routes) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(routes);
    }
}

#[cfg(test)]
mod tests;
