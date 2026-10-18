//! The routes of a rule bundle: the requests that are let through without being inspected.
//!
//! A route has a path and, if it is to hold for one host only, a host. Its action is always `bypass`: a request
//! that a route matches is not handed to the inspector, and goes on to the upstream. What the proxy itself checks
//! (the head, the type and the size of the body, the decoding of a gzip body) has been done before the request
//! gets here. The routes are in the manifest of the bundle, so they are part of its fingerprint, and a running proxy
//! changes them only by switching to another generation.
//!
//! A route is checked when it is made, whether it comes from the file of `rules import` or from a manifest, so the
//! same rules hold on both ways in:
//! - The path starts with `/`, has 2 to 255 bytes and is not `/` alone, which would skip the inspection of every
//!   request. Its bytes are `A-Z a-z 0-9 - . _ ~ ! $ & ' ( ) * + , = : @ / %`, and every `%` is followed by two
//!   hexadecimal digits. A path that can be read in more than one way is refused (see `ambiguous`).
//! - The host has 1 to 253 bytes: lowercase ASCII letters, digits, `-` and `.`, not ending in `.`, and then,
//!   if wanted, `:` and a port from 1 to 65535 without a leading zero.
//! - A table has at most 256 routes, and no two of them have the same host and path.
//!
//! A request matches a route when its target, up to the first `?`, is not ambiguous in the same sense and
//! - the route has no host, or the value of the `Host` field of the request, with its ASCII letters in lower
//!   case, is the host of the route, and
//! - the path of the route is the target, or the path of the route ends in `/` and the target starts with it.
//!
//! The comparison is made on the bytes of the target as they were received and as they will be forwarded: nothing
//! is decoded or cleaned first, and letters are compared with their case. A target that is ambiguous matches no
//! route, so that it is inspected.

use std::collections::BTreeSet;
use std::sync::{Arc, PoisonError, RwLock};

use serde::Deserialize;

use crate::rules::bundle::BundleError;

/// The most routes in a table.
pub const MAX_ROUTES: usize = 256;
const MAX_PATH_BYTES: usize = 255;
const MAX_HOST_BYTES: usize = 253;
const TOO_MANY: BundleError = BundleError("there are more than 256 routes");

/// Whether `path` (a target up to the first `?`, or the path of a route) can be read in more than one way. It
/// can if it has a backslash or a semicolon, `//`, a segment that is `.` or `..`, or the escape of a dot, a slash,
/// a backslash, a NUL byte or a percent sign (`%2e`, `%2f`, `%5c`, `%00`, `%25`, in any case). The escape of a
/// percent sign is there because an application that decodes the path twice turns `%252e` into a dot.
fn ambiguous(path: &[u8]) -> bool {
    path.iter().any(|&b| b == b'\\' || b == b';')
        || path.windows(2).any(|pair| pair == b"//")
        || path.windows(3).any(|w| {
            w[0] == b'%'
                && matches!(
                    (w[1], w[2].to_ascii_lowercase()),
                    (b'2', b'e' | b'f' | b'5') | (b'5', b'c') | (b'0', b'0')
                )
        })
        || path
            .split(|&b| b == b'/')
            .any(|segment| segment == b"." || segment == b"..")
}

/// A byte that the path of a route may hold.
fn path_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b'='
                | b':'
                | b'@'
                | b'/'
                | b'%'
        )
}

fn check_path(path: &str) -> Result<(), BundleError> {
    let bytes = path.as_bytes();
    if bytes == b"/" {
        return Err(BundleError(
            "a route path of / alone would skip the inspection of every request",
        ));
    }
    if !(2..=MAX_PATH_BYTES).contains(&bytes.len()) {
        return Err(BundleError("a route path is not 2 to 255 bytes"));
    }
    if bytes[0] != b'/' {
        return Err(BundleError("a route path does not start with /"));
    }
    if !bytes.iter().all(|&b| path_byte(b)) {
        return Err(BundleError(
            "a route path has a character that is not allowed",
        ));
    }
    for (i, &b) in bytes.iter().enumerate() {
        let digits = bytes.get(i + 1..i + 3);
        if b == b'%' && !digits.is_some_and(|pair| pair.iter().all(u8::is_ascii_hexdigit)) {
            return Err(BundleError(
                "a % in a route path is not followed by two hexadecimal digits",
            ));
        }
    }
    if ambiguous(bytes) {
        return Err(BundleError("a route path can be read in more than one way"));
    }
    Ok(())
}

fn check_host(host: &str) -> Result<(), BundleError> {
    const BAD: BundleError = BundleError("a route host is malformed");
    if !(1..=MAX_HOST_BYTES).contains(&host.len()) {
        return Err(BundleError("a route host is not 1 to 253 bytes"));
    }
    let (name, port) = match host.split_once(':') {
        Some((name, port)) => (name, Some(port)),
        None => (host, None),
    };
    let name_ok = !name.is_empty()
        && !name.ends_with('.')
        && name
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.'));
    if !name_ok {
        return Err(BAD);
    }
    if let Some(port) = port {
        let port_ok = port.bytes().all(|b| b.is_ascii_digit())
            && !port.starts_with('0')
            && port.parse::<u16>().is_ok();
        if !port_ok {
            return Err(BAD);
        }
    }
    Ok(())
}

/// One route. The action is always `bypass`, so it is not stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    host: Option<String>,
    path: String,
}

impl Route {
    /// A route for `path`, and for `host` only if one is given, if both pass the checks above.
    pub fn new(host: Option<&str>, path: &str) -> Result<Route, BundleError> {
        if let Some(host) = host {
            check_host(host)?;
        }
        check_path(path)?;
        Ok(Route {
            host: host.map(str::to_owned),
            path: path.to_owned(),
        })
    }

    pub fn host(&self) -> Option<&str> {
        self.host.as_deref()
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    /// Whether the route holds for a request with this `Host` value and this path (a target up to the first `?`).
    /// The route host is in lower case, so a comparison that ignores the case of `host` is the comparison of its
    /// lower case form.
    fn matches(&self, host: Option<&[u8]>, path: &[u8]) -> bool {
        if let Some(want) = &self.host
            && !host.is_some_and(|got| got.eq_ignore_ascii_case(want.as_bytes()))
        {
            return false;
        }
        let route = self.path.as_bytes();
        path == route || (route.ends_with(b"/") && path.starts_with(route))
    }
}

/// A route as the file of `rules import` and the manifest write it. Any other key is refused.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawRoute {
    host: Option<String>,
    path: String,
    action: String,
}

/// The routes of a bundle, in the order they were given. The table is valid: every route passed its checks, and
/// there are at most 256 with no two alike.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Routes(Vec<Route>);

impl Routes {
    pub fn new(routes: Vec<Route>) -> Result<Routes, BundleError> {
        if routes.len() > MAX_ROUTES {
            return Err(TOO_MANY);
        }
        let mut seen = BTreeSet::new();
        for route in &routes {
            if !seen.insert((route.host(), route.path())) {
                return Err(BundleError("two routes have the same host and path"));
            }
        }
        Ok(Routes(routes))
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

    pub fn as_slice(&self) -> &[Route] {
        &self.0
    }

    /// Whether the request is let through without being inspected. `host` is the value of its `Host` field, and
    /// `target` its request target as it was received. The first route that holds decides, and every route has
    /// the same action, so it is enough that one does.
    pub fn matches(&self, host: Option<&[u8]>, target: &[u8]) -> bool {
        if self.0.is_empty() {
            return false;
        }
        let path = target
            .iter()
            .position(|&b| b == b'?')
            .map_or(target, |end| &target[..end]);
        !ambiguous(path) && self.0.iter().any(|route| route.matches(host, path))
    }

    /// Appends `,"routes":[...]` in the one form of the manifest, or nothing for an empty table.
    pub(super) fn write_to(&self, out: &mut String) {
        if self.0.is_empty() {
            return;
        }
        out.push_str(r#","routes":["#);
        for (i, route) in self.0.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push('{');
            if let Some(host) = &route.host {
                out.push_str(r#""host":""#);
                out.push_str(host);
                out.push_str(r#"","#);
            }
            out.push_str(r#""path":""#);
            out.push_str(&route.path);
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
