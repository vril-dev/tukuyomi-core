//! The edits a route makes to the request on its way to the upstream and to the response on its way back.
//!
//! A request is matched to its route, and inspected, as the client sent it; these edits come after that and are made
//! once, before the request is tried on a server. They are, in this order: the request fields (remove, set, add), the
//! `Host` field, and the target (the path, then the query). `X-Forwarded-Host` is made before them, from the `Host`
//! the client sent. The response fields are edited when the head of the upstream's response has been checked; an
//! answer the proxy makes itself is not edited.
//!
//! The only bytes put into a request or a response are the bytes the operator wrote in the configuration and the
//! bytes that were received, unchanged. Nothing is decoded, normalized, re-cased or sorted, and nothing is expanded
//! from a variable.
//!
//! The path edit is for a route that has a path. If the route path ends in `/`, the rest of the target after it, the
//! query included, is kept byte for byte behind the new path, which ends in `/` too; otherwise the new path takes the
//! place of the path and the query is kept. A target that can be read in more than one way matches no route with a
//! path, so it is not edited either. The query edits and the field edits are in `query` and `headers`.
//!
//! An edit that cannot be made (the new target is longer than a target may be, or is not a target) fails the request:
//! it is not sent, and no server is counted as having failed.

use bytes::Bytes;
use http::header::HOST;
use http::{HeaderMap, HeaderValue, Uri};
use tukuyomi_kernel::limits;

use crate::route::Rule;

mod headers;
mod query;

pub use headers::Headers;
pub use query::Query;

/// The most items one group of edits (the query, the request fields, the response fields) holds.
const MAX_ITEMS: usize = 32;

/// Why an edit was refused: a fixed English sentence, never a value that was read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RewriteError(pub &'static str);

/// The edits of one route. The default makes none.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rewrite {
    host: Option<HeaderValue>,
    path: Option<PathEdit>,
    query: Query,
    request: Headers,
    response: Headers,
}

/// The path of a route and the path that takes its place.
#[derive(Clone, Debug, PartialEq, Eq)]
struct PathEdit {
    from: String,
    to: String,
}

impl PathEdit {
    /// `route` is the path of the route the edit belongs to. `to` is read as the path of a route is; if the route
    /// path is a prefix, `to` is one too.
    fn new(route: Option<&str>, to: &str) -> Result<PathEdit, RewriteError> {
        let from = route.ok_or(RewriteError(
            "a rewrite path is set on a route that has no path",
        ))?;
        Rule::forward(None, Some(to)).map_err(|_| RewriteError("a rewrite path is malformed"))?;
        if from.ends_with('/') && !to.ends_with('/') {
            return Err(RewriteError(
                "a rewrite path for a route path that ends in / does not end in /",
            ));
        }
        Ok(PathEdit {
            from: from.to_owned(),
            to: to.to_owned(),
        })
    }

    /// `path` is a target up to its first `?`, and it holds for the route. The new path, or `None` if it does not
    /// hold, which the route lookup rules out.
    fn apply(&self, path: &[u8]) -> Option<Vec<u8>> {
        let from = self.from.as_bytes();
        let rest = if from.ends_with(b"/") {
            path.strip_prefix(from)?
        } else if path == from {
            &[]
        } else {
            return None;
        };
        let mut out = Vec::with_capacity(self.to.len().saturating_add(rest.len()));
        out.extend_from_slice(self.to.as_bytes());
        out.extend_from_slice(rest);
        Some(out)
    }
}

/// A fixed `Host` value: a name and an optional port, as the host of a route is written, without a wildcard and
/// without an empty label.
fn fixed_host(host: &str) -> Result<HeaderValue, RewriteError> {
    const BAD: RewriteError = RewriteError("a rewrite host is malformed");
    // The rule of a route allows a name with an empty label, which no `Host` can hold for; as a value to send it
    // has no use.
    let name = host.split_once(':').map_or(host, |(name, _)| name);
    if host.starts_with('*') || name.split('.').any(str::is_empty) {
        return Err(BAD);
    }
    Rule::forward(Some(host), None).map_err(|_| BAD)?;
    HeaderValue::from_str(host).map_err(|_| BAD)
}

impl Rewrite {
    /// The edits of a route whose path is `route_path`. `host` is the new `Host`, `path` the new path.
    pub fn new(
        route_path: Option<&str>,
        host: Option<&str>,
        path: Option<&str>,
        query: Query,
        request: Headers,
        response: Headers,
    ) -> Result<Rewrite, RewriteError> {
        Ok(Rewrite {
            host: host.map(fixed_host).transpose()?,
            path: path.map(|to| PathEdit::new(route_path, to)).transpose()?,
            query,
            request,
            response,
        })
    }

    /// The fields and the target of the request as the upstream gets them. `fields` are the forwarding fields
    /// already made, `uri` is the target as received.
    pub fn request(
        &self,
        mut fields: HeaderMap,
        uri: Uri,
    ) -> Result<(HeaderMap, Uri), RewriteError> {
        self.request.apply(&mut fields);
        if let Some(host) = &self.host {
            fields.insert(HOST, host.clone());
        }
        let uri = self.target(uri)?;
        Ok((fields, uri))
    }

    /// The target of the request after the path and query edits; `uri` itself if they change nothing.
    fn target(&self, uri: Uri) -> Result<Uri, RewriteError> {
        const CANNOT: RewriteError = RewriteError("the target after the rewrite cannot be made");
        if self.path.is_none() && self.query.is_empty() {
            return Ok(uri);
        }
        let received = uri.path_and_query().ok_or(CANNOT)?.as_str().as_bytes();
        let at = received
            .iter()
            .position(|&b| b == b'?')
            .unwrap_or(received.len());
        let (path, tail) = received.split_at(at);
        let mut target = match &self.path {
            Some(edit) => edit.apply(path).ok_or(CANNOT)?,
            None => path.to_vec(),
        };
        target.extend_from_slice(&self.query.apply(tail).unwrap_or_else(|| tail.to_vec()));
        if target == received {
            return Ok(uri);
        }
        if target.len() > limits::URI {
            return Err(CANNOT);
        }
        Uri::from_maybe_shared(Bytes::from(target)).map_err(|_| CANNOT)
    }

    /// Edits the fields of the head of the upstream's response, which has been checked.
    pub fn respond(&self, fields: &mut HeaderMap) {
        self.response.apply(fields);
    }
}

#[cfg(test)]
mod tests;
