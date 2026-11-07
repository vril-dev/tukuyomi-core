//! The table of routes of the admin API and the checks that come before a route runs. The listener of the admin
//! process, its connections and its start and stop are in `listener`; the body of a request is read by `body`, and
//! the files of the page are answered by `ui`.
//!
//! An answer of a route is JSON, and an error is `{"error": "<words>"}` (a refusal of the input of the saving and of
//! the check of a managed version also has `at`, the place it is about; see `managed`). The number of a request is the
//! value of `X-Request-ID` when the peer is in `admin.trusted_proxies` and the value has the form that the proxy gives
//! (16 lowercase hexadecimal digits, `-`, and 1 to 16 digits more); else the process makes one of the same form. The
//! client of a request, for the limits and the audit log, is found as the proxy finds the client of a request, with
//! `admin.trusted_proxies` (see `forward::client_ip`).
//!
//! The table of routes is in five parts: `ROUTES` here (`GET /api/audit`), `account` (the login, the session, the
//! password, the second factor and the user's own tokens), `users::manage` (an owner's management of users and
//! tokens), `waf` (the rules) and `managed` (the managed configuration and the main file). Each route has its method
//! and path (a `*` stands for one part of the path, and a `*` that ends the path of the rules for the rest of it), the
//! least role that may use it (none: no credential is needed), the kind of state of a session that may use it
//! (`Gate`), and whether a request with an API token may. A body is at most `BODY_MAX`, but for the routes whose part
//! says otherwise (the import of a generation, the version to apply or to check: `body_limit`); such a body is read
//! only for a client of at least the least role of its route (see `body`).
//!
//! A request goes through these steps, and the first that refuses answers: the path (404 if the table has no route
//! with it) and the method (405 with `Allow`; `HEAD` is taken as `GET`); for a route that names a least role, the
//! credential: a session cookie or `Authorization: Bearer <token>`, never both (400), and none is 401 (the cookie
//! must be there once; a client that has used up its tries with tokens is 429); for every method but `GET` and
//! `HEAD`, the `Origin` header, which if present must be exactly `admin.origin` (403), and for a session,
//! `X-CSRF-Token`, which must be the token of the session (403; a token request has none); a token on a route that
//! no token may use (403); the state of the session (403, with fixed words: the session waits for the second factor,
//! the password must be changed, the second factor must be set up); and the role (403). A route with a credential
//! writes the refusal of the last four to the audit log. The routes of the table are used by a request whose
//! `Content-Type` is `application/json` when they read a body (415), and a body that is not the JSON they read, with
//! exactly the keys they know, is 400.
//!
//! The cookie is `tukuyomi_admin=<43 characters>; Secure; HttpOnly; SameSite=Strict; Path=/`.

mod body;
mod listener;
mod ui;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aws_lc_rs::constant_time;
use bytes::Bytes;
use http::header::{AUTHORIZATION, CONTENT_TYPE, COOKIE, HeaderMap, HeaderValue, ORIGIN};
use http::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use super::account;
use super::audit::AuditLog;
use super::auth::{Auth, Authed, Credential, Cx, Refusal, Who};
use super::managed::{self, Managed};
use super::store::AdminStore;
use super::users::{Role, manage};
use super::waf::{self, Op, Waf};
use crate::config::{AdminConfig, Mfa};
use crate::forward::client_ip::{Cidr, effective, trusts};
use crate::inbound::session::RequestIds;

pub use self::listener::run;

const BODY_WAIT: Duration = Duration::from_secs(30);
/// The time an answer has, but for the routes whose part says otherwise.
pub(super) const ANSWER_WAIT: Duration = Duration::from_secs(30);
/// The most bytes of a body, for every route but those whose part says otherwise.
const BODY_MAX: usize = 64 * 1024;
/// The lines that `GET /api/audit` gives.
const AUDIT_LINES: usize = 200;
pub(super) const COOKIE_NAME: &str = "tukuyomi_admin";
const CSRF_HEADER: &str = "x-csrf-token";

/// What a request asks the table for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Handler {
    Audit,
    Account(account::Op),
    Users(manage::Op),
    Waf(Op),
    Managed(managed::Op),
}

/// What kind of state of a session may use a route: a pending session (the password was right, the second factor is
/// not given) only the check of the second factor and the logout; a user who must change the password only the
/// change, the session and the logout; a user who must set up the second factor only the setup, the session and the
/// logout, and the password change too if the password must be changed; and every other route needs a session that
/// none of the three limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Gate {
    /// A session that is not limited by a state, and a token.
    Open,
    /// The change of the password.
    Password,
    /// The setup of the second factor.
    Mfa,
    /// The session of a user in any state but pending.
    Session,
    /// The logout: any session.
    Logout,
    /// The check of the second factor: a pending session only.
    Pending,
}

impl Gate {
    /// Why a request of `who` may not use a route of this kind: the word for the audit log and the sentence of the
    /// answer. None: it may.
    fn refusal(self, who: &Who) -> Option<(&'static str, &'static str)> {
        const PENDING: (&str, &str) = ("second factor pending", "second factor required");
        const PASSWORD: (&str, &str) = ("password change", "password change required");
        const SETUP: (&str, &str) = ("second factor setup", "second factor setup required");
        match self {
            Gate::Logout => None,
            Gate::Pending => (!who.pending).then_some(("state", "forbidden")),
            _ if who.pending => Some(PENDING),
            Gate::Session => None,
            Gate::Open if who.must_change => Some(PASSWORD),
            Gate::Open if who.setup_needed => Some(SETUP),
            Gate::Password if who.setup_needed && !who.must_change => Some(SETUP),
            Gate::Mfa if who.must_change && !who.setup_needed => Some(PASSWORD),
            _ => None,
        }
    }
}

/// One route: the method and the path, who may use it, and the action the audit log calls it.
pub(super) struct Route {
    pub(super) method: Method,
    pub(super) path: &'static str,
    pub(super) handler: Handler,
    /// The least role that may use the route; none: no session is needed.
    pub(super) least: Option<Role>,
    /// The state of a session that may use the route.
    pub(super) gate: Gate,
    /// Whether a request with an API token may use the route.
    pub(super) token: bool,
    pub(super) action: &'static str,
}

/// The routes that no other part of the table has. A path that is not in the table is 404.
static ROUTES: [Route; 1] = [Route {
    method: Method::GET,
    path: "/api/audit",
    handler: Handler::Audit,
    least: Some(Role::Operator),
    gate: Gate::Open,
    token: true,
    action: "audit",
}];

/// A request as the process sees it: what the routes need of it.
pub struct Req {
    pub method: Method,
    /// The path of the target, without the query.
    pub path: String,
    /// The query of the target, without the `?`; empty when there is none.
    pub query: String,
    pub headers: HeaderMap,
    /// The address of the peer of the connection.
    pub peer: SocketAddr,
    pub body: Bytes,
}

/// An answer: a status and a JSON body, and the fields that a route adds to the fixed ones.
pub struct Answer {
    pub status: StatusCode,
    pub body: Value,
    /// A `Set-Cookie` field.
    pub cookie: Option<String>,
    /// An `Allow` field.
    pub allow: Option<String>,
    /// The number of the request.
    pub request: String,
}

impl Answer {
    pub(super) fn json(status: StatusCode, body: Value) -> Answer {
        Answer {
            status,
            body,
            cookie: None,
            allow: None,
            request: String::new(),
        }
    }

    pub(super) fn error(status: StatusCode, words: &'static str) -> Answer {
        Answer::json(status, json!({ "error": words }))
    }

    pub(super) fn unavailable() -> Answer {
        Answer::error(StatusCode::SERVICE_UNAVAILABLE, "unavailable")
    }

    pub(super) fn cookie(mut self, cookie: String) -> Answer {
        self.cookie = Some(cookie);
        self
    }
}

/// The answer to an operation of the account that was refused.
pub(super) fn refusal(why: Refusal) -> Answer {
    match why {
        Refusal::Gone => Answer::error(StatusCode::UNAUTHORIZED, "unauthorized"),
        Refusal::Unavailable => Answer::unavailable(),
        Refusal::Password => Answer::error(StatusCode::FORBIDDEN, "the password is wrong"),
        Refusal::Code => Answer::error(StatusCode::FORBIDDEN, "the code is wrong"),
        Refusal::Denied(words) => Answer::error(StatusCode::FORBIDDEN, words),
        Refusal::Conflict(words) => Answer::error(StatusCode::CONFLICT, words),
        Refusal::Invalid(words) => Answer::error(StatusCode::BAD_REQUEST, words),
        Refusal::NotFound => Answer::error(StatusCode::NOT_FOUND, "not found"),
    }
}

/// The value of `Set-Cookie` for a session.
pub(super) fn session_cookie(id: &str) -> String {
    format!("{COOKIE_NAME}={id}; Secure; HttpOnly; SameSite=Strict; Path=/")
}

/// The value of `Set-Cookie` that takes the cookie away.
pub(super) fn cleared_cookie() -> String {
    format!("{COOKIE_NAME}=; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
}

/// What the request brings to show who it is from: the cookie of the session or `Authorization: Bearer`.
pub(super) fn credential(headers: &HeaderMap) -> Credential {
    let cookies: Vec<&str> = headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|text| text.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .filter(|(name, _)| *name == COOKIE_NAME)
        .map(|(_, value)| value)
        .collect();
    let mut fields = headers.get_all(AUTHORIZATION).iter();
    let authorization = match (fields.next(), fields.next()) {
        (None, _) => None,
        (Some(value), None) => Some(
            value
                .to_str()
                .ok()
                .and_then(|text| text.split_once(' '))
                .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
                .map(|(_, token)| token.to_owned()),
        ),
        (Some(_), Some(_)) => Some(None),
    };
    match (cookies.as_slice(), authorization) {
        ([], None) => Credential::Missing,
        ([], Some(token)) => Credential::Bearer(token),
        ([one], None) => Credential::Cookie(Some((*one).to_owned())),
        (_, None) => Credential::Cookie(None),
        (_, Some(_)) => Credential::Both,
    }
}

/// Whether the one `Content-Type` is `application/json`, with parameters or not.
fn is_json(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    match (values.next(), values.next()) {
        (Some(value), None) => value.to_str().is_ok_and(|text| {
            text.split(';')
                .next()
                .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
        }),
        _ => false,
    }
}

/// The body of the request as the JSON object `T`, with exactly the keys `T` knows.
pub(super) fn json_body<T: DeserializeOwned>(req: &Req) -> Result<T, Answer> {
    if !is_json(&req.headers) {
        return Err(Answer::error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported media type",
        ));
    }
    serde_json::from_slice(&req.body)
        .map_err(|_| Answer::error(StatusCode::BAD_REQUEST, "bad request"))
}

/// Whether `text` has the form of the number of a request: 16 hexadecimal digits, `-`, and 1 to 16 digits more.
fn proxy_form(text: &str) -> bool {
    let hexadecimal = |digits: &str| {
        digits
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    };
    text.split_once('-').is_some_and(|(prefix, count)| {
        prefix.len() == 16
            && (1..=16).contains(&count.len())
            && hexadecimal(prefix)
            && hexadecimal(count)
    })
}

/// The routes of the table: `GET /api/audit`, then those of the account, of the management, of the rules and of the
/// managed configuration.
fn routes() -> impl Iterator<Item = &'static Route> {
    ROUTES
        .iter()
        .chain(account::ROUTES.iter())
        .chain(manage::ROUTES.iter())
        .chain(waf::ROUTES.iter())
        .chain(managed::ROUTES.iter())
}

/// The path as the table has it: a path below `/api/generations/`, `/api/account/tokens/`, `/api/tokens/` or
/// `/api/managed/versions/` ends in `*`, and `/api/users/<name>` with nothing, `password` or `mfa` after the name has
/// `*` for the name.
fn pattern(path: &str) -> &str {
    let rules = waf::pattern(path);
    if rules != path {
        return rules;
    }
    for (prefix, star) in [
        ("/api/account/tokens/", "/api/account/tokens/*"),
        ("/api/tokens/", "/api/tokens/*"),
        ("/api/managed/versions/", "/api/managed/versions/*"),
    ] {
        if path.starts_with(prefix) {
            return star;
        }
    }
    match path
        .strip_prefix("/api/users/")
        .map(|rest| rest.split_once('/'))
    {
        Some(None) => "/api/users/*",
        Some(Some((_, "password"))) => "/api/users/*/password",
        Some(Some((_, "mfa"))) => "/api/users/*/mfa",
        _ => path,
    }
}

/// The most bytes of the body of a request for `method` and `path`, and the least role of a client whose body is read
/// when that is over `BODY_MAX`: the role of the route (none for a path that the table does not have, whose body is
/// then not read, see `body`).
fn body_limit(method: &Method, path: &str) -> (usize, Option<Role>) {
    match waf::body_limit(method, path).or_else(|| managed::body_limit(method, path)) {
        Some(limit) => {
            let path = pattern(path);
            let route = routes().find(|route| route.path == path && route.method == *method);
            (limit, route.and_then(|route| route.least))
        }
        None => (BODY_MAX, None),
    }
}

/// The methods that a path has in the table, for `Allow`.
fn allowed(path: &str) -> String {
    let mut methods: Vec<&str> = routes()
        .filter(|route| route.path == path)
        .flat_map(|route| {
            if route.method == Method::GET {
                vec!["GET", "HEAD"]
            } else {
                vec![route.method.as_str()]
            }
        })
        .collect();
    methods.dedup();
    methods.join(", ")
}

/// What the routes work with.
pub struct App {
    origin: String,
    trusted: Vec<Cidr>,
    pub(super) auth: Auth,
    ids: RequestIds,
    waf: Option<Waf>,
    managed: Option<Managed>,
    /// The time an answer may take.
    answer_wait: Duration,
}

impl App {
    /// The routes over `store` and `audit`, for the configuration. `iterations` are the rounds of a new password
    /// hash. `waf` are the routes of the rules and `managed` those of the managed configuration; without them those
    /// routes are 404. None: no random number.
    pub fn new(
        config: &AdminConfig,
        store: Arc<dyn AdminStore>,
        audit: Arc<AuditLog>,
        ids: RequestIds,
        iterations: u32,
        waf: Option<Waf>,
        managed: Option<Managed>,
    ) -> Option<App> {
        Some(App {
            origin: config.origin.clone(),
            trusted: config.trusted_proxies.clone(),
            auth: Auth::new(
                store,
                audit,
                config.session_idle,
                config.session_total,
                iterations,
                config.mfa == Mfa::Required,
            )?,
            ids,
            answer_wait: ANSWER_WAIT.max(waf.as_ref().map_or(Duration::ZERO, Waf::longest)),
            waf,
            managed,
        })
    }

    /// The number of the request: the one the proxy gave it, if that can be believed, else a new one.
    fn request_id(&self, req: &Req) -> String {
        let mut values = req.headers.get_all("x-request-id").iter();
        if let (Some(value), None) = (values.next(), values.next())
            && trusts(&self.trusted, req.peer.ip())
            && let Ok(text) = value.to_str()
            && proxy_form(text)
        {
            return text.to_owned();
        }
        self.ids.mint()
    }

    /// The client of a request from `peer` with these `headers`, as the proxy finds it.
    fn client(&self, headers: &HeaderMap, peer: SocketAddr) -> IpAddr {
        let forwarded: Vec<&[u8]> = headers
            .get_all("x-forwarded-for")
            .iter()
            .map(HeaderValue::as_bytes)
            .collect();
        effective(peer, &self.trusted, &forwarded).ip()
    }

    /// Answers a request. It reads files and computes a hash, so it is not called on the thread of the runtime.
    pub fn handle(&self, req: &Req) -> Answer {
        let id = self.request_id(req);
        let client = self.client(&req.headers, req.peer);
        let mut answer = self.dispatch(req, &Cx { id: &id, client });
        answer.request = id;
        answer
    }

    fn dispatch(&self, req: &Req, cx: &Cx<'_>) -> Answer {
        let now = Instant::now();
        let method = if req.method == Method::HEAD {
            Method::GET
        } else {
            req.method.clone()
        };
        let path = pattern(&req.path);
        if !routes().any(|route| route.path == path) {
            return Answer::error(StatusCode::NOT_FOUND, "not found");
        }
        let Some(route) = routes().find(|route| route.path == path && route.method == method)
        else {
            let mut answer = Answer::error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
            answer.allow = Some(allowed(path));
            return answer;
        };
        let who = match route.least {
            None => None,
            Some(_) => match self.who(req, cx, now) {
                Ok(who) => Some(who),
                Err(answer) => return answer,
            },
        };
        let safe = method == Method::GET;
        if !safe && !self.origin_ok(req) {
            return self.refused(who.as_ref(), cx, route, "origin", "forbidden");
        }
        if let Some(who) = &who {
            if !safe && !who.token() && !csrf_ok(req, who) {
                return self.refused(Some(who), cx, route, "csrf", "forbidden");
            }
            if who.token() && !route.token {
                return self.refused(Some(who), cx, route, "token", "forbidden");
            }
            if let Some((reason, words)) = route.gate.refusal(who) {
                return self.refused(Some(who), cx, route, reason, words);
            }
            if route.least.is_some_and(|least| who.role < least) {
                return self.refused(Some(who), cx, route, "role", "forbidden");
            }
        }
        match (route.handler, who) {
            (Handler::Account(op), who) => self.account(op, req, who.as_ref(), cx, now),
            (Handler::Users(op), Some(who)) => self.users(op, req, &who, cx),
            (Handler::Audit, Some(_)) => self.audit(),
            (Handler::Waf(op), Some(who)) => match &self.waf {
                Some(waf) => waf.handle(op, req, &who, cx),
                None => Answer::error(StatusCode::NOT_FOUND, "not found"),
            },
            (Handler::Managed(op), Some(who)) => match &self.managed {
                Some(managed) => managed.handle(op, req, &who, cx),
                None => Answer::error(StatusCode::NOT_FOUND, "not found"),
            },
            // A route that names a least role has a user by now.
            (_, None) => Answer::error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
        }
    }

    /// The user of the request, from its cookie or its token.
    fn who(&self, req: &Req, cx: &Cx<'_>, now: Instant) -> Result<Who, Answer> {
        let unauthorized = || Answer::error(StatusCode::UNAUTHORIZED, "unauthorized");
        let credential = credential(&req.headers);
        if credential == Credential::Both {
            return Err(Answer::error(StatusCode::BAD_REQUEST, "bad request"));
        }
        match self.auth.authenticate(&credential, cx.client, now) {
            Authed::Who(who) => Ok(who),
            Authed::Unauthorized => Err(unauthorized()),
            Authed::Limited => Err(Answer::error(
                StatusCode::TOO_MANY_REQUESTS,
                "too many tries",
            )),
            Authed::Unavailable => Err(Answer::unavailable()),
        }
    }

    /// Whether the request may change something as far as its `Origin` goes: the field is not there, or it is
    /// exactly `admin.origin` and there is one.
    fn origin_ok(&self, req: &Req) -> bool {
        let mut values = req.headers.get_all(ORIGIN).iter();
        match (values.next(), values.next()) {
            (None, _) => true,
            (Some(value), None) => value.as_bytes() == self.origin.as_bytes(),
            _ => false,
        }
    }

    /// The answer to a request that a check refused, with these `words`; the audit log has it, for `reason`, when a
    /// user is known.
    fn refused(
        &self,
        who: Option<&Who>,
        cx: &Cx<'_>,
        route: &Route,
        reason: &'static str,
        words: &'static str,
    ) -> Answer {
        if let Some(who) = who {
            self.auth.deny(who, cx, route.action, reason);
        }
        Answer::error(StatusCode::FORBIDDEN, words)
    }

    fn audit(&self) -> Answer {
        match self.auth.audit().recent(AUDIT_LINES) {
            Ok(entries) => Answer::json(StatusCode::OK, json!({ "entries": entries })),
            Err(_) => Answer::unavailable(),
        }
    }
}

/// Whether the request has the CSRF token of the session of `who`, once, compared in constant time.
fn csrf_ok(req: &Req, who: &Who) -> bool {
    let mut values = req.headers.get_all(CSRF_HEADER).iter();
    match (values.next(), values.next()) {
        (Some(token), None) => {
            constant_time::verify_slices_are_equal(token.as_bytes(), who.csrf.as_bytes()).is_ok()
        }
        _ => false,
    }
}

#[cfg(test)]
pub(crate) mod tests;
