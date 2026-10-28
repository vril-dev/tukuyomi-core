//! The listener of the admin API, the table of routes, and the start and stop of the admin process.
//!
//! The process listens on `admin.listen`, a loopback address, and speaks HTTP/1.1 without TLS (a route of the proxy
//! that has TLS can be the way in from outside). At most 32 connections are served at once;
//! one that finds no place is accepted and closed. A connection serves one request and is closed after the answer
//! (`Connection: close`), so a connection never waits for a second request. The head is at most 8 KiB and comes within
//! 10 s; the body is at most 64 KiB (12 MiB for the import of a generation, read only for a client with a live
//! session or token of an operator or an owner whose state lets it import; see `body`) and comes within 30 s; the
//! answer is made within 30 s, or for the import, the switch and the rollback of the rules within `Waf::longest`. A
//! connection lives for the three times together at the most. A head that hyper refuses by itself (a malformed one,
//! or one over the limit) gets hyper's own answer, or none, and not the fields below.
//!
//! Every answer is JSON and has `Content-Type: application/json`, `Cache-Control: no-store`, `X-Content-Type-Options:
//! nosniff`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, `Referrer-Policy: no-referrer`
//! and `X-Request-ID`. An error is `{"error": "<words>"}`. The number of a request is the value of `X-Request-ID`
//! when the peer is in `admin.trusted_proxies` and the value has the form that the proxy gives (16 lowercase
//! hexadecimal digits, `-`, and 1 to 16 digits more); else the process makes one of the same form. The client of a
//! request, for the limits and the audit log, is found as the proxy finds the client of a request, with
//! `admin.trusted_proxies` (see `forward::client_ip`).
//!
//! The table of routes is in four parts: `ROUTES` here (`GET /api/audit`), `account` (the login, the session, the
//! password, the second factor and the user's own tokens), `users::manage` (an owner's management of users and
//! tokens) and `waf` (the rules). Each route has its method and path (a `*` stands for one part of the path, and a
//! `*` that ends the path of the rules for the rest of it), the least role that may use it (none: no credential is
//! needed), the kind of state of a session that may use it (`Gate`), and whether a request with an API token may.
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
//!
//! The stop: SIGTERM, SIGINT and SIGHUP close the listener and tell the service manager `STOPPING=1`; the requests
//! in flight have 10 s to end, and the process exits with code 0. `READY=1` is told after the listener is bound.

mod body;

use std::convert::Infallible;
use std::future::poll_fn;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};

use aws_lc_rs::constant_time;
use bytes::Bytes;
use http::header::{
    ALLOW, AUTHORIZATION, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HeaderMap,
    HeaderName, HeaderValue, ORIGIN, SET_COOKIE,
};
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::net::{TcpListener, TcpStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout, timeout_at};
use tukuyomi_kernel::limits;

use super::Exit;
use super::account;
use super::audit::AuditLog;
use super::auth::{Auth, Authed, Credential, Cx, Refusal, Who};
use super::file_store::AUDIT_DIR;
use super::password::ITERATIONS;
use super::store::{self, AdminStore};
use super::users::{Role, manage};
use super::waf::{self, Op, Waf};
use crate::config::{self, AdminConfig, AdminStoreConfig, Mfa};
use crate::forward::client_ip::{Cidr, effective, trusts};
use crate::inbound::session::RequestIds;
use crate::log::Log;
use crate::run::host;
use crate::run::notify::Notify;

/// The most connections served at once.
const SEATS: usize = 32;
/// The most bytes of a head.
const HEAD_MAX: usize = 8192;
const HEAD_WAIT: Duration = Duration::from_secs(10);
const BODY_WAIT: Duration = Duration::from_secs(30);
const ANSWER_WAIT: Duration = Duration::from_secs(30);
/// The most bytes of a body, for every route.
const BODY_MAX: usize = 64 * 1024;
/// The time the requests in flight have at the stop.
const STOP_WAIT: Duration = Duration::from_secs(10);
/// The pause after an accept failed.
const ACCEPT_PAUSE: Duration = Duration::from_millis(100);
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

/// The routes of the table: `GET /api/audit`, then those of the account, of the management and of the rules.
fn routes() -> impl Iterator<Item = &'static Route> {
    ROUTES
        .iter()
        .chain(account::ROUTES.iter())
        .chain(manage::ROUTES.iter())
        .chain(waf::ROUTES.iter())
}

/// The path as the table has it: a path below `/api/generations/`, `/api/account/tokens/` or `/api/tokens/` ends in
/// `*`, and `/api/users/<name>` with nothing, `password` or `mfa` after the name has `*` for the name.
fn pattern(path: &str) -> &str {
    let rules = waf::pattern(path);
    if rules != path {
        return rules;
    }
    for (prefix, star) in [
        ("/api/account/tokens/", "/api/account/tokens/*"),
        ("/api/tokens/", "/api/tokens/*"),
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
    /// The time an answer may take.
    answer_wait: Duration,
}

impl App {
    /// The routes over `store` and `audit`, for the configuration. `iterations` are the rounds of a new password
    /// hash. `waf` are the routes of the rules; without them those routes are 404. None: no random number.
    pub fn new(
        config: &AdminConfig,
        store: Arc<dyn AdminStore>,
        audit: Arc<AuditLog>,
        ids: RequestIds,
        iterations: u32,
        waf: Option<Waf>,
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
        })
    }

    /// An answer for a request that never reached the routes.
    fn refuse(&self, status: StatusCode, words: &'static str) -> Response<Full<Bytes>> {
        let mut answer = Answer::error(status, words);
        answer.request = self.ids.mint();
        response(&answer)
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

/// The response for an answer, with the fields every answer has.
fn response(answer: &Answer) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(&answer.body).unwrap_or_else(|_| b"{}".to_vec());
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = answer.status;
    let fields = response.headers_mut();
    fields.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    fields.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    fields.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    fields.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
    fields.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    if let Ok(value) = HeaderValue::from_str(&answer.request) {
        fields.insert(HeaderName::from_static("x-request-id"), value);
    }
    if let Some(Ok(value)) = answer.cookie.as_deref().map(HeaderValue::from_str) {
        fields.append(SET_COOKIE, value);
    }
    if let Some(Ok(value)) = answer.allow.as_deref().map(HeaderValue::from_str) {
        fields.insert(ALLOW, value);
    }
    response
}

/// Reads the body of the request within its limits and answers it.
async fn answer(
    app: Arc<App>,
    peer: SocketAddr,
    request: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let (parts, body) = request.into_parts();
    let limit = waf::body_limit(&parts.method, parts.uri.path()).unwrap_or(BODY_MAX);
    let slow = waf::slow(&parts.method, parts.uri.path());
    let wait = if slow { app.answer_wait } else { ANSWER_WAIT };
    let declared = parts
        .headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|text| text.parse::<usize>().ok());
    if declared.is_some_and(|length| length > limit) {
        return app.refuse(StatusCode::PAYLOAD_TOO_LARGE, "payload too large");
    }
    let client = app.client(&parts.headers, peer);
    let body = match body::read(&app, &parts.headers, client, body, limit).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let req = Req {
        method: parts.method,
        path: parts.uri.path().to_owned(),
        query: parts.uri.query().unwrap_or_default().to_owned(),
        headers: parts.headers,
        peer,
        body,
    };
    let worker = app.clone();
    match timeout(
        wait,
        tokio::task::spawn_blocking(move || worker.handle(&req)),
    )
    .await
    {
        Ok(Ok(answer)) => response(&answer),
        _ => app.refuse(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
    }
}

/// One connection: one request, one answer, and the close.
async fn connection(stream: TcpStream, peer: SocketAddr, app: Arc<App>) {
    let total = HEAD_WAIT + BODY_WAIT + app.answer_wait;
    let service = service_fn(move |request: Request<Incoming>| {
        let app = app.clone();
        async move { Ok::<_, Infallible>(answer(app, peer, request).await) }
    });
    let mut server = http1::Builder::new();
    server
        .keep_alive(false)
        .timer(TokioTimer::new())
        .header_read_timeout(HEAD_WAIT)
        .max_headers(limits::HEADERS)
        .max_header_size(HEAD_MAX)
        .max_buf_size(HEAD_MAX);
    let served = server.serve_connection(TokioIo::new(stream), service);
    let _ = timeout(total, served).await;
}

/// Binds the listener, serves until a signal asks for the stop, and stops.
async fn serve(address: SocketAddr, app: Arc<App>, log: &Log) -> Exit {
    let (Ok(mut term), Ok(mut int), Ok(mut hup)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
        signal(SignalKind::hangup()),
    ) else {
        log.line("admin: cannot install the signal handlers");
        return Exit::Failed;
    };
    let notify = Notify::from_env(log);
    let Ok(listener) = TcpListener::bind(address).await else {
        log.line("admin: the listen address cannot be bound");
        return Exit::Failed;
    };
    log.line("admin: listening");
    notify.ready(log);
    let seats = Arc::new(Semaphore::new(SEATS));
    let mut conns = JoinSet::new();
    let cause = loop {
        let event = poll_fn(|cx| {
            for (name, stream) in [
                ("SIGTERM", &mut term),
                ("SIGINT", &mut int),
                ("SIGHUP", &mut hup),
            ] {
                if stream.poll_recv(cx).is_ready() {
                    return Poll::Ready(Err(name));
                }
            }
            // A connection that is done is joined here, so the set holds only those that are being served.
            while let Poll::Ready(Some(_)) = conns.poll_join_next(cx) {}
            listener.poll_accept(cx).map(Ok)
        })
        .await;
        match event {
            Err(name) => break name,
            Ok(Ok((stream, peer))) => match seats.clone().try_acquire_owned() {
                Ok(seat) => {
                    let app = app.clone();
                    conns.spawn(async move {
                        let _seat = seat;
                        connection(stream, peer, app).await;
                    });
                }
                // No place is free: the connection is closed.
                Err(_) => drop(stream),
            },
            Ok(Err(_)) => sleep(ACCEPT_PAUSE).await,
        }
    };
    log.line(&format!("admin: stop: {cause}"));
    notify.stopping(log);
    app.waf.iter().for_each(Waf::interrupt);
    drop(listener);
    let by = tokio::time::Instant::now() + STOP_WAIT;
    while timeout_at(by, conns.join_next())
        .await
        .is_ok_and(|done| done.is_some())
    {}
    conns.abort_all();
    Exit::Done
}

/// The admin process for the configuration file `path`.
pub fn run(path: &Path, log: &Log) -> Exit {
    if let Err(text) = host::check() {
        log.line(&format!("admin: host check refused: {text}"));
        return Exit::Failed;
    }
    let loaded = match config::load(path) {
        Ok(loaded) => loaded,
        Err(e) => {
            log.line(&format!("admin: configuration refused: {}", e.0));
            return Exit::Usage;
        }
    };
    let Some(admin) = loaded.admin.clone() else {
        log.line("admin: configuration refused: there is no admin object");
        return Exit::Usage;
    };
    log.line("admin: configuration accepted");
    let store = match store::open_exclusive(&admin.store) {
        Ok(store) => store,
        Err(e) => {
            log.line(&format!("admin: admin store refused: {}", e.0));
            return Exit::Failed;
        }
    };
    let AdminStoreConfig::File { dir } = &admin.store;
    let audit = match AuditLog::open(&dir.join(AUDIT_DIR), log.clone()) {
        Ok(audit) => Arc::new(audit),
        Err(e) => {
            log.line(&format!("admin: audit log refused: {}", e.0));
            return Exit::Failed;
        }
    };
    let Some(ids) = RequestIds::new() else {
        log.line("admin: no random number is available for the request numbers");
        return Exit::Failed;
    };
    let waf = Waf::from_config(&loaded, &admin, store.clone(), audit.clone());
    let Some(app) = App::new(&admin, store, audit, ids, ITERATIONS, Some(waf)) else {
        log.line("admin: no random number is available");
        return Exit::Failed;
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            log.line("admin: cannot build the runtime");
            return Exit::Failed;
        }
    };
    runtime.block_on(serve(admin.listen, Arc::new(app), log))
}

#[cfg(test)]
pub(crate) mod tests;
