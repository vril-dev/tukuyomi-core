//! The listener of the admin API, the table of routes, and the start and stop of the admin process.
//!
//! The process listens on `admin.listen`, a loopback address, and speaks HTTP/1.1 without TLS (a route of the proxy
//! that has TLS can be the way in from outside). At most 32 connections are served at once;
//! one that finds no place is accepted and closed. A connection serves one request and is closed after the answer
//! (`Connection: close`), so a connection never waits for a second request. The head is at most 8 KiB and comes within
//! 10 s; the body is at most 64 KiB, for every route, and comes within 30 s; the answer is made within 30 s. A
//! connection lives for 70 s at the most. A head that hyper refuses by itself (a malformed one, or one over the limit)
//! gets hyper's own answer, or none, and not the fields below.
//!
//! Every answer is JSON and has `Content-Type: application/json`, `Cache-Control: no-store`, `X-Content-Type-Options:
//! nosniff`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, `Referrer-Policy: no-referrer`
//! and `X-Request-ID`. An error is `{"error": "<words>"}`. The number of a request is the value of `X-Request-ID`
//! when the peer is in `admin.trusted_proxies` and the value has the form that the proxy gives (16 lowercase
//! hexadecimal digits, `-`, and 1 to 16 digits more); else the process makes one of the same form. The client of a
//! request, for the limits and the audit log, is found as the proxy finds the client of a request, with
//! `admin.trusted_proxies` (see `forward::client_ip`).
//!
//! A request goes through these steps, and the first that refuses answers: the path (404 if the table has no route
//! with it) and the method (405 with `Allow`; `HEAD` is taken as `GET`); the session, for a route that names a least
//! role (401 without one; the cookie must be there once); for every method but `GET` and `HEAD`, the `Origin`
//! header, which if present must be exactly `admin.origin` (403), and for a route with a session, `X-CSRF-Token`,
//! which must be the token of the session (403); the role (403). A route with a session writes the refusal of the
//! last three to the audit log. The routes of the table are used by a request whose `Content-Type` is
//! `application/json` when they read a body (415), and a body that is not the JSON they read, with exactly the keys
//! they know, is 400.
//!
//! The routes: `POST /api/login` (`{"name", "password"}`; 200 with `{"name", "role", "csrf", "mfa": false}` and the
//! cookie, 401 `invalid credentials` for every refusal alike, 429 when the client has tried too often, 503 when the
//! audit log or the store fails); `POST /api/logout` (200, and the session is closed also when the audit log cannot
//! take its line); `GET /api/session` (the user, the role, the token and the time left); `PUT
//! /api/account/password` (`{"current", "new"}`; 200 with the new `csrf` and a new cookie, the other sessions of the
//! user being closed); `GET /api/audit` (the newest 200 lines, the newest first, as `{"entries"}`).
//! The cookie is `tukuyomi_admin=<43 characters>; Secure; HttpOnly; SameSite=Strict; Path=/`.
//!
//! The start is refused, with exit code 1, when `admin.mfa` is `required`: there is no second factor yet, and the
//! process must not run with the password alone for a configuration that asks for one.
//!
//! The stop: SIGTERM, SIGINT and SIGHUP close the listener and tell the service manager `STOPPING=1`; the requests
//! in flight have 10 s to end, and the process exits with code 0. `READY=1` is told after the listener is bound.

use std::convert::Infallible;
use std::future::poll_fn;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};

use aws_lc_rs::constant_time;
use bytes::Bytes;
use http::header::{
    ALLOW, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HeaderMap, HeaderName, HeaderValue,
    ORIGIN, SET_COOKIE,
};
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::net::{TcpListener, TcpStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout, timeout_at};
use tukuyomi_kernel::limits;

use super::Exit;
use super::audit::AuditLog;
use super::auth::{Auth, Authed, Changed, Cx, Login, Who};
use super::file_store::AUDIT_DIR;
use super::password::{ITERATIONS, Secret};
use super::store::{self, AdminStore};
use super::users::Role;
use crate::config::{self, AdminConfig, AdminStoreConfig, Mfa};
use crate::forward::client_ip::{Cidr, effective, trusts};
use crate::inbound::session::RequestIds;
use crate::log::Log;
use crate::log::record::millis;
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
const COOKIE_NAME: &str = "tukuyomi_admin";
const CSRF_HEADER: &str = "x-csrf-token";

/// What a request asks the table for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Handler {
    Login,
    Logout,
    Session,
    Password,
    Audit,
}

/// One route: the method and the path, who may use it, and the action the audit log calls it.
struct Route {
    method: Method,
    path: &'static str,
    handler: Handler,
    /// The least role that may use the route; none: no session is needed.
    least: Option<Role>,
    action: &'static str,
}

/// The routes. A path that is not here is 404.
const ROUTES: [Route; 5] = [
    Route {
        method: Method::POST,
        path: "/api/login",
        handler: Handler::Login,
        least: None,
        action: "login",
    },
    Route {
        method: Method::POST,
        path: "/api/logout",
        handler: Handler::Logout,
        least: Some(Role::Viewer),
        action: "logout",
    },
    Route {
        method: Method::GET,
        path: "/api/session",
        handler: Handler::Session,
        least: Some(Role::Viewer),
        action: "session",
    },
    Route {
        method: Method::PUT,
        path: "/api/account/password",
        handler: Handler::Password,
        least: Some(Role::Viewer),
        action: "password",
    },
    Route {
        method: Method::GET,
        path: "/api/audit",
        handler: Handler::Audit,
        least: Some(Role::Operator),
        action: "audit",
    },
];

/// A request as the process sees it: what the routes need of it.
pub struct Req {
    pub method: Method,
    /// The path of the target, without the query.
    pub path: String,
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
    fn json(status: StatusCode, body: Value) -> Answer {
        Answer {
            status,
            body,
            cookie: None,
            allow: None,
            request: String::new(),
        }
    }

    fn error(status: StatusCode, words: &'static str) -> Answer {
        Answer::json(status, json!({ "error": words }))
    }

    fn unavailable() -> Answer {
        Answer::error(StatusCode::SERVICE_UNAVAILABLE, "unavailable")
    }

    fn cookie(mut self, cookie: String) -> Answer {
        self.cookie = Some(cookie);
        self
    }
}

/// The value of `Set-Cookie` for a session.
fn session_cookie(id: &str) -> String {
    format!("{COOKIE_NAME}={id}; Secure; HttpOnly; SameSite=Strict; Path=/")
}

/// The value of `Set-Cookie` that takes the cookie away.
fn cleared_cookie() -> String {
    format!("{COOKIE_NAME}=; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
}

/// The value of the cookie of the session. None: there is none, or the field is there more than once.
fn cookie_of(headers: &HeaderMap) -> Option<String> {
    let mut found = None;
    for value in headers.get_all(COOKIE) {
        let Ok(text) = value.to_str() else {
            continue;
        };
        for pair in text.split(';') {
            if let Some((name, value)) = pair.trim().split_once('=')
                && name == COOKIE_NAME
                && found.replace(value.to_owned()).is_some()
            {
                return None;
            }
        }
    }
    found
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
fn json_body<T: DeserializeOwned>(req: &Req) -> Result<T, Answer> {
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

/// The methods that a path has in the table, for `Allow`.
fn allowed(path: &str) -> String {
    let mut methods: Vec<&str> = ROUTES
        .iter()
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginBody {
    name: String,
    password: Secret,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordBody {
    current: Secret,
    new: Secret,
}

/// What the routes work with.
pub struct App {
    origin: String,
    trusted: Vec<Cidr>,
    auth: Auth,
    ids: RequestIds,
}

impl App {
    /// The routes over `store` and `audit`, for the configuration. `iterations` are the rounds of a new password
    /// hash. None: no random number.
    pub fn new(
        config: &AdminConfig,
        store: Arc<dyn AdminStore>,
        audit: Arc<AuditLog>,
        ids: RequestIds,
        iterations: u32,
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
            )?,
            ids,
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

    /// Answers a request. It reads files and computes a hash, so it is not called on the thread of the runtime.
    pub fn handle(&self, req: &Req) -> Answer {
        let id = self.request_id(req);
        let forwarded: Vec<&[u8]> = req
            .headers
            .get_all("x-forwarded-for")
            .iter()
            .map(HeaderValue::as_bytes)
            .collect();
        let client = effective(req.peer, &self.trusted, &forwarded).ip();
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
        if !ROUTES.iter().any(|route| route.path == req.path) {
            return Answer::error(StatusCode::NOT_FOUND, "not found");
        }
        let Some(route) = ROUTES
            .iter()
            .find(|route| route.path == req.path && route.method == method)
        else {
            let mut answer = Answer::error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
            answer.allow = Some(allowed(&req.path));
            return answer;
        };
        let who = match route.least {
            None => None,
            Some(_) => match self.who(req, now) {
                Ok(who) => Some(who),
                Err(answer) => return answer,
            },
        };
        let safe = method == Method::GET;
        if !safe && !self.origin_ok(req) {
            return self.refused(who.as_ref(), cx, route, "origin");
        }
        if let Some(who) = &who {
            if !safe && !csrf_ok(req, who) {
                return self.refused(Some(who), cx, route, "csrf");
            }
            if route.least.is_some_and(|least| who.role < least) {
                return self.refused(Some(who), cx, route, "role");
            }
        }
        match (route.handler, who) {
            (Handler::Login, _) => self.login(req, cx, now),
            (Handler::Logout, Some(who)) => self.logout(&who, cx),
            (Handler::Session, Some(who)) => session_answer(&who),
            (Handler::Password, Some(who)) => self.password(req, &who, cx, now),
            (Handler::Audit, Some(_)) => self.audit(),
            // A route that names a least role has a user by now.
            (_, None) => Answer::error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
        }
    }

    /// The user of the request, from its cookie.
    fn who(&self, req: &Req, now: Instant) -> Result<Who, Answer> {
        let unauthorized = || Answer::error(StatusCode::UNAUTHORIZED, "unauthorized");
        let cookie = cookie_of(&req.headers).ok_or_else(unauthorized)?;
        match self.auth.session(&cookie, now) {
            Authed::Who(who) => Ok(who),
            Authed::Unauthorized => Err(unauthorized()),
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

    /// The answer to a request that a check refused; the audit log has it when a user is known.
    fn refused(
        &self,
        who: Option<&Who>,
        cx: &Cx<'_>,
        route: &Route,
        reason: &'static str,
    ) -> Answer {
        if let Some(who) = who {
            self.auth.deny(who, cx, route.action, reason);
        }
        Answer::error(StatusCode::FORBIDDEN, "forbidden")
    }

    fn login(&self, req: &Req, cx: &Cx<'_>, now: Instant) -> Answer {
        let body: LoginBody = match json_body(req) {
            Ok(body) => body,
            Err(answer) => return answer,
        };
        if !self.auth.allow_client(cx.client, now) {
            return Answer::error(StatusCode::TOO_MANY_REQUESTS, "too many tries");
        }
        match self.auth.login(&body.name, &body.password, cx, now) {
            Login::Opened(opened, role) => Answer::json(
                StatusCode::OK,
                json!({
                    "name": body.name,
                    "role": role.name(),
                    "csrf": opened.csrf,
                    "mfa": false,
                }),
            )
            .cookie(session_cookie(&opened.cookie)),
            Login::Refused => Answer::error(StatusCode::UNAUTHORIZED, "invalid credentials"),
            Login::Unavailable => Answer::unavailable(),
        }
    }

    fn logout(&self, who: &Who, cx: &Cx<'_>) -> Answer {
        self.auth.logout(who, cx);
        Answer::json(StatusCode::OK, json!({})).cookie(cleared_cookie())
    }

    fn password(&self, req: &Req, who: &Who, cx: &Cx<'_>, now: Instant) -> Answer {
        let body: PasswordBody = match json_body(req) {
            Ok(body) => body,
            Err(answer) => return answer,
        };
        match self
            .auth
            .change_password(who, &body.current, &body.new, cx, now)
        {
            Changed::Done(Some(opened)) => {
                Answer::json(StatusCode::OK, json!({ "csrf": opened.csrf }))
                    .cookie(session_cookie(&opened.cookie))
            }
            Changed::Done(None) => {
                Answer::json(StatusCode::OK, json!({ "csrf": null })).cookie(cleared_cookie())
            }
            Changed::Wrong => Answer::error(StatusCode::FORBIDDEN, "the current password is wrong"),
            Changed::Invalid => Answer::error(
                StatusCode::BAD_REQUEST,
                "the new password is not 12 to 128 bytes",
            ),
            Changed::Conflict => Answer::error(StatusCode::CONFLICT, "conflict"),
            Changed::Gone => Answer::error(StatusCode::UNAUTHORIZED, "unauthorized"),
            Changed::Unavailable => Answer::unavailable(),
        }
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

fn session_answer(who: &Who) -> Answer {
    Answer::json(
        StatusCode::OK,
        json!({
            "name": who.name,
            "role": who.role.name(),
            "csrf": who.csrf,
            "mfa": false,
            "idle_expires_in_ms": millis(who.idle_left),
            "total_expires_in_ms": millis(who.total_left),
        }),
    )
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
    let declared = parts
        .headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|text| text.parse::<usize>().ok());
    if declared.is_some_and(|length| length > BODY_MAX) {
        return app.refuse(StatusCode::PAYLOAD_TOO_LARGE, "payload too large");
    }
    let body = match timeout(BODY_WAIT, Limited::new(body, BODY_MAX).collect()).await {
        Ok(Ok(collected)) => collected.to_bytes(),
        Ok(Err(e)) if e.is::<LengthLimitError>() => {
            return app.refuse(StatusCode::PAYLOAD_TOO_LARGE, "payload too large");
        }
        Ok(Err(_)) => return app.refuse(StatusCode::BAD_REQUEST, "bad request"),
        Err(_) => return app.refuse(StatusCode::REQUEST_TIMEOUT, "request timeout"),
    };
    let req = Req {
        method: parts.method,
        path: parts.uri.path().to_owned(),
        headers: parts.headers,
        peer,
        body,
    };
    let worker = app.clone();
    match timeout(
        ANSWER_WAIT,
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
    let _ = timeout(HEAD_WAIT + BODY_WAIT + ANSWER_WAIT, served).await;
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
    let Some(admin) = loaded.admin else {
        log.line("admin: configuration refused: there is no admin object");
        return Exit::Usage;
    };
    // The second factor is not built yet; a configuration that asks for it must not run with the password alone.
    if admin.mfa == Mfa::Required {
        log.line("admin: start: mfa required is not available yet");
        return Exit::Failed;
    }
    log.line("admin: configuration accepted");
    let store = match store::open(&admin.store) {
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
    let Some(app) = App::new(&admin, store, audit, ids, ITERATIONS) else {
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
mod tests;
