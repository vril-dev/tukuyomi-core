//! The listener of the admin process: its connections, the reading of a request and the fields of an answer, and the
//! start and stop of the process.
//!
//! The process listens on `admin.listen`, a loopback address, and speaks HTTP/1.1 without TLS (a route of the proxy
//! that has TLS can be the way in from outside). At most 32 connections are served at once; one that finds no place
//! is accepted and closed. A connection serves one request and is closed after the answer (`Connection: close`), so a
//! connection never waits for a second request. The head is at most 8 KiB and comes within 10 s; the body is at most
//! 64 KiB (12 MiB for the import of a generation and for the version to apply, read only for a client with a live
//! session or token of a user whose role and state let it use the route; see `body`) and comes within 30 s; the
//! answer is made within 30 s, or for the import, the switch and the rollback of the rules within `Waf::longest`. A
//! connection lives for the three times together at the most. A head that hyper refuses by itself (a malformed one,
//! or one over the limit) gets hyper's own answer, or none, and not the fields below.
//!
//! The files of the page (`GET /` and `GET /ui/<version>/<name>`) are answered first, by `ui`, with fields of their
//! own. Each API answer is JSON and has `Content-Type: application/json`, `Cache-Control: no-store`,
//! `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`,
//! `Referrer-Policy: no-referrer` and `X-Request-ID`.
//!
//! The stop: SIGTERM, SIGINT and SIGHUP close the listener and tell the service manager `STOPPING=1`; the requests
//! in flight have 10 s to end, and the process exits with code 0. `READY=1` is told after the listener is bound.

use std::convert::Infallible;
use std::future::poll_fn;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use bytes::Bytes;
use http::header::{
    ALLOW, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, HeaderName, HeaderValue, SET_COOKIE,
};
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::{TcpListener, TcpStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout, timeout_at};
use tukuyomi_kernel::limits;

use super::{ANSWER_WAIT, Answer, App, BODY_WAIT, Req, body, body_limit, ui};
use crate::admin::Exit;
use crate::admin::audit::AuditLog;
use crate::admin::file_store::AUDIT_DIR;
use crate::admin::managed::Managed;
use crate::admin::password::ITERATIONS;
use crate::admin::store;
use crate::admin::waf::{self, Waf};
use crate::config::{self, AdminStoreConfig};
use crate::inbound::session::RequestIds;
use crate::log::Log;
use crate::run::host;
use crate::run::notify::Notify;

/// The most connections served at once.
const SEATS: usize = 32;
/// The most bytes of a head.
const HEAD_MAX: usize = 8192;
const HEAD_WAIT: Duration = Duration::from_secs(10);
/// The time the requests in flight have at the stop.
const STOP_WAIT: Duration = Duration::from_secs(10);
/// The pause after an accept failed.
const ACCEPT_PAUSE: Duration = Duration::from_millis(100);

impl App {
    /// An answer for a request that never reached the routes.
    pub(super) fn refuse(&self, status: StatusCode, words: &'static str) -> Response<Full<Bytes>> {
        let mut answer = Answer::error(status, words);
        answer.request = self.ids.mint();
        response(&answer)
    }
}

/// The response for an answer, with the fields every answer has.
pub(super) fn response(answer: &Answer) -> Response<Full<Bytes>> {
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
    if let Some(page) = ui::serve(&app, &parts.method, parts.uri.path()) {
        return page;
    }
    let (limit, least) = body_limit(&parts.method, parts.uri.path());
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
    let body = match body::read(&app, &parts.headers, client, body, limit, least).await {
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
pub(super) async fn connection(stream: TcpStream, peer: SocketAddr, app: Arc<App>) {
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
    app.managed.iter().for_each(Managed::interrupt);
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
    let loaded = match config::load_main(path) {
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
    let managed = Managed::from_config(
        path,
        &loaded,
        &admin,
        store.clone(),
        audit.clone(),
        log.clone(),
    );
    let Some(app) = App::new(
        &admin,
        store,
        audit,
        ids,
        ITERATIONS,
        Some(waf),
        Some(managed),
    ) else {
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
