//! The body of a request: read within its limit and its time, or not read at all.
//!
//! A body over the usual limit (the import of a generation) is read only for a client with a live session, or an API
//! token, of a user whose role is at least that of the import and whom no state limits (a session that waits for
//! the second factor, a password that must be changed and a second factor that must be set up all do). A request
//! with a cookie and a token is not read either. For another client the body is not read, and the request goes on
//! with an empty one: the checks of `dispatch` (the credential, the state, the role) refuse it before any route
//! reads the body, and the audit log has the refusal. The user is read from the store, so the check runs on a thread
//! of the blocking pool. A token that is not right counts against the client here as it does in `dispatch`, and the
//! client that has used up its tries is not looked at.

use std::error::Error;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http::header::HeaderMap;
use http::{Response, StatusCode};
use http_body::Body;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use tokio::time::timeout;

use super::{App, BODY_MAX, BODY_WAIT, credential};
use crate::admin::waf::IMPORT_LEAST;

/// The body of the request with these `headers`, from `client`, at most `limit` bytes within `BODY_WAIT`; empty if it
/// is not to be read. The refusal is the response to send.
pub(super) async fn read<B>(
    app: &Arc<App>,
    headers: &HeaderMap,
    client: IpAddr,
    body: B,
    limit: usize,
) -> Result<Bytes, Response<Full<Bytes>>>
where
    B: Body<Data = Bytes>,
    B::Error: Into<Box<dyn Error + Send + Sync>>,
{
    if limit > BODY_MAX {
        let (worker, credential) = (app.clone(), credential(headers));
        let allowed = tokio::task::spawn_blocking(move || {
            worker
                .auth
                .allows(&credential, IMPORT_LEAST, client, Instant::now())
        })
        .await
        .unwrap_or(false);
        if !allowed {
            return Ok(Bytes::new());
        }
    }
    match timeout(BODY_WAIT, Limited::new(body, limit).collect()).await {
        Ok(Ok(collected)) => Ok(collected.to_bytes()),
        Ok(Err(e)) if e.is::<LengthLimitError>() => {
            Err(app.refuse(StatusCode::PAYLOAD_TOO_LARGE, "payload too large"))
        }
        Ok(Err(_)) => Err(app.refuse(StatusCode::BAD_REQUEST, "bad request")),
        Err(_) => Err(app.refuse(StatusCode::REQUEST_TIMEOUT, "request timeout")),
    }
}
