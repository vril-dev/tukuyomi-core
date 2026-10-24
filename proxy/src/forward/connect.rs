//! Making a connection to a server of an upstream group.
//!
//! The TCP connection is made to the address of the server. If the group has `tls`, the handshake of TLS follows on
//! it, and the certificate of the server is checked (see `tls`). The two together must be done by the end of the stage
//! (`upstream_connect`, or the end of the request time if that comes first; see `origin`). A handshake that fails in
//! any way, or that does not end in time, is a failure of the server (`Connect`), as a connection that is refused is:
//! a server that does not speak TLS, one that sends a certificate that is not trusted or is for another name, and
//! one that is silent are all the same to the request. The limits on what is read from the upstream (the cap on the
//! head of the answer, the idle limits) work above TLS, on the bytes after they are decrypted, as they work on the
//! bytes of a plain connection. The task that drives the connection hands the stream over when the upstream answers a
//! handshake of a WebSocket with 101, over TLS too.

use std::io;
use std::net::SocketAddr;

use bytes::Bytes;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout_at};

use crate::config::ProxyConfig;
use crate::forward::origin::{OriginError, Stage, head_cap, reached};
use crate::forward::pool::Lease;
use crate::forward::tls::Secure;
use crate::inbound::transport::io::Guarded;

/// The stage in which a connection to the upstream is taken or made; the error if its end is already past.
pub(super) fn connect_stage(cfg: &ProxyConfig, by: Instant) -> Result<Stage, OriginError> {
    let stage = Stage::new(Instant::now(), cfg.upstream_connect, by);
    if reached(stage.end) {
        return Err(stage.ran_out(OriginError::Connect));
    }
    Ok(stage)
}

/// Where a failed attempt to connect belongs. The server refusing the connection, resetting it, not being reachable
/// or not answering is its fault (`Connect`). Anything else is an error of the proxy itself (`Local`): no
/// descriptor, buffer, memory or port is left, or the system does not allow the connection.
pub(super) fn connect_error(e: &io::Error) -> OriginError {
    match e.kind() {
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::HostUnreachable
        | io::ErrorKind::NetworkUnreachable
        | io::ErrorKind::TimedOut => OriginError::Connect,
        _ => OriginError::Local,
    }
}

/// Makes a connection to the server at `address` within `stage`: over TLS if `secure` is there, and plain if not.
pub(super) async fn connect(
    address: SocketAddr,
    secure: Option<&Secure>,
    cfg: &ProxyConfig,
    stage: Stage,
) -> Result<Lease, OriginError> {
    let stream = match timeout_at(stage.end, TcpStream::connect(address)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => return Err(connect_error(&e)),
        Err(_) => return Err(stage.ran_out(OriginError::Connect)),
    };
    stream.set_nodelay(true).map_err(|_| OriginError::Local)?;
    let Some(secure) = secure else {
        return start(stream, cfg).await;
    };
    let stream = match timeout_at(stage.end, secure.handshake(stream)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(_)) => return Err(OriginError::Connect),
        Err(_) => return Err(stage.ran_out(OriginError::Connect)),
    };
    start(stream, cfg).await
}

/// The connection of HTTP/1.1 on `stream`, which is made and driven by a task of its own.
async fn start<T>(stream: T, cfg: &ProxyConfig) -> Result<Lease, OriginError>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Up to the final head the reads are capped as a whole; the cap is lifted as soon as the head is here.
    let (guarded, gauge) = Guarded::new(
        stream,
        Bytes::new(),
        cfg.response_idle,
        cfg.response_idle,
        head_cap(cfg),
    );
    let mut client = http1::Builder::new();
    client
        .max_headers(cfg.upstream_max_headers)
        .max_header_size(cfg.upstream_max_head_bytes)
        .max_buf_size(cfg.upstream_max_head_bytes.max(8192))
        .title_case_headers(true);
    let (sender, conn) = client
        .handshake(TokioIo::new(guarded))
        .await
        .map_err(|_| OriginError::Local)?;
    // With upgrades, the task hands the socket over when the upstream answers a handshake with 101.
    let task = tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });
    Ok(Lease::new(sender, gauge, task.abort_handle()))
}

#[cfg(test)]
mod tests;
