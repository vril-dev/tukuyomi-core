//! The listener that redirects to https.
//!
//! The first head is read as everywhere else, and then it is answered with the redirect, or with 404, without hyper,
//! the inspection or the upstream, and without reading its body; the connection is closed with the same `linger`
//! after the answer as any other.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpStream;
use tokio::time::{Instant, timeout_at};

use super::drive::Serving;
use super::gate::Taken;
use crate::inbound::answer::{NOT_REDIRECTED, Reply, redirect};
use crate::inbound::conn::{Ctx, Scheme, after};
use crate::inbound::head::Reject;
use crate::inbound::session::{Summary, first_head_by, linger, send_and_close};
use crate::inbound::transport::tls::host_name;

/// The listener redirects: its first head is answered with a redirect to https, or with 404, and the connection is
/// closed. The redirect is for a `Host` that a certificate of some TLS listener has among its hosts, when some route
/// (or the default group) holds for the request; the address is that name and the target as it was received. A
/// `Host` that is an IP literal, cannot be read, or is not served that way gets 404. The body is not read.
pub(in crate::inbound) async fn redirect_to(
    sock: TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
    ctx: &Arc<Ctx>,
    accept: Instant,
    https_port: u16,
) -> Summary {
    let cfg = &ctx.cfg;
    let (serving, mut gate) = Serving::start(sock, peer, local, ctx, accept, Scheme::Http);
    let session = &serving.session;
    if let Err(reject) = gate.first_head(first_head_by(cfg, accept)).await {
        return serving.refuse(&mut gate, reject).await;
    }
    let Some(Taken { head, .. }) = serving.link.take_first() else {
        return serving.refuse(&mut gate, Reject::BadRequest).await;
    };
    let name = host_name(head.host()).filter(|name| ctx.tls.serves(name));
    let routed = ctx.upstreams.find(head.host(), head.target()).is_some();
    let (reply, bytes) = match name {
        Some(name) if routed => (
            Reply::redirected(),
            redirect(&name, https_port, head.target()),
        ),
        _ => (
            Reply::rejected(404, "no redirect for the host"),
            NOT_REDIRECTED.to_vec(),
        ),
    };
    let by = after(Instant::now(), cfg.response_idle).min(session.conn_by());
    let sock = gate.stream();
    let _ = timeout_at(by, send_and_close(sock, &bytes)).await;
    linger(sock, cfg, session.conn_by()).await;
    Summary::of(session.id, reply)
}
