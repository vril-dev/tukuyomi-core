//! The listener that redirects to https.
//!
//! The first head is read as everywhere else, and then it is answered with the redirect, or with 404, without hyper,
//! the inspection or the upstream, and without reading its body; the connection is closed with the same `linger`
//! after the answer as any other. The challenge of the CA that issues the certificates with `acme` is answered
//! first, before the redirect is decided (see `challenge`). Next the policy of the configuration is asked (see
//! `policy`), as at the start of every request on the other listeners: a client that it turns away gets 403, or 429
//! with a `Retry-After`, instead of the redirect or the 404.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpStream;
use tokio::time::{Instant, timeout_at};

use super::drive::Serving;
use super::gate::Taken;
use crate::inbound::answer::{Noted, Reply, not_redirected, redirect, turned_away};
use crate::inbound::challenge::{Proof, found};
use crate::inbound::conn::{Ctx, Scheme, after, client_of, country_of};
use crate::inbound::head::Reject;
use crate::inbound::session::{Summary, first_head_by, linger, send_and_close};
use crate::inbound::transport::tls::host_name;
use crate::policy;

/// The listener redirects: its first head is answered with a redirect to https, or with 404, and the connection is
/// closed. The redirect is for a `Host` that a certificate of some TLS listener has among its hosts, when some route
/// (or the default group) holds for the request; the address is that name and the target as it was received. A
/// `Host` that is an IP literal, cannot be read, or is not served that way gets 404. The body is not read. A request
/// for the challenge of the CA is answered with the file of the challenge, or 404, instead (see `challenge`). A client
/// that the policy turns away is answered with 403 or 429 instead of all that. The records name the client that the
/// policy judges, found as on the other listeners (see `conn::client_of`).
pub(in crate::inbound) async fn redirect_to(
    sock: TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
    ctx: &Arc<Ctx>,
    listener: usize,
    accept: Instant,
    https_port: u16,
) -> Summary {
    let cfg = &ctx.cfg;
    let (serving, mut gate) =
        Serving::start(sock, peer, local, ctx, listener, accept, Scheme::Http);
    let session = &serving.session;
    if let Err(reject) = gate.first_head(first_head_by(cfg, accept)).await {
        return serving.refuse(&mut gate, reject).await;
    }
    let Some(Taken { head, .. }) = serving.link.take_first() else {
        return serving.refuse(&mut gate, Reject::BadRequest).await;
    };
    let id = ctx.ids.mint();
    // The client is found as on the other listeners: the peer, or what a trusted peer says. The policy judges it and
    // every record of the listener names it.
    let client = client_of(&head, peer, &cfg.trusted_proxies);
    // The bytes that are written, and how many of them are the body.
    let (reply, bytes, sent) = match ctx
        .challenge
        .as_ref()
        .and_then(|challenge| challenge.proof(&head))
    {
        Some(Proof::Found(body)) => {
            let head_only = head.method() == b"HEAD";
            let sent = if head_only { 0 } else { body.len() };
            (Reply::answered(200), found(&body, head_only, &id), sent)
        }
        Some(Proof::Missing) => (Reply::answered(404), not_redirected(&id), 0),
        None => match policy::check(
            &ctx.access,
            ctx.rate_limit.as_ref(),
            &ctx.counters,
            client.ip(),
            country_of(ctx, client.ip()),
        ) {
            Err(refusal) => (Reply::refused(refusal), turned_away(refusal, &id), 0),
            Ok(()) => {
                let name = host_name(head.host()).filter(|name| ctx.tls.serves(name));
                let routed = ctx.upstreams.find(head.host(), head.target()).is_some();
                match name {
                    Some(name) if routed => (
                        Reply::redirected(),
                        redirect(&name, https_port, head.target(), &id),
                        0,
                    ),
                    _ => (
                        Reply::rejected(404, "no redirect for the host"),
                        not_redirected(&id),
                        0,
                    ),
                }
            }
        },
    };
    let by = after(Instant::now(), cfg.response_idle).min(session.conn_by());
    let sock = gate.stream();
    let _ = timeout_at(by, send_and_close(sock, &bytes)).await;
    // The record of the answer comes before the wait for the client to stop sending.
    let mut noted = Noted::new(id, reply, client.ip()).of(&head);
    session.note(&mut noted, accept, u64::try_from(sent).unwrap_or(u64::MAX));
    linger(sock, cfg, session.conn_by()).await;
    session.summary(None)
}
