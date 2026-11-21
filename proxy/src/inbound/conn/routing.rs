//! The route that a request takes, before its body is read: the policy for the `Host`, the `Host` against the
//! certificate (421), the search for the route (404), the access lists (403), the limit of the body (413), the
//! admission of the record that is to be kept, and the way to the admin process.

use std::sync::atomic::Ordering;

use super::{Conn, Scheme};
use crate::forward::client_ip::Access;
use crate::forward::group::Route;
use crate::inbound::answer::{Reply, Stop};
use crate::policy::{self, Refusal};

impl Conn {
    /// The route the request takes. Before any route is looked for, a client that the `access` for its `Host`
    /// turns away is answered with 403, and one that is over the rate limit with 429 and the seconds to wait, also
    /// when the request would take a route that skips the inspection (a client that is in `exempt_cidrs` of the
    /// limit is not counted). A request that no route holds for, and that has no default group, is answered
    /// with 404 here, and one from a client that the access lists turn away with 403, before the body is read. If
    /// some route has an access list, every route that the request could be taken for, however it is written, has to
    /// allow the client (see `Upstreams::accesses`); if none has, nobody is turned away and that is not asked. On a
    /// connection that ended TLS the `Host` has to be covered by the certificate of the handshake first, or the
    /// answer is 421: the client may not use a connection for a site that its certificate does not stand for. Last
    /// comes the admission of a request that needs its record kept (see `keep`).
    pub(super) fn route(&self) -> Result<Route<'_>, Stop> {
        let client = self.client.ip();
        let ctx = &self.ctx;
        if let Some((route, access)) = ctx.setup.upstreams.admin(self.head.host()) {
            return self.admin(route, access);
        }
        policy::check(
            ctx.setup.scope(self.head.host()),
            &ctx.shared.counters,
            client,
            self.country,
        )
        .map_err(|refusal| self.turned_away_by(refusal))?;
        let (host, target) = (self.head.host(), self.head.target());
        if let Scheme::Https(hosts) = &self.scheme
            && !hosts.covers_host(host)
        {
            return Err(self.turned_away(421, "host not covered by the certificate"));
        }
        let upstreams = &self.ctx.setup.upstreams;
        let route = upstreams
            .find(host, target)
            .ok_or_else(|| self.turned_away(404, "no route matches"))?;
        let keeps = self.keep_by(&route);
        if upstreams.guarded()
            && !upstreams
                .accesses(host, target)
                .all(|access| access.permits(client, self.country))
        {
            return Err(self.turned_away(403, "denied by route access"));
        }
        // The limit of the route is looked at before the body is read, as the other limits that turn a request away.
        if let Some(max) = route.max_body
            && self
                .head
                .content_length()
                .is_some_and(|length| length > u64::try_from(max).unwrap_or(u64::MAX))
        {
            return Err(self.turned_away(413, "body over the limit of the route"));
        }
        self.admit_records(keeps)?;
        Ok(route)
    }

    /// The way to the admin process, without the policy: over a connection of its certificate (else 421, for an HTTP/2
    /// client may reuse one of a site that covers the name; 404 over plain HTTP), if its access list lets the client.
    fn admin<'a>(&self, route: Route<'a>, access: &Access) -> Result<Route<'a>, Stop> {
        match &self.scheme {
            Scheme::Https(hosts) if hosts.is_admin() => {}
            Scheme::Https(_) => {
                return Err(self.turned_away(421, "admin host on another certificate"));
            }
            Scheme::Http => return Err(self.turned_away(404, "admin host over plain http")),
        }
        if !access.permits(self.client.ip(), self.country) {
            return Err(self.turned_away(403, "denied by route access"));
        }
        self.admit_records(self.keep_by(&route))?;
        Ok(route)
    }

    /// The answer to a request that is turned away before its body is read. The connection goes on after it only if
    /// there was no body to read.
    fn turned_away(&self, status: u16, reason: &'static str) -> Stop {
        self.note_empty_body();
        Reply::rejected(status, reason).into()
    }

    /// The same for a request that the policy turns away (see `policy::check`).
    fn turned_away_by(&self, refusal: Refusal) -> Stop {
        self.note_empty_body();
        refusal.into()
    }

    /// A request with no body has been read to its end, whatever the answer is.
    pub(super) fn note_empty_body(&self) {
        if !self.head.chunked() && self.head.content_length().unwrap_or(0) == 0 {
            self.read_done.store(true, Ordering::Release);
        }
    }
}
