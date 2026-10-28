//! The step that asks the policy about a request, and what a request that it turns away is answered with.

use std::net::IpAddr;

use super::RateLimit;
use crate::forward::client_ip::Access;
use crate::log::counters::{self, Counters};

/// Why the policy turns a request away. It fixes the status of the answer, the text of the record and the seconds in
/// the `Retry-After`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The `access` does not let the client use the proxy at all.
    Access,
    /// The client is over the `rate_limit` and has to wait this many seconds, at least 1.
    RateLimit(u32),
}

impl Refusal {
    /// The status of the answer.
    pub fn status(self) -> u16 {
        match self {
            Refusal::Access => 403,
            Refusal::RateLimit(_) => 429,
        }
    }

    /// A fixed short text for the record.
    pub fn reason(self) -> &'static str {
        match self {
            Refusal::Access => "denied by access",
            Refusal::RateLimit(_) => "too many requests",
        }
    }

    /// The seconds that the answer tells the client to wait in `Retry-After`, if it does.
    pub fn retry_after(self) -> Option<u32> {
        match self {
            Refusal::Access => None,
            Refusal::RateLimit(seconds) => Some(seconds),
        }
    }
}

/// Asks the policy about `client`, the address that stands for the client of a request (see `forward::client_ip`):
/// the `access` first, so that a client it turns away is not counted by the rate limit, and then the `rate_limit`, if
/// there is one. A request that is turned away is counted in `counters` here, by what turned it away, so that every
/// place that asks counts alike.
pub fn check(
    access: &Access,
    rate_limit: Option<&RateLimit>,
    counters: &Counters,
    client: IpAddr,
) -> Result<(), Refusal> {
    if !access.permits(client) {
        counters.add_policy_refusal(counters::Policy::Access);
        return Err(Refusal::Access);
    }
    if let Some(limit) = rate_limit
        && let Err(seconds) = limit.admit(client)
    {
        counters.add_policy_refusal(counters::Policy::RateLimit);
        return Err(Refusal::RateLimit(seconds));
    }
    Ok(())
}
