//! The `status` object of the configuration: where the proxy answers `/healthz`, `/readyz` and `/metrics` (see
//! `run::status`).
//!
//! The object may be left out, and then there is no such listener. When it is there it has the one key `listen`, an IP
//! literal and a port (`[..]:port` for IPv6, port 0 is refused). Only a loopback address is accepted (`127.0.0.0/8`
//! and `::1`; an IPv4 address written in the IPv6 form is not one): the answers need no credentials, so they are for
//! a program on the same host. The address may not be the address of a listener, nor may one of the two be an
//! unspecified address at the port of the other (the same rule as for two listeners: the second bind would fail). No
//! server of an upstream may be at the address either (see `forward`), as it may not be at the address of a listener:
//! a route to it would send the requests of clients to the listener. The listener does not count among the 1 to 8
//! `listeners`, and it is not the plain or TLS listener that one of them has to be.

use std::net::SocketAddr;

use serde::Deserialize;

use super::listeners::clash;
use super::{ConfigError, ListenerConfig, Object, address, ensure};

/// The `status` object, checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatusConfig {
    pub listen: SocketAddr,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawStatus {
    listen: String,
}

/// Checks the object against the listeners.
pub(super) fn check(
    raw: Option<Object<RawStatus>>,
    listeners: &[ListenerConfig],
) -> Result<Option<StatusConfig>, ConfigError> {
    let Some(Object(raw)) = raw else {
        return Ok(None);
    };
    let listen = address(
        &raw.listen,
        "status listen is not an IP address and port",
        "status listen port is 0",
    )?;
    ensure(
        listen.ip().is_loopback(),
        "status listen is not a loopback address",
    )?;
    ensure(
        listeners
            .iter()
            .all(|listener| !clash(listener.address, listen)),
        "status listen is the address of a listener, or one is an unspecified address at the port of the other",
    )?;
    Ok(Some(StatusConfig { listen }))
}
