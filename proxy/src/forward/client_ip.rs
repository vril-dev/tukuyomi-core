//! Which address stands for the client of a request, and which peers are believed when they say who the client is.
//!
//! A peer that is in `trusted_proxies` may tell, in its `X-Forwarded-For` lines, who is behind it. The lines are
//! read as one list, from the right end to the left: the address of a trusted proxy is skipped, and the first
//! address that is not one is the client. If every address is trusted, the leftmost is the client. An entry that
//! is not an IP literal ends the reading and leaves the peer as the client. A peer that is not trusted is the
//! client, whatever its lines say. An address taken from the lines has no port of its own, so its port is 0.
//! Everything here is a pure function of its arguments.
//!
//! `Access` is the lists of networks and of countries of a route, and of the configuration as a whole: the client of
//! a request, as found above, decides whether the route may be used. The country is that of the same address (see
//! `policy::country`). A request is held to the lists of every route it could be taken for, however its path is
//! written, not only of the one it was matched to (see `route` and `inbound::conn`). The default route has no
//! lists.

use std::net::{IpAddr, SocketAddr};

use crate::inbound::head::trim_ows;

/// A network of `trusted_proxies`: the bits of an address that its prefix holds fixed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    v6: bool,
    /// The address from the top bit of 128: an IPv4 address is shifted up by 96 bits.
    net: u128,
    bits: u8,
}

/// The family of an address and its bits from the top of 128. An IPv4-mapped IPv6 address counts as the IPv4
/// address it holds.
fn key(ip: IpAddr) -> (bool, u128) {
    match ip.to_canonical() {
        IpAddr::V4(v4) => (false, u128::from(u32::from(v4)) << 96),
        IpAddr::V6(v6) => (true, u128::from(v6)),
    }
}

/// The top `bits` bits of 128.
fn mask(bits: u8) -> u128 {
    if bits == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(bits))
    }
}

impl Cidr {
    /// `address/bits`, read strictly: an IPv4 or IPv6 literal, and a prefix length of decimal digits (no sign, no
    /// leading zero) of at most 32 or 128. The address must have no bit set below the prefix: it names the
    /// network, so a host address with a prefix is refused and not silently widened. An IPv4-mapped IPv6 address
    /// is refused too; the network is written as IPv4.
    pub fn parse(text: &str) -> Option<Cidr> {
        let (net, bits) = text.split_once('/')?;
        if bits.is_empty()
            || bits.len() > 3
            || !bits.bytes().all(|b| b.is_ascii_digit())
            || (bits.len() > 1 && bits.starts_with('0'))
        {
            return None;
        }
        let bits: u8 = bits.parse().ok()?;
        let net: IpAddr = net.parse().ok()?;
        let width = match net {
            IpAddr::V4(_) => 32,
            IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some() => return None,
            IpAddr::V6(_) => 128,
        };
        if bits > width {
            return None;
        }
        let (v6, net) = key(net);
        (net & !mask(bits) == 0).then_some(Cidr { v6, net, bits })
    }

    /// Whether `ip` is in the network. An IPv4-mapped IPv6 address is looked at as the IPv4 address it holds.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let (v6, bits) = key(ip);
        v6 == self.v6 && (bits ^ self.net) & mask(self.bits) == 0
    }
}

/// Whether `ip` is in one of the networks.
pub fn trusts(list: &[Cidr], ip: IpAddr) -> bool {
    list.iter().any(|net| net.contains(ip))
}

/// A country, as the lists of an `Access` and the country database name it: the two letters of its ISO 3166-1 alpha-2
/// code, or `Unknown` for an address that no country is known for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Country {
    Known([u8; 2]),
    Unknown,
}

impl Country {
    /// `UNKNOWN`, or a code of exactly two upper-case ASCII letters; anything else, lower case included, is `None`.
    /// A code is not looked up in the list of ISO 3166: a database may hold codes that the list has not.
    pub fn parse(text: &str) -> Option<Country> {
        if text == "UNKNOWN" {
            return Some(Country::Unknown);
        }
        match text.as_bytes() {
            &[a, b] if a.is_ascii_uppercase() && b.is_ascii_uppercase() => {
                Some(Country::Known([a, b]))
            }
            _ => None,
        }
    }
}

/// The networks and the countries that decide who may use a route. A client in a `deny` network or country is turned
/// away; so is a client that is outside the `allow` networks, if there are any, and one that is outside the `allow`
/// countries, if there are any: every list of `allow` that is not empty has to hold the client. All four lists empty
/// turn nobody away.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Access {
    deny: Vec<Cidr>,
    allow: Vec<Cidr>,
    deny_countries: Vec<Country>,
    allow_countries: Vec<Country>,
}

impl Access {
    pub fn new(deny: Vec<Cidr>, allow: Vec<Cidr>) -> Access {
        Access {
            deny,
            allow,
            deny_countries: Vec::new(),
            allow_countries: Vec::new(),
        }
    }

    /// The same lists, with these countries.
    pub fn with_countries(self, deny: Vec<Country>, allow: Vec<Country>) -> Access {
        Access {
            deny_countries: deny,
            allow_countries: allow,
            ..self
        }
    }

    /// Whether the client at `ip`, which is in `country`, may use the route. `country` is only asked of the lists of
    /// countries, so it can be `Country::Unknown` where there are none.
    pub fn permits(&self, ip: IpAddr, country: Country) -> bool {
        !trusts(&self.deny, ip)
            && !self.deny_countries.contains(&country)
            && (self.allow.is_empty() || trusts(&self.allow, ip))
            && (self.allow_countries.is_empty() || self.allow_countries.contains(&country))
    }

    /// Whether all four lists are empty, so that nobody is turned away.
    pub fn is_empty(&self) -> bool {
        self.deny.is_empty() && self.allow.is_empty() && !self.has_countries()
    }

    /// Whether a list of countries is not empty.
    pub fn has_countries(&self) -> bool {
        !self.deny_countries.is_empty() || !self.allow_countries.is_empty()
    }
}

/// An entry of an `X-Forwarded-For` line: an IP literal, without the blanks around it.
fn literal(entry: &[u8]) -> Option<IpAddr> {
    std::str::from_utf8(trim_ows(entry)).ok()?.parse().ok()
}

/// The address of the client of a request that came from `peer`. `lines` are the values of the `X-Forwarded-For`
/// lines of the request, in the order received. `trusted` are the `trusted_proxies`.
pub fn effective(peer: SocketAddr, trusted: &[Cidr], lines: &[&[u8]]) -> SocketAddr {
    if !trusts(trusted, peer.ip()) {
        return peer;
    }
    let mut leftmost = None;
    for line in lines.iter().rev() {
        for entry in line.rsplit(|&b| b == b',') {
            let Some(ip) = literal(entry) else {
                return peer;
            };
            if !trusts(trusted, ip) {
                return SocketAddr::new(ip.to_canonical(), 0);
            }
            leftmost = Some(ip);
        }
    }
    leftmost.map_or(peer, |ip| SocketAddr::new(ip.to_canonical(), 0))
}

#[cfg(test)]
mod tests;
