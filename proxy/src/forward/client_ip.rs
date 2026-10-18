//! Which address stands for the client of a request, and which peers are believed when they say who the client is.
//!
//! A peer that is in `trusted_proxies` may tell, in its `X-Forwarded-For` lines, who is behind it. The lines are
//! read as one list, from the right end to the left: the address of a trusted proxy is skipped, and the first
//! address that is not one is the client. If every address is trusted, the leftmost is the client. An entry that
//! is not an IP literal ends the reading and leaves the peer as the client. A peer that is not trusted is the
//! client, whatever its lines say. An address taken from the lines has no port of its own, so its port is 0.
//! Everything here is a pure function of its arguments.

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
