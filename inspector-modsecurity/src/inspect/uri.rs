//! Whether a request target can be parsed, and where its query starts.
//!
//! The library does not say when a target is unusable, so the inspector decides it, the way the other rule
//! engine of this product does, which parses the target as a request target (no fragment, not a bare reference)
//! with the URL parser of its standard library. The same targets are then blocked by both engines. What follows
//! is that parser's check, copied branch by branch: it only says whether the target parses, and builds nothing.
//!
//! One part is not a copy: the address in square brackets (an IPv6 address, `http://[::1]/`) is checked with the
//! IPv6 parser of this crate's standard library, where the other engine uses a parser of its own. They are
//! written to the same rules, but a text they read differently is not known.
//!
//! The proxy forwards only targets of the form `/path?query`, for which the check comes down to a control byte, a
//! missing leading slash and a bad percent escape in the path; the rest is for what the kernel could be handed.
#![forbid(unsafe_code)]

use std::net::Ipv6Addr;

/// The target without its fragment, which is what the parser is given.
fn without_fragment(target: &[u8]) -> &[u8] {
    match target.iter().position(|&byte| byte == b'#') {
        Some(at) => &target[..at],
        None => target,
    }
}

/// The query of a target: what follows its first `?`, once the fragment is cut off. It is the same whether or not
/// the target parses.
pub(super) fn query(target: &[u8]) -> &[u8] {
    let target = without_fragment(target);
    match target.iter().position(|&byte| byte == b'?') {
        Some(at) => &target[at + 1..],
        None => &[],
    }
}

/// Whether the target can be parsed.
pub(super) fn parses(target: &[u8]) -> bool {
    let target = without_fragment(target);
    if target.iter().any(|&byte| byte < b' ' || byte == 0x7f) || target.is_empty() {
        return false;
    }
    if target == b"*" {
        return true;
    }
    let Some((scheme, rest)) = split_scheme(target) else {
        return false;
    };
    // The query is not looked at: the path is what comes before the first `?`.
    let rest = match rest.iter().position(|&byte| byte == b'?') {
        Some(at) => &rest[..at],
        None => rest,
    };
    if !rest.starts_with(b"/") {
        // After a scheme the rest is opaque and taken as it is. A target with no scheme has to start with a slash.
        return !scheme.is_empty();
    }
    let path = if !scheme.is_empty() && rest.starts_with(b"//") {
        let after = &rest[2..];
        let (authority, path) = match after.iter().position(|&byte| byte == b'/') {
            Some(at) => after.split_at(at),
            None => (after, &[][..]),
        };
        if !authority_parses(scheme, authority) {
            return false;
        }
        path
    } else {
        rest
    };
    unescape(path, Mode::Path).is_some()
}

/// The scheme and the rest. No scheme (an empty one) is not an error; a colon at the very start is.
fn split_scheme(target: &[u8]) -> Option<(&[u8], &[u8])> {
    for (at, &byte) in target.iter().enumerate() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' => {}
            b'0'..=b'9' | b'+' | b'-' | b'.' => {
                if at == 0 {
                    return Some((&[], target));
                }
            }
            b':' => {
                return if at == 0 {
                    None
                } else {
                    Some((&target[..at], &target[at + 1..]))
                };
            }
            _ => return Some((&[], target)),
        }
    }
    Some((&[], target))
}

/// The part after `//`: the user information before the last `@`, and the host.
fn authority_parses(scheme: &[u8], authority: &[u8]) -> bool {
    let at = authority.iter().rposition(|&byte| byte == b'@');
    let host = at.map_or(authority, |at| &authority[at + 1..]);
    if !host_parses(scheme, host) {
        return false;
    }
    let Some(at) = at else {
        return true;
    };
    let user = &authority[..at];
    if !user.iter().all(|&byte| user_byte(byte)) {
        return false;
    }
    match user.iter().position(|&byte| byte == b':') {
        None => unescape(user, Mode::User).is_some(),
        Some(colon) => {
            unescape(&user[..colon], Mode::User).is_some()
                && unescape(&user[colon + 1..], Mode::User).is_some()
        }
    }
}

fn user_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.'
                | b'_'
                | b':'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b'%'
                | b'@'
        )
}

fn host_parses(scheme: &[u8], host: &[u8]) -> bool {
    if let Some(open) = host.iter().rposition(|&byte| byte == b'[') {
        return open == 0 && ip_literal_parses(host);
    }
    if let Some(first) = host.iter().position(|&byte| byte == b':') {
        let last = host.iter().rposition(|&byte| byte == b':').unwrap_or(first);
        // With more than one colon the port is taken from the first for http and https, which then fails, and from
        // the last for any other scheme.
        let web = scheme.eq_ignore_ascii_case(b"http") || scheme.eq_ignore_ascii_case(b"https");
        let colon = if last != first && !web { last } else { first };
        if !port_parses(&host[colon..]) {
            return false;
        }
    }
    unescape(host, Mode::Host).is_some()
}

/// A host in square brackets, with an optional port after them.
fn ip_literal_parses(host: &[u8]) -> bool {
    let Some(close) = host.iter().rposition(|&byte| byte == b']') else {
        return false;
    };
    let port = &host[close + 1..];
    if !port_parses(port) || unescape(port, Mode::Host).is_none() {
        return false;
    }
    let name = &host[1..close];
    let address = match name.windows(3).position(|window| window == b"%25") {
        Some(zone) => {
            let Some(mut address) = unescape(&name[..zone], Mode::Host) else {
                return false;
            };
            let Some(zone) = unescape(&name[zone..], Mode::Zone) else {
                return false;
            };
            address.extend_from_slice(&zone);
            address
        }
        None => match unescape(name, Mode::Host) {
            Some(address) => address,
            None => return false,
        },
    };
    ipv6_parses(&address)
}

/// An IPv6 address, with an optional zone after a `%`. What starts with a dot is an IPv4 address, and an address
/// in brackets must not be one. A `%` before any other mark is a zone with no address.
fn ipv6_parses(address: &[u8]) -> bool {
    match address
        .iter()
        .find(|&&byte| matches!(byte, b'.' | b':' | b'%'))
    {
        Some(b':') => {}
        _ => return false,
    }
    let (address, zone) = match address.iter().position(|&byte| byte == b'%') {
        Some(at) => (&address[..at], Some(&address[at + 1..])),
        None => (address, None),
    };
    if zone.is_some_and(<[u8]>::is_empty) {
        return false;
    }
    std::str::from_utf8(address).is_ok_and(|address| address.parse::<Ipv6Addr>().is_ok())
}

/// Nothing, or a colon and digits.
fn port_parses(port: &[u8]) -> bool {
    match port {
        [] => true,
        [b':', digits @ ..] => digits.iter().all(u8::is_ascii_digit),
        _ => false,
    }
}

/// Where a text is read: a path or the user information, where only the percent escapes are checked, or a host or
/// the zone of one, where the other bytes are as well.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Path,
    User,
    Host,
    Zone,
}

fn unhex(byte: u8) -> u8 {
    9 * (byte >> 6) + (byte & 15)
}

/// A byte that a host may hold unescaped.
fn host_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'_'
                | b'.'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'['
                | b']'
                | b'<'
                | b'>'
                | b'"'
        )
}

/// Reads the percent escapes of a text. `None` for a `%` that is not followed by two hex digits, for an escape
/// that a host may not hold, and for a byte below 0x80 that a host may not hold.
fn unescape(text: &[u8], mode: Mode) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len());
    let mut at = 0;
    while at < text.len() {
        match text[at] {
            b'%' => {
                if at + 2 >= text.len()
                    || !text[at + 1].is_ascii_hexdigit()
                    || !text[at + 2].is_ascii_hexdigit()
                {
                    return None;
                }
                let escape = &text[at..at + 3];
                let value = (unhex(text[at + 1]) << 4) | unhex(text[at + 2]);
                if mode == Mode::Host && unhex(text[at + 1]) < 8 && escape != b"%25" {
                    return None;
                }
                if mode == Mode::Zone && escape != b"%25" && value != b' ' && !host_byte(value) {
                    return None;
                }
                out.push(value);
                at += 3;
            }
            byte => {
                if matches!(mode, Mode::Host | Mode::Zone) && byte < 0x80 && !host_byte(byte) {
                    return None;
                }
                out.push(byte);
                at += 1;
            }
        }
    }
    Some(out)
}
