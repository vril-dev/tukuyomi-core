//! The host of a rule, and the `Host` value of a request.

use super::rule::RouteError;

const MAX_HOST_BYTES: usize = 253;

/// A port as the text of a host holds it: 1 to 5 digits without a leading zero, from 1 to 65535.
fn parse_port(text: &[u8]) -> Option<u16> {
    if text.is_empty() || text.len() > 5 || text[0] == b'0' || !text.iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    std::str::from_utf8(text).ok()?.parse().ok()
}

/// The `Host` value of a request, split into its name and its port.
pub(super) struct RequestHost<'a> {
    name: &'a [u8],
    port: Option<u16>,
    /// The name ended in a `.`, which is not part of `name`.
    dotted: bool,
}

impl<'a> RequestHost<'a> {
    /// The name is letters, digits, `-` and `.`, or an IPv6 address in brackets; the port, if there is one, is as
    /// `parse_port` takes it. One `.` at the end of a name is dropped (`dotted` tells that it was there), and no
    /// label of the name may be empty. `None` for any other `Host` value: it holds for no rule that has a host.
    pub(super) fn parse(host: &'a [u8]) -> Option<RequestHost<'a>> {
        let (name, port, dotted) = if host.first() == Some(&b'[') {
            let end = host.iter().position(|&b| b == b']')?;
            let literal = &host[1..end];
            let ok = !literal.is_empty()
                && literal
                    .iter()
                    .all(|&b| b.is_ascii_hexdigit() || b == b':' || b == b'.');
            let port = match &host[end + 1..] {
                [] => None,
                [b':', port @ ..] => Some(parse_port(port)?),
                _ => return None,
            };
            (ok.then_some(&host[..=end])?, port, false)
        } else {
            let (name, port) = match host.iter().position(|&b| b == b':') {
                Some(at) => (&host[..at], Some(parse_port(&host[at + 1..])?)),
                None => (host, None),
            };
            let dotted = name.ends_with(b".");
            let name = name.strip_suffix(b".").unwrap_or(name);
            // An empty name is one empty label.
            let ok = name.split(|&b| b == b'.').all(|label| !label.is_empty())
                && name
                    .iter()
                    .all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
            (ok.then_some(name)?, port, dotted)
        };
        Some(RequestHost { name, port, dotted })
    }
}

/// How well the host of a rule holds for a request. The fields are in the order of their strength: a name before a
/// wildcard (a longer wildcard before a shorter one), and a rule with a port before one without.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct HostRank {
    kind: Kind,
    len: usize,
    port: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    /// The rule has no host, so it holds for every host.
    Any,
    Wildcard,
    Name,
}

impl HostRank {
    pub(super) const ANY: HostRank = HostRank {
        kind: Kind::Any,
        len: 0,
        port: false,
    };
}

/// The host of a rule: a name, or a wildcard (`*.` and a name), and a port or none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct HostRule {
    /// As it was given.
    text: String,
    /// The name; for a wildcard, the name with the `.` in front of it, which is the end of every name that holds.
    name: String,
    wildcard: bool,
    port: Option<u16>,
    /// The rule holds for the name as the request wrote it, so not for a name that ends in a `.`.
    exact: bool,
}

impl HostRule {
    /// `wildcard` allows a name that starts with `*.`. A rule that does not allow it is one that lets a request
    /// through without inspection, and it holds for the name as the request wrote it only: the upstream gets the
    /// `Host` with its last `.`, and may take it for another host than the one the rule names.
    pub(super) fn new(host: &str, wildcard: bool) -> Result<HostRule, RouteError> {
        const BAD: RouteError = RouteError("a route host is malformed");
        let exact = !wildcard;
        if !(1..=MAX_HOST_BYTES).contains(&host.len()) {
            return Err(RouteError("a route host is not 1 to 253 bytes"));
        }
        let (rest, wildcard) = match host.strip_prefix('*') {
            Some(rest) if wildcard && rest.starts_with('.') => (rest, true),
            _ => (host, false),
        };
        let (name, port) = match rest.split_once(':') {
            Some((name, port)) => (name, Some(port)),
            None => (rest, None),
        };
        // A wildcard keeps its dot, which a name could not start with.
        let label_part = if wildcard { &name[1..] } else { name };
        let name_ok = !label_part.is_empty()
            && !label_part.ends_with('.')
            && label_part
                .bytes()
                .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.'));
        if !name_ok {
            return Err(BAD);
        }
        let port = match port {
            Some(port) => Some(parse_port(port.as_bytes()).ok_or(BAD)?),
            None => None,
        };
        Ok(HostRule {
            text: host.to_owned(),
            name: name.to_owned(),
            wildcard,
            port,
            exact,
        })
    }

    pub(super) fn as_str(&self) -> &str {
        &self.text
    }

    /// How well the rule holds for the host; `None` if it does not.
    pub(super) fn rank(&self, host: &RequestHost) -> Option<HostRank> {
        if self.port.is_some_and(|port| host.port != Some(port)) {
            return None;
        }
        if self.exact && host.dotted {
            return None;
        }
        let rule = self.name.as_bytes();
        let kind = if self.wildcard {
            // At least one byte in front of the rule, which is the name with its dot.
            let front = host.name.len().checked_sub(rule.len())?;
            if front == 0 || !host.name[front..].eq_ignore_ascii_case(rule) {
                return None;
            }
            Kind::Wildcard
        } else {
            if !host.name.eq_ignore_ascii_case(rule) {
                return None;
            }
            Kind::Name
        };
        Some(HostRank {
            kind,
            len: rule.len(),
            port: self.port.is_some(),
        })
    }
}
