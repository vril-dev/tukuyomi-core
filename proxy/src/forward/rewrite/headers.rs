//! The field edits of a route, for the request or for the response: fields taken out, set and added.
//!
//! The edits are made in this order: every field of a name in `remove` is taken out; for each pair of `set`, every
//! field of its name is taken out and one is put in; for each pair of `add`, a field is put in after the others. A
//! name is in one of the three lists once, whatever the case of its letters.
//!
//! A name is 1 to 256 bytes of the characters of a field name. A value is 0 to 4096 bytes of visible ASCII, spaces
//! and tabs, and does not begin or end with a space or a tab. Some names are refused because the proxy makes the
//! field itself or the field would change what was inspected or how the message is framed: see `Side::refuses`.

use std::collections::BTreeSet;

use http::{HeaderMap, HeaderName, HeaderValue};

use super::{MAX_ITEMS, RewriteError};
use crate::forward::origin::{CLIENT_CLAIMS, REQUEST_HOP, RESPONSE_HOP};

const MAX_NAME: usize = 256;
const MAX_VALUE: usize = 4096;

/// Which message the fields are of.
#[derive(Clone, Copy)]
enum Side {
    Request,
    Response,
}

impl Side {
    /// Whether a route may not edit the field. For the request: the fields that belong to the connection or to a
    /// single hop, the fields by which a peer says who the client is, `Host`, `X-Forwarded-Host` and `X-Request-ID`
    /// (the proxy makes it), the fields that tell how the body is coded or how long it is (the body that was inspected
    /// is the body that is sent), and any name with an underscore (such a field is never inspected nor sent). For
    /// the response: the fields of the connection or of a single hop, `Set-Cookie`, `X-Request-ID` (the proxy makes
    /// it), and the fields that tell how the body is coded or how long it is.
    fn refuses(self, name: &HeaderName) -> bool {
        let name = name.as_str();
        match self {
            Side::Request => {
                name.contains('_')
                    || REQUEST_HOP.contains(&name)
                    || CLIENT_CLAIMS.contains(&name)
                    || matches!(
                        name,
                        "host"
                            | "x-forwarded-host"
                            | "x-request-id"
                            | "content-length"
                            | "content-type"
                            | "content-encoding"
                    )
            }
            Side::Response => {
                RESPONSE_HOP.contains(&name)
                    || matches!(
                        name,
                        "set-cookie"
                            | "x-request-id"
                            | "content-length"
                            | "content-encoding"
                            | "content-range"
                            | "content-type"
                    )
            }
        }
    }

    fn name_error(self) -> RewriteError {
        RewriteError(match self {
            Side::Request => "a request field name is not allowed in the edits",
            Side::Response => "a response field name is not allowed in the edits",
        })
    }
}

/// The name of a field to edit: 1 to 256 bytes of field name characters, and not one that `side` refuses.
fn name(side: Side, text: &str) -> Result<HeaderName, RewriteError> {
    let name = if (1..=MAX_NAME).contains(&text.len()) {
        HeaderName::from_bytes(text.as_bytes()).ok()
    } else {
        None
    };
    name.filter(|name| !side.refuses(name))
        .ok_or_else(|| side.name_error())
}

/// A value of 0 to 4096 bytes: visible ASCII, spaces and tabs, with none of them at either end.
fn value(text: &str) -> Result<HeaderValue, RewriteError> {
    const BAD: RewriteError =
        RewriteError("a field value is over 4096 bytes or has a character that is not allowed");
    let bytes = text.as_bytes();
    let blank = |b: &u8| matches!(b, b' ' | b'\t');
    let ok = bytes.len() <= MAX_VALUE
        && bytes
            .iter()
            .all(|&b| matches!(b, 0x21..=0x7e | b' ' | b'\t'))
        && !bytes.first().is_some_and(blank)
        && !bytes.last().is_some_and(blank);
    if !ok {
        return Err(BAD);
    }
    HeaderValue::from_str(text).map_err(|_| BAD)
}

fn pairs(
    side: Side,
    list: &[(String, String)],
) -> Result<Vec<(HeaderName, HeaderValue)>, RewriteError> {
    list.iter()
        .map(|(text, v)| Ok((name(side, text)?, value(v)?)))
        .collect()
}

/// The field edits of one route for one message. The default makes none.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Headers {
    remove: Vec<HeaderName>,
    set: Vec<(HeaderName, HeaderValue)>,
    add: Vec<(HeaderName, HeaderValue)>,
}

impl Headers {
    /// The edits of the request: names to take out, and the `name` and `value` pairs to set and to add.
    pub fn request(
        remove: Vec<String>,
        set: Vec<(String, String)>,
        add: Vec<(String, String)>,
    ) -> Result<Headers, RewriteError> {
        Headers::new(Side::Request, remove, set, add)
    }

    /// The same for the response.
    pub fn response(
        remove: Vec<String>,
        set: Vec<(String, String)>,
        add: Vec<(String, String)>,
    ) -> Result<Headers, RewriteError> {
        Headers::new(Side::Response, remove, set, add)
    }

    fn new(
        side: Side,
        remove: Vec<String>,
        set: Vec<(String, String)>,
        add: Vec<(String, String)>,
    ) -> Result<Headers, RewriteError> {
        if remove.len() + set.len() + add.len() > MAX_ITEMS {
            return Err(RewriteError("the field edits have more than 32 items"));
        }
        let remove = remove
            .iter()
            .map(|text| name(side, text))
            .collect::<Result<Vec<_>, _>>()?;
        let (set, add) = (pairs(side, &set)?, pairs(side, &add)?);
        let mut names = BTreeSet::new();
        let all = remove
            .iter()
            .chain(set.iter().chain(&add).map(|(name, _)| name));
        for name in all {
            if !names.insert(name.as_str()) {
                return Err(RewriteError("a field name is edited more than once"));
            }
        }
        Ok(Headers { remove, set, add })
    }

    /// Makes the edits.
    pub(super) fn apply(&self, fields: &mut HeaderMap) {
        for name in &self.remove {
            fields.remove(name);
        }
        for (name, value) in &self.set {
            fields.insert(name.clone(), value.clone());
        }
        for (name, value) in &self.add {
            fields.append(name.clone(), value.clone());
        }
    }
}
