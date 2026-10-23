//! The query edits of a route: items taken out, and items put at the end.
//!
//! The query is what follows the first `?` of the target, read as items between `&` (nothing else separates items;
//! `;` does not) and, in each item, a name up to the first `=` (the whole item if there is none). A `?` that ends the
//! target has no items. To tell whether an item is taken out, its name is decoded for the comparison only: `+` is a
//! space and `%` and two hexadecimal digits are that byte; any other `%` stays. An item is taken out if its name is
//! one of `remove`, starts with one of `remove_prefixes`, or is a name of `set`, and the case of ASCII letters does
//! not matter. A name that is one of those and then a `[` (`debug[]`, `debug[x]`) is that name too, for some
//! applications read it as an array of that name. Other ways that some applications fold names (a blank in front,
//! a `.` for a `_`) are not looked at. Every item that stays keeps its bytes and its place, an empty one included.
//! Then the items of `set` and those of `add` are put at the end, in this order, as `name=value`, each after a `&`.
//!
//! If nothing is taken out and nothing is put in, the target stays as it was, a `?` that ends it included. If every
//! item was taken out and none is put in, the `?` goes too.

use std::collections::BTreeSet;

use super::{MAX_ITEMS, RewriteError};

const MAX_NAME: usize = 256;
const MAX_VALUE: usize = 4096;

/// A byte of a name: `A-Z a-z 0-9 - . _ ~`.
fn name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// A byte of a value besides a `%` escape: `A-Z a-z 0-9 - . _ ~ ! $ ' ( ) * , : @ / ?`.
fn value_byte(b: u8) -> bool {
    name_byte(b)
        || matches!(
            b,
            b'!' | b'$' | b'\'' | b'(' | b')' | b'*' | b',' | b':' | b'@' | b'/' | b'?'
        )
}

fn name_ok(name: &str) -> bool {
    (1..=MAX_NAME).contains(&name.len()) && name.bytes().all(name_byte)
}

/// A value of 0 to 4096 bytes, in which every `%` is followed by two hexadecimal digits.
fn value_ok(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() > MAX_VALUE {
        return false;
    }
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        if b == b'%' {
            if !bytes
                .get(i + 1..i + 3)
                .is_some_and(|pair| pair.iter().all(u8::is_ascii_hexdigit))
            {
                return false;
            }
            i += 2;
        } else if !value_byte(b) {
            return false;
        }
        i += 1;
    }
    true
}

/// The value of a hexadecimal digit.
fn hex(digit: u8) -> Option<u8> {
    char::from(digit)
        .to_digit(16)
        .and_then(|value| u8::try_from(value).ok())
}

/// A name for the comparison: `+` as a space, `%` and two hexadecimal digits as their byte.
fn decode(name: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len());
    let mut i = 0;
    while let Some(&b) = name.get(i) {
        match (b, name.get(i + 1..i + 3)) {
            (b'+', _) => out.push(b' '),
            (b'%', Some(&[high, low])) => match (hex(high), hex(low)) {
                (Some(high), Some(low)) => {
                    out.push((high << 4) | low);
                    i += 2;
                }
                _ => out.push(b),
            },
            _ => out.push(b),
        }
        i += 1;
    }
    out
}

/// Whether `name` starts with `start`, the case of ASCII letters not mattering.
fn starts_with(name: &[u8], start: &[u8]) -> bool {
    name.get(..start.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(start))
}

/// Whether `name` is `taken`, or `taken` and a `[` and more, the case of ASCII letters not mattering.
fn is_name(name: &[u8], taken: &[u8]) -> bool {
    starts_with(name, taken) && matches!(name.get(taken.len()), None | Some(b'['))
}

/// The query edits of one route. The default makes none.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Query {
    remove: Vec<String>,
    prefixes: Vec<String>,
    set: Vec<(String, String)>,
    add: Vec<(String, String)>,
}

impl Query {
    /// The edits as the configuration gives them: names to take out, name beginnings to take out, and the `name` and
    /// `value` pairs to set and to add. At most 32 items in all; a name is in one of `remove`, `set` and `add` once.
    pub fn new(
        remove: Vec<String>,
        prefixes: Vec<String>,
        set: Vec<(String, String)>,
        add: Vec<(String, String)>,
    ) -> Result<Query, RewriteError> {
        let items = [remove.len(), prefixes.len(), set.len(), add.len()];
        if items.iter().sum::<usize>() > MAX_ITEMS {
            return Err(RewriteError("the query edits have more than 32 items"));
        }
        let mut names = BTreeSet::new();
        let named = remove
            .iter()
            .chain(set.iter().chain(&add).map(|(name, _)| name));
        for name in named {
            if !names.insert(name.to_ascii_lowercase()) {
                return Err(RewriteError("a query name is edited more than once"));
            }
        }
        if !remove.iter().chain(&prefixes).all(|name| name_ok(name))
            || !set.iter().chain(&add).all(|(name, _)| name_ok(name))
        {
            return Err(RewriteError(
                "a query name is not 1 to 256 bytes of letters, digits and - . _ ~",
            ));
        }
        if !set.iter().chain(&add).all(|(_, value)| value_ok(value)) {
            return Err(RewriteError(
                "a query value is over 4096 bytes or has a character that is not allowed",
            ));
        }
        Ok(Query {
            remove,
            prefixes,
            set,
            add,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.remove.is_empty()
            && self.prefixes.is_empty()
            && self.set.is_empty()
            && self.add.is_empty()
    }

    /// Whether the item is taken out.
    fn takes_out(&self, item: &[u8]) -> bool {
        let end = item.iter().position(|&b| b == b'=').unwrap_or(item.len());
        let name = decode(&item[..end]);
        self.remove
            .iter()
            .chain(self.set.iter().map(|(name, _)| name))
            .any(|taken| is_name(&name, taken.as_bytes()))
            || self
                .prefixes
                .iter()
                .any(|prefix| starts_with(&name, prefix.as_bytes()))
    }

    /// The target from its first `?` on (`tail`; nothing if there is no `?`) after the edits, or `None` if they
    /// change nothing.
    pub(super) fn apply(&self, tail: &[u8]) -> Option<Vec<u8>> {
        let items: Vec<&[u8]> = match tail.split_first() {
            Some((b'?', query)) if !query.is_empty() => query.split(|&b| b == b'&').collect(),
            _ => Vec::new(),
        };
        let stay: Vec<&[u8]> = items
            .iter()
            .copied()
            .filter(|item| !self.takes_out(item))
            .collect();
        if stay.len() == items.len() && self.set.is_empty() && self.add.is_empty() {
            return None;
        }
        let put = self.set.iter().chain(&self.add);
        let mut out = Vec::new();
        let mut first = true;
        let mut item = |bytes: &[&[u8]]| {
            out.push(if first { b'?' } else { b'&' });
            first = false;
            bytes.iter().for_each(|part| out.extend_from_slice(part));
        };
        stay.iter().for_each(|&bytes| item(&[bytes]));
        put.for_each(|(name, value)| item(&[name.as_bytes(), b"=", value.as_bytes()]));
        Some(out)
    }
}
