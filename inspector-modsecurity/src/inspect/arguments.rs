//! How many arguments a request has, counted the way the other rule engine of this product counts them, so that
//! the same requests are blocked for having too many.
//!
//! The library keeps every argument it is given. The limit is the inspector's: more than `LIMIT` arguments of one
//! kind is a block, and exactly `LIMIT` is not. Each kind has its own count:
//!
//! - the arguments of the query: the parts of the query between `&` that are not empty;
//! - the arguments of a URL-encoded body: counted the same way;
//! - the values of a JSON body: every value that is not an object or an array, and separately the arrays that
//!   are not empty, each of which adds one entry for its length;
//! - a multipart body is not counted: its fields are not subject to the limit.
//!
//! A JSON body that does not parse is counted as far as it parses; the library reports the failure on its own.
#![forbid(unsafe_code)]

use std::fmt;

use serde::de::{
    DeserializeSeed, Deserializer, Error as _, IgnoredAny, MapAccess, SeqAccess, Visitor,
};

/// The most arguments of one kind that a request may have.
pub(super) const LIMIT: usize = 1000;

/// The arguments of a query or of a URL-encoded body, counted as the parts between `&` that are not empty. A body
/// comes in pieces, and the count goes on across them.
#[derive(Default)]
pub(super) struct Parts {
    count: usize,
    inside: bool,
}

impl Parts {
    pub(super) fn feed(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            if byte == b'&' {
                self.inside = false;
            } else if !self.inside {
                self.inside = true;
                self.count = self.count.saturating_add(1);
            }
        }
    }

    pub(super) fn over(&self) -> bool {
        self.count > LIMIT
    }
}

#[derive(Default)]
struct Counts {
    values: usize,
    arrays: usize,
    over: bool,
}

/// Walks a JSON document and counts. It stops with an error as soon as the limit is passed, and the error carries
/// no message: it only unwinds the walk.
struct Walk<'a>(&'a mut Counts);

impl Walk<'_> {
    fn value<E>(self) -> Result<(), E> {
        self.0.values += 1;
        Ok(())
    }
}

impl<'de> DeserializeSeed<'de> for Walk<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        // Meeting another value or container once the values are at the limit is the one too many.
        if self.0.values >= LIMIT {
            self.0.over = true;
            return Err(D::Error::custom("too many values"));
        }
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Walk<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<(), E> {
        self.value()
    }

    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<(), E> {
        self.value()
    }

    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<(), E> {
        self.value()
    }

    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<(), E> {
        self.value()
    }

    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<(), E> {
        self.value()
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<(), E> {
        self.value()
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        let mut elements = 0usize;
        while seq.next_element_seed(Walk(&mut *self.0))?.is_some() {
            elements += 1;
        }
        // An array that is not empty adds one entry, for its length, to a count of its own.
        if elements > 0 {
            if self.0.arrays >= LIMIT {
                self.0.over = true;
                return Err(A::Error::custom("too many arrays"));
            }
            self.0.arrays += 1;
        }
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while map.next_key::<IgnoredAny>()?.is_some() {
            map.next_value_seed(Walk(&mut *self.0))?;
        }
        Ok(())
    }
}

/// Whether a JSON body has more values, or more arrays, than the limit.
pub(super) fn json_over(body: &[u8]) -> bool {
    let mut counts = Counts::default();
    let mut json = serde_json::Deserializer::from_slice(body);
    // A body that does not parse ends the walk with an error: what was counted until then is what there is.
    let _ = Walk(&mut counts).deserialize(&mut json);
    counts.over
}
