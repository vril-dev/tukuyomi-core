//! The `skipAfter` guard, over the rule files in the order they are loaded.
//!
//! A `skipAfter` whose marker does not follow it is no error in libmodsecurity, neither when the rules are
//! read nor in a transaction: the rules of the phase that come after it are skipped silently, and the
//! blocking rules with them. So every `skipAfter` has to name a `SecMarker` that comes later, in the same
//! file or in a later one (never in its own directive). A marker is looked for by its name as the
//! library compares it: byte by byte.
//!
//! It does not know the phase of a rule, so it cannot tell a marker that the rule's phase reaches from one
//! that only another phase has; it only makes sure that a marker comes after.

use std::collections::HashMap;

use super::reader::Reason;

pub(super) const NO_MARKER: Reason = "skipAfter names no marker after it";

struct Use {
    name: String,
    file: String,
    at: usize,
}

/// The markers and the `skipAfter` names seen so far. A position is the number of the directive in the
/// order of load.
#[derive(Default)]
pub(super) struct Markers {
    position: usize,
    /// The position of the last `SecMarker` of each name.
    markers: HashMap<String, usize>,
    uses: Vec<Use>,
}

impl Markers {
    /// The position of the next directive.
    pub(super) fn next(&mut self) -> usize {
        self.position += 1;
        self.position
    }

    pub(super) fn marker(&mut self, name: &str, at: usize) {
        self.markers.insert(name.to_owned(), at);
    }

    pub(super) fn skip_after(&mut self, name: &str, file: &str, at: usize) {
        self.uses.push(Use {
            name: name.to_owned(),
            file: file.to_owned(),
            at,
        });
    }

    /// The first `skipAfter` with no marker after it: the file it is in, and the reason.
    pub(super) fn finish(&self) -> Result<(), (&str, Reason)> {
        for u in &self.uses {
            if self
                .markers
                .get(&u.name)
                .is_none_or(|&marker| marker <= u.at)
            {
                return Err((&u.file, NO_MARKER));
            }
        }
        Ok(())
    }
}
