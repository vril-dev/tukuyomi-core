//! Matching a request to a rule by its `Host` and its path.
//!
//! A rule has a host, a path, both or neither, and a table of rules gives each of them a target. The table of the
//! routes that skip the inspection and the table of the routes that choose an upstream are made of the same parts
//! and match in the same way; they differ in the target and in what a rule may hold (see `Rule::forward` and
//! `Rule::bypass`).
//!
//! The path of a rule starts with `/`. It holds for that path only, or, if it ends in `/`, for every path that
//! starts with it. Its bytes are `A-Z a-z 0-9 - . _ ~ ! $ & ' ( ) * + , = : @ / %`, and every `%` is followed by two
//! hexadecimal digits. A path that can be read in more than one way is refused (see `ambiguous`).
//!
//! The host of a rule is 1 to 253 bytes: lowercase ASCII letters, digits, `-` and `.`, not ending in `.`, and then,
//! if wanted, `:` and a port from 1 to 65535 without a leading zero. A rule without a port holds for every port of
//! the request, and a rule with one for that port only. A forwarding rule may also start with `*.`, which holds for
//! every name of one label or more in front of the rest, but not for the rest alone.
//!
//! A request is matched by the value of its `Host` field and by its target up to the first `?`. The comparison is
//! made on the bytes of the target as they were received and as they will be forwarded: nothing is decoded or cleaned
//! first, and letters of the path are compared with their case. The case of the host is ignored, and one `.` at the end
//! of its name is dropped (`app.test.` is `app.test`), but not for a rule that lets a request through without
//! inspection: that rule does not hold for such a name, because the upstream gets the `Host` as it was written and may
//! take `app.test.` for another host than `app.test`, so the request is inspected. A `Host` value that cannot be
//! read as a name and an optional port, or whose name has an empty label (`app..test`, `.app.test`, `app.test..`),
//! holds for no rule that has a host. A target that is ambiguous in the sense of the path holds for no rule that has
//! a path, so that it is inspected, and it is not routed by a path.
//!
//! Of the rules that hold, the table gives the target of the one that is the most exact: the host decides first (a
//! name before a wildcard, the longer wildcard before the shorter, a rule with a port before one without, a rule with
//! a host before one without), and then the path (the path itself before a prefix, the longer prefix before the
//! shorter, a rule with a path before one without).

mod host;
mod path;
mod rule;
mod table;

pub use rule::{RouteError, Rule};
pub use table::Table;

#[cfg(test)]
mod tests;
