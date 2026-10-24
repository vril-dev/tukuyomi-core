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
//! A rule is matched on the bytes received, so a request that is another way to write a request for a rule is not
//! taken for it: an application behind the proxy may read `/priv%61te/x` or `/private/./x` as `/private/x`, which a
//! rule for `/private/` holds for. That does no harm where a rule only chooses an upstream or lets a request through
//! without inspection, but it does where a rule limits who may use a path. `Table::could_hold` gives the targets of
//! the rules that a request could be taken for. If its `Host` can be read and the path of its target has a canonical
//! form, they are the rules that are the most exact for the path as received, for its canonical form, and for its
//! canonical form with a `/` added at the end (unless it ends in one, or the rule for the path as received is for that
//! path itself: the operator wrote a rule for it, and the path with a `/` after it is another one). Otherwise they
//! are every rule whose host holds for the request, whatever its path, and every rule if the `Host` cannot be read.
//!
//! The canonical form of a path is the path with each escape written one way: an escape of a byte that the path of
//! a rule holds as it is becomes that byte (`%61` is `a`), and any other escape has uppercase digits (`%e3` is
//! `%E3`). A byte that a request may hold in its path as it is and the path of a rule may not (`"`, `[`, `]`, `^`,
//! `{`, `|` and `}`) is written as its escape too (`[` is `%5B`), so the raw byte and its escape meet the same rule.
//! The case of letters is not changed. A path that is ambiguous has none, and nor has one whose canonical
//! form would change if it were made again: a `%` that is not the start of an escape can become one when the
//! escapes after it are replaced (`%2%65` gives `%2e`). `Rule::canonical` tells whether the path of a rule is its
//! own canonical form; the path of a rule that is not would not be found by the form that a request is looked up by.
//!
//! Of the rules that hold, the table gives the target of the one that is the most exact: the host decides first (a
//! name before a wildcard, the longer wildcard before the shorter, a rule with a port before one without, a rule with
//! a host before one without), and then the path (the path itself before a prefix, the longer prefix before the
//! shorter, a rule with a path before one without).

mod host;
mod path;
mod rule;
mod table;

pub(crate) use host::{RequestHost, parse_port};
pub use rule::{RouteError, Rule};
pub use table::Table;

#[cfg(test)]
mod tests;
