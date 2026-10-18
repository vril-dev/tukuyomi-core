//! The path of a rule, and the target of a request.

use super::rule::RouteError;

const MAX_PATH_BYTES: usize = 255;

/// Whether `path` (a target up to the first `?`, or the path of a rule) can be read in more than one way. It
/// can if it has a backslash or a semicolon, `//`, a segment that is `.` or `..`, or the escape of a dot, a slash,
/// a backslash, a NUL byte or a percent sign (`%2e`, `%2f`, `%5c`, `%00`, `%25`, in any case). The escape of a
/// percent sign is there because an application that decodes the path twice turns `%252e` into a dot.
fn ambiguous(path: &[u8]) -> bool {
    path.iter().any(|&b| b == b'\\' || b == b';')
        || path.windows(2).any(|pair| pair == b"//")
        || path.windows(3).any(|w| {
            w[0] == b'%'
                && matches!(
                    (w[1], w[2].to_ascii_lowercase()),
                    (b'2', b'e' | b'f' | b'5') | (b'5', b'c') | (b'0', b'0')
                )
        })
        || path
            .split(|&b| b == b'/')
            .any(|segment| segment == b"." || segment == b"..")
}

/// A byte that the path of a rule may hold.
fn path_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'.'
                | b'_'
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
                | b'='
                | b':'
                | b'@'
                | b'/'
                | b'%'
        )
}

/// The target of a request as it is matched: the path (up to the first `?`), and whether the path is ambiguous.
pub(super) struct Target<'a> {
    path: &'a [u8],
    ambiguous: bool,
}

impl<'a> Target<'a> {
    pub(super) fn new(target: &'a [u8]) -> Target<'a> {
        let path = target
            .iter()
            .position(|&b| b == b'?')
            .map_or(target, |end| &target[..end]);
        Target {
            path,
            ambiguous: ambiguous(path),
        }
    }
}

/// How well the path of a rule holds for a target. The variants are in the order of their strength, and a prefix
/// is the stronger the longer it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum PathRank {
    /// The rule has no path, so it holds for every path.
    Any,
    Prefix(usize),
    Exact,
}

/// The path of a rule: that path only, or, if it ends in `/`, every path that starts with it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PathRule(String);

impl PathRule {
    /// `root` allows `/` alone, which holds for every path.
    pub(super) fn new(path: &str, root: bool) -> Result<PathRule, RouteError> {
        let bytes = path.as_bytes();
        if bytes == b"/" && !root {
            return Err(RouteError(
                "a route path of / alone would skip the inspection of every request",
            ));
        }
        let (least, text) = if root {
            (1, "a route path is not 1 to 255 bytes")
        } else {
            (2, "a route path is not 2 to 255 bytes")
        };
        if !(least..=MAX_PATH_BYTES).contains(&bytes.len()) {
            return Err(RouteError(text));
        }
        if bytes[0] != b'/' {
            return Err(RouteError("a route path does not start with /"));
        }
        if !bytes.iter().all(|&b| path_byte(b)) {
            return Err(RouteError(
                "a route path has a character that is not allowed",
            ));
        }
        for (i, &b) in bytes.iter().enumerate() {
            let digits = bytes.get(i + 1..i + 3);
            if b == b'%' && !digits.is_some_and(|pair| pair.iter().all(u8::is_ascii_hexdigit)) {
                return Err(RouteError(
                    "a % in a route path is not followed by two hexadecimal digits",
                ));
            }
        }
        if ambiguous(bytes) {
            return Err(RouteError("a route path can be read in more than one way"));
        }
        Ok(PathRule(path.to_owned()))
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }

    /// How well the rule holds for the target; `None` if it does not, and for every ambiguous target.
    pub(super) fn rank(&self, target: &Target) -> Option<PathRank> {
        if target.ambiguous {
            return None;
        }
        let rule = self.0.as_bytes();
        if rule.ends_with(b"/") {
            target
                .path
                .starts_with(rule)
                .then_some(PathRank::Prefix(rule.len()))
        } else {
            (target.path == rule).then_some(PathRank::Exact)
        }
    }
}
