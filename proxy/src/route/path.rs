//! The path of a rule, and the target of a request.

use std::borrow::Cow;

use super::rule::RouteError;

const MAX_PATH_BYTES: usize = 255;

/// Whether `path` (a target up to the first `?`, or the path of a rule) can be read in more than one way. It
/// can if it has a backslash or a semicolon, `//`, a segment that is `.` or `..`, or the escape of a dot, a slash,
/// a backslash, a NUL byte or a percent sign (`%2e`, `%2f`, `%5c`, `%00`, `%25`, in any case). The escape of a
/// percent sign is there because an application that decodes the path twice turns `%252e` into a dot.
pub(super) fn ambiguous(path: &[u8]) -> bool {
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

/// The value of a hexadecimal digit.
fn hex(digit: u8) -> Option<u8> {
    char::from(digit)
        .to_digit(16)
        .and_then(|value| u8::try_from(value).ok())
}

/// A byte that the canonical form writes as it is when the path has its escape: one that the path of a rule holds as
/// it is, except `%`, whose escape is ambiguous.
fn literal(b: u8) -> bool {
    b != b'%' && path_byte(b)
}

/// A byte that a request may hold in its path as it is and that the path of a rule may not (a backslash and a
/// semicolon are the others, and they make a path ambiguous): the only spelling of it in a rule is its escape.
fn only_escaped(b: u8) -> bool {
    matches!(b, b'"' | b'[' | b']' | b'^' | b'{' | b'|' | b'}')
}

/// The escape of a byte, with uppercase digits.
fn escape(b: u8) -> [u8; 3] {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    [
        b'%',
        DIGITS[usize::from(b >> 4)],
        DIGITS[usize::from(b & 0x0f)],
    ]
}

/// `path` with each `%` that is followed by two hexadecimal digits written one way: as the byte it stands for if
/// that is a `literal` one (`%61` is `a`), and otherwise with uppercase digits (`%e3` is `%E3`), and each byte that is
/// `only_escaped` written as its escape (`[` is `%5B`). A `%` that is not followed by two digits and every other byte
/// are kept, and so is the case of letters. `None` if `path` is ambiguous.
fn respell(path: &[u8]) -> Option<Cow<'_, [u8]>> {
    if ambiguous(path) {
        return None;
    }
    if !path.iter().any(|&b| b == b'%' || only_escaped(b)) {
        return Some(Cow::Borrowed(path));
    }
    let mut out = Vec::with_capacity(path.len());
    let mut rest = path;
    while let Some((&b, tail)) = rest.split_first() {
        if let (b'%', [high, low, after @ ..]) = (b, tail)
            && let (Some(h), Some(l)) = (hex(*high), hex(*low))
        {
            let value = (h << 4) | l;
            if literal(value) {
                out.push(value);
            } else {
                out.extend([b'%', high.to_ascii_uppercase(), low.to_ascii_uppercase()]);
            }
            rest = after;
        } else {
            if only_escaped(b) {
                out.extend(escape(b));
            } else {
                out.push(b);
            }
            rest = tail;
        }
    }
    Some(Cow::Owned(out))
}

/// The canonical form of `path` (a target up to the first `?`, or the path of a rule): the one spelling for all the
/// spellings that an application behind the proxy may read as the same path (see `respell`). It is not ambiguous,
/// it holds no byte that is `only_escaped`, and it is its own canonical form. There is none for a path that is
/// ambiguous, nor for one whose respelling is not final: a `%` that is not the start of an escape can become one when
/// the escapes after it are replaced (`%2%65` gives `%2e`, `%%34%31` gives `%41`), and an application that decodes
/// twice reads those as another path.
pub(super) fn canonical(path: &[u8]) -> Option<Cow<'_, [u8]>> {
    let once = respell(path)?;
    if once.as_ref() != path && respell(&once)?.as_ref() != once.as_ref() {
        return None;
    }
    Some(once)
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

    /// The canonical form of the path, if it has one.
    pub(super) fn canonical(&self) -> Option<Cow<'a, [u8]>> {
        canonical(self.path)
    }

    /// Whether the path is `other`.
    pub(super) fn path_is(&self, other: &[u8]) -> bool {
        self.path == other
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

    /// Whether the path is its own canonical form.
    pub(super) fn is_canonical(&self) -> bool {
        canonical(self.0.as_bytes()).is_some_and(|spelt| spelt.as_ref() == self.0.as_bytes())
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
