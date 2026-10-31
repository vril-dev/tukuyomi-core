//! The files that a rule may read (the operators that read a file).
//!
//! libmodsecurity looks for the file that such an operator names, in this order: as a path from the
//! working directory, after the expansion of `$VARIABLE`, `~` and `*` (never a command), and as a
//! path from the directory of the rule file. A name that is not a path of the generation could so
//! reach a file of the machine, and a name with a `$`, a `~` or a `*` could reach one that the
//! rules do not name. So the argument has to be made of paths of the generation that are written
//! in the plainest form, and each has to be a file of the generation: as written (found from the
//! working directory, which the build sets to the root of the copy), or with the directory of the rule
//! file in front (found from the directory of the rule file). A name that is a path of the
//! generation but names no file of it is refused, and so is everything with another character, and
//! an address (`https://...`, which the library fetches). A name that is a directory of the generation is
//! refused as well: the library opens a directory without an error and reads nothing from it, and it
//! looks at the path from the working directory first, so it would take the directory for the file.
//!
//! The operators that other parts of the library read files for (`@inspectFile`, `@fuzzyHash`,
//! `@validateDTD`, `@validateSchema`) are refused by the checks of the rules, as are `Include` and
//! the other directives that read a file.

use std::collections::BTreeMap;

use super::reader::Reason;

pub(super) const NOT_IN_GENERATION: Reason =
    "an operator reads a file that is not a file of the generation, named by a plain path";

const MAX_PATH: usize = 255;
const MAX_PART: usize = 128;
const MAX_PARTS: usize = 4;

/// Whether `path` is a path of the generation: 1 to 4 parts separated by `/`, each of 1 to 128 bytes of
/// letters, digits, `.`, `_` and `-` that does not start with a dot, at most 255 bytes in all, and not the
/// manifest.
pub(super) fn is_path(path: &[u8]) -> bool {
    if path.is_empty() || path.len() > MAX_PATH || path == b"manifest.json" {
        return false;
    }
    let mut parts = 0;
    for part in path.split(|b| *b == b'/') {
        parts += 1;
        let plain = part
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if parts > MAX_PARTS
            || part.is_empty()
            || part.len() > MAX_PART
            || part[0] == b'.'
            || !plain
        {
            return false;
        }
    }
    true
}

/// Checks the argument of a file-reading operator of the rule file `rule_file`. `@pmFromFile` and `@pmf`
/// cut the argument at each space (an empty piece is skipped) and read each piece as a file;
/// `@ipMatchFromFile` and `@ipMatchF` read the whole argument as one file.
pub(super) fn check_argument(
    operator: &str,
    argument: &[u8],
    rule_file: &str,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<(), Reason> {
    let pieces: Vec<&[u8]> = if matches!(operator, "pmfromfile" | "pmf") {
        argument
            .split(|b| *b == b' ')
            .filter(|piece| !piece.is_empty())
            .collect()
    } else {
        vec![argument]
    };
    if pieces.is_empty() {
        return Err(NOT_IN_GENERATION);
    }
    let directory = rule_file.rsplit_once('/').map(|(directory, _)| directory);
    for piece in pieces {
        // `is_path` leaves ASCII only.
        let piece = match std::str::from_utf8(piece) {
            Ok(piece) if is_path(piece.as_bytes()) => piece,
            _ => return Err(NOT_IN_GENERATION),
        };
        let found = files.contains_key(piece)
            || directory.is_some_and(|d| files.contains_key(&format!("{d}/{piece}")));
        let is_directory = |name: &str| {
            files.keys().any(|key| {
                key.strip_prefix(name)
                    .is_some_and(|rest| rest.starts_with('/'))
            })
        };
        if !found
            || is_directory(piece)
            || directory.is_some_and(|d| is_directory(&format!("{d}/{piece}")))
        {
            return Err(NOT_IN_GENERATION);
        }
    }
    Ok(())
}
