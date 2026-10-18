//! A rule bundle: the form of its paths, its limits, the manifest that lists it and its fingerprint.
//!
//! A bundle is a set of files (the rule files in the order they are loaded, and the data files that rules read)
//! below one root. `manifest.json` in the root lists every file with its size and SHA-256 and names the rule files
//! in the order they are loaded. The fingerprint of the bundle is the SHA-256 of the bytes of the manifest, so it
//! covers every file, every path, the order, the load list and the mode. It names a generation in the rules store.
//!
//! A bundle has a mode. A bundle in `Block` mode stops a request that a rule blocks. A bundle in `Detect` mode lets
//! the request through, and the inspector reports the rule that would have blocked it. The manifest of a `Block`
//! bundle is version 1, and that of a `Detect` bundle is version 2, which has the key `mode`.
//!
//! The manifest has one form for each mode, which `Manifest::encode` writes by hand and does not take from a
//! serializer: the keys in the order `version`, `mode` (version 2 only, always `"detect"`), `files`, `load` (`path`,
//! `size`, `sha256` in a file), no white space, strings between quotes without any escape (a path and a hexadecimal
//! digest hold no character that needs one), numbers in decimal, one newline at the end. `Manifest::parse` reads a
//! manifest with a loose decoder, writes what it read in that form again and requires the very bytes that were read,
//! so every other spelling of the same values is refused. The Go inspector reads and checks a bundle the same way,
//! and both sides are tested against the same golden files (`inspector/testdata/manifest-v1-golden.json` and
//! `manifest-v2-golden.json`).

use std::collections::BTreeSet;

use serde::Deserialize;
use sha2::{Digest, Sha256};

/// The name of the manifest in the root of a bundle.
pub const MANIFEST_NAME: &str = "manifest.json";
/// The most files in a bundle. The limits here stop mistakes and load; they are not tuning values.
pub const MAX_FILES: usize = 128;
/// The largest file of a bundle in bytes.
pub const MAX_FILE_BYTES: u64 = 2 << 20;
/// The most bytes that the files of a bundle add up to.
pub const MAX_BUNDLE_BYTES: u64 = 8 << 20;
/// The largest manifest in bytes.
pub const MAX_MANIFEST_BYTES: u64 = 64 << 10;
const MAX_PATH_BYTES: usize = 255;
const MAX_PATH_PARTS: usize = 4;
const MAX_PART_BYTES: usize = 128;

fn digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// The fingerprint of a rule bundle: the SHA-256 of the bytes of its manifest.json. It names a generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// Reads a fingerprint written as exactly 64 lowercase hexadecimal digits and nothing else: no sign, no
    /// space, no newline, no uppercase digit.
    pub fn from_hex(text: &[u8]) -> Option<Fingerprint> {
        if text.len() != 64 {
            return None;
        }
        let mut out = [0; 32];
        for (byte, pair) in out.iter_mut().zip(text.chunks_exact(2)) {
            *byte = digit(pair[0])? << 4 | digit(pair[1])?;
        }
        Some(Fingerprint(out))
    }

    /// The fingerprint of the bundle whose manifest is `manifest`.
    pub fn of(manifest: &[u8]) -> Fingerprint {
        Fingerprint(sha256(manifest))
    }

    /// The 64 lowercase hexadecimal digits of the fingerprint.
    pub fn hex(&self) -> String {
        hex(&self.0)
    }

    /// The 32 bytes of the fingerprint.
    pub fn bytes(&self) -> [u8; 32] {
        self.0
    }
}

/// Why a bundle or a manifest was refused: a fixed English sentence, never a path or a value read from a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BundleError(pub &'static str);

/// What the rules of a bundle do to a request they match: `Block` stops it, `Detect` lets it through and has the
/// match reported.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    #[default]
    Block,
    Detect,
}

impl Mode {
    /// The word for the records and the listing.
    pub fn name(self) -> &'static str {
        match self {
            Mode::Block => "block",
            Mode::Detect => "detect",
        }
    }
}

/// The path of a file in a bundle: relative, 1 to 4 components separated by `/`, each of 1 to 128 characters from
/// `A-Z a-z 0-9 . _ -` that does not start with `.`, at most 255 bytes in all, and not `manifest.json`. Letters
/// are case sensitive, and the paths are ordered by their bytes.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BundlePath(String);

impl BundlePath {
    pub fn parse(text: &str) -> Option<BundlePath> {
        if text.is_empty() || text.len() > MAX_PATH_BYTES || text == MANIFEST_NAME {
            return None;
        }
        let mut parts = 0;
        for part in text.split('/') {
            parts += 1;
            if parts > MAX_PATH_PARTS || !part_ok(part) {
                return None;
            }
        }
        Some(BundlePath(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The directories above the file, shortest first: `a/b/c` has `a` and `a/b`.
    pub fn parents(&self) -> impl Iterator<Item = &str> {
        self.0.match_indices('/').map(|(end, _)| &self.0[..end])
    }
}

fn part_ok(part: &str) -> bool {
    (1..=MAX_PART_BYTES).contains(&part.len())
        && !part.starts_with('.')
        && part
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// One file of a bundle as the manifest lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub path: BundlePath,
    pub size: u64,
    pub sha256: [u8; 32],
}

/// The content of `manifest.json`: version 1 for the mode `Block`, version 2 for the mode `Detect`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    mode: Mode,
    files: Vec<Entry>,
    load: Vec<BundlePath>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    version: u64,
    mode: Option<String>,
    files: Vec<RawEntry>,
    load: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEntry {
    path: String,
    size: u64,
    sha256: String,
}

impl Manifest {
    /// A manifest of `files`, which must be in strictly increasing order of their paths, and of the rule files
    /// that are `load`ed in this order, for the rules of the given `mode`. Every limit of a bundle is checked here
    /// except the size of the encoded manifest, which `Bundle::new` and `parse` check.
    pub fn new(
        mode: Mode,
        files: Vec<Entry>,
        load: Vec<BundlePath>,
    ) -> Result<Manifest, BundleError> {
        if files.is_empty() {
            return Err(BundleError("the bundle has no files"));
        }
        if files.len() > MAX_FILES {
            return Err(BundleError("the bundle has more than 128 files"));
        }
        let mut total = 0u64;
        for (i, file) in files.iter().enumerate() {
            if i > 0 && files[i - 1].path >= file.path {
                return Err(BundleError(
                    "the paths are not in strictly increasing byte order",
                ));
            }
            if file.size > MAX_FILE_BYTES {
                return Err(BundleError("a file of the bundle is over 2 MiB"));
            }
            total = total.saturating_add(file.size);
            if total > MAX_BUNDLE_BYTES {
                return Err(BundleError("the files of the bundle add up to over 8 MiB"));
            }
        }
        if load.is_empty() {
            return Err(BundleError("the bundle loads no rule file"));
        }
        let mut seen = BTreeSet::new();
        for path in &load {
            if files.binary_search_by(|f| f.path.cmp(path)).is_err() {
                return Err(BundleError("load names a path that is not in files"));
            }
            if !seen.insert(path) {
                return Err(BundleError("load names a path twice"));
            }
        }
        Ok(Manifest { mode, files, load })
    }

    /// What the rules of the bundle do to a request they match.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// The files of the bundle in the order of their paths.
    pub fn files(&self) -> &[Entry] {
        &self.files
    }

    /// The rule files in the order they are loaded.
    pub fn load(&self) -> &[BundlePath] {
        &self.load
    }

    /// The bytes of `manifest.json`: the one form.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = String::from(match self.mode {
            Mode::Block => r#"{"version":1,"files":["#,
            Mode::Detect => r#"{"version":2,"mode":"detect","files":["#,
        });
        for (i, file) in self.files.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(r#"{"path":""#);
            out.push_str(file.path.as_str());
            out.push_str(r#"","size":"#);
            out.push_str(&file.size.to_string());
            out.push_str(r#","sha256":""#);
            out.push_str(&hex(&file.sha256));
            out.push_str(r#""}"#);
        }
        out.push_str(r#"],"load":["#);
        for (i, path) in self.load.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push('"');
            out.push_str(path.as_str());
            out.push('"');
        }
        out.push_str("]}\n");
        out.into_bytes()
    }

    /// Reads the bytes of a `manifest.json`: only the form that `encode` writes, with the values of a bundle that
    /// pass `new`, and not over 64 KiB.
    pub fn parse(bytes: &[u8]) -> Result<Manifest, BundleError> {
        const BAD: BundleError =
            BundleError("the manifest is not a manifest of the expected types");
        if u64::try_from(bytes.len()).is_ok_and(|n| n > MAX_MANIFEST_BYTES) {
            return Err(BundleError("the manifest is over 64 KiB"));
        }
        let raw: RawManifest = serde_json::from_slice(bytes).map_err(|_| BAD)?;
        let mode = match (raw.version, raw.mode.as_deref()) {
            (1, None) => Mode::Block,
            (2, Some("detect")) => Mode::Detect,
            (1 | 2, _) => {
                return Err(BundleError(
                    "the mode of the manifest does not fit its version",
                ));
            }
            _ => return Err(BundleError("the version of the manifest is not 1 or 2")),
        };
        let path = |text: &str| BundlePath::parse(text).ok_or(BundleError("a path is malformed"));
        let files = raw
            .files
            .iter()
            .map(|file| {
                let sha256 = Fingerprint::from_hex(file.sha256.as_bytes())
                    .ok_or(BundleError("a sha256 is malformed"))?;
                Ok(Entry {
                    path: path(&file.path)?,
                    size: file.size,
                    sha256: sha256.bytes(),
                })
            })
            .collect::<Result<Vec<_>, BundleError>>()?;
        let load = raw
            .load
            .iter()
            .map(|text| path(text))
            .collect::<Result<Vec<_>, BundleError>>()?;
        let manifest = Manifest::new(mode, files, load)?;
        if manifest.encode() != bytes {
            return Err(BundleError("the manifest is not in the canonical form"));
        }
        Ok(manifest)
    }
}

/// A bundle as a store takes it: the bytes of every file, the manifest that lists them and its fingerprint.
#[derive(Debug)]
pub struct Bundle {
    files: Vec<(BundlePath, Vec<u8>)>,
    manifest: Vec<u8>,
    fingerprint: Fingerprint,
}

impl Bundle {
    /// A bundle of `files`, in any order but each path once, and of the rule files that are `load`ed in this order,
    /// for the rules of the given `mode`.
    pub fn new(
        mode: Mode,
        mut files: Vec<(BundlePath, Vec<u8>)>,
        load: Vec<BundlePath>,
    ) -> Result<Bundle, BundleError> {
        files.sort_by(|a, b| a.0.cmp(&b.0));
        if files.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(BundleError("a path is used twice in the bundle"));
        }
        let entries = files
            .iter()
            .map(|(path, data)| {
                Ok(Entry {
                    path: path.clone(),
                    size: u64::try_from(data.len())
                        .map_err(|_| BundleError("a file of the bundle is over 2 MiB"))?,
                    sha256: sha256(data),
                })
            })
            .collect::<Result<Vec<_>, BundleError>>()?;
        let manifest = Manifest::new(mode, entries, load)?.encode();
        if u64::try_from(manifest.len()).is_ok_and(|n| n > MAX_MANIFEST_BYTES) {
            return Err(BundleError("the manifest of the bundle is over 64 KiB"));
        }
        let fingerprint = Fingerprint::of(&manifest);
        Ok(Bundle {
            files,
            manifest,
            fingerprint,
        })
    }

    /// The files in the order of their paths.
    pub fn files(&self) -> &[(BundlePath, Vec<u8>)] {
        &self.files
    }

    /// The bytes of `manifest.json`.
    pub fn manifest(&self) -> &[u8] {
        &self.manifest
    }

    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }
}

#[cfg(test)]
mod tests;
