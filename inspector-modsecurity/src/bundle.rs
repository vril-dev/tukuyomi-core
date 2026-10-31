//! The generation: the directory of rules this inspector starts with, and the copy that the rules are built from.
//!
//! A generation is a directory with `manifest.json` and the files that the manifest lists. `Bundle::read` takes it in
//! three steps, and nothing is handed to the engine before the third has ended:
//!
//! 1. `manifest.json` is read. It must be the one canonical form of version 4 for this engine (`Manifest::parse`).
//! 2. Every file that the manifest lists is read, in the order of the manifest: a regular file below the generation,
//!    never a link, of the size and with the sha256 that the manifest gives. Reading never waits on a FIFO.
//! 3. The bytes that were checked are written into one directory of a fixed name (`COPY_DIR`) directly below the
//!    given `TMPDIR`, and every file of the copy is read back and compared with the manifest again. The rules are built
//!    from the copy only. The generation is never read a second time, so replacing it after step 2 changes nothing.
//!
//! The copy is made before the process restricts itself, because no directory can be made after that. The inspector
//! never removes it: the process that started the inspector removes the whole per-start directory.
//!
//! An error is a fixed English sentence with, at most, the path of a file relative to the generation. It never holds an
//! absolute path or a value read from a file. It carries the exit code of the process: `EXIT_RULES` for a generation
//! that cannot be read or is not what its manifest says, `EXIT_STARTUP` for a copy that cannot be made or written.
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

/// The exit code of a start that is refused because of the generation: it cannot be read, a file is not what the
/// manifest says, or the manifest is refused.
pub const EXIT_RULES: i32 = 11;
/// The exit code of a start that is refused because the place of work cannot be used: the copy cannot be made or
/// written.
pub const EXIT_STARTUP: i32 = 14;

/// The name of the directory of the copy, directly below `TMPDIR`.
pub const COPY_DIR: &str = "generation";

const MANIFEST_NAME: &str = "manifest.json";
const VERSION: u64 = 4;
const ENGINE: &str = "modsecurity";

// Limits of a generation. They stop mistakes and load; they are not tuning values. The form of a path is checked here
// whatever wrote the manifest.
const MAX_MANIFEST_BYTES: u64 = 64 << 10;
const MAX_FILES: usize = 128;
const MAX_FILE_BYTES: u64 = 2 << 20;
const MAX_BUNDLE_BYTES: u64 = 8 << 20;
const MAX_PATH_BYTES: usize = 255;
const MAX_PATH_PARTS: usize = 4;
const MAX_PART_BYTES: usize = 128;

// Limits of the routes of a manifest. The host counts the port.
const MAX_ROUTES: usize = 256;
const MAX_ROUTE_PATH_BYTES: usize = 255;
const MAX_ROUTE_HOST_BYTES: usize = 253;
const MAX_PORT: u32 = 65535;

/// Why a generation was refused: the exit code of the start, a fixed sentence, and the path of the file it is about,
/// relative to the generation (a path that the manifest gave and that passed the checks, or `manifest.json`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleError {
    code: i32,
    path: Option<String>,
    text: &'static str,
}

impl BundleError {
    fn rules(text: &'static str) -> BundleError {
        BundleError {
            code: EXIT_RULES,
            path: None,
            text,
        }
    }

    fn rules_at(path: &str, text: &'static str) -> BundleError {
        BundleError {
            code: EXIT_RULES,
            path: Some(path.to_owned()),
            text,
        }
    }

    fn startup(text: &'static str) -> BundleError {
        BundleError {
            code: EXIT_STARTUP,
            path: None,
            text,
        }
    }

    fn startup_at(path: &str, text: &'static str) -> BundleError {
        BundleError {
            code: EXIT_STARTUP,
            path: Some(path.to_owned()),
            text,
        }
    }

    /// The exit code of the start: `EXIT_RULES` or `EXIT_STARTUP`.
    pub fn exit_code(&self) -> i32 {
        self.code
    }

    /// The fixed sentence.
    pub fn text(&self) -> &'static str {
        self.text
    }

    /// The path of the file the error is about, relative to the generation.
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }
}

impl fmt::Display for BundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.path {
            Some(path) => write!(f, "{path}: {}", self.text),
            None => f.write_str(self.text),
        }
    }
}

impl std::error::Error for BundleError {}

/// A generation that `Bundle::read` checked and copied: the root of the copy, the bytes of every file of the manifest
/// by its path in the manifest, the rule files in the order they are loaded, whether the rules only detect, and the
/// fingerprint (the sha256 of the bytes of `manifest.json`).
pub struct Bundle {
    root: PathBuf,
    files: BTreeMap<String, Vec<u8>>,
    load: Vec<String>,
    detect: bool,
    fingerprint: [u8; 32],
}

// The bytes of the rules and the path of the copy stay out of any output that prints a `Bundle`.
impl fmt::Debug for Bundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bundle")
            .field("files", &self.files.len())
            .field("load", &self.load)
            .field("detect", &self.detect)
            .finish_non_exhaustive()
    }
}

impl Bundle {
    /// Reads and checks the generation in `dir`, then copies it into `COPY_DIR` directly below `tmp` (see the
    /// description of this module). `tmp` must be the `TMPDIR` that the process checked; `COPY_DIR` must not be in it
    /// yet.
    pub fn read(dir: &Path, tmp: &Path) -> Result<Bundle, BundleError> {
        match fs::metadata(dir) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => return Err(BundleError::rules("the generation is not a directory")),
            Err(_) => {
                return Err(BundleError::rules(
                    "the directory of the generation cannot be examined",
                ));
            }
        }
        let manifest_bytes = read_file(dir, MANIFEST_NAME, MAX_MANIFEST_BYTES)
            .map_err(|text| BundleError::rules_at(MANIFEST_NAME, text))?;
        let manifest = Manifest::parse(&manifest_bytes)
            .map_err(|text| BundleError::rules_at(MANIFEST_NAME, text))?;
        let mut checked = Vec::with_capacity(manifest.files.len());
        for entry in manifest.files {
            let data = read_file(dir, &entry.path, entry.size)
                .and_then(|data| entry.verify(&data).map(|()| data))
                .map_err(|text| BundleError::rules_at(&entry.path, text))?;
            checked.push((entry, data));
        }
        let root = copy(tmp, &checked)?;
        Ok(Bundle {
            root,
            files: checked
                .into_iter()
                .map(|(entry, data)| (entry.path, data))
                .collect(),
            load: manifest.load,
            detect: manifest.detect,
            fingerprint: Sha256::digest(&manifest_bytes).into(),
        })
    }

    /// The root of the copy: the directory that holds the files at the paths of the manifest.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The checked bytes of every file of the manifest, by its path in the manifest.
    pub fn files(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.files
    }

    /// The rule files in the order they are loaded.
    pub fn load(&self) -> &[String] {
        &self.load
    }

    /// Whether the rules only detect (the mode of the manifest is `detect`).
    pub fn detect(&self) -> bool {
        self.detect
    }

    /// The fingerprint of the generation: the sha256 of the bytes of `manifest.json`.
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    /// Drops the bytes of the files, which the rules need no more once they are built. The copy stays.
    pub fn clear_files(&mut self) {
        self.files = BTreeMap::new();
    }
}

/// One file of a manifest.
#[derive(Debug)]
struct Entry {
    path: String,
    size: u64,
    sha256: [u8; 32],
}

impl Entry {
    /// Whether `data` is the file that the manifest describes.
    fn verify(&self, data: &[u8]) -> Result<(), &'static str> {
        if u64::try_from(data.len()).ok() != Some(self.size) {
            return Err("size differs from the manifest");
        }
        if <[u8; 32]>::from(Sha256::digest(data)) != self.sha256 {
            return Err("sha256 differs from the manifest");
        }
        Ok(())
    }
}

/// A manifest that passed every check: the files in the strict order of their paths, the rule files in the order they
/// are loaded, and whether the rules only detect. The routes are checked and not kept: the proxy matches them.
#[derive(Debug)]
struct Manifest {
    files: Vec<Entry>,
    load: Vec<String>,
    detect: bool,
}

/// `manifest.json` as it is decoded. The decoding is loose; `parse` writes what it read in the one canonical form and
/// requires the bytes that were read. A manifest of version 1 to 3 has no `engine` and may have no `mode` or `routes`,
/// so these three may be missing here: the manifest is then refused for its version, and one of version 4 that lacks
/// a key is not the bytes that `encode` writes.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    version: u64,
    #[serde(default)]
    engine: String,
    #[serde(default)]
    mode: String,
    files: Vec<RawFile>,
    load: Vec<String>,
    #[serde(default)]
    routes: Vec<RawRoute>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    path: String,
    size: u64,
    sha256: String, // lowercase hex
}

/// A route. An empty host is a route with no host, which the writer leaves the key out for; a `host` that is given and
/// empty is not canonical. The action must be `bypass`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRoute {
    #[serde(default)]
    host: String,
    path: String,
    action: String,
}

impl RawManifest {
    /// The one canonical form: the keys in the order version, engine, mode, files (path, size, sha256 inside a file),
    /// load and routes (host when there is one, path, action); `routes` is written when there is none. No white
    /// space, numbers in decimal, strings between quotes without any escape, and one newline at the end. It does not
    /// use a serializer, so the bytes do not depend on its escaping; the decoder only reads.
    fn encode(&self) -> Vec<u8> {
        let mut out = format!(r#"{{"version":{VERSION},"engine":"{ENGINE}","mode":""#);
        out.push_str(&self.mode);
        out.push_str(r#"","files":["#);
        for (i, file) in self.files.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(r#"{"path":""#);
            out.push_str(&file.path);
            out.push_str(r#"","size":"#);
            out.push_str(&file.size.to_string());
            out.push_str(r#","sha256":""#);
            out.push_str(&file.sha256);
            out.push_str(r#""}"#);
        }
        out.push_str(r#"],"load":["#);
        for (i, path) in self.load.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push('"');
            out.push_str(path);
            out.push('"');
        }
        out.push_str(r#"],"routes":["#);
        for (i, route) in self.routes.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push('{');
            if !route.host.is_empty() {
                out.push_str(r#""host":""#);
                out.push_str(&route.host);
                out.push_str(r#"","#);
            }
            out.push_str(r#""path":""#);
            out.push_str(&route.path);
            out.push_str(r#"","action":""#);
            out.push_str(&route.action);
            out.push_str(r#""}"#);
        }
        out.push_str("]}\n");
        out.into_bytes()
    }

    /// Checks the mode and the routes: the mode is `block` or `detect`, there are at most 256 routes (none is
    /// allowed), each has the action `bypass`, a path and, when it has one, a host in the form the proxy writes, and
    /// no host and path occur twice.
    fn check_routes(&self) -> Result<(), &'static str> {
        if self.mode != "block" && self.mode != "detect" {
            return Err("mode is not block or detect");
        }
        if self.routes.len() > MAX_ROUTES {
            return Err("too many routes");
        }
        let mut seen = BTreeSet::new();
        for route in &self.routes {
            if route.action != "bypass" {
                return Err("the action of a route is not bypass");
            }
            if !valid_route_path(&route.path) {
                return Err("a route path is malformed");
            }
            if !route.host.is_empty() && !valid_route_host(&route.host) {
                return Err("a route host is malformed");
            }
            if !seen.insert((route.host.as_str(), route.path.as_str())) {
                return Err("routes name a host and path twice");
            }
        }
        Ok(())
    }
}

impl Manifest {
    /// Checks the bytes of a `manifest.json`. The decoding is loose (it takes white space, escapes and any spelling
    /// that serde accepts), so the manifest is decoded, written again in the canonical form and required to be the very
    /// bytes that were read; one comparison closes every such spelling. The version and the engine are checked first,
    /// so that the manifest of another engine is refused for that. The values are then checked without trusting the
    /// writer. The errors are fixed sentences that hold no value of the manifest.
    fn parse(bytes: &[u8]) -> Result<Manifest, &'static str> {
        let raw: RawManifest =
            serde_json::from_slice(bytes).map_err(|_| "not a manifest of the expected types")?;
        if raw.version != VERSION || raw.engine != ENGINE {
            return Err("not a manifest of version 4 for the engine of this inspector");
        }
        if raw.encode() != bytes {
            return Err("not in the canonical form");
        }
        if raw.files.is_empty() {
            return Err("no files");
        }
        if raw.files.len() > MAX_FILES {
            return Err("too many files");
        }
        let mut files = Vec::with_capacity(raw.files.len());
        let mut total = 0u64; // each size is at most MAX_FILE_BYTES and there are at most MAX_FILES: no overflow
        for (i, file) in raw.files.iter().enumerate() {
            if !valid_path(&file.path) {
                return Err("a path is malformed");
            }
            if i > 0 && raw.files[i - 1].path >= file.path {
                return Err("paths are not in strictly increasing byte order");
            }
            if file.size > MAX_FILE_BYTES {
                return Err("a size is out of range");
            }
            total += file.size;
            if total > MAX_BUNDLE_BYTES {
                return Err("the sizes add up to more than the limit");
            }
            files.push(Entry {
                path: file.path.clone(),
                size: file.size,
                sha256: parse_sha256(&file.sha256).ok_or("a sha256 is malformed")?,
            });
        }
        if raw.load.is_empty() {
            return Err("load is empty");
        }
        let mut seen = BTreeSet::new();
        for path in &raw.load {
            if files.binary_search_by(|f| f.path.cmp(path)).is_err() {
                return Err("load names a path that is not in files");
            }
            if !seen.insert(path) {
                return Err("load names a path twice");
            }
        }
        raw.check_routes()?;
        Ok(Manifest {
            files,
            load: raw.load,
            detect: raw.mode == "detect",
        })
    }
}

/// The value of a lowercase hexadecimal digit.
fn digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// The 32 bytes of a sha256 written as exactly 64 lowercase hexadecimal digits.
fn parse_sha256(text: &str) -> Option<[u8; 32]> {
    let text = text.as_bytes();
    if text.len() != 64 {
        return None;
    }
    let mut out = [0; 32];
    for (byte, pair) in out.iter_mut().zip(text.chunks_exact(2)) {
        *byte = digit(pair[0])? << 4 | digit(pair[1])?;
    }
    Some(out)
}

/// Whether `c` may stand in a component of a path of a generation.
fn name_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-')
}

/// Whether `p` is a path of a generation: relative, 1 to 4 components separated by `/`, each of 1 to 128 bytes of
/// `name_byte` that does not start with `.`, at most 255 bytes in all, and not `manifest.json`.
fn valid_path(p: &str) -> bool {
    if p.is_empty() || p.len() > MAX_PATH_BYTES || p == MANIFEST_NAME {
        return false;
    }
    let mut parts = 0;
    for part in p.split('/') {
        parts += 1;
        if parts > MAX_PATH_PARTS
            || !(1..=MAX_PART_BYTES).contains(&part.len())
            || part.starts_with('.')
            || !part.bytes().all(name_byte)
        {
            return false;
        }
    }
    true
}

/// Whether `c` may stand in the path of a route, `%` apart.
fn route_path_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"-._~!$&'()*+,=:@/".contains(&c)
}

/// The value of a hexadecimal digit of an escape in a path, where a capital letter is allowed.
fn escape_digit(c: u8) -> Option<u8> {
    digit(c.to_ascii_lowercase())
}

/// Whether `p` is the path of a route: 2 to 255 bytes that start with `/` (`/` alone would bypass everything) and hold
/// only letters, digits and `- . _ ~ ! $ & ' ( ) * + , = : @ / %`, where every `%` is followed by two hex digits
/// (small or capital letters). What can be read in more than one way is refused: an escape of `.`, `/`, a backslash,
/// the zero byte or `%` itself (`%2e %2f %5c %00 %25`, any case; a doubly escaped path can be read once more by the
/// application), a component that is `.` or `..`, and an empty component but the last (`//`).
fn valid_route_path(p: &str) -> bool {
    let b = p.as_bytes();
    if b.len() < 2 || b.len() > MAX_ROUTE_PATH_BYTES || b[0] != b'/' {
        return false;
    }
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'%' {
            if !route_path_byte(b[i]) {
                return false;
            }
            i += 1;
            continue;
        }
        let (Some(&high), Some(&low)) = (b.get(i + 1), b.get(i + 2)) else {
            return false;
        };
        let (Some(high), Some(low)) = (escape_digit(high), escape_digit(low)) else {
            return false;
        };
        if matches!(high << 4 | low, b'.' | b'/' | b'\\' | b'%' | 0) {
            return false;
        }
        i += 3;
    }
    let mut parts = p[1..].split('/').peekable();
    while let Some(part) = parts.next() {
        if part == "." || part == ".." || part.is_empty() && parts.peek().is_some() {
            return false;
        }
    }
    true
}

/// Whether `h` is the host of a route: at most 253 bytes, a name of lowercase ASCII letters, digits, `-` and `.` that
/// is not empty and does not end with `.`, then optionally `:` and a port.
fn valid_route_host(h: &str) -> bool {
    if h.len() > MAX_ROUTE_HOST_BYTES {
        return false;
    }
    let (name, port) = match h.split_once(':') {
        Some((name, port)) => (name, Some(port)),
        None => (h, None),
    };
    !name.is_empty()
        && !name.ends_with('.')
        && name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'.')
        && port.is_none_or(valid_port)
}

/// Whether `s` is a port: 1 to 5 decimal digits, no leading 0, from 1 to 65535.
fn valid_port(s: &str) -> bool {
    if s.is_empty() || s.len() > 5 || s.starts_with('0') || !s.bytes().all(|c| c.is_ascii_digit()) {
        return false;
    }
    s.parse::<u32>().is_ok_and(|n| n <= MAX_PORT) // at most 5 digits: no overflow
}

/// The directories above the file at `path`, shortest first: `a/b/c` has `a` and `a/b`.
fn parents(path: &str) -> impl Iterator<Item = &str> {
    path.match_indices('/').map(|(end, _)| &path[..end])
}

/// The sentence for a file or a directory that cannot be opened.
fn open_text(e: &io::Error) -> &'static str {
    if e.kind() == io::ErrorKind::NotFound {
        "no such file or directory"
    } else {
        "cannot be opened"
    }
}

/// Reads the file `rel` below `root` once: a regular file of at most `limit` bytes that is not a link, in a directory
/// that is not a link, and the bytes read must match the size seen by `fstat`. `rel` is a path of a generation (or
/// `manifest.json`); the sentences hold no path.
///
/// The type is looked at first with `lstat`, so a FIFO or a device is refused without being opened. The open then does
/// not follow a link (`O_NOFOLLOW`), does not wait on a FIFO that was put there in the meantime (`O_NONBLOCK`, which
/// does not affect reads of a regular file) and does not make a terminal the controlling terminal (`O_NOCTTY`); the
/// file that was opened must be the one that `lstat` saw. std has no `openat`, so a directory above the file is
/// checked by `lstat` before the open and may be replaced after it; that takes a process of this user, which could
/// do the same damage without this race.
fn read_file(root: &Path, rel: &str, limit: u64) -> Result<Vec<u8>, &'static str> {
    for parent in parents(rel) {
        match fs::symlink_metadata(root.join(parent)) {
            Ok(meta) if meta.file_type().is_dir() => {}
            Ok(_) => return Err("a directory above it is not a real directory"),
            Err(e) => return Err(open_text(&e)),
        }
    }
    let path = root.join(rel);
    let seen = fs::symlink_metadata(&path).map_err(|e| open_text(&e))?;
    if !seen.file_type().is_file() {
        return Err("not a regular file");
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(&path)
        .map_err(|e| open_text(&e))?;
    let meta = file.metadata().map_err(|_| "cannot be read")?;
    if !meta.is_file() || (meta.dev(), meta.ino()) != (seen.dev(), seen.ino()) {
        return Err("not a regular file");
    }
    if meta.len() > limit {
        return Err("too large");
    }
    let mut data = Vec::new();
    file.take(meta.len().saturating_add(1))
        .read_to_end(&mut data)
        .map_err(|_| "cannot be read")?;
    if u64::try_from(data.len()).ok() != Some(meta.len()) {
        return Err("size changed while reading");
    }
    Ok(data)
}

/// Writes the checked files into `COPY_DIR` directly below `tmp` and returns its path. The directory is made with one
/// `mkdir`, which fails when the name is taken (also by a link), with the directories that the paths need below it,
/// shortest first (mode 0700; never `create_dir_all`), and each file is created with `O_CREAT|O_EXCL|O_NOFOLLOW`,
/// mode 0600, from the bytes already checked. Each file is then read back and compared with the manifest. A copy that
/// cannot be made or written is `EXIT_STARTUP`; a file that does not read back as written is `EXIT_RULES`, like any
/// file that does not match its manifest. Nothing is removed on a failure: the process that started the inspector
/// removes the per-start directory.
fn copy(tmp: &Path, checked: &[(Entry, Vec<u8>)]) -> Result<PathBuf, BundleError> {
    let root = tmp.join(COPY_DIR);
    DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .map_err(|_| BundleError::startup("the directory of the copy cannot be made"))?;
    let mut made = BTreeSet::new();
    for (entry, data) in checked {
        for parent in parents(&entry.path) {
            if made.insert(parent) {
                DirBuilder::new()
                    .mode(0o700)
                    .create(root.join(parent))
                    .map_err(|_| {
                        BundleError::startup_at(parent, "a directory of the copy cannot be made")
                    })?;
            }
        }
        write_new(&root.join(&entry.path), data).map_err(|_| {
            BundleError::startup_at(&entry.path, "a file of the copy cannot be written")
        })?;
    }
    for (entry, _) in checked {
        read_file(&root, &entry.path, entry.size)
            .and_then(|data| entry.verify(&data))
            .map_err(|_| {
                BundleError::rules_at(&entry.path, "the copy differs from the manifest")
            })?;
    }
    Ok(root)
}

/// A new file of mode 0600 with `data`. It fails when the name is taken, also by a link.
fn write_new(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(data)
}

#[cfg(test)]
mod tests;
