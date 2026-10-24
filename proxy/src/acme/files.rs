//! The files of the command: the account key, the files of the challenges, and the certificate and key it writes.
//!
//! The account key is read from its file; if there is no such file a key is made and put there with mode 0600
//! (`create_new`). It is written and synced to a file of its own in the same directory (see `Staged`) and then linked
//! to its name, which fails if the name is taken: a file that is there is never replaced, not even through a link, and
//! the file at the name is whole or not there. The file of its own that a stop may leave behind is never read as the
//! key. A file of a challenge is named by the token of the CA, which must be a token (see
//! `inbound::challenge::is_token`) before it is a file name; it is written beside its place and renamed to it, so
//! that a reader never sees half of it, and it is removed when the `Challenges` are dropped, whichever way the order
//! ended.
//!
//! A certificate and its key are written by `install`: both are written to files of their own in the directories of
//! their places and synced first, so that a fault in writing leaves the old files as they were, and then the key is
//! renamed to its place, then the certificate. The key is mode 0600 and the certificate 0644 (less what the umask
//! takes off). A stop between the two renames leaves a key that does not go with the certificate: the proxy refuses
//! to read such a pair and goes on with the one it has, and the next run of the command sees the pair is broken and
//! makes a new one.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use rustls::crypto::aws_lc_rs::default_provider;

use super::Failure;
use super::key::Key;
use crate::inbound::challenge::is_token;
use crate::inbound::transport::tls::{Fault, read_file};

/// The longest account key file in bytes: a key of P-256 in PEM is a few hundred.
const MAX_KEY_FILE: u64 = 64 * 1024;

/// Makes the directory entries of `dir` durable.
fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// A new file of mode 0600 with `data`, synced; it is whole as soon as it is there. It fails if the name is taken, also
/// by a link.
fn create_new(path: &Path, data: &[u8]) -> io::Result<()> {
    // A key file that was half written would be read as the account's, so the data is written under another name.
    Staged::new(path, data, 0o600)?.link()?;
    path.parent().map_or(Ok(()), sync_dir)
}

/// The account key at `path`, which is made there if there is no file.
pub fn account_key(path: &Path) -> Result<Key, Failure> {
    const UNREADABLE: Failure = Failure::Text("the account key file cannot be read");
    match read_file(path, MAX_KEY_FILE) {
        Ok(pem) => return Key::from_pem(&pem),
        Err(Fault::Missing) => {}
        Err(_) => return Err(UNREADABLE),
    }
    let (key, pem) = Key::generate()?;
    match create_new(path, pem.as_bytes()) {
        Ok(()) => Ok(key),
        // Another run made it first: its key is the account's.
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            Key::from_pem(&read_file(path, MAX_KEY_FILE).map_err(|_| UNREADABLE)?)
        }
        Err(_) => Err("the account key file cannot be written".into()),
    }
}

/// A file written beside its place, to be renamed to it; it is removed if it is dropped before that.
struct Staged {
    temp: PathBuf,
    target: PathBuf,
    renamed: bool,
}

impl Staged {
    /// Writes `data` to a new file of mode `mode` next to `target`, and syncs it.
    fn new(target: &Path, data: &[u8], mode: u32) -> io::Result<Staged> {
        let dir = target.parent().ok_or(io::ErrorKind::InvalidInput)?;
        let mut random = [0u8; 8];
        default_provider()
            .secure_random
            .fill(&mut random)
            .map_err(|_| io::Error::other("no random number is available"))?;
        let digits: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let temp = dir.join(format!(".acme-{digits}.tmp"));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temp)?;
        let staged = Staged {
            temp,
            target: target.to_path_buf(),
            renamed: false,
        };
        file.write_all(data)?;
        file.sync_all()?;
        Ok(staged)
    }

    fn rename(&mut self) -> io::Result<()> {
        fs::rename(&self.temp, &self.target)?;
        self.renamed = true;
        Ok(())
    }

    /// Gives the file its place with a hard link, which fails if there is anything at the place, a link included.
    /// The other name is removed when `self` is dropped.
    fn link(&self) -> io::Result<()> {
        fs::hard_link(&self.temp, &self.target)
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        if !self.renamed {
            let _ = fs::remove_file(&self.temp);
        }
    }
}

/// The files of the challenges that were put in place for an order.
pub struct Challenges {
    dir: PathBuf,
    written: Vec<PathBuf>,
}

impl Challenges {
    pub fn new(dir: &Path) -> Challenges {
        Challenges {
            dir: dir.to_path_buf(),
            written: Vec::new(),
        }
    }

    /// Puts `content` in the file named `token`. A token that is not one is refused before any file is made.
    pub fn put(&mut self, token: &str, content: &str) -> Result<(), Failure> {
        if !is_token(token.as_bytes()) {
            return Err("the CA gave a token that is not allowed".into());
        }
        let path = self.dir.join(token);
        // Kept first, so that a file that is half done is removed too.
        self.written.push(path.clone());
        let mut staged = Staged::new(&path, content.as_bytes(), 0o644)
            .map_err(|_| "a file of a challenge cannot be written")?;
        staged
            .rename()
            .and_then(|()| sync_dir(&self.dir))
            .map_err(|_| "a file of a challenge cannot be written".into())
    }
}

impl Drop for Challenges {
    fn drop(&mut self) {
        for path in &self.written {
            let _ = fs::remove_file(path);
        }
    }
}

/// Puts the key and the chain (both PEM) in the places of `key_file` and `cert_file`, as the head of this file says.
pub fn install(cert_file: &Path, key_file: &Path, key: &str, chain: &str) -> Result<(), Failure> {
    const FAILED: Failure = Failure::Text("a certificate or key file cannot be written");
    let mut key = Staged::new(key_file, key.as_bytes(), 0o600).map_err(|_| FAILED)?;
    let mut chain = Staged::new(cert_file, chain.as_bytes(), 0o644).map_err(|_| FAILED)?;
    key.rename().map_err(|_| FAILED)?;
    chain.rename().map_err(|_| FAILED)?;
    for file in [key_file, cert_file] {
        file.parent().map_or(Ok(()), sync_dir).map_err(|_| FAILED)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
