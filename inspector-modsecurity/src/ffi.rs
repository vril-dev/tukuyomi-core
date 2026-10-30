//! The calls into the C++ bridge (`bridge.cc`): the only code of this crate that may be unsafe.
//!
//! The bridge is a few functions with C linkage that never throw. Each handle is owned by one safe
//! type that frees it when it is dropped. The handles are neither `Send` nor `Sync`: libmodsecurity
//! is not known to be safe to share between threads, and the inspector runs on one thread. An
//! error is one of a few fixed values: the text that libmodsecurity gives holds the paths of the
//! rules, and is never passed on.

use std::ffi::{CStr, CString};
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr::NonNull;

use libc::{c_char, c_int};

/// The handles are opaque to Rust.
#[repr(C)]
struct RawEngine {
    _opaque: [u8; 0],
}

#[repr(C)]
struct RawRules {
    _opaque: [u8; 0],
}

// The codes that `tkv_rules_add_file` returns.
const ADDED: c_int = 0;
const REFUSED: c_int = 1;

unsafe extern "C" {
    fn tkv_engine_version() -> *const c_char;
    fn tkv_engine_new() -> *mut RawEngine;
    fn tkv_engine_free(engine: *mut RawEngine);
    fn tkv_rules_new() -> *mut RawRules;
    fn tkv_rules_add_file(rules: *mut RawRules, path: *const c_char) -> c_int;
    fn tkv_rules_free(rules: *mut RawRules);
}

/// A failure of the library. It says what failed and nothing of the paths or the rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// An object could not be made.
    Create,
    /// The path of a rules file holds a NUL byte.
    Path,
    /// The library refused the rules file: it could not be read, or a rule in it is wrong.
    Rules,
    /// Any other failure.
    Internal,
}

impl Error {
    pub fn text(self) -> &'static str {
        match self {
            Error::Create => "the engine library could not make an object",
            Error::Path => "the path of the rules file holds a NUL byte",
            Error::Rules => "the engine library refused the rules file",
            Error::Internal => "the engine library failed",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.text())
    }
}

impl std::error::Error for Error {}

/// The version of the libmodsecurity headers the bridge was built with, for example `3.0.17`.
pub fn engine_version() -> Result<&'static str, Error> {
    // SAFETY: the bridge returns a pointer to a string literal, which lives for the whole process.
    let p = unsafe { tkv_engine_version() };
    if p.is_null() {
        return Err(Error::Internal);
    }
    // SAFETY: `p` is not null and points to a NUL-terminated literal.
    unsafe { CStr::from_ptr(p) }
        .to_str()
        .map_err(|_| Error::Internal)
}

/// The ModSecurity object. It has a log callback that writes nothing.
pub struct Engine {
    raw: NonNull<RawEngine>,
}

impl Engine {
    pub fn new() -> Result<Engine, Error> {
        // SAFETY: the bridge takes no argument and returns a new object or null.
        let raw = unsafe { tkv_engine_new() };
        NonNull::new(raw)
            .map(|raw| Engine { raw })
            .ok_or(Error::Create)
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // SAFETY: `raw` came from `tkv_engine_new` and is freed only here.
        unsafe { tkv_engine_free(self.raw.as_ptr()) }
    }
}

/// A set of rules, to which rules files are added by path.
pub struct Rules {
    raw: NonNull<RawRules>,
}

impl Rules {
    pub fn new() -> Result<Rules, Error> {
        // SAFETY: the bridge takes no argument and returns a new object or null.
        let raw = unsafe { tkv_rules_new() };
        NonNull::new(raw)
            .map(|raw| Rules { raw })
            .ok_or(Error::Create)
    }

    /// Adds the rules of the file at `path`. A failure leaves the set in a state that must not be
    /// used: the caller drops it.
    pub fn add_file(&mut self, path: &Path) -> Result<(), Error> {
        let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| Error::Path)?;
        // SAFETY: `raw` is a live set and `path` is a NUL-terminated string that outlives the call.
        match unsafe { tkv_rules_add_file(self.raw.as_ptr(), path.as_ptr()) } {
            ADDED => Ok(()),
            REFUSED => Err(Error::Rules),
            _ => Err(Error::Internal),
        }
    }
}

impl Drop for Rules {
    fn drop(&mut self) {
        // SAFETY: `raw` came from `tkv_rules_new` and is freed only here.
        unsafe { tkv_rules_free(self.raw.as_ptr()) }
    }
}

#[cfg(test)]
mod tests;
