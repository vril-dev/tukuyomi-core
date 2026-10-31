//! The calls into the C++ bridge (`bridge.cc`): the only code of this crate that may be unsafe.
//!
//! The bridge is a few functions with C linkage that never throw. Each handle is owned by one safe
//! type that frees it when it is dropped. The handles are neither `Send` nor `Sync`: libmodsecurity
//! is not known to be safe to share between threads, and the inspector runs on one thread. An
//! error is one of a few fixed values: the text that libmodsecurity gives holds the paths of the
//! rules, and is never passed on.
//!
//! The parser of libmodsecurity keeps its state in static variables, so two threads must not read
//! rules at the same time. Every call that reads rules holds one lock for its whole duration.

use std::ffi::{CStr, CString};
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::sync::{Mutex, PoisonError};

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

// The codes that `tkv_rules_add_file` and `tkv_rules_add_text` return, and the numbers that
// `tkv_rules_settings` gives for the rule engine and for a setting that was not set.
const ADDED: c_int = 0;
const REFUSED: c_int = 1;
const ENGINE_OFF: c_int = 0;
const ENGINE_DETECTION_ONLY: c_int = 1;
const ENGINE_ON: c_int = 2;
const NOT_SET: c_int = 3;

// What `tkv_rules_check` found.
const FOUND_NOTHING: c_int = 0;
const FOUND_FOREIGN: c_int = 1;
const FOUND_RESERVED_ID: c_int = 2;
const FOUND_EXEC: c_int = 3;
const FOUND_SETENV: c_int = 4;
const FOUND_CTL: c_int = 5;
const FOUND_NO_LOG: c_int = 6;
const FOUND_SETTING: c_int = 7;
const FOUND_OTHER: c_int = 8;

/// Held while the parser of libmodsecurity runs.
static PARSER: Mutex<()> = Mutex::new(());

unsafe extern "C" {
    fn tkv_engine_version() -> *const c_char;
    fn tkv_engine_new() -> *mut RawEngine;
    fn tkv_engine_free(engine: *mut RawEngine);
    fn tkv_rules_new() -> *mut RawRules;
    fn tkv_rules_add_file(rules: *mut RawRules, path: *const c_char) -> c_int;
    fn tkv_rules_add_text(rules: *mut RawRules, text: *const c_char) -> c_int;
    fn tkv_rules_settings(
        rules: *const RawRules,
        engine: *mut c_int,
        body_access: *mut c_int,
        json_depth_set: *mut c_int,
        json_depth: *mut u64,
    ) -> c_int;
    fn tkv_rules_check(
        rules: *mut RawRules,
        files: *const *const c_char,
        count: usize,
        found: *mut c_int,
    ) -> c_int;
    fn tkv_rules_describe(
        rules: *mut RawRules,
        buffer: *mut u8,
        capacity: usize,
        length: *mut usize,
    ) -> c_int;
    fn tkv_rules_free(rules: *mut RawRules);
}

/// A failure of the library. It says what failed and nothing of the paths or the rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// An object could not be made.
    Create,
    /// The path of a rules file holds a NUL byte.
    Path,
    /// A text of rules holds a NUL byte.
    Text,
    /// The library refused the rules file or the text: it could not be read, or a rule in it is
    /// wrong.
    Rules,
    /// Any other failure.
    Internal,
}

impl Error {
    pub fn text(self) -> &'static str {
        match self {
            Error::Create => "the engine library could not make an object",
            Error::Path => "the path of the rules file holds a NUL byte",
            Error::Text => "the text of rules holds a NUL byte",
            Error::Rules => "the engine library refused the rules",
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

/// The rule engine of a set of rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineState {
    Off,
    DetectionOnly,
    On,
    /// No rule or directive set it.
    NotSet,
}

/// What a set of rules holds about how it reads a request, after the rules were added.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    pub engine: EngineState,
    /// Whether the request body is accessed; `None` when no directive set it.
    pub body_access: Option<bool>,
    /// The depth limit of a JSON body; `None` when no directive set it.
    pub json_depth_limit: Option<u64>,
}

/// What `Rules::check` found in the rules that were built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Finding {
    /// A rule that none of the rule files holds.
    Foreign,
    /// A rule with an id that the inspector keeps for its own rules.
    ReservedId,
    /// An `exec` action.
    Exec,
    /// A `setenv` action.
    SetEnv,
    /// A `ctl` action that is not one of the allowed kinds.
    Ctl,
    /// A rule that stops a request and leaves no message, or a default action that leaves none.
    NoLog,
    /// A limit of the body or of the arguments, an upload or temporary-file setting, or an audit log,
    /// that the rules set.
    Setting,
    /// Anything else that the check does not know: a rule of another kind, or an action that a
    /// directive added to a rule.
    Other,
}

/// A set of rules, to which rules files and texts are added.
///
/// A setting that two additions both set keeps the value of the first addition: the library merges
/// the settings of each addition into the set and does not replace one that is already set. (Inside
/// one file or one text, the later directive wins.)
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
        let _parser = PARSER.lock().unwrap_or_else(PoisonError::into_inner);
        // SAFETY: `raw` is a live set and `path` is a NUL-terminated string that outlives the call.
        match unsafe { tkv_rules_add_file(self.raw.as_ptr(), path.as_ptr()) } {
            ADDED => Ok(()),
            REFUSED => Err(Error::Rules),
            _ => Err(Error::Internal),
        }
    }

    /// Adds the rules in `text`. A failure leaves the set in a state that must not be used: the
    /// caller drops it.
    pub fn add_text(&mut self, text: &str) -> Result<(), Error> {
        let text = CString::new(text).map_err(|_| Error::Text)?;
        let _parser = PARSER.lock().unwrap_or_else(PoisonError::into_inner);
        // SAFETY: `raw` is a live set and `text` is a NUL-terminated string that outlives the call.
        match unsafe { tkv_rules_add_text(self.raw.as_ptr(), text.as_ptr()) } {
            ADDED => Ok(()),
            REFUSED => Err(Error::Rules),
            _ => Err(Error::Internal),
        }
    }

    /// What the set holds about the rule engine, the request body and the depth of a JSON body.
    pub fn settings(&self) -> Result<Settings, Error> {
        let (mut engine, mut body_access, mut depth_set, mut depth) = (0, 0, 0, 0u64);
        // SAFETY: `raw` is a live set and the four pointers point to values that live for the call.
        let code = unsafe {
            tkv_rules_settings(
                self.raw.as_ptr(),
                &mut engine,
                &mut body_access,
                &mut depth_set,
                &mut depth,
            )
        };
        if code != ADDED {
            return Err(Error::Internal);
        }
        let engine = match engine {
            ENGINE_OFF => EngineState::Off,
            ENGINE_DETECTION_ONLY => EngineState::DetectionOnly,
            ENGINE_ON => EngineState::On,
            NOT_SET => EngineState::NotSet,
            _ => return Err(Error::Internal),
        };
        let body_access = match body_access {
            0 => Some(false),
            1 => Some(true),
            NOT_SET => None,
            _ => return Err(Error::Internal),
        };
        Ok(Settings {
            engine,
            body_access,
            json_depth_limit: (depth_set == 1).then_some(depth),
        })
    }

    /// Looks at the rules that were built, and not at the text they came from, for the first thing
    /// that must not be in them: a rule that is not from one of `files` (the paths that were given to
    /// `add_file`), a reserved id, an action that is not allowed, a stop that leaves no message, a
    /// setting that must not be set. `None` when there is nothing.
    pub fn check(&self, files: &[PathBuf]) -> Result<Option<Finding>, Error> {
        let files = files
            .iter()
            .map(|file| CString::new(file.as_os_str().as_bytes()).map_err(|_| Error::Path))
            .collect::<Result<Vec<_>, _>>()?;
        let pointers: Vec<*const c_char> = files.iter().map(|file| file.as_ptr()).collect();
        let mut found = 0;
        // SAFETY: `raw` is a live set, `pointers` holds `pointers.len()` pointers to NUL-terminated
        // strings that live for the call, and `found` is a live integer.
        let code = unsafe {
            tkv_rules_check(
                self.raw.as_ptr(),
                pointers.as_ptr(),
                pointers.len(),
                &mut found,
            )
        };
        if code != ADDED {
            return Err(Error::Internal);
        }
        match found {
            FOUND_NOTHING => Ok(None),
            FOUND_FOREIGN => Ok(Some(Finding::Foreign)),
            FOUND_RESERVED_ID => Ok(Some(Finding::ReservedId)),
            FOUND_EXEC => Ok(Some(Finding::Exec)),
            FOUND_SETENV => Ok(Some(Finding::SetEnv)),
            FOUND_CTL => Ok(Some(Finding::Ctl)),
            FOUND_NO_LOG => Ok(Some(Finding::NoLog)),
            FOUND_SETTING => Ok(Some(Finding::Setting)),
            FOUND_OTHER => Ok(Some(Finding::Other)),
            _ => Err(Error::Internal),
        }
    }
}

impl Rules {
    /// What the library built, as text: every rule of every phase with its actions, the markers, the
    /// default actions and all the settings (see `rules::model`, which writes the same text from what the
    /// rule files say). The text holds the values of the rules, so it is only ever compared, never shown.
    pub fn describe(&self) -> Result<Vec<u8>, Error> {
        let mut length = 0;
        // SAFETY: `raw` is a live set, with no buffer the call only writes `length`, a live integer.
        let code =
            unsafe { tkv_rules_describe(self.raw.as_ptr(), std::ptr::null_mut(), 0, &mut length) };
        if code != ADDED {
            return Err(Error::Internal);
        }
        let mut text = vec![0u8; length];
        let mut written = 0;
        // SAFETY: `raw` is a live set, `text` holds `length` bytes, and `written` is a live integer.
        let code = unsafe {
            tkv_rules_describe(
                self.raw.as_ptr(),
                text.as_mut_ptr(),
                text.len(),
                &mut written,
            )
        };
        if code != ADDED || written != length {
            return Err(Error::Internal);
        }
        Ok(text)
    }
}

impl Drop for Rules {
    fn drop(&mut self) {
        // SAFETY: `raw` came from `tkv_rules_new` and is freed only here.
        unsafe { tkv_rules_free(self.raw.as_ptr()) }
    }
}

#[cfg(test)]
pub(crate) mod tests;
