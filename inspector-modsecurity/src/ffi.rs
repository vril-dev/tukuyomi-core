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
use std::rc::Rc;
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

#[repr(C)]
struct RawTransaction {
    _opaque: [u8; 0],
}

/// One rule that matched, as `tkv_tx_messages` writes it.
#[repr(C)]
#[derive(Clone, Copy)]
struct RawMessage {
    id: i64,
    severity: i32,
    disruptive: i32,
}

// The codes that `tkv_rules_add_file` and `tkv_rules_add_text` return, and the numbers that
// `tkv_rules_settings` gives for the rule engine and for a setting that was not set.
const ADDED: c_int = 0;
const REFUSED: c_int = 1;
const ENGINE_OFF: c_int = 0;
const ENGINE_DETECTION_ONLY: c_int = 1;
const ENGINE_ON: c_int = 2;
const NOT_SET: c_int = 3;

// What `tkv_tx_append_body` returns when the library took fewer bytes than it was given, and the numbers of the
// request body processors.
const SHORT: c_int = 3;
const PROCESSOR_NONE: c_int = 0;
const PROCESSOR_URL_ENCODED: c_int = 1;
const PROCESSOR_MULTIPART: c_int = 2;
const PROCESSOR_JSON: c_int = 3;
const PROCESSOR_OTHER: c_int = 4;

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
    fn tkv_tx_new(
        engine: *mut RawEngine,
        rules: *mut RawRules,
        id: *const c_char,
    ) -> *mut RawTransaction;
    fn tkv_tx_free(tx: *mut RawTransaction);
    fn tkv_tx_connection(
        tx: *mut RawTransaction,
        client: *const c_char,
        client_port: c_int,
        server: *const c_char,
        server_port: c_int,
    ) -> c_int;
    fn tkv_tx_uri(
        tx: *mut RawTransaction,
        uri: *const u8,
        uri_length: usize,
        method: *const c_char,
        version: *const c_char,
    ) -> c_int;
    fn tkv_tx_header(
        tx: *mut RawTransaction,
        name: *const u8,
        name_length: usize,
        value: *const u8,
        value_length: usize,
    ) -> c_int;
    fn tkv_tx_request_headers(tx: *mut RawTransaction) -> c_int;
    fn tkv_tx_set_processor(tx: *mut RawTransaction, processor: c_int) -> c_int;
    fn tkv_tx_append_body(tx: *mut RawTransaction, bytes: *const u8, length: usize) -> c_int;
    fn tkv_tx_request_body(tx: *mut RawTransaction) -> c_int;
    fn tkv_tx_logging(tx: *mut RawTransaction) -> c_int;
    fn tkv_tx_intervention(
        tx: *mut RawTransaction,
        taken: *mut c_int,
        status: *mut c_int,
        redirect: *mut c_int,
    ) -> c_int;
    fn tkv_tx_state(
        tx: *const RawTransaction,
        engine_on: *mut c_int,
        body_access: *mut c_int,
        processor: *mut c_int,
        request_error: *mut c_int,
        processor_error: *mut c_int,
        pcre_limit: *mut c_int,
        pcre_error: *mut c_int,
    ) -> c_int;
    fn tkv_tx_messages(
        tx: *const RawTransaction,
        buffer: *mut RawMessage,
        capacity: usize,
        count: *mut usize,
    ) -> c_int;
    fn tkv_tx_score(
        tx: *mut RawTransaction,
        buffer: *mut u8,
        capacity: usize,
        length: *mut usize,
        present: *mut c_int,
    ) -> c_int;
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
    /// A value of the request holds a NUL byte where the library reads a C string.
    Value,
    /// The library took fewer bytes of the request body than it was given.
    Short,
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
            Error::Value => "a value of the request holds a NUL byte",
            Error::Short => "the engine library took less of the request body than it was given",
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

/// The request body processors that the inspector sets and that the library reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Processor {
    /// No processor: the library parses no body.
    None,
    UrlEncoded,
    Multipart,
    Json,
    /// A processor that a rule put in place and that this build of the library does not parse with (XML). It is
    /// read and never set.
    Other,
}

impl Processor {
    fn number(self) -> c_int {
        match self {
            Processor::None => PROCESSOR_NONE,
            Processor::UrlEncoded => PROCESSOR_URL_ENCODED,
            Processor::Multipart => PROCESSOR_MULTIPART,
            Processor::Json => PROCESSOR_JSON,
            Processor::Other => PROCESSOR_OTHER,
        }
    }

    fn from_number(number: c_int) -> Option<Processor> {
        match number {
            PROCESSOR_NONE => Some(Processor::None),
            PROCESSOR_URL_ENCODED => Some(Processor::UrlEncoded),
            PROCESSOR_MULTIPART => Some(Processor::Multipart),
            PROCESSOR_JSON => Some(Processor::Json),
            PROCESSOR_OTHER => Some(Processor::Other),
            _ => None,
        }
    }
}

/// What a transaction holds that has to be known before a request is let through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionState {
    /// The rule engine of this transaction is on (a rule can change it for one transaction).
    pub engine_on: bool,
    /// The request body is read, so the rules of phase 2 run on it.
    pub body_access: bool,
    /// The processor that would parse the request body now.
    pub processor: Processor,
    /// The flag `REQBODY_ERROR` is set.
    pub request_error: bool,
    /// The flag `REQBODY_PROCESSOR_ERROR` is set.
    pub processor_error: bool,
    /// The flag `MSC_PCRE_LIMITS_EXCEEDED` is set: a regular expression gave up, and the library took its rule
    /// as not matched.
    pub pcre_limit: bool,
    /// The flag `MSC_PCRE_ERROR` is set: a regular expression failed for any reason, which includes giving up, and
    /// the library took its rule as not matched.
    pub pcre_error: bool,
}

/// A rule that matched and was logged. The library keeps no other, so a rule with `nolog` is not among them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Message {
    pub id: i64,
    /// The severity of the rule; `None` when the rule has none.
    pub severity: Option<i32>,
    /// The rule stopped the request: a deny, a drop or a redirect ran in it.
    pub disruptive: bool,
}

/// What the rules left to stop the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Intervention {
    /// The status the rule gave.
    pub status: i32,
    /// It is a redirect.
    pub redirect: bool,
}

/// One request in the library. It holds the engine and the rules it was made with, which the library keeps
/// pointers to for as long as the transaction lives, so they are freed after it and never before.
pub struct EngineTransaction {
    raw: NonNull<RawTransaction>,
    _engine: Rc<Engine>,
    _rules: Rc<Rules>,
}

/// How many bytes of the anomaly score are read. A real score is a few digits.
const SCORE_CAPACITY: usize = 4096;

impl EngineTransaction {
    /// Makes the transaction of one request. `id` is the name that the library gives it.
    pub fn new(
        engine: &Rc<Engine>,
        rules: &Rc<Rules>,
        id: &str,
    ) -> Result<EngineTransaction, Error> {
        let id = CString::new(id).map_err(|_| Error::Value)?;
        // SAFETY: the engine and the rules are live, and the new value keeps them alive; `id` is a
        // NUL-terminated string that outlives the call, which copies it.
        let raw = unsafe { tkv_tx_new(engine.raw.as_ptr(), rules.raw.as_ptr(), id.as_ptr()) };
        NonNull::new(raw)
            .map(|raw| EngineTransaction {
                raw,
                _engine: Rc::clone(engine),
                _rules: Rc::clone(rules),
            })
            .ok_or(Error::Create)
    }

    /// The connection of the request. The library reads the addresses as C strings, so one that holds a NUL byte
    /// is refused.
    pub fn connection(
        &mut self,
        client: &[u8],
        client_port: u16,
        server: &[u8],
        server_port: u16,
    ) -> Result<(), Error> {
        let client = CString::new(client).map_err(|_| Error::Value)?;
        let server = CString::new(server).map_err(|_| Error::Value)?;
        // SAFETY: `raw` is a live transaction and both strings are NUL-terminated and outlive the call.
        let code = unsafe {
            tkv_tx_connection(
                self.raw.as_ptr(),
                client.as_ptr(),
                c_int::from(client_port),
                server.as_ptr(),
                c_int::from(server_port),
            )
        };
        done(code)
    }

    /// The request line. `version` is what follows `HTTP/`. The library reads the URI up to a NUL byte, if it
    /// holds one.
    pub fn uri(&mut self, uri: &[u8], method: &[u8], version: &[u8]) -> Result<(), Error> {
        let method = CString::new(method).map_err(|_| Error::Value)?;
        let version = CString::new(version).map_err(|_| Error::Value)?;
        // SAFETY: `raw` is a live transaction, `uri` is a slice of the length given, and the two strings are
        // NUL-terminated; all outlive the call.
        let code = unsafe {
            tkv_tx_uri(
                self.raw.as_ptr(),
                uri.as_ptr(),
                uri.len(),
                method.as_ptr(),
                version.as_ptr(),
            )
        };
        done(code)
    }

    /// One request header; a NUL byte in the name or the value is kept.
    pub fn header(&mut self, name: &[u8], value: &[u8]) -> Result<(), Error> {
        // SAFETY: `raw` is a live transaction and the two slices have the lengths given.
        let code = unsafe {
            tkv_tx_header(
                self.raw.as_ptr(),
                name.as_ptr(),
                name.len(),
                value.as_ptr(),
                value.len(),
            )
        };
        done(code)
    }

    /// Phase 1: the rules of the request headers.
    pub fn request_headers(&mut self) -> Result<(), Error> {
        // SAFETY: `raw` is a live transaction.
        done(unsafe { tkv_tx_request_headers(self.raw.as_ptr()) })
    }

    /// Puts the request body processor in place (`None` leaves the library with none), whatever the headers or a
    /// rule said before. `Other` cannot be set.
    pub fn set_processor(&mut self, processor: Processor) -> Result<(), Error> {
        // SAFETY: `raw` is a live transaction; the bridge refuses a number it does not know.
        done(unsafe { tkv_tx_set_processor(self.raw.as_ptr(), processor.number()) })
    }

    /// Appends a part of the request body. `Error::Short` when the library took less than it was given.
    pub fn append_body(&mut self, bytes: &[u8]) -> Result<(), Error> {
        // SAFETY: `raw` is a live transaction and `bytes` is a slice of the length given.
        match unsafe { tkv_tx_append_body(self.raw.as_ptr(), bytes.as_ptr(), bytes.len()) } {
            ADDED => Ok(()),
            SHORT => Err(Error::Short),
            _ => Err(Error::Internal),
        }
    }

    /// Phase 2: the library parses the body and runs the rules of the request body. A body that does not parse
    /// is not an error of this call: it sets the flags that `state` reads.
    pub fn request_body(&mut self) -> Result<(), Error> {
        // SAFETY: `raw` is a live transaction.
        done(unsafe { tkv_tx_request_body(self.raw.as_ptr()) })
    }

    /// The logging phase, which ends a transaction.
    pub fn logging(&mut self) -> Result<(), Error> {
        // SAFETY: `raw` is a live transaction.
        done(unsafe { tkv_tx_logging(self.raw.as_ptr()) })
    }

    /// Takes what the rules left to stop the request, if they left something. The library forgets what was taken:
    /// the next call gives only what a rule did after this one.
    pub fn intervention(&mut self) -> Result<Option<Intervention>, Error> {
        let (mut taken, mut status, mut redirect) = (0, 0, 0);
        // SAFETY: `raw` is a live transaction and the three pointers point to integers that live for the call.
        let code = unsafe {
            tkv_tx_intervention(self.raw.as_ptr(), &mut taken, &mut status, &mut redirect)
        };
        done(code)?;
        match taken {
            0 => Ok(None),
            1 => Ok(Some(Intervention {
                status,
                redirect: redirect == 1,
            })),
            _ => Err(Error::Internal),
        }
    }

    /// What the transaction holds before a request may be let through.
    pub fn state(&self) -> Result<TransactionState, Error> {
        let (mut engine_on, mut body_access, mut processor) = (0, 0, 0);
        let (mut request_error, mut processor_error) = (0, 0);
        let (mut pcre_limit, mut pcre_error) = (0, 0);
        // SAFETY: `raw` is a live transaction and the seven pointers point to integers that live for the call.
        let code = unsafe {
            tkv_tx_state(
                self.raw.as_ptr(),
                &mut engine_on,
                &mut body_access,
                &mut processor,
                &mut request_error,
                &mut processor_error,
                &mut pcre_limit,
                &mut pcre_error,
            )
        };
        done(code)?;
        let flag = |value: c_int| match value {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Internal),
        };
        Ok(TransactionState {
            engine_on: flag(engine_on)?,
            body_access: flag(body_access)?,
            processor: Processor::from_number(processor).ok_or(Error::Internal)?,
            request_error: flag(request_error)?,
            processor_error: flag(processor_error)?,
            pcre_limit: flag(pcre_limit)?,
            pcre_error: flag(pcre_error)?,
        })
    }

    /// The rules that matched and were logged, in the order they ran.
    pub fn messages(&self) -> Result<Vec<Message>, Error> {
        let mut count = 0;
        // SAFETY: `raw` is a live transaction; with no buffer the call only writes `count`, a live integer.
        let code =
            unsafe { tkv_tx_messages(self.raw.as_ptr(), std::ptr::null_mut(), 0, &mut count) };
        done(code)?;
        let mut buffer = vec![
            RawMessage {
                id: 0,
                severity: 0,
                disruptive: 0
            };
            count
        ];
        let mut again = 0;
        // SAFETY: `raw` is a live transaction, `buffer` holds `count` entries, and `again` is a live integer.
        let code = unsafe {
            tkv_tx_messages(
                self.raw.as_ptr(),
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut again,
            )
        };
        done(code)?;
        if again != count {
            return Err(Error::Internal);
        }
        buffer
            .iter()
            .map(|raw| {
                Ok(Message {
                    id: raw.id,
                    severity: (raw.severity >= 0).then_some(raw.severity),
                    disruptive: match raw.disruptive {
                        0 => false,
                        1 => true,
                        _ => return Err(Error::Internal),
                    },
                })
            })
            .collect()
    }

    /// The value of the TX variable that holds the anomaly score, as text; `None` when there is none. A value
    /// longer than `SCORE_CAPACITY` is cut.
    pub fn score(&self) -> Result<Option<Vec<u8>>, Error> {
        let mut text = vec![0u8; SCORE_CAPACITY];
        let (mut length, mut present) = (0, 0);
        // SAFETY: `raw` is a live transaction, `text` holds `SCORE_CAPACITY` bytes, and the two pointers point
        // to integers that live for the call.
        let code = unsafe {
            tkv_tx_score(
                self.raw.as_ptr(),
                text.as_mut_ptr(),
                text.len(),
                &mut length,
                &mut present,
            )
        };
        done(code)?;
        match present {
            0 => Ok(None),
            1 => {
                text.truncate(length.min(SCORE_CAPACITY));
                Ok(Some(text))
            }
            _ => Err(Error::Internal),
        }
    }
}

impl Drop for EngineTransaction {
    fn drop(&mut self) {
        // SAFETY: `raw` came from `tkv_tx_new` and is freed only here, before the engine and the rules it points
        // to, which are dropped after this.
        unsafe { tkv_tx_free(self.raw.as_ptr()) }
    }
}

/// The result of a call that only says whether it worked.
fn done(code: c_int) -> Result<(), Error> {
    match code {
        ADDED => Ok(()),
        _ => Err(Error::Internal),
    }
}

#[cfg(test)]
pub(crate) mod tests;
