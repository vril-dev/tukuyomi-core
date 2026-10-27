//! The import of a generation, `POST /api/generations`: the body of the request, the trial of the staged bundle and
//! what the answer says of the trial.
//!
//! The body is a JSON object with these keys, all of them optional and no other allowed: `rules` and `data` (arrays of
//! `{"name", "data"}`: the name of a file as `rules import` takes it from `--rules` and `--data`, one name and no path,
//! and its content in the standard base64 with padding), `crs` (true: the CRS of the directory `admin.crs_dir` is
//! taken; the request never names a directory, and it is refused when the configuration has none), `crs_off` (the
//! names of the files of the CRS that are not loaded), `routes` (the routes of the bundle, in the form of the file that
//! `--routes` names), `detect_only` and `accept_block` (as the options of `rules import`). The limits are those of
//! `rules import`: 128 files, 2 MiB for a file and 8 MiB for all (`collect` checks them); a file of the request that
//! is over 2 MiB is refused before it is decoded.
//!
//! The trial is the one of `rules import` (see `rules::trial`), run by the admin process with the kernel values of the
//! configuration. It is a trait, so that the tests need no inspector: `Inspector` starts one.

use std::ffi::OsString;
use std::path::Path;
use std::sync::atomic::AtomicBool;

use http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Caller, Waf, Waits, invalid, refused};
use crate::acme::base64;
use crate::admin::audit::Outcome;
use crate::admin::server::{Answer, Req, json_body};
use crate::config::KernelSettings;
use crate::log::escaped;
use crate::rules::bundle::{MAX_FILE_BYTES, MAX_FILES, Mode};
use crate::rules::collect::{CollectError, Upload, Uploads, collect_uploads};
use crate::rules::command::describe;
use crate::rules::store::{Committed, Staged};
use crate::rules::trial::{self, Accepted, Finish, Limits};

/// The longest base64 text of a file of 2 MiB.
const ENCODED_MAX: usize = (MAX_FILE_BYTES as usize).div_ceil(3) * 4;
/// The most bytes of what the inspector said that the answer shows.
const DETAIL_MAX: usize = 512;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Part {
    name: String,
    data: String,
}

/// The body of the request.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Body {
    #[serde(default)]
    rules: Vec<Part>,
    #[serde(default)]
    data: Vec<Part>,
    #[serde(default)]
    crs: bool,
    #[serde(default)]
    crs_off: Vec<String>,
    #[serde(default)]
    routes: Option<Value>,
    #[serde(default)]
    detect_only: bool,
    #[serde(default)]
    accept_block: bool,
}

/// What the body asks for.
pub struct Request {
    pub uploads: Uploads,
    /// A block of the trial is not a failure.
    pub accept_block: bool,
}

/// The files of `parts`, decoded.
fn uploads(parts: Vec<Part>) -> Result<Vec<Upload>, CollectError> {
    parts
        .into_iter()
        .map(|part| {
            let refuse = |reason: &'static str| CollectError {
                reason,
                subject: Some(OsString::from(&part.name)),
            };
            if part.data.len() > ENCODED_MAX {
                return Err(refuse("an input file is over 2 MiB"));
            }
            let data = base64::decode(&part.data).ok_or_else(|| {
                refuse("an input file is not base64 (the standard alphabet, with padding)")
            })?;
            Ok(Upload {
                name: part.name,
                data,
            })
        })
        .collect()
}

impl Body {
    /// The request that the body makes, or why it is refused. `crs_dir` is the directory that the configuration
    /// gives for the CRS, if it does.
    pub fn request(self, crs_dir: Option<&Path>) -> Result<Request, CollectError> {
        let refuse = |reason: &'static str| CollectError {
            reason,
            subject: None,
        };
        if self.rules.len().saturating_add(self.data.len()) > MAX_FILES {
            return Err(refuse("the request has more than 128 files"));
        }
        if self.crs_off.len() > MAX_FILES {
            return Err(refuse(
                "the request turns off more than 128 files of the CRS",
            ));
        }
        let crs = match (self.crs, crs_dir) {
            (true, None) => {
                return Err(refuse("the CRS is asked for but admin.crs_dir is not set"));
            }
            (true, Some(dir)) => Some(dir.to_path_buf()),
            (false, _) => None,
        };
        let routes = self
            .routes
            .map(|routes| serde_json::to_vec(&routes))
            .transpose()
            .map_err(|_| refuse("the routes cannot be read"))?;
        Ok(Request {
            uploads: Uploads {
                crs,
                crs_off: self.crs_off.into_iter().map(OsString::from).collect(),
                rules: uploads(self.rules)?,
                data: uploads(self.data)?,
                mode: if self.detect_only {
                    Mode::Detect
                } else {
                    Mode::Block
                },
                routes,
            },
            accept_block: self.accept_block,
        })
    }
}

/// Runs the trial of a staged bundle. The real one starts an inspector; the tests replace it.
pub trait Trial: Send + Sync {
    /// Tries `staged`, a bundle with the rules of `mode`; the trial ends early, as a failure, once `stop` is set. A
    /// sentence: the trial could not be run at all.
    fn run(
        &self,
        staged: &Staged,
        accept_block: bool,
        mode: Mode,
        stop: &AtomicBool,
    ) -> Result<Finish, &'static str>;
}

/// The trial with an inspector of its own, started with the kernel values of the configuration. The caller has made
/// the checks of the host that the kernel requires (`run::host::check`).
pub struct Inspector {
    kernel: KernelSettings,
    waits: Waits,
}

impl Inspector {
    pub fn new(kernel: KernelSettings, waits: Waits) -> Inspector {
        Inspector { kernel, waits }
    }
}

impl Trial for Inspector {
    fn run(
        &self,
        staged: &Staged,
        accept_block: bool,
        mode: Mode,
        stop: &AtomicBool,
    ) -> Result<Finish, &'static str> {
        let kernel = self
            .kernel
            .for_generation(staged.dir.clone(), staged.fingerprint)
            .map_err(|e| e.0)?;
        let limits = Limits {
            ready_wait: self.waits.ready,
            inspect_wait: self.waits.inspect,
            stop_inspect: self.waits.stop,
            slice: self.waits.slice,
            accept_block,
            mode,
        };
        trial::run_supervised(kernel, &limits, stop)
    }
}

fn accepted(item: &Accepted) -> Value {
    match item {
        Accepted::Block {
            probe,
            phase,
            rule_id,
            status,
        } => json!({
            "kind": "block", "probe": probe, "rule": rule_id, "phase": phase, "status": status,
        }),
        Accepted::Detected {
            probe,
            rule_id,
            status,
        } => json!({
            "kind": "detected", "probe": probe, "rule": rule_id, "status": status,
        }),
    }
}

/// The end of a trial as the answer shows it: whether it passed, what it accepted or why it failed, and the few
/// bytes the inspector said, every byte outside 0x20 to 0x7e as `\xNN`.
pub fn report(finish: &Finish) -> Value {
    let mut out = match &finish.result {
        Ok(items) if finish.clean => json!({
            "passed": true,
            "accepted": items.iter().map(accepted).collect::<Vec<_>>(),
        }),
        Ok(_) => json!({
            "passed": false,
            "failure": "the inspector did not stop cleanly; a process or a directory may be left behind",
        }),
        Err(failed) => json!({"passed": false, "failure": describe(failed)}),
    };
    if let Some(detail) = &finish.detail {
        let line = detail.strip_suffix(b"\n").unwrap_or(detail);
        out["detail"] = escaped(&line[..line.len().min(DETAIL_MAX)]).into();
    }
    out
}

impl Waf {
    pub(super) fn import(&self, req: &Req, caller: &Caller<'_>) -> Answer {
        let body: Body = match json_body(req) {
            Ok(body) => body,
            Err(answer) => return answer,
        };
        let request = match body.request(self.crs_dir.as_deref()) {
            Ok(request) => request,
            Err(e) => return invalid(e),
        };
        let (accept_block, mode) = (request.accept_block, request.uploads.mode);
        let bundle = match collect_uploads(request.uploads) {
            Ok(bundle) => bundle,
            Err(e) => return invalid(e),
        };
        let fingerprint = bundle.fingerprint().hex();
        let _changing = match self.changing() {
            Ok(guard) => guard,
            Err(answer) => return answer,
        };
        let mut store = match self.rules() {
            Ok(store) => store,
            Err(answer) => return answer,
        };
        let event = caller.event("import", Outcome::Ok).target(&fingerprint);
        if self.audit.write(&event).is_err() {
            return Answer::unavailable();
        }
        let staged = match store.stage(&bundle) {
            Ok(staged) => staged,
            Err(e) => {
                self.note(caller, "import", Outcome::Failed, "store", &fingerprint);
                return refused(e);
            }
        };
        let finish = match self.trial.run(&staged, accept_block, mode, &self.stopping) {
            Ok(finish) => finish,
            Err(text) => {
                let _ = store.discard();
                self.note(caller, "import", Outcome::Failed, "trial", &fingerprint);
                return Answer::error(StatusCode::INTERNAL_SERVER_ERROR, text);
            }
        };
        if !finish.passed() {
            let _ = store.discard();
            self.note(caller, "import", Outcome::Failed, "trial", &fingerprint);
            return Answer::json(
                StatusCode::UNPROCESSABLE_ENTITY,
                json!({"error": "the trial failed", "trial": report(&finish)}),
            );
        }
        match store.commit() {
            Ok(committed) => {
                let result = match committed {
                    Committed::Created => "created",
                    Committed::Existing => "existing",
                    Committed::Repaired => "repaired",
                };
                Answer::json(
                    StatusCode::OK,
                    json!({
                        "fingerprint": fingerprint,
                        "result": result,
                        "trial": report(&finish),
                    }),
                )
            }
            Err(e) => {
                self.note(caller, "import", Outcome::Failed, "store", &fingerprint);
                refused(e)
            }
        }
    }
}

#[cfg(test)]
mod tests;
