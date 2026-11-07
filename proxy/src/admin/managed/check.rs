//! The check of a version that saves nothing, `POST /api/managed/check`: the steps of the saving (see `import`) up to
//! the check of the version and its files, so that a client can show the refusal at its place before it saves.
//!
//! The body is `{"version", "files", "expect"?}`, as for the saving: `expect` may be there or not, and is read over
//! without a look at its form, so that a client can send the body of the saving as it is. The steps, and the first that
//! refuses answers:
//! 1. The seat of the check (see `import`): one that another request holds is 503. A main file that had no `managed`
//!    when the process started is 409 at once.
//! 2. The body, the files and the version, as for the saving: a refusal is 400 with its sentence and its place.
//! 3. The main file, read again: one without `managed`, or whose `managed.dir` is not the directory of the start, is
//!    409, and so is one that is refused, with its sentence.
//! 4. The managed store: one that cannot be opened is 500.
//! 5. The version with the main file and the files of the request and of the store, as for the saving (see
//!    `managed::import`): a refusal is 400 with its sentence and its place.
//!
//! The answer is 200 with `version`, the name that the version would have in the store. The check does not take the
//! right to change, does not ask the proxy, puts nothing in the store, and writes nothing to the audit log, for it
//! changes nothing; the store may choose no version yet.

use http::StatusCode;
use serde::Deserialize;
use serde::de::IgnoredAny;
use serde_json::json;

use super::import::{Files, body_of, invalid};
use super::routes::{Managed, conflict, failed, unmanaged};
use crate::admin::server::{Answer, Req};
use crate::managed::import;
use crate::managed::{Store, sent};
use crate::rules::bundle::{hex, sha256};

/// The body of the request.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    /// The version that the client saw chosen, which the check does not look at.
    #[serde(default, rename = "expect")]
    _expect: IgnoredAny,
    /// Read by `managed::sent`, in the form of a version.
    #[serde(rename = "version")]
    _version: IgnoredAny,
    files: Files,
}

impl Managed {
    pub(super) fn check(&self, req: &Req) -> Answer {
        let _checking = match self.check_seat() {
            Ok(seat) => seat,
            Err(answer) => return answer,
        };
        let Some(dir) = self.dir.as_deref() else {
            return unmanaged();
        };
        let body: Body = match body_of(req) {
            Ok(body) => body,
            Err(answer) => return answer,
        };
        let files = match body.files.contents() {
            Ok(files) => files,
            Err(answer) => return answer,
        };
        drop(body);
        let version = match sent(&req.body) {
            Ok(version) => version,
            Err(objection) => return invalid(&objection),
        };
        let built = match self.main_file(dir) {
            Ok(built) => built,
            Err((_, words)) => return conflict(words),
        };
        let store = match Store::open(dir) {
            Ok(store) => store,
            Err(e) => return failed(e),
        };
        let name = hex(&sha256(&version));
        match import::from_request(&built, &store, version, files) {
            Ok(_) => Answer::json(StatusCode::OK, json!({ "version": name })),
            Err(objection) => invalid(&objection),
        }
    }
}

#[cfg(test)]
mod tests;
