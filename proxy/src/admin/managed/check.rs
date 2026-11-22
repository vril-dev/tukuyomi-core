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
//!    `managed::import`): a refusal is 400 with its sentence and its place. A group whose engine has no generation
//!    chosen in the rules store is refused so, about the key `engine` of the group; a rules store that cannot be
//!    read is 500.
//!
//! The answer is 200 with `version`, the name that the version would have in the store, and `detect`, the groups whose
//! engine runs a generation that only detects (`[{"upstream", "engine"}, ..]`, in the order of the groups, empty for
//! none): a request that a rule matches goes to such a group, which the version would put in force all the same. The
//! check does not take the
//! right to change, does not ask the proxy, puts nothing in the store, and writes nothing to the audit log, for it
//! changes nothing; the store may choose no version yet.

use http::StatusCode;
use serde::Deserialize;
use serde::de::IgnoredAny;
use serde_json::json;

use super::import::{Files, body_of, invalid};
use super::routes::{Managed, conflict, failed, unmanaged};
use crate::admin::server::{Answer, Req};
use crate::managed::import::{self, Refused};
use crate::managed::{ManagedError, Store, sent};
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
            Ok(import) => {
                let detect: Vec<_> = import
                    .detecting()
                    .iter()
                    .map(
                        |(upstream, engine)| json!({"upstream": upstream, "engine": engine.name()}),
                    )
                    .collect();
                Answer::json(StatusCode::OK, json!({ "version": name, "detect": detect }))
            }
            Err(Refused::Input(objection)) => invalid(&objection),
            Err(Refused::Rules(e)) => failed(ManagedError(e.0)),
        }
    }
}

#[cfg(test)]
mod tests;
