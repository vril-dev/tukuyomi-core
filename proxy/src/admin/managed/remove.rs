//! The removal of a version of the managed store, `DELETE /api/managed/versions/<name>`, for an operator, with a token
//! as well, and without a body. The store removes the version and cleans up what no version names any more (see
//! `managed::remove`); the history has no line for it, and its lines that name the version stay.
//!
//! The steps, and the first that refuses answers:
//! 1. The name: one that is not 64 lowercase hexadecimal digits is 404.
//! 2. The right to change (`routes::Seat`), which a job holds too: a change under way is 409, a process that stops
//!    503. Not audited.
//! 3. The main file, read again: one without `managed` (or that had none when the process started), or whose
//!    `managed.dir` is not the directory of the start, is 409, and so is one that is refused, with its sentence.
//!    Audited as denied (`managed`, `configuration`).
//! 4. The store: one that cannot be opened is 500.
//! 5. A version that the list of the store does not have is 404; a list that cannot be read is 500.
//! 6. The version that the store chooses is 409, audited as denied (`chosen`); a record of the chosen version that
//!    cannot be read is 500.
//! 7. The target of a rollback (see `history`) is 409, audited as denied (`rollback target`); a history that cannot be
//!    read is 503, not audited.
//! 8. The audit log takes the line `managed-remove`, with the name of the version, before anything is removed: one that
//!    it does not take is 503, and nothing is removed.
//! 9. The removal by the store: a refusal is 409 with the sentence of the store (a lock that a command holds, a version
//!    that a proxy serves with or a command reads, one that is not a regular file), audited as failed (`store`).
//!
//! The answer is 200 `{"removed": <name>, "cleaned": <whether the store was cleaned whole as well>}`. The proxy is not
//! asked: a version that it serves with is held, and the store refuses it. The removal reads the other versions one by
//! one, so it takes longer as they grow in number; an answer that comes too late is 503, and the removal may end all
//! the same.

use http::StatusCode;
use serde_json::json;

use super::history::rollback_target;
use super::job::Caller;
use super::routes::{Managed, conflict, failed, name_of, not_found, unmanaged};
use crate::admin::audit::Outcome;
use crate::admin::auth::{Cx, Who};
use crate::admin::server::Answer;
use crate::managed::{Store, remove};
use crate::rules::bundle::hex;

/// The action of the audit log.
const ACTION: &str = "managed-remove";

impl Managed {
    /// The route, for the version that `path` names (see the module documentation).
    pub(super) fn remove(&self, path: &str, who: &Who, cx: &Cx<'_>) -> Answer {
        let Some(name) = name_of(path) else {
            return not_found();
        };
        let target = hex(&name);
        let caller = Caller::of(who, cx);
        let note = |outcome: Outcome, reason: &'static str| {
            let event = caller.event(ACTION, outcome).target(&target);
            let _ = self.audit.write(&event.reason(reason));
        };
        let Some(dir) = self.dir.as_deref() else {
            note(Outcome::Denied, "managed");
            return unmanaged();
        };
        let _seat = match self.seat() {
            Ok(seat) => seat,
            Err(answer) => return answer,
        };
        if let Err((reason, words)) = self.main_file(dir) {
            note(Outcome::Denied, reason);
            return conflict(words);
        }
        let store = match Store::open(dir) {
            Ok(store) => store,
            Err(e) => return failed(e),
        };
        match store.versions() {
            Ok(list) if list.iter().any(|listed| listed.name == name) => {}
            Ok(_) => return not_found(),
            Err(e) => return failed(e),
        }
        let chosen = match store.current() {
            Ok(Some(current)) if current == name => {
                note(Outcome::Denied, "chosen");
                return conflict("the version is the one the managed store chooses");
            }
            Ok(current) => current,
            Err(e) => return failed(e),
        };
        // A rollback has a target only while the history ends at the chosen version.
        let lines = match self.lines() {
            Ok(lines) => lines,
            Err(answer) => return answer,
        };
        if chosen.is_some_and(|chosen| rollback_target(&lines, chosen) == Ok(name)) {
            note(Outcome::Denied, "rollback target");
            return conflict("the version is the target of a rollback");
        }
        let event = caller.event(ACTION, Outcome::Ok).target(&target);
        if self.audit.write(&event).is_err() {
            return Answer::unavailable();
        }
        match remove::remove(&store, name) {
            Ok(removed) => Answer::json(
                StatusCode::OK,
                json!({"removed": target, "cleaned": removed.cleaned}),
            ),
            Err(e) => {
                note(Outcome::Failed, "store");
                conflict(e.0)
            }
        }
    }
}

#[cfg(test)]
mod tests;
