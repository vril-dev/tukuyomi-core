//! The saving of a version and its putting in force, `POST /api/managed/apply`: the body of the request, its check,
//! and the putting of the version and its files in the managed store before the job (see `job`) puts it in force.
//!
//! The body is `{"expect", "version", "files"}`. `expect` is the version that the client saw chosen, 64 lowercase
//! hexadecimal digits. `version` is the version to save, in the form of a version of the store (its files are named
//! by their SHA-256, and it names no path; see `managed::version`), in any written form: it is saved in its one
//! written form, and the SHA-256 of that is its name. `files` is the content of the files to save with it (the PEM
//! text of chains, keys and files of authorities): at most 192 files of at most 1 MiB each, no two the same, and each
//! one named by the version; a file that the version names and the request does not bring must be in the store. The
//! count and the size are kept while the body is read (`Files`): no file is kept past the 192nd or after a file over
//! 1 MiB, and the rest of the list is read over without being kept. The content of the files is held in memory that is
//! zeroed when it is dropped, and is never in an answer, in the audit log or in the history; the buffer that the body
//! of the request was read into is not zeroed, and neither is the copy that the JSON reader makes of a string with an
//! escape (a line feed of a PEM text is one) before it is taken.
//!
//! A refusal of the input is 400 with `{"error", "at"}`: the fixed sentence, and the place in the body it is about, or
//! `null` (see `managed::version` for the places of a version): `files` for too many files, `files[k]` (from 0) for
//! a file that is too large, twice or not named by the version, and for a version the item and the key it is about
//! (`sites[1].hosts[0]`, `upstreams.app.servers[2].address`, `sites[0].certificate.key`). A body that is not the
//! JSON of the route, and an `expect` that is not 64 lowercase digits, are about no place. The check of a version is
//! one at a time in the process, for apply and for check together (`Managed::check_seat`): its reading again of a
//! large body and of the files of the store holds much memory.
//!
//! The steps, and the first that refuses answers:
//! 1. The seat of the check: one that another request holds is 503. Not audited.
//! 2. The body: one that is not the JSON of the route is 400, and so are too many files and a file that is too large;
//!    a version that is not in the form of a version is 400 with the sentence of the main file (a repeated, unknown or
//!    missing key, a value of the wrong type), and so is an `expect` that is not 64 lowercase digits. Not audited.
//! 3. The steps 1 to 4 of a change (see `job`): the right to change, the main file read again, the store with
//!    `expect`, and the proxy. Nothing is saved for a proxy that could not take the version.
//! 4. The version with the main file and the files (see `managed::import`), as `managed import` checks a document but
//!    for the country database, which the proxy reads when it takes the version: a refusal is 400, with the fixed
//!    sentence (which names no site and no group) and its place. Not audited. The seat of the check is given back
//!    here.
//! 5. The audit log takes the line `managed-import`, with the name of the version, before anything is saved: one that
//!    it does not take is 503, and nothing is saved.
//! 6. The files and the version are put in the store under its lock: a lock that a command holds is 409 (`the managed
//!    store is in use by another command`), and so is another refusal of the store; a version that the reading with
//!    the files of the store refuses is 400, about no place, and a main file that it refuses (its country database) is
//!    409. These are audited as failed (`store`, `version`, `configuration`).
//! 7. The job starts (see `job`). A saved version that no job puts in force (the time of the answer was over, the
//!    process is stopping, the thread could not be started) stays in the store; it does no harm.
//!
//! The answer is 202 with `version`, the name of the version, `placed`, what its write found (`created`, `existing`,
//! or `recreated`: the store had a broken copy, which was replaced), and `job`.

use std::fmt;
use std::time::Instant;

use http::StatusCode;
use serde::Deserialize;
use serde::de::{self, DeserializeOwned, Deserializer, IgnoredAny, SeqAccess, Visitor};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::history::Kind;
use super::job::{Caller, Order, Ready, Target, version_of};
use super::routes::{Managed, conflict};
use crate::admin::audit::Outcome;
use crate::admin::auth::{Cx, Who};
use crate::admin::password::Secret;
use crate::admin::server::{Answer, Req, json_body};
use crate::managed::import::{self, LARGE_FILE, MANY_FILES, MAX_FILES, Placing, Reading};
use crate::managed::store::MAX_BYTES;
use crate::managed::{LoadError, Objection, Placed, sent};
use crate::rules::bundle::{hex, sha256};

/// The action of the audit log for the line that comes before anything is saved.
const IMPORT: &str = "managed-import";

/// The body of the request.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    expect: String,
    /// Read by `managed::sent`, in the form of a version.
    #[serde(rename = "version")]
    _version: IgnoredAny,
    files: Files,
}

/// The files of the body, read with their limits: past the 192nd file, or at a file over 1 MiB, no file is kept any
/// more, the rest of the list is read over, and the refusal is kept with its place.
pub(super) struct Files(Result<Vec<Secret>, Objection>);

/// One file of the body: its content, of at most 1 MiB, or none for a larger one, which is not taken.
enum File {
    Taken(Secret),
    Large,
}

impl Files {
    /// The content of the files, held in memory that is zeroed when it is dropped; the refusal of the list is 400.
    pub(super) fn contents(&self) -> Result<Vec<Zeroizing<Vec<u8>>>, Answer> {
        match &self.0 {
            Ok(files) => Ok(files
                .iter()
                .map(|file| Zeroizing::new(file.as_str().as_bytes().to_vec()))
                .collect()),
            Err(objection) => Err(invalid(objection)),
        }
    }
}

impl<'de> Deserialize<'de> for Files {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Files, D::Error> {
        deserializer.deserialize_seq(FilesVisitor)
    }
}

struct FilesVisitor;

impl<'de> Visitor<'de> for FilesVisitor {
    type Value = Files;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an array of strings")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Files, A::Error> {
        let mut files = Vec::new();
        while let Some(file) = seq.next_element()? {
            let refused = match file {
                File::Large => Objection::files(LARGE_FILE, Some(files.len())),
                File::Taken(_) if files.len() == MAX_FILES => Objection::files(MANY_FILES, None),
                File::Taken(file) => {
                    files.push(file);
                    continue;
                }
            };
            // The rest is read over, and nothing of it is kept.
            while seq.next_element::<IgnoredAny>()?.is_some() {}
            return Ok(Files(Err(refused)));
        }
        Ok(Files(Ok(files)))
    }
}

impl<'de> Deserialize<'de> for File {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<File, D::Error> {
        deserializer.deserialize_string(FileVisitor)
    }
}

struct FileVisitor;

impl Visitor<'_> for FileVisitor {
    type Value = File;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a string")
    }

    /// The text is taken only after its size is known to be within the limit.
    fn visit_str<E: de::Error>(self, text: &str) -> Result<File, E> {
        if u64::try_from(text.len()).is_ok_and(|n| n <= MAX_BYTES) {
            Ok(File::Taken(Secret::new(text.to_owned())))
        } else {
            Ok(File::Large)
        }
    }
}

/// A refusal of the input: 400 with its sentence and its place.
pub(super) fn invalid(objection: &Objection) -> Answer {
    Answer::json(
        StatusCode::BAD_REQUEST,
        json!({"error": objection.why, "at": objection.at}),
    )
}

/// `answer`, which is about no place of the body if it is 400.
pub(super) fn unplaced(mut answer: Answer) -> Answer {
    if answer.status == StatusCode::BAD_REQUEST {
        answer.body["at"] = Value::Null;
    }
    answer
}

/// The body of the request as the JSON object `T`, a 400 about no place.
pub(super) fn body_of<T: DeserializeOwned>(req: &Req) -> Result<T, Answer> {
    json_body(req).map_err(unplaced)
}

impl Managed {
    pub(super) fn apply(&self, req: &Req, who: &Who, cx: &Cx<'_>, began: Instant) -> Answer {
        let checking = match self.check_seat() {
            Ok(seat) => seat,
            Err(answer) => return answer,
        };
        let body: Body = match body_of(req) {
            Ok(body) => body,
            Err(answer) => return answer,
        };
        let files = match body.files.contents() {
            Ok(files) => files,
            Err(answer) => return answer,
        };
        let version = match sent(&req.body) {
            Ok(version) => version,
            Err(objection) => return invalid(&objection),
        };
        let expect = match version_of(&body.expect) {
            Ok(expect) => expect,
            Err(answer) => return unplaced(answer),
        };
        drop(body);
        let to = sha256(&version);
        let name = hex(&to);
        let caller = Caller::of(who, cx);
        let ready = match self.ready(Kind::Apply, &caller, expect, Target::Named(to)) {
            Ok(ready) => ready,
            Err(answer) => return answer,
        };
        let import = match import::from_request(&ready.built, &ready.store, version, files) {
            Ok(import) => import,
            Err(objection) => return invalid(&objection),
        };
        drop(checking);
        let event = caller.event(IMPORT, Outcome::Ok).target(&name);
        if self.audit.write(&event).is_err() {
            return Answer::unavailable();
        }
        let fail = |reason: &'static str| {
            let event = caller.event(IMPORT, Outcome::Failed);
            let _ = self.audit.write(&event.target(&name).reason(reason));
        };
        let Ready {
            seat,
            built,
            resolve_timeout,
            store,
            ..
        } = ready;
        let placed = match import::place(built, &store, &import, Reading::WithoutCountries) {
            Ok((_, Placed::Created)) => "created",
            Ok((_, Placed::Existing)) => "existing",
            Ok((_, Placed::Recreated)) => "recreated",
            Err(Placing::Store(e) | Placing::Load(LoadError::Store(e))) => {
                fail("store");
                return conflict(e.0);
            }
            Err(Placing::Load(LoadError::Version(e))) => {
                fail("version");
                return invalid(&Objection::whole(e.0));
            }
            Err(Placing::Load(LoadError::Main(e))) => {
                fail("configuration");
                return conflict(e.0);
            }
        };
        let order = Order {
            kind: Kind::Apply,
            caller,
            from: expect,
            to,
            resolve_timeout,
            store,
        };
        self.start(
            seat,
            order,
            began,
            json!({"version": name, "placed": placed}),
        )
    }
}

#[cfg(test)]
mod tests;
