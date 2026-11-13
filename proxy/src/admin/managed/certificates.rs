//! The certificates of the sites of a version, `GET /api/managed/certificates/<name>`, for an operator, with a token as
//! well: for each site of the version, in its order, what the managed store has for its certificate (see
//! `managed::certificates`). They are the certificates on the disk, not the ones that the proxy holds: after `acme
//! renew` the two differ until the proxy reads them again (SIGUSR2), and the version need not be the one in force.
//!
//! The steps, as for the content of a version (`GET /api/managed/versions/<name>`), and the first that refuses answers:
//! 1. The store: a main file that had no `managed` when the process started is 409, a store that cannot be opened 500.
//! 2. The name: one that is not 64 lowercase hexadecimal digits is 404.
//! 3. A version that the list of the store does not have is 404; a list that cannot be read is 500.
//! 4. The version, read without a main file and without the lock of its file: bytes that are not what its name says,
//!    or that are not a version, are 500 with the sentence of the store or of the version, and so is a version of more
//!    than 64 sites.
//!
//! The answer is 200 `{"name", "sites"}`, the sites in the order of the version, each with `name`, `kind` (`files`,
//! `acme` or `null` for a certificate in neither form), `chain` and `key` for the files (their names, never their
//! bytes), `hosts` for a site with `acme` whose hosts are of the form, `state` (`present`, `missing`, `issued`,
//! `waiting`, `unreadable` or `unparsed`), and, when a chain is read and its end with it, `not_after` (seconds since the
//! epoch) and `expired`, by the clock of the server, with `names` and `more` (the DNS names of the certificate and the
//! number of the others) when its names are read as well: `[]` is a certificate without the extension or without a
//! DNS name in it. The route takes no seat and no lock, does not ask the proxy, does not look at whether the
//! process stops, and writes nothing to the audit log, for it changes nothing.

use http::StatusCode;
use serde_json::{Value, json};

use super::routes::{CERTIFICATES, Managed, failed, name_of, not_found};
use crate::admin::server::Answer;
use crate::admin::users::now_ms;
use crate::managed::certificates::{self, Kind, Stored};
use crate::rules::bundle::hex;

impl Managed {
    /// The route, for the version that `path` names (see the module documentation).
    pub(super) fn certificates(&self, path: &str) -> Answer {
        let store = match self.store() {
            Ok(store) => store,
            Err(answer) => return answer,
        };
        let Some(name) = name_of(path, CERTIFICATES) else {
            return not_found();
        };
        match store.versions() {
            Ok(list) if list.iter().any(|listed| listed.name == name) => {}
            Ok(_) => return not_found(),
            Err(e) => return failed(e),
        }
        let now = i64::try_from(now_ms() / 1000).unwrap_or(i64::MAX);
        match certificates::certificates(&store, name, now) {
            Ok(sites) => Answer::json(
                StatusCode::OK,
                json!({
                    "name": hex(&name),
                    "sites": sites.iter().map(site_json).collect::<Vec<_>>(),
                }),
            ),
            Err(e) => failed(e),
        }
    }
}

/// A site as the answer shows it (see the module documentation).
fn site_json(site: &Stored) -> Value {
    let mut shown = json!({"name": site.name, "kind": null, "state": site.state.word()});
    match &site.kind {
        Some(Kind::Files { chain, key }) => {
            shown["kind"] = json!("files");
            shown["chain"] = json!(hex(chain));
            shown["key"] = json!(hex(key));
        }
        Some(Kind::Acme { hosts }) => {
            shown["kind"] = json!("acme");
            if let Some(hosts) = hosts {
                shown["hosts"] = json!(hosts);
            }
        }
        None => {}
    }
    if let Some(leaf) = &site.leaf {
        if let Some((names, more)) = &leaf.names {
            shown["names"] = json!(names);
            shown["more"] = json!(more);
        }
        shown["not_after"] = json!(leaf.expiry.not_after);
        shown["expired"] = json!(leaf.expiry.expired);
    }
    shown
}

#[cfg(test)]
mod tests;
