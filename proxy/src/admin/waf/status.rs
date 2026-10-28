//! The status route, `GET /api/status`: `{"current", "reachable", "proxy", "rollback_to", "crs"}`.
//!
//! `current` is the generation the rules store chooses (`null` when it chooses none), and `reachable` and `proxy` are
//! what the control socket says of the proxy (see `control`). `rollback_to` is the generation a rollback would go to
//! if it were asked for now: the target of the history (`history::rollback_target`) when the rules store still has
//! that generation, else `null`. A history that cannot be read makes the answer 503, as it does for the history route.
//!
//! `crs` is `{"available", "files"}`: `available` says whether the configuration names a directory of the CRS
//! (`admin.crs_dir`), and `files` are the names of the `.conf` files in its `rules` directory, which an import may turn
//! off (`crs_off`), by the bytes of the names. They are found as the import finds them: a link in place of the
//! directory of the CRS or of its `rules` directory is not followed, and a link, a directory, any other kind of file
//! and a name that is not a name in a bundle are left out; a directory that cannot be read lists none. The answer
//! holds names only, never a path.

use std::fs;
use std::path::Path;

use http::StatusCode;
use serde_json::json;

use super::history::rollback_target;
use super::{Waf, failed};
use crate::admin::server::Answer;
use crate::rules::bundle::{BundlePath, MAX_FILES};

/// The most entries of the directory that are read, as many as an import reads.
const SCAN_MAX: usize = 1024;

/// Whether `path` is a directory itself and not a link to one.
fn is_real_dir(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_dir())
}

/// The names of the `.conf` files in `<dir>/rules`, at most `MAX_FILES`.
fn crs_files(dir: &Path) -> Vec<String> {
    let rules = dir.join("rules");
    if !is_real_dir(dir) || !is_real_dir(&rules) {
        return Vec::new();
    }
    let Ok(entries) = fs::read_dir(&rules) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .take(SCAN_MAX)
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.ends_with(".conf"))
        .filter(|name| BundlePath::parse(&format!("crs/rules/{name}")).is_some())
        .collect();
    names.sort();
    names.truncate(MAX_FILES);
    names
}

impl Waf {
    pub(super) fn status(&self) -> Answer {
        let store = match self.rules() {
            Ok(store) => store,
            Err(answer) => return answer,
        };
        let (current, list) = match (store.current(), store.list()) {
            (Ok(current), Ok(list)) => (current, list),
            (Err(e), _) | (_, Err(e)) => return failed(e),
        };
        let lines = match self.lines() {
            Ok(lines) => lines,
            Err(answer) => return answer,
        };
        let rollback_to = current
            .and_then(|chosen| rollback_target(&lines, chosen).ok())
            .filter(|target| list.iter().any(|g| g.fingerprint == *target));
        let proxy = self.control.status();
        let crs = self.crs_dir.as_deref();
        Answer::json(
            StatusCode::OK,
            json!({
                "current": current.map(|current| current.hex()),
                "reachable": proxy.reachable(),
                "proxy": proxy.state().map(|status| status.json()),
                "rollback_to": rollback_to.map(|target| target.hex()),
                "crs": {"available": crs.is_some(), "files": crs.map(crs_files).unwrap_or_default()},
            }),
        )
    }
}
