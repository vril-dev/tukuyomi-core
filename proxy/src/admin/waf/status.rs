//! The status route, `GET /api/status`: `{"current", "reachable", "proxy", "rollback_to", "engines", "crs"}`.
//!
//! `current` is the generation the rules store chooses for the default engine (`null` when it chooses none), and
//! `reachable` and `proxy` are what the control socket says of the proxy (see `control`): `proxy` is `{"generation",
//! "mode", "engine", "phase", "switching", "engines", "reloading", "ready", "uptime_ms", "requests", "blocked",
//! "policy_refused", "upstream_failures", "config", "managed", "resolve_timeout_ms", "config_reloads"}`, the answer of
//! the proxy as it is (`generation`, `mode`, `engine` and `phase` are those of its default engine, and `engines` has
//! the same four for each engine it runs), and `null` when it could not be read. A proxy of an older version does not
//! send `engines` and the figures (`reloading` and the last nine), and each one it does not send is `null`, as
//! `managed` is for a proxy whose configuration has no `managed`; the answer is not refused for that. `rollback_to` is
//! the generation a rollback of the default engine would go to if it were asked for now: the target of the history
//! (`history::rollback_target`) when the rules store still has that generation, else `null`. `engines` has an entry for
//! each engine, `{"engine", "current", "rollback_to"}`, the same two for that engine. A history that cannot be read
//! makes the answer 503, as it does for the history route.
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
use crate::rules::store::ENGINES;

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
        let list = match store.list() {
            Ok(list) => list,
            Err(e) => return failed(e),
        };
        let lines = match self.lines() {
            Ok(lines) => lines,
            Err(answer) => return answer,
        };
        // The generation chosen for each engine, and where a rollback of the engine would go.
        let mut engines = Vec::new();
        for engine in ENGINES {
            let current = match store.current(engine) {
                Ok(current) => current,
                Err(e) => return failed(e),
            };
            let rollback_to = current
                .and_then(|chosen| {
                    rollback_target(&lines, chosen, engine, |g| store.engine(g).ok()).ok()
                })
                .filter(|target| list.iter().any(|g| g.fingerprint == *target));
            engines.push((engine, current, rollback_to));
        }
        let default = engines
            .iter()
            .find(|(engine, ..)| *engine == self.default_engine)
            .map_or((None, None), |&(_, current, rollback_to)| {
                (current, rollback_to)
            });
        let proxy = self.control.status();
        let crs = self.crs_dir.as_deref();
        Answer::json(
            StatusCode::OK,
            json!({
                "current": default.0.map(|current| current.hex()),
                "reachable": proxy.reachable(),
                "proxy": proxy.state().map(|status| status.json()),
                "rollback_to": default.1.map(|target| target.hex()),
                "engines": engines
                    .iter()
                    .map(|(engine, current, rollback_to)| json!({
                        "engine": engine.name(),
                        "current": current.map(|current| current.hex()),
                        "rollback_to": rollback_to.map(|target| target.hex()),
                    }))
                    .collect::<Vec<_>>(),
                "crs": {"available": crs.is_some(), "files": crs.map(crs_files).unwrap_or_default()},
            }),
        )
    }
}
