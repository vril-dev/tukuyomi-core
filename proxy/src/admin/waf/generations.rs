//! The routes of the generations: `GET /api/generations`, `GET /api/generations/<fingerprint>` and
//! `DELETE /api/generations/<fingerprint>`.

use http::StatusCode;
use serde_json::{Map, Value, json};

use super::history::rollback_target;
use super::{Caller, GENERATION, Waf, conflict, failed, not_found, refused};
use crate::admin::audit::Outcome;
use crate::admin::password::hex;
use crate::admin::server::Answer;
use crate::rules::bundle::Fingerprint;

/// The generation that `path`, a path below `/api/generations/`, names.
fn fingerprint_of(path: &str) -> Option<Fingerprint> {
    Fingerprint::from_hex(path.strip_prefix(GENERATION)?.as_bytes())
}

impl Waf {
    pub(super) fn generations(&self) -> Answer {
        let store = match self.rules() {
            Ok(store) => store,
            Err(answer) => return answer,
        };
        let (list, current) = match (store.list(), store.current()) {
            (Ok(list), Ok(current)) => (list, current),
            (Err(e), _) | (_, Err(e)) => return failed(e),
        };
        let proxy = self.control.status();
        let serving = proxy.state().map(|status| status.generation);
        let items: Vec<Value> = list
            .iter()
            .rev()
            .map(|g| {
                let (mode, engine, routes) = store
                    .manifest(g.fingerprint)
                    .map_or(("unknown", "unknown", 0), |m| {
                        (m.mode().name(), m.engine().name(), m.routes().len())
                    });
                json!({
                    "fingerprint": g.fingerprint.hex(),
                    "made": g.made,
                    "mode": mode,
                    "engine": engine,
                    "routes": routes,
                    "current": current == Some(g.fingerprint),
                    "serving": serving == Some(g.fingerprint),
                })
            })
            .collect();
        Answer::json(
            StatusCode::OK,
            json!({"reachable": proxy.reachable(), "generations": items}),
        )
    }

    pub(super) fn generation(&self, path: &str) -> Answer {
        let Some(fingerprint) = fingerprint_of(path) else {
            return not_found();
        };
        let store = match self.rules() {
            Ok(store) => store,
            Err(answer) => return answer,
        };
        let (list, current) = match (store.list(), store.current()) {
            (Ok(list), Ok(current)) => (list, current),
            (Err(e), _) | (_, Err(e)) => return failed(e),
        };
        let Some(entry) = list.iter().find(|g| g.fingerprint == fingerprint) else {
            return not_found();
        };
        let manifest = match store.manifest(fingerprint) {
            Ok(manifest) => manifest,
            Err(e) => return failed(e),
        };
        let serving = self
            .control
            .status()
            .state()
            .map(|status| status.generation);
        let files: Vec<Value> = manifest
            .files()
            .iter()
            .map(|f| json!({"path": f.path.as_str(), "size": f.size, "sha256": hex(&f.sha256)}))
            .collect();
        let load: Vec<&str> = manifest.load().iter().map(|path| path.as_str()).collect();
        let routes: Vec<Value> = manifest
            .routes()
            .iter()
            .map(|rule| {
                let mut route = Map::new();
                if let Some(host) = rule.host() {
                    route.insert("host".to_owned(), host.into());
                }
                route.insert("path".to_owned(), rule.path().unwrap_or_default().into());
                route.insert("action".to_owned(), "bypass".into());
                Value::Object(route)
            })
            .collect();
        Answer::json(
            StatusCode::OK,
            json!({
                "fingerprint": fingerprint.hex(),
                "made": entry.made,
                "mode": manifest.mode().name(),
                "engine": manifest.engine().name(),
                "current": current == Some(fingerprint),
                "serving": serving == Some(fingerprint),
                "load": load,
                "files": files,
                "routes": routes,
            }),
        )
    }

    pub(super) fn remove(&self, path: &str, caller: &Caller<'_>) -> Answer {
        let Some(generation) = fingerprint_of(path) else {
            return not_found();
        };
        let hex = generation.hex();
        let _changing = match self.changing() {
            Ok(guard) => guard,
            Err(answer) => return answer,
        };
        let mut store = match self.rules() {
            Ok(store) => store,
            Err(answer) => return answer,
        };
        match store.list() {
            Ok(list) if list.iter().any(|g| g.fingerprint == generation) => {}
            Ok(_) => return not_found(),
            Err(e) => return failed(e),
        }
        let chosen = match store.current() {
            Ok(Some(current)) if current == generation => {
                self.note(caller, "remove", Outcome::Denied, "chosen", &hex);
                return conflict("the generation is the one the rules store chooses");
            }
            Ok(current) => current,
            Err(e) => return failed(e),
        };
        // A rollback has a target only while the history ends at the chosen generation.
        let lines = match self.lines() {
            Ok(lines) => lines,
            Err(answer) => return answer,
        };
        if chosen.is_some_and(|chosen| rollback_target(&lines, chosen) == Ok(generation)) {
            self.note(caller, "remove", Outcome::Denied, "rollback target", &hex);
            return conflict("the generation is the target of a rollback");
        }
        if self
            .audit
            .write(&caller.event("remove", Outcome::Ok).target(&hex))
            .is_err()
        {
            return Answer::unavailable();
        }
        match store.remove(generation) {
            Ok(()) => Answer::json(StatusCode::OK, json!({"removed": hex})),
            Err(e) => {
                self.note(caller, "remove", Outcome::Failed, "store", &hex);
                refused(e)
            }
        }
    }
}
