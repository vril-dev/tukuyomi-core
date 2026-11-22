//! The routes of the generations: `GET /api/generations`, `GET /api/generations/<fingerprint>` and
//! `DELETE /api/generations/<fingerprint>`.

use http::StatusCode;
use serde_json::{Map, Value, json};

use super::control::Seen;
use super::history::rollback_target;
use super::{Caller, GENERATION, Waf, conflict, failed, not_found, refused};
use crate::admin::audit::Outcome;
use crate::admin::password::hex;
use crate::admin::server::Answer;
use crate::rules::bundle::Fingerprint;
use crate::rules::store::{ENGINES, RuleStore, StoreError};

/// The generation that `path`, a path below `/api/generations/`, names.
fn fingerprint_of(path: &str) -> Option<Fingerprint> {
    Fingerprint::from_hex(path.strip_prefix(GENERATION)?.as_bytes())
}

/// The generations that the proxy serves, one for each engine that it runs; the one of a proxy that does not report
/// its engines (an older version).
fn serving_of(proxy: &Seen) -> Vec<Fingerprint> {
    match proxy.state() {
        Some(status) => match status.engines {
            Some(engines) => engines
                .running()
                .map(|(_, state)| state.generation)
                .collect(),
            None => vec![status.generation],
        },
        None => Vec::new(),
    }
}

/// The generations chosen for the engines, which `current` of a generation is told by.
fn chosen(store: &dyn RuleStore) -> Result<Vec<Fingerprint>, StoreError> {
    let mut chosen = Vec::new();
    for engine in ENGINES {
        chosen.extend(store.current(engine)?);
    }
    Ok(chosen)
}

impl Waf {
    pub(super) fn generations(&self) -> Answer {
        let store = match self.rules() {
            Ok(store) => store,
            Err(answer) => return answer,
        };
        let (list, current) = match (store.list(), chosen(store.as_ref())) {
            (Ok(list), Ok(current)) => (list, current),
            (Err(e), _) | (_, Err(e)) => return failed(e),
        };
        let proxy = self.control.status();
        let serving = serving_of(&proxy);
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
                    "current": current.contains(&g.fingerprint),
                    "serving": serving.contains(&g.fingerprint),
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
        let (list, current) = match (store.list(), chosen(store.as_ref())) {
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
        let serving = serving_of(&self.control.status());
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
                "current": current.contains(&fingerprint),
                "serving": serving.contains(&fingerprint),
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
        // A generation whose manifest cannot be read is chosen for no engine that can be told; the store refuses to
        // remove it if a record names it all the same.
        let engine = store.engine(generation).ok();
        let chosen = match engine.map(|engine| store.current(engine)) {
            Some(Ok(Some(current))) if current == generation => {
                self.note(caller, "remove", Outcome::Denied, "chosen", &hex);
                return conflict("the generation is the one the rules store chooses");
            }
            Some(Ok(current)) => current,
            Some(Err(e)) => return failed(e),
            None => None,
        };
        // A rollback has a target only while the history ends at the chosen generation.
        let lines = match self.lines() {
            Ok(lines) => lines,
            Err(answer) => return answer,
        };
        // The target of the rollback of the engine of the generation: a generation that the history of another engine
        // goes back to is not held by it.
        let held = engine.zip(chosen).is_some_and(|(engine, chosen)| {
            rollback_target(&lines, chosen, engine, |g| store.engine(g).ok()) == Ok(generation)
        });
        if held {
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
