use super::*;
use crate::config;
use crate::rules::bundle::{Bundle, BundlePath, Mode};
use crate::rules::file_store::FileStore;
use crate::rules::routes::{Route, Routes};
use crate::rules::store::{StoreError, engines_from};
use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use tukuyomi_kernel::Engine;

const CONFIG: &str = r#"{"proxy":{"listeners":[{"address":"127.0.0.1:8080"}],"max_conns":1024,"max_head_bytes":8192,"max_body":1048576,"inspect_body":1048576,"max_body_wire":2097152,"max_buffered_bytes":8388608,"upstream_max_headers":100,"upstream_max_head_bytes":16384,"upstream_head_wire":65536,"drive_slice_ms":50,"ready_wait_ms":10000,"head_read_ms":10000,"body_read_ms":30000,"inspect_wait_ms":30000,"upstream_connect_ms":5000,"upstream_header_ms":30000,"request_total_ms":60000,"response_idle_ms":60000,"conn_total_ms":120000,"stop_inspect_ms":5000,"stop_wait_ms":10000,"keepalive_timeout_ms":75000,"keepalive_requests":1000,"keepalive_time_ms":60000,"lingering_time_ms":30000,"lingering_timeout_ms":5000,"lingering_bytes":262144,"trusted_proxies":[],"upstream_keepalive":32,"upstream_keepalive_timeout_ms":60000,"upstream_keepalive_requests":1000},"forward":{"resolve_timeout_ms":30000,"upstreams":{"main":{"servers":[{"address":"127.0.0.1:9000","weight":1,"max_fails":1,"fail_timeout_ms":10000,"backup":false}]},"api":{"servers":[{"address":"127.0.0.1:9001","weight":3,"max_fails":2,"fail_timeout_ms":5000,"backup":false},{"address":"127.0.0.1:9002","weight":1,"max_fails":0,"fail_timeout_ms":5000,"backup":true}]}},"routes":[{"host":"api.example.test","path":"/v1/","upstream":"api"}],"default_upstream":"main"},"kernel":{"inspector":"/opt/tukuyomi/inspector","tmp_root":"/var/lib/tukuyomi/tmp","gomaxprocs":2,"gomemlimit":1073741824,"slots":4,"wait_queue":16,"records":20,"discard_limit":4,"tick_ms":100,"hello_wait_ms":5000,"frame_io_ms":1000,"verdict_wait_ms":2000,"wait_deadline_ms":3000,"closed_wait_ms":2000,"stop_after_ms":2000,"drain_wait_ms":1000,"exit_wait_ms":1000,"kill_grace_ms":1000,"restarts":3,"restart_window_ms":60000},"rules":{"store":{"kind":"file","dir":"@DIR@"}}}"#;

/// A fresh 0700 directory under the temp directory (`TMPDIR`), removed with everything in it when dropped.
pub(crate) struct TestDir(pub(crate) PathBuf);

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(crate) fn scratch() -> TestDir {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "tukuyomi-proxy-switch-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    TestDir(dir)
}

fn bundle(name: &str) -> Bundle {
    let path = BundlePath::parse(&format!("rules/{name}.conf")).unwrap();
    Bundle::new(
        Engine::Coraza,
        Mode::Block,
        vec![(path.clone(), format!("SecRuleEngine {name}\n").into_bytes())],
        vec![path],
        Routes::default(),
    )
    .unwrap()
}

/// The store of `dir` that the commands use, with the generations `names` made (the first one chosen).
pub(crate) fn made_in(dir: &Path, names: &[&str]) -> (FileStore, Vec<Fingerprint>) {
    let mut store = FileStore::open(dir).unwrap();
    let made: Vec<Fingerprint> = names
        .iter()
        .map(|name| {
            let bundle = bundle(name);
            store.stage(&bundle).unwrap();
            store.commit().unwrap();
            bundle.fingerprint()
        })
        .collect();
    store.activate(made[0]).unwrap();
    (store, made)
}

/// A switcher that runs `generation`, on the store of `dir`.
pub(crate) fn switcher(dir: &Path, generation: Fingerprint) -> Switcher {
    switcher_of(dir, generation, CONFIG)
}

/// The same, for a configuration that has an inspector for ModSecurity as well.
fn switcher_with_modsecurity(dir: &Path, generation: Fingerprint) -> Switcher {
    let engines =
        r#""engines":{"modsecurity":{"inspector":"/opt/tukuyomi/inspector-modsecurity"}},"#;
    let text = CONFIG.replace(
        r#""kernel":{"inspector":"/opt/tukuyomi/inspector","#,
        &format!(r#""kernel":{{"inspector":"/opt/tukuyomi/inspector",{engines}"#),
    );
    switcher_of(dir, generation, &text)
}

fn switcher_of(dir: &Path, generation: Fingerprint, config: &str) -> Switcher {
    let file = dir.join("config.json");
    let text = config.replace("@DIR@", &dir.to_string_lossy());
    fs::write(&file, text).unwrap();
    let loaded = config::load(&file).unwrap();
    let store = FileStore::open(dir).unwrap();
    let hold = store.hold(generation).unwrap();
    Switcher::new(
        Box::new(store),
        loaded.kernel,
        vec![(Engine::Coraza, generation, hold)],
    )
}

fn refusal<T>(result: Result<T, StoreError>) -> &'static str {
    match result {
        Err(e) => e.0,
        Ok(_) => panic!("accepted"),
    }
}

#[test]
fn the_chosen_generation_is_held_until_the_switch_is_finished() {
    let root = scratch();
    let (mut commands, made) = made_in(&root.0, &["a", "b"]);
    let (a, b) = (made[0], made[1]);
    let mut switcher = switcher(&root.0, a);
    // The generation that runs is the chosen one: nothing to do.
    assert!(matches!(switcher.prepare(Engine::Coraza), Next::Running(g) if g == a));

    commands.activate(b).unwrap();
    let Next::Ready {
        generation,
        mode,
        routes,
        kernel,
    } = switcher.prepare(Engine::Coraza)
    else {
        panic!("the chosen generation was not prepared");
    };
    assert_eq!((generation, mode), (b, Mode::Block));
    assert!(routes.is_empty());
    let kernel = *kernel;
    assert_eq!(kernel.rules, root.0.join("generations").join(b.hex()));
    assert_eq!(kernel.rules_sha256, b.bytes());
    // A second signal while the switch is under way is not taken, and both generations are held.
    assert!(matches!(switcher.prepare(Engine::Coraza), Next::Busy));
    let in_use = "the generation is used by a running proxy";
    assert_eq!(refusal(commands.remove(a)), in_use);
    assert_eq!(
        refusal(commands.remove(b)),
        "the generation is the current one"
    );
    commands.activate(a).unwrap();
    assert_eq!(refusal(commands.remove(b)), in_use);

    // The new generation serves: the old one is free, the new one is held.
    assert_eq!(switcher.running(Engine::Coraza), Some(a));
    switcher.finish(true);
    assert_eq!(switcher.running(Engine::Coraza), Some(b));
    commands.activate(b).unwrap();
    assert_eq!(commands.remove(a), Ok(()));
    assert!(matches!(switcher.prepare(Engine::Coraza), Next::Running(g) if g == b));
}

#[test]
fn the_mode_and_the_routes_of_the_generation_come_with_the_switch_and_a_manifest_that_cannot_be_read_refuses_it()
 {
    let root = scratch();
    let (mut commands, made) = made_in(&root.0, &["a"]);
    let path = BundlePath::parse("rules/d.conf").unwrap();
    let files = vec![(path.clone(), b"SecRuleEngine d\n".to_vec())];
    let table = Routes::new(vec![Route::new(Some("example.test"), "/static/").unwrap()]).unwrap();
    let detect = Bundle::new(
        Engine::Coraza,
        Mode::Detect,
        files,
        vec![path],
        table.clone(),
    )
    .unwrap();
    commands.stage(&detect).unwrap();
    commands.commit().unwrap();
    commands.activate(detect.fingerprint()).unwrap();
    let mut switcher = switcher(&root.0, made[0]);
    let Next::Ready { mode, routes, .. } = switcher.prepare(Engine::Coraza) else {
        panic!("the chosen generation was not prepared");
    };
    assert_eq!((mode, routes), (Mode::Detect, table));
    switcher.finish(false);

    let manifest = root
        .0
        .join("generations")
        .join(detect.fingerprint().hex())
        .join("manifest.json");
    fs::remove_file(manifest).unwrap();
    assert!(matches!(
        switcher.prepare(Engine::Coraza),
        Next::Refused("the manifest of the generation cannot be read")
    ));
}

#[test]
fn a_generation_of_an_engine_that_cannot_be_used_is_refused_by_the_switch_and_holds_nothing() {
    let root = scratch();
    let (mut commands, made) = made_in(&root.0, &["a"]);
    let path = BundlePath::parse("rules/m.conf").unwrap();
    let files = vec![(path.clone(), b"SecRuleEngine m\n".to_vec())];
    let other = Bundle::new(
        Engine::ModSecurity,
        Mode::Block,
        files,
        vec![path],
        Routes::default(),
    )
    .unwrap();
    commands.stage(&other).unwrap();
    commands.commit().unwrap();
    commands.activate(other.fingerprint()).unwrap();
    // The configuration has no inspector for the engine of the generation chosen for ModSecurity: the proxy goes on as
    // it is, and what is chosen for Coraza is the generation that runs.
    let mut switcher = switcher(&root.0, made[0]);
    assert!(matches!(
        switcher.prepare(Engine::ModSecurity),
        Next::Refused("kernel.engines has no inspector for the engine of the generation")
    ));
    assert!(matches!(switcher.prepare(Engine::Coraza), Next::Running(g) if g == made[0]));
    // The refusal left no hold: the generation can be removed once it is no longer chosen.
    assert_eq!(
        commands.deactivate(Engine::ModSecurity),
        Ok(Some(other.fingerprint()))
    );
    assert_eq!(commands.remove(other.fingerprint()), Ok(()));
}

#[test]
fn a_switch_that_did_not_happen_gives_the_new_generation_back() {
    let root = scratch();
    let (mut commands, made) = made_in(&root.0, &["a", "b"]);
    let (a, b) = (made[0], made[1]);
    let mut switcher = switcher(&root.0, a);
    commands.activate(b).unwrap();
    assert!(matches!(
        switcher.prepare(Engine::Coraza),
        Next::Ready { .. }
    ));
    switcher.finish(false);
    // The one that ran is held still, the new one is free to be removed.
    commands.activate(a).unwrap();
    assert_eq!(commands.remove(b), Ok(()));
    assert_eq!(
        refusal(commands.remove(a)),
        "the generation is the current one"
    );
    assert!(matches!(switcher.prepare(Engine::Coraza), Next::Running(g) if g == a));
}

#[test]
fn a_store_that_refuses_keeps_the_running_generation_and_holds_nothing() {
    let root = scratch();
    let (mut commands, made) = made_in(&root.0, &["a"]);
    let a = made[0];
    let mut switcher = switcher(&root.0, a);

    // A record that is broken, and a record of a generation that is not there.
    let record = root.0.join("current");
    fs::write(&record, "not a record\n").unwrap();
    assert!(matches!(
        switcher.prepare(Engine::Coraza),
        Next::Refused("the current generation record is broken")
    ));
    let gone = "f".repeat(64);
    fs::write(&record, format!("{gone}\n")).unwrap();
    assert!(matches!(
        switcher.prepare(Engine::Coraza),
        Next::Refused("the generation is not a real directory")
    ));
    // The refusal left no hold on the generation that is not there, and the next switch is not blocked.
    assert!(!root.0.join("using").join(&gone).exists());
    commands.activate(a).unwrap();
    assert!(matches!(switcher.prepare(Engine::Coraza), Next::Running(g) if g == a));
}

#[test]
fn there_is_one_switch_under_way_whatever_the_engine_and_an_engine_that_does_not_run_is_started_by_its_switch()
 {
    let root = scratch();
    let (mut commands, made) = made_in(&root.0, &["a", "b"]);
    let (a, b) = (made[0], made[1]);
    let path = BundlePath::parse("rules/m.conf").unwrap();
    let other = Bundle::new(
        Engine::ModSecurity,
        Mode::Block,
        vec![(path.clone(), b"SecRuleEngine m\n".to_vec())],
        vec![path],
        Routes::default(),
    )
    .unwrap();
    let m = other.fingerprint();
    commands.stage(&other).unwrap();
    commands.commit().unwrap();
    commands.activate(m).unwrap();
    let mut switcher = switcher_with_modsecurity(&root.0, a);

    // ModSecurity does not run, and the store chooses a generation for it: its switch starts the engine.
    assert_eq!(switcher.running(Engine::ModSecurity), None);
    assert_eq!(switcher.switching(), None);
    let Next::Ready {
        generation, kernel, ..
    } = switcher.prepare(Engine::ModSecurity)
    else {
        panic!("the engine was not prepared");
    };
    assert_eq!((generation, kernel.engine), (m, Engine::ModSecurity));
    assert_eq!(switcher.switching(), Some(Engine::ModSecurity));
    // Coraza has another generation chosen, and waits: one switch is under way, of whichever engine.
    commands.activate(b).unwrap();
    assert!(matches!(switcher.prepare(Engine::Coraza), Next::Busy));
    assert!(matches!(switcher.prepare(Engine::ModSecurity), Next::Busy));
    // The switch ends: ModSecurity runs the generation, Coraza runs as it did, and then Coraza's switch can begin.
    switcher.finish(true);
    assert_eq!(switcher.running(Engine::ModSecurity), Some(m));
    assert_eq!(switcher.running(Engine::Coraza), Some(a));
    assert_eq!(switcher.switching(), None);
    assert!(matches!(switcher.prepare(Engine::ModSecurity), Next::Running(g) if g == m));
    assert!(
        matches!(switcher.prepare(Engine::Coraza), Next::Ready { generation, .. } if generation == b)
    );
    switcher.finish(false);
    assert_eq!(switcher.running(Engine::Coraza), Some(a));

    // An engine that has no generation chosen is nothing to switch to.
    assert_eq!(commands.deactivate(Engine::ModSecurity), Ok(Some(m)));
    assert!(matches!(
        switcher.prepare(Engine::ModSecurity),
        Next::Unchosen
    ));
}

#[test]
fn the_default_engine_is_switched_first_and_the_others_follow_in_the_order_of_their_names() {
    let names =
        |first: Engine| -> Vec<&'static str> { engines_from(first).map(Engine::name).collect() };
    assert_eq!(names(Engine::Coraza), ["coraza", "modsecurity"]);
    assert_eq!(names(Engine::ModSecurity), ["modsecurity", "coraza"]);
}
