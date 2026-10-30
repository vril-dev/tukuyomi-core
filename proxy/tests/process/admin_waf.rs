//! The routes of the rules in real processes: the proxy with a control socket, a record file and the status
//! listener, and the admin process over the same configuration and the same rules store. An owner is made with
//! `admin bootstrap` and logs in. A second generation is imported from uploaded rule files (the real inspector
//! tries it), activated (the proxy switches, which its `/metrics` and a request show), found in the history and
//! rolled back. The record of a request of the proxy is found by its number through the API. A second test, with no
//! proxy, shows that a generation of an engine that this build cannot use is refused by the import and the activation.

use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::time::Instant;

use serde_json::{Value, json};

use crate::admin::{Admin, OWNER, add_admin, bootstrap, cookie_of, json_of};
use crate::engines::{NOT_PINNED, add_generation, current, name_inspector};
use crate::support::*;

/// `data` in the standard base64 with padding.
fn b64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let bits = chunk.iter().enumerate().fold(0u32, |bits, (at, byte)| {
            bits | u32::from(*byte) << (16 - 8 * at)
        });
        for at in 0..4 {
            if at <= chunk.len() {
                out.push(char::from(ALPHABET[(bits >> (18 - 6 * at)) as usize & 63]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A user who is logged in to the admin process.
struct Session<'a> {
    admin: &'a Admin,
    cookie: String,
    csrf: String,
}

impl Session<'_> {
    fn get(&self, path: &str) -> Value {
        let answer = self
            .admin
            .call("GET", path, &[("Cookie", &self.cookie)], "");
        let text = String::from_utf8_lossy(&answer.body).into_owned();
        assert_eq!(answer.status(), 200, "{path}: {text}");
        json_of(&answer)
    }

    /// A change, with its status and the JSON of the answer.
    fn post(&self, path: &str, body: &Value) -> (u16, Value) {
        let fields = [
            ("Content-Type", "application/json"),
            ("Cookie", self.cookie.as_str()),
            ("X-CSRF-Token", self.csrf.as_str()),
        ];
        let answer = self.admin.call("POST", path, &fields, &body.to_string());
        (answer.status(), json_of(&answer))
    }

    /// The generation that the proxy serves, by its control socket.
    fn serving(&self) -> String {
        let status = self.get("/api/status");
        assert_eq!(status["reachable"], true);
        status["proxy"]["generation"].as_str().unwrap().to_owned()
    }
}

fn metrics(port: u16) -> String {
    let reply = exchange(port, &get("/metrics"));
    String::from_utf8(reply.message().body.clone()).expect("the page is text")
}

fn has_line(text: &str, line: &str) -> bool {
    text.lines().any(|have| have == line)
}

/// A directory beside the root of the test, removed with what it holds when it is dropped. The records are kept in
/// one: the proxy writes to them until it has exited, and the root may hold only the configuration and the store at
/// the end of the test.
struct Beside(PathBuf);

impl Drop for Beside {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn private_dirs(root: &std::path::Path, names: &[&str]) {
    for name in names {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(root.join(name))
            .expect("make a directory of the test");
    }
}

#[test]
#[ignore = "needs a built inspector"]
fn an_owner_imports_activates_and_rolls_back_a_generation_and_finds_the_record_of_a_request() {
    let (status_port, admin_port) = (free_port(), free_port());
    let records_dir = PathBuf::from(std::env::var("TUKUYOMI_TEST_TMP").expect("TUKUYOMI_TEST_TMP"))
        .join(format!("admin_waf-records-{}", std::process::id()));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&records_dir)
        .expect("make the directory of the records");
    let _records = Beside(records_dir.clone());
    let mut proxy = Proxy::start_with("admin_waf", Knobs::quick(), |root| {
        private_dirs(root, &["ctl", "admin"]);
        add_object(
            root,
            "status",
            json!({"listen": format!("127.0.0.1:{status_port}")}),
        );
        add_object(
            root,
            "records",
            json!({"dir": records_dir.to_string_lossy(), "file_bytes": 1 << 20, "files": 2}),
        );
        add_object(
            root,
            "admin",
            json!({
                "listen": format!("127.0.0.1:{admin_port}"),
                "control": root.join("ctl").join("c.sock").to_string_lossy(),
                "store": {"kind": "file", "dir": root.join("admin").to_string_lossy()},
                "origin": "https://admin.example.test",
                "trusted_proxies": [],
                "mfa": "optional",
                "session_idle_ms": 1_800_000,
                "session_total_ms": 43_200_000,
            }),
        );
    });
    let root = proxy.root().to_path_buf();
    let made = bootstrap(&root, "alice", &format!("{OWNER}\n"));
    assert_eq!(made.code, Some(0), "{}", made.err);
    let mut admin = Admin::start(&root, admin_port);
    let login = admin.call(
        "POST",
        "/api/login",
        &[("Content-Type", "application/json")],
        &json!({"name": "alice", "password": OWNER}).to_string(),
    );
    assert_eq!(login.status(), 200);
    let (cookie, csrf) = (
        cookie_of(&login),
        json_of(&login)["csrf"].as_str().unwrap().to_owned(),
    );
    let first = generation();
    {
        let session = Session {
            admin: &admin,
            cookie: cookie.clone(),
            csrf,
        };

        // The generation of the store is the one that the proxy serves.
        let list = session.get("/api/generations");
        let items = list["generations"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["fingerprint"], first.as_str());
        assert_eq!(
            (&items[0]["current"], &items[0]["serving"]),
            (&json!(true), &json!(true))
        );
        assert_eq!(session.serving(), first);
        assert_eq!(exchange(proxy.port, &get("/reload-probe")).status(), 200);

        // The test rules and one more are uploaded: the real inspector tries them, and they are a generation that
        // is not chosen. The same files again are the same generation.
        let extra = "SecRule REQUEST_URI \"@beginsWith /reload-probe\" \"id:9204,phase:1,deny,status:403,log,msg:'reload probe'\"\n";
        let body = json!({"rules": [
            {"name": "basic.conf", "data": b64(&fs::read(rules_file()).unwrap())},
            {"name": "extra.conf", "data": b64(extra.as_bytes())},
        ]});
        let (status, imported) = session.post("/api/generations", &body);
        assert_eq!(status, 200, "{imported}");
        assert_eq!(
            (&imported["result"], &imported["trial"]["passed"]),
            (&json!("created"), &json!(true))
        );
        let second = imported["fingerprint"].as_str().unwrap().to_owned();
        assert_ne!(second, first);
        assert_eq!(
            session.post("/api/generations", &body).1["result"],
            "existing"
        );
        assert_eq!(session.get("/api/status")["current"], first.as_str());
        let one = session.get(&format!("/api/generations/{second}"));
        assert_eq!(one["load"], json!(["rules/basic.conf", "rules/extra.conf"]));

        // A wrong expect changes nothing. The right one switches, and the proxy says so.
        let (status, refused) = session.post(
            "/api/activate",
            &json!({"generation": second, "expect": second}),
        );
        assert_eq!(status, 409, "{refused}");
        assert_eq!(session.serving(), first);
        let before = proxy.inspector();
        let (status, switched) = session.post(
            "/api/activate",
            &json!({"generation": second, "expect": first}),
        );
        assert_eq!(status, 200, "{switched}");
        assert_eq!(switched["result"], "switched");
        proxy.wait_inspector(Some(before));
        assert_eq!(session.serving(), second);
        let page = metrics(status_port);
        for line in [
            "tukuyomi_rules_switches_total{result=\"switched\"} 1".to_owned(),
            format!(
                "tukuyomi_rules_generation_info{{generation=\"{}\",mode=\"block\",engine=\"coraza\"}} 1",
                &second[..16]
            ),
        ] {
            assert!(has_line(&page, &line), "{line} in {page}");
        }
        assert_eq!(exchange(proxy.port, &get("/reload-probe")).status(), 403);
        let history = session.get("/api/history");
        let newest = &history["entries"][0];
        assert_eq!(
            (
                &newest["actor"],
                &newest["from"],
                &newest["to"],
                &newest["kind"],
                &newest["result"]
            ),
            (
                &json!("alice"),
                &json!(first),
                &json!(second),
                &json!("activate"),
                &json!("switched")
            )
        );

        // The way back goes to the generation before the last switch.
        let before = proxy.inspector();
        let (status, back) = session.post("/api/rollback", &json!({"expect": second}));
        assert_eq!(status, 200, "{back}");
        assert_eq!(
            (&back["result"], &back["generation"]),
            (&json!("switched"), &json!(first))
        );
        proxy.wait_inspector(Some(before));
        assert_eq!(session.serving(), first);
        assert_eq!(exchange(proxy.port, &get("/reload-probe")).status(), 200);
        assert!(has_line(
            &metrics(status_port),
            "tukuyomi_rules_switches_total{result=\"switched\"} 2"
        ));

        // The record of a request is found by the number that the answer to the client carried, and the block of
        // the switched generation by its rule.
        let reply = exchange(proxy.port, &get("/ok"));
        assert_eq!(reply.status(), 200);
        let message = reply.message();
        let id = message.values("x-request-id")[0].to_owned();
        let by = Instant::now() + MARGIN;
        let found = loop {
            let found = session.get(&format!("/api/records?id={id}"));
            if !found["records"].as_array().unwrap().is_empty() {
                break found;
            }
            assert!(Instant::now() < by, "the record of {id} is not found");
            std::thread::sleep(20 * MS);
        };
        let record = &found["records"][0];
        assert_eq!(
            (&record["id"], &record["status"], &record["generation"]),
            (&json!(id), &json!(200), &json!(first[..16]))
        );
        let blocked = session.get("/api/records?rule=9204&status=403");
        assert_eq!(blocked["records"].as_array().unwrap().len(), 1, "{blocked}");
        assert_eq!(blocked["records"][0]["generation"], second[..16]);

        // The audit log has the three changes with the user.
        let audit = session.get("/api/audit");
        for action in ["import", "activate", "rollback"] {
            assert!(
                audit["entries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|e| e["action"] == action && e["result"] == "ok" && e["actor"] == "alice"),
                "{action} in {audit}"
            );
        }

        // A body over the usual limit is read for a client with a session only, and 12 MiB are the most.
        let import = |length: usize, with_session: bool| {
            let mut head = format!(
                "POST /api/generations HTTP/1.1\r\nHost: admin.example.test\r\nContent-Type: application/json\r\nContent-Length: {length}\r\n"
            );
            if with_session {
                head.push_str(&format!(
                    "Cookie: {cookie}\r\nX-CSRF-Token: {}\r\n",
                    session.csrf
                ));
            }
            head.push_str("\r\n");
            exchange(admin_port, head.as_bytes()).status()
        };
        assert_eq!(import((12 << 20) + 1, true), 413);
        assert_eq!(import(100_000, false), 401);
        let login_head = "POST /api/login HTTP/1.1\r\nHost: admin.example.test\r\nContent-Type: application/json\r\nContent-Length: 100000\r\n\r\n";
        assert_eq!(exchange(admin_port, login_head.as_bytes()).status(), 413);
    }

    // The admin process stops with exit code 0, and then the proxy, as every proxy test ends: the socket goes before
    // the proxy has exited, and nothing but the configuration and the store is left in the root.
    assert_eq!(admin.stop().code(), Some(0));
    fs::remove_dir_all(root.join("admin")).expect("remove the store of the admin process");
    let since = proxy.term();
    let socket = root.join("ctl").join("c.sock");
    let by = Instant::now() + MARGIN;
    while fs::symlink_metadata(&socket).is_ok() {
        assert!(Instant::now() < by, "the socket is still there");
        std::thread::sleep(10 * MS);
    }
    fs::remove_dir(root.join("ctl")).expect("the directory of the socket is empty");
    let counts = proxy.finish_after_term(since, 3);
    assert_eq!(counts, [0, 0, 0], "the kernel held something at the stop");
}

#[test]
#[ignore = "needs a built inspector"]
fn a_generation_of_an_engine_that_cannot_be_used_is_refused_by_the_import_and_the_activation() {
    // No proxy runs, so an activation that got past the check of the engine would be 503, not 409.
    let port = free_port();
    let idle = Idle::new("admin_engine", &Knobs::quick(), |root| {
        add_admin(root, port);
        name_inspector(root);
    });
    let root = idle.root();
    let other = add_generation(root);
    let (first, chosen) = (generation(), current(root));
    let made = bootstrap(root, "alice", &format!("{OWNER}\n"));
    assert_eq!(made.code, Some(0), "{}", made.err);
    let mut admin = Admin::start(root, port);
    let login = admin.call(
        "POST",
        "/api/login",
        &[("Content-Type", "application/json")],
        &json!({"name": "alice", "password": OWNER}).to_string(),
    );
    assert_eq!(login.status(), 200);
    {
        let session = Session {
            admin: &admin,
            cookie: cookie_of(&login),
            csrf: json_of(&login)["csrf"].as_str().unwrap().to_owned(),
        };
        let engines = || -> Vec<(String, String)> {
            let list = session.get("/api/generations");
            let text = |g: &Value, key: &str| g[key].as_str().unwrap().to_owned();
            let items = list["generations"].as_array().unwrap();
            items
                .iter()
                .map(|g| (text(g, "fingerprint"), text(g, "engine")))
                .collect()
        };
        let before = engines();
        assert_eq!(before.len(), 2, "{before:?}");
        for (name, engine) in [(&first, "coraza"), (&other, "modsecurity")] {
            assert!(
                before.contains(&(name.clone(), engine.to_owned())),
                "{before:?}"
            );
        }

        // An import of that engine is 400 with the sentence, before anything is staged or tried: no generation.
        let body = json!({
            "rules": [{"name": "basic.conf", "data": b64(&fs::read(rules_file()).unwrap())}],
            "engine": "modsecurity",
        });
        let (status, refused) = session.post("/api/generations", &body);
        assert_eq!(status, 400, "{refused}");
        assert_eq!(refused["error"], NOT_PINNED);
        assert_eq!(engines(), before);

        // An activation of the one that is in the store is 409 with the sentence, and the store still chooses the
        // generation it chose.
        let (status, refused) = session.post(
            "/api/activate",
            &json!({"generation": other, "expect": first}),
        );
        assert_eq!(status, 409, "{refused}");
        assert_eq!(refused["error"], NOT_PINNED);
        assert_eq!(current(root), chosen);
        assert_eq!(session.get("/api/status")["current"], first.as_str());
        let audit = session.get("/api/audit");
        assert!(
            audit["entries"].as_array().unwrap().iter().any(|e| {
                e["action"] == "activate"
                    && e["result"] == "denied"
                    && e["reason"] == "engine"
                    && e["actor"] == "alice"
            }),
            "{audit}"
        );
    }
    assert_eq!(admin.stop().code(), Some(0));
}
