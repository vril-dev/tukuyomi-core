use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use http_body::Body;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use super::*;
use crate::admin::server::connection;
use crate::admin::server::tests::rig;

fn method(name: &str) -> Method {
    Method::from_bytes(name.as_bytes()).unwrap()
}

#[test]
fn each_file_answers_with_its_type_and_the_fields_of_the_page_and_needs_no_session() {
    let rig = rig();
    for (path, kind) in [
        ("/", "text/html; charset=utf-8"),
        ("/ui/app.css", "text/css; charset=utf-8"),
        ("/ui/app.js", "text/javascript; charset=utf-8"),
        ("/ui/api.js", "text/javascript; charset=utf-8"),
        ("/ui/dom.js", "text/javascript; charset=utf-8"),
        ("/ui/i18n.js", "text/javascript; charset=utf-8"),
        ("/ui/waf.js", "text/javascript; charset=utf-8"),
        ("/ui/parts.js", "text/javascript; charset=utf-8"),
        ("/ui/generations.js", "text/javascript; charset=utf-8"),
        ("/ui/import.js", "text/javascript; charset=utf-8"),
        ("/ui/records.js", "text/javascript; charset=utf-8"),
        ("/ui/account.js", "text/javascript; charset=utf-8"),
        ("/ui/users.js", "text/javascript; charset=utf-8"),
        ("/ui/qr.js", "text/javascript; charset=utf-8"),
        ("/ui/favicon.svg", "image/svg+xml"),
    ] {
        // No cookie, no token: the files hold no secret.
        for verb in ["GET", "HEAD"] {
            let answer = serve(&rig.app, &method(verb), path).unwrap_or_else(|| panic!("{path}"));
            assert_eq!(answer.status(), StatusCode::OK, "{verb} {path}");
            assert!(
                answer.body().size_hint().exact().is_some_and(|n| n > 0),
                "{path}"
            );
            let fields = answer.headers();
            for (name, value) in [
                ("content-type", kind),
                ("cache-control", "no-store"),
                ("x-content-type-options", "nosniff"),
                (
                    "content-security-policy",
                    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; \
                     base-uri 'none'; form-action 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'",
                ),
                ("referrer-policy", "same-origin"),
                ("cross-origin-opener-policy", "same-origin"),
                ("cross-origin-resource-policy", "same-origin"),
                (
                    "permissions-policy",
                    "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), \
                     payment=(), usb=()",
                ),
            ] {
                assert_eq!(fields.get_all(name).iter().count(), 1, "{path} {name}");
                assert_eq!(fields[name], value, "{path} {name}");
            }
            assert!(fields.get("set-cookie").is_none(), "{path}");
        }
    }
}

#[test]
fn a_name_that_the_table_does_not_hold_is_left_to_the_api_which_answers_404() {
    let rig = rig();
    for path in [
        "/ui",
        "/ui/",
        "/ui/nothing",
        "/ui/index.html",
        "/ui/js/app.js",
        "/ui/js/",
        "/ui/..",
        "/ui/../api/session",
        "/ui/%2e%2e/app.js",
        "/ui/app.js/",
        "/ui/app.js%00",
        "/ui/APP.JS",
        "/UI/app.js",
        "/index.html",
        "/app.js",
        "//",
    ] {
        for verb in ["GET", "HEAD", "POST"] {
            assert!(
                serve(&rig.app, &method(verb), path).is_none(),
                "{verb} {path}"
            );
        }
        let answer = rig.send("GET", path, &[], "");
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{path}");
        assert!(answer.allow.is_none(), "{path}");
    }
}

#[test]
fn a_method_but_get_and_head_is_405_with_allow_and_the_fields_of_the_api() {
    let rig = rig();
    for path in ["/", "/ui/app.js", "/ui/favicon.svg"] {
        for verb in ["POST", "PUT", "DELETE", "PATCH", "OPTIONS"] {
            let answer = serve(&rig.app, &method(verb), path).unwrap_or_else(|| panic!("{path}"));
            assert_eq!(
                answer.status(),
                StatusCode::METHOD_NOT_ALLOWED,
                "{verb} {path}"
            );
            let fields = answer.headers();
            assert_eq!(fields["allow"], "GET, HEAD");
            assert_eq!(fields["content-type"], "application/json");
            assert_eq!(fields["referrer-policy"], "no-referrer");
            assert_eq!(
                fields["content-security-policy"],
                "default-src 'none'; frame-ancestors 'none'"
            );
            assert!(fields.contains_key("x-request-id"));
            assert!(fields.get("cross-origin-opener-policy").is_none());
        }
    }
    // The fields of the API are not those of the page.
    let api = response(&Answer::error(StatusCode::NOT_FOUND, "not found"));
    for name in [
        "cross-origin-opener-policy",
        "cross-origin-resource-policy",
        "permissions-policy",
    ] {
        assert!(api.headers().get(name).is_none(), "{name}");
    }
    assert_eq!(
        api.headers()["content-security-policy"],
        "default-src 'none'; frame-ancestors 'none'"
    );
}

/// An answer that a client read from a real connection.
struct Reply {
    status: u16,
    /// The fields, by lowercase name.
    fields: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Reply {
    fn values(&self, name: &str) -> Vec<&str> {
        let same = |(field, _): &&(String, String)| field == name;
        self.fields
            .iter()
            .filter(same)
            .map(|(_, value)| value.as_str())
            .collect()
    }
}

/// Writes `request` on a real connection that is served as the admin process serves it (`connection`: hyper, then
/// `answer`), reads until the server closes it, and parses the answer. Nothing but `request` is ever written, so a
/// server that waits for a body that was announced does not answer within the time given.
fn exchange(app: &Arc<App>, request: &str) -> Reply {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let raw = runtime.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, peer) = listener.accept().await.unwrap();
        let served = tokio::spawn(connection(stream, peer, app.clone()));
        client.write_all(request.as_bytes()).await.unwrap();
        let mut raw = Vec::new();
        timeout(Duration::from_secs(5), client.read_to_end(&mut raw))
            .await
            .expect("the answer came before the body of the request")
            .unwrap();
        served.await.unwrap();
        raw
    });
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("the end of the head");
    let head = String::from_utf8(raw[..split].to_vec()).unwrap();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse().ok())
        .expect("a status");
    let fields = lines
        .map(|line| {
            let (name, value) = line.split_once(": ").expect("a field");
            (name.to_ascii_lowercase(), value.to_owned())
        })
        .collect();
    Reply {
        status,
        fields,
        body: raw[split + 4..].to_vec(),
    }
}

#[test]
fn the_page_is_answered_on_a_real_connection_before_any_body_is_read() {
    let rig = rig();
    let app = Arc::new(rig.app);
    // The page, with no session, and its fields.
    let page = exchange(&app, "GET / HTTP/1.1\r\nHost: h\r\n\r\n");
    assert_eq!(page.status, 200);
    assert_eq!(page.values("content-type"), ["text/html; charset=utf-8"]);
    assert_eq!(page.values("referrer-policy"), ["same-origin"]);
    assert_eq!(page.body, INDEX.bytes);
    // `HEAD` has the fields and no body.
    let head = exchange(&app, "HEAD /ui/app.js HTTP/1.1\r\nHost: h\r\n\r\n");
    assert_eq!(head.status, 200);
    assert_eq!(
        head.values("content-type"),
        ["text/javascript; charset=utf-8"]
    );
    assert!(head.body.is_empty());
    // A change of a file of the page is 405 with `Allow` at once, though the body that it announces never comes: the
    // page is answered before any body is read.
    let post = exchange(
        &app,
        "POST /ui/app.js HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\nContent-Length: 5\r\n\r\n",
    );
    assert_eq!(post.status, 405);
    assert_eq!(post.values("allow"), ["GET, HEAD"]);
    // A name that the table of the page does not hold is left to the API, which answers 404 with its own fields.
    let missing = exchange(&app, "GET /ui/nothing HTTP/1.1\r\nHost: h\r\n\r\n");
    assert_eq!(missing.status, 404);
    assert_eq!(missing.values("referrer-policy"), ["no-referrer"]);
    assert_eq!(missing.values("content-type"), ["application/json"]);
}

/// The names of the files (not the directories) in `dir`.
fn names(dir: &Path) -> BTreeSet<String> {
    fs::read_dir(dir)
        .unwrap()
        .map(Result::unwrap)
        .filter(|entry| entry.file_type().unwrap().is_file())
        .map(|entry| entry.file_name().into_string().unwrap())
        .collect()
}

#[test]
fn the_table_holds_every_file_of_the_directory_of_the_page() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("admin-ui");
    let mut on_disk = names(&root);
    on_disk.extend(names(&root.join("js")));
    let served: BTreeSet<String> = std::iter::once(INDEX.name)
        .chain(FILES.iter().map(|file| file.name))
        .map(str::to_owned)
        .collect();
    assert_eq!(served, on_disk);
}
