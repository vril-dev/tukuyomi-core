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
use crate::admin::server::listener::connection;
use crate::admin::server::tests::rig;

fn method(name: &str) -> Method {
    Method::from_bytes(name.as_bytes()).unwrap()
}

#[test]
fn each_file_answers_with_its_type_and_the_fields_of_the_page_and_needs_no_session() {
    let rig = rig();
    let version = &served().version;
    let js = "text/javascript; charset=utf-8";
    for (path, kind) in [
        ("/".to_owned(), "text/html; charset=utf-8"),
        (format!("/ui/{version}/app.css"), "text/css; charset=utf-8"),
        (format!("/ui/{version}/app.js"), js),
        (format!("/ui/{version}/api.js"), js),
        (format!("/ui/{version}/dom.js"), js),
        (format!("/ui/{version}/i18n.js"), js),
        (format!("/ui/{version}/waf.js"), js),
        (format!("/ui/{version}/parts.js"), js),
        (format!("/ui/{version}/table.js"), js),
        (format!("/ui/{version}/generations.js"), js),
        (format!("/ui/{version}/import.js"), js),
        (format!("/ui/{version}/records.js"), js),
        (format!("/ui/{version}/account.js"), js),
        (format!("/ui/{version}/users.js"), js),
        (format!("/ui/{version}/qr.js"), js),
        (format!("/ui/{version}/favicon.svg"), "image/svg+xml"),
    ] {
        // The page is not kept, as the next version is found in it; a file below its version never changes, so it is.
        let cache = if path == "/" {
            "no-store"
        } else {
            "public, max-age=31536000, immutable"
        };
        // No cookie, no token: the files hold no secret.
        for verb in ["GET", "HEAD"] {
            let answer = serve(&rig.app, &method(verb), &path).unwrap_or_else(|| panic!("{path}"));
            assert_eq!(answer.status(), StatusCode::OK, "{verb} {path}");
            assert!(
                answer.body().size_hint().exact().is_some_and(|n| n > 0),
                "{path}"
            );
            let fields = answer.headers();
            for (name, value) in [
                ("content-type", kind),
                ("cache-control", cache),
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
fn a_name_or_a_version_that_the_table_does_not_hold_is_left_to_the_api_which_answers_404() {
    let rig = rig();
    let version = &served().version;
    for path in [
        // No version.
        "/ui/app.js".to_owned(),
        // Another version, with the name of a file of the table.
        format!("/ui/{}/app.js", "0".repeat(16)),
        // The version, with no name, with a name that the table does not hold, and with a way out of its directory.
        format!("/ui/{version}"),
        format!("/ui/{version}/"),
        format!("/ui/{version}/nothing"),
        format!("/ui/{version}/../api/session"),
    ] {
        for verb in ["GET", "HEAD", "POST"] {
            assert!(
                serve(&rig.app, &method(verb), &path).is_none(),
                "{verb} {path}"
            );
        }
        let answer = rig.send("GET", &path, &[], "");
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{path}");
        assert!(answer.allow.is_none(), "{path}");
    }
}

#[test]
fn a_method_but_get_and_head_is_405_with_allow_and_the_fields_of_the_api() {
    let rig = rig();
    let version = &served().version;
    for path in [
        "/".to_owned(),
        format!("/ui/{version}/app.js"),
        format!("/ui/{version}/favicon.svg"),
    ] {
        for verb in ["POST", "PUT", "DELETE", "PATCH", "OPTIONS"] {
            let answer = serve(&rig.app, &method(verb), &path).unwrap_or_else(|| panic!("{path}"));
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
    let version = &served().version;
    // The page, with no session, and its fields. It is not kept, and it names the files below the version.
    let page = exchange(&app, "GET / HTTP/1.1\r\nHost: h\r\n\r\n");
    assert_eq!(page.status, 200);
    assert_eq!(page.values("content-type"), ["text/html; charset=utf-8"]);
    assert_eq!(page.values("cache-control"), ["no-store"]);
    assert_eq!(page.values("referrer-policy"), ["same-origin"]);
    let text = String::from_utf8(page.body).unwrap();
    assert_eq!(
        text,
        String::from_utf8_lossy(INDEX.bytes).replace("/ui/", &format!("/ui/{version}/"))
    );
    // Every path of the page that is below `/ui/` is below the version, and the page has some.
    assert!(text.contains(&format!("/ui/{version}/app.js")));
    assert_eq!(
        text.matches("/ui/").count(),
        text.matches(&format!("/ui/{version}/")).count()
    );
    // `HEAD` has the fields and no body.
    let head = exchange(
        &app,
        &format!("HEAD /ui/{version}/app.js HTTP/1.1\r\nHost: h\r\n\r\n"),
    );
    assert_eq!(head.status, 200);
    assert_eq!(
        head.values("content-type"),
        ["text/javascript; charset=utf-8"]
    );
    assert_eq!(
        head.values("cache-control"),
        ["public, max-age=31536000, immutable"]
    );
    assert!(head.body.is_empty());
    // A change of a file of the page is 405 with `Allow` at once, though the body that it announces never comes: the
    // page is answered before any body is read.
    let post = exchange(
        &app,
        &format!(
            "POST /ui/{version}/app.js HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\nContent-Length: 5\r\n\r\n"
        ),
    );
    assert_eq!(post.status, 405);
    assert_eq!(post.values("allow"), ["GET, HEAD"]);
    // A name that the table of the page does not hold, and a file with no version or with another one, are left to
    // the API, which answers 404 with its own fields.
    for target in [
        "/ui/nothing".to_owned(),
        "/ui/app.js".to_owned(),
        format!("/ui/{}/app.js", "0".repeat(16)),
        format!("/ui/{version}/nothing"),
    ] {
        let missing = exchange(&app, &format!("GET {target} HTTP/1.1\r\nHost: h\r\n\r\n"));
        assert_eq!(missing.status, 404, "{target}");
        assert_eq!(
            missing.values("referrer-policy"),
            ["no-referrer"],
            "{target}"
        );
        assert_eq!(
            missing.values("content-type"),
            ["application/json"],
            "{target}"
        );
        assert_eq!(missing.values("cache-control"), ["no-store"], "{target}");
    }
}

#[test]
fn the_version_follows_the_names_and_the_contents_of_the_files() {
    let file = |name: &'static str, bytes: &'static [u8]| File {
        name,
        kind: JAVASCRIPT,
        bytes,
    };
    let table = [file("a.js", b"one"), file("b.js", b"two")];
    let version = version_of(&table);
    // The first 16 digits, in lowercase.
    assert_eq!(version.len(), 16);
    assert!(
        version
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    assert_eq!(version_of(&table), version);
    // A byte of a file, the name of a file, and the files taking each other's contents change it.
    for changed in [
        [file("a.js", b"one"), file("b.js", b"twp")],
        [file("a.js", b"one"), file("c.js", b"two")],
        [file("a.js", b"two"), file("b.js", b"one")],
    ] {
        assert_ne!(version_of(&changed), version);
    }
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
