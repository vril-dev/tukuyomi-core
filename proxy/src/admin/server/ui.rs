//! The files of the admin page: `GET /` is the page, and `GET /ui/<version>/<name>` is its stylesheet, its scripts and
//! its icon. They are embedded in the executable from `proxy/admin-ui/` (the name of a script is its path below the
//! `js/` directory: `js/app.js` is `/ui/<version>/app.js`, and `js/waf/waf.js` is `/ui/<version>/waf/waf.js`), so
//! serving them reads no file of the host, and the page and the API are always of one version. A name that the table
//! below does not hold, and a version that is not the one of the table (no version at all included), whatever they look
//! like, are looked for nowhere: the request goes on to the table of the API, which answers 404 for it. A method but
//! `GET` and `HEAD` on the page or on a name of the table below its version is 405 with `Allow`, as for a route of the
//! API.
//!
//! The version is the first 16 digits of the SHA-256 of a list of the name and the SHA-256 of every file of the table
//! (as the fingerprint of a bundle is made of its manifest). It is made once, when the first request for the page or
//! for a file comes, and the page is made then too: the page of `proxy/admin-ui/` with each `/ui/` in it replaced by
//! `/ui/<version>/`. A path with a version always has the same content, so its files are kept for a year
//! (`immutable`); the page is `no-store`, so the next request for it finds the next version.
//!
//! No session is needed, as the files hold no secret. The fields of an answer are `FIELDS`, not those of the API: the
//! page may load its own scripts, styles and icon and call its own API, and nothing else; a script of the page cannot
//! make markup from a string (Trusted Types), so that a flaw in what the page shows does not become a script. The
//! referrer policy of the page is `same-origin`, not `no-referrer`: the Fetch standard has a browser send `Origin:
//! null` with a change (a request that is neither `GET` nor `HEAD`) when the policy is `no-referrer` and the mode is
//! not `cors`, and the API refuses that origin. The answers of the API keep the fields of `response`, with
//! `Referrer-Policy: no-referrer`.

use std::sync::OnceLock;

use bytes::Bytes;
use http::header::{CACHE_CONTROL, CONTENT_TYPE, HeaderName, HeaderValue};
use http::{Method, Response, StatusCode};
use http_body_util::Full;

use super::listener::response;
use super::{Answer, App};
use crate::rules::bundle::{hex, sha256};

const HTML: &str = "text/html; charset=utf-8";
const CSS: &str = "text/css; charset=utf-8";
const JAVASCRIPT: &str = "text/javascript; charset=utf-8";
const SVG: &str = "image/svg+xml";

/// `Cache-Control` of the page, which names the version of the files.
const NO_STORE: &str = "no-store";
/// `Cache-Control` of a file below its version, which never changes.
const IMMUTABLE: &str = "public, max-age=31536000, immutable";

/// The fields that every file of the page has besides its `Content-Type` and its `Cache-Control`.
const FIELDS: [(&str, &str); 6] = [
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
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",
    ),
];

/// A file of the page: its name below `/ui/`, its media type and its content.
struct File {
    name: &'static str,
    kind: &'static str,
    bytes: &'static [u8],
}

/// The page, which `/` answers.
static INDEX: File = File {
    name: "index.html",
    kind: HTML,
    bytes: include_bytes!("../../../admin-ui/index.html"),
};

/// The other files, below `/ui/<version>/`.
static FILES: [File; 31] = [
    File {
        name: "app.css",
        kind: CSS,
        bytes: include_bytes!("../../../admin-ui/app.css"),
    },
    File {
        name: "favicon.svg",
        kind: SVG,
        bytes: include_bytes!("../../../admin-ui/favicon.svg"),
    },
    File {
        name: "app.js",
        kind: JAVASCRIPT,
        bytes: include_bytes!("../../../admin-ui/js/app.js"),
    },
    File {
        name: "api.js",
        kind: JAVASCRIPT,
        bytes: include_bytes!("../../../admin-ui/js/api.js"),
    },
    File {
        name: "dom.js",
        kind: JAVASCRIPT,
        bytes: include_bytes!("../../../admin-ui/js/dom.js"),
    },
    File {
        name: "i18n.js",
        kind: JAVASCRIPT,
        bytes: include_bytes!("../../../admin-ui/js/i18n.js"),
    },
    File {
        name: "waf/waf.js",
        kind: JAVASCRIPT,
        bytes: include_bytes!("../../../admin-ui/js/waf/waf.js"),
    },
    File {
        name: "parts.js",
        kind: JAVASCRIPT,
        bytes: include_bytes!("../../../admin-ui/js/parts.js"),
    },
    File {
        name: "table.js",
        kind: JAVASCRIPT,
        bytes: include_bytes!("../../../admin-ui/js/table.js"),
    },
    File {
        name: "waf/generations.js",
        kind: JAVASCRIPT,
        bytes: include_bytes!("../../../admin-ui/js/waf/generations.js"),
    },
    File {
        name: "waf/import.js",
        kind: JAVASCRIPT,
        bytes: include_bytes!("../../../admin-ui/js/waf/import.js"),
    },
    File {
        name: "waf/records.js",
        kind: JAVASCRIPT,
        bytes: include_bytes!("../../../admin-ui/js/waf/records.js"),
    },
    File {
        name: "waf/words.js",
        kind: JAVASCRIPT,
        bytes: include_bytes!("../../../admin-ui/js/waf/words.js"),
    },
    File {
        name: "managed/managed.js",
        kind: JAVASCRIPT,
        bytes: include_bytes!("../../../admin-ui/js/managed/managed.js"),
    },
    File {
        name: "managed/screen.js",
        kind: JAVASCRIPT,
        bytes: include_bytes!("../../../admin-ui/js/managed/screen.js"),
    },
    File {
        name: "managed/job.js",
        kind: JAVASCRIPT,
        bytes: include_bytes!("../../../admin-ui/js/managed/job.js"),
    },
    File {
        name: "managed/history.js",
        kind: JAVASCRIPT,
        bytes: include_bytes!("../../../admin-ui/js/managed/history.js"),
    },
    File {
        name: "managed/words.js",
        kind: JAVASCRIPT,
        bytes: include_bytes!("../../../admin-ui/js/managed/words.js"),
    },
    File {
        name: "managed/edit/draft.js",
        kind: JAVASCRIPT,
        bytes: include_bytes!("../../../admin-ui/js/managed/edit/draft.js"),
    },
    File {
        name: "managed/edit/locate.js",
        kind: JAVASCRIPT,
        bytes: include_bytes!("../../../admin-ui/js/managed/edit/locate.js"),
    },
    File {
        name: "managed/edit/changes.js",
        kind: JAVASCRIPT,
        bytes: include_bytes!("../../../admin-ui/js/managed/edit/changes.js"),
    },
    File {
        name: "managed/edit/pem.js",
        kind: JAVASCRIPT,
        bytes: include_bytes!("../../../admin-ui/js/managed/edit/pem.js"),
    },
    File {
        name: "managed/edit/form.js",
        kind: JAVASCRIPT,
        bytes: include_bytes!("../../../admin-ui/js/managed/edit/form.js"),
    },
    File {
        name: "managed/edit/bar.js",
        kind: JAVASCRIPT,
        bytes: include_bytes!("../../../admin-ui/js/managed/edit/bar.js"),
    },
    File {
        name: "managed/edit/upstreams.js",
        kind: JAVASCRIPT,
        bytes: include_bytes!("../../../admin-ui/js/managed/edit/upstreams.js"),
    },
    File {
        name: "managed/edit/policy.js",
        kind: JAVASCRIPT,
        bytes: include_bytes!("../../../admin-ui/js/managed/edit/policy.js"),
    },
    File {
        name: "managed/edit/words.js",
        kind: JAVASCRIPT,
        bytes: include_bytes!("../../../admin-ui/js/managed/edit/words.js"),
    },
    File {
        name: "account/account.js",
        kind: JAVASCRIPT,
        bytes: include_bytes!("../../../admin-ui/js/account/account.js"),
    },
    File {
        name: "account/users.js",
        kind: JAVASCRIPT,
        bytes: include_bytes!("../../../admin-ui/js/account/users.js"),
    },
    File {
        name: "account/qr.js",
        kind: JAVASCRIPT,
        bytes: include_bytes!("../../../admin-ui/js/account/qr.js"),
    },
    File {
        name: "account/words.js",
        kind: JAVASCRIPT,
        bytes: include_bytes!("../../../admin-ui/js/account/words.js"),
    },
];

/// The version of the files of `files`: the first 16 digits of the SHA-256 of the list of the name and the SHA-256 of
/// each of them, in the order of the table.
fn version_of(files: &[File]) -> String {
    let mut list = String::new();
    for file in files {
        list.push_str(file.name);
        list.push('\n');
        list.push_str(&hex(&sha256(file.bytes)));
        list.push('\n');
    }
    hex(&sha256(list.as_bytes())[..8])
}

/// What is made of the table once: its version, and the page with that version in the paths of its files.
struct Served {
    version: String,
    index: Bytes,
}

static SERVED: OnceLock<Served> = OnceLock::new();

/// The version and the page, made when they are first asked for.
fn served() -> &'static Served {
    SERVED.get_or_init(|| {
        let version = version_of(&FILES);
        let index =
            String::from_utf8_lossy(INDEX.bytes).replace("/ui/", &format!("/ui/{version}/"));
        Served {
            version,
            index: Bytes::from(index),
        }
    })
}

/// The answer for a request of the page, or none when `path` is not the page or a file of the table below its
/// version (then the table of the API answers it). `HEAD` is answered as `GET`; hyper leaves the body out.
pub(super) fn serve(app: &App, method: &Method, path: &str) -> Option<Response<Full<Bytes>>> {
    let (kind, body, cache) = if path == "/" {
        (INDEX.kind, served().index.clone(), NO_STORE)
    } else {
        let (version, name) = path.strip_prefix("/ui/")?.split_once('/')?;
        if version != served().version {
            return None;
        }
        let file = FILES.iter().find(|file| file.name == name)?;
        (file.kind, Bytes::from_static(file.bytes), IMMUTABLE)
    };
    if !matches!(*method, Method::GET | Method::HEAD) {
        let mut answer = Answer::error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
        answer.allow = Some("GET, HEAD".to_owned());
        answer.request = app.ids.mint();
        return Some(response(&answer));
    }
    let mut page = Response::new(Full::new(body));
    let fields = page.headers_mut();
    fields.insert(CONTENT_TYPE, HeaderValue::from_static(kind));
    fields.insert(CACHE_CONTROL, HeaderValue::from_static(cache));
    for (name, value) in FIELDS {
        fields.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
    Some(page)
}

#[cfg(test)]
mod tests;
