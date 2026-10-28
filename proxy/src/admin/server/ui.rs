//! The files of the admin page: `GET /` is the page, and `GET /ui/<name>` is its stylesheet, its scripts and its
//! icon. They are embedded in the executable from `proxy/admin-ui/` (the files of its `js/` directory are served flat:
//! `js/app.js` is `/ui/app.js`), so serving them reads no file of the host, and the page and the API are always of one
//! version. A name that the table below does not hold, whatever it looks like, is looked for nowhere: the request goes
//! on to the table of the API, which answers 404 for it. A method but `GET` and `HEAD` on a name of the table is 405
//! with `Allow`, as for a route of the API.
//!
//! No session is needed, as the files hold no secret. The fields of an answer are `FIELDS`, not those of the API: the
//! page may load its own scripts, styles and icon and call its own API, and nothing else; a script of the page cannot
//! make markup from a string (Trusted Types), so that a flaw in what the page shows does not become a script. The
//! referrer policy of the page is `same-origin`, not `no-referrer`: the Fetch standard has a browser send `Origin:
//! null` with a change (a request that is neither `GET` nor `HEAD`) when the policy is `no-referrer` and the mode is
//! not `cors`, and the API refuses that origin. The answers of the API keep the fields of `response`, with
//! `Referrer-Policy: no-referrer`.

use bytes::Bytes;
use http::header::{CONTENT_TYPE, HeaderName, HeaderValue};
use http::{Method, Response, StatusCode};
use http_body_util::Full;

use super::{Answer, App, response};

const HTML: &str = "text/html; charset=utf-8";
const CSS: &str = "text/css; charset=utf-8";
const JAVASCRIPT: &str = "text/javascript; charset=utf-8";
const SVG: &str = "image/svg+xml";

/// The fields that every file of the page has besides its `Content-Type`.
const FIELDS: [(&str, &str); 7] = [
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

/// The other files, below `/ui/`.
static FILES: [File; 7] = [
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
        name: "waf.js",
        kind: JAVASCRIPT,
        bytes: include_bytes!("../../../admin-ui/js/waf.js"),
    },
];

/// The answer for a request of the page, or none when `path` is not a file of the table (then the table of the API
/// answers it). `HEAD` is answered as `GET`; hyper leaves the body out.
pub(super) fn serve(app: &App, method: &Method, path: &str) -> Option<Response<Full<Bytes>>> {
    let file = if path == "/" {
        &INDEX
    } else {
        let name = path.strip_prefix("/ui/")?;
        FILES.iter().find(|file| file.name == name)?
    };
    if !matches!(*method, Method::GET | Method::HEAD) {
        let mut answer = Answer::error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
        answer.allow = Some("GET, HEAD".to_owned());
        answer.request = app.ids.mint();
        return Some(response(&answer));
    }
    let mut page = Response::new(Full::new(Bytes::from_static(file.bytes)));
    let fields = page.headers_mut();
    fields.insert(CONTENT_TYPE, HeaderValue::from_static(file.kind));
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
