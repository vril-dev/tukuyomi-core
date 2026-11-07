//! The values of the main file, `GET /api/config`: what the operator wrote in the file the proxy follows, as it is now,
//! for a main file with `managed` or without it.
//!
//! The file is read again for each request, and the answer is made only of a file that passes every check of the main
//! file (see `config`); one that cannot be read or is refused is 409, with its sentence. The answer is `{"sha256",
//! "managed", ...}`: the SHA-256 of the bytes of the file (the one that the proxy shows in `/api/status` once it has
//! read them), whether the file has `managed`, and the keys of the file with the names and the forms that the file
//! writes them in. Each key is shown as a fixed list says (`TOP`), and a key that is not in the list is not shown: a
//! value that holds no path is given as it is; a path (of a certificate, a key, a file of authorities, a directory, an
//! inspector, a socket, a database file) is `true` when the file writes it and `null` when it leaves it out, and never
//! its text, as the state of the rules shows the directory of the CRS. The answer is for an operator, for a route may
//! write a secret for the upstream in its `rewrite`, and the file names the addresses of the servers and of the
//! listeners.

use http::StatusCode;
use serde_json::{Map, Value};

use super::routes::{Managed, conflict};
use crate::admin::server::Answer;
use crate::config;
use crate::rules::bundle::hex;

/// How a key of the main file is shown.
enum Shown {
    /// As it is: a value that holds no path.
    Plain,
    /// A path: `true` when it is written, else `null`.
    Path,
    /// An object, with the keys of the list shown as each says and no other.
    Object(&'static [(&'static str, Shown)]),
    /// A list, each entry shown as this says.
    Each(&'static Shown),
    /// An object of names (the upstream groups), each value shown as this says.
    Named(&'static Shown),
}

use Shown::{Each, Named, Object, Path, Plain};

/// The keys of the main file and how each is shown (see `config` and its parts for what they are), but `managed`,
/// which the answer shows as whether the file has it.
static TOP: Shown = Object(&[
    (
        "proxy",
        Object(&[
            (
                "listeners",
                Each(&Object(&[
                    ("address", Plain),
                    (
                        "tls",
                        Object(&[
                            ("min_version", Plain),
                            (
                                "certificates",
                                Each(&Object(&[
                                    ("cert_file", Path),
                                    ("key_file", Path),
                                    ("hosts", Plain),
                                    ("acme", Plain),
                                ])),
                            ),
                            ("http2", Plain),
                        ]),
                    ),
                    ("redirect", Plain),
                ])),
            ),
            ("max_conns", Plain),
            ("max_head_bytes", Plain),
            ("max_body", Plain),
            ("inspect_body", Plain),
            ("max_body_wire", Plain),
            ("max_buffered_bytes", Plain),
            ("upstream_max_headers", Plain),
            ("upstream_max_head_bytes", Plain),
            ("upstream_head_wire", Plain),
            ("drive_slice_ms", Plain),
            ("ready_wait_ms", Plain),
            ("head_read_ms", Plain),
            ("body_read_ms", Plain),
            ("inspect_wait_ms", Plain),
            ("upstream_connect_ms", Plain),
            ("upstream_header_ms", Plain),
            ("request_total_ms", Plain),
            ("response_idle_ms", Plain),
            ("conn_total_ms", Plain),
            ("stop_inspect_ms", Plain),
            ("stop_wait_ms", Plain),
            ("keepalive_timeout_ms", Plain),
            ("keepalive_requests", Plain),
            ("keepalive_time_ms", Plain),
            ("lingering_time_ms", Plain),
            ("lingering_timeout_ms", Plain),
            ("lingering_bytes", Plain),
            ("trusted_proxies", Plain),
            ("upstream_keepalive", Plain),
            ("upstream_keepalive_timeout_ms", Plain),
            ("upstream_keepalive_requests", Plain),
        ]),
    ),
    (
        "forward",
        Object(&[
            ("resolve_timeout_ms", Plain),
            (
                "upstreams",
                Named(&Object(&[
                    ("servers", Plain),
                    ("tls", Object(&[("ca_file", Path), ("server_name", Plain)])),
                ])),
            ),
            ("routes", Plain),
            ("default_upstream", Plain),
        ]),
    ),
    (
        "kernel",
        Object(&[
            ("inspector", Path),
            (
                "engines",
                Object(&[("modsecurity", Object(&[("inspector", Path)]))]),
            ),
            ("tmp_root", Path),
            ("gomaxprocs", Plain),
            ("gomemlimit", Plain),
            ("slots", Plain),
            ("wait_queue", Plain),
            ("records", Plain),
            ("discard_limit", Plain),
            ("tick_ms", Plain),
            ("hello_wait_ms", Plain),
            ("frame_io_ms", Plain),
            ("verdict_wait_ms", Plain),
            ("wait_deadline_ms", Plain),
            ("closed_wait_ms", Plain),
            ("stop_after_ms", Plain),
            ("drain_wait_ms", Plain),
            ("exit_wait_ms", Plain),
            ("kill_grace_ms", Plain),
            ("restarts", Plain),
            ("restart_window_ms", Plain),
        ]),
    ),
    (
        "rules",
        Object(&[("store", Object(&[("kind", Plain), ("dir", Path)]))]),
    ),
    (
        "acme",
        Object(&[
            ("directory_url", Plain),
            ("contact_email", Plain),
            ("account_key_file", Path),
            ("challenge_dir", Path),
            ("ca_file", Path),
            ("timeout_ms", Plain),
        ]),
    ),
    ("status", Plain),
    (
        "records",
        Object(&[
            ("dir", Path),
            ("file_bytes", Plain),
            ("files", Plain),
            ("keep", Plain),
            ("sync_ms", Plain),
            (
                "ship",
                Object(&[
                    ("db_driver", Plain),
                    ("db_dsn_file", Path),
                    ("batch", Plain),
                    ("interval_ms", Plain),
                    ("retention_days", Plain),
                ]),
            ),
        ]),
    ),
    ("access", Plain),
    ("rate_limit", Plain),
    ("geo", Object(&[("country_db", Path), ("sha256", Plain)])),
    (
        "admin",
        Object(&[
            ("listen", Plain),
            ("control", Path),
            ("store", Object(&[("kind", Plain), ("dir", Path)])),
            ("origin", Plain),
            ("trusted_proxies", Plain),
            ("mfa", Plain),
            ("session_idle_ms", Plain),
            ("session_total_ms", Plain),
            ("crs_dir", Path),
            (
                "route",
                Object(&[
                    ("host", Plain),
                    (
                        "certificate",
                        Object(&[("cert_file", Path), ("key_file", Path), ("acme", Plain)]),
                    ),
                    ("access", Plain),
                ]),
            ),
        ]),
    ),
]);

/// `value` shown as `how` says (see `Shown`). A path that `value` has is `true`; one that it leaves out is shown as
/// `null` by the object that holds it.
fn shown(value: &Value, how: &Shown) -> Value {
    match how {
        Shown::Plain => value.clone(),
        Shown::Path => Value::Bool(true),
        Shown::Object(keys) => {
            let mut object = Map::new();
            for (key, how) in *keys {
                match (value.get(*key), how) {
                    (Some(inner), _) => {
                        object.insert((*key).to_owned(), shown(inner, how));
                    }
                    (None, Shown::Path) => {
                        object.insert((*key).to_owned(), Value::Null);
                    }
                    (None, _) => {}
                }
            }
            Value::Object(object)
        }
        Shown::Each(how) => Value::Array(
            value
                .as_array()
                .map(|list| list.iter().map(|entry| shown(entry, how)).collect())
                .unwrap_or_default(),
        ),
        Shown::Named(how) => Value::Object(
            value
                .as_object()
                .map(|named| {
                    named
                        .iter()
                        .map(|(name, entry)| (name.clone(), shown(entry, how)))
                        .collect()
                })
                .unwrap_or_default(),
        ),
    }
}

impl Managed {
    pub(super) fn values(&self) -> Answer {
        let checked = config::read(&self.config).and_then(|bytes| {
            let built = config::main_file(&bytes)?;
            Ok((bytes, built))
        });
        let (bytes, built) = match checked {
            Ok(checked) => checked,
            Err(e) => return conflict(e.0),
        };
        // The bytes passed the check of the main file, so they are JSON without a repeated key.
        let file: Value = match serde_json::from_slice(&bytes) {
            Ok(file) => file,
            Err(e) => return conflict(config::refusal(&e).0),
        };
        let mut answer = shown(&file, &TOP);
        answer["sha256"] = Value::String(hex(&built.main.sha256));
        answer["managed"] = Value::Bool(built.main.managed.is_some());
        Answer::json(StatusCode::OK, answer)
    }
}

#[cfg(test)]
mod tests;
