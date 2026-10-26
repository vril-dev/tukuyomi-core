//! Real-process tests of the HTTP front.
//!
//! Every test starts the proxy binary with a configuration file that it writes into its own 0700 root, the real
//! inspector and the test rules of the kernel crate (rule 9201: a URI beginning `/block-probe`, phase 1, status
//! 403; rule 9202: the urlencoded argument `probe=block`, phase 2, status 403; rule 9203: the top-level JSON
//! member `probe` equal to `block`, phase 2, status 403). The tests also run a small upstream of their own on a
//! loopback port, which records every connection and the bytes it received, and they talk to the proxy with a
//! raw TCP client: the exact bytes out, everything read back until the proxy closes. The keep-alive tests keep a
//! connection open instead and read each response by its length.
//!
//! These tests need the environment variables `TUKUYOMI_TEST_INSPECTOR` (the built inspector),
//! `TUKUYOMI_TEST_RULES` (the directory of the rule bundle), `TUKUYOMI_TEST_RULES_SHA256` (the SHA-256 of the
//! `manifest.json` of that bundle, 64 hex digits) and `TUKUYOMI_TEST_TMP` (the parent of the per-test 0700 roots).
//! They fail when one is missing: a skipped real-process test must never look like a pass. Run them with
//! `-- --ignored`.
//!
//! The rules store of a test is `store/` in its root. It holds the files of the bundle as the generation named by
//! the hash, in `store/generations/<hash>/`, and `store/current`, which chooses that generation. A test that
//! needs another store changes the root before the proxy starts (`Proxy::spawn_with`); `rules` does that to see
//! how the start ends.
//!
//! How the scenes are made:
//! - A slow inspection is a 1 MiB urlencoded body with a drive slice of 400 ms. The driver then needs about 17
//!   steps of one slice each, so the inspection takes several seconds. The inspector process is found through
//!   `/proc/<proxy pid>/task/*/children`, and the test knows that the body is being inspected when the inspector's
//!   read counter in `/proc/<pid>/io` has grown by one body frame.
//! - The listen port is chosen by binding `127.0.0.1:0` and releasing the socket right before the start.
//! - Resources that come back are shown by the record line that the proxy writes when it is told to stop: it
//!   shows the kernel holding no record, no slot and no waiting request.
//! - A gzip body is built in the test with `flate2`: a plain body that is much longer than its coded form (so the
//!   length that reaches the upstream cannot be the coded one), or one that decodes to just over the limit.

mod acme;
mod bodies;
mod config_check;
mod deadlines;
mod forwarding;
mod http2;
mod inspector;
mod keepalive;
mod records;
mod refusals;
mod rewrite;
mod rules;
mod stopping;
mod support;
mod tls;
mod upstream_tls;
mod upstreams;
mod websocket;
