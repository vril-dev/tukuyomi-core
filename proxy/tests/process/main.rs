//! Real-process tests of the HTTP front.
//!
//! Every test starts the proxy binary with a configuration file that it writes into its own 0700 root, the real
//! inspector and the test rules of the kernel crate (rule 9201: a URI beginning `/block-probe`, phase 1, status
//! 403; rule 9202: the urlencoded argument `probe=block`, phase 2, status 403; rule 9203: the top-level JSON
//! member `probe` equal to `block`, phase 2, status 403). Rule 4000001 is not one of them: it is the inspector's
//! own reserved rule that blocks a body its parser refuses (status 403). The tests also run a small upstream of
//! their own on a loopback port, which records every connection and the bytes it received, and they talk to the
//! proxy with a raw TCP client: the exact bytes out, everything read back until the proxy closes.
//!
//! These tests need the environment variables `TUKUYOMI_TEST_INSPECTOR` (the built inspector),
//! `TUKUYOMI_TEST_RULES` (the rules file), `TUKUYOMI_TEST_RULES_SHA256` (its hash, 64 hex digits) and
//! `TUKUYOMI_TEST_TMP` (the parent of the per-test 0700 roots). They fail when one is missing: a skipped
//! real-process test must never look like a pass. Run them with `-- --ignored`.
//!
//! How the scenes are made:
//! - A slow inspection is a 1 MiB urlencoded body with a drive slice of 400 ms. The driver then needs about 17
//!   steps of one slice each, so the inspection takes several seconds. The inspector process is found through
//!   `/proc/<proxy pid>/task/*/children`, and the test knows that the body is being inspected when the inspector's
//!   read counter in `/proc/<pid>/io` has grown by one body frame.
//! - The listen port is chosen by binding `127.0.0.1:0` and releasing the socket right before the start. A
//!   process that takes the port in between would make the start fail with a clear record line.
//! - Resources that come back are shown in two ways: a normal request passes after the scene, and the record
//!   line that the proxy writes when it is told to stop shows the kernel holding no record, no slot and no
//!   waiting request. Deadlines that fire with the byte budget, or the connection limit, at their minimum show
//!   the budget or the permit coming back directly.
//! - Waiting is done on a channel, a condition variable or an exit. The few pauses that remain are polls of a
//!   `/proc` counter or of a socket state every 2 to 20 ms, bounded by `PATIENCE`.
//! - A response that streams for as long as the proxy lets it is a head that promises a million bytes and then one
//!   byte every 200 ms from the upstream. The scenes that cut it (the connection limit, the stop) are measured
//!   from the client's side: the cut must come at the configured time, within a generous margin.
//! - A client that resets is a socket closed with `SO_LINGER` set to zero. The standard library cannot set it, so
//!   the socket is handed to tokio for that one call (`set_zero_linger`; `set_linger` is deprecated).
//! - A gzip body is built in the test with `flate2`, with the exact bytes the scene needs: a plain body that is
//!   much longer than its coded form (so the length that reaches the upstream cannot be the coded one), a body
//!   that decodes to just over the limit from a few hundred bytes, a stream with one byte of its trailer changed,
//!   or with bytes after its member.
//! - A restart window is a scene in time. The window is counted from a kill, which is before the kernel's own
//!   record of the restart, so the earliest time the kernel may start the inspector again is known to the test:
//!   the kill plus the window. The scene checks its answers against that bound, and its other times (the wait
//!   for a verdict and the time to the second kill) leave a large part of the window over. The few seconds that
//!   remain are waited for in `wait_inspector`, not slept.
//! - A kernel that never becomes ready is a stand-in for the inspector: `/bin/sh` runs a script that becomes
//!   `/bin/sleep` and never says hello. The script is in the test root and is removed with it.

mod bodies;
mod clients;
mod deadlines;
mod forwarding;
mod inspector;
mod refusals;
mod stopping;
mod support;
