use std::os::unix::fs::{DirBuilderExt, symlink};
use std::os::unix::net::UnixListener as StdListener;
use std::sync::atomic::{AtomicU32, Ordering};

use tokio::io::AsyncWriteExt;
use tukuyomi_kernel::Failure;

use super::*;
use crate::log::recording;
use crate::rules::bundle::Mode;
use crate::run::signals::tests::runtime;

/// A fresh 0700 directory under the temp directory (`TMPDIR`), removed with everything in it when dropped.
struct TestDir(PathBuf);

impl TestDir {
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn scratch() -> TestDir {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "tukuyomi-proxy-control-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    // A umask can only remove bits; make the mode exactly 0700.
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    TestDir(dir)
}

/// A fingerprint of 64 times the digit `c`.
fn fingerprint(c: u8) -> Fingerprint {
    Fingerprint::from_hex(&[c; 64]).unwrap()
}

fn state(phase: Phase) -> State {
    State {
        phase,
        restarts: 0,
        generation: fingerprint(b'a'),
        mode: Mode::Block,
    }
}

/// Binds and serves `path`, and returns the handle with the way to change the state it reads.
fn serving(path: &Path, switch_wait: Duration, log: &Log) -> (Control, watch::Sender<State>) {
    let bound = bind(path).unwrap();
    let (changes, state) = watch::channel(state(Phase::Ready));
    let readiness = Arc::new(Readiness::new());
    readiness.bound();
    (
        serve(bound, state, readiness, switch_wait, log.clone()),
        changes,
    )
}

/// Sends `request` as it is and reads the answer until the socket closes. A reset ends the read as a close does.
async fn ask(path: PathBuf, request: Vec<u8>) -> String {
    let mut sock = UnixStream::connect(path).await.unwrap();
    sock.write_all(&request).await.unwrap();
    let mut out = Vec::new();
    let _ = sock.read_to_end(&mut out).await;
    String::from_utf8(out).unwrap()
}

fn status_line(phase: &str, switching: bool, ready: bool) -> String {
    format!(
        "{{\"generation\":\"{}\",\"mode\":\"block\",\"phase\":\"{phase}\",\"switching\":{switching},\"ready\":{ready}}}\n",
        "a".repeat(64)
    )
}

fn switch_request(c: u8) -> Vec<u8> {
    format!(
        "{{\"op\":\"switch\",\"expect\":\"{}\"}}\n",
        char::from(c).to_string().repeat(64)
    )
    .into_bytes()
}

fn mode_of(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn the_socket_has_mode_0600_and_an_old_socket_nobody_listens_at_is_replaced_and_anything_else_ends_the_start()
 {
    runtime().block_on(async {
        let dir = scratch();
        let path = dir.path().join("c.sock");
        // What a process that was killed leaves: a socket file that nobody listens at.
        drop(StdListener::bind(&path).unwrap());
        assert!(path.exists());
        let bound = bind(&path).unwrap();
        assert_eq!(mode_of(&path), 0o600);
        assert!(fs::symlink_metadata(&path).unwrap().file_type().is_socket());
        UnixStream::connect(&path).await.unwrap();
        // The file goes with the socket.
        drop(bound);
        assert!(!path.exists());

        // A socket that a process listens at is not taken over: the start ends and the file stays.
        let live = StdListener::bind(&path).unwrap();
        assert_eq!(
            bind(&path).err(),
            Some("the control socket is in use by another process")
        );
        StdStream::connect(&path).unwrap();
        drop(live);
        fs::remove_file(&path).unwrap();

        // A file that is not a socket, a link and a directory are not removed and end the start.
        let refused = Some("something other than a socket of this user is at the path");
        fs::write(&path, b"x").unwrap();
        assert_eq!(bind(&path).err(), refused);
        assert_eq!(fs::read(&path).unwrap(), b"x");
        fs::remove_file(&path).unwrap();
        symlink(dir.path(), &path).unwrap();
        assert_eq!(bind(&path).err(), refused);
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert_eq!(bind(&path).err(), refused);
        fs::remove_dir(&path).unwrap();

        // A file that took the place of the socket while it was served is not removed with it.
        let bound = bind(&path).unwrap();
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"y").unwrap();
        drop(bound);
        assert_eq!(fs::read(&path).unwrap(), b"y");
        fs::remove_file(&path).unwrap();

        // The directory has to be the user's and closed to others.
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o750)).unwrap();
        assert_eq!(
            bind(&path).err(),
            Some("the directory has group or other permission bits")
        );
        assert!(!path.exists());
    });
}

#[test]
fn a_status_and_a_switch_go_to_the_main_loop_and_its_answers_to_the_client() {
    runtime().block_on(async {
        let dir = scratch();
        let path = dir.path().join("c.sock");
        let (log, lines) = recording();
        let (mut control, changes) = serving(&path, Duration::from_secs(30), &log);

        let client = tokio::spawn(ask(path.clone(), b"{\"op\":\"status\"}\n".to_vec()));
        let Some(Order::Status(reply)) = control.orders.recv().await else {
            panic!("no status order");
        };
        reply.send(control.status(false)).unwrap();
        assert_eq!(client.await.unwrap(), status_line("ready", false, true));

        // A kernel that failed is not ready, and a switch under way is told.
        changes.send_replace(state(Phase::Failed(Failure::BudgetExhausted)));
        let client = tokio::spawn(ask(path.clone(), b"{\"op\":\"status\"}\n".to_vec()));
        let Some(Order::Status(reply)) = control.orders.recv().await else {
            panic!("no status order");
        };
        reply.send(control.status(true)).unwrap();
        assert_eq!(client.await.unwrap(), status_line("failed", true, false));

        // A switch is answered when the main loop says so, with the generation that serves then.
        let client = tokio::spawn(ask(path.clone(), switch_request(b'b')));
        let Some(Order::Switch(order)) = control.orders.recv().await else {
            panic!("no switch order");
        };
        assert_eq!(order.expect(), fingerprint(b'b'));
        control.hold(order);
        control.switch_ended(true, fingerprint(b'b'), &log);
        assert_eq!(
            client.await.unwrap(),
            format!(
                "{{\"result\":\"switched\",\"generation\":\"{}\"}}\n",
                "b".repeat(64)
            )
        );
        let client = tokio::spawn(ask(path.clone(), switch_request(b'c')));
        let Some(Order::Switch(order)) = control.orders.recv().await else {
            panic!("no switch order");
        };
        control.hold(order);
        control.switch_ended(false, fingerprint(b'b'), &log);
        assert_eq!(
            client.await.unwrap(),
            format!(
                "{{\"result\":\"failed\",\"reason\":\"not switched\",\"generation\":\"{}\"}}\n",
                "b".repeat(64)
            )
        );
        let client = tokio::spawn(ask(path.clone(), switch_request(b'c')));
        let Some(Order::Switch(order)) = control.orders.recv().await else {
            panic!("no switch order");
        };
        order.finish(
            Outcome::Refused,
            Some("current changed"),
            fingerprint(b'a'),
            &log,
        );
        assert_eq!(
            client.await.unwrap(),
            format!(
                "{{\"result\":\"refused\",\"reason\":\"current changed\",\"generation\":\"{}\"}}\n",
                "a".repeat(64)
            )
        );
        // One record line for each switch order.
        let (a, b, c) = ("a".repeat(64), "b".repeat(64), "c".repeat(64));
        assert_eq!(
            lines.texts(),
            [
                format!("control: switch expect {b}: switched, serving {b}"),
                format!("control: switch expect {c}: failed (not switched), serving {b}"),
                format!("control: switch expect {c}: refused (current changed), serving {a}"),
            ]
        );
    });
}

#[test]
fn a_line_that_is_not_a_request_is_answered_with_a_word_and_never_reaches_the_main_loop() {
    runtime().block_on(async {
        let dir = scratch();
        let path = dir.path().join("c.sock");
        let (log, _lines) = recording();
        let (mut control, _changes) = serving(&path, Duration::from_secs(30), &log);
        let upper = format!("{{\"op\":\"switch\",\"expect\":\"{}\"}}\n", "A".repeat(64));
        let mut past_the_limit = vec![b' '; LINE_MAX];
        past_the_limit.push(b'\n');
        let cases: [(Vec<u8>, &str); 9] = [
            (b"not json\n".to_vec(), "malformed request"),
            (b"{\"op\":\"stop\"}\n".to_vec(), "unknown op"),
            (
                b"{\"op\":\"status\",\"x\":1}\n".to_vec(),
                "malformed request",
            ),
            (
                b"{\"op\":\"status\",\"expect\":\"a\"}\n".to_vec(),
                "malformed request",
            ),
            (b"{\"op\":\"switch\"}\n".to_vec(), "malformed request"),
            (
                b"{\"op\":\"status\"} {\"op\":\"status\"}\n".to_vec(),
                "malformed request",
            ),
            (upper.into_bytes(), "bad expect"),
            (
                b"{\"op\":\"switch\",\"expect\":\"abc\"}\n".to_vec(),
                "bad expect",
            ),
            // 4096 bytes without a line feed, and the first byte past that.
            (past_the_limit, "line too long"),
        ];
        for (request, reason) in cases {
            let answer = ask(path.clone(), request).await;
            assert_eq!(
                answer,
                format!("{{\"result\":\"error\",\"reason\":\"{reason}\"}}\n")
            );
        }
        assert!(control.orders.try_recv().is_err());

        // A line of exactly 4096 bytes with its line feed is read.
        let mut fits = b"{\"op\":\"status\"}".to_vec();
        fits.resize(LINE_MAX - 1, b' ');
        fits.push(b'\n');
        assert_eq!(fits.len(), LINE_MAX);
        let client = tokio::spawn(ask(path.clone(), fits));
        let Some(Order::Status(reply)) = control.orders.recv().await else {
            panic!("no status order");
        };
        reply.send(control.status(false)).unwrap();
        assert_eq!(client.await.unwrap(), status_line("ready", false, true));
    });
}

#[test]
fn a_fifth_connection_is_closed_and_a_switch_that_is_not_answered_in_time_is_told_busy() {
    runtime().block_on(async {
        let dir = scratch();
        let path = dir.path().join("c.sock");
        let (log, lines) = recording();
        let (mut control, _changes) = serving(&path, Duration::from_millis(100), &log);
        let mut held = Vec::new();
        for _ in 0..SEATS {
            held.push(UnixStream::connect(&path).await.unwrap());
        }
        // Let the accept side take the four places.
        sleep(Duration::from_millis(100)).await;
        let mut fifth = UnixStream::connect(&path).await.unwrap();
        let mut out = Vec::new();
        timeout(Duration::from_secs(1), fifth.read_to_end(&mut out))
            .await
            .expect("the fifth connection is closed at once")
            .ok();
        assert!(out.is_empty());
        drop(held);
        sleep(Duration::from_millis(100)).await;

        // The order is taken and not answered: the client is told that the switch is going on.
        let client = tokio::spawn(ask(path.clone(), switch_request(b'b')));
        let Some(Order::Switch(order)) = control.orders.recv().await else {
            panic!("no switch order");
        };
        let busy = |reason: &str| {
            format!(
                "{{\"result\":\"busy\",\"reason\":\"{reason}\",\"generation\":\"{}\"}}\n",
                "a".repeat(64)
            )
        };
        assert_eq!(client.await.unwrap(), busy("switch under way"));
        drop(order);
        // An order that is dropped without an answer is the stop.
        let client = tokio::spawn(ask(path.clone(), switch_request(b'b')));
        let Some(Order::Switch(order)) = control.orders.recv().await else {
            panic!("no switch order");
        };
        drop(order);
        assert_eq!(client.await.unwrap(), busy("stopping"));

        // Orders that nobody takes wait in the queue, which holds four; the fifth finds no place.
        for _ in 0..SEATS {
            let answer = ask(path.clone(), switch_request(b'b')).await;
            assert_eq!(answer, busy("switch under way"));
        }
        let answer = ask(path.clone(), switch_request(b'b')).await;
        assert_eq!(answer, busy("too many orders"));
        // Every busy answer of a connection has the record line of a switch order.
        let (a, b) = ("a".repeat(64), "b".repeat(64));
        let line =
            |reason: &str| format!("control: switch expect {b}: busy ({reason}), serving {a}");
        let mut want = vec![line("switch under way"), line("stopping")];
        want.extend(vec![line("switch under way"); SEATS]);
        want.push(line("too many orders"));
        assert_eq!(lines.texts(), want);

        // The handle closes the socket and removes its file.
        drop(control);
        assert!(!path.exists());
    });
}
