use std::fs;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use super::*;
use crate::log::recording;

static NEXT: AtomicU32 = AtomicU32::new(1);

/// A socket that is bound to a name of its own in the abstract namespace, and the value of `NOTIFY_SOCKET` for it.
fn abstract_receiver() -> (UnixDatagram, OsString) {
    let name = format!(
        "tukuyomi-notify-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let address = SocketAddr::from_abstract_name(&name).unwrap();
    let socket = UnixDatagram::bind_addr(&address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    (socket, OsString::from(format!("@{name}")))
}

fn receive(socket: &UnixDatagram) -> String {
    let mut buf = [0u8; 64];
    let got = socket.recv(&mut buf).expect("a notice");
    String::from_utf8_lossy(&buf[..got]).into_owned()
}

#[test]
fn only_an_absolute_path_or_an_at_and_a_name_is_a_target() {
    let long_name = format!("@{}", "n".repeat(MAX_NAME));
    let long_path = format!("/{}", "p".repeat(MAX_NAME - 1));
    for good in ["/run/systemd/notify", "@name", &long_name, &long_path] {
        assert!(target(OsStr::new(good)).is_some(), "{good}");
    }
    // One byte more than a socket address holds, an empty name, and the forms of other kinds.
    let too_long_name = format!("{long_name}n");
    let too_long_path = format!("{long_path}p");
    for bad in [
        "",
        "@",
        "name",
        "run/notify",
        "vsock:2:5",
        &too_long_name,
        &too_long_path,
    ] {
        assert!(target(OsStr::new(bad)).is_none(), "{bad}");
    }
}

#[test]
fn ready_and_stopping_reach_a_socket_named_by_a_path_or_by_a_name() {
    let (log, lines) = recording();

    let (socket, value) = abstract_receiver();
    let notify = Notify::new(Some(value), &log);
    notify.ready(&log);
    notify.stopping(&log);
    assert_eq!(receive(&socket), "READY=1");
    assert_eq!(receive(&socket), "STOPPING=1");

    let path = std::env::temp_dir().join(format!("tn-{}.sock", std::process::id()));
    let socket = UnixDatagram::bind(&path).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let notify = Notify::new(Some(path.clone().into_os_string()), &log);
    notify.ready(&log);
    assert_eq!(receive(&socket), "READY=1");
    fs::remove_file(&path).unwrap();

    assert!(lines.texts().is_empty());
}

#[test]
fn a_value_that_is_no_target_is_refused_and_a_notice_that_cannot_be_sent_is_a_line() {
    let (log, lines) = recording();
    let notify = Notify::new(Some(OsString::from("run/notify")), &log);
    notify.ready(&log);
    notify.stopping(&log);
    assert_eq!(
        lines.texts(),
        ["start: NOTIFY_SOCKET is not an absolute path or an @ and a name, no notice is sent"]
    );

    // No variable: nothing is sent and nothing is said.
    let notify = Notify::new(None, &log);
    notify.ready(&log);
    assert!(lines.texts().is_empty());

    // A path where no socket is: the notice is lost, one line says so, and the proxy goes on.
    let missing = std::env::temp_dir().join(format!("tn-missing-{}.sock", std::process::id()));
    let notify = Notify::new(Some(missing.into_os_string()), &log);
    notify.stopping(&log);
    let texts = lines.texts();
    assert_eq!(texts.len(), 1, "{texts:?}");
    assert!(
        texts[0].starts_with("notify: STOPPING=1 not sent"),
        "{texts:?}"
    );
}
