use std::fs;
use std::os::unix::net::UnixDatagram;
use std::time::Duration;

use tukuyomi_proxy::log::{Format, start_logger};

use super::*;

#[test]
fn ready_and_stopping_reach_the_socket() {
    // A short name: the path of a socket is at most 107 bytes, and the temporary directory may be a long one.
    let dir = std::env::temp_dir().join(format!("ship-notify-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir(&dir).unwrap();
    let path = dir.join("n.sock");
    let receiver = UnixDatagram::bind(&path).unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let log = start_logger(Format::Json).unwrap();
    let notify = Notify::new(Some(path.clone().into_os_string()), &log);
    notify.ready(&log);
    notify.stopping(&log);
    let mut buffer = [0u8; 64];
    let n = receiver.recv(&mut buffer).unwrap();
    assert_eq!(&buffer[..n], b"READY=1");
    let n = receiver.recv(&mut buffer).unwrap();
    assert_eq!(&buffer[..n], b"STOPPING=1");
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_value_that_is_no_socket_name_gives_no_notice() {
    let log = start_logger(Format::Json).unwrap();
    for value in ["relative/path", "", "@"] {
        assert!(
            Notify::new(Some(value.into()), &log).sender.is_none(),
            "{value}"
        );
    }
    assert!(Notify::new(None, &log).sender.is_none());
}
