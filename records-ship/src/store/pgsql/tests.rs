use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread::{self, JoinHandle};

use super::*;
use crate::store::CONNECT;

/// A connection string from a file, as `run` makes it.
fn dsn(text: &str) -> Dsn {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let path = std::env::temp_dir().join(format!(
        "tukuyomi-ship-pgdsn-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&path, text).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let uid = std::os::unix::fs::MetadataExt::uid(&fs::metadata(&path).unwrap());
    let dsn = crate::dsn::read(&path, uid).unwrap();
    fs::remove_file(&path).unwrap();
    dsn
}

#[test]
fn the_settings_come_from_the_string_with_a_wait_and_a_name() {
    let settings = Settings::parse(
        &dsn("host=127.0.0.1 port=5432 user=u password=p dbname=d"),
        "src",
    )
    .unwrap();
    assert_eq!(settings.source, "src");
    assert_eq!(settings.config.get_connect_timeout(), Some(&CONNECT_WAIT));
    assert_eq!(settings.config.get_application_name(), Some(APPLICATION));
    // What the string says stays.
    let settings = Settings::parse(
        &dsn("host=h connect_timeout=3 application_name=mine sslmode=disable"),
        "src",
    )
    .unwrap();
    assert_eq!(
        settings.config.get_connect_timeout(),
        Some(&Duration::from_secs(3))
    );
    assert_eq!(settings.config.get_application_name(), Some("mine"));
    assert_eq!(settings.config.get_ssl_mode(), SslMode::Disable);
}

#[test]
fn a_string_that_does_not_parse_is_refused_without_a_part_of_it() {
    for text in [
        "host=h password=hunter2 nonsense=1",
        "port=hunter2",
        "host=h sslmode=hunter2",
        "host=h password=hunter2 sslmode=verify-all",
    ] {
        let e = match Settings::parse(&dsn(text), "src") {
            Ok(_) => panic!("{text} was accepted"),
            Err(e) => e,
        };
        assert_eq!(e, Error::new(DSN));
        assert!(!format!("{e} {e:?}").contains("hunter2"));
    }
}

#[test]
fn the_columns_and_the_parameters_go_together() {
    let rows = [
        Row::of(br#"{"ts":"2026-10-25T08:00:00.123Z","type":"line","line":"a"}"#),
        Row::of(b"plain"),
    ];
    let columns = Columns::of(&rows);
    assert_eq!(columns.parameters().len(), 22);
    assert_eq!(columns.kind, ["line", "unknown"]);
    assert_eq!(columns.ts, [Some("2026-10-25T08:00:00.123Z"), None]);
    assert_eq!(columns.raw[1], "plain");
    assert_eq!(columns.line_hash.len(), 2);
}

#[test]
fn a_string_without_sslmode_means_tls_and_only_a_written_disable_means_plain() {
    let mode = |text: &str| Settings::parse(&dsn(text), "src").map(|s| s.config.get_ssl_mode());
    assert_eq!(mode("host=h user=u"), Ok(SslMode::Require));
    assert_eq!(mode("host=h sslmode=require"), Ok(SslMode::Require));
    assert_eq!(mode("host=h sslmode=disable"), Ok(SslMode::Disable));
    assert_eq!(mode("host=h sslmode = disable"), Ok(SslMode::Disable));
    assert_eq!(
        mode("postgresql://u@h/d?sslmode=disable&connect_timeout=3"),
        Ok(SslMode::Disable)
    );
    // The two that fall back to plain text are refused, in each form of the string, with a sentence that holds no
    // part of the string.
    for text in [
        "host=h sslmode=prefer",
        "host=h password=hunter2 sslmode='prefer' user=u",
        "host=h sslmode=allow",
        "host=h sslmode = prefer",
        "host=h sslmode =  'allow' user=u",
        "postgresql://u:hunter2@h/d?sslmode=prefer",
        "host=h sslmode=disable sslmode=prefer",
        "host=h sslmode=verify-full sslmode=prefer",
    ] {
        let e = mode(text).unwrap_err();
        assert_eq!(e, Error::new(SSLMODE), "{text}");
        assert!(!format!("{e} {e:?}").contains("hunter2"));
    }
    // The two names of the verifying mode, which the client does not know, are the mode of a string without
    // `sslmode`, in each form of the string.
    for text in [
        "host=h sslmode=verify-full",
        "host=h sslmode=verify-ca user=u",
        "host=h sslmode = 'verify-full' user=u",
        "postgresql://u@h/d?sslmode=verify-ca&connect_timeout=3",
        "host=h sslmode=prefer sslmode=verify-full",
    ] {
        assert_eq!(mode(text), Ok(SslMode::Require), "{text}");
    }
    // A string that the client takes is used as it stands, a password that holds such a text included.
    let settings =
        Settings::parse(&dsn("host=h password='sslmode=verify-full' user=u"), "src").unwrap();
    assert_eq!(
        settings.config.get_password(),
        Some(&b"sslmode=verify-full"[..])
    );
}

/// What one connection sent: the request for TLS, and what came after the answer to it.
type Sent = ([u8; 8], Vec<u8>);

/// A server on this host that answers the request for TLS with "no" `times` times and then reads what the client
/// sends until it hangs up: the port, and for each connection the request and what came after the "no".
fn server_that_declines_tls(times: usize) -> (u16, JoinHandle<Vec<Sent>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let mut seen = Vec::new();
        for _ in 0..times {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = [0u8; 8];
            stream.read_exact(&mut request).unwrap();
            stream.write_all(b"N").unwrap();
            let mut after = Vec::new();
            let _ = stream.read_to_end(&mut after);
            seen.push((request, after));
        }
        seen
    });
    (port, server)
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}

#[test]
fn a_server_that_declines_tls_gets_no_password_in_any_mode_but_disable() {
    let (port, server) = server_that_declines_tls(2);
    let mut settings = Settings::parse(
        &dsn(&format!(
            "host=127.0.0.1 port={port} user=u password=hunter2 dbname=d"
        )),
        "src",
    )
    .unwrap();
    for mode in [SslMode::Require, SslMode::Prefer] {
        settings.config.ssl_mode(mode);
        let e = match block_on(PgStore::connect(&settings)) {
            Ok(_) => panic!("a connection without TLS was made in the mode {mode:?}"),
            Err(e) => e,
        };
        assert_eq!(e, Error::new(CONNECT), "{mode:?}");
    }
    // Each connection sent the request for TLS, and nothing after the answer.
    for (request, after) in server.join().unwrap() {
        assert_eq!(request, [0, 0, 0, 8, 4, 210, 22, 47]);
        assert!(after.is_empty(), "{after:?}");
    }
}
