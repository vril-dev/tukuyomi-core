use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread::{self, JoinHandle};

use mysql_async::ServerError;

use super::*;

/// A connection string from a file, as `run` makes it.
fn dsn(text: &str) -> Dsn {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let path = std::env::temp_dir().join(format!(
        "tukuyomi-ship-mydsn-{}-{}",
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

fn parse(text: &str) -> Result<Settings, Error> {
    Settings::parse(&dsn(text), "src")
}

#[test]
fn the_settings_come_from_the_string_with_the_habits_of_the_client_turned_off() {
    let settings = parse("mysql://u:p@127.0.0.1:3306/d?require_ssl=false").unwrap();
    assert_eq!(settings.source, "src");
    assert_eq!(settings.opts.db_name(), Some("d"));
    assert_eq!(settings.opts.init(), [SESSION]);
    // The string cannot turn these on: the connection stays on the address it names, and a row that is stored
    // already is not counted as one that was found.
    let settings = parse(
        "mysql://u:p@127.0.0.1:3306/d?require_ssl=false&prefer_socket=true&client_found_rows=true",
    )
    .unwrap();
    assert!(!settings.opts.prefer_socket());
    assert!(!settings.opts.client_found_rows());
}

#[test]
fn a_string_that_does_not_parse_is_refused_without_a_part_of_it() {
    for text in [
        "mysql://u:hunter2@h/d?nonsense=1",
        "mysql://u:hunter2@h/d?require_ssl=maybe",
        "mysql://u:hunter2@h/d?pool_min=hunter2",
        "postgres://u:hunter2@h/d",
        "mysql://u:hunter2@h",
        "mysql://u:hunter2@h/",
        "hunter2",
    ] {
        let e = match parse(text) {
            Ok(_) => panic!("{text} was accepted"),
            Err(e) => e,
        };
        assert_eq!(e, Error::new(DSN), "{text}");
        assert!(!format!("{e} {e:?}").contains("hunter2"));
    }
}

#[test]
fn a_string_without_require_ssl_means_tls_and_only_a_written_false_means_plain() {
    let tls = |text: &str| parse(text).map(|settings| settings.opts.ssl_opts().is_some());
    assert_eq!(tls("mysql://u@h/d"), Ok(true));
    assert_eq!(tls("mysql://u@h/d?require_ssl=true"), Ok(true));
    assert_eq!(tls("mysql://u@h/d?require_ssl=false"), Ok(false));
    assert_eq!(
        tls("mysql://u@h/d?tcp_nodelay=true&require_ssl=false"),
        Ok(false)
    );
    // The last one the client reads is the one that counts.
    assert_eq!(
        tls("mysql://u@h/d?require_ssl=true&require_ssl=false"),
        Ok(false)
    );
    assert_eq!(
        tls("mysql://u@h/d?require_ssl=false&require_ssl=true"),
        Ok(true)
    );
    // Plain is for the form written just so: another spelling of it, a text that is not in the query, and a text
    // that the client does not read as the query are all TLS.
    for text in [
        "mysql://u@h/d?require%5Fssl=false",
        "mysql://u:require_ssl=false@h/d",
        "mysql://u@h/d#?require_ssl=false",
        "mysql://u@h/d#x&require_ssl=false",
    ] {
        assert_eq!(tls(text), Ok(true), "{text}");
    }
    // What the client takes as the default is taken.
    assert_eq!(
        tls("mysql://u@h/d?verify_ca=true&verify_identity=true&require_ssl=true"),
        Ok(true)
    );
    // The check of the certificate or of the name cannot be turned off, in either order and with or without
    // `require_ssl=true`, with a sentence that holds no part of the string. It means nothing in a plain string,
    // which is taken.
    for text in [
        "mysql://u:hunter2@h/d?verify_ca=false",
        "mysql://u:hunter2@h/d?verify_identity=false",
        "mysql://u:hunter2@h/d?require_ssl=true&verify_ca=false",
        "mysql://u:hunter2@h/d?verify_identity=false&require_ssl=true",
        "mysql://u:hunter2@h/d?require_ssl=true&verify_ca=false&verify_identity=false",
    ] {
        let e = tls(text).unwrap_err();
        assert_eq!(e, Error::new(UNVERIFIED), "{text}");
        assert!(!format!("{e} {e:?}").contains("hunter2"));
    }
    assert_eq!(
        tls("mysql://u@h/d?require_ssl=false&verify_ca=false"),
        Ok(false)
    );
    // A unix socket is not secured by the client, so it is taken only with the plain form written.
    assert_eq!(tls("mysql://u@h/d?socket=%2Ftmp%2Fs"), Err(Error::new(DSN)));
    assert_eq!(
        tls("mysql://u@h/d?socket=%2Ftmp%2Fs&require_ssl=false"),
        Ok(false)
    );
}

#[test]
fn a_source_is_taken_up_to_the_length_of_its_column() {
    let source = |chars: usize| Settings::parse(&dsn("mysql://u@h/d"), &"é".repeat(chars));
    assert!(source(SOURCE_MAX).is_ok());
    assert_eq!(source(SOURCE_MAX + 1).err(), Some(Error::new(VALUE)));
}

#[test]
fn the_columns_and_the_parameters_go_together() {
    let rows = [
        Row::of(br#"{"ts":"2026-10-25T08:00:00.123Z","type":"line","line":"a"}"#),
        Row::of(b"plain"),
    ];
    let first = values(&rows[0]);
    assert_eq!(first.len(), COLUMNS);
    assert_eq!(first[0], Value::Date(2026, 10, 25, 8, 0, 0, 123_000));
    assert_eq!(first[1], Value::from("line"));
    assert_eq!(first[20], Value::from(rows[0].raw.as_str()));
    assert_eq!(first[21], Value::from(rows[0].line_hash.as_slice()));
    let second = values(&rows[1]);
    assert_eq!(second[0], Value::NULL);
    assert_eq!(second[1], Value::from("unknown"));
    assert_eq!(second[2], Value::NULL);
    // The statement has a placeholder for each parameter, and the number of rows it is asked for.
    for n in [1, 2, ROWS_PER_INSERT] {
        let sql = insert(n);
        assert_eq!(sql.matches('?').count(), n * COLUMNS);
        assert!(sql.ends_with(INSERT_TAIL));
    }
}

#[test]
fn a_time_is_a_datetime_value_from_the_first_year_the_type_holds() {
    assert_eq!(
        datetime("1000-01-01T00:00:00.000Z"),
        Some(Value::Date(1000, 1, 1, 0, 0, 0, 0))
    );
    assert_eq!(datetime("0999-12-31T23:59:59.999Z"), None);
    assert_eq!(
        datetime("9999-12-31T23:59:59.999Z"),
        Some(Value::Date(9999, 12, 31, 23, 59, 59, 999_000))
    );
}

#[test]
fn an_error_holds_the_sqlstate_and_never_the_message() {
    let server = |state: &str| {
        MyError::Server(ServerError {
            code: 1045,
            message: "Access denied for user 'hunter2'".to_owned(),
            state: state.to_owned(),
        })
    };
    let e = failed(&server("28000"));
    assert_eq!(
        e,
        Error {
            what: LOGIN,
            code: Some("28000".to_owned())
        }
    );
    assert!(!format!("{e} {e:?}").contains("hunter2"));
    assert_eq!(failed(&server("42000")).what, FAILED);
    assert_eq!(failed(&server("HY000")).code.as_deref(), Some("HY000"));
    // Text that is not a SQLSTATE is not kept.
    for state in ["", "2800", "280000", "28 00", "hunter2"] {
        assert_eq!(failed(&server(state)), Error::new(FAILED), "{state:?}");
    }
    assert_eq!(
        failed(&MyError::Driver(DriverError::ConnectionClosed)),
        Error::new(CLOSED)
    );
    // An error without a kind is a failure to connect when it is the connection that failed.
    let refused = MyError::Io(std::io::Error::from(std::io::ErrorKind::ConnectionRefused).into());
    assert_eq!(failed(&refused), Error::new(FAILED));
    assert_eq!(not_connected(&refused), Error::new(CONNECT));
    assert_eq!(not_connected(&server("28000")).what, LOGIN);
}

/// The first packet of a server that does not offer TLS, as a MySQL server sends it.
fn handshake_without_tls() -> Vec<u8> {
    // The client may use the protocol 4.1, the secure connection and the choice of the plugin; no TLS.
    let capabilities: u32 = 0x0001 | 0x0200 | 0x2000 | 0x8000 | 0x0008_0000;
    let mut payload = vec![10];
    payload.extend_from_slice(b"8.0.0-test\0");
    payload.extend_from_slice(&1u32.to_le_bytes());
    payload.extend_from_slice(b"abcdefgh\0");
    payload.extend_from_slice(&capabilities.to_le_bytes()[..2]);
    payload.push(45);
    payload.extend_from_slice(&2u16.to_le_bytes());
    payload.extend_from_slice(&capabilities.to_le_bytes()[2..]);
    payload.push(21);
    payload.extend_from_slice(&[0; 10]);
    payload.extend_from_slice(b"ijklmnopqrst\0");
    payload.extend_from_slice(b"mysql_native_password\0");
    let mut packet = u32::try_from(payload.len()).unwrap().to_le_bytes()[..3].to_vec();
    packet.push(0);
    packet.extend_from_slice(&payload);
    packet
}

/// A server on this host that offers no TLS, `times` times: the port, and for each connection what the client sent
/// after the first packet, as far as the first read gets (the client sends nothing more until it is answered).
fn server_without_tls(times: usize) -> (u16, JoinHandle<Vec<Vec<u8>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let mut seen = Vec::new();
        for _ in 0..times {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream.write_all(&handshake_without_tls()).unwrap();
            let mut buffer = [0u8; 4096];
            let read = stream.read(&mut buffer).unwrap_or(0);
            seen.push(buffer[..read].to_vec());
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
fn a_server_that_offers_no_tls_gets_nothing_of_the_login_unless_plain_is_written() {
    let (port, server) = server_without_tls(2);
    let connect = |url: String| {
        let settings = parse(&url).unwrap();
        block_on(MyStore::connect(&settings)).err()
    };
    // With TLS, which a string without `require_ssl` means, the client stops at the first packet.
    let e = connect(format!("mysql://u:hunter2@127.0.0.1:{port}/d"));
    assert_eq!(e, Some(Error::new(CONNECT)));
    // With the plain form written the client answers the first packet with its login: so the packet of the test is
    // one that the client reads, and what it sent before was not for want of that.
    let e = connect(format!(
        "mysql://u:hunter2@127.0.0.1:{port}/d?require_ssl=false"
    ));
    assert!(e.is_some());
    let seen = server.join().unwrap();
    // The client may say goodbye as it lets go; a login is much longer than that.
    assert!(
        seen[0].is_empty() || seen[0] == [1, 0, 0, 0, 1],
        "{:?}",
        seen[0]
    );
    assert!(
        seen[1].len() > 32 && seen[1].windows(2).any(|w| w == b"u\0"),
        "{:?}",
        seen[1]
    );
}
