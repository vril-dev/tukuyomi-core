//! The certificates with `acme` in a real process: a proxy that starts while the files of such a certificate are not
//! there yet, refuses the handshake for its host, answers the challenge of the CA on its plain listener and takes the
//! files when SIGUSR2 comes; and the command `acme renew`, whose CA here is a port where nothing listens, or one that
//! never answers (the exchange with a CA is the acceptance run, with a CA of its own).
//!
//! The certificates, the account key and the files of the challenges are in the directory of the authority of the
//! test, outside the test root.

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::support::*;
use crate::tls::Pki;

const CHALLENGE: &str = "/.well-known/acme-challenge/Tok_-1";

/// Adds to the configuration in `root`: a listener that ends TLS with a certificate with `acme` for `a.example`, whose
/// files are `a.pem` and `a.key` of the directory of `pki`, and the `acme` object with the CA at `directory`, which the
/// command may take `timeout_ms` to deal with.
fn add_to(root: &Path, pki: &Pki, tls_port: u16, directory: &str, timeout_ms: u64) {
    let path = root.join("config.json");
    let mut config: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    config["proxy"]["listeners"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "address": format!("127.0.0.1:{tls_port}"),
            "tls": {
                "min_version": "1.2",
                "certificates": [{
                    "cert_file": pki.path("a.pem"),
                    "key_file": pki.path("a.key"),
                    "hosts": ["a.example"],
                    "acme": {"renew_before_days": 30},
                }],
            },
        }));
    config["acme"] = json!({
        "directory_url": directory,
        "contact_email": "ops@example.test",
        "account_key_file": pki.path("account.key"),
        "challenge_dir": pki.path("challenges"),
        "ca_file": pki.path("ca.pem"),
        "timeout_ms": timeout_ms,
    });
    fs::write(&path, config.to_string()).unwrap();
}

fn request(target: &str, host: &str) -> String {
    format!("GET {target} HTTP/1.1\r\nHost: {host}\r\n\r\n")
}

/// The command `acme renew` with these arguments; its exit code, standard output and standard error.
fn command(args: &[&Path]) -> (Option<i32>, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_tukuyomi-proxy"))
        .args(args)
        .output()
        .expect("run the command");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
#[ignore = "needs a built inspector"]
fn a_certificate_with_acme_not_issued_yet_waits_and_the_challenge_is_answered_until_sigusr2_takes_the_files()
 {
    let mut pki = Pki::new("acme_first");
    fs::create_dir(pki.path("challenges")).unwrap();
    let tls_port = free_port();
    let directory = format!("https://127.0.0.1:{}/dir", free_port());
    let proxy = Proxy::start_with("acme_first", Knobs::quick(), |root| {
        add_to(root, &pki, tls_port, &directory, 20_000);
    });
    // The start was not refused for the missing files: the certificate is named, and its host gets no handshake.
    proxy.records.wait_lines("the waiting certificate", 1, |l| {
        l == "start: tls certificate not issued yet (listener 2, certificate 1)"
    });
    let mut refused = pki.client("a.example", tls_port);
    assert!(refused.conn.complete_io(&mut refused.sock).is_err());

    // The challenge of the CA is answered on the plain listener for the host of the certificate, from the file; for
    // another host, and with a query, the request goes on to the upstream like any other.
    fs::write(pki.path("challenges/Tok_-1"), b"abc.def").unwrap();
    let reply = exchange(proxy.port, request(CHALLENGE, "a.example").as_bytes());
    let answer = reply.message();
    assert_eq!(answer.status(), 200, "{:?}", reply.text());
    assert_eq!(answer.values("content-type"), ["text/plain"]);
    assert_eq!(answer.body, b"abc.def");
    for (target, host) in [
        (CHALLENGE.to_owned(), "other.example"),
        (format!("{CHALLENGE}?x=1"), "a.example"),
    ] {
        let reply = exchange(proxy.port, request(&target, host).as_bytes());
        assert_eq!(
            reply.message().body,
            UPSTREAM_BODY.as_bytes(),
            "{target} {host}"
        );
    }
    proxy.records.conn("the record of the challenge", |l| {
        is_answer(l, "answered", 200, "acme challenge") && no(l, "rule")
    });

    // The command cannot reach the CA: the certificate is `failed`, nothing of it is written, the account key is
    // there (mode 0600) and the challenge directory is empty. A wrong argument is 2.
    let config = proxy.root().join("config.json");
    let (code, out, err) = command(&[Path::new("acme"), Path::new("renew"), &config]);
    assert_eq!((code, out.as_str()), (Some(1), "2.1 failed\n"), "{err}");
    assert_eq!(err, "acme renew: 2.1: the CA cannot be reached\n");
    assert!(!pki.path("a.pem").exists() && !pki.path("a.key").exists());
    assert_eq!(
        fs::metadata(pki.path("account.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(fs::read_dir(pki.path("challenges")).unwrap().count(), 1); // Tok_-1, which the test wrote
    fs::remove_file(pki.path("challenges/Tok_-1")).unwrap();
    for args in [
        vec![Path::new("acme")],
        vec![Path::new("acme"), Path::new("renew")],
        vec![
            Path::new("acme"),
            Path::new("renew"),
            Path::new("config.json"),
        ],
        vec![Path::new("acme"), Path::new("renew"), &config, &config],
    ] {
        assert_eq!(command(&args).0, Some(2), "{args:?}");
    }

    // The files appear, and SIGUSR2 takes them: a request over TLS is forwarded.
    pki.issue("a", &["a.example"]);
    proxy.signal("USR2");
    proxy.records.wait_lines("the certificates", 1, |l| {
        l == "reload: certificates replaced"
    });
    let mut stream = pki.client("a.example", tls_port);
    stream
        .write_all(request("/ok", "a.example").as_bytes())
        .unwrap();
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .expect("the proxy ended the connection with the closing alert");
    assert_eq!(Message::parse(&raw).status(), 200);
    proxy.finish(3);
}

#[test]
#[ignore = "needs a built inspector"]
fn the_command_ends_by_its_time_when_the_ca_does_not_answer() {
    const TIME: Duration = Duration::from_millis(500);
    // What the start and the end of the process take besides.
    const MARGIN: Duration = Duration::from_secs(3);
    let pki = Pki::new("acme_silent");
    fs::create_dir(pki.path("challenges")).unwrap();
    // The system takes the connection to this port and nobody answers on it, so the handshake with the CA hangs.
    let silent = TcpListener::bind("127.0.0.1:0").unwrap();
    let directory = format!(
        "https://127.0.0.1:{}/dir",
        silent.local_addr().unwrap().port()
    );
    let proxy = Proxy::start_with("acme_silent", Knobs::quick(), |root| {
        add_to(root, &pki, free_port(), &directory, 500);
    });
    let config = proxy.root().join("config.json");
    let started = Instant::now();
    let (code, out, err) = command(&[Path::new("acme"), Path::new("renew"), &config]);
    let took = started.elapsed();
    assert_eq!((code, out.as_str()), (Some(1), "2.1 failed\n"), "{err}");
    assert_eq!(
        err,
        "acme renew: 2.1: the time for the command is used up\n"
    );
    assert!(took >= TIME, "{took:?}");
    assert!(took < TIME + MARGIN, "{took:?}");
    assert_eq!(fs::read_dir(pki.path("challenges")).unwrap().count(), 0);
    proxy.finish(0);
}

#[test]
#[ignore = "needs a built inspector"]
fn the_command_does_not_run_on_a_configuration_with_no_certificate_with_acme() {
    let proxy = Proxy::start("acme_none", Knobs::quick());
    let config = proxy.root().join("config.json");
    let (code, out, err) = command(&[Path::new("acme"), Path::new("renew"), &config]);
    assert_eq!((code, out.as_str()), (Some(2), ""), "{err}");
    assert_eq!(
        err,
        "acme renew: no certificate of the configuration has acme\n"
    );
    proxy.finish(0);
}
