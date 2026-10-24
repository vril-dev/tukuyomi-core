use std::fs;

use super::*;
use crate::acme::tests::{Scratch, openssl};
use crate::config::CertificateAcme;

fn args(text: &[&str]) -> Vec<OsString> {
    text.iter().map(OsString::from).collect()
}

#[test]
fn the_command_takes_renew_and_one_absolute_clean_path() {
    assert_eq!(
        parse(&args(&["renew", "/etc/t.json"])),
        Ok(PathBuf::from("/etc/t.json"))
    );
    for bad in [
        &[][..],
        &["renew"],
        &["renew", "t.json"],
        &["renew", "/etc/../t.json"],
        &["renew", "/etc/t.json", "extra"],
        &["issue", "/etc/t.json"],
        &["/etc/t.json"],
    ] {
        assert!(parse(&args(bad)).is_err(), "{bad:?}");
    }
    let (mut out, mut err) = (Vec::new(), Vec::new());
    assert_eq!(run(&args(&["renew"]), &mut out, &mut err), Exit::Usage);
    assert!(out.is_empty());
    let err = String::from_utf8(err).unwrap();
    assert!(
        err.starts_with("acme: the configuration file is missing\nusage: "),
        "{err}"
    );
}

#[test]
fn a_certificate_is_not_renewed_with_exactly_the_days_left_and_is_with_a_second_less() {
    let day = 86_400;
    for days in [1, 30, 60] {
        let end = 1_900_000_000;
        assert!(
            !expires_soon(end, end - i64::from(days) * day, days),
            "{days}"
        );
        assert!(
            expires_soon(end, end - i64::from(days) * day + 1, days),
            "{days}"
        );
        assert!(
            !expires_soon(end, end - i64::from(days) * day - 1, days),
            "{days}"
        );
    }
    // A certificate that has ended, and one whose end is far from the clock.
    assert!(expires_soon(1_000, 2_000, 1));
    assert!(expires_soon(i64::MIN, i64::MAX, 60));
    assert!(!expires_soon(i64::MAX, i64::MIN, 60));
}

fn issue(dir: &Scratch, name: &str, host: &str) {
    openssl(
        dir.path(),
        &[
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-keyout",
            &format!("{name}.key"),
            "-out",
            &format!("{name}.pem"),
            "-subj",
            "/CN=x",
            "-days",
            "90",
            "-addext",
            &format!("subjectAltName=DNS:{host}"),
        ],
    );
}

#[test]
fn a_certificate_is_due_when_it_cannot_be_read_goes_with_no_key_or_host_or_has_less_than_the_days_left()
 {
    let dir = Scratch::new();
    issue(&dir, "a", "a.test");
    issue(&dir, "other", "a.test");
    fs::write(dir.join("garbage.pem"), b"not a certificate").unwrap();
    let certificate = |cert: &str, key: &str, hosts: &[&str]| CertificateConfig {
        cert_file: dir.join(cert),
        key_file: dir.join(key),
        hosts: hosts.iter().map(|host| (*host).to_owned()).collect(),
        acme: Some(CertificateAcme {
            renew_before_days: 30,
        }),
    };
    let due_for = |certificate: &CertificateConfig, now: i64| {
        let target = Target {
            label: "1.1".to_owned(),
            certificate,
            renew_before_days: 30,
        };
        due(&target, now)
    };
    let good = certificate("a.pem", "a.key", &["a.test"]);
    let loaded = Files.load(&good.cert_file, &good.key_file).unwrap();
    let end = der::not_after(loaded.cert[0].as_ref()).unwrap();
    let day = 86_400;
    // At the time the end of the certificate is exactly 30 days away it is not due, and a second later it is.
    assert!(!due_for(&good, end - 30 * day));
    assert!(due_for(&good, end - 30 * day + 1));
    assert!(due_for(&good, end + 1));
    // Whatever the clock says, these are due.
    let now = end - 80 * day;
    assert!(!due_for(&good, now));
    for (cert, key, hosts) in [
        ("missing.pem", "a.key", &["a.test"][..]),
        ("a.pem", "missing.key", &["a.test"]),
        ("garbage.pem", "a.key", &["a.test"]),
        ("a.pem", "other.key", &["a.test"]),
        ("a.pem", "a.key", &["b.test"]),
        ("a.pem", "a.key", &["a.test", "b.test"]),
    ] {
        assert!(
            due_for(&certificate(cert, key, hosts), now),
            "{cert} {key} {hosts:?}"
        );
    }
}
