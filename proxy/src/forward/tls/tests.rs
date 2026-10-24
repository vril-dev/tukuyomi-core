//! The keys and certificates of these tests are made by the `openssl` command into a directory of their own: no key
//! or certificate is kept in the repository.

use std::fs::{self, DirBuilder};
use std::os::unix::fs::DirBuilderExt;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use super::*;

static NEXT_DIR: AtomicU32 = AtomicU32::new(0);

/// A certificate authority of a test and the certificates it issues, in a directory that is removed when it is dropped.
pub(in crate::forward) struct Pki {
    dir: PathBuf,
    serial: AtomicU32,
}

/// The files of one certificate and its key.
#[derive(Clone)]
pub(in crate::forward) struct Pair {
    pub(in crate::forward) cert: PathBuf,
    pub(in crate::forward) key: PathBuf,
}

fn openssl(dir: &Path, args: &[&str]) {
    let out = Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("run the openssl command");
    assert!(
        out.status.success(),
        "openssl {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

impl Pki {
    pub(in crate::forward) fn new() -> Pki {
        let dir = std::env::temp_dir().join(format!(
            "tukuyomi-upstream-pki-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .expect("make the directory of the test certificates");
        openssl(
            &dir,
            &[
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-nodes",
                "-keyout",
                "ca.key",
                "-out",
                "ca.pem",
                "-subj",
                "/CN=test-ca",
                "-days",
                "2",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign",
            ],
        );
        Pki {
            dir,
            serial: AtomicU32::new(100),
        }
    }

    /// The file of the authority.
    pub(in crate::forward) fn ca(&self) -> PathBuf {
        self.dir.join("ca.pem")
    }

    /// A certificate for `sans` (each of the form `DNS:name` or `IP:address`), signed by the authority, and its key.
    /// `stem` is the start of the names of the files.
    pub(in crate::forward) fn issue(&self, stem: &str, sans: &[&str]) -> Pair {
        let serial = self.serial.fetch_add(1, Ordering::Relaxed).to_string();
        let (key, csr, ext, cert) = (
            format!("{stem}.key"),
            format!("{stem}.csr"),
            format!("{stem}.ext"),
            format!("{stem}.pem"),
        );
        fs::write(
            self.dir.join(&ext),
            format!(
                "basicConstraints=CA:FALSE\nsubjectAltName={}\n",
                sans.join(",")
            ),
        )
        .unwrap();
        openssl(
            &self.dir,
            &[
                "req",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-nodes",
                "-keyout",
                &key,
                "-out",
                &csr,
                "-subj",
                &format!("/CN={stem}"),
            ],
        );
        openssl(
            &self.dir,
            &[
                "x509",
                "-req",
                "-in",
                &csr,
                "-CA",
                "ca.pem",
                "-CAkey",
                "ca.key",
                "-set_serial",
                &serial,
                "-out",
                &cert,
                "-days",
                "2",
                "-extfile",
                &ext,
            ],
        );
        Pair {
            cert: self.dir.join(cert),
            key: self.dir.join(key),
        }
    }

    /// A file of the directory with these bytes.
    pub(in crate::forward) fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.dir.join(name);
        fs::write(&path, bytes).unwrap();
        path
    }
}

impl Drop for Pki {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn refused(path: &Path) -> Fault {
    match roots(path) {
        Ok(_) => panic!("the file was taken"),
        Err(fault) => fault,
    }
}

#[test]
fn the_file_of_authorities_holds_1_to_100_certificates_and_is_at_most_1_mib() {
    let pki = Pki::new();
    let one = fs::read(pki.ca()).unwrap();
    for count in [1, 100] {
        let path = pki.file("many.pem", &one.repeat(count));
        assert_eq!(roots(&path).unwrap().roots.len(), count);
    }
    assert_eq!(
        refused(&pki.file("many.pem", &one.repeat(101))),
        Fault::NotCertificates
    );
    // The size is that of the file, whatever is in it besides the certificate.
    let padded = |len: usize| {
        let mut bytes = one.clone();
        bytes.resize(len, b'\n');
        pki.file("padded.pem", &bytes)
    };
    assert_eq!(roots(&padded(1 << 20)).unwrap().roots.len(), 1);
    assert_eq!(refused(&padded((1 << 20) + 1)), Fault::TooLarge);
}

#[test]
fn a_file_that_is_not_authorities_in_pem_is_refused_and_a_fifo_is_not_waited_for() {
    let pki = Pki::new();
    assert_eq!(refused(Path::new("/nonexistent/ca.pem")), Fault::Unreadable);
    assert_eq!(refused(pki.ca().parent().unwrap()), Fault::Unreadable);
    let fifo = pki.ca().with_file_name("fifo.pem");
    let made = Command::new("mkfifo").arg(&fifo).status().unwrap();
    assert!(made.success());
    assert_eq!(refused(&fifo), Fault::Unreadable);
    // Nothing in PEM, a key and no certificate, a certificate whose base64 is broken.
    let key = fs::read_to_string(pki.issue("k", &["DNS:k.test"]).key).unwrap();
    let broken = "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n";
    for (name, text) in [
        ("empty.pem", String::new()),
        ("text.pem", "no certificate here\n".to_string()),
        ("key.pem", key),
        ("broken.pem", broken.to_string()),
    ] {
        assert_eq!(
            refused(&pki.file(name, text.as_bytes())),
            Fault::NotCertificates,
            "{name}"
        );
    }
    // A certificate in PEM whose bytes are no certificate cannot be a trust anchor.
    let junk = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    assert_eq!(
        refused(&pki.file("junk.pem", junk.as_bytes())),
        Fault::NotAnchor
    );
}

#[test]
fn a_server_is_checked_for_the_server_name_of_the_group_else_its_name_else_its_address() {
    let by = |server_name: Option<&str>| Settings {
        ca_file: PathBuf::from("/ca.pem"),
        server_name: server_name.map(str::to_string),
    };
    let named = Address::Name {
        name: "app.test".to_string(),
        port: 443,
    };
    let literal = |text: &str| Address::Literal(text.parse().unwrap());
    let dns = |text: &str| dns_name(text).unwrap();
    assert_eq!(name_of(&by(None), &named), Some(dns("app.test")));
    assert_eq!(
        name_of(&by(Some("api.test")), &named),
        Some(dns("api.test"))
    );
    assert_eq!(
        name_of(&by(Some("api.test")), &literal("192.0.2.1:443")),
        Some(dns("api.test"))
    );
    let ip = |text: &str| ServerName::IpAddress(text.parse::<std::net::IpAddr>().unwrap().into());
    assert_eq!(
        name_of(&by(None), &literal("192.0.2.1:443")),
        Some(ip("192.0.2.1"))
    );
    assert_eq!(
        name_of(&by(None), &literal("[::ffff:192.0.2.1]:443")),
        Some(ip("192.0.2.1"))
    );
    assert_eq!(
        name_of(&by(None), &literal("[2001:db8::1]:443")),
        Some(ip("2001:db8::1"))
    );
    // A label may not start or end with `-` in TLS, though a server name may.
    for text in ["-a.test", "a-.test", "a..test", ""] {
        assert!(dns_name(text).is_none(), "{text:?}");
    }
    assert!(dns_name("a_b.test").is_some());
}
