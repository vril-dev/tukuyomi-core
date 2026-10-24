//! The keys and certificates of these tests are made by the `openssl` command into a directory of their own: no key
//! or certificate is kept in the repository.

use std::fs::{self, DirBuilder};
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use rustls::crypto::aws_lc_rs::default_provider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore, SupportedProtocolVersion, version};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::{Builder, Runtime};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream as ClientStream;

use super::*;
use crate::config::{CertificateConfig, ListenerConfig, ListenerKind, MinVersion, TlsConfig};

static NEXT_DIR: AtomicU32 = AtomicU32::new(0);

/// A certificate authority of a test and the certificates it issues, in a directory that is removed when it is dropped.
pub(in crate::inbound) struct Pki {
    dir: PathBuf,
    serial: AtomicU32,
}

/// The files of one certificate and its key.
#[derive(Clone)]
pub(in crate::inbound) struct Pair {
    pub(in crate::inbound) cert: PathBuf,
    pub(in crate::inbound) key: PathBuf,
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
    pub(in crate::inbound) fn new() -> Pki {
        let dir = std::env::temp_dir().join(format!(
            "tukuyomi-pki-{}-{}",
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

    /// A certificate for the names `sans` (each `DNS:` name in the certificate), signed by the authority, and its
    /// key. `name` is the stem of the files; a name that is used again makes new files of the same names.
    pub(in crate::inbound) fn issue(&self, name: &str, sans: &[&str]) -> Pair {
        let serial = self.serial.fetch_add(1, Ordering::Relaxed).to_string();
        let (key, csr, ext, cert) = (
            format!("{name}.key"),
            format!("{name}.csr"),
            format!("{name}.ext"),
            format!("{name}.pem"),
        );
        let list: Vec<String> = sans.iter().map(|san| format!("DNS:{san}")).collect();
        fs::write(
            self.dir.join(&ext),
            format!(
                "basicConstraints=CA:FALSE\nsubjectAltName={}\n",
                list.join(",")
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
                &format!("/CN={name}"),
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
    pub(in crate::inbound) fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.dir.join(name);
        fs::write(&path, bytes).unwrap();
        path
    }

    /// The authority as the roots of a client.
    fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_file(self.dir.join("ca.pem")).unwrap())
            .unwrap();
        roots
    }

    /// A client that trusts the authority, speaks only `versions` and offers `alpn`.
    pub(in crate::inbound) fn client(
        &self,
        versions: &[&'static SupportedProtocolVersion],
        alpn: &[&[u8]],
    ) -> TlsConnector {
        let mut config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_protocol_versions(versions)
            .unwrap()
            .with_root_certificates(self.roots())
            .with_no_client_auth();
        config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
        TlsConnector::from(Arc::new(config))
    }

    pub(in crate::inbound) fn any_client(&self) -> TlsConnector {
        self.client(&[&version::TLS13, &version::TLS12], &[])
    }
}

impl Drop for Pki {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

pub(in crate::inbound) fn der(path: &Path) -> CertificateDer<'static> {
    CertificateDer::from_pem_file(path).unwrap()
}

/// A TLS listener at the loopback address with these certificates: files and hosts.
pub(in crate::inbound) fn listener(
    min_version: MinVersion,
    certificates: &[(&Pair, &[&str])],
) -> ListenerConfig {
    ListenerConfig {
        address: "127.0.0.1:1".parse().unwrap(),
        kind: ListenerKind::Tls(TlsConfig {
            min_version,
            certificates: certificates
                .iter()
                .map(|(pair, hosts)| CertificateConfig {
                    cert_file: pair.cert.clone(),
                    key_file: pair.key.clone(),
                    hosts: hosts.iter().map(|host| host.to_string()).collect(),
                })
                .collect(),
        }),
    }
}

fn runtime() -> Runtime {
    Builder::new_current_thread().enable_all().build().unwrap()
}

// ---- names ----

#[test]
fn a_host_is_found_exactly_or_by_one_label_in_front_of_a_wildcard_and_the_exact_one_wins() {
    let certificate = |hosts: &[&str]| CertificateConfig {
        cert_file: PathBuf::from("/a"),
        key_file: PathBuf::from("/b"),
        hosts: hosts.iter().map(|host| host.to_string()).collect(),
    };
    let names = Names::new(&[
        certificate(&["*.a.example", "other.example"]),
        certificate(&["www.a.example", "a.example"]),
    ]);
    assert_eq!(names.find("www.a.example"), Some(1));
    assert_eq!(names.find("WWW.A.Example"), Some(1));
    assert_eq!(names.find("api.a.example"), Some(0));
    assert_eq!(names.find("other.example"), Some(0));
    assert_eq!(names.find("a.example"), Some(1));
    // A wildcard is one label: not the name alone, not two labels, not a name that only ends alike.
    for name in [
        "x.y.a.example",
        "xa.example",
        "example",
        "",
        ".a.example",
        "b.example",
    ] {
        assert_eq!(names.find(name), None, "{name}");
    }
    let hosts = names.hosts(0).unwrap();
    assert!(hosts.covers("api.a.example") && hosts.covers("other.example"));
    assert!(!hosts.covers("a.example") && !hosts.covers("www.b.example"));
    // The `Host` of a request: the port and the dot at the end and the case do not matter; a literal names no host.
    for host in [
        &b"api.a.example"[..],
        b"API.a.example:8443",
        b"api.a.example.",
        b"other.example:80",
    ] {
        assert!(hosts.covers_host(Some(host)), "{host:?}");
    }
    for host in [
        None,
        Some(&b"a.example"[..]),
        Some(b"192.0.2.1"),
        Some(b"[::1]:8443"),
        Some(b"api.a.example:0"),
        Some(b"api..a.example"),
        Some(b""),
    ] {
        assert!(!hosts.covers_host(host), "{host:?}");
    }
}

// ---- reading the files ----

fn load(listener: ListenerConfig) -> Result<Tls, Refusal> {
    Tls::load(&[listener], &Files)
}

fn refusal(listener: ListenerConfig) -> (&'static str, usize, Option<usize>) {
    match load(listener) {
        Ok(_) => panic!("the certificates were taken"),
        Err(refusal) => (refusal.why, refusal.listener, refusal.certificate),
    }
}

#[test]
fn a_certificate_is_checked_against_its_key_and_its_hosts_before_it_is_taken() {
    let pki = Pki::new();
    let a = pki.issue("a", &["a.example", "*.a.example"]);
    let b = pki.issue("b", &["b.example"]);
    let take = |pair: &Pair, hosts: &[&str]| load(listener(MinVersion::Tls12, &[(pair, hosts)]));
    assert!(take(&a, &["a.example", "*.a.example", "www.a.example"]).is_ok());

    // The key of another certificate.
    let crossed = Pair {
        cert: a.cert.clone(),
        key: b.key.clone(),
    };
    assert_eq!(
        refusal(listener(MinVersion::Tls12, &[(&crossed, &["a.example"])])).0,
        Fault::NotPair.text()
    );
    // A host the certificate does not cover: a name, a name under a name, a wildcard of another name.
    for host in ["c.example", "a.example.net", "*.b.example", "*.example"] {
        let (why, at, place) = refusal(listener(MinVersion::Tls12, &[(&a, &[host])]));
        assert_eq!(
            (why, at, place),
            (Fault::NotCovered.text(), 1, Some(1)),
            "{host}"
        );
    }
    // A certificate for one name does not cover the wildcard of it.
    assert_eq!(
        refusal(listener(MinVersion::Tls12, &[(&b, &["*.b.example"])])).0,
        Fault::NotCovered.text()
    );
    // The place of the certificate is told: the second certificate of the second listener.
    let two = [
        listener(MinVersion::Tls12, &[(&a, &["a.example"])]),
        listener(
            MinVersion::Tls12,
            &[(&a, &["a.example"]), (&b, &["x.example"])],
        ),
    ];
    let refused = Tls::load(&two, &Files).err().expect("refused");
    assert_eq!((refused.listener, refused.certificate), (2, Some(2)));
    let text = refused.to_string();
    assert!(text.ends_with("(listener 2, certificate 2)"), "{text}");
}

#[test]
fn a_file_that_is_missing_too_large_or_not_what_it_should_be_refuses_the_start() {
    let pki = Pki::new();
    let a = pki.issue("a", &["a.example"]);
    let b = pki.issue("b", &["b.example"]);
    let one = |pair: &Pair| refusal(listener(MinVersion::Tls12, &[(pair, &["a.example"])])).0;
    let with = |cert: PathBuf, key: PathBuf| one(&Pair { cert, key });

    let missing = pki.dir.join("missing.pem");
    assert_eq!(
        with(missing.clone(), a.key.clone()),
        Fault::Unreadable.text()
    );
    assert_eq!(with(a.cert.clone(), missing), Fault::Unreadable.text());
    // A directory is not a file.
    assert_eq!(
        with(pki.dir.clone(), a.key.clone()),
        Fault::Unreadable.text()
    );
    // A FIFO is refused as it is found: the open does not wait for a writer.
    let fifo = pki.dir.join("fifo.pem");
    let made = Command::new("mkfifo").arg(&fifo).status();
    assert!(made.expect("run the mkfifo command").success());
    assert_eq!(with(fifo.clone(), a.key.clone()), Fault::Unreadable.text());
    assert_eq!(with(a.cert.clone(), fifo), Fault::Unreadable.text());
    // The limit is 1 MiB: a file of that size is read (and found to be no certificate), one byte more is too large.
    let at_limit = pki.file("limit.pem", &vec![b'#'; 1 << 20]);
    assert_eq!(with(at_limit, a.key.clone()), Fault::NotCertificates.text());
    let over = pki.file("over.pem", &vec![b'#'; (1 << 20) + 1]);
    assert_eq!(with(over.clone(), a.key.clone()), Fault::TooLarge.text());
    assert_eq!(with(a.cert.clone(), over), Fault::TooLarge.text());
    // No certificate, or not PEM; and a key file with no key, two keys, or a certificate in place of a key.
    let empty = pki.file("empty.pem", b"");
    assert_eq!(
        with(empty.clone(), a.key.clone()),
        Fault::NotCertificates.text()
    );
    assert_eq!(with(a.cert.clone(), empty), Fault::NotOneKey.text());
    let two = pki.file(
        "two.key",
        &[fs::read(&a.key).unwrap(), fs::read(&b.key).unwrap()].concat(),
    );
    assert_eq!(with(a.cert.clone(), two), Fault::NotOneKey.text());
    assert_eq!(
        with(a.cert.clone(), a.cert.clone()),
        Fault::NotOneKey.text()
    );
    // More than ten certificates in a chain.
    let chain = |n: usize| pki.file("chain.pem", &fs::read(&a.cert).unwrap().repeat(n));
    assert_eq!(
        with(chain(11), a.key.clone()),
        Fault::NotCertificates.text()
    );
    assert!(
        load(listener(
            MinVersion::Tls12,
            &[(
                &Pair {
                    cert: chain(10),
                    key: a.key.clone()
                },
                &["a.example"]
            )]
        ))
        .is_ok()
    );
    // A key that is broken PEM.
    let broken = pki.file(
        "broken.key",
        b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
    );
    assert_eq!(with(a.cert.clone(), broken), Fault::KeyType.text());
}

// ---- the handshake ----

/// What the two ends of one handshake made of it.
struct Outcome {
    server: std::io::Result<Arc<Hosts>>,
    client: std::io::Result<ClientStream<TcpStream>>,
}

/// One handshake with the TLS listener at position 0, the client saying `name` as its server name.
async fn shake(tls: &Arc<Tls>, client: TlsConnector, name: ServerName<'static>) -> Outcome {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server: JoinHandle<std::io::Result<Arc<Hosts>>> = {
        let tls = tls.clone();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await?;
            let handshake = tls.handshake(0).expect("a TLS listener");
            // The stream is kept until the client has seen the end, or the end would be a reset.
            let (stream, hosts) = timeout(Duration::from_secs(10), handshake.accept(sock))
                .await
                .map_err(|_| std::io::Error::other("the handshake did not end"))??;
            drop(stream);
            Ok(hosts)
        })
    };
    let sock = TcpStream::connect(addr).await.unwrap();
    let client = timeout(Duration::from_secs(10), client.connect(name, sock))
        .await
        .expect("the client's handshake ended");
    Outcome {
        server: server.await.unwrap(),
        client,
    }
}

fn name(text: &str) -> ServerName<'static> {
    ServerName::try_from(text.to_owned()).unwrap()
}

fn served(outcome: &Outcome) -> Vec<u8> {
    let stream = outcome.client.as_ref().expect("the client's handshake");
    stream.get_ref().1.peer_certificates().unwrap()[0].to_vec()
}

#[test]
fn the_certificate_is_chosen_by_the_server_name_and_there_is_no_default() {
    runtime().block_on(async {
        let pki = Pki::new();
        let exact = pki.issue("exact", &["www.a.example"]);
        let wild = pki.issue("wild", &["*.a.example", "a.example"]);
        let tls = Arc::new(
            Tls::load(
                &[listener(
                    MinVersion::Tls12,
                    &[
                        (&wild, &["*.a.example", "a.example"]),
                        (&exact, &["www.a.example"]),
                    ],
                )],
                &Files,
            )
            .unwrap(),
        );
        for (sni, want) in [
            ("www.a.example", &exact),
            ("WWW.A.EXAMPLE", &exact),
            ("api.a.example", &wild),
            ("a.example", &wild),
        ] {
            let outcome = shake(&tls, pki.any_client(), name(sni)).await;
            assert_eq!(served(&outcome), der(&want.cert).to_vec(), "{sni}");
            assert!(outcome.server.is_ok(), "{sni}");
        }
        // A wildcard stands for one label, and a name that no host has gets nothing: the handshake fails on both
        // ends. So does a client that sends no name (an address in place of one).
        for sni in ["x.y.a.example", "b.example", "example"] {
            let outcome = shake(&tls, pki.any_client(), name(sni)).await;
            assert!(outcome.server.is_err() && outcome.client.is_err(), "{sni}");
        }
        let none = ServerName::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST).into());
        let outcome = shake(&tls, pki.any_client(), none).await;
        assert!(outcome.server.is_err() && outcome.client.is_err());
    });
}

#[test]
fn the_oldest_version_is_the_setting_and_the_only_protocol_is_http_1_1() {
    runtime().block_on(async {
        let pki = Pki::new();
        let a = pki.issue("a", &["a.example"]);
        let old = Arc::new(
            Tls::load(
                &[listener(MinVersion::Tls12, &[(&a, &["a.example"])])],
                &Files,
            )
            .unwrap(),
        );
        let new = Arc::new(
            Tls::load(
                &[listener(MinVersion::Tls13, &[(&a, &["a.example"])])],
                &Files,
            )
            .unwrap(),
        );
        let only_12 = || pki.client(&[&version::TLS12], &[]);
        let only_13 = || pki.client(&[&version::TLS13], &[]);
        assert!(
            shake(&old, only_12(), name("a.example"))
                .await
                .client
                .is_ok()
        );
        assert!(
            shake(&old, only_13(), name("a.example"))
                .await
                .client
                .is_ok()
        );
        let refused = shake(&new, only_12(), name("a.example")).await;
        assert!(refused.server.is_err() && refused.client.is_err());
        assert!(
            shake(&new, only_13(), name("a.example"))
                .await
                .client
                .is_ok()
        );

        // A client that offers protocols without `http/1.1` is refused; one that offers it gets it; one that offers
        // none is served (as HTTP/1.1).
        let both = &[&version::TLS13, &version::TLS12][..];
        let refused = shake(&old, pki.client(both, &[b"h2"]), name("a.example")).await;
        assert!(refused.server.is_err() && refused.client.is_err());
        let offered = shake(
            &old,
            pki.client(both, &[b"h2", b"http/1.1"]),
            name("a.example"),
        )
        .await;
        let stream = offered.client.unwrap();
        assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
        let none = shake(&old, pki.any_client(), name("a.example")).await;
        assert_eq!(none.client.unwrap().get_ref().1.alpn_protocol(), None);
        assert!(none.server.is_ok());
    });
}

// ---- reading the files again ----

#[test]
fn a_reload_replaces_every_certificate_or_none() {
    runtime().block_on(async {
        let pki = Pki::new();
        let a = pki.issue("a", &["a.example"]);
        let b = pki.issue("b", &["b.example"]);
        let listeners = [listener(
            MinVersion::Tls12,
            &[(&a, &["a.example"]), (&b, &["b.example"])],
        )];
        let tls = Arc::new(Tls::load(&listeners, &Files).unwrap());
        let seen = |sni: &'static str| {
            let (tls, pki) = (tls.clone(), &pki);
            async move { served(&shake(&tls, pki.any_client(), name(sni)).await) }
        };
        let (old_a, old_b) = (seen("a.example").await, seen("b.example").await);
        assert_eq!(old_a, der(&a.cert).to_vec());

        // Both files are replaced by new ones: every handshake from now on uses the new ones.
        let (new_a, new_b) = (
            pki.issue("a", &["a.example"]),
            pki.issue("b", &["b.example"]),
        );
        assert_eq!((&new_a.cert, &new_b.key), (&a.cert, &b.key));
        tls.reload(&listeners, &Files).unwrap();
        let (now_a, now_b) = (seen("a.example").await, seen("b.example").await);
        assert_eq!(now_a, der(&new_a.cert).to_vec());
        assert_ne!((&now_a, &now_b), (&old_a, &old_b));

        // One file is replaced by a good one and one is broken: nothing changes.
        pki.issue("a", &["a.example"]);
        fs::write(&b.key, b"not a key").unwrap();
        let refused = tls.reload(&listeners, &Files).expect_err("refused");
        assert_eq!((refused.listener, refused.certificate), (1, Some(2)));
        assert_eq!(seen("a.example").await, now_a);
        // A certificate that no longer covers its host is refused as well.
        pki.issue("b", &["c.example"]);
        assert!(tls.reload(&listeners, &Files).is_err());
        assert_eq!(seen("a.example").await, now_a);
    });
}
