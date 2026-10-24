//! Helpers of the tests of the command: a directory of its own, the `openssl` command, a certificate authority and the
//! certificate it gives to 127.0.0.1, and an HTTPS server that answers with what a test gives it. No key or
//! certificate is kept in the repository; they are made when a test runs.

use std::collections::VecDeque;
use std::fs::{self, DirBuilder};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use rustls::ServerConfig;
use rustls::crypto::aws_lc_rs::default_provider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

static NEXT: AtomicU32 = AtomicU32::new(0);

/// A directory of a test, removed when it is dropped.
pub(crate) struct Scratch(PathBuf);

impl Scratch {
    pub(crate) fn new() -> Scratch {
        let dir = std::env::temp_dir().join(format!(
            "tukuyomi-acme-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .expect("make the directory of a test");
        Scratch(dir)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }

    pub(crate) fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Runs `openssl` in `dir` and gives its standard output.
pub(crate) fn openssl(dir: &Path, args: &[&str]) -> String {
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
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The text of a base64 string in the URL-safe alphabet as bytes.
pub(crate) fn unurl(text: &str) -> Vec<u8> {
    let (mut out, mut bits, mut count) = (Vec::new(), 0u32, 0u32);
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => panic!("not in the URL-safe alphabet"),
        };
        bits = ((bits << 6) | u32::from(value)) & 0xffff;
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push(u8::try_from((bits >> count) & 0xff).unwrap());
        }
    }
    out
}

/// A certificate authority named `name` and a certificate for 127.0.0.1 that it signed, as the files `<name>-ca.pem`,
/// `<name>.pem` and `<name>.key` of `dir`.
pub(crate) fn authority(dir: &Path, name: &str) {
    let (ca_key, ca, key, csr, ext, cert) = (
        format!("{name}-ca.key"),
        format!("{name}-ca.pem"),
        format!("{name}.key"),
        format!("{name}.csr"),
        format!("{name}.ext"),
        format!("{name}.pem"),
    );
    let curve = [
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:prime256v1",
        "-nodes",
    ];
    let mut ca_args = vec![
        "req",
        "-x509",
        "-keyout",
        &ca_key,
        "-out",
        &ca,
        "-subj",
        "/CN=test-ca",
        "-days",
        "2",
    ];
    ca_args.extend(curve);
    ca_args.extend([
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign",
    ]);
    openssl(dir, &ca_args);
    let mut csr_args = vec!["req", "-keyout", &key, "-out", &csr, "-subj", "/CN=server"];
    csr_args.extend(curve);
    openssl(dir, &csr_args);
    fs::write(
        dir.join(&ext),
        "subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\n",
    )
    .unwrap();
    openssl(
        dir,
        &[
            "x509",
            "-req",
            "-in",
            &csr,
            "-CA",
            &ca,
            "-CAkey",
            &ca_key,
            "-set_serial",
            "5",
            "-out",
            &cert,
            "-days",
            "2",
            "-extfile",
            &ext,
        ],
    );
}

/// A whole HTTP/1.1 response.
pub(crate) fn response(status: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str("\r\n");
    [out.as_bytes(), body].concat()
}

/// An HTTPS server on 127.0.0.1 with the certificate `<name>.pem` of `authority`. It answers each connection with the
/// next response that was `push`ed (and closes a connection when there is none), and keeps what it was asked.
pub(crate) struct Canned {
    pub(crate) port: u16,
    pub(crate) requests: Arc<Mutex<Vec<String>>>,
    script: Arc<Mutex<VecDeque<Vec<u8>>>>,
    task: JoinHandle<()>,
}

impl Canned {
    /// Needs a runtime to be entered.
    pub(crate) async fn start(dir: &Path, name: &str) -> Canned {
        let chain = CertificateDer::pem_file_iter(dir.join(format!("{name}.pem")))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = PrivateKeyDer::from_pem_file(dir.join(format!("{name}.key"))).unwrap();
        let config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let script: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
        let task = {
            let (requests, script) = (requests.clone(), script.clone());
            tokio::spawn(async move {
                loop {
                    let Ok((sock, _)) = listener.accept().await else {
                        return;
                    };
                    let Ok(mut stream) = acceptor.accept(sock).await else {
                        continue;
                    };
                    let mut raw = Vec::new();
                    let mut buf = [0u8; 4096];
                    loop {
                        let Ok(n) = stream.read(&mut buf).await else {
                            break;
                        };
                        if n == 0 {
                            break;
                        }
                        raw.extend_from_slice(&buf[..n]);
                        let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
                            continue;
                        };
                        let head = String::from_utf8_lossy(&raw[..end]).to_ascii_lowercase();
                        let length = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if raw.len() >= end + 4 + length {
                            break;
                        }
                    }
                    requests
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push(String::from_utf8_lossy(&raw).into_owned());
                    let answer = script
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .pop_front();
                    if let Some(answer) = answer {
                        let _ = stream.write_all(&answer).await;
                    }
                    let _ = stream.shutdown().await;
                }
            })
        };
        Canned {
            port,
            requests,
            script,
            task,
        }
    }

    pub(crate) fn url(&self, path: &str) -> String {
        format!("https://127.0.0.1:{}{path}", self.port)
    }

    pub(crate) fn push(&self, answer: Vec<u8>) {
        self.script
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push_back(answer);
    }

    /// The requests so far, whole.
    pub(crate) fn asked(&self) -> Vec<String> {
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Drop for Canned {
    fn drop(&mut self) {
        self.task.abort();
    }
}
