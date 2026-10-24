//! HTTPS to the CA.
//!
//! A request is made on a connection of its own: TCP, then TLS with the authorities of `ca_file` as the only roots (the
//! configuration of `forward::tls`, with the name of the URL as the name to check), then one HTTP/1.1 request with
//! `Connection: close`, and the answer. No redirect is followed: an answer is what the CA's URL gave. The URL is
//! `https://` only, at most 2048 bytes, printable ASCII, with no user and no fragment. The head of an answer and its
//! body are at most 64 KiB each. Every request ends by the deadline of the whole command.

use std::path::Path;
use std::time::Duration;

use bytes::Bytes;
use http::header::{CONNECTION, CONTENT_TYPE, HOST, USER_AGENT};
use http::{HeaderMap, Method, Request, Uri};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1::{self, SendRequest};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use serde::de::DeserializeOwned;
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout_at};
use tokio_rustls::TlsConnector;

use super::Failure;
use crate::forward::tls::{self, Settings};
use crate::log::escaped;

/// The longest URL in bytes.
const MAX_URL: usize = 2048;
/// The most bytes of the body of an answer, and of its head.
const MAX_BODY: usize = 64 * 1024;
const MAX_HEADERS: usize = 64;
/// The longest the `type` of a problem document is written out, in bytes of the CA's text.
const MAX_PROBLEM: usize = 200;
/// The longest nonce in bytes.
const MAX_NONCE: usize = 256;
/// The pause between two looks at a resource that is not ready, when the CA does not say, and its bounds.
const RETRY_DEFAULT: u64 = 1;
const RETRY_LEAST: u64 = 1;
const RETRY_MOST: u64 = 10;
const TIMED_OUT: Failure = Failure::Text("the time for the command is used up");

/// A URL that the CA gave, or that the configuration names.
#[derive(Clone, Debug)]
pub struct Url {
    text: String,
    /// The host without the brackets of an IPv6 address.
    host: String,
    port: u16,
    /// The path and the query.
    target: String,
    /// The host and the port as the URL has them, for the `Host` field.
    authority: String,
    name: ServerName<'static>,
}

impl Url {
    pub fn parse(text: &str) -> Result<Url, Failure> {
        const BAD: Failure =
            Failure::Text("a URL is not an https URL of at most 2048 bytes without a user");
        if text.len() > MAX_URL
            || !text.starts_with("https://")
            || !text.bytes().all(|b| (0x21..=0x7e).contains(&b))
            || text.contains('#')
        {
            return Err(BAD);
        }
        let uri: Uri = text.parse().map_err(|_| BAD)?;
        let authority = uri.authority().ok_or(BAD)?;
        // The port is read from the text: the URI type takes a port that is not a number of 16 bits for no port.
        let after_host = authority
            .as_str()
            .rsplit_once(']')
            .map_or(authority.as_str(), |(_, rest)| rest);
        let port = match after_host.rsplit_once(':') {
            Some((_, digits)) if digits.bytes().all(|b| b.is_ascii_digit()) => {
                digits.parse::<u16>().map_err(|_| BAD)?
            }
            Some(_) => return Err(BAD),
            None => 443,
        };
        if authority.as_str().contains('@') || authority.host().is_empty() || port == 0 {
            return Err(BAD);
        }
        let host = authority.host();
        let host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host);
        Ok(Url {
            text: text.to_owned(),
            host: host.to_owned(),
            port,
            target: uri
                .path_and_query()
                .map_or("/", |target| target.as_str())
                .to_owned(),
            authority: authority.as_str().to_owned(),
            name: ServerName::try_from(host.to_owned()).map_err(|_| BAD)?,
        })
    }

    /// The URL as it was written; a message that is signed for it names it so.
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

/// What the CA answered.
#[derive(Debug)]
pub struct Reply {
    pub status: u16,
    headers: HeaderMap,
    pub body: Vec<u8>,
}

impl Reply {
    /// The first value of the field `name`, if it is text.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name)?.to_str().ok()
    }

    /// The nonce for the next request: `Replay-Nonce` if it is 1 to 256 characters of the URL-safe alphabet.
    pub fn nonce(&self) -> Option<String> {
        self.header("replay-nonce")
            .filter(|nonce| {
                (1..=MAX_NONCE).contains(&nonce.len())
                    && nonce
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            })
            .map(str::to_owned)
    }

    /// How long to wait before looking again: whole seconds of `Retry-After`, from 1 to 10; 1 if it is not there or
    /// is not a number of seconds.
    pub fn retry_after(&self) -> Duration {
        let seconds = self
            .header("retry-after")
            .filter(|text| !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()))
            .map_or(RETRY_DEFAULT, |text| text.parse().unwrap_or(RETRY_MOST));
        Duration::from_secs(seconds.clamp(RETRY_LEAST, RETRY_MOST))
    }

    /// The body as the JSON of type `T`; members that `T` does not name are left alone.
    pub fn json<T: DeserializeOwned>(&self) -> Result<T, Failure> {
        serde_json::from_slice(&self.body)
            .map_err(|_| Failure::Text("an answer of the CA is not the JSON that was expected"))
    }

    /// The `type` of the problem document the body is, as the CA wrote it.
    pub fn problem_type(&self) -> Option<String> {
        let document: serde_json::Value = serde_json::from_slice(&self.body).ok()?;
        document.get("type")?.as_str().map(str::to_owned)
    }

    /// Why an answer that was not the one that was hoped for is a failure: the problem type, if it has one.
    pub fn refused(&self) -> Failure {
        match self.problem_type() {
            Some(kind) => problem(&kind),
            None => Failure::Text("the CA answered with a status that was not expected"),
        }
    }
}

/// The failure for a problem type: at most 200 bytes of it, every byte outside 0x20 to 0x7e written as `\xNN`.
pub fn problem(kind: &str) -> Failure {
    let bytes = kind.as_bytes();
    Failure::Problem(escaped(&bytes[..bytes.len().min(MAX_PROBLEM)]))
}

/// The way to the CA.
#[derive(Clone)]
pub struct Client {
    connector: TlsConnector,
    deadline: Instant,
}

impl Client {
    /// The client whose requests all end by `deadline`. The authorities are read from `ca_file` here.
    pub fn new(ca_file: &Path, deadline: Instant) -> Result<Client, Failure> {
        let config = tls::config(&Settings {
            ca_file: ca_file.to_path_buf(),
            server_name: None,
        })
        .map_err(|_| Failure::Text("the acme ca_file cannot be used for the CA"))?;
        Ok(Client {
            connector: TlsConnector::from(config),
            deadline,
        })
    }

    pub async fn get(&self, url: &Url) -> Result<Reply, Failure> {
        self.send(Method::GET, url, None).await
    }

    pub async fn head(&self, url: &Url) -> Result<Reply, Failure> {
        self.send(Method::HEAD, url, None).await
    }

    /// A POST of `jws`, a signed message.
    pub async fn post(&self, url: &Url, jws: String) -> Result<Reply, Failure> {
        self.send(Method::POST, url, Some(jws)).await
    }

    async fn send(
        &self,
        method: Method,
        url: &Url,
        body: Option<String>,
    ) -> Result<Reply, Failure> {
        match timeout_at(self.deadline, self.exchange(method, url, body)).await {
            Ok(done) => done,
            Err(_) => Err(TIMED_OUT),
        }
    }

    async fn exchange(
        &self,
        method: Method,
        url: &Url,
        body: Option<String>,
    ) -> Result<Reply, Failure> {
        // A host name is looked up by the system on a thread of the blocking pool of the runtime. A deadline cannot
        // stop that thread, so the command ends its runtime without waiting for it.
        let tcp = TcpStream::connect((url.host.as_str(), url.port))
            .await
            .map_err(|_| "the CA cannot be reached")?;
        let _ = tcp.set_nodelay(true);
        let stream = self
            .connector
            .connect(url.name.clone(), tcp)
            .await
            .map_err(|_| "the TLS handshake with the CA failed")?;
        let (mut sender, connection) = http1::Builder::new()
            .max_buf_size(MAX_BODY)
            .max_headers(MAX_HEADERS)
            .handshake(TokioIo::new(stream))
            .await
            .map_err(|_| "the connection to the CA failed")?;
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        let reply = round_trip(&mut sender, method, url, body).await;
        driver.abort();
        reply
    }
}

/// One request on the connection, and the answer read to its end.
async fn round_trip(
    sender: &mut SendRequest<Full<Bytes>>,
    method: Method,
    url: &Url,
    body: Option<String>,
) -> Result<Reply, Failure> {
    let mut request = Request::builder()
        .method(method)
        .uri(url.target.as_str())
        .header(HOST, url.authority.as_str())
        .header(USER_AGENT, "tukuyomi-proxy")
        .header(CONNECTION, "close");
    let payload = match body {
        Some(text) => {
            request = request.header(CONTENT_TYPE, "application/jose+json");
            Bytes::from(text)
        }
        None => Bytes::new(),
    };
    let request = request
        .body(Full::new(payload))
        .map_err(|_| "a request to the CA cannot be made")?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|_| "the CA did not answer")?;
    let (parts, mut incoming) = response.into_parts();
    let mut body = Vec::new();
    while let Some(frame) = incoming.frame().await {
        let frame = frame.map_err(|_| "the answer of the CA was cut off")?;
        if let Ok(data) = frame.into_data() {
            if body.len().saturating_add(data.len()) > MAX_BODY {
                return Err("an answer of the CA is over 64 KiB".into());
            }
            body.extend_from_slice(&data);
        }
    }
    Ok(Reply {
        status: parts.status.as_u16(),
        headers: parts.headers,
        body,
    })
}

#[cfg(test)]
mod tests;
