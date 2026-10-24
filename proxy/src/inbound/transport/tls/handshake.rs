//! The TLS handshake of one listener.
//!
//! The configuration is made with the crypto provider named outright, TLS 1.3 and, if the listener allows it, TLS
//! 1.2, the suites and key exchanges the provider has by default, no client certificate, no early data, tickets from
//! the provider's ticketer (its keys change as the provider says), and the session cache that rustls has by default.
//! The protocols of ALPN are `http/1.1`, and `h2` before it if the listener has `http2` in its settings: a client
//! that offers protocols and none of these is refused, and a client that offers none is taken to speak HTTP/1.1.
//! A client that offers both gets `h2` from a listener that has it.
//!
//! The certificate is chosen by the server name of the client (see `sni`). A client that sends no name, or a name
//! that no host of the listener has, gets no certificate and the handshake fails: there is no default certificate.
//! The keys come from the material in use when the handshake starts (see `certs`). A handshake that has finished
//! tells which hosts the certificate it used covers.

use std::io;
use std::sync::Arc;

use rustls::crypto::aws_lc_rs::{Ticketer, default_provider};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ServerConfig, SupportedProtocolVersion, version};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

use super::certs::{Fault, Store};
use super::sni::{Hosts, Names};
use crate::config::{MinVersion, TlsConfig};

const ALPN: &[u8] = b"http/1.1";
const ALPN_H2: &[u8] = b"h2";

/// The certificate for a handshake: the one the name of the client finds among the hosts of the listener.
#[derive(Debug)]
struct Resolver {
    listener: usize,
    names: Arc<Names>,
    store: Arc<Store>,
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let index = self.names.find(hello.server_name()?)?;
        self.store.current().get(self.listener)?.get(index).cloned()
    }
}

/// The handshake of one TLS listener.
pub struct Handshake {
    acceptor: TlsAcceptor,
    names: Arc<Names>,
}

impl Handshake {
    /// `listener` is the position of the listener, which is where its certificates are in the material.
    pub(super) fn new(
        listener: usize,
        tls: &TlsConfig,
        store: Arc<Store>,
    ) -> Result<Handshake, Fault> {
        let names = Arc::new(Names::new(&tls.certificates));
        let resolver = Arc::new(Resolver {
            listener,
            names: names.clone(),
            store,
        });
        let versions: &[&SupportedProtocolVersion] = match tls.min_version {
            MinVersion::Tls12 => &[&version::TLS13, &version::TLS12],
            MinVersion::Tls13 => &[&version::TLS13],
        };
        let mut config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_protocol_versions(versions)
            .map_err(|_| Fault::Build)?
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        config.alpn_protocols = if tls.http2.is_some() {
            vec![ALPN_H2.to_vec(), ALPN.to_vec()]
        } else {
            vec![ALPN.to_vec()]
        };
        config.ticketer = Ticketer::new().map_err(|_| Fault::Build)?;
        Ok(Handshake {
            acceptor: TlsAcceptor::from(Arc::new(config)),
            names,
        })
    }

    /// The hosts of the certificates of the listener.
    pub fn names(&self) -> &Names {
        &self.names
    }

    /// Runs the handshake on `sock`. The caller bounds its time. On success: the stream, and the hosts of the
    /// certificate that the handshake used.
    pub async fn accept(&self, sock: TcpStream) -> io::Result<(TlsStream<TcpStream>, Arc<Hosts>)> {
        let stream = self.acceptor.accept(sock).await?;
        let hosts = stream
            .get_ref()
            .1
            .server_name()
            .and_then(|name| self.names.find(name))
            .and_then(|index| self.names.hosts(index))
            .cloned()
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "no certificate was chosen")
            })?;
        Ok((stream, hosts))
    }
}
