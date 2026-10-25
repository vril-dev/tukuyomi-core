//! The front of the proxy, in folders by what they do: `transport` has the bytes of a connection (the accept side, TLS
//! and the guards of the stream), `http1` and `http2` have the two protocols a request can arrive in, and this folder
//! has what a connection and a request are, whichever protocol they came in: the connection (`session`), the request
//! (`conn`, `head`, `represent`, `upload`) and its answers (`answer`). The answer to the challenge of the CA that issues the
//! certificates with `acme` is made here too (`challenge`), for the plain and the redirecting listeners.

mod answer;
pub mod challenge;
pub mod conn;
pub mod head;
pub mod http1;
pub mod http2;
mod represent;
pub mod session;
pub mod transport;
pub mod upload;
