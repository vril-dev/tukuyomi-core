//! The HTTP/2 side of a connection, for a TLS listener that has `http2` in its settings and a client that chose
//! `h2` in the handshake: a look at the frames that gives the preface and the header blocks a time (`frames`), the
//! head of every stream as the head of an HTTP/1.1 request (`head`), and the connection with its streams (`drive`).

mod drive;
mod frames;
mod head;

pub(super) use drive::run;
