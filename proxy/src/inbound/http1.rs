//! The HTTP/1.1 side of a connection: the gate that checks the head of every request before hyper sees it (`gate`),
//! the connection that hyper serves behind the gate (`drive`), and the listener that redirects to https (`redirect`).
//! Besides the redirect and 404 it answers only the challenge of the CA that issues the certificates with `acme`, and
//! 403 or 429 to a client that the policy of the configuration turns away.

mod drive;
pub mod gate;
mod redirect;

pub(super) use drive::run;
pub(super) use redirect::redirect_to;
