//! The HTTP/1.1 side of a connection: the gate that checks the head of every request before hyper sees it (`gate`),
//! the connection that hyper serves behind the gate (`drive`), and the listener that redirects to https and
//! otherwise answers only the challenge of the CA that issues the certificates with `acme` (`redirect`).

mod drive;
pub mod gate;
mod redirect;

pub(super) use drive::run;
pub(super) use redirect::redirect_to;
