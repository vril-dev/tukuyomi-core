//! The HTTP/1.1 side of a connection: the gate that checks the head of every request before hyper sees it (`gate`),
//! the connection that hyper serves behind the gate (`drive`), and the listener that only redirects to https
//! (`redirect`).

mod drive;
pub mod gate;
mod redirect;

pub(super) use drive::run;
pub(super) use redirect::redirect_to;
