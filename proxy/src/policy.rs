//! What turns a request away before its route is looked for, whichever route it would take and whether or not the
//! route skips the inspection: the networks and countries that may not use the proxy at all (`access` of the
//! configuration, the type `forward::client_ip::Access` that a route has as well) and the most requests a client may
//! make (`rate`). The values come from the top-level `access`, `rate_limit` and `geo` objects (see `config`), are read
//! when the proxy starts and stay as they are until it is started again. The countries are those that `country` reads
//! from the database that `geo` names. `check` asks the `access` and the `rate_limit` in that order. `inbound::conn`
//! calls it at the start of every request, and the listener that redirects to https calls it before it redirects
//! (after it has answered the challenge of the CA). A request that is turned away is answered before its body is read
//! and before the inspection is asked for.

pub mod country;
pub mod mmdb;
pub mod rate;
mod refusal;

pub use rate::RateLimit;
pub use refusal::{Refusal, check};
