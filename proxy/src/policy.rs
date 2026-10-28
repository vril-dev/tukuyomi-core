//! What turns a request away before its route is looked for, whichever route it would take and whether or not the
//! route skips the inspection: the networks that may not use the proxy at all (`access` of the configuration, the
//! type `forward::client_ip::Access` that a route has as well) and the most requests a client may make (`rate`). The
//! values come from the top-level `access` and `rate_limit` objects (see `config`), are read when the proxy starts and
//! stay as they are until it is started again. `check` asks them in that order. `inbound::conn` calls it at the start
//! of every request, and the listener that redirects to https calls it before it redirects (after it has answered the
//! challenge of the CA). A request that is turned away is answered before its body is read and before the inspection
//! is asked for.

pub mod rate;
mod refusal;

pub use rate::RateLimit;
pub use refusal::{Refusal, check};
