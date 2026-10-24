#![forbid(unsafe_code)]
//! HTTP front of the inspection kernel: the listeners (plain, TLS, or a redirect to https), HTTP/1.1 on every one of
//! them and HTTP/2 on the TLS listeners that turn it on, the upstream groups that its routes choose from, and every
//! request inspected before it is forwarded. The command `acme renew` issues and renews the certificates that have
//! `acme` (see `acme`), and the plain and the redirecting listeners answer the challenge of the CA for it.

pub mod acme;
pub mod config;
pub mod forward;
pub mod host;
pub mod inbound;
pub mod inspect;
pub mod log;
pub mod route;
pub mod rules;
