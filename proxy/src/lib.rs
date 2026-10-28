#![forbid(unsafe_code)]
//! HTTP front of the inspection kernel: the listeners (plain, TLS, or a redirect to https), HTTP/1.1 on every one of
//! them and HTTP/2 on the TLS listeners that turn it on, the upstream groups that its routes choose from, and every
//! request inspected before it is forwarded. The command `acme renew` issues and renews the certificates that have
//! `acme` (see `acme`), and the plain and the redirecting listeners answer the challenge of the CA for it. The admin
//! API runs as a process of its own (see `admin`). The networks that may not use the proxy at all and the most requests
//! a client may make (see `policy`) are applied to every request before its route is looked for.

pub mod acme;
pub mod admin;
pub mod config;
pub mod forward;
pub mod inbound;
pub mod inspect;
pub mod log;
pub mod policy;
pub mod route;
pub mod rules;
pub mod run;
