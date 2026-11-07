//! The managed configuration: the part of the configuration that is to be changed from the admin screens (the sites
//! with their certificates, the upstream groups, the routes, the default group, and the `access` and `rate_limit` of
//! the proxy), kept in versions in a directory of its own, the managed store, which the `managed` object of the main
//! file names (see `config`). The main file keeps the rest, and does not write what a version holds.
//!
//! The store holds `versions/<64 lowercase hexadecimal digits>.json`, a version (see `version`), `files/<64 digits>`,
//! a certificate chain, a private key or a file of authorities that a version names, `current`, the record of the
//! chosen version (its 64 digits and a newline), and `lock`, which a command that changes the store holds with
//! `File::try_lock` until it ends, so that one command at a time changes it. The name of a version and of a file is the
//! SHA-256 of its bytes, which are at most 1 MiB; neither changes once it is there, and each is checked against its
//! name every time it is read, so one whose bytes are not what the name says is refused, never used. A version or a
//! file is written to `<name>.new`, synced and renamed onto its name, and `current` is replaced through
//! `current.new` in the same way, the directory being synced after each; a reader sees the old entry or the new one,
//! whole, and a command that stopped halfway leaves at most a `.new`, which the next write of that name removes. No
//! version is removed here. Only the store directory itself is examined, as the directory of the rules store is: a real
//! directory (not a link) owned by the user that the file system sees for this process, without group or other
//! permission bits. What is read is opened without following a link and without waiting for a writer.
//!
//! The store also holds `acme/<64 digits>/chain` and `acme/<64 digits>/key`: the certificate chain and the private key
//! of a site with `acme`, which the command `acme renew` writes and replaces (see `acme`). They are outside the
//! versions: their directory is named by the hosts of the site (`acme_name`), not by a version, and their names
//! are not their SHA-256, for they are replaced in place. `acme/` and the directories in it are real directories, made
//! (0700) by the command when they are not there; one that is not there yet, or a file that is not, is a certificate
//! that has not been issued yet, and anything else that is wrong with them is refused.
//!
//! The proxy reads the main file and a version as one configuration (`load`): when it starts, for `config check` and at
//! SIGHUP, with the version that `current` names, and for a reload order of its control socket with the version that
//! the order names. Every TLS listener of the main file then chooses, by the name the client asks for, from the
//! certificates of the sites and that of the way to the admin process, which the main file writes in `admin.route` and
//! the proxy makes itself (see `config::admin`, `inbound::transport::tls`). The commands (see `command`) make a version
//! from a document whose files are named by their paths (`managed import`), choose one after the same reading as the
//! proxy's (`managed activate`), and list them (`managed list`); a running proxy takes the version they choose at the
//! next SIGHUP or start. The admin process puts a version in force in a running proxy the other way round (see
//! `apply`): the proxy reads its configuration again with the version by a reload order, and the store chooses it
//! only once the proxy has taken it. The proxy never writes the store.

pub mod apply;
pub mod command;
mod load;
pub(crate) mod store;
mod version;

#[cfg(test)]
pub(crate) use load::whole;
pub use load::{Choice, LoadError, Version, load};
pub use store::{Listed, ManagedError, Placed, Store, acme_name};
pub use version::{Site, SiteCertificate, SiteOf};
