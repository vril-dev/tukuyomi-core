//! The notices to the service manager that the proxy is ready and that it is stopping (`sd_notify`).
//!
//! When the environment has `NOTIFY_SOCKET`, the proxy sends one datagram, `READY=1`, once every forwarding listener is
//! bound, and one, `STOPPING=1`, at the first cause of a stop, to the socket the variable names: an absolute path, or
//! `@` and a name for a name in the abstract namespace of Linux. Any other value is refused with one line, and the
//! proxy goes on without notices. A notice that cannot be sent changes nothing but a line. The socket does not wait,
//! so a manager that does not read cannot hold the proxy. The inspector gets no notice socket: its environment is
//! empty.

use std::ffi::{OsStr, OsString};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::path::PathBuf;

use crate::log::Log;

/// The most bytes of a path, or of the name after the `@`: what the address of a Unix socket holds, less the end byte.
const MAX_NAME: usize = 107;

/// Where the notices go.
enum Target {
    Path(PathBuf),
    Abstract(SocketAddr),
}

/// The target that a value of `NOTIFY_SOCKET` names, or `None` for any other value.
fn target(value: &OsStr) -> Option<Target> {
    let bytes = value.as_bytes();
    match bytes.split_first() {
        Some((b'@', name)) if (1..=MAX_NAME).contains(&name.len()) => {
            SocketAddr::from_abstract_name(name)
                .ok()
                .map(Target::Abstract)
        }
        Some((b'/', _)) if bytes.len() <= MAX_NAME => Some(Target::Path(PathBuf::from(value))),
        _ => None,
    }
}

/// Sends the notices, or does nothing when there is no socket to send them to.
pub(super) struct Notify {
    sender: Option<(UnixDatagram, Target)>,
}

impl Notify {
    /// The notices for the value of `NOTIFY_SOCKET`, which is `None` when the variable is not set.
    pub(super) fn new(value: Option<OsString>, log: &Log) -> Notify {
        let none = Notify { sender: None };
        let Some(value) = value else {
            return none;
        };
        let Some(target) = target(&value) else {
            log.line(
                "start: NOTIFY_SOCKET is not an absolute path or an @ and a name, no notice is sent",
            );
            return none;
        };
        let socket = UnixDatagram::unbound().and_then(|socket| {
            socket.set_nonblocking(true)?;
            Ok(socket)
        });
        match socket {
            Ok(socket) => Notify {
                sender: Some((socket, target)),
            },
            Err(_) => {
                log.line("start: no socket for the notices of NOTIFY_SOCKET, no notice is sent");
                none
            }
        }
    }

    /// The notices for the environment of the process.
    pub(super) fn from_env(log: &Log) -> Notify {
        Notify::new(std::env::var_os("NOTIFY_SOCKET"), log)
    }

    /// Every forwarding listener is bound.
    pub(super) fn ready(&self, log: &Log) {
        self.send("READY=1", log);
    }

    /// The proxy begins to stop.
    pub(super) fn stopping(&self, log: &Log) {
        self.send("STOPPING=1", log);
    }

    fn send(&self, message: &str, log: &Log) {
        let Some((socket, target)) = &self.sender else {
            return;
        };
        let sent = match target {
            Target::Path(path) => socket.send_to(message.as_bytes(), path),
            Target::Abstract(address) => socket.send_to_addr(message.as_bytes(), address),
        };
        if let Err(e) = sent {
            match e.raw_os_error() {
                Some(errno) => log.line(&format!("notify: {message} not sent, errno {errno}")),
                None => log.line(&format!("notify: {message} not sent")),
            }
        }
    }
}

#[cfg(test)]
mod tests;
