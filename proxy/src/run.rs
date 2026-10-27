//! The running proxy process, in the parts it is made of: `start` (the arguments, the short commands that take the
//! place of the proxy, and `prepare`, the steps from the configuration to the kernel configuration), `serve` (the
//! runtime part: the driver, the wait for the kernel, the listeners and the accept side), `reload` (SIGUSR1 and
//! SIGUSR2), `stop`, `signals` (what the process waits for, behind one poll), `status` (the listener that answers
//! `/healthz`, `/readyz` and `/metrics`), `control` (the socket on which the admin process asks for the state and for
//! a switch), `notify` (the notices to the service manager) and `host` (the checks of the
//! host process).
//!
//! Start-up runs in this order: the logger thread, one argument (the absolute clean path of the configuration file),
//! the host checks, the configuration, the lookup of the names of the upstream servers (in the same step, the CA file
//! of each upstream group that has `tls` is read), the certificate and key files of the TLS listeners, the rules store
//! (the chosen generation, the hold on it, its directory, mode and routes, and with them the kernel configuration), the
//! record file (when the configuration has `records`: the directory is looked at, the file is opened and the logger is
//! given it; a refusal ends the start with exit code 1 before the inspector is started), the random part of the
//! numbers of the requests, the runtime and the signal handlers, the socket of the notices to
//! the service manager, the status listener (bound here, so that an address that cannot be bound ends the start with
//! exit code 1 before the inspector is started), the control socket (when the configuration has `admin`; bound here
//! for the same reason, see `control`), the driver thread, the wait for the kernel to be ready, bind, accept. The steps
//! from the configuration to the kernel configuration are `prepare`,
//! which `config check` runs as well. The rules store is read here, and again when SIGUSR1 comes; the certificate
//! and key files are read here, and again when SIGUSR2 comes. Handlers exist for SIGTERM, SIGINT, SIGHUP, SIGUSR1 and SIGUSR2 only and are installed before the
//! kernel starts its child process; SIGCHLD is never handled. The listeners are bound only after the kernel is ready,
//! all of them or none, and the accept side takes a connection permit before every accept (see
//! `inbound::transport::accept`). When they are bound, `/readyz` says `ready` (as long as the kernel that serves is) and,
//! if the environment has `NOTIFY_SOCKET`, `READY=1` is sent (see `notify`). The status listener is not one of the
//! listeners of the configuration: it is bound earlier, answers before the proxy is ready (`/healthz` 200, `/readyz`
//! 503), forwards nothing and takes no permit of the accept side (see `status`).
//!
//! `config check <config>` refuses a process that runs as root and then takes the steps of `prepare`, and writes the
//! lines of the start headed `config check:` where the start heads them `start:`. It builds no runtime, starts no
//! kernel and no inspector, binds nothing, installs no signal handler, and looks at neither SIGCHLD nor the
//! descriptors. The hold on the generation is taken as at the start, and ends with the command; like the start, it
//! makes the directory `using` of the store and the file of the generation in it when they are not there yet, which
//! is the one thing the command writes. When all the steps pass, the standard output gets one line, `accepted`, and
//! the exit code is 0. Every other line goes to the standard error and starts with `config check:`, except after a
//! wrong argument, where the line starts with `config:` and the usage line follows (as with `rules` and `acme`).
//! The exit codes are those of the start. The command does not check what comes after `prepare`: that the
//! inspector can be started and the rules can be built (the start does that, and `rules import` has tried the rules
//! before they are a generation), that the listeners and the status address can be bound, that the record file can
//! be opened and that the control socket can be bound.
//!
//! The upstream groups and the routes to them are read from the configuration file when the proxy starts, and stay
//! as they are until it is started again; so do the addresses that the names of the servers have then, the
//! authorities in the CA files of the groups that have `tls` (SIGUSR2 does not read them again), and the listeners
//! with the hosts of their certificates.
//!
//! SIGUSR1 makes the proxy switch to the generation that the rules store chooses now (`rules::switch` reads the
//! store, the driver starts the new inspector and moves the requests over when it is ready). It is a line in the
//! records and nothing else before the listeners are bound, while a switch is under way, and while the proxy stops.
//! A switch order on the control socket takes the same steps (see `control`) once the store chooses the generation
//! that the order expects, and is answered when the switch has ended.
//! SIGUSR2 reads every certificate and key file of every TLS listener again. If all of them pass the checks, they
//! replace the old ones for the handshakes that start from then on (a connection that is open keeps what it has);
//! if one does not, none is replaced and a line says which. It is a line and nothing else before the listeners are
//! bound and while the proxy stops, and it has nothing to do with SIGUSR1. A certificate with `acme` whose files do
//! not exist yet is not a refusal, at the start or at SIGUSR2: a line names it, and it is left out of the handshakes
//! until a SIGUSR2 finds its files (the command `acme renew` makes them).
//!
//! The first cause of a stop (a signal, or a failure of start-up or of the driver) fixes the time `t0`. From then
//! on `/readyz` says `stopping`, and `STOPPING=1` is sent if the environment has `NOTIFY_SOCKET`. The stop closes the
//! listeners, the control socket (its file is removed) and the way from the connections to the driver (a request
//! that starts from then on is refused, and a connection that waits for its next request is closed), tells the driver
//! to finish inspecting by
//! `t0 + stop_inspect`, waits for the connections until `t0 + stop_wait` and aborts what is left (a tunnel, which is
//! a WebSocket that the proxy copies, is not ended by the stop: it runs until it ends by itself or is aborted
//! there), closes the status listener (it answers until the connections are done), then waits for the driver's end
//! until `t0 + stop_wait + kill_grace`. The exit code is 0 only when the
//! stop was not caused by a failure and the driver reports a stopped kernel whose child exit and per-start
//! directory removal are confirmed, and the same for every kernel that was stopped before it; 1 for any other end,
//! and for a process that runs as root or fails another host check, names of upstream servers that cannot be looked
//! up, a CA file of an upstream group that cannot be used, a refused certificate or key file, a refused rules
//! store or generation, no random number for the numbers of the requests, a status address that cannot be bound, a
//! record file that cannot be opened, or a control socket that cannot be bound (nothing has been started then, the
//! inspector included); 2 for
//! a wrong argument or a refused configuration. The log is flushed for at most 200 ms at the end.

mod control;
pub(crate) mod host;
mod notify;
mod reload;
mod serve;
mod signals;
mod start;
mod status;
mod stop;

use start::EXIT_OK;
pub use start::{EXIT_FAILED, start};
