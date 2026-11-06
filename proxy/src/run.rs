//! The running proxy process, in the parts it is made of: `start` (the arguments, the short commands that take the
//! place of the proxy, the admin process and its command `admin bootstrap`, which are in `admin`, and `prepare`, the
//! steps from the configuration to the kernel configuration), `serve` (the
//! runtime part: the driver, the wait for the kernel, the listeners and the accept side), `reload` (SIGHUP, SIGUSR1
//! and SIGUSR2), `stop`, `signals` (what the process waits for, behind one poll), `status` (the listener that answers
//! `/healthz`, `/readyz` and `/metrics`), `control` (the socket on which the admin process asks for the state and for
//! a switch), `notify` (the notices to the service manager, which the admin process sends as well) and `host` (the
//! checks of the host process, which the admin process makes as well).
//!
//! Start-up runs in this order: the logger thread, one argument (the absolute clean path of the configuration file),
//! the host checks, the configuration (when the file has `managed`, with the version of the managed store that its
//! `current` names and the files it names, see `managed`; the version is on a line of its own, `start: managed version
//! <name>`), the lookup of the names of the upstream servers (in the same step, the CA file of each upstream group that
//! has `tls` is read, from the managed store for a group of a version), the certificate and key files of the TLS
//! listeners, the rules store (the chosen generation, the hold on it, its directory, mode and routes, and with them the
//! kernel configuration), the record file (when the configuration has `records`: the directory is looked at, the file
//! is opened and the logger is given it; a refusal ends the start with exit code 1 before the inspector is started),
//! the random part of the numbers of the requests, the runtime and the signal handlers, the socket of the notices to
//! the service manager, the status listener (bound here, so that an address that cannot be bound ends the start with
//! exit code 1 before the inspector is started), the control socket (when the configuration has `admin`; bound here for
//! the same reason, see `control`), the driver thread, the wait for the kernel to be ready, bind, accept. The steps
//! from the configuration to the kernel configuration are `prepare`, which `config check` runs as well. The
//! configuration file is read here, and again when SIGHUP comes (the steps before the rules store only); the rules
//! store is read here, and again when SIGUSR1 comes; the certificate and key files are read here, and again when
//! SIGUSR2 comes. Handlers exist for SIGTERM, SIGINT, SIGHUP, SIGUSR1 and SIGUSR2 only and are installed before the
//! kernel starts its child process; SIGCHLD is never handled. The listeners are bound only after the kernel is ready,
//! all of them or none, and the accept side takes a connection permit before every accept (see
//! `inbound::transport::accept`). When they are bound, `/readyz` says `ready` (as long as the kernel that serves is)
//! and, if the environment has `NOTIFY_SOCKET`, `READY=1` is sent (see `notify`). The status listener is not one of the
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
//! SIGHUP reads the configuration file again, the one the proxy was started with, with the version of the managed store
//! that is chosen then if the file has `managed`, on a thread of its own: the steps of the start before the rules
//! store, with their lines headed `reload:`. When the file passes them, and none of the values that cannot change while
//! the proxy runs differs from the ones it had at the start, the proxy binds the addresses of the listeners that are
//! new, makes a setup of the file and puts it in the place of the old one in a single step, with the listeners put in
//! the order of the file. Those values are `proxy.max_conns`, `max_buffered_bytes`, `drive_slice_ms`, `ready_wait_ms`,
//! `stop_inspect_ms`, `stop_wait_ms`, `records` but for its `keep`, `status`, `admin`, `rules.store`, `managed` and
//! `kernel`. A setup is what the configuration gives the connections: the other values of `proxy`, the upstream groups
//! and the routes to them (the names of the servers are looked up again, and the CA files of the groups that have `tls`
//! are read again), the TLS of the listeners with the hosts of their certificates (the certificate and key files are
//! read again) and the answer to the challenge of the CA, the `access`, the `rate_limit` and the country database (see
//! `policy`), and the `records.keep`. A connection that starts after that takes the new setup. A connection that is
//! open keeps the setup it started with for its requests, and is wound down: an HTTP/1.1 connection that waits for its
//! next request is closed, one with a request under way, or with part of the head of the next one, is closed after its
//! response, and an HTTP/2 connection is told with a `GOAWAY` and ends when its open streams are done. No request is
//! turned away for that. A tunnel (a WebSocket that the proxy copies) and a response of a route with a `stream` go on
//! until their own time. The clients that the rate limit counts go on being counted when the old and the new
//! configuration both have a `rate_limit` with the same `keys`, `rate` and `burst`; otherwise the new limit counts from
//! nothing, and a line says so. The listeners can be added, removed and put in another order. A listener whose address
//! is still in the file keeps its socket, wherever it is now, so nobody is refused at it; the listener of a new address
//! is bound before anything is replaced, all of them or none; the listener of an address that is gone is closed, which
//! cuts the connections that have not started there (the ones still in the backlog of the system, and the one that
//! waits for a permit), while a connection that is open goes on as above. An address that overlaps one in use, such as
//! `127.0.0.1:8080` for `0.0.0.0:8080` (or the other way round), cannot be bound, and the file is refused: that change
//! takes two readings, or a restart. An address written another way for the same socket, such as
//! `[::ffff:127.0.0.1]:8080` for `127.0.0.1:8080`, counts as another address, cannot be bound while the first is in
//! use, and so refuses the file like an overlap. The rules store is not read, and the generation that serves is not
//! touched. A file that is refused anywhere (it is not valid, a name cannot be looked up, a certificate or key file is
//! refused, a value that cannot change differs, an address cannot be bound) changes nothing, and a line says why. Both
//! ends are counted in `tukuyomi_config_reloads_total`. SIGHUP is a line and nothing else while a reading is under way,
//! before the listeners are bound and while the proxy stops. SIGUSR2 while a reading is under way reads the certificate
//! files when the reading has ended, for the setup that is current then. A thread that cannot be started, or that ends
//! without an answer, is a refusal and no cause of a stop; an answer that comes while the proxy stops is dropped.
//!
//! SIGUSR1 makes the proxy switch to the generation that the rules store chooses now (`rules::switch` reads the
//! store, the driver starts the new inspector and moves the requests over when it is ready). It is a line in the
//! records and nothing else before the listeners are bound, while a switch is under way, and while the proxy stops.
//! A switch order on the control socket takes the same steps (see `control`) once the store chooses the generation
//! that the order expects, and is answered when the switch has ended.
//! SIGUSR2 reads every certificate and key file of every TLS listener again (with `managed`, the files of the way to
//! the admin process, and those of the sites from the managed store, `acme/` for a site with `acme`). If all of them
//! pass the checks, they replace the old ones for the handshakes that start from then on (a connection that is open
//! keeps what it has);
//! if one does not, none is replaced and a line says which. It is a line and nothing else before the listeners are
//! bound and while the proxy stops, and it has nothing to do with SIGUSR1. A certificate with `acme` whose files do
//! not exist yet, of a listener, of the way to the admin process or of a site, is not a refusal, at the start, at
//! SIGHUP or at SIGUSR2: a line names it, and it is left out of the handshakes until a reading finds its files (the
//! command `acme renew` makes them).
//!
//! The first cause of a stop (SIGTERM or SIGINT, or a failure of start-up or of the driver) fixes the time `t0`. From
//! then on `/readyz` says `stopping`, and `STOPPING=1` is sent if the environment has `NOTIFY_SOCKET`. The stop
//! closes the listeners, the control socket (its file is removed) and the way from the connections to the driver (a
//! request that starts from then on is refused, and a connection that waits for its next request is closed), tells
//! the driver to finish inspecting by `t0 + stop_inspect`, waits for the connections until `t0 + stop_wait` and
//! aborts what is left (a tunnel, which is a WebSocket that the proxy copies, is not ended by the stop: it runs until
//! it ends by itself or is aborted there), closes the status listener (it answers until the connections are done),
//! then waits for the driver's end until `t0 + stop_wait + kill_grace`. The exit code is 0 only when the
//! stop was not caused by a failure and the driver reports a stopped kernel whose child exit and per-start
//! directory removal are confirmed, and the same for every kernel that was stopped before it; 1 for any other end,
//! and for a process that runs as root or fails another host check, names of upstream servers that cannot be looked
//! up, a CA file of an upstream group that cannot be used, a refused certificate or key file, a refused rules
//! store or generation, a refused managed store or version, no random number for the numbers of the requests, a
//! status address that cannot be bound, a record file that cannot be opened, or a control socket that cannot be bound
//! (nothing has been started then, the inspector included); 2 for a wrong argument or a refused configuration (the
//! main file). The log is flushed for at most 200 ms at the end.

mod control;
pub(crate) mod host;
pub(crate) mod notify;
mod reload;
mod serve;
mod signals;
mod start;
mod status;
mod stop;

use start::EXIT_OK;
pub(crate) use start::read_parts;
pub use start::{EXIT_FAILED, start};
