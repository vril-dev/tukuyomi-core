//! The start of the process, before the runtime runs: the arguments, which of the short commands (`rules`, `acme`,
//! `config`, `managed`) the process is, whether it is the admin process or one of its commands `admin bootstrap` and
//! `admin reset` (see `admin`), and the steps from the configuration to the kernel configuration (`prepare`), which
//! `config check` runs as well. The steps before the rules store (`read_parts`) are run again when the proxy reads
//! the configuration file again (at SIGHUP, and for a reload order of the control socket with the version that the
//! order names), and by `managed activate` with the version it is to choose; a refusal there comes back with the part
//! that refused and its sentence, for the answer to the order.

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use super::host;
use super::reload::Fixed;
use super::serve::run;
use crate::acme;
use crate::admin;
use crate::config::{
    self, AdminConfig, AdminWay, ForwardConfig, Keep, KernelSettings, PolicyConfig, ProxyConfig,
    Records, StatusConfig, StoreConfig, addresses,
};
use crate::forward::resolve;
use crate::forward::tls::{self, Authorities, Fault};
use crate::inbound::challenge::Challenge;
use crate::inbound::session::RequestIds;
use crate::inbound::transport::tls::{Files, Tls};
use crate::log::Log;
use crate::log::sink::RecordFile;
use crate::managed::{self, Choice, LoadError};
use crate::rules::bundle::{Fingerprint, Mode, hex};
use crate::rules::command;
use crate::rules::routes::Routes;
use crate::rules::store;
use crate::rules::switch::Switcher;

pub(super) const EXIT_OK: u8 = 0;
pub const EXIT_FAILED: u8 = 1;
const EXIT_USAGE: u8 = 2;
const CHECK_USAGE: &str = "usage: tukuyomi-proxy config check <config>";
const ADMIN_USAGE: [&str; 3] = [
    "usage: tukuyomi-proxy admin <config>",
    "       tukuyomi-proxy admin bootstrap <config> <name>",
    "       tukuyomi-proxy admin reset <config> <name>",
];

/// Everything before the runtime runs, then the runtime. Returns the exit code.
pub fn start(log: &Log) -> u8 {
    let mut args = std::env::args_os().skip(1).peekable();
    if args.peek().is_some_and(|arg| arg == "rules") {
        args.next();
        let args: Vec<OsString> = args.collect();
        return match command::run(&args, &mut io::stdout(), &mut io::stderr()) {
            command::Exit::Done => EXIT_OK,
            command::Exit::Failed => EXIT_FAILED,
            command::Exit::Usage => EXIT_USAGE,
        };
    }
    if args.peek().is_some_and(|arg| arg == "acme") {
        args.next();
        let args: Vec<OsString> = args.collect();
        return match acme::command::run(&args, &mut io::stdout(), &mut io::stderr()) {
            acme::command::Exit::Done => EXIT_OK,
            acme::command::Exit::Failed => EXIT_FAILED,
            acme::command::Exit::Usage => EXIT_USAGE,
        };
    }
    if args.peek().is_some_and(|arg| arg == "config") {
        args.next();
        let args: Vec<OsString> = args.collect();
        return config_check(&args, log);
    }
    if args.peek().is_some_and(|arg| arg == "managed") {
        args.next();
        let args: Vec<OsString> = args.collect();
        return match managed::command::run(&args, &mut io::stdout(), log) {
            managed::command::Exit::Done => EXIT_OK,
            managed::command::Exit::Failed => EXIT_FAILED,
            managed::command::Exit::Usage => EXIT_USAGE,
        };
    }
    if args.peek().is_some_and(|arg| arg == "admin") {
        args.next();
        let args: Vec<OsString> = args.collect();
        return admin_command(&args, log);
    }
    let path = match (args.next(), args.next()) {
        (Some(path), None) if config::clean_abs(Path::new(&path)) => PathBuf::from(path),
        _ => {
            log.line(
                "start: expected one argument, the absolute clean path of the configuration file",
            );
            return EXIT_USAGE;
        }
    };
    if let Err(text) = host::check() {
        log.line(&format!("start: host check refused: {text}"));
        return EXIT_FAILED;
    }
    let Prepared {
        proxy,
        forward,
        tls,
        challenge,
        kernel,
        generation,
        mode,
        routes,
        switcher,
        status,
        records,
        admin,
        policy,
        sha256,
        managed,
        hold,
        fixed,
    } = match prepare(&path, "start", log) {
        Ok(prepared) => prepared,
        Err(code) => return code,
    };
    if let Some(records) = &records {
        let handed = match RecordFile::open(records) {
            Ok(file) => log.attach(file),
            Err(why) => {
                log.line(&format!("start: record file refused: {why}"));
                return EXIT_FAILED;
            }
        };
        if !handed {
            log.line("start: record file refused: the logger did not take it");
            return EXIT_FAILED;
        }
        if records.ship.is_some()
            && let Err(why) = log.watch_ship(records)
        {
            log.line(&format!("start: shipper refused: {why}"));
            return EXIT_FAILED;
        }
    }
    let keep = records
        .as_ref()
        .map_or(Keep::BestEffort, |records| records.keep);
    let Some(ids) = RequestIds::new() else {
        log.line("start: no random number is available for the request numbers");
        return EXIT_FAILED;
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            log.line("start: cannot build the runtime");
            return EXIT_FAILED;
        }
    };
    runtime.block_on(run(
        proxy,
        forward,
        tls,
        challenge,
        kernel,
        generation,
        mode,
        routes,
        switcher,
        ids,
        status,
        admin,
        policy,
        keep,
        path,
        sha256,
        managed,
        hold,
        fixed,
        log.clone(),
    ))
}

/// What the steps of start-up before the runtime give.
struct Prepared {
    proxy: ProxyConfig,
    forward: ForwardConfig,
    tls: Tls,
    challenge: Option<Challenge>,
    kernel: tukuyomi_kernel::Config,
    generation: Fingerprint,
    mode: Mode,
    routes: Routes,
    /// Keeps the hold on `generation`, and the store for the switches.
    switcher: Switcher,
    /// Where the status listener is bound, if the configuration has one.
    status: Option<StatusConfig>,
    /// Where the record file is kept, if the configuration has one.
    records: Option<Records>,
    /// The admin process settings, if the configuration has them; the proxy binds its control socket.
    admin: Option<AdminConfig>,
    /// The `access` and the `rate_limit` of the configuration.
    policy: PolicyConfig,
    /// The SHA-256 of the bytes of the configuration file.
    sha256: [u8; 32],
    /// The name of the managed version, if the file has `managed`.
    managed: Option<[u8; 32]>,
    /// The shared lock on the managed version, which the reading of the file again keeps while the version serves.
    hold: Option<managed::Hold>,
    /// The values that a reading of the file again may not change.
    fixed: Fixed,
}

/// What the steps before the rules store give: the configuration with the addresses of the upstream servers in it, the
/// TLS of the listeners and the answer to the challenge of the CA. The proxy builds its setup of them at the start
/// and again when it reads the file again.
pub(crate) struct Parts {
    pub(super) proxy: ProxyConfig,
    pub(super) forward: ForwardConfig,
    pub(super) tls: Tls,
    pub(super) challenge: Option<Challenge>,
    pub(super) kernel: KernelSettings,
    pub(super) store: StoreConfig,
    pub(super) status: Option<StatusConfig>,
    pub(super) records: Option<Records>,
    pub(super) admin: Option<AdminConfig>,
    pub(super) policy: PolicyConfig,
    /// The values that a reading of the file again may not change, as this file has them.
    pub(super) fixed: Fixed,
    /// The SHA-256 of the bytes of the file.
    pub(super) sha256: [u8; 32],
    /// The name of the managed version that was read with the file, if it has `managed`.
    pub(super) managed: Option<[u8; 32]>,
    /// The shared lock on that version (see `managed::Hold`), which goes with the parts if they are not served with.
    pub(super) hold: Option<managed::Hold>,
}

/// The part of a reading of the configuration that refused it. Its word is the `reason` of a reload order of the
/// control socket that the reading refused (see `control`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Reason {
    /// The main file, or its country database.
    Configuration,
    /// The managed version, checked with the main file.
    Version,
    /// The managed store: it, a version or a file that cannot be read or is not what its name says.
    Store,
    /// The lookup of the names of the upstream servers, or the authorities of an upstream group.
    Upstream,
    /// A certificate or key file: of a listener, of a site or of the way to the admin process.
    Tls,
    /// A value that cannot change while the proxy runs (see `reload::Fixed`), `managed` being there or not included.
    Fixed,
    /// The address of a new listener cannot be bound.
    Listener,
    /// The thread of the reading cannot be started, or ended without an answer.
    Thread,
    /// The configuration in force has no `managed`: a reload order is refused before any reading.
    Unmanaged,
}

impl Reason {
    pub(super) fn word(self) -> &'static str {
        match self {
            Reason::Configuration => "configuration",
            Reason::Version => "version",
            Reason::Store => "store",
            Reason::Upstream => "upstream",
            Reason::Tls => "tls",
            Reason::Fixed => "fixed",
            Reason::Listener => "listener",
            Reason::Thread => "thread",
            Reason::Unmanaged => "unmanaged",
        }
    }
}

/// Why a reading of the configuration refused it: the part that refused, and the sentence of the record line that says
/// so, the part of it after `refused: `. The sentence is fixed but for its place (a key, a listener, a site, the way to
/// the admin process, a server of an upstream group), and never shows a value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Refusal {
    pub(super) reason: Reason,
    pub(super) detail: String,
}

impl Refusal {
    /// The exit code of the start, `config check` or `managed activate` that the refusal ends: 2 for the main file, 1
    /// for the rest, a managed version included (as for a generation of rules that is refused).
    pub(crate) fn exit(&self) -> u8 {
        if self.reason == Reason::Configuration {
            EXIT_USAGE
        } else {
            EXIT_FAILED
        }
    }
}

/// The steps of start-up before the rules store: the configuration (with `managed`, with the version of `choice`), the
/// lookup of the names of the upstream servers, the files of the TLS listeners and the challenge of the CA. `name` is
/// at the head of each line: `start` for the start, `config check` for the command of that name, `reload` for a
/// reading of the file again, `managed activate` for that command. A refusal is a line, `<name>: <part> refused:
/// <sentence>`, and comes back with the part and the sentence (`Refusal`, whose `exit` is the exit code).
pub(crate) fn read_parts(
    path: &Path,
    choice: &Choice,
    name: &str,
    log: &Log,
) -> Result<Parts, Refusal> {
    let refuse = |reason: Reason, part: &str, detail: String| {
        log.line(&format!("{name}: {part} refused: {detail}"));
        Refusal { reason, detail }
    };
    let loaded = match managed::load(path, choice) {
        Ok(loaded) => loaded,
        Err(LoadError::Main(e)) => {
            return Err(refuse(Reason::Configuration, "configuration", e.0.into()));
        }
        Err(LoadError::Version(e)) => {
            return Err(refuse(Reason::Version, "managed version", e.0.into()));
        }
        Err(LoadError::Store(e)) => {
            return Err(refuse(Reason::Store, "managed store", e.0.into()));
        }
    };
    log.line(&format!("{name}: configuration accepted"));
    let fixed = Fixed::of(&loaded);
    // A server may not have an address the proxy listens on, the one of the status listener included.
    let mut listening = addresses(&loaded.proxy.listeners);
    listening.extend(loaded.status.map(|status| status.listen));
    // The file of the authorities of a group of a managed version is a file of its store, named by its SHA-256
    // (`Authorities::Stored`): it is read here through the store, which refuses a link and a file that is not what its
    // name says, and `tls::config` refuses it.
    let completed = match &loaded.version {
        None => resolve::complete(loaded.forward, &listening, resolve::system),
        Some(version) => {
            resolve::complete_with(loaded.forward, &listening, resolve::system, |settings| {
                let Authorities::Stored(name) = settings.authorities else {
                    return Err(Fault::Unreadable);
                };
                let bytes = version.store.file(name).map_err(|_| Fault::Unreadable)?;
                tls::config_of(&bytes)
            })
        }
    };
    let mut forward = match completed {
        Ok(done) => {
            for line in &done.lines {
                log.line(&format!("{name}: {line}"));
            }
            done.forward
        }
        Err(refusal) => return Err(refuse(Reason::Upstream, "upstream", refusal.to_string())),
    };
    // No server of a version is the admin process, also once its names are looked up: the way to it is the proxy's own,
    // to `admin.listen`, which the proxy makes itself (see `forward::group`).
    if let (Some(_), Some(admin)) = (&loaded.version, &loaded.admin)
        && let Err(refusal) = resolve::refuse_at(
            &forward,
            admin.listen,
            "a server name has the address of the admin process",
        )
    {
        return Err(refuse(Reason::Upstream, "upstream", refusal.to_string()));
    }
    forward.admin = loaded
        .admin_route
        .as_ref()
        .zip(loaded.admin.as_ref())
        .map(|(route, admin)| AdminWay {
            host: route.host.clone(),
            access: route.access.clone(),
            server: admin.listen,
        });
    let route = loaded.admin_route.as_ref().map(|route| &route.certificate);
    let loaded_tls = match &loaded.version {
        None => Tls::load(&loaded.proxy.listeners, &Files),
        Some(version) => Tls::load_sites(
            &loaded.proxy.listeners,
            route,
            &version.sites,
            &version.store,
            &Files,
        ),
    };
    let tls = match loaded_tls {
        Ok(tls) => tls,
        Err(refusal) => return Err(refuse(Reason::Tls, "tls", refusal.to_string())),
    };
    for place in tls.waiting() {
        log.line(&format!("{name}: tls certificate not issued yet ({place})"));
    }
    let sites = loaded
        .version
        .as_ref()
        .map_or(&[][..], |version| &version.sites);
    let challenge = Challenge::new(loaded.acme.as_ref(), &loaded.proxy.listeners, route, sites);
    let (managed, hold) = loaded
        .version
        .map_or((None, None), |version| (Some(version.name), version.hold));
    Ok(Parts {
        proxy: loaded.proxy,
        forward,
        tls,
        challenge,
        kernel: loaded.kernel,
        store: loaded.store,
        status: loaded.status,
        records: loaded.records,
        admin: loaded.admin,
        policy: loaded.policy,
        fixed,
        sha256: loaded.sha256,
        managed,
        hold,
    })
}

/// The steps of start-up from the configuration to the kernel configuration of the chosen generation, the hold on it
/// and the one on the managed version included. `name` is at the head of each line: `start` for the start, `config
/// check` for the command of that name. A refusal is a line, and its exit code is the error.
fn prepare(path: &Path, name: &str, log: &Log) -> Result<Prepared, u8> {
    let parts = read_parts(path, &Choice::Current, name, log).map_err(|refusal| refusal.exit())?;
    if let Some(version) = parts.managed {
        log.line(&format!("{name}: managed version {}", hex(&version)));
    }
    let rules = match store::open(&parts.store) {
        Ok(rules) => rules,
        Err(e) => {
            log.line(&format!("{name}: rules store refused: {}", e.0));
            return Err(EXIT_FAILED);
        }
    };
    let generation = match rules.current() {
        Ok(Some(generation)) => generation,
        Ok(None) => {
            log.line(&format!(
                "{name}: rules store refused: no generation is chosen"
            ));
            return Err(EXIT_FAILED);
        }
        Err(e) => {
            log.line(&format!("{name}: rules store refused: {}", e.0));
            return Err(EXIT_FAILED);
        }
    };
    // The hold comes before the directory is looked at: a removal that has finished is found there, and one that
    // is going on keeps the hold from being taken.
    let hold = match rules.hold(generation) {
        Ok(hold) => hold,
        Err(e) => {
            log.line(&format!("{name}: rules store refused: {}", e.0));
            return Err(EXIT_FAILED);
        }
    };
    let dir = match rules.generation_dir(generation) {
        Ok(dir) => dir,
        Err(e) => {
            log.line(&format!("{name}: rules store refused: {}", e.0));
            return Err(EXIT_FAILED);
        }
    };
    let engine = match rules.engine(generation) {
        Ok(engine) => engine,
        Err(e) => {
            log.line(&format!("{name}: rules store refused: {}", e.0));
            return Err(EXIT_FAILED);
        }
    };
    let mode = match rules.mode(generation) {
        Ok(mode) => mode,
        Err(e) => {
            log.line(&format!("{name}: rules store refused: {}", e.0));
            return Err(EXIT_FAILED);
        }
    };
    let routes = match rules.routes(generation) {
        Ok(routes) => routes,
        Err(e) => {
            log.line(&format!("{name}: rules store refused: {}", e.0));
            return Err(EXIT_FAILED);
        }
    };
    let kernel = match parts.kernel.for_generation(dir, generation, engine) {
        Ok(kernel) => kernel,
        Err(e) => {
            log.line(&format!("{name}: rules generation refused: {}", e.0));
            return Err(EXIT_FAILED);
        }
    };
    log.line(&format!("{name}: rules generation {}", generation.hex()));
    log.line(&format!("{name}: rules engine {}", engine.name()));
    log.line(&format!("{name}: rules mode {}", mode.name()));
    log.line(&format!("{name}: rules routes {}", routes.len()));
    Ok(Prepared {
        proxy: parts.proxy,
        forward: parts.forward,
        tls: parts.tls,
        challenge: parts.challenge,
        kernel,
        generation,
        mode,
        routes,
        switcher: Switcher::new(rules, parts.kernel, generation, hold),
        status: parts.status,
        records: parts.records,
        admin: parts.admin,
        policy: parts.policy,
        sha256: parts.sha256,
        managed: parts.managed,
        hold: parts.hold,
        fixed: parts.fixed,
    })
}

/// The command `config check`: the host check against root and `prepare`, and nothing of what follows them. `args`
/// is what follows `config`. Returns the exit code.
fn config_check(args: &[OsString], log: &Log) -> u8 {
    const NAME: &str = "config check";
    let path = match check_path(args) {
        Ok(path) => path,
        Err(why) => {
            log.line(&format!("config: {why}"));
            log.line(CHECK_USAGE);
            return EXIT_USAGE;
        }
    };
    if let Err(text) = host::not_root() {
        log.line(&format!("{NAME}: host check refused: {text}"));
        return EXIT_FAILED;
    }
    // What `prepare` gives is dropped at once, and with it the holds on the generation and on the managed version.
    if let Err(code) = prepare(&path, NAME, log) {
        return code;
    }
    let _ = writeln!(io::stdout(), "accepted");
    EXIT_OK
}

/// What the arguments after `admin` ask for.
#[derive(Debug, PartialEq, Eq)]
enum AdminArgs {
    /// The admin process, with its configuration file.
    Run(PathBuf),
    /// The first user, with the configuration file and the name.
    Bootstrap { config: PathBuf, name: String },
    /// The new password of a user, with the configuration file and the name.
    Reset { config: PathBuf, name: String },
}

/// The arguments after `admin`: one absolute clean path, or `bootstrap` or `reset`, one such path and a name.
fn admin_args(args: &[OsString]) -> Result<AdminArgs, &'static str> {
    let path = |arg: &OsString| {
        if config::clean_abs(Path::new(arg)) {
            Ok(PathBuf::from(arg))
        } else {
            Err("the configuration file is not an absolute clean path")
        }
    };
    match args {
        [] => Err("the configuration file is missing"),
        [first, rest @ ..] if first == "bootstrap" => match rest {
            [config, name] => Ok(AdminArgs::Bootstrap {
                config: path(config)?,
                name: name.to_str().ok_or("the name is not text")?.to_owned(),
            }),
            _ => Err("bootstrap takes the configuration file and a name"),
        },
        [first, rest @ ..] if first == "reset" => match rest {
            [config, name] => Ok(AdminArgs::Reset {
                config: path(config)?,
                name: name.to_str().ok_or("the name is not text")?.to_owned(),
            }),
            _ => Err("reset takes the configuration file and a name"),
        },
        [config] => Ok(AdminArgs::Run(path(config)?)),
        _ => Err("admin takes one argument, the configuration file"),
    }
}

/// The admin process or its command. `args` is what follows `admin`. Returns the exit code.
fn admin_command(args: &[OsString], log: &Log) -> u8 {
    let exit = match admin_args(args) {
        Err(why) => {
            log.line(&format!("admin: {why}"));
            for line in ADMIN_USAGE {
                log.line(line);
            }
            return EXIT_USAGE;
        }
        Ok(AdminArgs::Run(path)) => admin::server::run(&path, log),
        Ok(AdminArgs::Bootstrap { config, name }) => {
            admin::users::bootstrap(&config, &name, &mut io::stdin().lock(), log)
        }
        Ok(AdminArgs::Reset { config, name }) => {
            admin::users::reset(&config, &name, &mut io::stdin().lock(), log)
        }
    };
    match exit {
        admin::Exit::Done => EXIT_OK,
        admin::Exit::Failed => EXIT_FAILED,
        admin::Exit::Usage => EXIT_USAGE,
    }
}

/// The configuration file that `args` (what follows `config`) name: `check` and one absolute clean path.
fn check_path(args: &[OsString]) -> Result<PathBuf, &'static str> {
    let (name, rest) = args.split_first().ok_or("a command is missing")?;
    if name != "check" {
        return Err("unknown command");
    }
    match rest {
        [] => Err("the configuration file is missing"),
        [path] if config::clean_abs(Path::new(path)) => Ok(PathBuf::from(path)),
        [_] => Err("the configuration file is not an absolute clean path"),
        _ => Err("check takes one argument, the configuration file"),
    }
}

#[cfg(test)]
mod tests;
