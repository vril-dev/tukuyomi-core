//! The start of the process, before the runtime runs: the arguments, which of the short commands (`rules`, `acme`,
//! `config`) the process is, and the steps from the configuration to the kernel configuration (`prepare`), which
//! `config check` runs as well.

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use super::host;
use super::serve::run;
use crate::acme;
use crate::config::{self, ForwardConfig, ProxyConfig, StatusConfig, addresses};
use crate::forward::resolve;
use crate::inbound::challenge::Challenge;
use crate::inbound::session::RequestIds;
use crate::inbound::transport::tls::{Files, Tls};
use crate::log::Log;
use crate::rules::bundle::{Fingerprint, Mode};
use crate::rules::command;
use crate::rules::routes::Routes;
use crate::rules::store;
use crate::rules::switch::Switcher;

pub(super) const EXIT_OK: u8 = 0;
pub const EXIT_FAILED: u8 = 1;
const EXIT_USAGE: u8 = 2;
const CHECK_USAGE: &str = "usage: tukuyomi-proxy config check <config>";

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
    } = match prepare(&path, "start", log) {
        Ok(prepared) => prepared,
        Err(code) => return code,
    };
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
}

/// The steps of start-up from the configuration to the kernel configuration of the chosen generation, the hold on it
/// included. `name` is at the head of each line: `start` for the start, `config check` for the command of that name.
/// A refusal is a line, and its exit code is the error.
fn prepare(path: &Path, name: &str, log: &Log) -> Result<Prepared, u8> {
    let loaded = match config::load(path) {
        Ok(loaded) => loaded,
        Err(e) => {
            log.line(&format!("{name}: configuration refused: {}", e.0));
            return Err(EXIT_USAGE);
        }
    };
    log.line(&format!("{name}: configuration accepted"));
    // A server may not have an address the proxy listens on, the one of the status listener included.
    let mut listening = addresses(&loaded.proxy.listeners);
    listening.extend(loaded.status.map(|status| status.listen));
    let forward = match resolve::complete(loaded.forward, &listening, resolve::system) {
        Ok(done) => {
            for line in &done.lines {
                log.line(&format!("{name}: {line}"));
            }
            done.forward
        }
        Err(refusal) => {
            log.line(&format!("{name}: upstream refused: {refusal}"));
            return Err(EXIT_FAILED);
        }
    };
    let tls = match Tls::load(&loaded.proxy.listeners, &Files) {
        Ok(tls) => tls,
        Err(refusal) => {
            log.line(&format!("{name}: tls refused: {refusal}"));
            return Err(EXIT_FAILED);
        }
    };
    for place in tls.waiting() {
        log.line(&format!("{name}: tls certificate not issued yet ({place})"));
    }
    let challenge = Challenge::new(loaded.acme.as_ref(), &loaded.proxy.listeners);
    let rules = match store::open(&loaded.store) {
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
    let kernel = match loaded.kernel.for_generation(dir, generation) {
        Ok(kernel) => kernel,
        Err(e) => {
            log.line(&format!("{name}: rules generation refused: {}", e.0));
            return Err(EXIT_FAILED);
        }
    };
    log.line(&format!("{name}: rules generation {}", generation.hex()));
    log.line(&format!("{name}: rules mode {}", mode.name()));
    log.line(&format!("{name}: rules routes {}", routes.len()));
    Ok(Prepared {
        proxy: loaded.proxy,
        forward,
        tls,
        challenge,
        kernel,
        generation,
        mode,
        routes,
        switcher: Switcher::new(rules, loaded.kernel, generation, hold),
        status: loaded.status,
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
    // What `prepare` gives is dropped at once, and with it the hold on the generation.
    if let Err(code) = prepare(&path, NAME, log) {
        return code;
    }
    let _ = writeln!(io::stdout(), "accepted");
    EXIT_OK
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
