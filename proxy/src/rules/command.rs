//! The commands that change and show the rules store: `rules import`, `rules activate`, `rules remove` and
//! `rules list`.
//!
//! ```text
//! tukuyomi-proxy rules import <config> [--crs <dir>] [--crs-off <name>]... [--rules <file>]... [--data <file>]... [--routes <file>] [--accept-block] [--detect-only]
//! tukuyomi-proxy rules activate <config> <fingerprint>
//! tukuyomi-proxy rules remove <config> <fingerprint>
//! tukuyomi-proxy rules list <config>
//! ```
//!
//! A command is a short process of its own, apart from a running proxy, which does not notice what it does. The
//! configuration is the one of the proxy, as an absolute clean path; the paths of the options are as the operator
//! writes them, from the working directory. `import` builds a bundle from the inputs (`collect`), stages it in the
//! store, tries it (`trial`: an inspector is started on it, three requests are inspected) and makes it a generation
//! only if the trial passes; it does not choose it. With `--detect-only` the bundle is a detect bundle: a request that
//! a rule matches is let through and the match is reported, and the trial passes on such a match and writes a line
//! for each; without it the bundle blocks. With `--routes` the bundle has the routes of the file, a JSON array of
//! `{"host": "<host>", "path": "<path>", "action": "bypass"}` (`host` is optional, no other key is taken): a request
//! that a route matches is not inspected and goes on to the upstream. The routes are checked as the module `routes`
//! says, and a running proxy takes them when it switches to the generation. `activate` chooses a generation, which
//! a proxy that starts later
//! uses, and a running proxy that is told to switch. `remove` deletes a generation that is not the chosen one and
//! that no running proxy uses. `list` shows the generations.
//!
//! The results go to the standard output, one line each, and the first word of a line is the fingerprint: `import`
//! says `created`, `already exists` or `recreated` after it, `activate` says `current`, `remove` says `removed`, and
//! `list` gives the time the generation was made (seconds since the epoch), its mode (`block` or `detect`, and
//! `unknown` when its manifest cannot be read), `routes` and their number for a generation that has routes, and
//! `current` for the chosen one.
//! Everything else goes to the
//! standard error, a line each, and starts with the name of the command. Whatever came from outside (an entry of a
//! directory, the line an inspector left behind) is written with every byte outside 0x20 to 0x7e as `\xNN`.
//!
//! No command runs as root: when any user id of the process is 0, the command writes a `host check refused` line and
//! ends before it reads the configuration. `import` makes the other checks that the proxy makes before it starts too,
//! because it starts an inspector (see `host`).
//!
//! The exit code is 0 for success, 1 for any other end (a refused store or input, a failed trial, a store that is in
//! use, a listed generation whose manifest cannot be read, a process that runs as root) and 2 for a wrong argument or
//! a refused configuration.

use std::ffi::OsString;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::runtime::Builder;
use tokio::signal::unix::{SignalKind, signal};
use tukuyomi_kernel::Failure;

use crate::config::{self, Loaded};
use crate::log::escaped;
use crate::rules::bundle::{Fingerprint, Mode};
use crate::rules::collect::{self, CollectError, Inputs};
use crate::rules::store::{self, Committed, RuleStore, Staged};
use crate::rules::trial::{self, Accepted, Failed, Finish, Limits};
use crate::run::host;

const USAGE: &str = "usage: tukuyomi-proxy rules import <config> [--crs <dir>] [--crs-off <name>]... [--rules <file>]... [--data <file>]... [--routes <file>] [--accept-block] [--detect-only]\n       tukuyomi-proxy rules activate <config> <fingerprint>\n       tukuyomi-proxy rules remove <config> <fingerprint>\n       tukuyomi-proxy rules list <config>";

/// How a command ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    Done,
    Failed,
    Usage,
}

/// What the operator asked for.
#[derive(Debug, PartialEq, Eq)]
enum Command {
    Import {
        config: PathBuf,
        inputs: Inputs,
        accept_block: bool,
    },
    Activate {
        config: PathBuf,
        generation: Fingerprint,
    },
    Remove {
        config: PathBuf,
        generation: Fingerprint,
    },
    List {
        config: PathBuf,
    },
}

/// Where a command writes.
struct Terminal<'a> {
    out: &'a mut dyn Write,
    err: &'a mut dyn Write,
}

impl Terminal<'_> {
    /// A result line. A write that fails does not change how the command ends.
    fn result(&mut self, line: &str) {
        let _ = writeln!(self.out, "{line}");
    }

    fn note(&mut self, line: &str) {
        let _ = writeln!(self.err, "{line}");
    }
}

/// Runs the command that `args` (what follows `rules`) name.
pub fn run(args: &[OsString], out: &mut dyn Write, err: &mut dyn Write) -> Exit {
    let mut term = Terminal { out, err };
    match parse(args) {
        Err(why) => {
            term.note(&format!("rules: {why}"));
            term.note(USAGE);
            Exit::Usage
        }
        Ok(Command::Import {
            config,
            inputs,
            accept_block,
        }) => import(&config, &inputs, accept_block, &mut term),
        Ok(Command::Activate { config, generation }) => activate(&config, generation, &mut term),
        Ok(Command::Remove { config, generation }) => remove(&config, generation, &mut term),
        Ok(Command::List { config }) => list(&config, &mut term),
    }
}

fn parse(args: &[OsString]) -> Result<Command, &'static str> {
    let (name, rest) = args.split_first().ok_or("a command is missing")?;
    if name != "import" && name != "activate" && name != "remove" && name != "list" {
        return Err("unknown command");
    }
    let (config, rest) = rest
        .split_first()
        .ok_or("the configuration file is missing")?;
    if !config::clean_abs(Path::new(config)) {
        return Err("the configuration file is not an absolute clean path");
    }
    let config = PathBuf::from(config);
    if name == "import" {
        parse_import(config, rest)
    } else if name == "activate" {
        match rest {
            [generation] => Ok(Command::Activate {
                config,
                generation: fingerprint(generation)?,
            }),
            _ => Err("activate takes one fingerprint"),
        }
    } else if name == "remove" {
        match rest {
            [generation] => Ok(Command::Remove {
                config,
                generation: fingerprint(generation)?,
            }),
            _ => Err("remove takes one fingerprint"),
        }
    } else if rest.is_empty() {
        Ok(Command::List { config })
    } else {
        Err("list takes no argument after the configuration file")
    }
}

fn fingerprint(arg: &OsString) -> Result<Fingerprint, &'static str> {
    Fingerprint::from_hex(arg.as_bytes())
        .ok_or("the fingerprint is not 64 lowercase hexadecimal digits")
}

fn parse_import(config: PathBuf, rest: &[OsString]) -> Result<Command, &'static str> {
    let mut inputs = Inputs::default();
    let mut accept_block = false;
    let mut args = rest.iter();
    while let Some(arg) = args.next() {
        if arg == "--accept-block" {
            accept_block = true;
            continue;
        }
        if arg == "--detect-only" {
            inputs.mode = Mode::Detect;
            continue;
        }
        // The value of an option is the next argument, which is not another option.
        let value = args
            .next()
            .filter(|value| !value.as_bytes().starts_with(b"--"))
            .ok_or("an option needs a value that does not start with --")?;
        if arg == "--crs" {
            if inputs.crs.replace(PathBuf::from(value)).is_some() {
                return Err("--crs is given twice");
            }
        } else if arg == "--crs-off" {
            inputs.crs_off.push(value.clone());
        } else if arg == "--rules" {
            inputs.rules.push(PathBuf::from(value));
        } else if arg == "--data" {
            inputs.data.push(PathBuf::from(value));
        } else if arg == "--routes" {
            if inputs.routes.replace(PathBuf::from(value)).is_some() {
                return Err("--routes is given twice");
            }
        } else {
            return Err("unknown option");
        }
    }
    if inputs.crs.is_none() && !inputs.crs_off.is_empty() {
        return Err("--crs-off needs --crs");
    }
    Ok(Command::Import {
        config,
        inputs,
        accept_block,
    })
}

/// `: "<escaped subject>"`, or nothing.
fn subject_of(subject: &Option<OsString>) -> String {
    subject.as_ref().map_or_else(String::new, |subject| {
        format!(": \"{}\"", escaped(subject.as_bytes()))
    })
}

/// Refuses a process that runs as root, with a line that names `command`.
fn not_root(command: &str, term: &mut Terminal) -> Result<(), Exit> {
    host::not_root().map_err(|text| {
        term.note(&format!("{command}: host check refused: {text}"));
        Exit::Failed
    })
}

/// The configuration and the store it names.
fn open_store(
    command: &str,
    config: &Path,
    term: &mut Terminal,
) -> Result<(Loaded, Box<dyn RuleStore>), Exit> {
    let loaded = config::load(config).map_err(|e| {
        term.note(&format!("{command}: configuration refused: {}", e.0));
        Exit::Usage
    })?;
    match store::open(&loaded.store) {
        Ok(store) => Ok((loaded, store)),
        Err(e) => {
            term.note(&format!("{command}: rules store refused: {}", e.0));
            Err(Exit::Failed)
        }
    }
}

fn import(config: &Path, inputs: &Inputs, accept_block: bool, term: &mut Terminal) -> Exit {
    const NAME: &str = "rules import";
    // The kernel requires this of its host process, as the proxy checks it before it starts.
    if let Err(text) = host::check() {
        term.note(&format!("{NAME}: host check refused: {text}"));
        return Exit::Failed;
    }
    let (loaded, mut store) = match open_store(NAME, config, term) {
        Ok(opened) => opened,
        Err(exit) => return exit,
    };
    let bundle = match collect::collect(inputs) {
        Ok(bundle) => bundle,
        Err(CollectError { reason, subject }) => {
            term.note(&format!("{NAME}: {reason}{}", subject_of(&subject)));
            return Exit::Failed;
        }
    };
    let staged = match store.stage(&bundle) {
        Ok(staged) => staged,
        Err(e) => {
            term.note(&format!("{NAME}: {}", e.0));
            return Exit::Failed;
        }
    };
    if !try_staged(&loaded, &staged, accept_block, inputs.mode, term) {
        if let Err(e) = store.discard() {
            term.note(&format!("{NAME}: {}", e.0));
        }
        return Exit::Failed;
    }
    match store.commit() {
        Ok(committed) => {
            let how = match committed {
                Committed::Created => "created",
                Committed::Existing => "already exists",
                Committed::Repaired => "recreated, the stored copy was broken",
            };
            term.result(&format!("{} {how}", staged.fingerprint.hex()));
            Exit::Done
        }
        Err(e) => {
            term.note(&format!("{NAME}: {}", e.0));
            Exit::Failed
        }
    }
}

/// Tries the staged bundle and tells how it went. True if it passed. `mode` is the mode of the bundle.
fn try_staged(
    loaded: &Loaded,
    staged: &Staged,
    accept_block: bool,
    mode: Mode,
    term: &mut Terminal,
) -> bool {
    let kernel = match loaded
        .kernel
        .for_generation(staged.dir.clone(), staged.fingerprint)
    {
        Ok(kernel) => kernel,
        Err(e) => {
            term.note(&format!(
                "rules import: the kernel configuration is refused: {}",
                e.0
            ));
            return false;
        }
    };
    let limits = Limits {
        ready_wait: loaded.proxy.ready_wait,
        inspect_wait: loaded.proxy.inspect_wait,
        stop_inspect: loaded.proxy.stop_inspect,
        slice: loaded.proxy.drive_slice,
        accept_block,
        mode,
    };
    match supervised(kernel, limits) {
        Ok(finish) => {
            report(&finish, term);
            finish.passed()
        }
        Err(text) => {
            term.note(&format!("rules import: the trial could not run: {text}"));
            false
        }
    }
}

/// Runs the trial with handlers for SIGINT and SIGTERM, which stop the trial (it then ends the inspector and
/// removes its directory like every other end) instead of ending this process in the middle of it. The handlers
/// are installed before the inspector is started.
fn supervised(kernel: tukuyomi_kernel::Config, limits: Limits) -> Result<Finish, &'static str> {
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "cannot build the runtime")?;
    let interrupt = Arc::new(AtomicBool::new(false));
    runtime.block_on(async {
        for kind in [SignalKind::interrupt(), SignalKind::terminate()] {
            let mut stream = signal(kind).map_err(|_| "cannot install the signal handlers")?;
            let flag = interrupt.clone();
            tokio::spawn(async move {
                while stream.recv().await.is_some() {
                    flag.store(true, Ordering::SeqCst);
                }
            });
        }
        let flag = interrupt.clone();
        tokio::task::spawn_blocking(move || trial::run_supervised(kernel, &limits, &flag))
            .await
            .map_err(|_| "the trial ended abnormally")?
    })
}

/// What the end of a trial says, to the standard error.
fn report(finish: &Finish, term: &mut Terminal) {
    if let Ok(accepted) = &finish.result {
        for item in accepted {
            term.note(&match item {
                Accepted::Block {
                    probe,
                    phase,
                    rule_id,
                    status,
                } => format!(
                    "rules import: accepted a block: {probe}: rule {rule_id} in phase {phase}, status {status}"
                ),
                Accepted::Detected {
                    probe,
                    rule_id,
                    status,
                } => format!(
                    "rules import: detected: {probe}: rule {rule_id}, status {status}"
                ),
            });
        }
    }
    if let Err(failed) = &finish.result {
        term.note(&format!(
            "rules import: the trial failed: {}",
            describe(failed)
        ));
    }
    if let Some(detail) = &finish.detail {
        let line = detail.strip_suffix(b"\n").unwrap_or(detail);
        term.note(&format!(
            "rules import: the inspector said: \"{}\"",
            escaped(line)
        ));
    }
    if !finish.clean {
        term.note(
            "rules import: the inspector did not stop cleanly; a process or a directory may be left behind",
        );
    }
}

pub(crate) fn describe(failed: &Failed) -> String {
    match failed {
        Failed::Interrupted => "stopped by a signal".to_owned(),
        Failed::Start(Failure::Exit(code)) => {
            format!("the inspector refused to start (exit code {code})")
        }
        Failed::Start(other) => format!("the inspector could not be started ({other:?})"),
        Failed::NotReady => "the inspector was not ready in time".to_owned(),
        Failed::Refused { probe, refused } => {
            format!("{probe}: the request was refused ({refused:?})")
        }
        Failed::NoVerdict { probe } => format!("{probe}: no verdict in time"),
        Failed::Blocked {
            probe,
            phase,
            rule_id,
            status,
        } => format!("{probe}: blocked by rule {rule_id} in phase {phase}, status {status}"),
        Failed::Uninspectable { probe, reason } => {
            format!("{probe}: could not be inspected ({reason:?})")
        }
        Failed::NotStopped => "the inspector did not stop as it was asked".to_owned(),
    }
}

fn activate(config: &Path, generation: Fingerprint, term: &mut Terminal) -> Exit {
    const NAME: &str = "rules activate";
    if let Err(exit) = not_root(NAME, term) {
        return exit;
    }
    let (_, mut store) = match open_store(NAME, config, term) {
        Ok(opened) => opened,
        Err(exit) => return exit,
    };
    match store.activate(generation) {
        Ok(()) => {
            term.result(&format!("{} current", generation.hex()));
            Exit::Done
        }
        Err(e) => {
            term.note(&format!("{NAME}: {}", e.0));
            Exit::Failed
        }
    }
}

fn remove(config: &Path, generation: Fingerprint, term: &mut Terminal) -> Exit {
    const NAME: &str = "rules remove";
    if let Err(exit) = not_root(NAME, term) {
        return exit;
    }
    let (_, mut store) = match open_store(NAME, config, term) {
        Ok(opened) => opened,
        Err(exit) => return exit,
    };
    match store.remove(generation) {
        Ok(()) => {
            term.result(&format!("{} removed", generation.hex()));
            Exit::Done
        }
        Err(e) => {
            term.note(&format!("{NAME}: {}", e.0));
            Exit::Failed
        }
    }
}

fn list(config: &Path, term: &mut Terminal) -> Exit {
    const NAME: &str = "rules list";
    if let Err(exit) = not_root(NAME, term) {
        return exit;
    }
    let (_, store) = match open_store(NAME, config, term) {
        Ok(opened) => opened,
        Err(exit) => return exit,
    };
    let generations = match store.list() {
        Ok(generations) => generations,
        Err(e) => {
            term.note(&format!("{NAME}: {}", e.0));
            return Exit::Failed;
        }
    };
    let current = store.current();
    let chosen = current.as_ref().ok().copied().flatten();
    let mut unreadable = Vec::new();
    for generation in &generations {
        let described = store.mode(generation.fingerprint).and_then(|mode| {
            store
                .routes(generation.fingerprint)
                .map(|routes| (mode.name(), routes.len()))
        });
        let (mode, routes) = match described {
            Ok(described) => described,
            Err(e) => {
                unreadable.push((generation.fingerprint, e));
                ("unknown", 0)
            }
        };
        let routes = if routes == 0 {
            String::new()
        } else {
            format!(" routes {routes}")
        };
        let mark = if Some(generation.fingerprint) == chosen {
            " current"
        } else {
            ""
        };
        term.result(&format!(
            "{} {} {mode}{routes}{mark}",
            generation.fingerprint.hex(),
            generation.made
        ));
    }
    // The list is complete either way; a generation whose manifest cannot be read, or a current generation that a
    // start could not use, ends the command with 1.
    for (fingerprint, e) in &unreadable {
        term.note(&format!("{NAME}: {}: {}", fingerprint.hex(), e.0));
    }
    let mut exit = if unreadable.is_empty() {
        Exit::Done
    } else {
        Exit::Failed
    };
    match current {
        Err(e) => {
            term.note(&format!("{NAME}: {}", e.0));
            exit = Exit::Failed;
        }
        Ok(Some(chosen)) if !generations.iter().any(|g| g.fingerprint == chosen) => {
            term.note(&format!(
                "{NAME}: the current generation is not in the store"
            ));
            exit = Exit::Failed;
        }
        Ok(_) => {}
    }
    exit
}

#[cfg(test)]
mod tests;
