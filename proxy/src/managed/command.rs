//! The commands on the managed store: `managed import`, `managed activate`, `managed remove` and `managed list`.
//!
//! ```text
//! tukuyomi-proxy managed import <config> <document>
//! tukuyomi-proxy managed activate <config> <version>
//! tukuyomi-proxy managed remove <config> <version>
//! tukuyomi-proxy managed list <config>
//! ```
//!
//! A command is a short process of its own, apart from a running proxy, which does not notice what it does: a proxy
//! takes the chosen version when it starts or reads its configuration again at SIGHUP. The commands ask no proxy; the
//! admin process puts a version in force in a running proxy by its control socket (see `apply`), and holds the lock of
//! the store while it does, so that `import`, `activate` and `remove` are refused meanwhile (the store is in use). The
//! configuration is the main file of the proxy, as an absolute clean path, and it has `managed`; the document is a
//! path as the operator writes it, from the working directory, and the version is its 64 lowercase hexadecimal digits.
//!
//! `import` takes a document of at most 1 MiB (see `version`) and checks it with the main file as a version is
//! checked. It reads each file that the document names once, as the proxy reads a certificate file (a regular file of
//! at most 1 MiB; a link is followed), and checks it as the proxy would: the chain and the key of each site go together
//! and cover its hosts, and the file of the authorities of each group holds certificates that can be trust anchors. A
//! site with `acme` names no file, and its certificate is in the version as the document writes it. Then it makes the
//! version that names the files by their SHA-256. A document that is refused so far has written nothing. Then, with
//! the lock of the store, it puts the files in the store (a file that is there already is not written again), reads
//! the version with the main file it read first as the proxy would, the country database included (see `load`), and
//! puts the version in the store (see `import`, whose way the admin process takes as well). It does not choose it. A
//! file that was put in the store stays there if that last reading refuses. `activate` takes the lock
//! of the store and chooses the version only if the steps of the start before the rules store pass with it (see
//! `run`): the main file with the version, the lookup of the names of the upstream servers and the files of their
//! authorities, and the certificates of the listeners. `remove` removes a version that `current` does not name and
//! that nothing holds (a proxy that serves with it, or a command that reads it), and with it the files and the
//! certificates of the sites with `acme` that no version names any more (see `remove`); it looks at no rollback.
//! `list` shows the versions.
//!
//! The results go to the standard output, one line each, and the first word of a line is the name of a version:
//! `import` says `created`, `existing` or `recreated` after it (`recreated`: the store had a broken copy, which was
//! replaced), `activate` says `current`, `remove` says `removed`, and `list` gives the time the version was made
//! (seconds since the epoch), and `current` for the chosen one. Everything else goes to the standard error, a line
//! each, and starts with the name of the command; a path that came from the document is written with every byte
//! outside 0x20 to 0x7e as `\xNN`. A removal whose cleaning did not go whole says so there, and ends with 0 all the
//! same: the version is gone.
//!
//! No command runs as root: when any user id of the process is 0, the command writes a `host check refused` line and
//! ends before it reads the configuration.
//!
//! The exit code is 0 for success, 1 for any other end (a refused store, document or file, a store that is in use, a
//! name that cannot be looked up or a file that cannot be used when the version is chosen, a current version that is
//! not in the store, a version that `activate` refuses, as a document that `import` refuses, a version that `remove`
//! refuses, a process that runs as root) and 2 for a wrong argument or a refused configuration, a main file without
//! `managed` included.

use std::ffi::OsString;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use super::import::{self, Placing, Reading};
use super::load::{Choice, LoadError};
use super::remove;
use super::store::{MAX_BYTES, Placed, Store};
use crate::config::{self, Built};
use crate::inbound::transport::tls::{Fault, read_file};
use crate::log::{Log, escaped};
use crate::rules::bundle::{Fingerprint, hex};
use crate::run::{EXIT_FAILED, host, read_parts};

const USAGE: &str = "usage: tukuyomi-proxy managed import <config> <document>\n       tukuyomi-proxy managed activate <config> <version>\n       tukuyomi-proxy managed remove <config> <version>\n       tukuyomi-proxy managed list <config>";

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
    Import { config: PathBuf, document: PathBuf },
    Activate { config: PathBuf, version: [u8; 32] },
    Remove { config: PathBuf, version: [u8; 32] },
    List { config: PathBuf },
}

/// Runs the command that `args` (what follows `managed`) name. The results go to `out`, the other lines to `log`.
pub fn run(args: &[OsString], out: &mut dyn Write, log: &Log) -> Exit {
    match parse(args) {
        Err(why) => {
            log.line(&format!("managed: {why}"));
            log.line(USAGE);
            Exit::Usage
        }
        Ok(Command::Import { config, document }) => import(&config, &document, out, log),
        Ok(Command::Activate { config, version }) => activate(&config, version, out, log),
        Ok(Command::Remove { config, version }) => remove(&config, version, out, log),
        Ok(Command::List { config }) => list(&config, out, log),
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
        match rest {
            [document] => Ok(Command::Import {
                config,
                document: PathBuf::from(document),
            }),
            _ => Err("import takes one document"),
        }
    } else if name == "activate" {
        match rest {
            [version] => Ok(Command::Activate {
                config,
                version: version_name(version)?,
            }),
            _ => Err("activate takes one version"),
        }
    } else if name == "remove" {
        match rest {
            [version] => Ok(Command::Remove {
                config,
                version: version_name(version)?,
            }),
            _ => Err("remove takes one version"),
        }
    } else if rest.is_empty() {
        Ok(Command::List { config })
    } else {
        Err("list takes no argument after the configuration file")
    }
}

fn version_name(arg: &OsString) -> Result<[u8; 32], &'static str> {
    Fingerprint::from_hex(arg.as_bytes())
        .map(|name| name.bytes())
        .ok_or("the version is not 64 lowercase hexadecimal digits")
}

/// A result line. A write that fails does not change how the command ends.
fn result(out: &mut dyn Write, line: &str) {
    let _ = writeln!(out, "{line}");
}

/// Refuses a process that runs as root, with a line that names `command`.
fn not_root(command: &str, log: &Log) -> Result<(), Exit> {
    host::not_root().map_err(|text| {
        log.line(&format!("{command}: host check refused: {text}"));
        Exit::Failed
    })
}

/// The main file at `config`, checked, which has `managed`, and the store it names.
fn open(command: &str, config: &Path, log: &Log) -> Result<(Built, Store), Exit> {
    let built = config::read(config)
        .and_then(|bytes| config::main_file(&bytes))
        .map_err(|e| {
            log.line(&format!("{command}: configuration refused: {}", e.0));
            Exit::Usage
        })?;
    let Some(managed) = &built.main.managed else {
        log.line(&format!(
            "{command}: configuration refused: there is no managed object"
        ));
        return Err(Exit::Usage);
    };
    match Store::open(&managed.dir) {
        Ok(store) => Ok((built, store)),
        Err(e) => {
            log.line(&format!("{command}: managed store refused: {}", e.0));
            Err(Exit::Failed)
        }
    }
}

fn import(config: &Path, document: &Path, out: &mut dyn Write, log: &Log) -> Exit {
    const NAME: &str = "managed import";
    if let Err(exit) = not_root(NAME, log) {
        return exit;
    }
    let (built, store) = match open(NAME, config, log) {
        Ok(opened) => opened,
        Err(exit) => return exit,
    };
    let text = match read_file(document, MAX_BYTES) {
        Ok(text) => text,
        Err(fault) => {
            let why = match fault {
                Fault::Missing => "the document does not exist",
                Fault::TooLarge => "the document is over 1 MiB",
                _ => "the document cannot be read",
            };
            log.line(&format!(
                "{NAME}: {why}: \"{}\"",
                escaped(document.as_os_str().as_bytes())
            ));
            return Exit::Failed;
        }
    };
    let import = match import::from_document(&built, &text) {
        Ok(import) => import,
        Err(line) => {
            log.line(&format!("{NAME}: {line}"));
            return Exit::Failed;
        }
    };
    match import::place(built, &store, &import, Reading::Whole) {
        Ok((name, placed)) => {
            let how = match placed {
                Placed::Created => "created",
                Placed::Existing => "existing",
                Placed::Recreated => "recreated, the stored copy was broken",
            };
            result(out, &format!("{} {how}", hex(&name)));
            Exit::Done
        }
        Err(Placing::Store(e)) => {
            log.line(&format!("{NAME}: {}", e.0));
            Exit::Failed
        }
        Err(Placing::Load(LoadError::Main(e))) => {
            log.line(&format!("{NAME}: configuration refused: {}", e.0));
            Exit::Usage
        }
        Err(Placing::Load(LoadError::Version(e))) => {
            log.line(&format!("{NAME}: document refused: {}", e.0));
            Exit::Failed
        }
        Err(Placing::Load(LoadError::Store(e))) => {
            log.line(&format!("{NAME}: managed store refused: {}", e.0));
            Exit::Failed
        }
    }
}

fn activate(config: &Path, version: [u8; 32], out: &mut dyn Write, log: &Log) -> Exit {
    const NAME: &str = "managed activate";
    if let Err(exit) = not_root(NAME, log) {
        return exit;
    }
    let (_, store) = match open(NAME, config, log) {
        Ok(opened) => opened,
        Err(exit) => return exit,
    };
    let _lock = match store.lock() {
        Ok(lock) => lock,
        Err(e) => {
            log.line(&format!("{NAME}: {}", e.0));
            return Exit::Failed;
        }
    };
    // The check comes before the store chooses: a version that the proxy would refuse is never the chosen one.
    if let Err(refusal) = read_parts(config, &Choice::Named(version), NAME, log) {
        return if refusal.exit() == EXIT_FAILED {
            Exit::Failed
        } else {
            Exit::Usage
        };
    }
    match store.choose(version) {
        Ok(()) => {
            result(out, &format!("{} current", hex(&version)));
            Exit::Done
        }
        Err(e) => {
            log.line(&format!("{NAME}: {}", e.0));
            Exit::Failed
        }
    }
}

fn remove(config: &Path, version: [u8; 32], out: &mut dyn Write, log: &Log) -> Exit {
    const NAME: &str = "managed remove";
    if let Err(exit) = not_root(NAME, log) {
        return exit;
    }
    let (_, store) = match open(NAME, config, log) {
        Ok(opened) => opened,
        Err(exit) => return exit,
    };
    match remove::remove(&store, version) {
        Ok(removed) => {
            result(out, &format!("{} removed", hex(&version)));
            if !removed.cleaned {
                log.line(&format!(
                    "{NAME}: the files that no version names were not cleaned up"
                ));
            }
            Exit::Done
        }
        Err(e) => {
            log.line(&format!("{NAME}: {}", e.0));
            Exit::Failed
        }
    }
}

fn list(config: &Path, out: &mut dyn Write, log: &Log) -> Exit {
    const NAME: &str = "managed list";
    if let Err(exit) = not_root(NAME, log) {
        return exit;
    }
    let (_, store) = match open(NAME, config, log) {
        Ok(opened) => opened,
        Err(exit) => return exit,
    };
    let versions = match store.versions() {
        Ok(versions) => versions,
        Err(e) => {
            log.line(&format!("{NAME}: {}", e.0));
            return Exit::Failed;
        }
    };
    let current = store.current();
    let chosen = current.as_ref().ok().copied().flatten();
    for listed in &versions {
        let mark = if Some(listed.name) == chosen {
            " current"
        } else {
            ""
        };
        result(out, &format!("{} {}{mark}", hex(&listed.name), listed.made));
    }
    // The list is complete either way; a current version that a start could not use ends the command with 1.
    match current {
        Err(e) => {
            log.line(&format!("{NAME}: {}", e.0));
            Exit::Failed
        }
        Ok(Some(chosen)) if !versions.iter().any(|listed| listed.name == chosen) => {
            log.line(&format!(
                "{NAME}: the current managed version is not in the store"
            ));
            Exit::Failed
        }
        Ok(_) => Exit::Done,
    }
}

#[cfg(test)]
mod tests;
