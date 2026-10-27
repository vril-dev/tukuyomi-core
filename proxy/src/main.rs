#![forbid(unsafe_code)]
//! The proxy process: start-up, the wait for the kernel, the listeners and the stop. When the first argument is
//! `rules` the process is a short command on the rules store instead (`rules::command`), when it is `acme` it is
//! the short command that issues and renews the certificates that have `acme` (`acme::command`), and when it is
//! `config` it is the short command `config check <config>`; nothing of the proxy starts in any of them. When it
//! is `admin` the process is the admin process (`admin <config>`, see `admin`) or the short command `admin
//! bootstrap <config> <name>`.
//!
//! This file starts the logger and the panic hook, runs `run::start` (see `run` for the rest), and flushes the log
//! before the process ends with the exit code that `start` gave, or the failure code if it panicked. The logger
//! writes JSON, except in the three short commands and in `admin bootstrap`, which write texts for a person to
//! read.

use std::io::{self, Write};
use std::panic::{self, AssertUnwindSafe};
use std::process::ExitCode;
use std::time::Duration;

use tukuyomi_proxy::log::{self, Format};
use tukuyomi_proxy::run::{EXIT_FAILED, start};

/// The longest the end of the process waits for the logger.
const FLUSH_WAIT: Duration = Duration::from_millis(200);

fn main() -> ExitCode {
    // The short commands write texts for a person; the proxy and the admin process write JSON, also when their
    // argument is wrong.
    let mut args = std::env::args_os().skip(1);
    let format = match (args.next(), args.next()) {
        (Some(first), _) if first == "rules" || first == "acme" || first == "config" => {
            Format::Text
        }
        (Some(first), Some(second)) if first == "admin" && second == "bootstrap" => Format::Text,
        _ => Format::Json,
    };
    let log = match log::start_logger(format) {
        Ok(log) => log,
        Err(text) => {
            let _ = writeln!(io::stderr(), "{text}");
            return ExitCode::from(EXIT_FAILED);
        }
    };
    log::install_panic_hook(log.clone());
    // A panic on this thread is reported through the log and ends the process with the failure code.
    let code = panic::catch_unwind(AssertUnwindSafe(|| start(&log))).unwrap_or(EXIT_FAILED);
    log.flush(FLUSH_WAIT);
    ExitCode::from(code)
}
