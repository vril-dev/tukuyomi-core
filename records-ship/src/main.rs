#![forbid(unsafe_code)]
//! The shipper process: `tukuyomi-records-ship <config>` (see `run`). This file starts the logger and the panic
//! hook, runs `run::start`, and flushes the log before the process ends with the exit code that `start` gave, or
//! the failure code if it panicked. The logger writes JSON, as the proxy's does.

use std::io::{self, Write};
use std::panic::{self, AssertUnwindSafe};
use std::process::ExitCode;
use std::time::Duration;

use tukuyomi_proxy::log::{self, Format};
use tukuyomi_records_ship::run::{EXIT_FAILED, start};

/// The longest the end of the process waits for the logger.
const FLUSH_WAIT: Duration = Duration::from_millis(200);

fn main() -> ExitCode {
    let log = match log::start_logger(Format::Json) {
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
