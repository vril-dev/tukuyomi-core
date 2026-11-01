//! What the process does when it gets a signal.

use std::os::unix::process::ExitStatusExt;

use crate::support::{KIND_BYE, KIND_DRAIN, Options, frame, start};

// A reload of the service sends SIGUSR1 and SIGUSR2 to the whole process group, and the process takes no notice: it
// still answers a DRAIN with BYE and ends with 0.
#[test]
fn sigusr1_and_sigusr2_are_ignored() {
    let mut p = start(Options::default());
    p.hello();
    p.signal("USR1");
    p.signal("USR2");
    p.send(&frame(KIND_DRAIN, 0, 0, &[]));
    assert_eq!(p.recv().expect("BYE").kind(), KIND_BYE);
    assert_eq!(p.code(), 0);
}

// SIGTERM ends the process: it dies of the signal, with no exit code.
#[test]
fn sigterm_ends_the_process() {
    let mut p = start(Options::default());
    p.hello();
    p.signal("TERM");
    let status = p.wait();
    assert_eq!(status.signal(), Some(15), "{status:?}");
}
