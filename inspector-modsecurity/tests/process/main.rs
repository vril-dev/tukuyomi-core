//! Real-process tests of the inspector.
//!
//! Every test starts the binary as the kernel starts it: the connection as descriptor 0 (a socket pair), an
//! environment that holds nothing but the variables of the kernel, a new `TMPDIR` of mode 0700, and a small
//! generation of rules that the test writes. The tests look at the start (its order, the exit codes and the
//! diagnostic lines), the HELLO, DRAIN and BYE, the signals and the loss of the connection. What a verdict
//! holds is the business of the tests of the inspection, and nothing here depends on it.

mod session;
mod signals;
mod start;
mod support;
