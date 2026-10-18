//! The life of the inspector process: `shutdown`, the start with its restart window, the wait for the
//! exit, and what is left when the supervisor cannot go on.
#![forbid(unsafe_code)]

use std::mem;
use std::thread;
use std::time::Instant;

use crate::process::child;
use crate::process::start::{self, LaunchError, Step, Stopped};
use crate::requests::state::Halt;

use super::{
    End, Failure, Leftover, Next, POLL, Run, Shutdown, Slot, StopTag, Supervisor, apply_stop,
    bounded, next, restart_slot,
};

impl Supervisor {
    /// Ends the intake for good. Callable again: a reap or clean-up left unknown stays owned and is retried.
    ///
    /// Every request accepted and not decided is decided in this call, whatever the state, and comes out in
    /// `results` (or came out of an earlier `poll`) once. Nothing is started. Every wait a step creates is cut at
    /// `deadline`; the return is no later than `max(call time, deadline)` plus `kill_grace`, plus what the
    /// following take, which the bound leaves out: the operating system's scheduling delay, the granularity of
    /// socket timeouts, the `kill`, `waitpid` and `lstat` system calls, and the removal of the directory after the
    /// exit is confirmed (how long it takes depends on what the directory holds).
    pub fn shutdown(&mut self, deadline: Instant) -> Shutdown {
        // Only a supervisor that was already failed when this call began retries what the failure left. One that
        // fails inside this call keeps its leftover: a second kill here would double the wait.
        let was_failed = matches!(self.run, Run::Failed { .. });
        self.shutdown_by = Some(deadline);
        let now = Instant::now();
        // Deadlines that have passed are decided first, with their own reasons; then the intake ends.
        let _ = self.engine.tick(now);
        self.engine.halt(now, Halt::Drain);
        let mut bye = false;
        if was_failed {
            if let Run::Failed { why, left } = mem::replace(&mut self.run, Run::Down) {
                let left = match left {
                    Some(Leftover::Running(s)) => {
                        let mut s = s.again(now);
                        loop {
                            let t = Instant::now();
                            match s.step(t) {
                                Stopped::Waiting(w) => {
                                    let wake = bounded(t, self.cfg.tick, None).min(w.next_at());
                                    thread::sleep(wake.saturating_duration_since(t));
                                    s = w;
                                }
                                Stopped::Done { inc, detail, .. } => {
                                    self.engine.exit_confirmed(t, inc);
                                    if detail.is_some() {
                                        self.detail = detail;
                                    }
                                    break None;
                                }
                                Stopped::DirLeft {
                                    inc, dir, detail, ..
                                } => {
                                    self.engine.exit_confirmed(t, inc);
                                    if detail.is_some() {
                                        self.detail = detail;
                                    }
                                    break Some(Leftover::Dir(dir));
                                }
                                Stopped::Unreaped { left: s2, .. } => {
                                    break Some(Leftover::Running(s2));
                                }
                            }
                        }
                    }
                    Some(Leftover::Dir(dir)) => match dir.remove() {
                        Ok(()) => None,
                        Err((dir, _)) => Some(Leftover::Dir(dir)),
                    },
                    other @ (Some(Leftover::Unidentified) | None) => other,
                };
                self.run = Run::Failed { why, left };
            }
        } else {
            match &mut self.run {
                Run::Down => self.run = Run::Stopped,
                Run::Hello { .. } => self.end(now, End::Restart("shutdown"), now),
                Run::Stopping { stop, .. } => stop.kill_by(deadline),
                Run::Ready { .. } | Run::Draining { .. } | Run::Stopped | Run::Failed { .. } => {}
            }
            while !matches!(self.run, Run::Stopped | Run::Failed { .. }) {
                let until = match &self.run {
                    Run::Stopping { stop, .. } => stop.next_at(),
                    _ => deadline,
                };
                self.step(until);
                bye |= matches!(self.run, Run::Stopping { end: End::Bye, .. });
            }
        }
        Shutdown {
            results: self.results(),
            phase: self.phase(),
            bye,
            exit_confirmed: !matches!(
                self.run,
                Run::Failed {
                    left: Some(Leftover::Running(_)),
                    ..
                }
            ),
            dir_removed: !matches!(self.run, Run::Failed { left: Some(_), .. }),
            held_left: self.engine.held_slots(),
            waiting_left: self.engine.waiting(),
        }
    }

    /// Down: while the restart window is full, nothing is started; the engine's clock still runs, so the waiting
    /// requests keep their deadlines. When the time has come the window decides again and, with room, the start is
    /// made.
    pub(super) fn down(&mut self, now: Instant, until: Instant) {
        if let Some(due) = self.not_before {
            let _ = self.engine.tick(now);
            if now < due {
                return self.nap(now, until, Some(due));
            }
            self.not_before = self.restart_wait(now);
            // Still full: wait for the time it names.
            if self.not_before.is_some() {
                return;
            }
        }
        self.launch(now);
    }

    /// A restart is wanted at `now`: `None` when the window has room (the time is recorded and counted), else the
    /// time before which it must not start.
    fn restart_wait(&mut self, now: Instant) -> Option<Instant> {
        match restart_slot(
            &mut self.restart_times,
            now,
            self.cfg.restarts,
            self.cfg.restart_window,
        ) {
            Slot::Now => {
                self.restarts = self.restarts.saturating_add(1);
                None
            }
            Slot::Wait(t) => Some(t),
        }
    }

    /// One try to start. Nothing is started after the intake ended or the numbers ran out. A try that fails has
    /// no process, so the incarnation is used up and never used again.
    fn launch(&mut self, now: Instant) {
        match self.engine.halted() {
            None => {}
            Some(Halt::Drain) => {
                self.run = Run::Stopped;
                return;
            }
            Some(_) => return self.fail(now, Failure::Exhausted, None),
        }
        let inc = self.engine.incarnation();
        let launched = match self.run_id.map_or_else(child::fresh_run, Ok) {
            Ok(run) => {
                self.run_id = Some(run);
                start::launch(&self.cfg, run, inc)
            }
            Err(_) => Err(LaunchError::Clean {
                step: Step::Random,
                why: "run id not available",
            }),
        };
        let now = Instant::now().max(now);
        let error = match launched {
            Ok(start) => {
                let until = bounded(start.started, self.cfg.hello_wait, None);
                self.run = Run::Hello { start, until };
                return;
            }
            Err(e) => e,
        };
        self.engine.exit_confirmed(now, inc);
        match error {
            LaunchError::Clean {
                step: Step::TmpDir,
                why,
            } => self.fail(now, Failure::TmpDir(why), None),
            LaunchError::Clean { why, .. } => {
                let n = next(
                    End::Restart(why),
                    None,
                    self.engine.halted(),
                    self.restarts,
                    self.cfg.restarts,
                );
                self.proceed(now, n);
            }
            LaunchError::DirLeft { dir, .. } => {
                self.fail(now, Failure::CleanupUnknown, Some(Leftover::Dir(dir)));
            }
            LaunchError::Unidentified { .. } => {
                self.fail(now, Failure::CleanupUnknown, Some(Leftover::Unidentified));
            }
        }
    }

    /// Stopping: one try to see the exit, with the engine's clock first (the waiting requests keep their
    /// deadlines meanwhile).
    pub(super) fn reap(&mut self, now: Instant, until: Instant) {
        let (stop, end) = match mem::replace(&mut self.run, Run::Down) {
            Run::Stopping { stop, end } => (stop, end),
            other => {
                self.run = other;
                return;
            }
        };
        let _ = self.engine.tick(now);
        let (inc, tag, exit, left, detail) = match stop.step(now) {
            Stopped::Waiting(stop) => {
                let wake = stop.next_at();
                self.run = Run::Stopping { stop, end };
                return self.nap(now, until, Some(wake));
            }
            Stopped::Done { inc, exit, detail } => (inc, StopTag::Done, Some(exit), None, detail),
            Stopped::DirLeft {
                inc,
                exit,
                detail,
                dir,
                ..
            } => (
                inc,
                StopTag::DirLeft,
                Some(exit),
                Some(Leftover::Dir(dir)),
                detail,
            ),
            Stopped::Unreaped { left: rest, .. } => (
                rest.inc(),
                StopTag::Unreaped,
                None,
                Some(Leftover::Running(rest)),
                None,
            ),
        };
        if detail.is_some() {
            self.detail = detail;
        }
        match apply_stop(&mut self.engine, now, inc, tag) {
            Some(why) => self.fail(now, why, left),
            None => {
                let n = next(
                    end,
                    exit,
                    self.engine.halted(),
                    self.restarts,
                    self.cfg.restarts,
                );
                self.proceed(now, n);
            }
        }
    }

    /// The step after a stop whose exit was seen (or a try to start that failed without a process).
    fn proceed(&mut self, now: Instant, n: Next) {
        match n {
            Next::Restart => {
                // `next` chose this only with `restarts` above 0. A full window keeps `Down` waiting.
                self.not_before = self.restart_wait(now);
                self.run = Run::Down;
            }
            Next::Stopped => self.run = Run::Stopped,
            Next::Fail(why) => self.fail(now, why, None),
        }
    }

    /// The end of the road: what is still owned stays in `left`, the waiting requests are decided, and nothing is
    /// started again.
    pub(super) fn fail(&mut self, now: Instant, why: Failure, left: Option<Leftover>) {
        self.engine.halt(now, Halt::NoRestart);
        self.run = Run::Failed { why, left };
    }
}

impl Drop for Supervisor {
    /// A separate, bounded best effort (the results the engine still holds are lost): a start that runs is
    /// stopped at once, a stop in progress is killed now, a leftover reap gets one more kill, a leftover directory
    /// one try. It waits for the exit for at most about two `kill_grace` (this loop and the `Drop` of the
    /// inspector that still owns an unreaped child), plus what the operating system takes.
    fn drop(&mut self) {
        let now = Instant::now();
        let mut stop = match mem::replace(&mut self.run, Run::Down) {
            Run::Hello { start, .. } | Run::Ready { start } | Run::Draining { start, .. } => {
                start.stop(now)
            }
            Run::Stopping { mut stop, .. } => {
                stop.kill_by(now);
                stop
            }
            Run::Failed {
                left: Some(Leftover::Running(s)),
                ..
            } => s.again(now),
            Run::Failed {
                left: Some(Leftover::Dir(dir)),
                ..
            } => {
                let _ = dir.remove();
                return;
            }
            Run::Down | Run::Stopped | Run::Failed { .. } => return,
        };
        loop {
            let t = Instant::now();
            match stop.step(t) {
                Stopped::Waiting(s) => {
                    thread::sleep(POLL.min(s.next_at().saturating_duration_since(t)));
                    stop = s;
                }
                // Done, or the directory kept, or not reaped (the `Inspector` kills and waits once more).
                Stopped::Done { .. } | Stopped::DirLeft { .. } | Stopped::Unreaped { .. } => return,
            }
        }
    }
}
