//! The calls of the host: a request goes in, its result comes out, and the state can be read.
#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::time::Instant;

use crate::config::{Config, ConfigError};
use crate::protocol::codec::{self, Matched};
use crate::requests::state::{self, Engine, Limits, SubmitError};

use super::{
    Phase, Refused, ReqId, Request, Run, Status, Supervisor, Verdict, is_json_suffix_type,
    verdict_of,
};

impl Supervisor {
    /// Checks the configuration and nothing else: no process is started and the file system is not touched.
    pub fn new(cfg: Config) -> Result<Supervisor, ConfigError> {
        cfg.check()?;
        let engine = Engine::new(
            Limits {
                slots: cfg.slots,
                wait_queue: cfg.wait_queue,
                records: cfg.records,
                discard_limit: cfg.discard_limit,
                verdict_wait: cfg.verdict_wait,
                wait_deadline: cfg.wait_deadline,
                closed_wait: cfg.closed_wait,
                stop_after: cfg.stop_after,
            },
            1,
            1,
        );
        // At most `restarts` entries (`check` caps it), so the queue never grows.
        let restart_times =
            VecDeque::with_capacity(usize::try_from(cfg.restarts).unwrap_or_default());
        Ok(Supervisor {
            cfg,
            engine,
            run_id: None,
            run: Run::Down,
            restarts: 0,
            restart_times,
            not_before: None,
            shutdown_by: None,
            detail: None,
        })
    }

    /// Takes one request. What cannot be inspected faithfully is refused here (`Refused::Unsupported`) and never
    /// becomes `Allow`. A decision the engine takes at once (queue full, intake ended, wait deadline that does
    /// not fit) makes a record like any other and comes out of the next `poll` or `shutdown`.
    pub fn submit(&mut self, req: &Request<'_>) -> Result<ReqId, Refused> {
        let Some(declared) = u64::try_from(req.body.len())
            .ok()
            .filter(|&n| n <= codec::MAX_DECLARED)
        else {
            return Err(Refused::Unsupported("body over the protocol limit"));
        };
        // A body that goes on needs bytes to stand on: the inspector refuses a cut body that has none.
        if req.body_cut && req.body.is_empty() {
            return Err(Refused::Invalid("cut body without bytes"));
        }
        // Every field of TX_BEGIN is bounded first; for the headers that is their number, the length of each name
        // and value, and their total. What passes is small, so the header rules below read no more than that.
        let begin = codec::encode_tx_begin(&codec::TxBegin {
            client_addr: req.client_addr,
            client_port: req.client_port,
            server_addr: req.server_addr,
            server_port: req.server_port,
            method: req.method,
            uri: req.uri,
            proto: req.proto,
            declared,
            headers: req.headers,
        })
        .map_err(|e| Refused::Invalid(e.0))?;
        let header = |name: &'static [u8]| {
            req.headers
                .iter()
                .filter(move |h| h.0.eq_ignore_ascii_case(name))
        };
        if header(b"transfer-encoding").next().is_some() {
            return Err(Refused::Unsupported("transfer-encoding"));
        }
        // The body is not decompressed, so a body that is coded cannot be inspected.
        if header(b"content-encoding").next().is_some() {
            return Err(Refused::Unsupported("content-encoding"));
        }
        let mut lengths = header(b"content-length");
        if let Some(first) = lengths.next() {
            let value = first.1;
            // The length of a body that goes on is more than the bytes given.
            let same = !value.is_empty()
                && value.iter().all(u8::is_ascii_digit)
                && std::str::from_utf8(value)
                    .ok()
                    .and_then(|s| s.parse::<u64>().ok())
                    .is_some_and(|n| {
                        if req.body_cut {
                            n > declared
                        } else {
                            n == declared
                        }
                    });
            if lengths.next().is_some() || !same {
                return Err(Refused::Unsupported("content-length"));
            }
        }
        if !req.body.is_empty() {
            // Only these types get a body processor: Coraza selects it for the first two, and the inspector sets the
            // JSON processor for `application/json` and for `application/<name>+json`. Any other body is not parsed.
            let mut types = header(b"content-type");
            let known = match (types.next(), types.next()) {
                (Some(t), None) => {
                    let essence =
                        t.1.split(|&b| b == b';')
                            .next()
                            .unwrap_or_default()
                            .trim_ascii();
                    essence.eq_ignore_ascii_case(b"application/x-www-form-urlencoded")
                        || essence.eq_ignore_ascii_case(b"multipart/form-data")
                        || essence.eq_ignore_ascii_case(b"application/json")
                        || is_json_suffix_type(essence)
                }
                _ => false,
            };
            if !known {
                return Err(Refused::Unsupported("content-type"));
            }
        }
        let body: Vec<Vec<u8>> = req
            .body
            .chunks(codec::MAX_BODY)
            .map(<[u8]>::to_vec)
            .collect();
        match self.engine.submit(
            Instant::now(),
            state::Request {
                begin,
                body,
                cut: req.body_cut,
            },
        ) {
            Ok(id) => Ok(id),
            Err(SubmitError::Full) => Err(Refused::Full),
            Err(SubmitError::IdsExhausted) => Err(Refused::IdsExhausted),
        }
    }

    /// The client went away. An id that is unknown, or already delivered, is ignored.
    pub fn cancel(&mut self, id: ReqId) {
        self.engine.cancel(Instant::now(), id);
    }

    /// Steps until a result is ready or `until`, and returns the results (each once). `until` is looked at between
    /// steps: one step writes the frames queued when it begins and reads one frame, so the return can be later than
    /// `until` by what those writes and that read take (every write is cut at `frame_io`). A step whose `until` has
    /// passed writes but does not read. At least one step is made.
    /// The return can also be later by a start made in that call (creating the start directory, spawning the
    /// inspector, reading `/dev/urandom`), by the removal of a start directory after an exit, and by the operating
    /// system's scheduling delay. A read in progress is not cut.
    pub fn poll(&mut self, until: Instant) -> Vec<(ReqId, Verdict, Matched)> {
        loop {
            self.step(until);
            let results = self.results();
            if !results.is_empty() || Instant::now() >= until {
                return results;
            }
        }
    }

    pub fn status(&self) -> Status {
        Status {
            phase: self.phase(),
            inc: self.engine.incarnation(),
            restarts: self.restarts,
            waiting: self.engine.waiting(),
            held: self.engine.held_slots(),
            records: self.engine.records(),
        }
    }

    /// The bytes an inspector left in `start-failure` of its start directory when it ended in a refusal (exit code 10,
    /// 11 or 14, which is `Failure::Exit`): at most 512, read once after the exit was seen and before the directory
    /// was removed. `None` when there is none, also when the file was not what it should be. The bytes are the
    /// inspector's own and no one else checked them: the caller must not write them anywhere unescaped.
    pub fn start_detail(&self) -> Option<Vec<u8>> {
        self.detail.clone()
    }

    pub(super) fn phase(&self) -> Phase {
        match &self.run {
            Run::Down | Run::Hello { .. } => Phase::Starting,
            Run::Ready { .. } => Phase::Ready,
            Run::Draining { .. } | Run::Stopping { .. } => Phase::Stopping,
            Run::Stopped => Phase::Stopped,
            Run::Failed { why, .. } => Phase::Failed(*why),
        }
    }

    /// Every decision not delivered yet, each once, in the order they were made.
    pub(super) fn results(&mut self) -> Vec<(ReqId, Verdict, Matched)> {
        let mut results = Vec::new();
        while let Some((id, decision, matched)) = self.engine.next_done() {
            results.push((id, verdict_of(decision), matched));
        }
        results
    }
}
