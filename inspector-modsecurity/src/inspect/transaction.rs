//! The inspection of one request.
//!
//! The request is fed to the library in its order: the connection, the target, the headers, phase 1; then the
//! processor of the body is put in place, the body is appended, and phase 2 parses it and runs the rules of the
//! body. After each phase the inspection looks at whether the rules stopped the request.
//!
//! A stop is an intervention of the library, and the rule that did it is the one whose message has the stop mark.
//! An intervention that no message names (a rule that stops and logs nothing) is an inspection that cannot be
//! trusted, and so is every request that is about to go on and for which the inspection cannot say it ran to the
//! end (`check_complete`). A generation that only detects takes the first stop as a detection and lets the request
//! go on: the phase 2 answer says what would have stopped it.
//!
//! The inspector makes three blocks of its own, at the end of phase 2: a body that the processor could not parse,
//! more arguments than the limit, and a target that cannot be parsed. They come after the stop of an operator's
//! rule in a generation that blocks, and before a detection in one that only detects.
#![forbid(unsafe_code)]

use crate::codec::{FaultCode, RuleDetail, TxBegin};
use crate::ffi::{EngineTransaction, Error, Message, Processor, TransactionState};
use crate::matched;
use crate::owner::{Fault, Outcome, Stop, Transaction};

use super::arguments::{self, Parts};
use super::processor;
use super::uri;

// The blocks of the inspector: the rule ids they carry in the answer, and the status. They are not rules of the
// library; the ids are kept for them, and a rule of the operator cannot have one.
const BODY_ERROR_ID: i64 = 4_000_001;
const ARGUMENTS_LIMIT_ID: i64 = 4_000_002;
const TARGET_ERROR_ID: i64 = 4_000_003;
const BLOCK_STATUS: i32 = 403;

const DENY: &[u8] = b"deny";
const REDIRECT: &[u8] = b"redirect";

fn fault(code: FaultCode, text: &'static str) -> Fault {
    Fault { code, text }
}

/// The inspection that cannot say it ran to the end.
fn incomplete() -> Fault {
    fault(FaultCode::Incomplete, "request inspection incomplete")
}

/// A failure while the request is fed to the library. A value that the library cannot take as text is a fault of
/// the content of the request; any other failure is an inspection that did not run.
fn feed_fault(error: Error) -> Fault {
    match error {
        Error::Value => fault(
            FaultCode::BadContent,
            "a value of the request holds a NUL byte",
        ),
        _ => incomplete(),
    }
}

/// What a generation that only detects keeps of the first stop.
struct Detection {
    rule_id: i64,
    status: i32,
    action: Vec<u8>,
}

/// The inspection of one request.
pub struct InspectedRequest {
    engine: EngineTransaction,
    /// The generation only detects.
    detect: bool,
    /// The declared length of the body, and whether the body goes on past it.
    declared: u64,
    cut: bool,
    /// The processor that the Content-Type asks for; none when there is no Content-Type, when there is more than
    /// one, and when it is a multipart one that the library would not parse (`processor::choose`).
    want: Processor,
    /// The target can be parsed, and the arguments of its query.
    target_parses: bool,
    query: Parts,
    /// The arguments of a URL-encoded body, and a JSON body (kept to be counted at the end).
    form: Parts,
    json: Vec<u8>,
    /// There are more arguments than the limit. Known at the end of phase 2.
    too_many_arguments: bool,
    /// A part of the body has been appended.
    body_started: bool,
    /// How many of the messages of the library have been looked at for a stop.
    seen: usize,
    detection: Option<Detection>,
}

impl InspectedRequest {
    pub(super) fn new(engine: EngineTransaction, detect: bool) -> InspectedRequest {
        InspectedRequest {
            engine,
            detect,
            declared: 0,
            cut: false,
            want: Processor::None,
            target_parses: true,
            query: Parts::default(),
            form: Parts::default(),
            json: Vec::new(),
            too_many_arguments: false,
            body_started: false,
            seen: 0,
            detection: None,
        }
    }

    /// Feeds the connection, the target and the headers, then runs phase 1. The library takes the protocol of the
    /// request line without its `HTTP/`.
    fn feed(&mut self, t: &TxBegin<'_>) -> Result<(), Fault> {
        let version = t.proto.strip_prefix(b"HTTP/").unwrap_or(t.proto);
        let engine = &mut self.engine;
        engine
            .connection(t.client_addr, t.client_port, t.server_addr, t.server_port)
            .map_err(feed_fault)?;
        engine.uri(t.uri, t.method, version).map_err(feed_fault)?;
        for (name, value) in &t.headers {
            engine.header(name, value).map_err(feed_fault)?;
        }
        engine.request_headers().map_err(feed_fault)
    }

    fn state(&self) -> Result<TransactionState, Fault> {
        self.engine.state().map_err(|_| incomplete())
    }

    /// What the rules that matched say, with the deciding rule left out. The rules and the score are read now;
    /// when they cannot be read, the answer says nothing of them and the request goes on.
    fn detail(&self, deciding: i64) -> RuleDetail {
        match self.engine.messages() {
            Ok(messages) => self.detail_of(&messages, deciding),
            Err(_) => RuleDetail::NONE,
        }
    }

    fn detail_of(&self, messages: &[Message], deciding: i64) -> RuleDetail {
        let score = self.engine.score().ok().flatten();
        matched::detail(messages, deciding, score.as_deref())
    }

    /// What the rules left to stop the request since the last look, as the stop it stands for. An intervention is
    /// taken once, so what comes later is new. The rule is the last message since the last look that has the stop
    /// mark; none is a stop that cannot be told from any rule, which is not trusted.
    fn stop(&mut self) -> Result<Option<Stop>, Fault> {
        let messages = self.engine.messages().map_err(|_| incomplete())?;
        let intervention = self.engine.intervention().map_err(|_| incomplete())?;
        let rule = messages
            .get(self.seen..)
            .unwrap_or_default()
            .iter()
            .rev()
            .find(|message| message.disruptive)
            .map(|message| message.id);
        self.seen = messages.len();
        let Some(intervention) = intervention else {
            return Ok(None);
        };
        let Some(rule_id) = rule.filter(|&id| id >= 1) else {
            return Err(incomplete());
        };
        let action = if intervention.redirect {
            REDIRECT
        } else {
            DENY
        };
        Ok(Some(Stop {
            rule_id,
            status: intervention.status,
            action: action.to_vec(),
            data: Vec::new(),
            rules: self.detail_of(&messages, rule_id),
        }))
    }

    /// What to do with a stop: a generation that blocks answers with it, one that only detects keeps the first of
    /// them and goes on.
    fn take(&mut self, stop: Stop) -> Option<Outcome> {
        if !self.detect {
            return Some(Outcome::Block(stop));
        }
        self.detection.get_or_insert(Detection {
            rule_id: stop.rule_id,
            status: stop.status,
            action: stop.action,
        });
        None
    }

    /// The first block of the inspector that applies at the end of phase 2.
    fn own_block(&self, state: &TransactionState) -> Option<Stop> {
        // A body that was cut ends where the client had not ended it, so its parser can fail on a body that was
        // fine as far as it went: that failure is no reason to block it.
        let rule_id = if !self.cut && (state.request_error || state.processor_error) {
            BODY_ERROR_ID
        } else if self.too_many_arguments {
            ARGUMENTS_LIMIT_ID
        } else if !self.target_parses {
            TARGET_ERROR_ID
        } else {
            return None;
        };
        Some(Stop {
            rule_id,
            status: BLOCK_STATUS,
            action: DENY.to_vec(),
            data: Vec::new(),
            rules: self.detail(0),
        })
    }

    /// The checks that say the inspection ran to the end, which the answer that lets a request go on needs. They
    /// are not assumed from the rules: the rules of the operator can switch the engine or the body access off for
    /// one request, replace the processor, or leave a regular expression that failed or gave up (the library then
    /// takes the rule as not matched). After phase 1 the engine and the body access are all that can be looked
    /// at; the rest needs the body to have been parsed.
    ///
    /// For a request with a body the processor must be the one that the Content-Type asks for, and there must be
    /// one: a body that was not parsed as its Content-Type says, or not parsed at all, was not inspected. A request
    /// with more than one Content-Type has none, and so has one whose multipart boundary is empty, which the
    /// library skips without a flag (`processor::choose`).
    ///
    /// The body flags, the arguments and the target are also the blocks of the inspector, which `end` makes before
    /// it gets here. They are checked again so that no answer that lets a request go on depends on that order.
    fn check_complete(&self, state: &TransactionState, phase2: bool) -> Result<(), Fault> {
        if !state.engine_on || !state.body_access {
            return Err(incomplete());
        }
        if !phase2 {
            return Ok(());
        }
        let body_failed = !self.cut && (state.request_error || state.processor_error);
        if body_failed
            || state.pcre_limit
            || state.pcre_error
            || self.too_many_arguments
            || !self.target_parses
        {
            return Err(incomplete());
        }
        if self.declared > 0 && (self.want == Processor::None || state.processor != self.want) {
            return Err(incomplete());
        }
        Ok(())
    }

    /// The answer that lets the request go on, after the checks: the rules that matched so far, and in phase 2 the
    /// detection that a generation which only detects has kept, if it has one.
    fn finish(&self, phase2: bool, state: &TransactionState) -> Result<Outcome, Fault> {
        self.check_complete(state, phase2)?;
        match &self.detection {
            Some(detection) if phase2 => Ok(Outcome::Detected(Stop {
                rule_id: detection.rule_id,
                status: detection.status,
                action: detection.action.clone(),
                data: Vec::new(),
                rules: self.detail(detection.rule_id),
            })),
            _ => Ok(Outcome::Continue(self.detail(0))),
        }
    }
}

impl Transaction for InspectedRequest {
    fn begin(&mut self, t: &TxBegin<'_>) -> Result<Outcome, Fault> {
        self.declared = t.declared;
        self.cut = t.cut;
        self.want = processor::choose(&t.headers);
        self.target_parses = uri::parses(t.uri);
        self.query.feed(uri::query(t.uri));
        self.feed(t)?;
        if let Some(stop) = self.stop()?
            && let Some(blocked) = self.take(stop)
        {
            return Ok(blocked);
        }
        // The processor is put in place after the rules of phase 1, so that no rule of the operator decides how
        // the body is parsed. A request with no body has none.
        let chosen = if self.declared > 0 {
            self.want
        } else {
            Processor::None
        };
        self.engine
            .set_processor(chosen)
            .map_err(|_| incomplete())?;
        let state = self.state()?;
        self.finish(false, &state)
    }

    /// A part of the body, appended to the library's. The library's own limit on the body is never reached: the
    /// declared length is at most 1 MiB, the table refuses more body than was declared, and the rules are not
    /// allowed to set a limit, so the body that arrives here always fits.
    ///
    /// The errors are for the calls into the library: that the library does not read the body (18), that it
    /// failed to take it (19), and that it took less than it was given (20).
    fn body(&mut self, bytes: &[u8]) -> Result<Option<Stop>, Fault> {
        if !self.body_started && !self.state()?.body_access {
            return Err(fault(
                FaultCode::ReqNotInspect,
                "request body not accessible",
            ));
        }
        self.body_started = true;
        self.engine
            .append_body(bytes)
            .map_err(|error| match error {
                Error::Short => fault(FaultCode::ReqShort, "request body short write"),
                _ => fault(FaultCode::ReqWrite, "request body write failed"),
            })?;
        match self.want {
            Processor::UrlEncoded => self.form.feed(bytes),
            Processor::Json => self.json.extend_from_slice(bytes),
            _ => {}
        }
        Ok(None)
    }

    /// The end of the body: phase 2. The errors are for the call into the library that parses the body and runs
    /// the rules (23), and again for a library that does not read the body (18).
    fn end(&mut self) -> Result<Outcome, Fault> {
        if self.declared != 0 && !self.state()?.body_access {
            return Err(fault(
                FaultCode::ReqNotInspect,
                "request body not accessible",
            ));
        }
        self.engine
            .request_body()
            .map_err(|_| fault(FaultCode::ReqProcess, "request body processing failed"))?;
        if let Some(stop) = self.stop()?
            && let Some(blocked) = self.take(stop)
        {
            return Ok(blocked);
        }
        self.too_many_arguments =
            self.query.over() || self.form.over() || arguments::json_over(&self.json);
        let state = self.state()?;
        if let Some(block) = self.own_block(&state) {
            return Ok(Outcome::Block(block));
        }
        self.finish(true, &state)
    }

    /// Runs the logging phase, which ends a transaction of the library, and frees it. `true` when the phase
    /// failed.
    fn close(mut self) -> bool {
        self.engine.logging().is_err()
    }
}
