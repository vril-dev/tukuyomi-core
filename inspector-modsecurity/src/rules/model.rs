//! What the reader read of the rule files, written in the form in which the library's rules are described
//! (`ffi::Rules::describe`, written by `bridge.cc`).
//!
//! The reader and the scanner of the library are two readers of one text, and a text that they cut in two
//! ways would pass the checks of the reader and mean something else to the library. So the library is
//! asked what it built, and a set of rules is taken only when that is what the reader read: the same rules
//! in the same phases and order, the same chains, ids, operators and action names (and the values of the
//! ones that decide where a request goes: `skipAfter`, `skip`, `ctl`, the action that stops or lets pass),
//! the same markers and default actions, and the settings (`settings`). A reading that differs shows as a
//! difference here: a rule that the scanner swallowed is a rule fewer, a marker with a blank in front of its
//! name is another name, an action that the scanner found in the text of a value is one more.
//!
//! The model keeps what the library keeps, made the way the library makes it (`Driver` in
//! `src/parser/driver.cc`, `RuleWithActions` in `src/rule_with_actions.cc`): an action that only sets a field
//! of the rule (`id`, `phase`, `chain`, ...) is not an action of it, the last of several disruptive actions
//! stays, a marker is put in every phase, a rule after a rule with `chain` is its child and takes its phase,
//! and a chain does not go over a file. Every rule is compared whole: its variables (with what an exclusion
//! leaves out of them and the number of values that a count makes), its operator (the name, the negation and the
//! argument, with its macros), and the texts of `msg`, `logdata`, `tag`, `setvar`, `redirect`, `setsid`, `setuid`,
//! `setrsc`, `expirevar` and `initcol` with their macros (the pieces that `describe` writes).

use super::describe::{self, Held, Out};
use super::reader::{Action, Body, FORM, Piece, Reason, SetVar, Statement};
use super::settings::Settings;

/// The number of phases of the library (`modsecurity::Phases::NUMBER_OF_PHASES`).
const PHASES: usize = 7;
/// The phase of a rule that names none (`RequestHeadersPhase`).
const DEFAULT_PHASE: usize = 2;
/// The phase of the library for each number that `phase:` takes (0 to 5).
const PHASE_OF_NUMBER: [usize; 6] = [0, 2, 3, 4, 5, 6];
/// The most rules that a chain holds, the rule that starts it included. The library drops a chain by a recursion
/// as long as the chain, which overflows the stack of a thread with a small one when the chain is long.
const MAX_CHAIN: usize = 64;
const CHAIN_TOO_LONG: Reason = "a chain of rules is longer than 64 rules";

/// An action as the library holds it: its name in lower case, and its payload where that is compared.
struct Item {
    name: String,
    payload: Vec<u8>,
    /// The text of the actions that keep one: `msg`, `logdata`, `tag` and `setvar` (only a default action has
    /// them here: the library keeps the ones of a rule apart from its actions to run), and `redirect`, `setsid`,
    /// `setuid`, `setrsc`, `expirevar` and `initcol`.
    detail: Vec<u8>,
}

impl Item {
    fn new(action: &Action) -> Item {
        let value = &action.value;
        // The names that the library makes up for itself, and the transformations, whose names it keeps whole.
        let name = match action.name.as_str() {
            "redirect" => "redirert".to_owned(),
            "setrsc" => "setsrc".to_owned(),
            "t" => format!("t:{}", String::from_utf8_lossy(value).to_ascii_lowercase()),
            other => other.to_owned(),
        };
        let payload = match action.name.as_str() {
            "skip" | "skipafter" => value.clone(),
            "ctl" => ctl_payload(value),
            _ => Vec::new(),
        };
        let detail = match action.name.as_str() {
            "msg" | "logdata" | "tag" | "redirect" | "setsid" | "setuid" | "setrsc"
            | "expirevar" | "initcol" => describe::pieces(&action.text),
            "setvar" => action
                .set_var
                .as_ref()
                .map(describe::set_var)
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        Item {
            name,
            payload,
            detail,
        }
    }

    fn encode(&self, out: &mut Out) {
        out.str(self.name.as_bytes());
        out.str(&self.payload);
        out.str(&self.detail);
    }
}

/// The payload that the library holds for a `ctl` action. The scanner gives most of them whole, as they
/// are written, and the parser makes three from a fixed text. (The ones that change the rule engine or the
/// body access are refused by the checks of the kinds before the comparison, and are not made here.)
fn ctl_payload(value: &[u8]) -> Vec<u8> {
    let (name, rest) = match value.iter().position(|b| *b == b'=') {
        Some(at) => (&value[..at], &value[at + 1..]),
        None => (value, &[][..]),
    };
    let lower = |text: &[u8]| text.to_ascii_lowercase();
    match lower(name).as_slice() {
        b"auditengine" => [b"auditengine=".as_slice(), &lower(rest)].concat(),
        b"parsexmlintoargs" => [b"parseXmlIntoArgs=".as_slice(), &lower(rest)].concat(),

        // The value is a token of its own that the library drops.
        b"forcerequestbodyvariable" => [name, b"="].concat(),
        _ => value.to_vec(),
    }
}

/// Digits as a number, with no overflow.
pub(super) fn number(digits: &[u8]) -> i64 {
    digits.iter().fold(0i64, |n, d| {
        n.saturating_mul(10)
            .saturating_add(i64::from(d.wrapping_sub(b'0')))
    })
}

/// The phase of the library for the value of a `phase` action.
fn phase_of(value: &[u8]) -> Result<usize, Reason> {
    match String::from_utf8_lossy(value).to_ascii_lowercase().as_str() {
        "request" => Ok(3),
        "response" => Ok(5),
        "logging" => Ok(6),
        digits => PHASE_OF_NUMBER
            .get(usize::try_from(number(digits.as_bytes())).unwrap_or(usize::MAX))
            .copied()
            .ok_or(FORM),
    }
}

fn severity_of(value: &[u8]) -> i64 {
    const NAMES: [&str; 8] = [
        "emergency",
        "alert",
        "critical",
        "error",
        "warning",
        "notice",
        "info",
        "debug",
    ];
    let lower = String::from_utf8_lossy(value).to_ascii_lowercase();
    match NAMES.iter().position(|name| *name == lower) {
        Some(level) => level as i64,
        None => number(value),
    }
}

/// The name that the library gives an operator, in lower case (a regular expression with no operator is `@rx`).
fn operator_of(name: Option<&'static str>) -> &'static str {
    match name {
        None => "rx",
        Some("pmf") => "pmfromfile",
        Some("ipmatchf") => "ipmatchfromfile",
        Some(name) => name,
    }
}

/// The operator of a rule.
struct Operator {
    name: &'static str,
    negated: bool,
    /// The argument in pieces; `None` for an operator that takes none.
    pieces: Option<Vec<Piece>>,
}

/// A rule, or a rule of a chain.
struct Rule {
    /// The operator; `None` for the rule of a `SecAction`.
    operator: Option<Operator>,
    variables: Vec<Held>,
    id: i64,
    phase: usize,
    chained: bool,
    disruptive: Option<Item>,
    runtime: Vec<Item>,
    capture: bool,
    multi_match: bool,
    block: bool,
    severity: i64,
    message: Option<Vec<Piece>>,
    log_data: Option<Vec<Piece>>,
    set_vars: Vec<SetVar>,
    tags: Vec<Vec<Piece>>,
    transformations: usize,
    rev: Vec<u8>,
    ver: Vec<u8>,
    accuracy: i64,
    maturity: i64,
}

impl Rule {
    /// The rule that the actions make, as `RuleWithActions` makes it.
    fn new(
        operator: Option<Operator>,
        variables: Vec<Held>,
        actions: &[Action],
    ) -> Result<Rule, Reason> {
        let mut rule = Rule {
            operator,
            variables,
            id: 0,
            phase: DEFAULT_PHASE,
            chained: false,
            disruptive: None,
            runtime: Vec::new(),
            capture: false,
            multi_match: false,
            block: false,
            severity: -1,
            message: None,
            log_data: None,
            set_vars: Vec::new(),
            tags: Vec::new(),
            transformations: 0,
            rev: Vec::new(),
            ver: Vec::new(),
            accuracy: 0,
            maturity: 0,
        };
        for action in actions {
            let value = &action.value;
            match action.name.as_str() {
                "id" => rule.id = number(value),
                "phase" => rule.phase = phase_of(value)?,
                "chain" => rule.chained = true,
                "rev" => rule.rev = value.clone(),
                "ver" => rule.ver = value.clone(),
                "accuracy" => rule.accuracy = number(value),
                "maturity" => rule.maturity = number(value),
                "capture" => rule.capture = true,
                "multimatch" => rule.multi_match = true,
                "severity" => rule.severity = severity_of(value),
                // The library keeps the last of the messages and of the log data.
                "msg" => rule.message = Some(action.text.clone()),
                "logdata" => rule.log_data = Some(action.text.clone()),
                "setvar" => rule.set_vars.extend(action.set_var.clone()),
                "tag" => rule.tags.push(action.text.clone()),
                "t" => rule.transformations += 1,
                // The last of the actions that stop a request or let it pass is the one that stays.
                "allow" | "deny" | "drop" | "pass" | "redirect" => {
                    rule.disruptive = Some(Item::new(action));
                }
                "block" => {
                    rule.block = true;
                    rule.runtime.push(Item::new(action));
                }
                _ => rule.runtime.push(Item::new(action)),
            }
        }
        Ok(rule)
    }

    fn encode(&self, out: &mut Out) {
        match &self.operator {
            Some(operator) => {
                out.word("rule");
                out.str(operator.name.as_bytes());
                out.flag(operator.negated);
                describe::optional_pieces(out, operator.pieces.as_deref());
                out.count(self.variables.len());
                for variable in &self.variables {
                    out.str(&variable.encode());
                }
            }
            None => out.word("action"),
        }
        out.num(self.id);
        out.count(self.phase);
        out.flag(self.chained);
        match &self.disruptive {
            Some(item) => {
                out.word("disruptive");
                item.encode(out);
            }
            None => out.word("passive"),
        }
        out.count(self.runtime.len());
        for item in &self.runtime {
            item.encode(out);
        }
        out.flag(self.capture);
        out.flag(self.multi_match);
        out.flag(self.block);
        out.num(self.severity);
        describe::optional_pieces(out, self.message.as_deref());
        describe::optional_pieces(out, self.log_data.as_deref());
        out.count(self.set_vars.len());
        for set_var in &self.set_vars {
            out.str(&describe::set_var(set_var));
        }
        out.count(self.tags.len());
        for tag in &self.tags {
            out.str(&describe::pieces(tag));
        }
        out.count(self.transformations);
        out.str(&self.rev);
        out.str(&self.ver);
        out.num(self.accuracy);
        out.num(self.maturity);
    }
}

enum Entry {
    Marker(Vec<u8>),
    /// A rule and the rules chained after it, in the order of the chain.
    Chain(Vec<Rule>),
}

/// All that the reader read of the rule files, as the library keeps it.
#[derive(Default)]
pub(super) struct Model {
    phases: [Vec<Entry>; PHASES],
    defaults: [Vec<Item>; PHASES],
    settings: Settings,
    /// Where the chain is that holds the last rule that a `SecRule` made: a `SecRule` after a rule with `chain`
    /// is its child, and goes at the end of that chain.
    last: Option<(usize, usize)>,
}

impl Model {
    /// Takes a statement that the checks accepted.
    pub(super) fn statement(&mut self, statement: &Statement<'_>) -> Result<(), Reason> {
        match &statement.body {
            Body::Rule(read) => {
                self.settings.actions(&read.actions);
                let operator = Operator {
                    name: operator_of(read.operator.name),
                    negated: read.operator.negated,
                    pieces: read.operator.pieces.clone(),
                };
                let held = describe::held(&read.variables);
                self.add(Rule::new(Some(operator), held, &read.actions)?, true)?;
            }
            Body::Actions(actions) => {
                self.settings.actions(actions);
                if statement.keyword == "secaction" {
                    self.add(Rule::new(None, Vec::new(), actions)?, false)?;
                } else {
                    self.default_actions(actions)?;
                }
            }
            Body::Marker(name) => {
                for phase in &mut self.phases {
                    phase.push(Entry::Marker(name.as_bytes().to_vec()));
                }
            }
            Body::Argument(_) | Body::Targets { .. } | Body::Plain => {
                self.settings
                    .directive(&statement.keyword, &statement.body)?;
            }
        }
        Ok(())
    }

    /// The end of a rule file: the library reads each file on its own, and does not carry a chain over, and
    /// merges the settings of the file into those it has.
    pub(super) fn end_of_file(&mut self) {
        self.last = None;
        self.settings.end_of_file();
    }

    /// `SecDefaultAction`: the actions go to the phase that its `phase` names, except that one.
    fn default_actions(&mut self, actions: &[Action]) -> Result<(), Reason> {
        let mut phase = DEFAULT_PHASE;
        for action in actions.iter().filter(|action| action.name == "phase") {
            phase = phase_of(&action.value)?;
        }
        for action in actions.iter().filter(|action| action.name != "phase") {
            self.defaults[phase].push(Item::new(action));
        }
        Ok(())
    }

    /// Puts a rule where `Driver::addSecRule` and `addSecAction` put it. A chain is a list that a rule is added
    /// to at the end, so adding costs the same however long the chain is, and dropping it goes link by link.
    /// A rule that would be the one after the last that a chain may hold is refused.
    fn add(&mut self, mut rule: Rule, is_sec_rule: bool) -> Result<(), Reason> {
        if is_sec_rule
            && let Some((phase, index)) = self.last
            && let Entry::Chain(links) = &mut self.phases[phase][index]
            && let Some(parent) = links.last().filter(|parent| parent.chained)
        {
            if links.len() >= MAX_CHAIN {
                return Err(CHAIN_TOO_LONG);
            }
            rule.phase = parent.phase;
            links.push(rule);
            return Ok(());
        }
        let phase = rule.phase;
        self.phases[phase].push(Entry::Chain(vec![rule]));
        if is_sec_rule {
            self.last = Some((phase, self.phases[phase].len() - 1));
        }
        Ok(())
    }

    /// The text that the library describes the same rules with.
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut out = Out::default();
        out.word("rules");
        out.count(PHASES);
        for (phase, entries) in self.phases.iter().enumerate() {
            out.word("phase");
            out.count(phase);
            out.count(entries.len());
            for entry in entries {
                match entry {
                    Entry::Marker(name) => {
                        out.word("marker");
                        out.str(name);
                    }
                    Entry::Chain(links) => {
                        for (at, link) in links.iter().enumerate() {
                            link.encode(&mut out);
                            out.word(if at + 1 < links.len() { "child" } else { "end" });
                        }
                    }
                }
            }
        }
        for (phase, items) in self.defaults.iter().enumerate() {
            out.word("defaults");
            out.count(phase);
            out.count(items.len());
            for item in items {
                item.encode(&mut out);
            }
        }
        self.settings.encode(&mut out);
        out.text()
    }
}
