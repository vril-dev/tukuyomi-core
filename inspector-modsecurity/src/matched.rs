//! What a VERDICT of the request phases says about the rules that matched: their ids, how severe the worst of
//! them is, and the anomaly score of the request.
//!
//! The library keeps a message for each rule that matched and was logged (a rule with `nolog` leaves none), so
//! those are the rules counted. Nothing of a rule that could carry a value of the request goes into a VERDICT:
//! no message text, tag, log data, matched value or variable name. Only numbers.
#![forbid(unsafe_code)]

use crate::codec::{MAX_RULE_IDS, MAX_SEVERITY, RuleDetail};
use crate::ffi::Message;

/// The score of a request that has none.
const SCORE_NONE: i32 = -1;

/// What the rules that matched so far say, in the order they ran. `deciding` is the id of the rule that stopped
/// the request (0 when none did): it is not listed, but its severity counts.
///
/// The ids are the first `MAX_RULE_IDS` of them, and `more` is set when there are others. The severity is the
/// lowest number among the rules (0 is the heaviest); a rule without one, or with a number that the protocol
/// cannot carry, is skipped. A message with an id below 1, which the protocol cannot carry either, leaves the
/// whole detail empty: nothing is said rather than something wrong. `score` is the text of the TX variable
/// that the common rule sets add the score to, or `None` when there is none.
pub fn detail(messages: &[Message], deciding: i64, score: Option<&[u8]>) -> RuleDetail {
    let mut detail = RuleDetail::default();
    for message in messages {
        if message.id < 1 {
            return RuleDetail::default();
        }
        if let Some(severity) = message
            .severity
            .and_then(|severity| u8::try_from(severity).ok())
            .filter(|&severity| severity <= MAX_SEVERITY)
        {
            detail.severity = detail.severity.min(severity);
        }
        if message.id == deciding {
            continue;
        }
        if detail.ids.len() < MAX_RULE_IDS {
            detail.ids.push(message.id);
        } else {
            detail.more = true;
        }
    }
    detail.score = score.map_or(SCORE_NONE, parse_score);
    detail
}

/// A score is a decimal number of digits only. A number that an `i32` cannot hold is the largest `i32`. An empty
/// text, a sign, a space or any other byte is no score.
pub fn parse_score(text: &[u8]) -> i32 {
    if text.is_empty() {
        return SCORE_NONE;
    }
    let mut score = 0i64;
    for &byte in text {
        if !byte.is_ascii_digit() {
            return SCORE_NONE;
        }
        score = (score * 10 + i64::from(byte - b'0')).min(i64::from(i32::MAX));
    }
    i32::try_from(score).unwrap_or(i32::MAX)
}

#[cfg(test)]
mod tests;
