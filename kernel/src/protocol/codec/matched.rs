//! The rules that matched a request, as a VERDICT of the request phases says it: the value that the kernel hands on
//! with the verdict, and the end of the VERDICT payload that carries it.
//!
//! The end of a VERDICT is the count of the listed rule ids (u8, 0 to 16), that many ids (i64, each above 0), the
//! severity (u8, 0 to 7 with 0 the heaviest, or 255 for none) and the score (i32, -1 for none, 0 and up a score).
//! The flag `FLAG_MORE_RULES` of the VERDICT says that more rules matched than the 16 that are listed; it needs a
//! full list. Only a VERDICT of the phases 1 and 2 carries anything: phases 3 and 4 carry the form that says
//! nothing, 0, 255 and -1. The same limits as the Go constants (`codec.go`).
#![forbid(unsafe_code)]

use super::{ContentError, Cursor};

/// The most rule ids one VERDICT lists.
pub(crate) const MAX_RULE_IDS: usize = 16;
/// The highest severity number (the lightest); 0 is the heaviest.
const MAX_SEVERITY: u8 = 7;
const SEVERITY_NONE: u8 = 255;
const SCORE_NONE: i32 = -1;

/// The rules that matched a request: a fixed-size value, so that the answer for a request stays `Copy`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Matched {
    /// How many of `ids` are listed, 0 to 16.
    pub count: u8,
    /// The ids of the rules that matched and were logged, in the order they were evaluated, without the rule that
    /// decided the request. The ids behind the first `count` are 0.
    pub ids: [i64; MAX_RULE_IDS],
    /// More rules matched than the ones listed.
    pub more: bool,
    /// The heaviest (lowest) severity of the rules that matched and of the one that decided, 0 to 7, or 255 for none.
    pub severity: u8,
    /// The anomaly score of the rules at the end of the inspection, 0 and up, or -1 for none.
    pub score: i32,
}

impl Matched {
    /// Nothing to say: no ids, no severity and no score.
    pub const NONE: Matched = Matched {
        count: 0,
        ids: [0; MAX_RULE_IDS],
        more: false,
        severity: SEVERITY_NONE,
        score: SCORE_NONE,
    };

    /// The listed rule ids.
    pub fn ids(&self) -> &[i64] {
        &self.ids[..usize::from(self.count).min(MAX_RULE_IDS)]
    }
}

/// `NONE`, not zeros: a severity 0 and a score 0 are values.
impl Default for Matched {
    fn default() -> Matched {
        Matched::NONE
    }
}

/// Reads the end of a VERDICT of `phase`; `more` is its flag `FLAG_MORE_RULES`. Every value is checked against the
/// limits before it is kept, and the rules of the phases 3 and 4 are refused. The cursor is left behind the score.
pub(super) fn read(c: &mut Cursor<'_>, phase: u8, more: bool) -> Result<Matched, ContentError> {
    let count = c.u8()?;
    if usize::from(count) > MAX_RULE_IDS {
        return Err(ContentError("verdict rule count out of range"));
    }
    let mut ids = [0i64; MAX_RULE_IDS];
    for id in ids.iter_mut().take(usize::from(count)) {
        *id = i64::from_be_bytes(c.array()?);
        if *id < 1 {
            return Err(ContentError("verdict rule id out of range"));
        }
    }
    let severity = c.u8()?;
    if severity > MAX_SEVERITY && severity != SEVERITY_NONE {
        return Err(ContentError("verdict severity out of range"));
    }
    let score = i32::from_be_bytes(c.array()?);
    if score < SCORE_NONE {
        return Err(ContentError("verdict score out of range"));
    }
    if more && usize::from(count) != MAX_RULE_IDS {
        return Err(ContentError(
            "verdict more flag needs a full list of rule ids",
        ));
    }
    let matched = Matched {
        count,
        ids,
        more,
        severity,
        score,
    };
    if phase > 2 && matched != Matched::NONE {
        return Err(ContentError(
            "verdict of a response phase carries rules, a severity or a score",
        ));
    }
    Ok(matched)
}
