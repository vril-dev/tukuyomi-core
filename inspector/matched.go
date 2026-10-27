// What a VERDICT of the request phases says about the rules that matched.
package main

import (
	"math"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// scoreVar is the TX variable in which the common rule sets add up the score
// of a request; their blocking rule compares it with the threshold. It is in
// lower case like bodyCutVar: the TX collection folds the case of its keys.
// It is set by the end of phase 2. A bundle without such rules does not have it.
const scoreVar = "blocking_inbound_anomaly_score"

// detailOf reads the transaction once, in the order of evaluation, when a
// VERDICT of phase 1 or 2 is made. deciding is the rule id of that VERDICT (0
// for a Continue that no rule decided): the rule is not listed, but its
// severity counts.
//
// A match counts when it is logged (a nolog rule does not: the common rule
// sets have many of them, for set-up and for adding up the score) and its id is
// not one of the inspector's own rules (reservedID). The ids are the first
// maxRuleIDs of them, with more set when there are others. The severity is the
// lowest number of them (0 is the heaviest); a rule without one (-1) is
// skipped, and so is a number that Coraza does not accept. The score is read
// last (anomalyScore).
//
// Log is a method of the match that Coraza makes, not of types.MatchedRule, so
// it is asked through an interface of its own, as detectionOf asks for
// DetectionOnlyInterruption. When a match does not have it (a Coraza that
// changed), the VERDICT carries nothing and the request goes on.
func detailOf(tx types.Transaction, deciding int) ruleDetail {
	d := ruleDetail{severity: severityNone}
	for _, m := range tx.MatchedRules() {
		l, ok := m.(interface{ Log() bool })
		if !ok {
			return noDetail
		}
		r := m.Rule()
		id := r.ID()
		if !l.Log() || reservedID(id) {
			continue
		}
		if s := r.Severity().Int(); s >= 0 && s <= maxSeverity && uint8(s) < d.severity {
			d.severity = uint8(s)
		}
		if id == deciding {
			continue
		}
		if len(d.ids) < maxRuleIDs {
			d.ids = append(d.ids, int64(id))
		} else {
			d.more = true
		}
	}
	d.score = anomalyScore(tx)
	return d
}

// anomalyScore reads scoreVar the way markCut and requestComplete read the TX
// collection. It is scoreNone when the transaction or the collection is not of
// the expected type, the variable is missing or not one value, or the value is
// not a score (parseScore). The variable anomaly_score is not read: it stays 0
// until phase 5.
func anomalyScore(tx types.Transaction) int32 {
	ts, ok := tx.(plugintypes.TransactionState)
	if !ok {
		return scoreNone
	}
	m, ok := ts.Collection(variables.TX).(collection.Map)
	if !ok {
		return scoreNone
	}
	v := m.Get(scoreVar)
	if len(v) != 1 {
		return scoreNone
	}
	return parseScore(v[0])
}

// parseScore reads a decimal number of digits only. A larger number than an
// int32 holds is the largest int32. An empty text, a sign, a space or any other
// byte is no score: scoreNone.
func parseScore(s string) int32 {
	if s == "" {
		return scoreNone
	}
	n := int64(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return scoreNone
		}
		n = min(n*10+int64(c-'0'), math.MaxInt32)
	}
	return int32(n)
}
