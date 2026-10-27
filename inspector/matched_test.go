package main

import (
	"fmt"
	"math"
	"slices"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/types"
)

// The rules of the tests: every one says log or nolog (a rule without it takes
// the default action of the bundle, which has none here), and all of them match
// a POST. The first is logged with a severity of WARNING, the second is not
// logged and has the heaviest severity (it must not count), the third sets the
// score as a rule set does, the fourth and the fifth deny, each with a severity.
const (
	logRule   = `SecRule REQUEST_METHOD "@streq POST" "id:9301,phase:2,pass,log,severity:4"` + "\n"
	nologRule = `SecRule REQUEST_METHOD "@streq POST" "id:9302,phase:2,pass,nolog,severity:0"` + "\n"
	scoreRule = `SecAction "id:9303,phase:2,pass,nolog,setvar:tx.blocking_inbound_anomaly_score=7"` + "\n"
	denyRule  = `SecRule REQUEST_METHOD "@streq POST" "id:9304,phase:2,deny,log,status:403,severity:2"` + "\n"
	laterDeny = `SecRule REQUEST_METHOD "@streq POST" "id:9305,phase:2,deny,log,status:401,severity:6"` + "\n"
)

const matchedBase = baseRules + "SecRequestBodyLimit 1024\n"

func expectDetail(t *testing.T, o out, ids []int64, severity uint8, score int32) {
	t.Helper()
	if !slices.Equal(o.ids, ids) || o.sev != severity || o.score != score {
		t.Fatalf("rules %v severity %d score %d, want %v %d %d", o.ids, o.sev, o.score, ids, severity, score)
	}
}

func postReply(t *testing.T, h *harness) (out, uint32) {
	t.Helper()
	return flagCase{begin: defaultBegin(11), body: "probe=block"}.send(t, h)
}

// A Block lists the logged rule and not the one that is not logged nor the
// rule that decided; the severity is the lowest of the logged rules and the
// deciding rule; the score is the one the rules set. A rule after the deciding
// one is not evaluated.
func TestBlockCarriesMatchedRules(t *testing.T) {
	o, msg := postReply(t, productHarness(t, matchedBase+logRule+nologRule+scoreRule+denyRule+laterDeny))
	expectVerdict(t, o, 1, msg, 2, true)
	if o.rule != 9304 {
		t.Fatalf("%+v", o)
	}
	expectDetail(t, o, []int64{9301}, 2, 7)
}

// In a bundle that only detects, the first match that would have blocked is the
// rule of the VERDICT, and the others that would have are listed.
func TestDetectionCarriesMatchedRules(t *testing.T) {
	o, msg := postReply(t, detectHarness(t, matchedBase+logRule+nologRule+scoreRule+denyRule+laterDeny))
	expectDetected(t, o, msg, 9304, 403)
	expectDetail(t, o, []int64{9301, 9305}, 2, 7)
}

// A Continue carries the rules too. A bundle without the variable of the
// score has none; a variable that is 0 beside nothing else carries nothing,
// in phase 1 as well as in phase 2.
func TestContinueCarriesMatchedRules(t *testing.T) {
	o, msg := postReply(t, productHarness(t, matchedBase+logRule+nologRule))
	expectVerdict(t, o, 1, msg, 2, false)
	expectDetail(t, o, []int64{9301}, 4, scoreNone)

	h := productHarness(t, matchedBase+`SecAction "id:9300,phase:1,pass,nolog,setvar:tx.blocking_inbound_anomaly_score=0"`+"\n")
	h.in(kindTxBegin, 1, 1, defaultBegin(11).payload())
	o = h.cap.next(t)
	expectVerdict(t, o, 1, 1, 1, false)
	expectDetail(t, o, nil, severityNone, scoreNone)
	h.in(kindBody, 1, 2, []byte("probe=block"))
	h.in(kindBodyEnd, 1, 3, nil)
	o = h.cap.next(t)
	expectVerdict(t, o, 1, 3, 2, false)
	expectDetail(t, o, nil, severityNone, scoreNone)
}

// A rule of phase 1 that blocks is listed by its severity only: it is the
// deciding rule. The score is not set yet.
func TestPhase1BlockCarriesSeverity(t *testing.T) {
	h := productHarness(t, matchedBase+`SecRule REQUEST_METHOD "@streq POST" "id:9306,phase:1,deny,log,status:403,severity:3"`+"\n")
	h.in(kindTxBegin, 1, 1, defaultBegin(11).payload())
	o := h.cap.next(t)
	expectVerdict(t, o, 1, 1, 1, true)
	expectDetail(t, o, nil, 3, scoreNone)
}

// 16 matches are all listed; the 17th sets the more mark and is not listed, but
// its severity counts.
func TestMatchedRulesLimit(t *testing.T) {
	for _, n := range []int{maxRuleIDs, maxRuleIDs + 1} {
		var rules strings.Builder
		for i := range n {
			sev := ""
			if i == n-1 {
				sev = ",severity:1"
			}
			fmt.Fprintf(&rules, `SecRule REQUEST_METHOD "@streq POST" "id:%d,phase:2,pass,log%s"`+"\n", 9400+i, sev)
		}
		o, msg := postReply(t, productHarness(t, matchedBase+rules.String()))
		expectVerdict(t, o, 1, msg, 2, false)
		var ids []int64
		for i := range maxRuleIDs {
			ids = append(ids, 9400+int64(i))
		}
		expectDetail(t, o, ids, 1, scoreNone)
		if more := o.flags&flagMoreRules != 0; more != (n > maxRuleIDs) {
			t.Errorf("%d matches: more mark %v", n, more)
		}
	}
}

// The response phases carry nothing, whatever matched before.
func TestResponseVerdictsCarryNothing(t *testing.T) {
	h := productHarness(t, matchedBase+logRule+scoreRule)
	o, msg := postReply(t, h)
	expectDetail(t, o, []int64{9301}, 4, 7)
	h.in(kindRespBegin, 1, msg+1, respPayload(200, "HTTP/1.1", 0, nil))
	o = h.cap.next(t)
	expectVerdict(t, o, 1, msg+1, 3, false)
	expectDetail(t, o, nil, severityNone, scoreNone)
	h.in(kindRespEnd, 1, msg+2, nil)
	o = h.cap.next(t)
	expectVerdict(t, o, 1, msg+2, 4, false)
	expectDetail(t, o, nil, severityNone, scoreNone)
}

// fakeMeta is the rule of a fake match, fakeMatch a match that has Log as the
// matches of Coraza have, bareMatch one that does not.
type fakeMeta struct {
	types.RuleMetadata
	id  int
	sev types.RuleSeverity
}

func (m fakeMeta) ID() int                      { return m.id }
func (m fakeMeta) Severity() types.RuleSeverity { return m.sev }

type fakeMatch struct {
	types.MatchedRule
	meta fakeMeta
	log  bool
}

func (m fakeMatch) Rule() types.RuleMetadata { return m.meta }
func (m fakeMatch) Log() bool                { return m.log }

type bareMatch struct {
	types.MatchedRule
	meta fakeMeta
}

func (m bareMatch) Rule() types.RuleMetadata { return m.meta }

// matchedTx is a real transaction that says it matched these rules.
type matchedTx struct {
	realTx
	rules []types.MatchedRule
}

func (m matchedTx) MatchedRules() []types.MatchedRule { return m.rules }

// detailOf lists the logged matches except the inspector's own rules (the ids
// 4000001 to 4000011, but not the ones next to them), leaves the deciding rule
// out of the list but not out of the severity, skips a severity that is not set,
// and carries nothing when a match has no Log.
func TestDetailOf(t *testing.T) {
	tx := productWAFFor(t, matchedBase).NewTransaction()
	defer tx.Close()
	m := func(id int, sev types.RuleSeverity, log bool) types.MatchedRule {
		return fakeMatch{meta: fakeMeta{id: id, sev: sev}, log: log}
	}
	got := detailOf(matchedTx{tx.(realTx), []types.MatchedRule{
		m(4000000, -1, true), // the id before the inspector's own: listed
		m(4000001, 0, true),  // the first of them: not listed, and its severity is not used
		m(4000011, 0, true),  // the last of them
		m(4000012, -1, true), // the id after them: listed
		m(5, 1, false),       // not logged: neither listed nor used
		m(6, 3, true),        // the deciding rule: its severity is used
		m(7, types.RuleSeverityUnset, true),
	}}, 6)
	if want := (ruleDetail{ids: []int64{4000000, 4000012, 7}, severity: 3, score: scoreNone}); !slices.Equal(got.ids, want.ids) ||
		got.more || got.severity != want.severity || got.score != want.score {
		t.Errorf("%+v, want %+v", got, want)
	}
	got = detailOf(matchedTx{tx.(realTx), []types.MatchedRule{
		m(5, 2, true), bareMatch{meta: fakeMeta{id: 6, sev: 1}}, m(7, 0, true),
	}}, 0)
	if got.severity != noDetail.severity || got.score != noDetail.score || len(got.ids) != 0 || got.more {
		t.Errorf("a match without Log: %+v", got)
	}
}

// A score is digits only, and a number past the largest int32 is that largest
// number.
func TestParseScore(t *testing.T) {
	for in, want := range map[string]int32{
		"0": 0, "5": 5, "007": 7,
		"2147483647": math.MaxInt32, "2147483648": math.MaxInt32, "99999999999999999999999999": math.MaxInt32,

		"": scoreNone, "-1": scoreNone, "-5": scoreNone, "+5": scoreNone, " 5": scoreNone, "5 ": scoreNone,
		"5.0": scoreNone, "1e3": scoreNone, "abc": scoreNone, "99999999999999999999x": scoreNone,
	} {
		if got := parseScore(in); got != want {
			t.Errorf("%q: %d, want %d", in, got, want)
		}
	}
}
