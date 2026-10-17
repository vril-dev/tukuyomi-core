package main

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

func blockIt(rule, status int) *types.Interruption {
	return &types.Interruption{RuleID: rule, Status: status, Action: "deny", Data: "d"}
}

func TestNormalZeroBodyAndClose(t *testing.T) {
	h := newHarness(t, nil)
	h.in(kindTxBegin, 1, 1, defaultBegin(0).payload())
	expectVerdict(t, h.cap.next(t), 1, 1, 1, false)
	h.in(kindBodyEnd, 1, 2, nil)
	expectVerdict(t, h.cap.next(t), 1, 2, 2, false) // phase 2 even without a body
	// CLOSED is handed over only after the entry left the table.
	h.cap.onOut = func(b []byte) {
		if o, _ := parseOut(b); o.kind == kindClosed {
			h.tab.mu.Lock()
			n := len(h.tab.active)
			h.tab.mu.Unlock()
			if n != 0 {
				t.Errorf("CLOSED sent while %d entries active", n)
			}
		}
	}
	h.in(kindTxEnd, 1, 3, []byte{endComplete})
	o := h.cap.next(t)
	expect(t, o, kindClosed, 1, 3)
	h.waitOwners()
	f := h.fake(1)
	if o.cerr != 0 || f.count("phase2") != 1 || f.count("logging") != 1 || f.count("close") != 1 || f.count("write") != 0 {
		t.Fatalf("close error %d, calls %v", o.cerr, f.calls)
	}
	if got := strings.Join(f.calls[:5], ","); got != "conn,uri,reqhdr,reqhdr,server" || f.serverNames[0] != "example.test" {
		t.Fatalf("call order %s, server names %q", got, f.serverNames)
	}
}

func TestBodyFlowAndDeclaredChecks(t *testing.T) {
	h := newHarness(t, nil)
	h.in(kindTxBegin, 1, 1, defaultBegin(5).payload())
	expectVerdict(t, h.cap.next(t), 1, 1, 1, false)
	h.in(kindBody, 1, 2, []byte("a=b"))
	h.in(kindBody, 1, 3, []byte("&c")) // 3 + 2: exactly the declared 5
	h.in(kindBodyEnd, 1, 4, nil)
	expectVerdict(t, h.cap.next(t), 1, 4, 2, false)
	h.in(kindTxEnd, 1, 5, []byte{endComplete})
	expect(t, h.cap.next(t), kindClosed, 1, 5)
	h.waitOwners()
	if f := h.fake(1); f.count("write") != 2 || f.count("reqaccess") != 4 { // the two Continue checks, first BODY and BODY_END
		t.Fatalf("calls %v", f.calls)
	}

	// The first frame past the limit is refused before Coraza sees it.
	for _, c := range []struct {
		name   string
		bodies []string
		end    bool // BODY_END after the bodies
		code   uint16
		writes int // WriteRequestBody calls before the ERROR
	}{
		{"3 + 3 over a declared 5", []string{"abc", "def"}, false, codeReqOver, 1},
		{"BODY_END before the declared bytes", []string{"abcd"}, true, codeReqTruncated, 1},
		{"empty BODY", []string{""}, false, codeBadContent, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, nil)
			h.in(kindTxBegin, 1, 1, defaultBegin(5).payload())
			h.cap.next(t)
			msg := uint32(1)
			for _, b := range c.bodies {
				msg++
				h.in(kindBody, 1, msg, []byte(b))
			}
			if c.end {
				msg++
				h.in(kindBodyEnd, 1, msg, nil)
			}
			expectError(t, h.cap.next(t), 1, msg, classTxFailed, c.code)
			if f := h.fake(1); f.count("write") != c.writes || f.count("phase2") != 0 {
				t.Fatalf("calls %s", f.trace())
			}
		})
	}
}

func TestBodyNotAccessible(t *testing.T) {
	// The body access is lost after the phase 1 check (the first call).
	h := newHarness(t, func(string) *fakeTx { return &fakeTx{reqAccess: true, accessLost: 2} })
	h.in(kindTxBegin, 1, 1, defaultBegin(5).payload())
	h.cap.next(t)
	h.in(kindBody, 1, 2, []byte("abcde"))
	expectError(t, h.cap.next(t), 1, 2, classTxFailed, codeReqNotInspect)
	if f := h.fake(1); f.count("write") != 0 {
		t.Fatal("WriteRequestBody called although the body is not accessible")
	}
}

// A rule can ask for a status that the VERDICT cannot hold: ERROR code 29
// instead of a VERDICT, and later frames of the transaction are discarded.
func TestWriteOutcomes(t *testing.T) {
	h := newHarness(t, func(string) *fakeTx {
		return &fakeTx{reqAccess: true, write: func(b []byte) (*types.Interruption, int, error) { return blockIt(1, 70000), 0, nil }}
	})
	h.in(kindTxBegin, 1, 1, defaultBegin(10).payload())
	h.cap.next(t)
	h.in(kindBody, 1, 2, []byte("abcde"))
	expectError(t, h.cap.next(t), 1, 2, classTxFailed, codeBadVerdict)
	h.in(kindBody, 1, 3, []byte("fghij"))
	h.in(kindBodyEnd, 1, 4, nil)
	h.cap.none(t, 50*time.Millisecond)
	h.in(kindTxEnd, 1, 5, []byte{endBlocked})
	expect(t, h.cap.next(t), kindClosed, 1, 5)
	h.waitOwners()
	if f := h.fake(1); f.count("write") != 1 || f.count("phase2") != 0 {
		t.Fatalf("calls %v", f.calls)
	}
}

func TestMessageNumberGap(t *testing.T) {
	h := newHarness(t, nil)
	h.in(kindTxBegin, 1, 1, defaultBegin(5).payload())
	h.cap.next(t)
	h.in(kindBody, 1, 3, []byte("abcde"))
	expectError(t, h.cap.next(t), 1, 3, classTxFailed, codeOrder)
	if f := h.fake(1); f.count("write") != 0 {
		t.Fatal("the frame with the wrong number reached Coraza")
	}
}

// TestStateFrameMatrix sends, in a state that does not take it, a frame that
// is refused with ERROR code 16 (the frame's msg) or dropped without a reply
// (after a block or an ERROR), then TX_END. Coraza is not called for it.
func TestStateFrameMatrix(t *testing.T) {
	type fr struct {
		kind uint8
		p    []byte
	}
	tb := func(decl uint64) fr { return fr{kindTxBegin, defaultBegin(decl).payload()} }
	rb := func(decl uint64) fr { return fr{kindRespBegin, respPayload(200, "HTTP/1.1", decl, nil)} }
	end, body, rbody, rend := fr{kindBodyEnd, nil}, fr{kindBody, []byte("ab")}, fr{kindRespBody, []byte("ab")}, fr{kindRespEnd, nil}
	blockReq := func(string) *fakeTx { return &fakeTx{phase1: blockIt(1, 403), reqAccess: true} }
	blockResp := func(string) *fakeTx { return &fakeTx{reqAccess: true, phase3: blockIt(2, 403)} }
	for _, c := range []struct {
		name    string
		mk      func(string) *fakeTx
		setup   []fr
		replies int // replies to the setup frames
		send    fr
		drop    bool // else ERROR code 16
	}{
		{"headers/RESP_BEGIN", nil, []fr{tb(4)}, 1, rb(4), false},
		{"request done/RESP_BODY", nil, []fr{tb(0), end}, 2, rbody, false},
		{"response/BODY_END", nil, []fr{tb(0), end, rb(4)}, 3, end, false},
		{"response done/RESP_END", nil, []fr{tb(0), end, rb(0), rend}, 4, rend, false},
		{"blocked request/BODY", blockReq, []fr{tb(4)}, 1, body, true},
		{"blocked response/RESP_BODY", blockResp, []fr{tb(0), end, rb(0)}, 3, rbody, true},
		{"failed/BODY_END", nil, []fr{tb(4), {kindBody, nil}}, 2, end, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, c.mk)
			for i, f := range c.setup {
				h.in(f.kind, 1, uint32(i+1), f.p)
			}
			for range c.replies {
				h.cap.next(t)
			}
			last := uint32(len(c.setup))
			fk := h.fake(1)
			d0, before := h.discarded(), fk.trace()
			h.in(c.send.kind, 1, last+1, c.send.p)
			if c.drop {
				waitUntil(t, "the frame to be discarded", func() bool { return h.discarded() == d0+1 })
			} else {
				expectError(t, h.cap.next(t), 1, last+1, classTxFailed, codeOrder)
			}
			h.in(kindTxEnd, 1, last+2, []byte{endComplete})
			expect(t, h.cap.next(t), kindClosed, 1, last+2)
			h.waitOwners()
			if got := fk.trace(); got != before+",logging,close" {
				t.Fatalf("Coraza calls %s -> %s", before, got)
			}
		})
	}
}

func TestResponseFlow(t *testing.T) {
	// start plays the request and RESP_BEGIN (msg 3) and consumes the three
	// Continue verdicts.
	start := func(t *testing.T, mk func(string) *fakeTx, decl uint64) *harness {
		h := newHarness(t, mk)
		h.in(kindTxBegin, 1, 1, defaultBegin(0).payload())
		h.in(kindBodyEnd, 1, 2, nil)
		h.in(kindRespBegin, 1, 3, respPayload(200, "HTTP/1.1", decl, [][2]string{{"Content-Type", "text/plain"}}))
		for range 3 {
			h.cap.next(t)
		}
		return h
	}
	h := start(t, nil, 5)
	h.in(kindRespBody, 1, 4, []byte("abc"))
	h.in(kindRespBody, 1, 5, []byte("de")) // 3 + 2: exactly the declared 5
	h.in(kindRespEnd, 1, 6, nil)
	expectVerdict(t, h.cap.next(t), 1, 6, 4, false)
	h.in(kindTxEnd, 1, 7, []byte{endComplete})
	expect(t, h.cap.next(t), kindClosed, 1, 7)

	resp := func(access, proc bool) func(string) *fakeTx {
		return func(string) *fakeTx { return &fakeTx{reqAccess: true, respAccess: access, respProc: proc} }
	}
	for _, c := range []struct {
		name string
		mk   func(string) *fakeTx
		decl uint64
		body string
		code uint16
	}{
		{"not accessible", resp(false, true), 2, "ab", codeRespNotInspect},
		{"over declared", resp(true, true), 2, "abc", codeRespOver},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := start(t, c.mk, c.decl)
			h.in(kindRespBody, 1, 4, []byte(c.body))
			expectError(t, h.cap.next(t), 1, 4, classTxFailed, c.code)
		})
	}
}

// The 18th frame behind a held write overflows the queue (17): the ERROR
// comes first, and neither the queued frames nor later ones reach Coraza.
func TestOverflowCheckedBeforeDequeue(t *testing.T) {
	entered, rel := make(chan struct{}, 1), make(chan struct{})
	h := newHarness(t, func(string) *fakeTx {
		first := true
		return &fakeTx{reqAccess: true, write: func(b []byte) (*types.Interruption, int, error) {
			if first {
				first = false
				entered <- struct{}{}
				<-rel
			}
			return nil, len(b), nil
		}}
	})
	release := sync.OnceFunc(func() { close(rel) })
	t.Cleanup(release) // runs before the harness check, so a failed test cannot hold the owner
	h.in(kindTxBegin, 1, 1, defaultBegin(100).payload())
	h.cap.next(t)
	h.in(kindBody, 1, 2, []byte("a"))
	recvWithin(t, entered, "BODY #1 in Coraza") // the owner holds BODY #1 inside Coraza
	for i := range queueDepth {
		h.in(kindBody, 1, uint32(3+i), []byte("b")) // queued until full
	}
	const over = 3 + queueDepth
	h.in(kindBody, 1, over, []byte("c")) // one more: the overflow mark
	release()
	expectError(t, h.cap.next(t), 1, over, classTxFailed, codeOverflow)
	h.in(kindBody, 1, over+1, []byte("d")) // after overflow: discarded
	h.in(kindTxEnd, 1, over+2, []byte{endUninspectable})
	expect(t, h.cap.next(t), kindClosed, 1, over+2)
	h.waitOwners()
	if f := h.fake(1); f.count("write") != 1 || f.count("phase2") != 0 {
		t.Fatalf("queued frames reached Coraza: %v", f.calls)
	}
}

func TestNotCreatedAndMaxID(t *testing.T) {
	h := newHarness(t, nil)
	begin := defaultBegin(0).payload()
	for id := uint64(1); id <= maxConcurTx; id++ {
		h.in(kindTxBegin, id, 1, begin)
		h.cap.next(t)
	}
	h.in(kindTxBegin, 5, 1, begin)
	expectError(t, h.cap.next(t), 5, 1, classNotCreated, codeLimit)
	h.in(kindTxBegin, 5, 1, begin)    // id 5 used: counted only
	h.in(kindBody, 9, 2, []byte("x")) // unstarted id: advances max
	expectError(t, h.cap.next(t), 9, 2, classNotCreated, codeUnstarted)
	h.in(kindTxBegin, 8, 1, begin) // below max: counted only
	h.cap.none(t, 30*time.Millisecond)

	h.in(kindTxEnd, 1, 2, []byte{endComplete}) // frees a slot
	expect(t, h.cap.next(t), kindClosed, 1, 2)
	h.in(kindTxBegin, 11, 2, begin) // msg is not 1
	expectError(t, h.cap.next(t), 11, 2, classNotCreated, codeBadBegin)
	h.in(kindTxBegin, 12, 1, begin[:len(begin)-1]) // payload cut short
	expectError(t, h.cap.next(t), 12, 1, classNotCreated, codeBadBegin)
	h.in(kindBody, 1, 3, []byte("x")) // closed id: counted only
	h.cap.none(t, 30*time.Millisecond)
	if !h.tab.startDrain() || h.tab.startDrain() {
		t.Fatal("startDrain")
	}
	h.in(kindTxBegin, 13, 1, begin)
	expectError(t, h.cap.next(t), 13, 1, classNotCreated, codeDraining)
}

func TestBadTxEndStillCloses(t *testing.T) {
	h := newHarness(t, nil)
	h.in(kindTxBegin, 1, 1, defaultBegin(0).payload())
	h.cap.next(t)
	h.in(kindTxEnd, 1, 2, []byte{9})
	expect(t, h.cap.next(t), kindClosed, 1, 2)
}

func TestConnLostClosesWithoutClosed(t *testing.T) {
	h := newHarness(t, nil)
	for id := uint64(1); id <= 3; id++ {
		h.in(kindTxBegin, id, 1, defaultBegin(10).payload())
		h.cap.next(t)
	}
	h.in(kindBody, 2, 2, []byte("abc"))
	h.tab.connLost()
	h.waitOwners()
	h.cap.none(t, 30*time.Millisecond)
	for id := uint64(1); id <= 3; id++ {
		if f := h.fake(id); f.count("close") != 1 || f.count("logging") != 1 {
			t.Fatalf("tx %d calls %v", id, f.calls)
		}
	}
}

// ---- real Coraza (the pinned tag) ----

func realWAF(t *testing.T, directives string) coraza.WAF {
	t.Helper()
	t.Setenv("TMPDIR", t.TempDir())
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
	if err != nil {
		t.Fatalf("NewWAF: %v", err)
	}
	return waf
}

func productWAFFor(t *testing.T, rules string) coraza.WAF {
	t.Helper()
	t.Setenv("TMPDIR", t.TempDir())
	waf, err := newWAF(ruleBundle(rules))
	if err != nil {
		t.Fatalf("newWAF: %v", err)
	}
	return waf
}

// realHarness runs the owners on the transactions of the WAF that Coraza
// builds from the directives alone, productHarness on the WAF that the
// inspector builds (newWAF).
func realHarness(t *testing.T, directives string) *harness {
	return harnessFor(t, realWAF(t, directives))
}

func productHarness(t *testing.T, rules string) *harness {
	return harnessFor(t, productWAFFor(t, rules))
}

func harnessFor(t *testing.T, waf coraza.WAF) *harness {
	h := &harness{t: t, cap: newCapture(), txs: map[string]*fakeTx{}}
	h.tab = newTable(testRun, testInc, func(id string) types.Transaction { return waf.NewTransactionWithID(id) }, h.cap.send)
	t.Cleanup(h.check) // as for a lost connection; every owner must finish
	return h
}

const baseRules = "SecRuleEngine On\nSecRequestBodyAccess On\nSecRequestBodyLimit 16\nSecRequestBodyInMemoryLimit 8\nSecRequestBodyLimitAction Reject\nSecResponseBodyAccess Off\nSecAuditEngine Off\n"

func TestRealCorazaBodyLimitBoundary(t *testing.T) {
	// limit 16 (>=): 15 bytes pass, exactly 16 is rejected with rule 0 / 413.
	for _, n := range []int{15, 16} {
		h := realHarness(t, baseRules)
		h.in(kindTxBegin, 1, 1, defaultBegin(uint64(n)).payload())
		h.cap.next(t)
		h.in(kindBody, 1, 2, []byte(strings.Repeat("a", n)))
		h.in(kindBodyEnd, 1, 3, nil)
		o := h.cap.next(t)
		if n < 16 {
			expectVerdict(t, o, 1, 3, 2, false)
			continue
		}
		expectVerdict(t, o, 1, 2, 2, true)
		if o.rule != 0 || o.stat != 413 || o.act != "deny" {
			t.Fatalf("n=%d %+v", n, o)
		}
	}
}

// With the body access or the rule engine off, phase 1 is no Continue.
func TestRealCorazaPhase1Incomplete(t *testing.T) {
	for _, off := range []string{"SecRequestBodyAccess Off", "SecRuleEngine Off"} {
		t.Run(off, func(t *testing.T) {
			key, _, _ := strings.Cut(off, " ")
			h := realHarness(t, strings.Replace(baseRules, key+" On", off, 1))
			h.in(kindTxBegin, 1, 1, defaultBegin(3).payload())
			expectError(t, h.cap.next(t), 1, 1, classTxFailed, codeIncomplete)
			h.in(kindBody, 1, 2, []byte("abc")) // failed: counted, no reply
			h.in(kindTxEnd, 1, 3, []byte{endUninspectable})
			expect(t, h.cap.next(t), kindClosed, 1, 3)
		})
	}
}

// ---- reserved directives and requestComplete ----

// flagCase is a request that sets one of the flags that the reserved rules
// test: a URI that does not parse, more arguments than the limit, a multipart
// body that does not parse, a JSON body that does not parse.
type flagCase struct {
	name  string
	rules string // appended to the operator's rules
	begin tBegin
	body  string
	rule  int // the reserved rule that blocks it
}

func flagCases() []flagCase {
	uri := defaultBegin(0)
	uri.uri = "/%zz"
	multipart := defaultBegin(7)
	multipart.headers = [][2]string{{"Host", "example.test"}, {"Content-Type", "multipart/form-data; boundary=xx"}}
	return []flagCase{
		{"uri", "", uri, "", 4000003},
		{"arguments", "SecArgumentsLimit 2\n", defaultBegin(11), "a=1&b=2&c=3", 4000002},
		{"body", "", multipart, "garbage", 4000001},
		{"json body", "", jsonBegin(1), "{", 4000001},
	}
}

// send plays the request through h as transaction 1 up to BODY_END and returns
// the reply to BODY_END and its message number (the phase 1 Continue is
// checked on the way).
func (c flagCase) send(t *testing.T, h *harness) (out, uint32) {
	t.Helper()
	h.in(kindTxBegin, 1, 1, c.begin.payload())
	expectVerdict(t, h.cap.next(t), 1, 1, 1, false)
	msg := uint32(2)
	if c.body != "" {
		h.in(kindBody, 1, msg, []byte(c.body))
		msg++
	}
	h.in(kindBodyEnd, 1, msg, nil)
	return h.cap.next(t), msg
}

// Whatever the operator's rules or a recommended configuration say, the
// reserved rules block.
func TestReservedRulesBlock(t *testing.T) {
	settings := map[string]string{
		"none":                   "",
		"all of them, any order": "SecRequestBodyAccess Off\nSecRuleEngine DetectionOnly\nSecRequestBodyLimitAction ProcessPartial\n",
	}
	for sname, s := range settings {
		for _, c := range flagCases() {
			t.Run(sname+"/"+c.name, func(t *testing.T) {
				h := productHarness(t, baseRules+s+c.rules)
				o, msg := c.send(t, h)
				expectVerdict(t, o, 1, msg, 2, true)
				if o.rule != int64(c.rule) || o.act != "deny" {
					t.Fatalf("%+v", o)
				}
			})
		}
	}
	// A body over the limit is rejected, not cut (SecRequestBodyLimitAction).
	h := productHarness(t, baseRules+settings["all of them, any order"])
	h.in(kindTxBegin, 1, 1, defaultBegin(16).payload())
	expectVerdict(t, h.cap.next(t), 1, 1, 1, false)
	h.in(kindBody, 1, 2, []byte(strings.Repeat("a", 16)))
	if o := h.cap.next(t); o.kind != kindVerdict || !o.block || o.rule != 0 || o.stat != 413 {
		t.Fatalf("%+v", o)
	}
}

// The reserved ids are taken, and a default transformation is refused: both
// stop NewWAF (without SecIgnoreRuleCompilationErrors).
func TestReservedRulesNameClash(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	for name, rules := range map[string]string{
		"reserved id":                `SecRule REQUEST_METHOD "@streq NOPE" "id:4000002,phase:1,pass"`,
		"default transformation set": `SecDefaultAction "phase:2,log,pass,t:lowercase"` + "\n" + `SecRule REQUEST_METHOD "@streq NOPE" "id:1,phase:2,pass"`,
	} {
		if _, err := newWAF(ruleBundle(baseRules + rules + "\n")); err == nil {
			t.Errorf("%s: NewWAF succeeded", name)
		}
	}
}

// A rule of the operator that skips, allows, removes or (with
// SecIgnoreRuleCompilationErrors) displaces the reserved rules must not turn a
// set flag into a Continue: the reply is ERROR code 25, and a Block that
// was decided earlier stays a Block.
func TestReservedRulesBypassedIsNoContinue(t *testing.T) {
	const post = `SecRule REQUEST_METHOD "@streq POST" "id:1,phase:1,`
	dup := "SecIgnoreRuleCompilationErrors On\n"
	for _, id := range []string{"4000001", "4000002", "4000003"} {
		dup += `SecRule REQUEST_METHOD "@streq NOPE" "id:` + id + `,phase:1,pass"` + "\n"
	}
	bypass := map[string]string{
		"skipAfter a missing marker": post + "pass,skipAfter:NOWHERE\"\n",
		"allow":                      post + "allow\"\n",
		"ruleRemoveById":             post + "pass,ctl:ruleRemoveById=4000001-4000003\"\n",
		"ignored duplicate id":       dup,
	}
	for bname, b := range bypass {
		for _, c := range flagCases() {
			t.Run(bname+"/"+c.name, func(t *testing.T) {
				h := productHarness(t, baseRules+b+c.rules)
				o, msg := c.send(t, h)
				expectError(t, o, 1, msg, classTxFailed, codeIncomplete)
			})
		}
	}
	t.Run("earlier block stays", func(t *testing.T) {
		h := productHarness(t, baseRules+`SecRule REQUEST_METHOD "@streq POST" "id:9,phase:2,deny,status:401"`+"\n")
		o, msg := flagCases()[0].send(t, h)
		expectVerdict(t, o, 1, msg, 2, true)
		if o.rule != 9 || o.stat != 401 {
			t.Fatalf("%+v", o)
		}
	})
}

// plainTx hides everything of a transaction but types.Transaction.
type plainTx struct{ types.Transaction }

// noProcessor returns no collection for the request body processor only.
type noProcessor struct{ realTx }

func (n noProcessor) Collection(v variables.RuleVariable) collection.Collection {
	if v == variables.ReqbodyProcessor {
		return nil
	}
	return n.realTx.Collection(v)
}

// noFlags returns no collection at all.
type noFlags struct{ realTx }

func (noFlags) Collection(variables.RuleVariable) collection.Collection { return nil }

// requestComplete on the real transaction, with the values the flags have on a
// fresh one, and on the values and types that it must not accept.
func TestRequestComplete(t *testing.T) {
	tx := productWAFFor(t, baseRules).NewTransaction()
	defer tx.Close()
	ts := tx.(plugintypes.TransactionState)
	for _, v := range []variables.RuleVariable{variables.ReqbodyError, variables.ArgumentsLimitReached, variables.URIParseError} {
		if g := ts.Collection(v).(collection.Single).Get(); g != "0" {
			t.Fatalf("%s is %q on a fresh transaction", v.Name(), g)
		}
	}
	if !requestComplete(tx, true, 0, "") || requestComplete(tx, true, 1, "URLENCODED") {
		t.Fatal("a fresh transaction is complete without a body only: it has no body processor")
	}
	tx.ProcessConnection("127.0.0.1", 1, "127.0.0.1", 2)
	tx.ProcessURI("/%zz", "GET", "HTTP/1.1")
	if !requestComplete(tx, false, 0, "") || requestComplete(tx, true, 0, "") {
		t.Fatal("the flags are read before phase 2 only, and a set flag is incomplete")
	}
	// Empty and "0" are no flag; anything else is one.
	for val, want := range map[string]bool{"": true, "0": true, "1": false} {
		f := &fakeTx{reqAccess: true, flags: map[variables.RuleVariable]string{variables.ArgumentsLimitReached: val}}
		if got := requestComplete(f, true, 1, "URLENCODED"); got != want {
			t.Errorf("flag %q: complete %v, want %v", val, got, want)
		}
	}
	// A type that is not the expected one is incomplete.
	if requestComplete(plainTx{tx}, true, 1, "URLENCODED") || requestComplete(noFlags{tx.(realTx)}, true, 1, "URLENCODED") ||
		requestComplete(noProcessor{&fakeTx{reqAccess: true}}, true, 1, "URLENCODED") {
		t.Error("a transaction or collection of another type is complete")
	}
}

// ---- request body processors ----

const probeRule = `SecRule ARGS_POST:probe "@streq block" "id:9202,phase:2,deny,status:403"` + "\n"

// bodyReply plays a request with the given headers and body through the
// product WAF up to the reply to BODY_END.
func bodyReply(t *testing.T, rules string, headers [][2]string, body string) (out, uint32) {
	t.Helper()
	b := defaultBegin(uint64(len(body)))
	b.headers = headers
	return flagCase{begin: b, body: body}.send(t, productHarness(t, baseRules+"SecRequestBodyLimit 1024\n"+rules))
}

// A rule of the operator that replaces or forces the request body processor,
// or a body that no processor takes, leaves the body not parsed as the
// Content-Type says: no Continue (ERROR code 25), unless the processor is the
// expected one again. A Block stays a Block, and a request without a body is
// not asked.
func TestRealBodyProcessorReplaced(t *testing.T) {
	ctl := func(v string) string {
		return `SecRule REQUEST_METHOD "@streq POST" "id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=` + v + `"` + "\n"
	}
	force := `SecRule REQUEST_METHOD "@streq POST" "id:2,phase:1,pass,nolog,ctl:forceRequestBodyVariable=On"` + "\n"
	form := [][2]string{{"Host", "example.test"}, {"Content-Type", "application/x-www-form-urlencoded"}}
	for _, c := range []struct {
		name, rules string
		headers     [][2]string
		body        string
	}{
		{"RAW", ctl("RAW"), form, "probe=block"},
		{"no Content-Type", "", [][2]string{{"Host", "example.test"}}, "probe=block"},
	} {
		t.Run(c.name, func(t *testing.T) {
			o, msg := bodyReply(t, probeRule+c.rules, c.headers, c.body)
			expectError(t, o, 1, msg, classTxFailed, codeIncomplete)
		})
	}
	t.Run("empty and forced for a urlencoded body", func(t *testing.T) { // the processor is the expected one again
		o, msg := bodyReply(t, probeRule+ctl("")+force, form, "probe=block")
		expectVerdict(t, o, 1, msg, 2, true)
		if o.rule != 9202 {
			t.Fatalf("%+v", o)
		}
	})
}

// ---- JSON bodies ----

// jsonProbeRule matches the argument probe of a JSON body ({"probe":"block"}),
// jsonAnyRule the value block anywhere in it.
const (
	jsonProbeRule = `SecRule ARGS_POST:json.probe "@streq block" "id:9203,phase:2,deny,status:403"` + "\n"
	jsonAnyRule   = `SecRule ARGS_POST "@streq block" "id:9204,phase:2,deny,status:403"` + "\n"
	bigBody       = "SecRequestBodyLimit 65536\n" // bodyReply sets 1024; the later directive wins
)

func jsonHeaders(ctype string) [][2]string {
	return [][2]string{{"Host", "example.test"}, {"Content-Type", ctype}}
}

func jsonBody(v string) string { return `{"probe":"` + v + `"}` }

// nestedJSON is n objects inside one another with the value v in the innermost.
func nestedJSON(n int, v string) string {
	return strings.Repeat(`{"a":`, n) + `"` + v + `"` + strings.Repeat("}", n)
}

// expectRule checks the reply to BODY_END: a Continue for rule 0, else the
// Block of that rule with status 403.
func expectRule(t *testing.T, o out, msg uint32, rule int64) {
	t.Helper()
	expectVerdict(t, o, 1, msg, 2, rule != 0)
	if rule != 0 && (o.rule != rule || o.stat != 403) {
		t.Fatalf("%+v", o)
	}
}

// beginOn runs begin of an owner on tx, on this goroutine, for the request b
// and returns the owner and the one frame that begin sent.
func beginOn(t *testing.T, tx types.Transaction, b tBegin) (*owner, out) {
	t.Helper()
	c := newCapture()
	tab := newTable(testRun, testInc, func(string) types.Transaction { return tx }, c.send)
	tb, err := decodeTxBegin(b.payload())
	if err != nil {
		t.Fatal(err)
	}
	o := &owner{t: tab, e: newEntry(), id: 1}
	o.begin(tb, 1)
	return o, c.next(t)
}

// begin selects the expected processor from the first Content-Type by the rule
// of Coraza, adds JSON to it (application/json by prefix, application/<name>+json
// by the part before the first ";"), and sets the JSON processor after the
// check of phase 1 for a request with a body (declared > 0) only. A phase 1
// Block keeps its VERDICT; anything that keeps the processor from being set is
// an ERROR code 25 and no Continue.
func TestBeginSetsJSONProcessor(t *testing.T) {
	good := func() *fakeTx { return &fakeTx{reqAccess: true} }
	plain := func(f *fakeTx) types.Transaction { return plainTx{f} }
	noProc := func(f *fakeTx) types.Transaction { return noProcessor{f} }
	js, form := "application/json", "application/x-www-form-urlencoded"
	for _, c := range []struct {
		name     string
		ctypes   []string // the Content-Type headers, in order
		declared uint64
		fake     func() *fakeTx
		wrap     func(*fakeTx) types.Transaction // nil: the fake itself
		wantProc string                          // the expected processor of the owner
		sets     int                             // calls of Set
		reply    string                          // "continue", "block" or "error"
	}{
		{"json, case, spaces and charset", []string{" \tApplication/JSON ; charset=utf-8 \t"}, 5, good, nil, "JSON", 1, "continue"},
		{"json after urlencoded: only the first selects", []string{form, js}, 5, good, nil, "URLENCODED", 0, "continue"},
		{"vnd.api+json with charset", []string{"application/vnd.api+json; charset=UTF-8"}, 5, good, nil, "JSON", 1, "continue"},
		{"+json only after the semicolon", []string{"application/x; y=+json"}, 5, good, nil, "", 0, "continue"},
		{"phase 1 block", []string{js}, 5, func() *fakeTx { return &fakeTx{reqAccess: true, phase1: blockIt(1001, 403)} }, nil, "JSON", 0, "block"},
		{"processor without Set", []string{js}, 5, func() *fakeTx { return &fakeTx{reqAccess: true, plainProc: true} }, nil, "JSON", 0, "error"},
		{"not a TransactionState", []string{js}, 5, good, plain, "JSON", 0, "error"},
		{"no collection for the processor", []string{js}, 5, good, noProc, "JSON", 0, "error"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := c.fake()
			var tx types.Transaction = f
			if c.wrap != nil {
				tx = c.wrap(f)
			}
			b := defaultBegin(c.declared)
			b.headers = [][2]string{{"Host", "example.test"}}
			for _, v := range c.ctypes {
				b.headers = append(b.headers, [2]string{"Content-Type", v})
			}
			o, rep := beginOn(t, tx, b)
			if o.wantProc != c.wantProc {
				t.Errorf("expected processor %q, want %q", o.wantProc, c.wantProc)
			}
			if got := f.sets(); len(got) != c.sets || (c.sets == 1 && got[0] != "JSON") {
				t.Errorf("Set called with %q, want %d call of JSON", got, c.sets)
			}
			switch c.reply {
			case "continue":
				expectVerdict(t, rep, 1, 1, 1, false)
			case "block":
				expectVerdict(t, rep, 1, 1, 1, true)
			default:
				expectError(t, rep, 1, 1, classTxFailed, codeIncomplete)
			}
			if v := f.violations(); len(v) != 0 {
				t.Errorf("findings %q", v)
			}
		})
	}
}

// A ctl of the operator in phase 1 replaces the processor before begin sets
// JSON, and one in phase 2 is refused by Coraza: neither stops the JSON
// processor, so the rule on the argument still matches.
func TestRealJSONProcessorNotReplaced(t *testing.T) {
	ctl := func(phase, v string) string {
		return `SecRule REQUEST_METHOD "@streq POST" "id:1,phase:` + phase + `,pass,nolog,ctl:requestBodyProcessor=` + v + `"` + "\n"
	}
	force := `SecRule REQUEST_METHOD "@streq POST" "id:2,phase:1,pass,nolog,ctl:forceRequestBodyVariable=On"` + "\n"
	for name, rules := range map[string]string{
		"phase 1 URLENCODED":       ctl("1", "URLENCODED"),
		"phase 1 empty and forced": ctl("1", "") + force,
		"phase 2 URLENCODED":       ctl("2", "URLENCODED"),
	} {
		t.Run(name, func(t *testing.T) {
			o, msg := bodyReply(t, jsonProbeRule+rules, jsonHeaders("application/json"), jsonBody("block"))
			expectRule(t, o, msg, 9203)
		})
	}
}

// What the JSON processor and the reserved rules do with a body, at the
// boundaries: a nesting depth of 64 containers passes (and is read to the
// innermost value) and 65 is a body error (rule 4000001), whatever depth limit
// the operator asks for; a body that is not JSON is a body error; 1000 scalars
// pass and 1001 are too many arguments (rule 4000002).
func TestRealJSONBodyLimits(t *testing.T) {
	scalars := func(n int) string { return "[" + strings.Repeat("1,", n-1) + "1]" }
	for _, c := range []struct {
		name, rules, body string
		rule              int64
	}{
		{"depth 64 is read to the innermost value", jsonAnyRule, nestedJSON(64, "block"), 9204},
		{"depth 65", jsonAnyRule, nestedJSON(65, "fine"), 4000001},
		{"operator limit 1024, depth 65", "SecRequestBodyJsonDepthLimit 1024\n", nestedJSON(65, "fine"), 4000001},
		{"truncated", "", `{"probe":`, 4000001},
		{"UTF-16 with a byte order mark", "", "\xff\xfe{\x00\"\x00a\x00\"\x00:\x001\x00}\x00", 4000001},
		{"1000 scalars", "", scalars(1000), 0},
		{"1001 scalars", "", scalars(1001), 4000002},
	} {
		t.Run(c.name, func(t *testing.T) {
			o, msg := bodyReply(t, bigBody+c.rules, jsonHeaders("application/json"), c.body)
			expectRule(t, o, msg, c.rule)
		})
	}
	t.Run("structured suffix selects JSON", func(t *testing.T) {
		o, msg := bodyReply(t, jsonProbeRule, jsonHeaders("application/vnd.api+json"), jsonBody("block"))
		expectRule(t, o, msg, 9203)
	})
}
