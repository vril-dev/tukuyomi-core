package main

import (
	"errors"
	"os"
	"path/filepath"
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
	if o.cerr != 0 {
		t.Fatal("close error reported")
	}
	h.waitOwners()
	f := h.fake(1)
	if f.count("phase2") != 1 || f.count("logging") != 1 || f.count("close") != 1 || f.count("write") != 0 {
		t.Fatalf("calls %v", f.calls)
	}
	if got := strings.Join(f.calls[:5], ","); got != "conn,uri,reqhdr,reqhdr,server" {
		t.Fatalf("call order %s", got)
	}
	if f.serverNames[0] != "example.test" {
		t.Fatalf("server name %q", f.serverNames)
	}
	s, c, ce, _, _ := h.tab.counts()
	if s != 1 || c != 1 || ce != 0 {
		t.Fatalf("counts %d %d %d", s, c, ce)
	}
}

func TestBodyFlowAndDeclaredChecks(t *testing.T) {
	h := newHarness(t, nil)
	h.in(kindTxBegin, 1, 1, defaultBegin(5).payload())
	expectVerdict(t, h.cap.next(t), 1, 1, 1, false)
	h.in(kindBody, 1, 2, []byte("a=b"))
	h.in(kindBody, 1, 3, []byte("&c"))
	h.in(kindBodyEnd, 1, 4, nil)
	expectVerdict(t, h.cap.next(t), 1, 4, 2, false)
	h.in(kindTxEnd, 1, 5, []byte{endComplete})
	expect(t, h.cap.next(t), kindClosed, 1, 5)
	h.waitOwners()
	if f := h.fake(1); f.count("write") != 2 || f.count("reqaccess") != 4 { // the two Continue checks, first BODY and BODY_END
		t.Fatalf("calls %v", f.calls)
	}

	// More than declared: rejected before Coraza sees the bytes.
	h = newHarness(t, nil)
	h.in(kindTxBegin, 2, 1, defaultBegin(3).payload())
	h.cap.next(t)
	h.in(kindBody, 2, 2, []byte("abcd"))
	expectError(t, h.cap.next(t), 2, 2, classTxFailed, codeReqOver)
	h.in(kindBodyEnd, 2, 3, nil) // failed: counted, no reply
	h.in(kindTxEnd, 2, 4, []byte{endUninspectable})
	expect(t, h.cap.next(t), kindClosed, 2, 4)
	h.waitOwners()
	if f := h.fake(2); f.count("write") != 0 || f.count("phase2") != 0 || f.count("close") != 1 {
		t.Fatalf("calls %v", f.calls)
	}

	// Body when 0 was declared.
	h = newHarness(t, nil)
	h.in(kindTxBegin, 3, 1, defaultBegin(0).payload())
	h.cap.next(t)
	h.in(kindBody, 3, 2, []byte("x"))
	expectError(t, h.cap.next(t), 3, 2, classTxFailed, codeReqOver)

	// Truncated: BODY_END before the declared bytes.
	h = newHarness(t, nil)
	h.in(kindTxBegin, 4, 1, defaultBegin(5).payload())
	h.cap.next(t)
	h.in(kindBody, 4, 2, []byte("abcd"))
	h.in(kindBodyEnd, 4, 3, nil)
	expectError(t, h.cap.next(t), 4, 3, classTxFailed, codeReqTruncated)
	if f := h.fake(4); f.count("phase2") != 0 {
		t.Fatal("phase 2 ran on a truncated body")
	}

	// Empty BODY.
	h = newHarness(t, nil)
	h.in(kindTxBegin, 5, 1, defaultBegin(5).payload())
	h.cap.next(t)
	h.in(kindBody, 5, 2, nil)
	expectError(t, h.cap.next(t), 5, 2, classTxFailed, codeBadContent)
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
	// No access at the phase 1 check: ERROR, even with nothing declared.
	h = newHarness(t, func(string) *fakeTx { return &fakeTx{reqAccess: false} })
	h.in(kindTxBegin, 2, 1, defaultBegin(0).payload())
	expectError(t, h.cap.next(t), 2, 1, classTxFailed, codeIncomplete)
	h.in(kindBodyEnd, 2, 2, nil) // failed: counted, no reply
	if f := h.fake(2); f.count("phase2") != 0 {
		t.Fatal("phase 2 ran after the ERROR")
	}
}

func TestWriteOutcomes(t *testing.T) {
	boom := errors.New("boom")
	cases := []struct {
		name  string
		write func(b []byte) (*types.Interruption, int, error)
		check func(t *testing.T, o out)
	}{
		{"interruption", func(b []byte) (*types.Interruption, int, error) { return blockIt(0, 413), 0, nil },
			func(t *testing.T, o out) {
				expectVerdict(t, o, 1, 2, 2, true)
				if o.rule != 0 || o.stat != 413 || o.act != "deny" {
					t.Fatalf("%+v", o)
				}
			}},
		{"interruption with error", func(b []byte) (*types.Interruption, int, error) { return blockIt(7, 403), 0, boom },
			func(t *testing.T, o out) { expectVerdict(t, o, 1, 2, 2, true) }},
		{"error", func(b []byte) (*types.Interruption, int, error) { return nil, 0, boom },
			func(t *testing.T, o out) { expectError(t, o, 1, 2, classTxFailed, codeReqWrite) }},
		{"short", func(b []byte) (*types.Interruption, int, error) { return nil, len(b) - 1, nil },
			func(t *testing.T, o out) { expectError(t, o, 1, 2, classTxFailed, codeReqShort) }},
		{"bad status", func(b []byte) (*types.Interruption, int, error) { return blockIt(1, 70000), 0, nil },
			func(t *testing.T, o out) { expectError(t, o, 1, 2, classTxFailed, codeBadVerdict) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, func(string) *fakeTx { return &fakeTx{reqAccess: true, write: c.write} })
			h.in(kindTxBegin, 1, 1, defaultBegin(10).payload())
			h.cap.next(t)
			h.in(kindBody, 1, 2, []byte("abcde"))
			c.check(t, h.cap.next(t))
			h.in(kindBody, 1, 3, []byte("fghij")) // blocked: discarded; failed: discarded
			h.in(kindBodyEnd, 1, 4, nil)
			h.cap.none(t, 50*time.Millisecond)
			h.in(kindTxEnd, 1, 5, []byte{endBlocked})
			expect(t, h.cap.next(t), kindClosed, 1, 5)
			h.waitOwners()
			if f := h.fake(1); f.count("write") != 1 || f.count("phase2") != 0 || f.count("close") != 1 {
				t.Fatalf("calls %v", f.calls)
			}
		})
	}
}

func TestProcessRequestBodyOutcomes(t *testing.T) {
	h := newHarness(t, func(string) *fakeTx {
		return &fakeTx{reqAccess: true, reqBody: func() (*types.Interruption, error) { return nil, errors.New("x") }}
	})
	h.in(kindTxBegin, 1, 1, defaultBegin(0).payload())
	h.cap.next(t)
	h.in(kindBodyEnd, 1, 2, nil)
	expectError(t, h.cap.next(t), 1, 2, classTxFailed, codeReqProcess)

	h = newHarness(t, func(string) *fakeTx {
		return &fakeTx{reqAccess: true, reqBody: func() (*types.Interruption, error) { return blockIt(1021, 403), nil }}
	})
	h.in(kindTxBegin, 1, 1, defaultBegin(0).payload())
	h.cap.next(t)
	h.in(kindBodyEnd, 1, 2, nil)
	o := h.cap.next(t)
	expectVerdict(t, o, 1, 2, 2, true)
	if o.rule != 1021 || o.stat != 403 || o.data != "d" {
		t.Fatalf("%+v", o)
	}
}

func TestPhase1BlockAndCloseError(t *testing.T) {
	h := newHarness(t, func(string) *fakeTx {
		return &fakeTx{phase1: blockIt(1001, 403), closeErr: errors.New("rm failed")}
	})
	h.in(kindTxBegin, 1, 1, defaultBegin(5).payload())
	o := h.cap.next(t)
	expectVerdict(t, o, 1, 1, 1, true)
	if o.rule != 1001 {
		t.Fatalf("%+v", o)
	}
	h.in(kindBody, 1, 2, []byte("abcde")) // in flight when blocked: counted
	h.in(kindBodyEnd, 1, 3, nil)
	h.cap.none(t, 50*time.Millisecond)
	h.in(kindTxEnd, 1, 4, []byte{endBlocked})
	o = h.cap.next(t)
	expect(t, o, kindClosed, 1, 4)
	if o.cerr != 1 {
		t.Fatal("close error not reported")
	}
	h.waitOwners()
	if f := h.fake(1); f.count("write") != 0 || f.count("reqaccess") != 0 {
		t.Fatalf("calls %v", f.calls)
	}
	if _, _, ce, disc, _ := h.tab.counts(); ce != 1 || disc != 2 {
		t.Fatalf("close errors %d discarded %d", ce, disc)
	}
}

func TestMessageNumberGap(t *testing.T) {
	h := newHarness(t, nil)
	h.in(kindTxBegin, 1, 1, defaultBegin(5).payload())
	h.cap.next(t)
	h.in(kindBody, 1, 3, []byte("abcde"))
	expectError(t, h.cap.next(t), 1, 3, classTxFailed, codeOrder)
	if f := h.fake(1); f.count("write") != 0 {
		t.Fatal("gapped frame reached Coraza")
	}
	h = newHarness(t, nil)
	h.in(kindTxBegin, 1, 1, defaultBegin(5).payload())
	h.cap.next(t)
	h.in(kindBody, 1, 2, []byte("ab"))
	h.in(kindBody, 1, 2, []byte("cd")) // duplicate number
	expectError(t, h.cap.next(t), 1, 2, classTxFailed, codeOrder)
}

// stateRow drives a fresh transaction to one transaction state. decl is the
// declared length that the row leaves open: the request body of "headers" and
// "body", the response body of "response"; other rows ignore it.
type stateRow struct {
	name  string
	setup func(t *testing.T, h *harness, decl uint64) uint32 // returns the last used msg number
}

func stateRows() []stateRow {
	cont := func(t *testing.T, h *harness, n int) { // consume n continue verdicts
		t.Helper()
		for range n {
			if o := h.cap.next(t); o.kind != kindVerdict || o.block {
				t.Fatalf("setup: unexpected %+v", o)
			}
		}
	}
	return []stateRow{
		{"headers", func(t *testing.T, h *harness, decl uint64) uint32 {
			h.in(kindTxBegin, 1, 1, defaultBegin(decl).payload())
			cont(t, h, 1)
			return 1
		}},
		{"body", func(t *testing.T, h *harness, decl uint64) uint32 {
			h.in(kindTxBegin, 1, 1, defaultBegin(decl).payload())
			cont(t, h, 1)
			h.in(kindBody, 1, 2, []byte("ab"))
			waitUntil(t, "BODY #1 in Coraza", func() bool { return h.fake(1).count("write") == 1 })
			return 2
		}},
		{"request done", func(t *testing.T, h *harness, _ uint64) uint32 {
			h.in(kindTxBegin, 1, 1, defaultBegin(0).payload())
			h.in(kindBodyEnd, 1, 2, nil)
			cont(t, h, 2)
			return 2
		}},
		{"response", func(t *testing.T, h *harness, decl uint64) uint32 {
			h.in(kindTxBegin, 1, 1, defaultBegin(0).payload())
			h.in(kindBodyEnd, 1, 2, nil)
			h.in(kindRespBegin, 1, 3, respPayload(200, "HTTP/1.1", decl, nil))
			cont(t, h, 3)
			return 3
		}},
		{"response done", func(t *testing.T, h *harness, _ uint64) uint32 {
			h.in(kindTxBegin, 1, 1, defaultBegin(0).payload())
			h.in(kindBodyEnd, 1, 2, nil)
			h.in(kindRespBegin, 1, 3, respPayload(200, "HTTP/1.1", 0, nil))
			h.in(kindRespEnd, 1, 4, nil)
			cont(t, h, 4)
			return 4
		}},
		{"blocked request", func(t *testing.T, h *harness, _ uint64) uint32 {
			h.in(kindTxBegin, 1, 1, defaultBegin(4).payload())
			if o := h.cap.next(t); !o.block {
				t.Fatal("setup: no block")
			}
			return 1
		}},
		{"blocked resp", func(t *testing.T, h *harness, _ uint64) uint32 {
			h.in(kindTxBegin, 1, 1, defaultBegin(0).payload())
			h.in(kindBodyEnd, 1, 2, nil)
			h.in(kindRespBegin, 1, 3, respPayload(200, "HTTP/1.1", 0, nil))
			h.cap.next(t)
			h.cap.next(t)
			if o := h.cap.next(t); !o.block || o.phase != 3 {
				t.Fatal("setup: no response block")
			}
			return 3
		}},
		{"failed", func(t *testing.T, h *harness, _ uint64) uint32 {
			h.in(kindTxBegin, 1, 1, defaultBegin(4).payload())
			h.cap.next(t)
			h.in(kindBody, 1, 2, nil) // empty BODY: ERROR 17
			if o := h.cap.next(t); o.kind != kindError {
				t.Fatal("setup: no error")
			}
			return 2
		}},
	}
}

// TestStateFrameMatrix checks every queued frame kind in every reachable state
// (with the blocked state split into request and response). Each cell is
// decided by what the owner did, not by a silent period: ERROR 16 with the
// frame's msg; or, for a handled frame, its exact reply (or, without a reply,
// the Coraza call that was waited for); or, for a dropped frame, the discard
// counter and no Coraza call. TX_END is sent only after that, so it cannot
// pre-empt the frame, and the first reply to it must be CLOSED.
func TestStateFrameMatrix(t *testing.T) {
	const (
		process = "process" // handled by Coraza
		errOrd  = "error16"
		drop    = "drop"
	)
	kinds := []struct {
		name    string
		kind    uint8
		payload []byte
	}{
		{"TX_BEGIN", kindTxBegin, defaultBegin(0).payload()},
		{"BODY", kindBody, []byte("ab")},
		{"BODY_END", kindBodyEnd, nil},
		{"RESP_BEGIN", kindRespBegin, respPayload(200, "HTTP/1.1", 4, nil)},
		{"RESP_BODY", kindRespBody, []byte("ab")},
		{"RESP_END", kindRespEnd, nil},
	}
	want := map[string][6]string{
		// TX_BEGIN, BODY, BODY_END, RESP_BEGIN, RESP_BODY, RESP_END
		"headers":         {errOrd, process, process, errOrd, errOrd, errOrd},
		"body":            {errOrd, process, process, errOrd, errOrd, errOrd},
		"request done":    {errOrd, errOrd, errOrd, process, errOrd, errOrd},
		"response":        {errOrd, errOrd, errOrd, errOrd, process, process},
		"response done":   {errOrd, errOrd, errOrd, errOrd, errOrd, errOrd},
		"blocked request": {errOrd, drop, drop, errOrd, errOrd, errOrd},
		"blocked resp":    {errOrd, errOrd, errOrd, errOrd, drop, drop},
		"failed":          {drop, drop, drop, drop, drop, drop},
	}
	// The declared length that lets the cell succeed (default 4: BODY "ab"
	// twice, RESP_BODY "ab"); an end frame needs exactly what was sent.
	declFor := map[string]uint64{"headers/BODY_END": 0, "body/BODY_END": 2, "response/RESP_END": 0}
	for _, r := range stateRows() {
		for i, k := range kinds {
			t.Run(r.name+"/"+k.name, func(t *testing.T) {
				mk := func(string) *fakeTx { return &fakeTx{reqAccess: true, respAccess: true, respProc: true} }
				switch r.name {
				case "blocked request":
					mk = func(string) *fakeTx { return &fakeTx{phase1: blockIt(1, 403), reqAccess: true} }
				case "blocked resp":
					mk = func(string) *fakeTx { return &fakeTx{reqAccess: true, phase3: blockIt(2, 403)} }
				}
				decl, ok := declFor[r.name+"/"+k.name]
				if !ok {
					decl = 4
				}
				h := newHarness(t, mk)
				last := r.setup(t, h, decl)
				f := h.fake(1)
				d0, before := h.discarded(), f.trace() // the setup is settled here
				wantDisc := d0
				h.in(k.kind, 1, last+1, k.payload)
				switch want[r.name][i] {
				case errOrd:
					expectError(t, h.cap.next(t), 1, last+1, classTxFailed, codeOrder)
					if f.trace() != before {
						t.Fatalf("Coraza called for an out-of-order frame: %s -> %s", before, f.trace())
					}
				case drop:
					waitUntil(t, "the frame to be discarded", func() bool { return h.discarded() > d0 })
					if f.trace() != before {
						t.Fatalf("Coraza called for a dropped frame: %s -> %s", before, f.trace())
					}
					wantDisc = d0 + 1
				case process:
					switch k.kind {
					case kindBody: // no reply; wait until the owner is inside Coraza with it
						n := 1
						if r.name == "body" {
							n = 2
						}
						waitUntil(t, "BODY in Coraza", func() bool { return f.count("write") == n })
						if f.count("reqaccess") != 2 { // the phase 1 check and the first BODY
							t.Fatalf("calls %s", f.trace())
						}
					case kindBodyEnd:
						expectVerdict(t, h.cap.next(t), 1, last+1, 2, false)
						writes := 0 // the BODY of the setup, if any
						if r.name == "body" {
							writes = 1
						}
						if f.count("phase2") != 1 || f.count("write") != writes {
							t.Fatalf("calls %s", f.trace())
						}
					case kindRespBegin:
						expectVerdict(t, h.cap.next(t), 1, last+1, 3, false)
						if f.count("phase3") != 1 || f.count("write") != 0 || f.count("writeresp") != 0 {
							t.Fatalf("calls %s", f.trace())
						}
					case kindRespBody:
						waitUntil(t, "RESP_BODY in Coraza", func() bool { return f.count("writeresp") == 1 })
					case kindRespEnd:
						expectVerdict(t, h.cap.next(t), 1, last+1, 4, false)
						if f.count("phase4") != 1 || f.count("writeresp") != 0 {
							t.Fatalf("calls %s", f.trace())
						}
					default:
						t.Fatalf("no expectation for %s", k.name)
					}
				}
				h.in(kindTxEnd, 1, last+2, []byte{endComplete})
				o := h.cap.next(t)
				expect(t, o, kindClosed, 1, last+2)
				if o.cerr != 0 {
					t.Fatal("close error reported")
				}
				h.waitOwners()
				if got := h.discarded(); got != wantDisc {
					t.Fatalf("discarded %d, want %d", got, wantDisc)
				}
				if n := len(h.cap.ch); n != 0 {
					t.Fatalf("%d more outbound frames after CLOSED", n)
				}
				if f.count("close") != 1 || f.count("logging") != 1 {
					t.Fatalf("close/logging %d/%d", f.count("close"), f.count("logging"))
				}
				if want[r.name][i] != process && f.trace() != before+",logging,close" {
					t.Fatalf("calls after the close: %s -> %s", before, f.trace())
				}
			})
		}
	}
}

func TestResponseFlow(t *testing.T) {
	h := newHarness(t, nil)
	h.in(kindTxBegin, 1, 1, defaultBegin(0).payload())
	h.in(kindBodyEnd, 1, 2, nil)
	h.cap.next(t)
	h.cap.next(t)
	h.in(kindRespBegin, 1, 3, respPayload(200, "HTTP/1.1", 5, [][2]string{{"Content-Type", "text/plain"}}))
	expectVerdict(t, h.cap.next(t), 1, 3, 3, false)
	h.in(kindRespBody, 1, 4, []byte("abc"))
	h.in(kindRespBody, 1, 5, []byte("de"))
	h.in(kindRespEnd, 1, 6, nil)
	expectVerdict(t, h.cap.next(t), 1, 6, 4, false)
	h.in(kindTxEnd, 1, 7, []byte{endComplete})
	expect(t, h.cap.next(t), kindClosed, 1, 7)

	cases := []struct {
		name string
		mk   func(string) *fakeTx
		body []byte
		decl uint64
		want func(t *testing.T, o out)
	}{
		{"not accessible", func(string) *fakeTx { return &fakeTx{reqAccess: true, respAccess: false, respProc: true} }, []byte("ab"), 2,
			func(t *testing.T, o out) { expectError(t, o, 1, 4, classTxFailed, codeRespNotInspect) }},
		{"not processable", func(string) *fakeTx { return &fakeTx{reqAccess: true, respAccess: true, respProc: false} }, []byte("ab"), 2,
			func(t *testing.T, o out) { expectError(t, o, 1, 4, classTxFailed, codeRespNotInspect) }},
		{"over declared", nil, []byte("abc"), 2,
			func(t *testing.T, o out) { expectError(t, o, 1, 4, classTxFailed, codeRespOver) }},
		{"write block", func(string) *fakeTx {
			return &fakeTx{reqAccess: true, respAccess: true, respProc: true,
				writeResp: func(b []byte) (*types.Interruption, int, error) { return blockIt(1040, 403), 0, nil }}
		}, []byte("ab"), 4, func(t *testing.T, o out) { expectVerdict(t, o, 1, 4, 4, true) }},
		{"write short", func(string) *fakeTx {
			return &fakeTx{reqAccess: true, respAccess: true, respProc: true,
				writeResp: func(b []byte) (*types.Interruption, int, error) { return nil, 1, nil }}
		}, []byte("ab"), 4, func(t *testing.T, o out) { expectError(t, o, 1, 4, classTxFailed, codeRespShort) }},
		{"write error", func(string) *fakeTx {
			return &fakeTx{reqAccess: true, respAccess: true, respProc: true,
				writeResp: func(b []byte) (*types.Interruption, int, error) { return nil, 0, errors.New("x") }}
		}, []byte("ab"), 4, func(t *testing.T, o out) { expectError(t, o, 1, 4, classTxFailed, codeRespWrite) }},
		{"empty", nil, []byte{}, 2, func(t *testing.T, o out) { expectError(t, o, 1, 4, classTxFailed, codeBadContent) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, c.mk)
			h.in(kindTxBegin, 1, 1, defaultBegin(0).payload())
			h.in(kindBodyEnd, 1, 2, nil)
			h.in(kindRespBegin, 1, 3, respPayload(200, "HTTP/1.1", c.decl, nil))
			for range 3 {
				h.cap.next(t)
			}
			h.in(kindRespBody, 1, 4, c.body)
			c.want(t, h.cap.next(t))
		})
	}
	// Truncated response and RESP_END with a declared body that is not inspectable.
	h = newHarness(t, nil)
	h.in(kindTxBegin, 1, 1, defaultBegin(0).payload())
	h.in(kindBodyEnd, 1, 2, nil)
	h.in(kindRespBegin, 1, 3, respPayload(200, "HTTP/1.1", 3, nil))
	for range 3 {
		h.cap.next(t)
	}
	h.in(kindRespBody, 1, 4, []byte("ab"))
	h.in(kindRespEnd, 1, 5, nil)
	expectError(t, h.cap.next(t), 1, 5, classTxFailed, codeRespTruncated)

	h = newHarness(t, func(string) *fakeTx { return &fakeTx{reqAccess: true, respAccess: true, respProc: false} })
	h.in(kindTxBegin, 1, 1, defaultBegin(0).payload())
	h.in(kindBodyEnd, 1, 2, nil)
	h.in(kindRespBegin, 1, 3, respPayload(200, "HTTP/1.1", 0, nil))
	h.in(kindRespEnd, 1, 4, nil)
	for range 3 {
		h.cap.next(t)
	}
	expectVerdict(t, h.cap.next(t), 1, 4, 4, false) // nothing declared: phase 4 runs

	h = newHarness(t, nil)
	h.in(kindTxBegin, 1, 1, defaultBegin(0).payload())
	h.in(kindBodyEnd, 1, 2, nil)
	h.in(kindRespBegin, 1, 3, []byte{0, 99}) // bad status, truncated
	h.cap.next(t)
	h.cap.next(t)
	expectError(t, h.cap.next(t), 1, 3, classTxFailed, codeBadContent)
}

// gatedWrite lets a test hold the owner inside WriteRequestBody.
func gatedWrite(entered chan<- struct{}, release <-chan struct{}) func(string) *fakeTx {
	return func(string) *fakeTx {
		first := true
		return &fakeTx{reqAccess: true, write: func(b []byte) (*types.Interruption, int, error) {
			if first {
				first = false
				entered <- struct{}{}
				<-release
			}
			return nil, len(b), nil
		}}
	}
}

func TestOverflowCheckedBeforeDequeue(t *testing.T) {
	entered, release := make(chan struct{}, 1), make(chan struct{})
	h := newHarness(t, gatedWrite(entered, release))
	rel := sync.OnceFunc(func() { close(release) })
	t.Cleanup(rel) // runs before the harness check, so a failed test cannot hold the owner
	h.in(kindTxBegin, 1, 1, defaultBegin(100).payload())
	h.cap.next(t)
	h.in(kindBody, 1, 2, []byte("a"))
	recvWithin(t, entered, "BODY #1 in Coraza") // the owner holds BODY #1 inside Coraza
	for i := range queueDepth {
		h.in(kindBody, 1, uint32(3+i), []byte("b")) // 17 queued: full
	}
	h.in(kindBody, 1, 20, []byte("c")) // 18th: overflow mark
	rel()
	expectError(t, h.cap.next(t), 1, 20, classTxFailed, codeOverflow)
	h.in(kindBody, 1, 21, []byte("d")) // after overflow: discarded
	h.in(kindTxEnd, 1, 22, []byte{endUninspectable})
	expect(t, h.cap.next(t), kindClosed, 1, 22)
	h.waitOwners()
	if f := h.fake(1); f.count("write") != 1 || f.count("phase2") != 0 || f.count("close") != 1 {
		t.Fatalf("queued frames reached Coraza: %v", f.calls)
	}
	if _, _, _, disc, _ := h.tab.counts(); disc != 19 { // 17 queued + overflowing + after
		t.Fatalf("discarded %d", disc)
	}
}

// TestTxEndIsNotQueued: the queue is full, the overflow mark is set, and
// TX_END still lands; the owner must see the close mark first, so the first
// reply is CLOSED and the overflow is not reported (Rust has decided already).
func TestTxEndIsNotQueued(t *testing.T) {
	entered, release := make(chan struct{}, 1), make(chan struct{})
	h := newHarness(t, gatedWrite(entered, release))
	rel := sync.OnceFunc(func() { close(release) })
	t.Cleanup(rel) // runs before the harness check, so a failed test cannot hold the owner
	h.in(kindTxBegin, 1, 1, defaultBegin(100).payload())
	h.cap.next(t)
	h.in(kindBody, 1, 2, []byte("a"))
	recvWithin(t, entered, "BODY #1 in Coraza") // the owner holds BODY #1 inside Coraza
	for i := range queueDepth {
		h.in(kindBody, 1, uint32(3+i), []byte("b")) // 17 queued: full
	}
	over := uint32(3 + queueDepth)       // msg of the 18th BODY
	h.in(kindBody, 1, over, []byte("c")) // 18th: overflow mark, counted by the reader
	if d := h.discarded(); d != 1 {      // the owner is still inside Coraza: only the reader has counted
		t.Fatalf("discarded %d after the overflow, want 1", d)
	}
	h.in(kindTxEnd, 1, over+1, []byte{endDisconnect}) // close mark on top of the overflow mark
	rel()
	o := h.cap.next(t)
	if o.kind == kindError {
		t.Fatalf("overflow ERROR code %d msg %d before CLOSED", o.code, o.msg)
	}
	expect(t, o, kindClosed, 1, over+1)
	if o.cerr != 0 {
		t.Fatal("close error reported")
	}
	h.waitOwners()
	if f := h.fake(1); f.count("write") != 1 || f.count("close") != 1 || f.count("logging") != 1 {
		t.Fatalf("calls %v", f.calls)
	}
	if d := h.discarded(); d != 18 { // 17 queued frames dropped at the close mark + the overflowing frame
		t.Fatalf("discarded %d, want 18", d)
	}
	h.in(kindTxEnd, 1, over+2, []byte{endDisconnect}) // after the close: counted only
	if d := h.discarded(); d != 19 {
		t.Fatalf("discarded %d, want 19", d)
	}
	if n := len(h.cap.ch); n != 0 {
		t.Fatalf("%d more outbound frames", n)
	}
}

// A second TX_END that lands after the close mark and before the owner hands
// over CLOSED is not queued and not answered; the reader only counts it.
func TestSecondTxEndWhileClosingIsCounted(t *testing.T) {
	entered, release := make(chan struct{}, 1), make(chan struct{})
	h := newHarness(t, gatedWrite(entered, release))
	rel := sync.OnceFunc(func() { close(release) })
	t.Cleanup(rel) // runs before the harness check, so a failed test cannot hold the owner
	h.in(kindTxBegin, 1, 1, defaultBegin(100).payload())
	h.cap.next(t)
	h.in(kindBody, 1, 2, []byte("a"))
	recvWithin(t, entered, "BODY in Coraza")     // the owner holds BODY inside Coraza
	h.in(kindTxEnd, 1, 3, []byte{endDisconnect}) // close mark; the owner has not taken it yet
	if d := h.discarded(); d != 0 {
		t.Fatalf("discarded %d after the first TX_END, want 0", d)
	}
	h.in(kindTxEnd, 1, 4, []byte{endDisconnect}) // second TX_END while closing
	if d := h.discarded(); d != 1 {
		t.Fatalf("discarded %d after the second TX_END, want 1", d)
	}
	rel()
	o := h.cap.next(t)
	expect(t, o, kindClosed, 1, 3) // answers the first TX_END only
	if o.cerr != 0 {
		t.Fatal("close error reported")
	}
	h.waitOwners()
	if f := h.fake(1); f.count("write") != 1 || f.count("close") != 1 || f.count("logging") != 1 {
		t.Fatalf("calls %s", f.trace())
	}
	if d := h.discarded(); d != 1 {
		t.Fatalf("discarded %d, want 1", d)
	}
	if n := len(h.cap.ch); n != 0 {
		t.Fatalf("%d more outbound frames", n)
	}
}

func TestCloseBeforeBeginProcessed(t *testing.T) {
	gate := make(chan struct{})
	h := newHarness(t, func(string) *fakeTx { return &fakeTx{hdrGate: gate, reqAccess: true} })
	h.in(kindTxBegin, 1, 1, defaultBegin(0).payload())
	h.in(kindTxEnd, 1, 2, []byte{endDisconnect})
	close(gate)
	expectVerdict(t, h.cap.next(t), 1, 1, 1, false) // TX_BEGIN processed first
	expect(t, h.cap.next(t), kindClosed, 1, 2)
	h.waitOwners()
	if f := h.fake(1); f.count("close") != 1 {
		t.Fatal("close count")
	}
}

func TestNotCreatedAndMaxID(t *testing.T) {
	h := newHarness(t, nil)
	for id := uint64(1); id <= maxConcurTx; id++ {
		h.in(kindTxBegin, id, 1, defaultBegin(0).payload())
		h.cap.next(t)
	}
	h.in(kindTxBegin, 5, 1, defaultBegin(0).payload())
	expectError(t, h.cap.next(t), 5, 1, classNotCreated, codeLimit)
	h.in(kindTxBegin, 5, 1, defaultBegin(0).payload()) // id 5 used: counted only
	h.in(kindBody, 5, 2, []byte("x"))
	h.cap.none(t, 30*time.Millisecond)
	h.in(kindBody, 9, 2, []byte("x")) // unstarted id: advances max
	expectError(t, h.cap.next(t), 9, 2, classNotCreated, codeUnstarted)
	h.in(kindTxBegin, 8, 1, defaultBegin(0).payload()) // below max: counted only
	h.in(kindTxBegin, 9, 1, defaultBegin(0).payload())
	h.cap.none(t, 30*time.Millisecond)
	h.in(kindTxEnd, 10, 1, []byte{endComplete})
	expectError(t, h.cap.next(t), 10, 1, classNotCreated, codeUnstarted)

	h.in(kindTxEnd, 1, 2, []byte{endComplete})
	expect(t, h.cap.next(t), kindClosed, 1, 2)
	h.in(kindTxBegin, 11, 2, defaultBegin(0).payload())
	expectError(t, h.cap.next(t), 11, 2, classNotCreated, codeBadBegin)
	bad := defaultBegin(0).payload()
	h.in(kindTxBegin, 12, 1, bad[:len(bad)-1])
	expectError(t, h.cap.next(t), 12, 1, classNotCreated, codeBadBegin)
	h.in(kindBody, 1, 3, []byte("x")) // closed id: counted only
	h.cap.none(t, 30*time.Millisecond)

	if !h.tab.startDrain() || h.tab.startDrain() {
		t.Fatal("startDrain")
	}
	h.in(kindTxBegin, 13, 1, defaultBegin(0).payload())
	expectError(t, h.cap.next(t), 13, 1, classNotCreated, codeDraining)
	h.in(kindTxBegin, 2, 1, defaultBegin(0).payload()) // active id while draining: duplicate
	expectError(t, h.cap.next(t), 2, 1, classTxFailed, codeOrder)
	s, _, _, _, _ := h.tab.counts()
	if s != 4 {
		t.Fatalf("started %d", s)
	}
}

func TestBadTxEndStillCloses(t *testing.T) {
	h := newHarness(t, nil)
	h.in(kindTxBegin, 1, 1, defaultBegin(0).payload())
	h.cap.next(t)
	h.in(kindTxEnd, 1, 2, []byte{9})
	expect(t, h.cap.next(t), kindClosed, 1, 2)
	if _, _, _, _, bad := h.tab.counts(); bad != 1 {
		t.Fatalf("bad tx_end %d", bad)
	}
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
	h.in(kindTxBegin, 4, 1, defaultBegin(0).payload()) // after loss: ignored
	h.cap.none(t, 30*time.Millisecond)
	if s, c, _, _, _ := h.tab.counts(); s != 3 || c != 3 {
		t.Fatalf("counts %d %d", s, c)
	}
}

func TestDeclaredOverrunAccumulates(t *testing.T) {
	// 3 + 3 bytes against a declared 5: the second frame is refused before
	// Coraza sees it, and the ERROR carries that frame's msg.
	h := newHarness(t, nil)
	h.in(kindTxBegin, 1, 1, defaultBegin(5).payload())
	h.cap.next(t)
	h.in(kindBody, 1, 2, []byte("abc"))
	h.in(kindBody, 1, 3, []byte("def"))
	expectError(t, h.cap.next(t), 1, 3, classTxFailed, codeReqOver)
	if f := h.fake(1); f.count("write") != 1 {
		t.Fatalf("calls %s", f.trace())
	}
	h = newHarness(t, nil)
	h.in(kindTxBegin, 1, 1, defaultBegin(0).payload())
	h.in(kindBodyEnd, 1, 2, nil)
	h.in(kindRespBegin, 1, 3, respPayload(200, "HTTP/1.1", 5, nil))
	for range 3 {
		h.cap.next(t)
	}
	h.in(kindRespBody, 1, 4, []byte("abc"))
	h.in(kindRespBody, 1, 5, []byte("def"))
	expectError(t, h.cap.next(t), 1, 5, classTxFailed, codeRespOver)
	if f := h.fake(1); f.count("writeresp") != 1 {
		t.Fatalf("calls %s", f.trace())
	}
}

func TestOverflowAfterBlockOrFailureIsOnlyCounted(t *testing.T) {
	cases := []struct {
		name  string
		phase *types.Interruption
		check func(t *testing.T, o out)
	}{
		{"blocked", blockIt(1, 403), func(t *testing.T, o out) { expectVerdict(t, o, 1, 1, 1, true) }},
		{"failed", blockIt(1, 70000), func(t *testing.T, o out) { expectError(t, o, 1, 1, classTxFailed, codeBadVerdict) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gate := make(chan struct{})
			open := sync.OnceFunc(func() { close(gate) })
			h := newHarness(t, func(string) *fakeTx { return &fakeTx{phase1: c.phase, hdrGate: gate} })
			t.Cleanup(open) // runs before the harness check
			h.in(kindTxBegin, 1, 1, defaultBegin(100).payload())
			waitUntil(t, "phase 1 in Coraza", func() bool { f := h.fake(1); return f != nil && f.count("phase1") == 1 })
			for i := range queueDepth {
				h.in(kindBody, 1, uint32(2+i), []byte("b")) // 17 queued: full
			}
			h.in(kindBody, 1, 19, []byte("c")) // 18th: overflow mark
			open()
			c.check(t, h.cap.next(t))
			waitUntil(t, "the overflow to be counted", func() bool { return h.discarded() >= 18 }) // 1 by the reader, 17 by the owner
			h.in(kindTxEnd, 1, 20, []byte{endBlocked})
			expect(t, h.cap.next(t), kindClosed, 1, 20) // no ERROR for the overflow
			h.waitOwners()
			if d := h.discarded(); d != 18 { // exactly: the TX_END is not counted
				t.Fatalf("discarded %d, want 18", d)
			}
			if n := len(h.cap.ch); n != 0 {
				t.Fatalf("%d more outbound frames", n)
			}
			if f := h.fake(1); f.count("write") != 0 || f.count("close") != 1 {
				t.Fatalf("calls %s", f.trace())
			}
		})
	}
}

func TestServerNameFromFirstHost(t *testing.T) {
	cases := []struct {
		name string
		hs   [][2]string
		want []string
	}{
		{"name case folded, value kept", [][2]string{{"HoSt", "Example.TEST"}}, []string{"Example.TEST"}},
		{"first of several", [][2]string{{"Host", "a.test"}, {"host", "b.test"}}, []string{"a.test"}},
		{"empty first is not replaced", [][2]string{{"Host", ""}, {"Host", "b.test"}}, nil},
		{"no Host", [][2]string{{"X-A", "y"}}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, nil)
			b := defaultBegin(0)
			b.headers = c.hs
			h.in(kindTxBegin, 1, 1, b.payload())
			expectVerdict(t, h.cap.next(t), 1, 1, 1, false)
			f := h.fake(1)
			f.mu.Lock()
			got := append([]string(nil), f.serverNames...)
			f.mu.Unlock()
			if strings.Join(got, "|") != strings.Join(c.want, "|") || f.count("server") != len(c.want) || f.count("reqhdr") != len(c.hs) {
				t.Fatalf("server names %q, calls %s", got, f.trace())
			}
		})
	}
}

func TestConnLostDuringWrite(t *testing.T) {
	entered, release := make(chan struct{}, 1), make(chan struct{})
	h := newHarness(t, gatedWrite(entered, release))
	rel := sync.OnceFunc(func() { close(release) })
	t.Cleanup(rel) // runs before the harness check
	h.in(kindTxBegin, 1, 1, defaultBegin(100).payload())
	h.cap.next(t)
	h.in(kindBody, 1, 2, []byte("a"))
	recvWithin(t, entered, "BODY #1 in Coraza")
	h.in(kindBody, 1, 3, []byte("b")) // queued behind the held write
	h.tab.connLost()
	rel()
	h.waitOwners()
	if f := h.fake(1); f.count("write") != 1 || f.count("logging") != 1 || f.count("close") != 1 {
		t.Fatalf("calls %s", f.trace())
	}
	if n := len(h.cap.ch); n != 0 { // lost: no CLOSED, nothing else
		t.Fatalf("%d outbound frames after the loss", n)
	}
}

// ---- real Coraza (the pinned tag) ----

func realWAF(t *testing.T, directives string) coraza.WAF {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
	if err != nil {
		t.Fatalf("NewWAF: %v", err)
	}
	return waf
}

// closeCounted counts Close calls on a real transaction.
type closeCounted struct {
	realTx
	mu sync.Mutex
	n  int
}

func (c *closeCounted) Close() error {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	return c.realTx.Close()
}

// realHarness runs the owners on the transactions of the WAF that Coraza
// builds from the directives alone.
func realHarness(t *testing.T, directives string) *harness {
	return harnessFor(t, realWAF(t, directives))
}

// productHarness runs them on the WAF that the inspector builds (newWAF).
func productHarness(t *testing.T, rules string) *harness {
	t.Helper()
	return harnessFor(t, productWAFFor(t, rules))
}

func harnessFor(t *testing.T, waf coraza.WAF) *harness {
	h := &harness{t: t, cap: newCapture(), txs: map[string]*fakeTx{}}
	var mu sync.Mutex
	var made []*closeCounted
	h.tab = newTable(testRun, testInc, func(id string) types.Transaction {
		c := &closeCounted{realTx: waf.NewTransactionWithID(id).(realTx)}
		mu.Lock()
		made = append(made, c)
		mu.Unlock()
		return c
	}, h.cap.send)
	t.Cleanup(func() {
		h.check() // as for a lost connection; every owner must finish
		mu.Lock()
		defer mu.Unlock()
		for i, c := range made {
			c.mu.Lock()
			if c.n != 1 {
				t.Errorf("real tx #%d: Close called %d times", i, c.n)
			}
			c.mu.Unlock()
		}
	})
	return h
}

const baseRules = "SecRuleEngine On\nSecRequestBodyAccess On\nSecRequestBodyLimit 16\nSecRequestBodyInMemoryLimit 8\nSecRequestBodyLimitAction Reject\nSecResponseBodyAccess Off\nSecAuditEngine Off\n"

func TestRealCorazaPhase2WithoutBody(t *testing.T) {
	h := realHarness(t, baseRules+`SecRule REQUEST_METHOD "@streq POST" "id:2,phase:2,deny,status:401"`)
	h.in(kindTxBegin, 1, 1, defaultBegin(0).payload())
	expectVerdict(t, h.cap.next(t), 1, 1, 1, false)
	h.in(kindBodyEnd, 1, 2, nil)
	o := h.cap.next(t)
	expectVerdict(t, o, 1, 2, 2, true)
	if o.rule != 2 || o.stat != 401 || o.act != "deny" {
		t.Fatalf("%+v", o)
	}
	h.in(kindTxEnd, 1, 3, []byte{endBlocked})
	expect(t, h.cap.next(t), kindClosed, 1, 3)
}

func TestRealCorazaBodyLimitBoundary(t *testing.T) {
	// limit 16 (>=): 15 bytes pass, exactly 16 is rejected with rule 0 / 413.
	for _, n := range []int{15, 16, 17} {
		h := realHarness(t, baseRules)
		h.in(kindTxBegin, 1, 1, defaultBegin(uint64(n)).payload())
		h.cap.next(t)
		h.in(kindBody, 1, 2, []byte(strings.Repeat("a", n)))
		h.in(kindBodyEnd, 1, 3, nil)
		o := h.cap.next(t)
		if n < 16 {
			expectVerdict(t, o, 1, 3, 2, false)
		} else {
			expectVerdict(t, o, 1, 2, 2, true)
			if o.rule != 0 || o.stat != 413 || o.act != "deny" {
				t.Fatalf("n=%d %+v", n, o)
			}
		}
		h.in(kindTxEnd, 1, 4, []byte{endComplete})
		for o.kind != kindClosed {
			o = h.cap.next(t)
		}
		h.waitOwners()
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

func TestRealCorazaSpillRemovedOnClose(t *testing.T) {
	h := realHarness(t, baseRules)
	tmp := os.Getenv("TMPDIR")
	h.in(kindTxBegin, 1, 1, defaultBegin(12).payload())
	h.cap.next(t)
	h.in(kindBody, 1, 2, []byte("abcdefghijkl")) // over the 8-byte memory limit
	h.in(kindBodyEnd, 1, 3, nil)
	expectVerdict(t, h.cap.next(t), 1, 3, 2, false)
	if ents, _ := os.ReadDir(tmp); len(ents) == 0 {
		t.Fatal("expected a spill file before Close")
	}
	h.in(kindTxEnd, 1, 4, []byte{endComplete})
	o := h.cap.next(t)
	expect(t, o, kindClosed, 1, 4)
	if o.cerr != 0 {
		t.Fatal("close error")
	}
	h.waitOwners()
	ents, err := os.ReadDir(tmp)
	if err != nil || len(ents) != 0 {
		names := []string{}
		for _, e := range ents {
			names = append(names, filepath.Join(tmp, e.Name()))
		}
		t.Fatalf("left after Close: %v %v", names, err)
	}
}

// ---- reserved directives and requestComplete ----

// flagCase is a request that sets one of the flags that the reserved rules
// test: a URI that does not parse, more arguments than the limit, a multipart
// body that does not parse.
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
	args := defaultBegin(11)
	multipart := defaultBegin(7)
	multipart.headers = [][2]string{{"Host", "example.test"}, {"Content-Type", "multipart/form-data; boundary=xx"}}
	return []flagCase{
		{"uri", "", uri, "", 4000003},
		{"arguments", "SecArgumentsLimit 2\n", args, "a=1&b=2&c=3", 4000002},
		{"body", "", multipart, "garbage", 4000001},
		{"json body", "", jsonBegin(1), "{", 4000001},
		{"json arguments", "SecArgumentsLimit 2\n", jsonBegin(7), "[1,2,3]", 4000002},
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
		"detection only":         "SecRuleEngine DetectionOnly\nSecRequestBodyLimitAction ProcessPartial\n",
		"rule engine off":        "SecRuleEngine Off\n",
		"body access off":        "SecRequestBodyAccess Off\n",
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
	h := productHarness(t, baseRules+settings["detection only"])
	h.in(kindTxBegin, 1, 1, defaultBegin(16).payload())
	expectVerdict(t, h.cap.next(t), 1, 1, 1, false)
	h.in(kindBody, 1, 2, []byte(strings.Repeat("a", 16)))
	o := h.cap.next(t)
	expectVerdict(t, o, 1, 2, 2, true)
	if o.rule != 0 || o.stat != 413 {
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
		if _, err := newWAF(baseRules + rules + "\n"); err == nil {
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
	bypass := map[string]string{
		"skipAfter a missing marker": post + "pass,skipAfter:NOWHERE\"\n",
		"allow":                      post + "allow\"\n",
		"ruleRemoveById":             post + "pass,ctl:ruleRemoveById=4000001-4000003\"\n",
		"ignored duplicate id": "SecIgnoreRuleCompilationErrors On\n" +
			`SecRule REQUEST_METHOD "@streq NOPE" "id:4000001,phase:1,pass"` + "\n" +
			`SecRule REQUEST_METHOD "@streq NOPE" "id:4000002,phase:1,pass"` + "\n" +
			`SecRule REQUEST_METHOD "@streq NOPE" "id:4000003,phase:1,pass"` + "\n",
		"ignored default transformation": "SecIgnoreRuleCompilationErrors On\n" +
			`SecDefaultAction "phase:2,log,pass,t:lowercase"` + "\n",
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
		c := flagCases()[0]
		h := productHarness(t, baseRules+`SecRule REQUEST_METHOD "@streq POST" "id:9,phase:2,deny,status:401"`+"\n")
		o, msg := c.send(t, h)
		expectVerdict(t, o, 1, msg, 2, true)
		if o.rule != 9 || o.stat != 401 {
			t.Fatalf("%+v", o)
		}
	})
}

// requestComplete on the real transaction, with the values the flags have on a
// fresh one, and on the values and types that it must not accept.
func TestRequestComplete(t *testing.T) {
	waf := productWAFFor(t, baseRules)
	tx := waf.NewTransaction()
	defer tx.Close()
	ts := tx.(plugintypes.TransactionState)
	for _, v := range []variables.RuleVariable{variables.ReqbodyError, variables.ArgumentsLimitReached, variables.URIParseError} {
		if g := ts.Collection(v).(collection.Single).Get(); g != "0" {
			t.Fatalf("%s is %q on a fresh transaction", v.Name(), g)
		}
	}
	if g := ts.Collection(variables.ReqbodyProcessor).(collection.Single).Get(); g != "" {
		t.Fatalf("REQBODY_PROCESSOR is %q on a fresh transaction", g)
	}
	if !requestComplete(tx, false, 0, "") || !requestComplete(tx, true, 0, "") || !requestComplete(tx, false, 1, "") {
		t.Fatal("a fresh transaction is not complete")
	}
	if requestComplete(tx, true, 1, "URLENCODED") || requestComplete(tx, true, 1, "") {
		t.Fatal("a request with a body and no body processor is complete")
	}
	tx.ProcessConnection("127.0.0.1", 1, "127.0.0.1", 2)
	tx.ProcessURI("/%zz", "GET", "HTTP/1.1")
	if g := ts.Collection(variables.URIParseError).(collection.Single).Get(); g != "1" {
		t.Fatalf("URI_PARSE_ERROR is %q", g)
	}
	if !requestComplete(tx, false, 0, "") || requestComplete(tx, true, 0, "") {
		t.Fatal("the flags are read before phase 2 only, and a set flag is incomplete")
	}

	// Values: empty and "0" are no flag; "1" and anything else is one.
	for val, want := range map[string]bool{"": true, "0": true, "1": false, "2": false, "x": false, " 0": false, "00": false} {
		f := &fakeTx{reqAccess: true, flags: map[variables.RuleVariable]string{variables.ArgumentsLimitReached: val}}
		if got := requestComplete(f, true, 1, "URLENCODED"); got != want {
			t.Errorf("flag %q: complete %v, want %v", val, got, want)
		}
	}
	if requestComplete(&fakeTx{reqAccess: true, ruleOff: true}, false, 0, "") || requestComplete(&fakeTx{}, false, 0, "") {
		t.Error("rule engine off or no body access is complete")
	}

	// The request body processor is read for a request with a body only, and
	// must be exactly the expected one, which is not empty.
	for _, c := range []struct {
		read, want string
		ok         bool
	}{
		{"URLENCODED", "URLENCODED", true}, {"MULTIPART", "MULTIPART", true},
		{"MULTIPART", "URLENCODED", false}, {"URLENCODED", "MULTIPART", false},
		{"URLENCODED", "", false}, {"MULTIPART", "", false}, {"", "", false}, {"", "URLENCODED", false},
		{"RAW", "URLENCODED", false}, {"JSON", "MULTIPART", false}, {"XML", "URLENCODED", false},
		{"JSON", "JSON", true}, {"URLENCODED", "JSON", false}, {"MULTIPART", "JSON", false}, {"JSON", "URLENCODED", false},
		{"RAW", "JSON", false}, {"XML", "JSON", false}, {"", "JSON", false}, {"json", "JSON", false}, {"JSON ", "JSON", false},
		{"urlencoded", "URLENCODED", false}, {"URLENCODED ", "URLENCODED", false}, {"UNKNOWN", "URLENCODED", false},
	} {
		f := &fakeTx{reqAccess: true, flags: map[variables.RuleVariable]string{variables.ReqbodyProcessor: c.read}}
		if got := requestComplete(f, true, 1, c.want); got != c.ok {
			t.Errorf("processor %q, expected %q: complete %v, want %v", c.read, c.want, got, c.ok)
		}
		if got := requestComplete(f, true, 0, c.want); !got {
			t.Errorf("processor %q, expected %q: a request without a body is incomplete", c.read, c.want)
		}
		if got := requestComplete(f, false, 1, c.want); !got {
			t.Errorf("processor %q, expected %q: read before phase 2", c.read, c.want)
		}
	}

	// A type that is not the expected one is incomplete.
	if requestComplete(plainTx{tx}, true, 1, "URLENCODED") {
		t.Error("a transaction that is no TransactionState is complete")
	}
	if requestComplete(noFlags{tx.(realTx)}, true, 1, "URLENCODED") {
		t.Error("a collection that is no Single is complete")
	}
	if requestComplete(noProcessor{&fakeTx{reqAccess: true}}, true, 1, "URLENCODED") {
		t.Error("a request body processor that is no Single is complete")
	}
	if !requestComplete(noProcessor{&fakeTx{reqAccess: true}}, true, 0, "URLENCODED") {
		t.Error("a request without a body reads the request body processor")
	}
}

const probeRule = `SecRule ARGS_POST:probe "@streq block" "id:9202,phase:2,deny,status:403"` + "\n"

// bodyReply plays a request with the given headers and body through the
// product WAF up to the reply to BODY_END.
func bodyReply(t *testing.T, rules string, headers [][2]string, body string) (out, uint32) {
	t.Helper()
	b := defaultBegin(uint64(len(body)))
	b.headers = headers
	return flagCase{begin: b, body: body}.send(t, productHarness(t, baseRules+"SecRequestBodyLimit 1024\n"+rules))
}

// formBody and multipartBody are a body with the argument probe=v.
func formBody(v string) string { return "probe=" + v }

func multipartBody(v string) string {
	return "--xx\r\nContent-Disposition: form-data; name=\"probe\"\r\n\r\n" + v + "\r\n--xx--\r\n"
}

// The Content-Type that Coraza takes for urlencoded or multipart (the first
// one, lower-cased, trimmed, with a prefix match) selects the processor, so
// the body is parsed and judged; a different body is a Continue.
func TestRealBodyProcessorSelected(t *testing.T) {
	host := [2]string{"Host", "example.test"}
	for _, c := range []struct {
		name, rules, ctype string
		body               func(v string) string
	}{
		{"urlencoded", "", "application/x-www-form-urlencoded", formBody},
		{"charset", "", "application/x-www-form-urlencoded; charset=UTF-8", formBody},
		{"spaces", "", "  application/x-www-form-urlencoded; charset=UTF-8 \t", formBody},
		{"upper case", "", "APPLICATION/X-WWW-FORM-URLENCODED", formBody},
		{"no-break space", "", "\u00a0application/x-www-form-urlencoded", formBody},
		{"multipart", "", "multipart/form-data; boundary=xx", multipartBody},
		{"multipart spaces", "", " multipart/form-data; boundary=xx ", multipartBody},
		{"multipart upper case", "", "MULTIPART/FORM-DATA; boundary=xx", multipartBody},
	} {
		t.Run(c.name, func(t *testing.T) {
			headers := [][2]string{host}
			if c.ctype != "" {
				headers = append(headers, [2]string{"Content-Type", c.ctype})
			}
			o, msg := bodyReply(t, probeRule+c.rules, headers, c.body("block"))
			expectVerdict(t, o, 1, msg, 2, true)
			if o.rule != 9202 || o.stat != 403 {
				t.Fatalf("%+v", o)
			}
			o, msg = bodyReply(t, probeRule+c.rules, headers, c.body("fine"))
			expectVerdict(t, o, 1, msg, 2, false)
		})
	}
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
	multi := [][2]string{{"Host", "example.test"}, {"Content-Type", "multipart/form-data; boundary=xx"}}
	for _, c := range []struct{ name, rules, body string }{
		{"RAW", ctl("RAW"), "probe=block"},
		{"empty", ctl(""), "probe=block"},
		{"JSON", ctl("JSON"), `{"probe":"block"}`},
		{"XML", ctl("XML"), "<probe>block</probe>"},
	} {
		t.Run(c.name, func(t *testing.T) {
			o, msg := bodyReply(t, probeRule+c.rules, form, c.body)
			expectError(t, o, 1, msg, classTxFailed, codeIncomplete)
		})
	}
	t.Run("no Content-Type", func(t *testing.T) {
		o, msg := bodyReply(t, probeRule, [][2]string{{"Host", "example.test"}}, "probe=block")
		expectError(t, o, 1, msg, classTxFailed, codeIncomplete)
	})
	// The other processor of the two: the body is parsed without an error, but
	// not as the Content-Type says, so the rule on probe cannot match.
	t.Run("urlencoded for a multipart body", func(t *testing.T) {
		o, msg := bodyReply(t, probeRule+ctl("URLENCODED"), multi, multipartBody("block"))
		expectError(t, o, 1, msg, classTxFailed, codeIncomplete)
	})
	// A phase 2 ctl comes after the body was read and parsed, and Coraza
	// refuses the processor change after phase 1: it cannot restore the one
	// the Content-Type says, and it cannot make the wrong one right.
	t.Run("phase 2 multipart does not restore a multipart body", func(t *testing.T) {
		rules := ctl("URLENCODED") +
			`SecRule REQUEST_METHOD "@streq POST" "id:3,phase:2,pass,nolog,ctl:requestBodyProcessor=MULTIPART"` + "\n" + probeRule
		o, msg := bodyReply(t, rules, multi, multipartBody("block"))
		expectError(t, o, 1, msg, classTxFailed, codeIncomplete)
	})
	t.Run("phase 2 urlencoded does not change a multipart body", func(t *testing.T) {
		rules := `SecRule REQUEST_METHOD "@streq POST" "id:3,phase:2,pass,nolog,ctl:requestBodyProcessor=URLENCODED"` + "\n" + probeRule
		o, msg := bodyReply(t, rules, multi, multipartBody("block"))
		expectVerdict(t, o, 1, msg, 2, true)
		if o.rule != 9202 || o.stat != 403 {
			t.Fatalf("%+v", o)
		}
	})
	t.Run("empty and forced for a multipart body", func(t *testing.T) {
		o, msg := bodyReply(t, probeRule+ctl("")+force, multi, multipartBody("block"))
		expectError(t, o, 1, msg, classTxFailed, codeIncomplete)
	})
	t.Run("empty and forced for a urlencoded body", func(t *testing.T) { // the processor is the expected one again
		o, msg := bodyReply(t, probeRule+ctl("")+force, form, "probe=block")
		expectVerdict(t, o, 1, msg, 2, true)
		if o.rule != 9202 || o.stat != 403 {
			t.Fatalf("%+v", o)
		}
		o, msg = bodyReply(t, probeRule+ctl("")+force, form, "probe=fine")
		expectVerdict(t, o, 1, msg, 2, false)
	})
	t.Run("forced without Content-Type", func(t *testing.T) {
		none := [][2]string{{"Host", "example.test"}}
		o, msg := bodyReply(t, probeRule+force, none, "probe=fine")
		expectError(t, o, 1, msg, classTxFailed, codeIncomplete)
		o, msg = bodyReply(t, probeRule+force, none, "probe=block") // parsed as urlencoded: a Block stays
		expectVerdict(t, o, 1, msg, 2, true)
		if o.rule != 9202 || o.stat != 403 {
			t.Fatalf("%+v", o)
		}
	})
	t.Run("multipart for a urlencoded body is a body error", func(t *testing.T) {
		o, msg := bodyReply(t, probeRule+ctl("MULTIPART"), form, "probe=block")
		expectVerdict(t, o, 1, msg, 2, true)
		if o.rule != 4000001 {
			t.Fatalf("%+v", o)
		}
	})
	t.Run("block stays", func(t *testing.T) {
		rules := ctl("RAW") + `SecRule REQUEST_METHOD "@streq POST" "id:9,phase:2,deny,status:401"` + "\n"
		o, msg := bodyReply(t, rules, form, "probe=block")
		expectVerdict(t, o, 1, msg, 2, true)
		if o.rule != 9 || o.stat != 401 {
			t.Fatalf("%+v", o)
		}
	})
	t.Run("unknown name is a body error", func(t *testing.T) {
		o, msg := bodyReply(t, ctl("NOPE"), form, "probe=block")
		expectVerdict(t, o, 1, msg, 2, true)
		if o.rule != 4000001 {
			t.Fatalf("%+v", o)
		}
	})
	t.Run("no body", func(t *testing.T) {
		for _, headers := range [][][2]string{form, {{"Host", "example.test"}}} {
			o, msg := bodyReply(t, probeRule+ctl("RAW"), headers, "")
			expectVerdict(t, o, 1, msg, 2, false)
		}
	})
}

// Only the first Content-Type header selects the processor, whatever the case
// of its name, and the expectation follows the same header: a later one that
// would select a processor does not, and does not change what is judged.
func TestRealBodyProcessorFirstContentType(t *testing.T) {
	host := [2]string{"Host", "example.test"}
	urlenc := "application/x-www-form-urlencoded"
	multi := "multipart/form-data; boundary=xx"
	for _, c := range []struct {
		name    string
		headers [][2]string
		body    func(v string) string
		judged  bool // the body is parsed and judged; else no processor: ERROR
	}{
		{"lower case name", [][2]string{host, {"content-type", urlenc}}, formBody, true},
		{"upper case name", [][2]string{host, {"CONTENT-TYPE", urlenc}}, formBody, true},
		{"urlencoded first", [][2]string{host, {"Content-Type", urlenc}, {"content-type", multi}}, formBody, true},
		{"multipart first", [][2]string{host, {"Content-Type", multi}, {"CONTENT-TYPE", urlenc}}, multipartBody, true},
		{"other type first", [][2]string{host, {"Content-Type", "text/plain"}, {"Content-Type", urlenc}}, formBody, false},
		{"empty first", [][2]string{host, {"Content-Type", ""}, {"Content-Type", urlenc}}, formBody, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			o, msg := bodyReply(t, probeRule, c.headers, c.body("fine"))
			if !c.judged {
				expectError(t, o, 1, msg, classTxFailed, codeIncomplete)
				return
			}
			expectVerdict(t, o, 1, msg, 2, false)
			o, msg = bodyReply(t, probeRule, c.headers, c.body("block"))
			expectVerdict(t, o, 1, msg, 2, true)
			if o.rule != 9202 || o.stat != 403 {
				t.Fatalf("%+v", o)
			}
		})
	}
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

func productWAFFor(t *testing.T, rules string) coraza.WAF {
	t.Helper()
	t.Setenv("TMPDIR", t.TempDir())
	waf, err := newWAF(rules)
	if err != nil {
		t.Fatalf("newWAF: %v", err)
	}
	return waf
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

// scalarsJSON is an array of n numbers.
func scalarsJSON(n int) string { return "[" + strings.Repeat("1,", n-1) + "1]" }

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
	noAny := func(f *fakeTx) types.Transaction { return noFlags{f} }
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
		{"json", []string{"application/json"}, 5, good, nil, "JSON", 1, "continue"},
		{"charset", []string{"application/json; charset=UTF-8"}, 5, good, nil, "JSON", 1, "continue"},
		{"spaces and tab", []string{" \tapplication/json ; charset=utf-8 \t"}, 5, good, nil, "JSON", 1, "continue"},
		{"upper case", []string{"APPLICATION/JSON"}, 5, good, nil, "JSON", 1, "continue"},
		{"mixed case", []string{"Application/Json"}, 5, good, nil, "JSON", 1, "continue"},
		{"no-break space", []string{" application/json"}, 5, good, nil, "JSON", 1, "continue"},
		{"prefix of a longer name", []string{"application/jsonp"}, 5, good, nil, "JSON", 1, "continue"}, // the caller of the kernel refuses it first
		{"json first", []string{"application/json", "text/plain"}, 5, good, nil, "JSON", 1, "continue"},
		{"json after urlencoded", []string{"application/x-www-form-urlencoded", "application/json"}, 5, good, nil, "URLENCODED", 0, "continue"},
		{"json after another type", []string{"text/plain", "application/json"}, 5, good, nil, "", 0, "continue"},
		{"urlencoded", []string{"application/x-www-form-urlencoded"}, 5, good, nil, "URLENCODED", 0, "continue"},
		{"multipart", []string{"multipart/form-data; boundary=xx"}, 5, good, nil, "MULTIPART", 0, "continue"},
		{"text/json", []string{"text/json"}, 5, good, nil, "", 0, "continue"},
		// application/<name>+json: the part before the first ";", trimmed and
		// lower-cased, starts with application/ and ends with +json.
		{"vnd.api+json", []string{"application/vnd.api+json"}, 5, good, nil, "JSON", 1, "continue"},
		{"problem+json", []string{"application/problem+json"}, 5, good, nil, "JSON", 1, "continue"},
		{"suffix with charset", []string{"application/vnd.api+json; charset=UTF-8"}, 5, good, nil, "JSON", 1, "continue"},
		{"suffix, spaces and tab", []string{" \tapplication/vnd.api+json \t; charset=utf-8 \t"}, 5, good, nil, "JSON", 1, "continue"},
		{"suffix, upper case", []string{"APPLICATION/VND.API+JSON"}, 5, good, nil, "JSON", 1, "continue"},
		{"suffix, mixed case with charset", []string{"Application/Vnd.Api+Json; Charset=UTF-8"}, 5, good, nil, "JSON", 1, "continue"},
		{"suffix, no-break space", []string{"\u00a0application/vnd.api+json"}, 5, good, nil, "JSON", 1, "continue"},
		{"suffix, name of one character", []string{"application/x+json"}, 5, good, nil, "JSON", 1, "continue"},
		{"suffix first", []string{"application/vnd.api+json", "text/plain"}, 5, good, nil, "JSON", 1, "continue"},
		{"suffix after urlencoded", []string{"application/x-www-form-urlencoded", "application/vnd.api+json"}, 5, good, nil, "URLENCODED", 0, "continue"},
		{"suffix after another type", []string{"text/plain", "application/vnd.api+json"}, 5, good, nil, "", 0, "continue"},
		{"text/x+json", []string{"text/x+json"}, 5, good, nil, "", 0, "continue"},
		{"no slash after application", []string{"application+json"}, 5, good, nil, "", 0, "continue"},
		{"suffix of a longer name", []string{"application/x+jsonp"}, 5, good, nil, "", 0, "continue"},
		{"hyphen, not plus", []string{"application/x-json"}, 5, good, nil, "", 0, "continue"},
		{"+json only after the semicolon", []string{"application/x; y=+json"}, 5, good, nil, "", 0, "continue"},
		{"+json at the end of the name, parameters after it", []string{"application/x+json; y=z"}, 5, good, nil, "JSON", 1, "continue"},
		{"suffix, name of 122 characters", []string{"application/" + strings.Repeat("a", 122) + "+json"}, 5, good, nil, "JSON", 1, "continue"},
		// Rust refuses an empty name and one of 123 characters; begin does not
		// limit the name, so it takes everything that Rust accepts and more.
		{"suffix, empty name", []string{"application/+json"}, 5, good, nil, "JSON", 1, "continue"},
		{"suffix, name of 123 characters", []string{"application/" + strings.Repeat("a", 123) + "+json"}, 5, good, nil, "JSON", 1, "continue"},
		// The urlencoded prefix is checked first, as in Coraza, so a name that
		// starts with x-www-form-urlencoded is a form here (Rust refuses it,
		// or a JSON body would be parsed as a form); one character less is JSON.
		{"suffix, name of urlencoded", []string{"application/x-www-form-urlencoded+json"}, 5, good, nil, "URLENCODED", 0, "continue"},
		{"suffix, name starting with urlencoded", []string{"application/x-www-form-urlencoded-x+json; y=z"}, 5, good, nil, "URLENCODED", 0, "continue"},
		{"suffix, name one character short of urlencoded", []string{"application/x-www-form-urlencode+json"}, 5, good, nil, "JSON", 1, "continue"},
		{"no Content-Type", nil, 5, good, nil, "", 0, "continue"},
		{"empty Content-Type", []string{""}, 5, good, nil, "", 0, "continue"},
		// The boundary of the body: one declared byte sets it, none does not.
		{"one byte declared", []string{"application/json"}, 1, good, nil, "JSON", 1, "continue"},
		{"nothing declared", []string{"application/json"}, 0, good, nil, "JSON", 0, "continue"},
		{"suffix, one byte declared", []string{"application/vnd.api+json"}, 1, good, nil, "JSON", 1, "continue"},
		{"suffix, nothing declared", []string{"application/vnd.api+json"}, 0, good, nil, "JSON", 0, "continue"},
		{"suffix, processor without Set", []string{"application/vnd.api+json"}, 5, func() *fakeTx { return &fakeTx{reqAccess: true, plainProc: true} }, nil, "JSON", 0, "error"},
		{"phase 1 block", []string{"application/json"}, 5, func() *fakeTx { return &fakeTx{reqAccess: true, phase1: blockIt(1001, 403)} }, nil, "JSON", 0, "block"},
		{"rule engine off", []string{"application/json"}, 5, func() *fakeTx { return &fakeTx{reqAccess: true, ruleOff: true} }, nil, "JSON", 0, "error"},
		{"body not accessible", []string{"application/json"}, 5, func() *fakeTx { return &fakeTx{} }, nil, "JSON", 0, "error"},
		{"processor without Set", []string{"application/json"}, 5, func() *fakeTx { return &fakeTx{reqAccess: true, plainProc: true} }, nil, "JSON", 0, "error"},
		{"not a TransactionState", []string{"application/json"}, 5, good, plain, "JSON", 0, "error"},
		{"no collection for the processor", []string{"application/json"}, 5, good, noProc, "JSON", 0, "error"},
		{"no collection at all", []string{"application/json"}, 5, good, noAny, "JSON", 0, "error"},
		// The same fakes with a form: nothing asks for Set, so a missing one is no error.
		{"urlencoded, processor without Set", []string{"application/x-www-form-urlencoded"}, 5, func() *fakeTx { return &fakeTx{reqAccess: true, plainProc: true} }, nil, "URLENCODED", 0, "continue"},
		{"nothing declared, processor without Set", []string{"application/json"}, 0, func() *fakeTx { return &fakeTx{reqAccess: true, plainProc: true} }, plain, "JSON", 0, "continue"},
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
				if o.state != stHeaders {
					t.Errorf("state %v", o.state)
				}
			case "block":
				expectVerdict(t, rep, 1, 1, 1, true)
				if o.state != stBlockedRq || rep.rule != 1001 {
					t.Errorf("state %v rule %d", o.state, rep.rule)
				}
			default:
				expectError(t, rep, 1, 1, classTxFailed, codeIncomplete)
				if o.state != stFailed {
					t.Errorf("state %v", o.state)
				}
			}
			if v := f.violations(); len(v) != 0 {
				t.Errorf("findings %q", v)
			}
		})
	}
}

// The processor that begin sets is the one that is read before the Continue
// of phase 2, in this order: phase 1, Set, the body, phase 2.
func TestJSONBodyFlowWithFakes(t *testing.T) {
	h := newHarness(t, nil)
	h.in(kindTxBegin, 1, 1, jsonBegin(7).payload())
	expectVerdict(t, h.cap.next(t), 1, 1, 1, false)
	h.in(kindBody, 1, 2, []byte(`{"a":1}`))
	h.in(kindBodyEnd, 1, 3, nil)
	expectVerdict(t, h.cap.next(t), 1, 3, 2, false)
	h.in(kindTxEnd, 1, 4, []byte{endComplete})
	expect(t, h.cap.next(t), kindClosed, 1, 4)
	h.waitOwners()
	f := h.fake(1)
	if got := f.sets(); len(got) != 1 || got[0] != "JSON" {
		t.Fatalf("Set called with %q", got)
	}
	calls := strings.Split(f.trace(), ",")
	at := func(s string) int {
		for i, c := range calls {
			if c == s {
				return i
			}
		}
		return -1
	}
	if !(0 < at("phase1") && at("phase1") < at("setproc") && at("setproc") < at("write") && at("write") < at("phase2")) {
		t.Fatalf("order %v", calls)
	}

	// A processor that is not JSON any more before the Continue of phase 2.
	h = newHarness(t, func(string) *fakeTx {
		f := &fakeTx{reqAccess: true}
		f.reqBody = func() (*types.Interruption, error) {
			f.mu.Lock()
			f.flags = map[variables.RuleVariable]string{variables.ReqbodyProcessor: "URLENCODED"}
			f.mu.Unlock()
			return nil, nil
		}
		return f
	})
	h.in(kindTxBegin, 1, 1, jsonBegin(7).payload())
	expectVerdict(t, h.cap.next(t), 1, 1, 1, false)
	h.in(kindBody, 1, 2, []byte(`{"a":1}`))
	h.in(kindBodyEnd, 1, 3, nil)
	expectError(t, h.cap.next(t), 1, 3, classTxFailed, codeIncomplete)
}

// The Content-Type that Coraza does not know for JSON still selects it here
// (the first one, lower-cased, trimmed, by prefix for application/json, by the
// part before the first ";" for application/<name>+json), begin sets the
// processor, so the body is parsed as JSON and judged by the rules on its
// arguments. A name that starts with x-www-form-urlencoded is a form for
// Coraza, so the JSON text is not judged as JSON.
func TestRealJSONBodySelected(t *testing.T) {
	host := [2]string{"Host", "example.test"}
	urlenc := "application/x-www-form-urlencoded"
	js := "application/json"
	for _, c := range []struct {
		name    string
		headers [][2]string
		want    string // "json": parsed as JSON and judged; "form": parsed as urlencoded; "error": ERROR code 25
	}{
		{"json", jsonHeaders(js), "json"},
		{"charset", jsonHeaders("application/json; charset=UTF-8"), "json"},
		{"spaces and tab", jsonHeaders("  application/json; charset=UTF-8 \t"), "json"},
		{"upper case", jsonHeaders("APPLICATION/JSON"), "json"},
		{"no-break space", jsonHeaders(" application/json"), "json"},
		{"lower case name", [][2]string{host, {"content-type", js}}, "json"},
		{"upper case name", [][2]string{host, {"CONTENT-TYPE", js}}, "json"},
		{"json first", [][2]string{host, {"Content-Type", js}, {"content-type", urlenc}}, "json"},
		{"urlencoded first", [][2]string{host, {"Content-Type", urlenc}, {"content-type", js}}, "form"},
		{"other type first", [][2]string{host, {"Content-Type", "text/plain"}, {"Content-Type", js}}, "error"},
		{"empty first", [][2]string{host, {"Content-Type", ""}, {"Content-Type", js}}, "error"},
		{"structured suffix", jsonHeaders("application/vnd.api+json"), "json"},
		{"structured suffix, charset and case", jsonHeaders(" Application/Problem+JSON ; Charset=UTF-8"), "json"},
		{"structured suffix, name of one character", jsonHeaders("application/x+json"), "json"},
		{"structured suffix, name of 122 characters", jsonHeaders("application/" + strings.Repeat("a", 122) + "+json"), "json"},
		{"structured suffix first", [][2]string{host, {"Content-Type", "application/vnd.api+json"}, {"content-type", "text/plain"}}, "json"},
		{"structured suffix after another type", [][2]string{host, {"Content-Type", "text/plain"}, {"Content-Type", "application/vnd.api+json"}}, "error"},
		{"structured suffix, name of urlencoded", jsonHeaders("application/x-www-form-urlencoded+json"), "form"},
		{"structured suffix, name one character short of urlencoded", jsonHeaders("application/x-www-form-urlencode+json"), "json"},
		{"+json only after the semicolon", jsonHeaders("application/x; y=+json"), "error"},
		{"text/x+json", jsonHeaders("text/x+json"), "error"},
		{"suffix of a longer name", jsonHeaders("application/x+jsonp"), "error"},
		{"text/json", jsonHeaders("text/json"), "error"},
	} {
		t.Run(c.name, func(t *testing.T) {
			o, msg := bodyReply(t, jsonProbeRule, c.headers, jsonBody("fine"))
			if c.want == "error" {
				expectError(t, o, 1, msg, classTxFailed, codeIncomplete)
				return
			}
			expectRule(t, o, msg, 0)
			o, msg = bodyReply(t, jsonProbeRule, c.headers, jsonBody("block"))
			if c.want == "json" {
				expectRule(t, o, msg, 9203)
			} else { // the JSON text is a name of a urlencoded argument: no rule on json.probe matches
				expectRule(t, o, msg, 0)
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
	for _, c := range []struct{ name, rules string }{
		{"no ctl", ""},
		{"URLENCODED", ctl("1", "URLENCODED")},
		{"RAW", ctl("1", "RAW")},
		{"MULTIPART", ctl("1", "MULTIPART")},
		{"XML", ctl("1", "XML")},
		{"unknown name", ctl("1", "NOPE")},
		{"empty", ctl("1", "")},
		{"empty and forced", ctl("1", "") + force},
		{"forced", force},
		{"phase 2 URLENCODED", ctl("2", "URLENCODED")},
		{"phase 2 RAW", ctl("2", "RAW")},
	} {
		t.Run(c.name, func(t *testing.T) {
			headers := jsonHeaders("application/json")
			o, msg := bodyReply(t, jsonProbeRule+c.rules, headers, jsonBody("block"))
			expectRule(t, o, msg, 9203)
			o, msg = bodyReply(t, jsonProbeRule+c.rules, headers, jsonBody("fine"))
			expectRule(t, o, msg, 0)
		})
	}
	// Without a body nothing is parsed and the processor is not asked.
	t.Run("no body", func(t *testing.T) {
		o, msg := bodyReply(t, jsonProbeRule+ctl("1", "RAW"), jsonHeaders("application/json"), "")
		expectRule(t, o, msg, 0)
	})
}

// The rules of phase 1 see an empty REQBODY_PROCESSOR for a JSON body (it is
// set after them), the rules of phase 2 see JSON.
func TestRealJSONProcessorSeenByRules(t *testing.T) {
	const (
		phase1 = `SecRule REQBODY_PROCESSOR "@streq JSON" "id:9301,phase:1,deny,status:403"` + "\n"
		phase2 = `SecRule REQBODY_PROCESSOR "@streq JSON" "id:9302,phase:2,deny,status:403"` + "\n"
	)
	// bodyReply checks that phase 1 is a Continue, so the first rule does not match.
	o, msg := bodyReply(t, phase1+phase2, jsonHeaders("application/json"), jsonBody("fine"))
	expectRule(t, o, msg, 9302)
	o, msg = bodyReply(t, phase1, jsonHeaders("application/json"), jsonBody("fine"))
	expectRule(t, o, msg, 0)
}

// What the JSON processor and the reserved rules do with a body, at the
// boundaries: a nesting depth of 64 containers passes and 65 is a body error
// (rule 4000001), whatever depth limit the operator asks for; a body that is
// not RFC 8259 JSON is a body error; 1000 scalars pass and 1001 are too many
// arguments (rule 4000002).
func TestRealJSONBodyLimits(t *testing.T) {
	for _, c := range []struct {
		name, rules, body string
		rule              int64 // 0: Continue
	}{
		{"depth 64", "", nestedJSON(64, "fine"), 0},
		{"depth 64 is read to the innermost value", jsonAnyRule, nestedJSON(64, "block"), 9204},
		{"depth 65", jsonAnyRule, nestedJSON(65, "fine"), 4000001},
		{"depth 1", "", nestedJSON(1, "fine"), 0},
		{"operator limit 8, depth 20", "SecRequestBodyJsonDepthLimit 8\n", nestedJSON(20, "fine"), 0},
		{"operator limit 8, depth 65", "SecRequestBodyJsonDepthLimit 8\n", nestedJSON(65, "fine"), 4000001},
		{"operator limit 1024, depth 20", "SecRequestBodyJsonDepthLimit 1024\n", nestedJSON(20, "fine"), 0},
		{"operator limit 1024, depth 64", "SecRequestBodyJsonDepthLimit 1024\n", nestedJSON(64, "fine"), 0},
		{"operator limit 1024, depth 65", "SecRequestBodyJsonDepthLimit 1024\n", nestedJSON(65, "fine"), 4000001},
		{"truncated", "", `{"probe":`, 4000001},
		{"trailing comma", "", `{"probe":"fine",}`, 4000001},
		{"missing value", "", `{"probe":}`, 4000001},
		{"trailing text", "", `{"probe":"fine"}x`, 4000001},
		{"NaN", "", `{"probe":NaN}`, 4000001},
		{"white space only", "", " \n", 4000001},
		{"byte order mark", "", "\xef\xbb\xbf" + jsonBody("fine"), 4000001},
		{"UTF-16 with a byte order mark", "", "\xff\xfe{\x00\"\x00a\x00\"\x00:\x001\x00}\x00", 4000001},
		{"UTF-16 without one", "", "{\x00\"\x00a\x00\"\x00:\x001\x00}\x00", 4000001},
		{"UTF-32 with a byte order mark", "", "\xff\xfe\x00\x00{\x00\x00\x00}\x00\x00\x00", 4000001},
		{"valid", "", jsonBody("fine"), 0},
		{"1000 scalars", "", scalarsJSON(1000), 0},
		{"1001 scalars", "", scalarsJSON(1001), 4000002},
	} {
		t.Run(c.name, func(t *testing.T) {
			o, msg := bodyReply(t, bigBody+c.rules, jsonHeaders("application/json"), c.body)
			expectRule(t, o, msg, c.rule)
		})
	}
}
