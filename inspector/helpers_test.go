package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// realTx is what a transaction of the pinned Coraza is: the public interface
// and the experimental one that requestComplete reads (the method sets overlap
// with identical signatures). The fakes and wrappers of the tests implement it
// too, else the assertion of requestComplete fails.
type realTx interface {
	types.Transaction
	plugintypes.TransactionState
}

const (
	testRun = uint64(0x0102030405060708)
	testInc = uint32(7)
)

// ---- test-side encoders for frames that Rust sends (checked against golden) ----

func tHeader(kind uint8, tx uint64, msg uint32, n int) []byte {
	b := make([]byte, headerLen, headerLen+n)
	copy(b, "TKV0")
	b[4] = kind
	binary.BigEndian.PutUint32(b[8:], uint32(n))
	binary.BigEndian.PutUint64(b[12:], testRun)
	binary.BigEndian.PutUint32(b[20:], testInc)
	binary.BigEndian.PutUint64(b[24:], tx)
	binary.BigEndian.PutUint32(b[32:], msg)
	return b
}

func tFrame(kind uint8, tx uint64, msg uint32, payload []byte) []byte {
	return append(tHeader(kind, tx, msg, len(payload)), payload...)
}

type pw struct{ b []byte }

func (w *pw) u16(v uint16) { w.b = binary.BigEndian.AppendUint16(w.b, v) }
func (w *pw) u64(v uint64) { w.b = binary.BigEndian.AppendUint64(w.b, v) }
func (w *pw) s(v string)   { w.u16(uint16(len(v))); w.b = append(w.b, v...) }

type tBegin struct {
	client     string
	clientPort uint16
	server     string
	serverPort uint16
	method     string
	uri        string
	proto      string
	declared   uint64
	headers    [][2]string
}

func defaultBegin(declared uint64) tBegin {
	return tBegin{"127.0.0.1", 40000, "127.0.0.1", 8080, "POST", "/a?q=1", "HTTP/1.1", declared,
		[][2]string{{"Host", "example.test"}, {"Content-Type", "application/x-www-form-urlencoded"}}}
}

// jsonBegin is a request with a JSON body of the given length.
func jsonBegin(declared uint64) tBegin {
	b := defaultBegin(declared)
	b.headers = [][2]string{{"Host", "example.test"}, {"Content-Type", "application/json"}}
	return b
}

func (b tBegin) payload() []byte {
	w := &pw{}
	w.s(b.client)
	w.u16(b.clientPort)
	w.s(b.server)
	w.u16(b.serverPort)
	w.s(b.method)
	w.s(b.uri)
	w.s(b.proto)
	w.u64(b.declared)
	w.u16(uint16(len(b.headers)))
	for _, h := range b.headers {
		w.s(h[0])
		w.s(h[1])
	}
	return w.b
}

func respPayload(status uint16, proto string, declared uint64, headers [][2]string) []byte {
	w := &pw{}
	w.u16(status)
	w.s(proto)
	w.u64(declared)
	w.u16(uint16(len(headers)))
	for _, h := range headers {
		w.s(h[0])
		w.s(h[1])
	}
	return w.b
}

// ---- test-side decoder for frames that the inspector sends ----

type out struct {
	kind  uint8
	tx    uint64
	msg   uint32
	run   uint64
	inc   uint32
	p     []byte
	phase uint8
	block bool
	flags uint8
	rule  int64
	stat  uint16
	act   string
	data  string
	class uint8
	code  uint16
	text  string
	cerr  uint8
	bye   [3]uint64
}

func rdStr(p []byte, off *int) (string, error) {
	if len(p)-*off < 2 {
		return "", fmt.Errorf("short str len")
	}
	n := int(binary.BigEndian.Uint16(p[*off:]))
	*off += 2
	if len(p)-*off < n {
		return "", fmt.Errorf("short str")
	}
	s := string(p[*off : *off+n])
	*off += n
	return s, nil
}

func parseOut(b []byte) (out, error) {
	var o out
	if len(b) < headerLen || string(b[:4]) != "TKV0" || b[5] != 0 || b[6] != 0 || b[7] != 0 {
		return o, fmt.Errorf("bad header")
	}
	o.kind = b[4]
	n := binary.BigEndian.Uint32(b[8:])
	o.run = binary.BigEndian.Uint64(b[12:])
	o.inc = binary.BigEndian.Uint32(b[20:])
	o.tx = binary.BigEndian.Uint64(b[24:])
	o.msg = binary.BigEndian.Uint32(b[32:])
	if int(n) != len(b)-headerLen {
		return o, fmt.Errorf("length %d != %d", n, len(b)-headerLen)
	}
	o.p = b[headerLen:]
	p := o.p
	off := 0
	var err error
	switch o.kind {
	case kindVerdict:
		if len(p) < 14 {
			return o, fmt.Errorf("short verdict")
		}
		o.phase, o.block, o.flags = p[0], p[1] == 1, p[2]
		if p[1] > 1 || p[3] != 0 {
			return o, fmt.Errorf("bad verdict bytes")
		}
		o.rule = int64(binary.BigEndian.Uint64(p[4:]))
		o.stat = binary.BigEndian.Uint16(p[12:])
		off = 14
		if o.act, err = rdStr(p, &off); err != nil {
			return o, err
		}
		if o.data, err = rdStr(p, &off); err != nil {
			return o, err
		}
	case kindError:
		if len(p) < 4 || p[1] != 0 {
			return o, fmt.Errorf("bad error")
		}
		o.class, o.code = p[0], binary.BigEndian.Uint16(p[2:])
		off = 4
		if o.text, err = rdStr(p, &off); err != nil {
			return o, err
		}
	case kindClosed:
		if len(p) != 1 || p[0] > 1 {
			return o, fmt.Errorf("bad closed")
		}
		o.cerr, off = p[0], 1
	case kindBye:
		if len(p) != 24 {
			return o, fmt.Errorf("bad bye")
		}
		for i := range 3 {
			o.bye[i] = binary.BigEndian.Uint64(p[8*i:])
		}
		off = 24
	case kindHello:
		off = len(p) // checked field by field in the process test
	default:
		return o, fmt.Errorf("unexpected kind 0x%02x", o.kind)
	}
	if off != len(p) {
		return o, fmt.Errorf("trailing bytes in kind 0x%02x", o.kind)
	}
	return o, nil
}

// ---- capture sender ----

type capture struct {
	ch    chan []byte
	onOut func(b []byte) // optional hook run synchronously in the sender
}

func newCapture() *capture { return &capture{ch: make(chan []byte, 256)} }

func (c *capture) send(b []byte) bool {
	if c.onOut != nil {
		c.onOut(b)
	}
	c.ch <- b
	return true
}

func (c *capture) next(t *testing.T) out {
	t.Helper()
	select {
	case b := <-c.ch:
		o, err := parseOut(b)
		if err != nil {
			t.Fatalf("parse outbound frame: %v", err)
		}
		if o.run != testRun || o.inc != testInc {
			t.Fatalf("outbound run/inc %x/%d", o.run, o.inc)
		}
		return o
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for an outbound frame")
	}
	return out{}
}

func (c *capture) none(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case b := <-c.ch:
		o, _ := parseOut(b)
		t.Fatalf("unexpected outbound frame kind 0x%02x tx %d msg %d code %d", o.kind, o.tx, o.msg, o.code)
	case <-time.After(d):
	}
}

// ---- fake Coraza transaction ----

// fakeTx embeds a nil types.Transaction: any method not overridden panics,
// which fails the test on an unexpected Coraza call.
//
// Every implemented method also checks, under mu, how it is used, and keeps
// the findings in viol (the harness reports them in Cleanup): no call after
// Close, no call between ProcessLogging and Close, exactly one ProcessLogging
// before Close, every call from the goroutine that made the fake (the harness
// calls adopt where the inspector makes it; a fake without adopt, as in
// link_test.go, is bound to the goroutine of its first call), and no
// overlapping calls. Only a fake made through the harness is checked at the
// end. The mutex makes these fields race-free; -race does not judge the
// ownership itself.
type fakeTx struct {
	realTx
	mu          sync.Mutex
	calls       []string
	phase1      *types.Interruption
	reqAccess   bool
	write       func(b []byte) (*types.Interruption, int, error)
	reqBody     func() (*types.Interruption, error)
	respAccess  bool
	respProc    bool
	phase3      *types.Interruption
	writeResp   func(b []byte) (*types.Interruption, int, error)
	respBody    func() (*types.Interruption, error)
	closeErr    error
	hdrGate     chan struct{}                     // if set, ProcessRequestHeaders waits on it
	ruleOff     bool                              // IsRuleEngineOff
	accessLost  int                               // IsRequestBodyAccessible is false from this call on (1-based); 0: as reqAccess
	flags       map[variables.RuleVariable]string // raw value of a flag; absent is empty, except REQBODY_PROCESSOR (URLENCODED); Set of the processor writes here
	plainProc   bool                              // REQBODY_PROCESSOR is a fakeFlag, a value without Set, as a type of Coraza that changed would be
	procSets    []string                          // the values given to Set of REQBODY_PROCESSOR
	serverNames []string

	owner  uint64 // goroutine that made the fake, else of the first call
	active int    // calls in progress
	logged int    // ProcessLogging calls
	closed bool   // Close was called
	viol   []string
}

func (f *fakeTx) rec(s string) {
	f.mu.Lock()
	f.calls = append(f.calls, s)
	f.mu.Unlock()
}

// enter records a call, checks the rules above and returns the function that
// ends the call: defer f.enter("name")().
func (f *fakeTx) enter(s string) func() {
	g, ok := goid()
	f.mu.Lock()
	switch {
	case f.closed:
		f.violf("%s after Close", s)
	case f.logged > 0 && s != "close":
		f.violf("%s after ProcessLogging", s)
	}
	switch {
	case !ok:
		f.violf("%s: goroutine number not read from runtime.Stack", s)
	case f.owner == 0:
		f.owner = g
	case f.owner != g:
		f.violf("%s from goroutine %d, owner is %d", s, g, f.owner)
	}
	if f.active++; f.active > 1 {
		f.violf("%s overlaps another call", s)
	}
	switch s {
	case "logging":
		f.logged++
	case "close":
		if f.logged != 1 {
			f.violf("Close after %d ProcessLogging, want 1", f.logged)
		}
		f.closed = true
	}
	f.mu.Unlock()
	f.rec(s)
	return func() {
		f.mu.Lock()
		f.active--
		f.mu.Unlock()
	}
}

// adopt binds the fake to the calling goroutine, which is where the inspector
// makes it (newTx runs in the owner).
func (f *fakeTx) adopt() {
	g, ok := goid()
	f.mu.Lock()
	defer f.mu.Unlock()
	if !ok {
		f.violf("creation: goroutine number not read from runtime.Stack")
		return
	}
	f.owner = g
}

// violf adds a finding; the caller holds mu.
func (f *fakeTx) violf(format string, a ...any) { f.viol = append(f.viol, fmt.Sprintf(format, a...)) }

func (f *fakeTx) violations() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.viol...)
}

// trace is the call list as one string, to compare before and after a frame.
func (f *fakeTx) trace() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.calls, ",")
}

func (f *fakeTx) count(s string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c == s {
			n++
		}
	}
	return n
}

// goid returns the number of the calling goroutine. Test only: the inspector
// does not depend on it. It reads the first line that runtime.Stack writes.
func goid() (uint64, bool) {
	var buf [64]byte
	return parseGoid(buf[:runtime.Stack(buf[:], false)])
}

// parseGoid reads "goroutine <n> [" at the start of b. This is the form of
// the header in runtime/traceback.go (goroutineheader) of Go 1.27.2.
// runtime.Stack forces traceback level 1 (runtime/mprof.go), so GOTRACEBACK
// does not change the header. Any other form is reported as not read, never
// skipped.
func parseGoid(b []byte) (uint64, bool) {
	b, ok := bytes.CutPrefix(b, []byte("goroutine "))
	if !ok {
		return 0, false
	}
	i := bytes.IndexByte(b, ' ')
	if i < 1 || !bytes.HasPrefix(b[i:], []byte(" [")) {
		return 0, false
	}
	n, err := strconv.ParseUint(string(b[:i]), 10, 64)
	if err != nil || n == 0 {
		return 0, false
	}
	return n, true
}

func (f *fakeTx) ProcessConnection(string, int, string, int) { defer f.enter("conn")() }
func (f *fakeTx) ProcessURI(string, string, string)          { defer f.enter("uri")() }
func (f *fakeTx) AddRequestHeader(string, string)            { defer f.enter("reqhdr")() }
func (f *fakeTx) SetServerName(s string) {
	defer f.enter("server")()
	f.mu.Lock()
	f.serverNames = append(f.serverNames, s)
	f.mu.Unlock()
}
func (f *fakeTx) ProcessRequestHeaders() *types.Interruption {
	defer f.enter("phase1")()
	if f.hdrGate != nil {
		<-f.hdrGate
	}
	return f.phase1
}
func (f *fakeTx) IsRuleEngineOff() bool { defer f.enter("ruleoff")(); return f.ruleOff }
func (f *fakeTx) IsRequestBodyAccessible() bool {
	defer f.enter("reqaccess")()
	return f.reqAccess && (f.accessLost == 0 || f.count("reqaccess") < f.accessLost)
}

// fakeFlag is the collection.Single of a flag of a fakeTx.
type fakeFlag struct{ v string }

func (fakeFlag) FindAll() []types.MatchData { return nil }
func (fakeFlag) Name() string               { return "" }
func (s fakeFlag) Get() string              { return s.v }

// fakeProc is the REQBODY_PROCESSOR of a fakeTx. As the one of Coraza it is
// a pointer and has Set; Set stores into the flags of the fake, where Get
// reads, so the value that begin sets is the one that requestComplete reads.
type fakeProc struct{ f *fakeTx }

func (*fakeProc) FindAll() []types.MatchData { return nil }
func (*fakeProc) Name() string               { return "" }
func (p *fakeProc) Get() string              { return p.f.procValue() }
func (p *fakeProc) Set(s string) {
	defer p.f.enter("setproc")()
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	m := make(map[variables.RuleVariable]string, len(p.f.flags)+1)
	for k, v := range p.f.flags {
		m[k] = v
	}
	m[variables.ReqbodyProcessor] = s
	p.f.flags = m
	p.f.procSets = append(p.f.procSets, s)
}

// procValue is the raw value of REQBODY_PROCESSOR.
func (f *fakeTx) procValue() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if g, ok := f.flags[variables.ReqbodyProcessor]; ok {
		return g
	}
	return "URLENCODED" // what the Content-Type of defaultBegin selects
}

// sets is the list of values given to Set of REQBODY_PROCESSOR.
func (f *fakeTx) sets() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.procSets...)
}

func (f *fakeTx) Collection(v variables.RuleVariable) collection.Collection {
	defer f.enter("flags")()
	if v == variables.ReqbodyProcessor {
		if f.plainProc {
			return fakeFlag{f.procValue()}
		}
		return &fakeProc{f}
	}
	f.mu.Lock()
	g := f.flags[v]
	f.mu.Unlock()
	return fakeFlag{g}
}
func (f *fakeTx) WriteRequestBody(b []byte) (*types.Interruption, int, error) {
	defer f.enter("write")()
	if f.write != nil {
		return f.write(b)
	}
	return nil, len(b), nil
}
func (f *fakeTx) ProcessRequestBody() (*types.Interruption, error) {
	defer f.enter("phase2")()
	if f.reqBody != nil {
		return f.reqBody()
	}
	return nil, nil
}
func (f *fakeTx) AddResponseHeader(string, string) { defer f.enter("resphdr")() }
func (f *fakeTx) ProcessResponseHeaders(int, string) *types.Interruption {
	defer f.enter("phase3")()
	return f.phase3
}
func (f *fakeTx) IsResponseBodyAccessible() bool  { defer f.enter("respaccess")(); return f.respAccess }
func (f *fakeTx) IsResponseBodyProcessable() bool { defer f.enter("respproc")(); return f.respProc }
func (f *fakeTx) WriteResponseBody(b []byte) (*types.Interruption, int, error) {
	defer f.enter("writeresp")()
	if f.writeResp != nil {
		return f.writeResp(b)
	}
	return nil, len(b), nil
}
func (f *fakeTx) ProcessResponseBody() (*types.Interruption, error) {
	defer f.enter("phase4")()
	if f.respBody != nil {
		return f.respBody()
	}
	return nil, nil
}
func (f *fakeTx) ProcessLogging() { defer f.enter("logging")() }
func (f *fakeTx) Close() error {
	defer f.enter("close")()
	return f.closeErr
}

// harness drives a table with fake transactions and a capture sender.
type harness struct {
	t   *testing.T
	tab *table
	cap *capture
	mu  sync.Mutex
	txs map[string]*fakeTx
	mk  func(id string) *fakeTx
}

func newHarness(t *testing.T, mk func(id string) *fakeTx) *harness {
	h := &harness{t: t, cap: newCapture(), txs: map[string]*fakeTx{}, mk: mk}
	if h.mk == nil {
		h.mk = func(string) *fakeTx { return &fakeTx{reqAccess: true, respAccess: true, respProc: true} }
	}
	h.tab = newTable(testRun, testInc, func(id string) types.Transaction {
		f := h.mk(id)
		f.adopt()
		h.mu.Lock()
		h.txs[id] = f
		h.mu.Unlock()
		return f
	}, h.cap.send)
	t.Cleanup(h.check)
	return h
}

// check runs at the end of every harness test. Open transactions are closed
// as for a lost connection and every owner must finish in time. Then no fake
// may have a usage finding (see fakeTx) and every fake was closed once. A
// fake that a test makes without the harness is not covered.
func (h *harness) check() {
	h.t.Helper()
	h.tab.connLost()
	done := make(chan struct{})
	go func() { h.tab.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		h.t.Errorf("owners did not finish after connLost")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, f := range h.txs {
		for _, v := range f.violations() {
			h.t.Errorf("tx %s: %s", id, v)
		}
		if n := f.count("close"); n != 1 {
			h.t.Errorf("tx %s: Close called %d times", id, n)
		}
	}
}

// discarded is the table's diagnostic discard counter.
func (h *harness) discarded() uint64 {
	_, _, _, d, _ := h.tab.counts()
	return d
}

func (h *harness) fake(tx uint64) *fakeTx {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.txs[h.tab.txIDString(tx)]
}

func (h *harness) in(kind uint8, tx uint64, msg uint32, payload []byte) {
	h.t.Helper()
	b := tFrame(kind, tx, msg, payload)
	var hb [headerLen]byte
	copy(hb[:], b)
	hd, err := checkHeader(&hb, testRun, testInc)
	if err != nil {
		h.t.Fatalf("test frame rejected: %v", err)
	}
	h.tab.dispatch(hd, b[headerLen:])
}

// waitOwners waits for every owner goroutine to finish.
func (h *harness) waitOwners() {
	h.t.Helper()
	done := make(chan struct{})
	go func() { h.tab.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		h.t.Fatalf("owners did not finish")
	}
}

func expect(t *testing.T, o out, kind uint8, tx uint64, msg uint32) {
	t.Helper()
	if o.kind != kind || o.tx != tx || o.msg != msg {
		t.Fatalf("got kind 0x%02x tx %d msg %d (code %d), want kind 0x%02x tx %d msg %d", o.kind, o.tx, o.msg, o.code, kind, tx, msg)
	}
}

func expectVerdict(t *testing.T, o out, tx uint64, msg uint32, phase uint8, block bool) {
	t.Helper()
	expect(t, o, kindVerdict, tx, msg)
	if o.phase != phase || o.block != block {
		t.Fatalf("verdict phase %d block %v, want phase %d block %v", o.phase, o.block, phase, block)
	}
}

func expectError(t *testing.T, o out, tx uint64, msg uint32, class uint8, code uint16) {
	t.Helper()
	expect(t, o, kindError, tx, msg)
	if o.class != class || o.code != code {
		t.Fatalf("error class %d code %d, want class %d code %d", o.class, o.code, class, code)
	}
}

// waitUntil polls cond, which reads a counter that another goroutine moves,
// and fails the test after a deadline.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(2 * time.Second); !cond(); time.Sleep(time.Millisecond) {
		if time.Now().After(end) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// recvWithin waits for a gate signal with a deadline.
func recvWithin(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// TestFakeTxCatchesViolations shows that the checks in fakeTx record what
// they are for (the harness reports these findings in Cleanup).
func TestFakeTxCatchesViolations(t *testing.T) {
	has := func(t *testing.T, f *fakeTx, sub string) {
		t.Helper()
		for _, v := range f.violations() {
			if strings.Contains(v, sub) {
				return
			}
		}
		t.Fatalf("no finding with %q in %q", sub, f.violations())
	}

	t.Run("valid", func(t *testing.T) {
		f := &fakeTx{}
		f.ProcessConnection("", 0, "", 0)
		f.ProcessLogging()
		f.Close()
		if v := f.violations(); len(v) != 0 {
			t.Fatalf("findings %q", v)
		}
	})
	t.Run("call after Close", func(t *testing.T) {
		f := &fakeTx{}
		f.ProcessLogging()
		f.Close()
		f.ProcessURI("", "", "")
		has(t, f, "uri after Close")
	})
	t.Run("second Close", func(t *testing.T) {
		f := &fakeTx{}
		f.ProcessLogging()
		f.Close()
		f.Close()
		has(t, f, "close after Close")
	})
	t.Run("Close without ProcessLogging", func(t *testing.T) {
		f := &fakeTx{}
		f.Close()
		has(t, f, "Close after 0 ProcessLogging")
	})
	t.Run("call between ProcessLogging and Close", func(t *testing.T) {
		f := &fakeTx{}
		f.ProcessLogging()
		f.ProcessURI("", "", "")
		has(t, f, "uri after ProcessLogging")
	})
	t.Run("second ProcessLogging", func(t *testing.T) {
		f := &fakeTx{}
		f.ProcessLogging()
		f.ProcessLogging()
		has(t, f, "logging after ProcessLogging")
	})
	t.Run("other goroutine", func(t *testing.T) {
		f := &fakeTx{}
		f.ProcessConnection("", 0, "", 0)
		done := make(chan struct{})
		go func() { defer close(done); f.ProcessURI("", "", "") }()
		recvWithin(t, done, "the other goroutine")
		has(t, f, "uri from goroutine")
	})
	t.Run("made on another goroutine", func(t *testing.T) {
		f := &fakeTx{}
		done := make(chan struct{})
		go func() { defer close(done); f.adopt() }() // made where the owner is not
		recvWithin(t, done, "the other goroutine")
		f.ProcessConnection("", 0, "", 0)
		has(t, f, "conn from goroutine")
	})
	t.Run("overlap", func(t *testing.T) {
		gate := make(chan struct{})
		f := &fakeTx{hdrGate: gate}
		done := make(chan struct{})
		go func() { defer close(done); f.ProcessRequestHeaders() }() // the owner, held inside the call
		waitUntil(t, "the call to start", func() bool { return f.count("phase1") == 1 })
		f.ProcessURI("", "", "")
		close(gate)
		recvWithin(t, done, "the held call")
		has(t, f, "uri overlaps another call")
		has(t, f, "uri from goroutine")
	})
	t.Run("goroutine number", func(t *testing.T) {
		if id, ok := goid(); !ok || id == 0 {
			t.Fatalf("goid %d %v", id, ok)
		}
		for _, c := range []struct {
			in   string
			id   uint64
			want bool
		}{
			{"goroutine 7 [running]:\nmain.f()", 7, true},
			{"goroutine 18446744073709551615 [chan receive]:", 18446744073709551615, true},
			{"", 0, false},
			{"goroutine ", 0, false},
			{"goroutine 7", 0, false},
			{"goroutine 7 gp=0x1 [running]:", 0, false},
			{"goroutine x [running]:", 0, false},
			{"goroutine 0 [running]:", 0, false},
			{"goroutine 18446744073709551616 [running]:", 0, false},
			{" goroutine 7 [running]:", 0, false},
		} {
			if id, ok := parseGoid([]byte(c.in)); id != c.id || ok != c.want {
				t.Errorf("parseGoid(%q) = %d, %v", c.in, id, ok)
			}
		}
	})
}
