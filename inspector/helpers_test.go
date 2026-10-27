package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
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
// and the experimental one that requestComplete reads. The fakes and wrappers
// of the tests implement it too, else the assertion of requestComplete fails.
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
func (w *pw) headers(hs [][2]string) {
	w.u16(uint16(len(hs)))
	for _, h := range hs {
		w.s(h[0])
		w.s(h[1])
	}
}

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
	w.headers(b.headers)
	return w.b
}

func respPayload(status uint16, proto string, declared uint64, headers [][2]string) []byte {
	w := &pw{}
	w.u16(status)
	w.s(proto)
	w.u64(declared)
	w.headers(headers)
	return w.b
}

// ---- test-side decoder for frames that the inspector sends ----

type out struct {
	kind  uint8
	tx    uint64
	msg   uint32
	run   uint64
	inc   uint32
	phase uint8
	block bool
	flags uint8
	rule  int64
	stat  uint16
	act   string
	data  string
	ids   []int64 // VERDICT: rule ids, severity and score at its end
	sev   uint8
	score int32
	class uint8
	code  uint16
	text  string
	cerr  uint8
	bye   [3]uint64
}

func parseOut(b []byte) (out, error) {
	var o out
	if len(b) < headerLen || string(b[:4]) != "TKV0" || b[5] != 0 || b[6] != 0 || b[7] != 0 {
		return o, fmt.Errorf("bad header")
	}
	o.kind = b[4]
	o.run = binary.BigEndian.Uint64(b[12:])
	o.inc = binary.BigEndian.Uint32(b[20:])
	o.tx = binary.BigEndian.Uint64(b[24:])
	o.msg = binary.BigEndian.Uint32(b[32:])
	if n := int(binary.BigEndian.Uint32(b[8:])); n != len(b)-headerLen {
		return o, fmt.Errorf("length %d != %d", n, len(b)-headerLen)
	}
	c := &cursor{p: b[headerLen:]}
	switch o.kind {
	case kindVerdict:
		var d, zero uint8
		o.phase, d, o.flags, zero = c.u8(), c.u8(), c.u8(), c.u8()
		o.block = d == 1
		o.rule, o.stat = int64(c.u64()), c.u16()
		o.act, o.data = c.str16(0, 0xffff), c.str16(0, 0xffff)
		n := c.u8()
		for range n {
			o.ids = append(o.ids, int64(c.u64()))
		}
		o.sev = c.u8()
		if v := c.take(4); v != nil {
			o.score = int32(binary.BigEndian.Uint32(v))
		}
		c.bad = c.bad || d > 1 || zero != 0 || n > maxRuleIDs || (o.flags&flagMoreRules != 0 && n != maxRuleIDs) ||
			(o.sev > maxSeverity && o.sev != severityNone) || o.score < scoreNone
	case kindError:
		var zero uint8
		o.class, zero = c.u8(), c.u8()
		o.code, o.text = c.u16(), c.str16(0, 0xffff)
		c.bad = c.bad || zero != 0
	case kindClosed:
		o.cerr = c.u8()
		c.bad = c.bad || o.cerr > 1
	case kindBye:
		o.bye = [3]uint64{c.u64(), c.u64(), c.u64()}
	case kindHello:
		c.off = len(c.p) // compared whole in the process test
	default:
		return o, fmt.Errorf("unexpected kind 0x%02x", o.kind)
	}
	if !c.done() {
		return o, fmt.Errorf("malformed kind 0x%02x", o.kind)
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

// fakeTx embeds a nil realTx: any method not overridden panics, which fails
// the test on an unexpected Coraza call. Every method also checks, under mu,
// how it is used: no call after Close or between ProcessLogging and Close,
// exactly one ProcessLogging before Close, every call from the goroutine that
// made the fake (the harness calls adopt where the inspector makes it; a fake
// without adopt is bound to the goroutine of its first call), and no
// overlapping calls. The findings are in viol; a fake made through the harness
// is checked at the end of the test.
type fakeTx struct {
	realTx
	mu          sync.Mutex
	calls       []string
	phase1      *types.Interruption
	reqAccess   bool
	write       func(b []byte) (*types.Interruption, int, error)
	respAccess  bool
	respProc    bool
	phase3      *types.Interruption
	hdrGate     chan struct{}                     // if set, ProcessRequestHeaders waits on it
	accessLost  int                               // IsRequestBodyAccessible is false from this call on (1-based); 0: as reqAccess
	flags       map[variables.RuleVariable]string // raw value of a flag; absent is empty, except REQBODY_PROCESSOR (URLENCODED); Set of the processor writes here
	plainProc   bool                              // REQBODY_PROCESSOR is a value without Set, as a type of Coraza that changed would be
	procSets    []string                          // the values given to Set of REQBODY_PROCESSOR
	serverNames []string

	owner  uint64 // goroutine that made the fake, else of the first call
	active int    // calls in progress
	logged int    // ProcessLogging calls
	closed bool   // Close was called
	viol   []string
}

// enter records a call, checks the rules above and returns the function that
// ends the call: defer f.enter("name")().
func (f *fakeTx) enter(s string) func() {
	g := goid()
	f.mu.Lock()
	switch {
	case f.closed:
		f.violf("%s after Close", s)
	case f.logged > 0 && s != "close":
		f.violf("%s after ProcessLogging", s)
	}
	switch {
	case g == 0:
		f.violf("%s: goroutine number not read", s)
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
	f.calls = append(f.calls, s)
	f.mu.Unlock()
	return func() {
		f.mu.Lock()
		f.active--
		f.mu.Unlock()
	}
}

// adopt binds the fake to the calling goroutine, which is where the inspector
// makes it (newTx runs in the owner).
func (f *fakeTx) adopt() {
	g := goid()
	f.mu.Lock()
	defer f.mu.Unlock()
	if g == 0 {
		f.violf("creation: goroutine number not read")
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

// goid returns the number of the calling goroutine from the first line that
// runtime.Stack writes ("goroutine 7 [running]:"), or 0 if it is not read.
// Test only: the inspector does not depend on it.
func goid() uint64 {
	var buf [64]byte
	var n uint64
	if _, err := fmt.Sscanf(string(buf[:runtime.Stack(buf[:], false)]), "goroutine %d ", &n); err != nil {
		return 0
	}
	return n
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
func (f *fakeTx) MatchedRules() []types.MatchedRule { defer f.enter("matched")(); return nil }
func (f *fakeTx) IsRuleEngineOff() bool             { defer f.enter("ruleoff")(); return false }
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
	if p.f.flags == nil {
		p.f.flags = map[variables.RuleVariable]string{}
	}
	p.f.flags[variables.ReqbodyProcessor] = s
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
	return nil, len(b), nil
}
func (f *fakeTx) ProcessResponseBody() (*types.Interruption, error) {
	defer f.enter("phase4")()
	return nil, nil
}
func (f *fakeTx) ProcessLogging() { defer f.enter("logging")() }
func (f *fakeTx) Close() error {
	defer f.enter("close")()
	return nil
}

// harness drives a table with fake transactions and a capture sender.
type harness struct {
	t   *testing.T
	tab *table
	cap *capture
	mu  sync.Mutex
	txs map[string]*fakeTx
}

func newHarness(t *testing.T, mk func(id string) *fakeTx) *harness {
	h := &harness{t: t, cap: newCapture(), txs: map[string]*fakeTx{}}
	if mk == nil {
		mk = func(string) *fakeTx { return &fakeTx{reqAccess: true, respAccess: true, respProc: true} }
	}
	h.tab = newTable(testRun, testInc, func(id string) types.Transaction {
		f := mk(id)
		f.adopt()
		h.mu.Lock()
		h.txs[id] = f
		h.mu.Unlock()
		return f
	}, false, h.cap.send)
	t.Cleanup(h.check)
	return h
}

// check runs at the end of every harness test. Open transactions are closed
// as for a lost connection and every owner must finish in time. Then no fake
// may have a usage finding (see fakeTx) and every fake was closed once.
func (h *harness) check() {
	h.t.Helper()
	h.tab.connLost()
	h.waitOwners()
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
	h.inFlags(0, kind, tx, msg, payload)
}

// inFlags is in with the flags of the header.
func (h *harness) inFlags(flags, kind uint8, tx uint64, msg uint32, payload []byte) {
	h.t.Helper()
	b := tFrame(kind, tx, msg, payload)
	b[5] = flags
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
	recvWithin(h.t, done, "the owners to finish")
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

// ---- bundles ----

// ruleFile is the path of the one rule file of the bundles that ruleBundle and
// startProc make.
const ruleFile = "rules/rules.conf"

// testManifest is the manifest of the files (path to text) with the order of
// load, as the writer of a bundle makes it: the files in byte order, the size
// and the sha256 of each.
func testManifest(files map[string]string, load []string) manifest {
	m := manifest{Version: 1, Load: load}
	for p, s := range files {
		sum := sha256.Sum256([]byte(s))
		m.Files = append(m.Files, manifestFile{Path: p, Size: int64(len(s)), SHA256: hex.EncodeToString(sum[:])})
	}
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })
	return m
}

// testBundle is the bundle in memory of the files and the order of load. Its
// manifest is the one that encode writes.
func testBundle(files map[string]string, load ...string) *bundle {
	mb := testManifest(files, load).encode()
	b := &bundle{manifestBytes: mb, fingerprint: sha256.Sum256(mb), load: load, files: make(map[string][]byte, len(files))}
	for p, s := range files {
		b.files[p] = []byte(s)
	}
	return b
}

// ruleBundle is the bundle of one rule file, ruleFile, with the text.
func ruleBundle(text string) *bundle {
	return testBundle(map[string]string{ruleFile: text}, ruleFile)
}

// detectBundle is ruleBundle for a manifest of version 2: its rules only
// detect.
func detectBundle(text string) *bundle {
	b := ruleBundle(text)
	m := testManifest(map[string]string{ruleFile: text}, b.load)
	m.Version = versionDetect
	b.manifestBytes = m.encode()
	b.fingerprint = sha256.Sum256(b.manifestBytes)
	b.detect = true
	return b
}

// writeBundle writes the same bundle into the directory dir (made with mode
// 0700 when it is not there) and returns its fingerprint.
func writeBundle(t *testing.T, dir string, files map[string]string, load ...string) [32]byte {
	t.Helper()
	return writeBundleVersion(t, dir, versionBlock, files, load...)
}

// writeBundleVersion is writeBundle with the version of the manifest.
func writeBundleVersion(t *testing.T, dir string, version int, files map[string]string, load ...string) [32]byte {
	t.Helper()
	m := testManifest(files, load)
	m.Version = version
	mb := m.encode()
	put := func(name string, data []byte) {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	put(manifestName, mb)
	for p, s := range files {
		put(p, []byte(s))
	}
	return sha256.Sum256(mb)
}
