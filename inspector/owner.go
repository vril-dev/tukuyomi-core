// Transaction ownership. One goroutine owns one Coraza transaction: only that
// goroutine creates it, calls Coraza on it, emits its VERDICT/ERROR and closes
// it. The shared reader never touches a Coraza transaction.
package main

import (
	"strings"
	"sync"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// inFrame is a transaction frame handed from the reader to an owner.
type inFrame struct {
	kind    uint8
	msg     uint32
	payload []byte
}

// entry is the shared part of one transaction. The reader and the owner use it
// only under mu: queue append, the overflow mark, the close mark and wake-up.
type entry struct {
	mu          sync.Mutex
	cond        *sync.Cond
	q           []inFrame
	overflow    bool   // set by the reader when the queue was full
	overflowNew bool   // overflow not yet reported by the owner
	overflowMsg uint32 // msg number of the first discarded frame
	closing     bool
	closeMsg    uint32
	connLost    bool
	done        bool // the owner took the close mark; later frames are discarded
}

func newEntry() *entry {
	e := &entry{q: make([]inFrame, 0, queueDepth)}
	e.cond = sync.NewCond(&e.mu)
	return e
}

// push appends a frame without blocking. It reports false when the frame was
// discarded (after the close mark, or because the queue overflowed).
func (e *entry) push(f inFrame) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.done || e.closing || e.overflow {
		return false
	}
	if len(e.q) >= queueDepth {
		e.overflow, e.overflowNew, e.overflowMsg = true, true, f.msg
		e.cond.Signal()
		return false
	}
	e.q = append(e.q, f)
	e.cond.Signal()
	return true
}

// markClose records TX_END; it is not queued. It reports false for a second
// TX_END.
func (e *entry) markClose(msg uint32) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.done || e.closing {
		return false
	}
	e.closing, e.closeMsg = true, msg
	e.cond.Signal()
	return true
}

func (e *entry) markConnLost() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.connLost, e.closing = true, true
	e.cond.Signal()
}

type event int

const (
	evFrame event = iota
	evOverflow
	evClose
)

// next blocks until there is work. Under the same lock it looks at the close
// mark, then the overflow mark, and only then dequeues: queued frames are
// never handed to Coraza after either mark. After the close mark Rust has
// already decided, so a late overflow ERROR is not sent.
func (e *entry) next() (ev event, f inFrame, dropped int, msg uint32, connLost bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for {
		if e.closing {
			e.done = true
			dropped = len(e.q)
			clear(e.q)
			e.q = nil
			return evClose, inFrame{}, dropped, e.closeMsg, e.connLost
		}
		if e.overflowNew {
			msg, dropped = e.overflowMsg, len(e.q)
			e.overflowNew = false // reported once; e.overflow stays so later frames are discarded
			clear(e.q)
			e.q = e.q[:0]
			return evOverflow, inFrame{}, dropped, msg, false
		}
		if len(e.q) > 0 {
			f = e.q[0]
			e.q[0] = inFrame{}
			e.q = e.q[1:]
			return evFrame, f, 0, 0, false
		}
		e.cond.Wait()
	}
}

type txState int

const (
	stHeaders   txState = iota // phase 1 continue; no BODY yet
	stBody                     // BODY received
	stReqDone                  // phase 2 continue
	stResp                     // phase 3 continue
	stRespDone                 // phase 4 continue
	stBlockedRq                // blocked in phase 1 or 2
	stBlockedRs                // blocked in phase 3 or 4
	stFailed                   // ERROR sent
)

// sender delivers one encoded frame to the single writer. It reports false if
// the connection is gone (the frame is dropped).
type sender func(b []byte) bool

// owner is the single goroutine of one transaction.
type owner struct {
	t        *table
	e        *entry
	id       uint64
	tx       types.Transaction // local to the owner goroutine only
	state    txState
	lastMsg  uint32
	declared uint64
	cut      bool   // the body goes on past the declared bytes: its parse failures are no reason to block
	wantProc string // request body processor that the first Content-Type selects (urlencoded and multipart: Coraza; JSON: begin); empty: none
	recv     uint64
	rDecl    uint64
	rRecv    uint64
}

func (o *owner) run(b txBegin, msg uint32) {
	defer o.t.wg.Done()
	o.lastMsg = msg
	o.begin(b, msg)
	for {
		ev, f, dropped, m, lost := o.e.next()
		switch ev {
		case evOverflow:
			o.t.countDiscard(uint64(dropped))
			// The overflowing frame was already counted by the reader. After a
			// block or an ERROR, frames are only counted, so no reply.
			if o.state != stBlockedRq && o.state != stBlockedRs && o.state != stFailed {
				o.fail(m, codeOverflow, "receive queue overflow")
			}
		case evClose:
			o.t.countDiscard(uint64(dropped))
			o.close(m, lost)
			return
		default:
			o.handle(f)
		}
	}
}

func (o *owner) send(b []byte) { o.t.send(b) }

// verdict sends the Continue (it is nil) or the Block of a phase. In a bundle
// that only detects, a Block of the request phases is sent only when the rule
// before the files ran (detectBeginID): without it the transaction was never
// switched to DetectionOnly, so a rule of the operator may have blocked it and
// nothing says what the engine did. That request is incomplete, as for a
// Continue (detectionOf).
func (o *owner) verdict(msg uint32, phase uint8, it *types.Interruption) {
	if it == nil {
		b, _ := encodeVerdict(o.t.run, o.t.inc, o.id, msg, phase, 0, 0, "", "", false)
		o.send(b)
		return
	}
	if o.t.detect && phase <= 2 && !ruleMatched(o.tx, detectBeginID) {
		o.fail(msg, codeIncomplete, "request inspection incomplete")
		return
	}
	b, ok := encodeVerdict(o.t.run, o.t.inc, o.id, msg, phase, it.RuleID, it.Status, it.Action, it.Data, true)
	if !ok {
		o.fail(msg, codeBadVerdict, "interruption status out of range")
		return
	}
	if phase <= 2 {
		o.state = stBlockedRq
	} else {
		o.state = stBlockedRs
	}
	o.send(b)
}

// fail sends the transaction's single ERROR and moves to the failed state.
func (o *owner) fail(msg uint32, code uint16, text string) {
	if o.state == stFailed {
		o.t.countDiscard(1)
		return
	}
	o.state = stFailed
	o.send(encodeError(o.t.run, o.t.inc, o.id, msg, classTxFailed, code, text))
}

func (o *owner) begin(b txBegin, msg uint32) {
	o.tx = o.t.newTx(o.t.txIDString(o.id))
	o.declared = b.declared
	o.cut = b.cut
	o.tx.ProcessConnection(b.clientAddr, int(b.clientPort), b.serverAddr, int(b.serverPort))
	o.tx.ProcessURI(b.uri, b.method, b.proto)
	host, hasHost, hasType := "", false, false
	for _, h := range b.headers {
		o.tx.AddRequestHeader(h.name, h.value)
		if !hasHost && strings.EqualFold(h.name, "host") {
			host, hasHost = h.value, true
		}
		// transaction.go:404-416 of the pinned Coraza version: only the first
		// Content-Type selects the processor, from its lower-cased, trimmed
		// value by prefix. Coraza picks urlencoded and multipart that way and
		// never picks JSON; the same prefix rule gives JSON here for
		// application/json. A second rule gives JSON for application/<name>+json:
		// the part before the first ";", trimmed, starts with application/ and
		// ends with +json. The processor is set below. The urlencoded check
		// comes first, as in Coraza, so a name that starts with
		// x-www-form-urlencoded is a form here and never JSON; Rust refuses
		// such a type.
		if !hasType && strings.EqualFold(h.name, "content-type") {
			hasType = true
			v := strings.TrimSpace(strings.ToLower(h.value))
			essence, _, _ := strings.Cut(v, ";")
			essence = strings.TrimSpace(essence)
			if strings.HasPrefix(v, "application/x-www-form-urlencoded") {
				o.wantProc = "URLENCODED"
			} else if strings.HasPrefix(v, "multipart/form-data") {
				o.wantProc = "MULTIPART"
			} else if strings.HasPrefix(v, "application/json") {
				o.wantProc = "JSON"
			} else if strings.HasPrefix(essence, "application/") && strings.HasSuffix(essence, "+json") {
				o.wantProc = "JSON"
			}
		}
	}
	if hasHost && host != "" { // middleware.go: only a non-empty Host
		o.tx.SetServerName(host)
	}
	o.state = stHeaders
	it := o.tx.ProcessRequestHeaders()
	if it == nil && !requestComplete(o.tx, false, o.declared, o.wantProc, o.cut) {
		o.fail(msg, codeIncomplete, "request inspection incomplete")
		return
	}
	// The JSON processor is set here, after the rules of phase 1 (a ctl of
	// the operator can no longer take it back: Coraza refuses
	// ctl:requestBodyProcessor after the headers phase, ctl.go:253-255) and
	// before the body is read (transaction.go:1142). The assertions are those
	// of requestComplete, and the processor of the pinned Coraza has Set.
	if it == nil && o.declared > 0 && o.wantProc == "JSON" {
		ts, ok := o.tx.(plugintypes.TransactionState)
		if !ok {
			o.fail(msg, codeIncomplete, "request inspection incomplete")
			return
		}
		p, ok := ts.Collection(variables.ReqbodyProcessor).(interface{ Set(string) })
		if !ok {
			o.fail(msg, codeIncomplete, "request inspection incomplete")
			return
		}
		p.Set("JSON")
	}
	// The variable that rule 4000001 reads is put here as well, after the rules
	// of phase 1 and before the body is read.
	if it == nil && o.cut && !markCut(o.tx) {
		o.fail(msg, codeIncomplete, "request inspection incomplete")
		return
	}
	o.verdict(msg, 1, it)
}

// markCut puts bodyCutVar on the transaction of a body that was cut, which tells
// rule 4000001 that the parse failure of the body is no reason to block. A
// transaction or collection that is not of the expected type is not marked.
func markCut(tx types.Transaction) bool {
	ts, ok := tx.(plugintypes.TransactionState)
	if !ok {
		return false
	}
	m, ok := ts.Collection(variables.TX).(collection.Map)
	if !ok {
		return false
	}
	m.Set(bodyCutVar, []string{"1"})
	return true
}

// requestComplete is the guard before a Continue of phase 1 or 2: the rules
// of the operator may have switched the rule engine or the body access off for
// this transaction, may have replaced the request body processor, and a rule
// of the reserved set (id 4000001 to 4000003) may have been skipped or
// dropped, so nothing is assumed from the rules. A rule engine Off or a body
// that is not accessible make the inspection incomplete. Before the Continue
// of phase 2 the raw value of each flag that the reserved rules test must be
// empty or "0", except the parse failure of the body (REQBODY_ERROR) when the
// body was cut (cut): the cut causes it, and rule 4000001 lets it pass then. For
// a body that was not cut it stays a flag whatever bodyCutVar says, so a rule
// that sets the variable on such a transaction by a key that a macro builds
// (which checkRules cannot see) does not turn the block into a Continue.
// For a request with a body (declared > 0) the request body
// processor must equal wantProc, the one that the first Content-Type selects
// (URLENCODED and MULTIPART: Coraza picks them; JSON, for application/json
// and application/<name>+json: begin sets it; empty when it is none of these,
// or when there is none), and wantProc must not be empty. Otherwise the body
// was not parsed as the Content-Type says: a rule of the operator replaced the
// processor (ctl:requestBodyProcessor), forced one
// (ctl:forceRequestBodyVariable sets URLENCODED when the processor is empty),
// or left it empty (an empty processor parses nothing and sets no error). For
// JSON a replacement in phase 1 is undone by begin, and Coraza refuses one in
// phase 2. A transaction or collection that is not of the expected type is
// incomplete.
// The assertions use the experimental plugin interface of the pinned Coraza
// version; the Transaction that its WAF returns implements it. The callers
// ask only for a Continue: a Block keeps its VERDICT.
func requestComplete(tx types.Transaction, phase2 bool, declared uint64, wantProc string, cut bool) bool {
	if tx.IsRuleEngineOff() || !tx.IsRequestBodyAccessible() {
		return false
	}
	if !phase2 {
		return true
	}
	ts, ok := tx.(plugintypes.TransactionState)
	if !ok {
		return false
	}
	for _, v := range [...]variables.RuleVariable{
		variables.ReqbodyError, variables.ArgumentsLimitReached, variables.URIParseError,
	} {
		s, ok := ts.Collection(v).(collection.Single)
		if !ok {
			return false
		}
		if cut && v == variables.ReqbodyError {
			continue
		}
		if g := s.Get(); g != "" && g != "0" {
			return false
		}
	}
	if declared == 0 {
		return true
	}
	s, ok := ts.Collection(variables.ReqbodyProcessor).(collection.Single)
	if !ok {
		return false
	}
	return wantProc != "" && s.Get() == wantProc
}

// handle applies the frame and state rules to one queued frame.
func (o *owner) handle(f inFrame) {
	if o.state == stFailed {
		o.t.countDiscard(1)
		return
	}
	if f.msg != o.lastMsg+1 {
		o.lastMsg = f.msg
		o.fail(f.msg, codeOrder, "message number gap or duplicate")
		return
	}
	o.lastMsg = f.msg
	switch f.kind {
	case kindBody:
		switch o.state {
		case stHeaders, stBody:
			o.body(f)
		case stBlockedRq: // request body that was in flight when blocked
			o.t.countDiscard(1)
		default:
			o.fail(f.msg, codeOrder, "BODY not allowed in this state")
		}
	case kindBodyEnd:
		switch o.state {
		case stHeaders, stBody:
			o.bodyEnd(f)
		case stBlockedRq:
			o.t.countDiscard(1)
		default:
			o.fail(f.msg, codeOrder, "BODY_END not allowed in this state")
		}
	case kindRespBegin:
		if o.state == stReqDone {
			o.respBegin(f)
		} else {
			o.fail(f.msg, codeOrder, "RESP_BEGIN not allowed in this state")
		}
	case kindRespBody, kindRespEnd:
		switch o.state {
		case stResp:
			if f.kind == kindRespBody {
				o.respBody(f)
			} else {
				o.respEnd(f)
			}
		case stBlockedRs:
			o.t.countDiscard(1)
		default:
			o.fail(f.msg, codeOrder, "response frame not allowed in this state")
		}
	default: // a second TX_BEGIN for an active id
		o.fail(f.msg, codeOrder, "duplicate TX_BEGIN")
	}
}

func (o *owner) body(f inFrame) {
	n := uint64(len(f.payload))
	if n == 0 {
		o.fail(f.msg, codeBadContent, "empty BODY")
		return
	}
	if o.state == stHeaders && !o.tx.IsRequestBodyAccessible() {
		o.fail(f.msg, codeReqNotInspect, "request body not accessible")
		return
	}
	if n > o.declared-o.recv { // recv <= declared always holds here
		o.fail(f.msg, codeReqOver, "request body longer than declared")
		return
	}
	it, w, err := o.tx.WriteRequestBody(f.payload)
	switch {
	case it != nil:
		o.verdict(f.msg, 2, it)
	case err != nil:
		o.fail(f.msg, codeReqWrite, "request body write failed")
	case w != len(f.payload):
		o.fail(f.msg, codeReqShort, "request body short write")
	default:
		o.recv += n
		o.state = stBody
	}
}

func (o *owner) bodyEnd(f inFrame) {
	if o.recv != o.declared {
		o.fail(f.msg, codeReqTruncated, "request body shorter than declared")
		return
	}
	if o.declared != 0 && !o.tx.IsRequestBodyAccessible() {
		o.fail(f.msg, codeReqNotInspect, "request body not accessible")
		return
	}
	it, err := o.tx.ProcessRequestBody()
	switch {
	case it != nil:
		o.verdict(f.msg, 2, it)
	case err != nil:
		o.fail(f.msg, codeReqProcess, "request body processing failed")
	case !requestComplete(o.tx, true, o.declared, o.wantProc, o.cut):
		o.fail(f.msg, codeIncomplete, "request inspection incomplete")
	case o.t.detect:
		o.continueDetect(f.msg)
	default:
		o.state = stReqDone
		o.verdict(f.msg, 2, nil)
	}
}

// continueDetect sends the Continue of phase 2 of a bundle that only detects.
// The match that DetectionOnly kept back, if there is one, goes with it
// (encodeDetected). When detectionOf cannot say what the rules of the operator
// did, the request is incomplete: nothing is let through on a guess.
func (o *owner) continueDetect(msg uint32) {
	it, ok := detectionOf(o.tx)
	if !ok {
		o.fail(msg, codeIncomplete, "request inspection incomplete")
		return
	}
	o.state = stReqDone
	if it == nil {
		o.verdict(msg, 2, nil)
		return
	}
	b, ok := encodeDetected(o.t.run, o.t.inc, o.id, msg, it.RuleID, it.Status, it.Action, it.Data)
	if !ok {
		o.fail(msg, codeBadVerdict, "interruption status out of range")
		return
	}
	o.send(b)
}

// detectionOf reads what a transaction of a bundle that only detects has to say
// before the Continue of phase 2: the first interruption that DetectionOnly
// kept back, or nil. ok is false when it cannot be trusted: the two rules of
// detectBegin and detectEnd must both be among the matched rules (a rule of the
// operator may have removed or skipped one, and then the engine was On or
// DetectionOnly where it should not be), and the transaction must have
// DetectionOnlyInterruption. That is a method of the transaction that Coraza
// makes and not of types.Transaction, so it is asked through an interface of
// its own.
func detectionOf(tx types.Transaction) (*types.Interruption, bool) {
	d, ok := tx.(interface{ DetectionOnlyInterruption() *types.Interruption })
	if !ok {
		return nil, false
	}
	if !ruleMatched(tx, detectBeginID) || !ruleMatched(tx, detectEndID) {
		return nil, false
	}
	return d.DetectionOnlyInterruption(), true
}

// ruleMatched reports whether the rule with this id is among the matched rules
// of the transaction.
func ruleMatched(tx types.Transaction, id int) bool {
	for _, m := range tx.MatchedRules() {
		if m.Rule().ID() == id {
			return true
		}
	}
	return false
}

func (o *owner) respBegin(f inFrame) {
	r, err := decodeRespBegin(f.payload)
	if err != nil {
		o.fail(f.msg, codeBadContent, "invalid RESP_BEGIN")
		return
	}
	o.rDecl = r.declared
	for _, h := range r.headers {
		o.tx.AddResponseHeader(h.name, h.value)
	}
	it := o.tx.ProcessResponseHeaders(int(r.status), r.proto)
	if it == nil {
		o.state = stResp
	}
	o.verdict(f.msg, 3, it)
}

func (o *owner) respInspectable() bool {
	return o.tx.IsResponseBodyAccessible() && o.tx.IsResponseBodyProcessable()
}

func (o *owner) respBody(f inFrame) {
	n := uint64(len(f.payload))
	if n == 0 {
		o.fail(f.msg, codeBadContent, "empty RESP_BODY")
		return
	}
	if o.rRecv == 0 && !o.respInspectable() {
		o.fail(f.msg, codeRespNotInspect, "response body not inspectable")
		return
	}
	if n > o.rDecl-o.rRecv {
		o.fail(f.msg, codeRespOver, "response body longer than declared")
		return
	}
	it, w, err := o.tx.WriteResponseBody(f.payload)
	switch {
	case it != nil:
		o.verdict(f.msg, 4, it)
	case err != nil:
		o.fail(f.msg, codeRespWrite, "response body write failed")
	case w != len(f.payload):
		o.fail(f.msg, codeRespShort, "response body short write")
	default:
		o.rRecv += n
	}
}

func (o *owner) respEnd(f inFrame) {
	if o.rRecv != o.rDecl {
		o.fail(f.msg, codeRespTruncated, "response body shorter than declared")
		return
	}
	if o.rDecl != 0 && !o.respInspectable() {
		o.fail(f.msg, codeRespNotInspect, "response body not inspectable")
		return
	}
	it, err := o.tx.ProcessResponseBody()
	switch {
	case it != nil:
		o.verdict(f.msg, 4, it)
	case err != nil:
		o.fail(f.msg, codeRespProcess, "response body processing failed")
	default:
		o.state = stRespDone
		o.verdict(f.msg, 4, nil)
	}
}

// close runs the logging phase and Close exactly once, removes the entry and
// releases the concurrency slot, then (if the connection is alive) sends
// CLOSED. The transaction is not touched after Close.
func (o *owner) close(msg uint32, connLost bool) {
	o.tx.ProcessLogging()
	err := o.tx.Close()
	o.tx = nil
	o.t.remove(o.id, err != nil)
	if !connLost {
		o.send(encodeClosed(o.t.run, o.t.inc, o.id, msg, err != nil))
	}
}

// table is the shared transaction table used by the single reader.
type table struct {
	run    uint64
	inc    uint32
	newTx  func(id string) types.Transaction
	detect bool // the rules only detect: a Block of the request phases and the Continue of phase 2 are checked, and the Continue may carry a match (verdict, continueDetect)
	send   sender
	wg     sync.WaitGroup

	mu        sync.Mutex
	active    map[uint64]*entry
	maxID     uint64
	draining  bool
	lost      bool
	started   uint64
	closed    uint64
	closeErrs uint64
	discarded uint64 // diagnostic counter; not the Rust-side limit of 64
	badEnds   uint64 // TX_END with an invalid reason byte (still closed)
}

func newTable(run uint64, inc uint32, newTx func(string) types.Transaction, detect bool, send sender) *table {
	return &table{run: run, inc: inc, newTx: newTx, detect: detect, send: send, active: make(map[uint64]*entry)}
}

func (t *table) txIDString(id uint64) string {
	const hexd = "0123456789abcdef"
	b := make([]byte, 0, 16+1+8+1+16)
	put := func(v uint64, n int) {
		for i := n - 1; i >= 0; i-- {
			b = append(b, hexd[(v>>(4*uint(i)))&0xf])
		}
	}
	put(t.run, 16)
	b = append(b, '-')
	put(uint64(t.inc), 8)
	b = append(b, '-')
	put(id, 16)
	return string(b)
}

func (t *table) countDiscard(n uint64) {
	t.mu.Lock()
	t.discarded += n
	t.mu.Unlock()
}

func (t *table) remove(id uint64, closeErr bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.active, id)
	t.closed++
	if closeErr {
		t.closeErrs++
	}
}

func (t *table) notCreated(id uint64, msg uint32, code uint16, text string) {
	t.send(encodeError(t.run, t.inc, id, msg, classNotCreated, code, text))
}

// dispatch applies the frame and state rules to one validated transaction
// frame from the reader.
// The max id advances only on TX_BEGIN (accepted or refused) and on the first
// frame for an unstarted id.
func (t *table) dispatch(h header, p []byte) {
	t.mu.Lock()
	if t.lost {
		t.mu.Unlock()
		return
	}
	e, active := t.active[h.tx]
	if !active && h.tx <= t.maxID {
		t.discarded++ // closed id, or an id used by a "not created" reply
		t.mu.Unlock()
		return
	}
	if !active { // unstarted: h.tx > maxID
		t.maxID = h.tx
		if h.kind != kindTxBegin {
			t.mu.Unlock()
			t.notCreated(h.tx, h.msg, codeUnstarted, "frame for an unstarted transaction")
			return
		}
		code, text := uint16(0), ""
		var b txBegin
		var err error
		switch {
		case t.draining:
			code, text = codeDraining, "draining"
		case len(t.active) >= maxConcurTx:
			code, text = codeLimit, "concurrency limit"
		case h.msg != 1:
			code, text = codeBadBegin, "TX_BEGIN message number is not 1"
		default:
			if b, err = decodeTxBegin(p); err != nil || h.cut && b.declared == 0 { // a cut body has declared bytes
				code, text = codeBadBegin, "invalid TX_BEGIN payload"
			}
			b.cut = h.cut
		}
		if code != 0 {
			t.mu.Unlock()
			t.notCreated(h.tx, h.msg, code, text)
			return
		}
		e = newEntry()
		t.active[h.tx] = e
		t.started++
		t.wg.Add(1)
		t.mu.Unlock()
		o := &owner{t: t, e: e, id: h.tx}
		go o.run(b, h.msg)
		return
	}
	t.mu.Unlock()
	if h.kind == kindTxEnd {
		if _, err := decodeTxEnd(p); err != nil {
			t.mu.Lock()
			t.badEnds++
			t.mu.Unlock()
		}
		if !e.markClose(h.msg) {
			t.countDiscard(1)
		}
		return
	}
	if !e.push(inFrame{kind: h.kind, msg: h.msg, payload: p}) {
		t.countDiscard(1)
	}
}

// startDrain marks the table draining; no owner can be added afterwards.
// It reports false for a second DRAIN.
func (t *table) startDrain() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.draining {
		return false
	}
	t.draining = true
	return true
}

// connLost stops new owners and tells every owner to close without CLOSED.
func (t *table) connLost() {
	t.mu.Lock()
	t.lost = true
	es := make([]*entry, 0, len(t.active))
	for _, e := range t.active {
		es = append(es, e)
	}
	t.mu.Unlock()
	for _, e := range es {
		e.markConnLost()
	}
}

func (t *table) counts() (started, closed, closeErrs, discarded, badEnds uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.started, t.closed, t.closeErrs, t.discarded, t.badEnds
}
