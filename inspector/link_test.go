package main

import (
	"errors"
	"io"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3/types"
)

// ---- serve() in process over net.Pipe ----

type served struct {
	code chan int
	d    *diag
	buf  *syncBuf
}

func startServe(t *testing.T, newTx func(string) types.Transaction, closeDeadline time.Duration) (*peer, *served) {
	a, b := net.Pipe()
	t.Cleanup(func() { b.Close() })
	hello, err := encodeHello(testRun, testInc, hello{pid: 1, goVersion: "go", corazaVersion: "v", corazaSum: "s"})
	if err != nil {
		t.Fatal(err)
	}
	s := &served{code: make(chan int, 1), buf: &syncBuf{}}
	s.d = &diag{w: s.buf}
	go func() { s.code <- serve(a, testRun, testInc, hello, newTx, s.d, closeDeadline) }()
	p := &peer{t: t, c: b}
	if o := p.recv(); o.kind != kindHello {
		t.Fatalf("first frame kind 0x%02x", o.kind)
	}
	return p, s
}

func (s *served) wait(t *testing.T, want int) {
	t.Helper()
	select {
	case c := <-s.code:
		if c != want {
			t.Fatalf("exit %d, want %d (diag %q)", c, want, s.buf.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not return")
	}
}

type fakeSet struct {
	mu  sync.Mutex
	txs []*fakeTx
	mk  func() *fakeTx
}

func (f *fakeSet) newTx(string) types.Transaction {
	x := f.mk()
	f.mu.Lock()
	f.txs = append(f.txs, x)
	f.mu.Unlock()
	return x
}

func (f *fakeSet) closes() (n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, x := range f.txs {
		n += x.count("close")
	}
	return n
}

func okFake() *fakeTx { return &fakeTx{reqAccess: true, respAccess: true, respProc: true} }

func TestServeDrainAndBye(t *testing.T) {
	fs := &fakeSet{mk: okFake}
	p, s := startServe(t, fs.newTx, time.Second)
	p.send(tFrame(kindTxBegin, 1, 1, defaultBegin(0).payload()))
	expectVerdict(t, p.recv(), 1, 1, 1, false)
	p.send(tFrame(kindDrain, 0, 0, nil))
	p.send(tFrame(kindTxBegin, 2, 1, defaultBegin(0).payload()))
	expectError(t, p.recv(), 2, 1, classNotCreated, codeDraining)
	p.send(tFrame(kindDrain, 0, 0, nil)) // duplicate: ignored
	p.send(tFrame(kindBodyEnd, 1, 2, nil))
	expectVerdict(t, p.recv(), 1, 2, 2, false)
	p.send(tFrame(kindTxEnd, 1, 3, []byte{endComplete}))
	expect(t, p.recv(), kindClosed, 1, 3)
	o := p.recv()
	if o.kind != kindBye || o.bye != [3]uint64{1, 1, 0} {
		t.Fatalf("bye %+v", o)
	}
	s.wait(t, exitOK)
	if _, err := readOne(p.c); err == nil {
		t.Fatal("a frame after BYE")
	}
	if fs.closes() != 1 || !strings.Contains(s.buf.String(), "exit=0 started=1 closed=1 close_errors=0") || !strings.Contains(s.buf.String(), "dup_drain=1") {
		t.Fatalf("closes %d diag %q", fs.closes(), s.buf.String())
	}
}

func TestServeDrainEmpty(t *testing.T) {
	p, s := startServe(t, (&fakeSet{mk: okFake}).newTx, time.Second)
	p.send(tFrame(kindDrain, 0, 0, nil))
	if o := p.recv(); o.kind != kindBye || o.bye != [3]uint64{} {
		t.Fatalf("%+v", o)
	}
	s.wait(t, exitOK)
}

func TestServeLostClean(t *testing.T) {
	fs := &fakeSet{mk: okFake}
	p, s := startServe(t, fs.newTx, time.Second)
	for id := uint64(1); id <= 3; id++ {
		p.send(tFrame(kindTxBegin, id, 1, defaultBegin(0).payload()))
		p.recv()
	}
	p.c.Close()
	s.wait(t, exitLostClean)
	if fs.closes() != 3 || !strings.Contains(s.buf.String(), "exit=12 started=3 closed=3") {
		t.Fatalf("closes %d diag %q", fs.closes(), s.buf.String())
	}
}

func TestServeLostTimeout(t *testing.T) {
	gate := make(chan struct{})
	fs := &fakeSet{mk: func() *fakeTx { return &fakeTx{hdrGate: gate} }}
	p, s := startServe(t, fs.newTx, 200*time.Millisecond)
	p.send(tFrame(kindTxBegin, 1, 1, defaultBegin(0).payload()))
	time.Sleep(50 * time.Millisecond) // the owner is inside ProcessRequestHeaders
	p.c.Close()
	s.wait(t, exitLostTimeout)
	close(gate)
	deadline := time.Now().Add(5 * time.Second)
	for fs.closes() != 1 {
		if time.Now().After(deadline) {
			t.Fatal("the stuck owner never closed its transaction")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestServeConnectionWideErrors(t *testing.T) {
	cases := map[string][]byte{
		"bad magic":    append([]byte("XKV0"), tFrame(kindDrain, 0, 0, nil)[4:]...),
		"fault kind":   tFrame(0x7f, 1, 1, []byte{1}),
		"verdict kind": tFrame(kindVerdict, 1, 1, nil),
		"long body":    tHeader(kindBody, 1, 2, maxBody+1),
		"tx zero":      tFrame(kindBody, 0, 2, []byte("x")),
		"truncated":    tFrame(kindTxBegin, 1, 1, defaultBegin(0).payload())[:40],
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			fs := &fakeSet{mk: okFake}
			p, s := startServe(t, fs.newTx, time.Second)
			p.send(tFrame(kindTxBegin, 9, 1, defaultBegin(0).payload()))
			expectVerdict(t, p.recv(), 9, 1, 1, false)
			// The inspector rejects at the header and closes without reading
			// the payload, so this synchronous pipe write may fail part-way.
			p.c.SetWriteDeadline(time.Now().Add(5 * time.Second))
			p.c.Write(b)
			if name == "truncated" {
				p.c.Close() // EOF in the middle of the frame
			}
			s.wait(t, exitLostClean)
			if fs.closes() != 1 {
				t.Fatalf("closes %d", fs.closes())
			}
		})
	}
}

func TestServeWriterStall(t *testing.T) {
	// The peer stops reading: the frame write deadline (3 s) ends the session
	// and the owner does not block on its CLOSED/VERDICT afterwards.
	fs := &fakeSet{mk: okFake}
	p, s := startServe(t, fs.newTx, time.Second)
	p.send(tFrame(kindTxBegin, 1, 1, defaultBegin(0).payload()))
	start := time.Now()
	s.wait(t, exitLostClean)
	if el := time.Since(start); el < frameTimeout-100*time.Millisecond {
		t.Fatalf("ended after %v", el)
	}
	if fs.closes() != 1 {
		t.Fatalf("closes %d", fs.closes())
	}
}

func TestServeFramesNotInterleaved(t *testing.T) {
	// Four owners answer concurrently; every frame read back must be whole.
	// A round starts only after the previous round's CLOSED frames arrived
	// (slots are released at CLOSED, not at Close).
	fs := &fakeSet{mk: okFake}
	p, s := startServe(t, fs.newTx, time.Second)
	const rounds = 50
	got := map[uint8]int{}
	readN := func(n int, kind uint8) {
		t.Helper()
		for range n {
			o := p.recv() // parseOut fails the test on any malformed frame
			got[o.kind]++
			if o.kind != kind || (kind == kindVerdict && o.block) {
				t.Fatalf("got kind 0x%02x code %d, want 0x%02x", o.kind, o.code, kind)
			}
		}
	}
	id := uint64(0)
	for range rounds {
		ids := []uint64{}
		for range maxConcurTx {
			id++
			ids = append(ids, id)
			p.send(tFrame(kindTxBegin, id, 1, defaultBegin(4).payload()))
		}
		readN(maxConcurTx, kindVerdict)
		for _, x := range ids {
			p.send(tFrame(kindBody, x, 2, []byte("ab")))
			p.send(tFrame(kindBody, x, 3, []byte("cd")))
			p.send(tFrame(kindBodyEnd, x, 4, nil))
		}
		readN(maxConcurTx, kindVerdict)
		for _, x := range ids {
			p.send(tFrame(kindTxEnd, x, 5, []byte{endComplete}))
		}
		readN(maxConcurTx, kindClosed)
	}
	if got[kindVerdict] != 2*rounds*maxConcurTx || got[kindClosed] != rounds*maxConcurTx || fs.closes() != rounds*maxConcurTx {
		t.Fatalf("frames %v closes %d", got, fs.closes())
	}
	p.send(tFrame(kindDrain, 0, 0, nil))
	if o := p.recv(); o.kind != kindBye || o.bye != [3]uint64{rounds * maxConcurTx, rounds * maxConcurTx, 0} {
		t.Fatalf("%+v", o)
	}
	s.wait(t, exitOK)
}

// ---- BYE versus a connection-wide failure (a scripted connection) ----

// scriptConn is a conn that the test drives: it feeds bytes to Read, can hold
// or fail Write at a chosen frame, and reports the first Close. Write is
// always handed whole frames by writeFrame.
type scriptConn struct {
	in     chan []byte   // bytes for Read; closing it is EOF
	closed chan struct{} // closed by the first Close
	once   sync.Once
	rbuf   []byte                 // only the reader goroutine uses it
	hook   func(kind uint8) error // called inside Write; may block
	mu     sync.Mutex
	kinds  []uint8 // the kind of every frame handed to Write
}

func newScriptConn(hook func(kind uint8) error) *scriptConn {
	return &scriptConn{in: make(chan []byte, 16), closed: make(chan struct{}), hook: hook}
}

func (c *scriptConn) feed(b []byte) { c.in <- b }

func (c *scriptConn) Read(p []byte) (int, error) {
	if len(c.rbuf) == 0 {
		select {
		case b, ok := <-c.in:
			if !ok {
				return 0, io.EOF
			}
			c.rbuf = b
		case <-c.closed:
			return 0, net.ErrClosed
		}
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

func (c *scriptConn) Write(p []byte) (int, error) {
	if len(p) < headerLen {
		return 0, errors.New("short frame")
	}
	c.mu.Lock()
	c.kinds = append(c.kinds, p[4])
	c.mu.Unlock()
	if c.hook != nil {
		if err := c.hook(p[4]); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (c *scriptConn) Close() error                     { c.once.Do(func() { close(c.closed) }); return nil }
func (c *scriptConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptConn) SetWriteDeadline(time.Time) error { return nil }

func (c *scriptConn) wrote(kind uint8) (n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, k := range c.kinds {
		if k == kind {
			n++
		}
	}
	return n
}

func waitCh(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// holdAt returns a Write hook that holds the first frame of the given kind
// until release is called (or 10 s pass), and the channel that reports the hold.
func holdAt(t *testing.T, kind uint8) (hook func(uint8) error, held <-chan struct{}, release func()) {
	h, rel := make(chan struct{}), make(chan struct{})
	var holdOnce, relOnce sync.Once
	release = func() { relOnce.Do(func() { close(rel) }) }
	t.Cleanup(release)
	hook = func(k uint8) error {
		if k == kind {
			holdOnce.Do(func() { close(h) })
			select {
			case <-rel:
			case <-time.After(10 * time.Second):
			}
		}
		return nil
	}
	return hook, h, release
}

// waitParked waits until a goroutine running serve is blocked in a select
// inside fn (as printed in a goroutine dump); goroutines that other tests
// left behind do not count.
func waitParked(t *testing.T, fn string) {
	t.Helper()
	buf := make([]byte, 1<<20)
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(time.Millisecond) {
		for _, g := range strings.Split(string(buf[:runtime.Stack(buf, true)]), "\n\n") {
			if strings.Contains(g, "[select") && strings.Contains(g, fn) && strings.Contains(g, ".serve(") {
				return
			}
		}
	}
	t.Fatalf("no goroutine of serve is blocked in %s", fn)
}

func startScripted(t *testing.T, c *scriptConn, newTx func(string) types.Transaction, closeDeadline time.Duration) *served {
	t.Helper()
	t.Cleanup(func() { c.Close() })
	hello, err := encodeHello(testRun, testInc, hello{pid: 1, goVersion: "go", corazaVersion: "v", corazaSum: "s"})
	if err != nil {
		t.Fatal(err)
	}
	s := &served{code: make(chan int, 1), buf: &syncBuf{}}
	s.d = &diag{w: s.buf}
	go func() { s.code <- serve(c, testRun, testInc, hello, newTx, s.d, closeDeadline) }()
	return s
}

func badMagic() []byte { return append([]byte("XKV0"), tFrame(kindDrain, 0, 0, nil)[4:]...) }

func TestLinkFatalBeforeByeWritesNothing(t *testing.T) {
	// Once the link is lost and the held write is released, the writer's
	// select picks at random between the queue and the loss: repeat so that a
	// missing check is caught every time.
	for i := 0; i < 32; i++ {
		t.Run(strconv.Itoa(i), linkFatalBeforeBye)
	}
}

func linkFatalBeforeBye(t *testing.T) {
	// A frame that is not final and then BYE wait behind a held CLOSED write; a
	// fatal failure closes the link; when the write is released the writer must
	// start neither of them.
	hook, held, release := holdAt(t, kindClosed)
	c := newScriptConn(hook)
	l := newLink(c)
	t.Cleanup(func() { l.fail("test end") }) // stops the writer if the test stops early
	writerDone := make(chan struct{})
	go func() { l.writer(); close(writerDone) }()
	if !l.send(encodeClosed(testRun, testInc, 1, 2, false)) {
		t.Fatal("send refused")
	}
	waitCh(t, held, "the CLOSED write")
	if !l.send(encodeClosed(testRun, testInc, 3, 4, false)) { // not final, queued before BYE
		t.Fatal("second send refused")
	}
	bye := make(chan bool, 1)
	go func() { bye <- l.sendWait(encodeBye(testRun, testInc, 0, 0, 0), true) }()
	for end := time.Now().Add(5 * time.Second); len(l.out) != 2; time.Sleep(time.Millisecond) {
		if time.Now().After(end) {
			t.Fatal("BYE was not queued")
		}
	}
	l.fail("read: bad magic")
	if l.begin(false) || l.begin(true) {
		t.Fatal("begin allows a frame after the fatal failure")
	}
	waitCh(t, c.closed, "Close")
	release()
	waitCh(t, writerDone, "the writer to return")
	if n := c.wrote(kindBye); n != 0 {
		t.Fatalf("BYE written %d times after the fatal failure", n)
	}
	if n := c.wrote(kindClosed); n != 1 {
		t.Fatalf("CLOSED written %d times; only the held write may have started", n)
	}
	select {
	case ok := <-bye:
		if ok {
			t.Fatal("sendWait reported BYE written")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sendWait did not return")
	}
}

func TestLinkRefusesSendAfterFatal(t *testing.T) {
	// The writer is not started and the queue has room: once the fatal failure
	// closed the link, send and sendWait must still accept nothing.
	l := newLink(newScriptConn(nil))
	l.fail("x")
	for i := 0; i < 200; i++ {
		if l.send(encodeClosed(testRun, testInc, 1, 2, false)) {
			t.Fatalf("send %d accepted after the fatal failure", i)
		}
	}
	if n := len(l.out); n != 0 {
		t.Fatalf("%d frames queued after the fatal failure", n)
	}
	res := make(chan bool, 1)
	go func() {
		accepted := false
		for i := 0; i < 200; i++ {
			accepted = l.sendWait(encodeBye(testRun, testInc, 0, 0, 0), i%2 == 0) || accepted
		}
		res <- accepted
	}()
	select {
	case accepted := <-res:
		if accepted {
			t.Fatal("sendWait reported a frame written after the fatal failure")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sendWait did not return")
	}
	if n := len(l.out); n != 0 {
		t.Fatalf("%d frames queued by sendWait after the fatal failure", n)
	}
}

func TestServeFatalBeforeByeIsLost(t *testing.T) {
	// The writer's select (lost or queued) and sendWait's (lost or ack) pick at
	// random when both are ready: repeat so that a missing check is caught every
	// time.
	for i := 0; i < 32; i++ {
		t.Run(strconv.Itoa(i), serveFatalBeforeBye)
	}
}

func serveFatalBeforeBye(t *testing.T) {
	// After DRAIN, BYE is queued behind a held CLOSED write. A bad magic is a
	// connection-wide failure; it closes the connection before the write is
	// released. The session is lost (12), not drained, and BYE is not written.
	hook, held, release := holdAt(t, kindClosed)
	c := newScriptConn(hook)
	fs := &fakeSet{mk: okFake}
	s := startScripted(t, c, fs.newTx, time.Second)
	c.feed(tFrame(kindTxBegin, 1, 1, defaultBegin(0).payload()))
	c.feed(tFrame(kindTxEnd, 1, 2, []byte{endComplete}))
	waitCh(t, held, "the CLOSED write")
	c.feed(tFrame(kindDrain, 0, 0, nil))
	waitParked(t, "(*link).sendWait") // serve queued BYE and waits for it
	c.feed(badMagic())
	waitCh(t, c.closed, "Close")
	release()
	s.wait(t, exitLostClean)
	if n := c.wrote(kindBye); n != 0 {
		t.Fatalf("BYE written %d times after the fatal failure (diag %q)", n, s.buf.String())
	}
	if fs.closes() != 1 || !strings.Contains(s.buf.String(), "exit=12 ") || !strings.Contains(s.buf.String(), "reason=read: ") {
		t.Fatalf("closes %d diag %q", fs.closes(), s.buf.String())
	}
}

func TestServePeerClosesDuringBye(t *testing.T) {
	// Repeated for the same reason as TestServeFatalBeforeByeIsLost.
	for i := 0; i < 32; i++ {
		t.Run(strconv.Itoa(i), servePeerClosesDuringBye)
	}
}

func servePeerClosesDuringBye(t *testing.T) {
	// The peer reads BYE and closes; the reader's EOF closes the connection
	// while the BYE write is still in progress. The written BYE stands.
	var c *scriptConn
	c = newScriptConn(func(kind uint8) error {
		if kind == kindBye {
			close(c.in)
			select {
			case <-c.closed: // the reader's failure has closed the connection
			case <-time.After(5 * time.Second):
				return errors.New("the reader did not close the connection")
			}
		}
		return nil
	})
	s := startScripted(t, c, (&fakeSet{mk: okFake}).newTx, time.Second)
	c.feed(tFrame(kindDrain, 0, 0, nil))
	s.wait(t, exitOK)
	if !strings.Contains(s.buf.String(), "exit=0 ") || !strings.HasSuffix(strings.TrimSpace(s.buf.String()), "reason=drained") || c.wrote(kindBye) != 1 {
		t.Fatalf("diag %q", s.buf.String())
	}
}

func TestServeByeWriteFails(t *testing.T) {
	for _, closedFirst := range []bool{false, true} {
		name := "write error"
		if closedFirst {
			name = "write error after the peer closed"
		}
		t.Run(name, func(t *testing.T) {
			var c *scriptConn
			c = newScriptConn(func(kind uint8) error {
				if kind != kindBye {
					return nil
				}
				if closedFirst {
					close(c.in)
					select {
					case <-c.closed:
					case <-time.After(5 * time.Second):
						return errors.New("the reader did not close the connection")
					}
				}
				return errors.New("injected")
			})
			s := startScripted(t, c, (&fakeSet{mk: okFake}).newTx, time.Second)
			c.feed(tFrame(kindDrain, 0, 0, nil))
			s.wait(t, exitLostClean)
			if !strings.Contains(s.buf.String(), "exit=12 ") || !strings.Contains(s.buf.String(), "reason=write: injected") {
				t.Fatalf("diag %q", s.buf.String())
			}
		})
	}
}
