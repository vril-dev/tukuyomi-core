package main

import (
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3/types"
)

type served struct {
	code chan int
	d    *diag
	buf  *syncBuf
}

// startServe runs serve on c in the background.
func startServe(t *testing.T, c conn, newTx func(string) types.Transaction, closeDeadline time.Duration) *served {
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

// startPiped serves one end of a pipe and returns the peer at the other end,
// after it has read the HELLO.
func startPiped(t *testing.T, newTx func(string) types.Transaction, closeDeadline time.Duration) (*peer, *served) {
	a, b := net.Pipe()
	t.Cleanup(func() { b.Close() })
	s := startServe(t, a, newTx, closeDeadline)
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
	p, s := startPiped(t, fs.newTx, time.Second)
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

func TestServeLostClean(t *testing.T) {
	fs := &fakeSet{mk: okFake}
	p, s := startPiped(t, fs.newTx, time.Second)
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
	p, s := startPiped(t, fs.newTx, 200*time.Millisecond)
	p.send(tFrame(kindTxBegin, 1, 1, defaultBegin(0).payload()))
	waitUntil(t, "the owner inside ProcessRequestHeaders", func() bool {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		return len(fs.txs) == 1 && fs.txs[0].count("phase1") == 1
	})
	p.c.Close()
	s.wait(t, exitLostTimeout)
	close(gate)
	waitUntil(t, "the stuck owner to close its transaction", func() bool { return fs.closes() == 1 })
}

func TestServeWriterStall(t *testing.T) {
	// The peer stops reading: the frame write deadline (3 s) ends the session
	// and the owner does not block on its CLOSED/VERDICT afterwards.
	fs := &fakeSet{mk: okFake}
	p, s := startPiped(t, fs.newTx, time.Second)
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
	// Four owners answer concurrently; every frame read back must be whole
	// (recv fails the test on a malformed one). A round starts only after the
	// previous round's CLOSED frames arrived (slots are released at CLOSED).
	fs := &fakeSet{mk: okFake}
	p, s := startPiped(t, fs.newTx, time.Second)
	const rounds = 10
	for r := range rounds {
		each := func(reply uint8, f func(id uint64)) {
			for i := range maxConcurTx {
				f(uint64(r*maxConcurTx + i + 1))
			}
			for range maxConcurTx {
				if o := p.recv(); o.kind != reply || o.block {
					t.Fatalf("got kind 0x%02x code %d, want 0x%02x", o.kind, o.code, reply)
				}
			}
		}
		each(kindVerdict, func(id uint64) { p.send(tFrame(kindTxBegin, id, 1, defaultBegin(4).payload())) })
		each(kindVerdict, func(id uint64) {
			p.send(tFrame(kindBody, id, 2, []byte("abcd")))
			p.send(tFrame(kindBodyEnd, id, 3, nil))
		})
		each(kindClosed, func(id uint64) { p.send(tFrame(kindTxEnd, id, 4, []byte{endComplete})) })
	}
	p.send(tFrame(kindDrain, 0, 0, nil))
	if o := p.recv(); o.kind != kindBye || o.bye != [3]uint64{rounds * maxConcurTx, rounds * maxConcurTx, 0} || fs.closes() != rounds*maxConcurTx {
		t.Fatalf("%+v closes %d", o, fs.closes())
	}
	s.wait(t, exitOK)
}

// ---- BYE versus a failure of the connection ----

// byeConn counts the BYE frames that the session starts to write and fails
// them with err.
type byeConn struct {
	net.Conn
	err  error
	byes atomic.Int32
}

func (c *byeConn) Write(p []byte) (int, error) {
	if p[4] == kindBye {
		c.byes.Add(1)
		if c.err != nil {
			return 0, c.err
		}
	}
	return c.Conn.Write(p)
}

// startBye serves a byeConn and returns it with the peer, after the HELLO.
func startBye(t *testing.T, err error, newTx func(string) types.Transaction) (*byeConn, *peer, *served) {
	a, b := net.Pipe()
	t.Cleanup(func() { b.Close() })
	c := &byeConn{Conn: a, err: err}
	s := startServe(t, c, newTx, time.Second)
	p := &peer{t: t, c: b}
	p.recv() // HELLO
	return c, p, s
}

// A failed write of BYE is a lost session, not a drain.
func TestServeByeWriteFails(t *testing.T) {
	_, p, s := startBye(t, errors.New("injected"), (&fakeSet{mk: okFake}).newTx)
	p.send(tFrame(kindDrain, 0, 0, nil))
	s.wait(t, exitLostClean)
	if !strings.Contains(s.buf.String(), "reason=write: injected") {
		t.Fatalf("diag %q", s.buf.String())
	}
}

// DRAIN is complete but the peer does not read, so BYE waits behind the
// VERDICT write; then a bad frame is a fatal failure. The session is lost
// (12), not drained, and BYE is not written.
func TestServeFatalBeforeByeIsLost(t *testing.T) {
	fs := &fakeSet{mk: okFake}
	c, p, s := startBye(t, nil, fs.newTx)
	p.send(tFrame(kindTxBegin, 1, 1, defaultBegin(0).payload()))
	p.send(tFrame(kindTxEnd, 1, 2, []byte{endComplete}))
	p.send(tFrame(kindDrain, 0, 0, nil))
	p.send(append([]byte("XKV0"), tFrame(kindDrain, 0, 0, nil)[4:]...))
	s.wait(t, exitLostClean)
	if n := c.byes.Load(); n != 0 || fs.closes() != 1 || !strings.Contains(s.buf.String(), "reason=read: ") {
		t.Fatalf("BYE started %d times, closes %d, diag %q", n, fs.closes(), s.buf.String())
	}
}
