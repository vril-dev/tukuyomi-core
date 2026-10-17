package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

// TestMain doubles as the inspector (and a spawner) for the process tests:
// the test binary re-executes itself with TKV0_TEST_MODE set.
func TestMain(m *testing.M) {
	switch os.Getenv("TKV0_TEST_MODE") {
	case "inspector":
		var args []string
		if p := os.Getenv("TKV0_TEST_RULES"); p != "" {
			args = []string{p}
		}
		os.Exit(run(args))
	case "spawner": // the inspector's parent is not the socket's creator
		cmd := exec.Command(os.Args[0])
		env := []string{}
		for _, kv := range os.Environ() {
			if !strings.HasPrefix(kv, "TKV0_TEST_MODE=") {
				env = append(env, kv)
			}
		}
		cmd.Env = append(env, "TKV0_TEST_MODE=inspector")
		cmd.Stdin, cmd.Stderr = os.Stdin, os.Stderr
		if err := cmd.Run(); err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				os.Exit(ee.ExitCode())
			}
			os.Exit(99)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestParseConfig(t *testing.T) {
	tmp := t.TempDir()
	env := map[string]string{
		"TKV0_RUN_ID":      "0102030405060708",
		"TKV0_INCARNATION": "00000007",
		"TKV0_NONCE":       "000102030405060708090a0b0c0d0e0f",
		"TMPDIR":           tmp,
	}
	get := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	c, err := parseConfig([]string{"/r/rules.conf"}, get(env))
	if err != nil || c.run != testRun || c.inc != testInc || c.nonce[15] != 0x0f || c.rulesPath != "/r/rules.conf" {
		t.Fatalf("%+v %v", c, err)
	}
	with := func(k, v string) map[string]string {
		m := map[string]string{}
		for a, b := range env {
			m[a] = b
		}
		m[k] = v
		return m
	}
	bad := map[string]map[string]string{
		"run upper":   with("TKV0_RUN_ID", "0102030405060A08"),
		"run short":   with("TKV0_RUN_ID", "010203040506070"),
		"run long":    with("TKV0_RUN_ID", "01020304050607080"),
		"run sign":    with("TKV0_RUN_ID", "+102030405060708"),
		"run empty":   with("TKV0_RUN_ID", ""),
		"inc short":   with("TKV0_INCARNATION", "7"),
		"inc space":   with("TKV0_INCARNATION", " 0000007"),
		"nonce short": with("TKV0_NONCE", "00"),
		"nonce g":     with("TKV0_NONCE", "g00102030405060708090a0b0c0d0e0"),
		"tmp empty":   with("TMPDIR", ""),
		"tmp rel":     with("TMPDIR", "tmp"),
		"tmp unclean": with("TMPDIR", tmp+"/"),
		"tmp missing": with("TMPDIR", filepath.Join(tmp, "nope")),
	}
	for name, m := range bad {
		if _, err := parseConfig([]string{"/r/rules.conf"}, get(m)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	for name, args := range map[string][]string{"none": nil, "two": {"/a", "/b"}, "relative": {"rules.conf"}, "unclean": {"/r/../rules.conf"}, "empty": {""}} {
		if _, err := parseConfig(args, get(env)); err == nil {
			t.Errorf("args %s accepted", name)
		}
	}
}

func TestCheckTmpDir(t *testing.T) {
	base := t.TempDir()
	d := filepath.Join(base, "d")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := checkTmpDir(d); err != nil {
		t.Fatalf("0700: %v", err)
	}
	if err := os.Chmod(d, 0o500); err != nil {
		t.Fatal(err)
	}
	if err := checkTmpDir(d); err != nil { // writability is NewWAF's check
		t.Fatalf("0500: %v", err)
	}
	for _, m := range []os.FileMode{0o710, 0o701, 0o770, 0o777} {
		os.Chmod(d, m)
		if err := checkTmpDir(d); err == nil {
			t.Errorf("mode %o accepted", m)
		}
	}
	os.Chmod(d, 0o700)
	link := filepath.Join(base, "link")
	if err := os.Symlink(d, link); err != nil {
		t.Fatal(err)
	}
	if err := checkTmpDir(link); err == nil {
		t.Error("symlink accepted")
	}
	f := filepath.Join(base, "file")
	os.WriteFile(f, nil, 0o600)
	if err := checkTmpDir(f); err == nil {
		t.Error("file accepted")
	}
}

func TestReadRules(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "r.conf")
	os.WriteFile(p, []byte("SecRuleEngine On\n"), 0o400)
	if b, err := readRules(p); err != nil || string(b) != "SecRuleEngine On\n" {
		t.Fatalf("%q %v", b, err)
	}
	big := filepath.Join(d, "big.conf")
	os.WriteFile(big, make([]byte, maxRulesBytes+1), 0o400)
	if _, err := readRules(big); err == nil {
		t.Error("oversized rules accepted")
	}
	exact := filepath.Join(d, "exact.conf")
	os.WriteFile(exact, make([]byte, maxRulesBytes), 0o400)
	if _, err := readRules(exact); err != nil {
		t.Errorf("rules at the limit: %v", err)
	}
	link := filepath.Join(d, "link.conf")
	os.Symlink(p, link)
	if _, err := readRules(link); err == nil {
		t.Error("symlink accepted")
	}
	if _, err := readRules(d); err == nil {
		t.Error("directory accepted")
	}
	if _, err := readRules(filepath.Join(d, "missing")); err == nil {
		t.Error("missing accepted")
	}
	// Several reads: the bytes must be exactly the file (the descriptor is
	// opened non-blocking).
	patt := filepath.Join(d, "patt.conf")
	want := bytes.Repeat([]byte("SecRuleEngine On\n"), 4000)
	os.WriteFile(patt, want, 0o400)
	if b, err := readRules(patt); err != nil || !bytes.Equal(b, want) {
		t.Errorf("multi-read rules: %d bytes, err %v", len(b), err)
	}
	// A FIFO must be rejected without waiting for a writer.
	fifo := filepath.Join(d, "r.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	res := make(chan error, 1)
	go func() { _, err := readRules(fifo); res <- err }()
	select {
	case err := <-res:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("FIFO: err %v, want the fstat rejection (not a regular file)", err)
		}
	case <-time.After(5 * time.Second):
		// Release the open that waits for a writer so no goroutine is left.
		if w, err := syscall.Open(fifo, syscall.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			syscall.Close(w)
		}
		select {
		case <-res:
		case <-time.After(5 * time.Second):
		}
		t.Fatal("readRules waited on a FIFO")
	}
}

func TestCheckPeerInProcess(t *testing.T) {
	// A socketpair made by this process: the peer pid is ours, not our parent.
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fds[0])
	defer syscall.Close(fds[1])
	if err := checkPeer(fds[1]); err == nil || !strings.Contains(err.Error(), "parent") {
		t.Fatalf("got %v", err)
	}
	dg, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(dg[0])
	defer syscall.Close(dg[1])
	if err := checkPeer(dg[1]); err == nil || !strings.Contains(err.Error(), "stream") {
		t.Fatalf("dgram: %v", err)
	}
	r, w, _ := os.Pipe()
	defer r.Close()
	defer w.Close()
	if err := checkPeer(int(r.Fd())); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("pipe: %v", err)
	}
}

func TestCorazaModule(t *testing.T) {
	v, s, err := corazaModule()
	if err != nil || !strings.HasPrefix(v, "v3.") || !strings.HasPrefix(s, "h1:") {
		t.Fatalf("%q %q %v", v, s, err)
	}
}

func TestDiag(t *testing.T) {
	var b bytes.Buffer
	d := &diag{w: &b}
	d.printf("a\nb\x00c\\%s", strings.Repeat("x", 2000))
	line := b.String()
	if strings.Count(line, "\n") != 1 || !strings.HasSuffix(line, "\n") || strings.ContainsRune(line[:len(line)-1], 0) || len(line) > maxDiagLine+8 {
		t.Fatalf("line %q", line)
	}
	if !strings.Contains(line, `a\x0ab\x00c\x5c`) {
		t.Fatalf("escaping %q", line[:40])
	}
	ew := &errWriter{}
	d = &diag{w: ew}
	d.printf("one")
	d.printf("two")
	d.printf("three")
	if ew.calls != 1 || !d.broken || d.dropped != 3 {
		t.Fatalf("calls %d broken %v dropped %d", ew.calls, d.broken, d.dropped)
	}
}

type errWriter struct{ calls int }

func (e *errWriter) Write(p []byte) (int, error) { e.calls++; return 0, syscall.EPIPE }

// ---- serve() in process over net.Pipe ----

type peer struct {
	t *testing.T
	c net.Conn
}

func (p *peer) send(b []byte) {
	p.t.Helper()
	p.c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := p.c.Write(b); err != nil {
		p.t.Fatalf("peer write: %v", err)
	}
}

func readOne(c net.Conn) ([]byte, error) {
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	h := make([]byte, headerLen)
	if _, err := io.ReadFull(c, h); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(h[8:])
	if n > 64*1024 {
		return nil, errors.New("too long")
	}
	b := make([]byte, headerLen+int(n))
	copy(b, h)
	if _, err := io.ReadFull(c, b[headerLen:]); err != nil {
		return nil, err
	}
	return b, nil
}

func (p *peer) recv() out {
	p.t.Helper()
	b, err := readOne(p.c)
	if err != nil {
		p.t.Fatalf("peer read: %v", err)
	}
	o, err := parseOut(b)
	if err != nil {
		p.t.Fatalf("peer parse: %v", err)
	}
	return o
}

type served struct {
	code chan int
	d    *diag
	buf  *syncBuf
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
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

// ---- the real process: fd 0 socketpair, peer check, exit codes ----

const testNonceHex = "000102030405060708090a0b0c0d0e0f"

type proc struct {
	cmd    *exec.Cmd
	c      net.Conn
	stderr *syncBuf
	rules  []byte
}

type procOpt struct {
	mode    string // "inspector" (default) or "spawner"
	env     map[string]string
	rules   string // file content; "" means baseRules
	noRules bool
	stdin   *os.File // overrides the socketpair
	dgram   bool
	stderr  io.Writer
}

func startProc(t *testing.T, o procOpt) *proc {
	t.Helper()
	dir := t.TempDir()
	tmp := filepath.Join(dir, "tmp")
	if err := os.Mkdir(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	rules := o.rules
	if rules == "" {
		rules = baseRules
	}
	rp := filepath.Join(dir, "rules.conf")
	if err := os.WriteFile(rp, []byte(rules), 0o400); err != nil {
		t.Fatal(err)
	}
	mode := o.mode
	if mode == "" {
		mode = "inspector"
	}
	env := map[string]string{
		"TKV0_TEST_MODE": mode, "TKV0_TEST_RULES": rp,
		"TKV0_RUN_ID": "0102030405060708", "TKV0_INCARNATION": "00000007", "TKV0_NONCE": testNonceHex,
		"TMPDIR": tmp, "GOMAXPROCS": "2", "GOMEMLIMIT": "256MiB",
	}
	if o.noRules {
		delete(env, "TKV0_TEST_RULES")
	}
	for k, v := range o.env {
		if v == "\x00unset" {
			delete(env, k)
		} else {
			env[k] = strings.ReplaceAll(v, "$TMP", tmp)
		}
	}
	cmd := exec.Command(os.Args[0])
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	p := &proc{cmd: cmd, stderr: &syncBuf{}, rules: []byte(rules)}
	cmd.Stderr = p.stderr
	if o.stderr != nil {
		cmd.Stderr = o.stderr
	}
	var child *os.File
	if o.stdin != nil {
		cmd.Stdin = o.stdin
	} else {
		typ := syscall.SOCK_STREAM
		if o.dgram {
			typ = syscall.SOCK_DGRAM
		}
		fds, err := syscall.Socketpair(syscall.AF_UNIX, typ|syscall.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		child = os.NewFile(uintptr(fds[1]), "child")
		mine := os.NewFile(uintptr(fds[0]), "mine")
		c, err := net.FileConn(mine)
		mine.Close()
		if err != nil {
			t.Fatal(err)
		}
		p.c = c
		cmd.Stdin = child
		t.Cleanup(func() { c.Close() })
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if child != nil {
		child.Close()
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	return p
}

func (p *proc) exit(t *testing.T) int {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- p.cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			return 0
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
				t.Fatalf("killed by signal %v (stderr %q)", ws.Signal(), p.stderr.String())
			}
			return ee.ExitCode()
		}
		t.Fatalf("wait: %v", err)
	case <-time.After(20 * time.Second):
		t.Fatal("inspector did not exit")
	}
	return -1
}

func (p *proc) frame(t *testing.T) []byte {
	t.Helper()
	b, err := readOne(p.c)
	if err != nil {
		t.Fatalf("read: %v (stderr %q)", err, p.stderr.String())
	}
	return b
}

func TestProcessHappyPath(t *testing.T) {
	p := startProc(t, procOpt{})
	b := p.frame(t)
	if b[4] != kindHello || binary.BigEndian.Uint64(b[24:]) != 0 || binary.BigEndian.Uint32(b[32:]) != 0 {
		t.Fatalf("not a HELLO: %x", b[:36])
	}
	pl := b[headerLen:]
	off := 0
	u16 := func() uint16 { v := binary.BigEndian.Uint16(pl[off:]); off += 2; return v }
	u32 := func() uint32 { v := binary.BigEndian.Uint32(pl[off:]); off += 4; return v }
	u64 := func() uint64 { v := binary.BigEndian.Uint64(pl[off:]); off += 8; return v }
	raw := func(n int) []byte { v := pl[off : off+n]; off += n; return v }
	str := func() string {
		s, err := rdStr(pl, &off)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	ver, pid := u16(), u32()
	nonce, run, inc := raw(16), u64(), u32()
	gov, cv, cs := str(), str(), str()
	sha := raw(32)
	bodyLimit, mem, procs, conc, queue := u32(), u64(), u16(), u16(), u16()
	if off != len(pl) {
		t.Fatalf("hello trailing %d", len(pl)-off)
	}
	wantSHA := sha256.Sum256(p.rules)
	bi, _ := debug.ReadBuildInfo()
	var dv, ds string
	for _, m := range bi.Deps {
		if m.Path == corazaModulePath {
			dv, ds = m.Version, m.Sum
		}
	}
	if ver != 0 || int(pid) != p.cmd.Process.Pid || !bytes.Equal(nonce, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}) ||
		run != testRun || inc != testInc || gov != runtime.Version() || cv != dv || cs != ds || !bytes.Equal(sha, wantSHA[:]) ||
		bodyLimit != maxDeclared || mem != 256<<20 || procs != 2 || conc != maxConcurTx || queue != queueDepth {
		t.Fatalf("hello: ver %d pid %d/%d run %x inc %d go %s coraza %s %s body %d mem %d procs %d conc %d q %d",
			ver, pid, p.cmd.Process.Pid, run, inc, gov, cv, cs, bodyLimit, mem, procs, conc, queue)
	}
	pr := &peer{t: t, c: p.c}
	pr.send(tFrame(kindTxBegin, 1, 1, defaultBegin(0).payload()))
	expectVerdict(t, pr.recv(), 1, 1, 1, false)
	pr.send(tFrame(kindBodyEnd, 1, 2, nil))
	expectVerdict(t, pr.recv(), 1, 2, 2, false)
	pr.send(tFrame(kindTxEnd, 1, 3, []byte{endComplete}))
	expect(t, pr.recv(), kindClosed, 1, 3)
	pr.send(tFrame(kindDrain, 0, 0, nil))
	if o := pr.recv(); o.kind != kindBye || o.bye != [3]uint64{1, 1, 0} {
		t.Fatalf("%+v", o)
	}
	if c := p.exit(t); c != exitOK {
		t.Fatalf("exit %d stderr %q", c, p.stderr.String())
	}
	if !strings.Contains(p.stderr.String(), "exit=0 started=1 closed=1 close_errors=0") {
		t.Fatalf("stderr %q", p.stderr.String())
	}
}

// A JSON body through the whole path: the start (checkRules accepts the depth
// limit of the operator, newWAF replaces it), the protocol, begin that sets
// the JSON processor, a rule of the operator on an argument of the body, and
// the reserved rule on a body that nests deeper than the reserved limit.
func TestProcessJSONBody(t *testing.T) {
	p := startProc(t, procOpt{rules: baseRules + bigBody + "SecRequestBodyJsonDepthLimit 1024\n" + jsonProbeRule})
	p.frame(t) // HELLO
	pr := &peer{t: t, c: p.c}
	cases := []struct {
		body string
		rule int64 // 0: Continue
	}{
		{jsonBody("block"), 9203},
		{jsonBody("fine"), 0},
		{nestedJSON(64, "fine"), 0},
		{nestedJSON(65, "fine"), 4000001},
	}
	for i, c := range cases {
		tx := uint64(i + 1)
		pr.send(tFrame(kindTxBegin, tx, 1, jsonBegin(uint64(len(c.body))).payload()))
		expectVerdict(t, pr.recv(), tx, 1, 1, false)
		pr.send(tFrame(kindBody, tx, 2, []byte(c.body)))
		pr.send(tFrame(kindBodyEnd, tx, 3, nil))
		o := pr.recv()
		expectVerdict(t, o, tx, 3, 2, c.rule != 0)
		if c.rule != 0 && (o.rule != c.rule || o.stat != 403) {
			t.Fatalf("body %d: %+v", i, o)
		}
		pr.send(tFrame(kindTxEnd, tx, 4, []byte{endComplete}))
		expect(t, pr.recv(), kindClosed, tx, 4)
	}
	pr.send(tFrame(kindDrain, 0, 0, nil))
	if o := pr.recv(); o.kind != kindBye || o.bye != [3]uint64{uint64(len(cases)), uint64(len(cases)), 0} {
		t.Fatalf("%+v", o)
	}
	if c := p.exit(t); c != exitOK {
		t.Fatalf("exit %d stderr %q", c, p.stderr.String())
	}
}

func TestProcessExitCodes(t *testing.T) {
	r, w, _ := os.Pipe()
	defer r.Close()
	defer w.Close()
	fifo := filepath.Join(t.TempDir(), "rules.fifo") // no writer ever opens it
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		opt  procOpt
		want int
	}{
		{"stdin is a pipe", procOpt{stdin: r}, exitPeer},
		{"dgram socketpair", procOpt{dgram: true}, exitPeer},
		{"parent is not the creator", procOpt{mode: "spawner"}, exitPeer},
		{"no rules arg", procOpt{noRules: true}, exitStartup},
		{"relative rules", procOpt{env: map[string]string{"TKV0_TEST_RULES": "rules.conf"}}, exitStartup},
		{"bad run id", procOpt{env: map[string]string{"TKV0_RUN_ID": "0102030405060708x"}}, exitStartup},
		{"no nonce", procOpt{env: map[string]string{"TKV0_NONCE": "\x00unset"}}, exitStartup},
		{"no tmpdir", procOpt{env: map[string]string{"TMPDIR": "\x00unset"}}, exitStartup},
		{"missing rules", procOpt{env: map[string]string{"TKV0_TEST_RULES": "/nonexistent/tkv0/rules.conf"}}, exitRules},
		{"rules is a FIFO", procOpt{env: map[string]string{"TKV0_TEST_RULES": fifo}}, exitRules},
		{"bad directive", procOpt{rules: "SecRuleEngine On\nSecNoSuchDirective 1\n"}, exitRules},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := startProc(t, c.opt)
			if got := p.exit(t); got != c.want {
				t.Fatalf("exit %d want %d stderr %q", got, c.want, p.stderr.String())
			}
			if c.name == "rules is a FIFO" && !strings.Contains(p.stderr.String(), "start: rules: not a regular file") {
				t.Fatalf("FIFO not rejected by the fstat check: stderr %q", p.stderr.String())
			}
			if p.c != nil {
				if _, err := readOne(p.c); err == nil {
					t.Fatal("a frame was sent")
				}
			}
		})
	}
}

func TestProcessUnwritableTmp(t *testing.T) {
	dir := t.TempDir()
	ro := filepath.Join(dir, "ro")
	os.Mkdir(ro, 0o500)
	t.Cleanup(func() { os.Chmod(ro, 0o700) })
	p := startProc(t, procOpt{env: map[string]string{"TMPDIR": ro}})
	if got := p.exit(t); got != exitRules {
		t.Fatalf("exit %d stderr %q", got, p.stderr.String())
	}
}

func TestProcessLostAndFault(t *testing.T) {
	for name, send := range map[string][]byte{
		"eof":         nil,
		"fault kind":  tFrame(0x7f, 0, 0, nil),
		"bad version": append([]byte("TKV1"), tFrame(kindDrain, 0, 0, nil)[4:]...),
	} {
		t.Run(name, func(t *testing.T) {
			p := startProc(t, procOpt{})
			p.frame(t) // HELLO
			pr := &peer{t: t, c: p.c}
			pr.send(tFrame(kindTxBegin, 1, 1, defaultBegin(0).payload()))
			expectVerdict(t, pr.recv(), 1, 1, 1, false)
			if send != nil {
				pr.send(send)
			} else {
				p.c.Close()
			}
			if c := p.exit(t); c != exitLostClean {
				t.Fatalf("exit %d stderr %q", c, p.stderr.String())
			}
			if !strings.Contains(p.stderr.String(), "exit=12 started=1 closed=1") {
				t.Fatalf("stderr %q", p.stderr.String())
			}
		})
	}
}

func TestProcessFrameDeadline(t *testing.T) {
	p := startProc(t, procOpt{})
	p.frame(t)
	p.c.Write([]byte("T")) // first byte, then nothing
	start := time.Now()
	if c := p.exit(t); c != exitLostClean {
		t.Fatalf("exit %d", c)
	}
	if el := time.Since(start); el < frameTimeout-200*time.Millisecond || el > frameTimeout+3*time.Second {
		t.Fatalf("ended after %v", el)
	}
}

func TestProcessBrokenStderr(t *testing.T) {
	// stderr's reader is gone: the final diagnostic write gets EPIPE instead of
	// SIGPIPE killing the process, and the close-down still completes.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	p := startProc(t, procOpt{stderr: w})
	w.Close()
	r.Close()
	p.frame(t)
	pr := &peer{t: t, c: p.c}
	pr.send(tFrame(kindTxBegin, 1, 1, defaultBegin(0).payload()))
	expectVerdict(t, pr.recv(), 1, 1, 1, false)
	p.c.Close()
	if c := p.exit(t); c != exitLostClean {
		t.Fatalf("exit %d", c)
	}
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

// ---- checkRules, withoutPath ----

// rawEffect builds the text with Coraza alone (no reserved directives), runs
// the headers phase and reports whether the effect that checkRules guards
// against happened: the rule engine is off ("engine"), the body access is off
// ("body"), a rule of an included file blocked the GET ("include") or, for
// "ignore", two rules with one id after the text build: Coraza reads the text
// as SecIgnoreRuleCompilationErrors On and drops the second rule (no
// transaction is run).
func rawEffect(t *testing.T, kind, rules string) bool {
	t.Helper()
	t.Setenv("TMPDIR", t.TempDir())
	if kind == "ignore" {
		rules += dupPass + dupDeny
	}
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives("SecRuleEngine On\nSecRequestBodyAccess On\n" + rules))
	if kind == "ignore" {
		return err == nil
	}
	if err != nil {
		t.Fatalf("Coraza does not accept the text: %v", err)
	}
	tx := waf.NewTransaction()
	defer tx.Close()
	tx.ProcessConnection("127.0.0.1", 1, "127.0.0.1", 2)
	tx.ProcessURI("/", "GET", "HTTP/1.1")
	it := tx.ProcessRequestHeaders()
	tx.ProcessLogging()
	switch kind {
	case "engine":
		return tx.IsRuleEngineOff()
	case "body":
		return !tx.IsRequestBodyAccessible()
	}
	return it != nil
}

func TestCheckRules(t *testing.T) {
	inc := filepath.Join(t.TempDir(), "extra.conf")
	if err := os.WriteFile(inc, []byte("SecRule REQUEST_METHOD \"@streq GET\" \"id:77,phase:1,deny\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const act = `SecAction "id:1,phase:1,pass,`
	// Every row is rejected. A row with a kind is a spelling that Coraza v3.8.1
	// evaluates as the ctl, the Include or the SecIgnoreRuleCompilationErrors On
	// that checkRules guards against: rawEffect shows its effect in Coraza. A row
	// without a kind is either a false reject by design: Coraza gets no
	// observable effect from it, or does not read it as the directive with On
	// (Off, no argument), and telling On from Off would need a parser of the
	// argument; or a row of the name and word guards (the SecAuditLog,
	// SecDebugLog and SecUpload directives, @inspectFile, @rbl, setenv and
	// ctl:requestBodyLimit), whose effect is a file, a program, a DNS query or
	// the environment and is not run here.
	reject := []struct{ name, kind, rules string }{
		{"plain", "engine", act + "ctl:ruleEngine=Off\"\n"},
		{"DetectionOnly value (no observable effect)", "", act + "ctl:ruleEngine=DetectionOnly\"\n"},
		{"space before colon", "engine", act + "ctl :ruleEngine=Off\"\n"},
		{"space after colon", "engine", act + "ctl: ruleEngine=Off\"\n"},
		{"single quotes", "engine", act + "ctl:'ruleEngine=Off'\"\n"},
		{"no-break space", "engine", act + "ctl: ruleEngine=Off\"\n"},
		{"upper case key", "engine", act + "CTL:ruleEngine=Off\"\n"},
		{"continuation inside the name", "engine", act + "ctl:rule\\\nEngine=Off\"\n"},
		{"comment line inside a continuation", "engine", act + "ctl:rule\\\n# note\nEngine=Off\"\n"},
		{"backtick block", "engine", "SecAction id:1,phase:1,pass,msg:'`\n',ctl:\nruleEngine=Off,msg:'\n`'\n"},
		{"body access", "body", act + "ctl:requestBodyAccess=Off\"\n"},
		{"body access split", "body", act + "ctl:request\\\nBodyAccess=Off\"\n"},
		{"Include", "include", "Include " + inc + "\n"},
		{"include lower case", "include", "include " + inc + "\n"},
		{"dotted capital I", "include", "İnclude " + inc + "\n"},
		{"Include split by a continuation", "include", "Inc\\\nlude " + inc + "\n"},
		{"Include after a comment line", "include", "# note\nInclude " + inc + "\n"},
		{"SecIgnoreRuleCompilationErrors On", "ignore", "SecIgnoreRuleCompilationErrors On\n"},
		{"SecIgnoreRuleCompilationErrors Off", "", "SecIgnoreRuleCompilationErrors Off\n"},
		{"ignore errors without an argument", "", "SecIgnoreRuleCompilationErrors\n"},
		{"ignore errors with a quoted argument", "ignore", "SecIgnoreRuleCompilationErrors \"On\"\n"},
		{"ignore errors mixed case", "ignore", "secIGNORErulecompilationERRORS on\n"},
		{"ignore errors upper case", "", "SECIGNORERULECOMPILATIONERRORS OFF\n"},
		{"ignore errors dotted capital I", "ignore", "Secİgnorerulecompilationerrors On\n"},
		{"ignore errors split by a continuation", "ignore", "SecIgnoreRule\\\nCompilationErrors On\n"},
		{"ignore errors after a comment line", "ignore", "# note\nSecIgnoreRuleCompilationErrors On\n"},
		{"ignore errors after white space", "ignore", " \t SecIgnoreRuleCompilationErrors On\n"},
		{"ignore errors after rules", "", baseRules + "SecRule ARGS \"@contains a\" \"id:5,phase:1,pass\"\nSecIgnoreRuleCompilationErrors Off\n"},
		// A directive that starts with SecAuditLog, SecDebugLog or SecUpload:
		// the start of the name decides, whatever the argument.
		{"audit log", "", "SecAuditLog /x\n"},
		{"audit log type", "", "SecAuditLogType HTTPS\n"},
		{"audit log format", "", "SecAuditLogFormat JSON\n"},
		{"audit log storage dir", "", "SecAuditLogStorageDir /x\n"},
		{"audit log dir mode", "", "SecAuditLogDirMode 0700\n"},
		{"audit log file mode", "", "SecAuditLogFileMode 0600\n"},
		{"audit log parts", "", "SecAuditLogParts ABZ\n"},
		{"audit log relevant status", "", "SecAuditLogRelevantStatus ^5\n"},
		{"debug log", "", "SecDebugLog /x\n"},
		{"debug log level", "", "SecDebugLogLevel 0\n"},
		{"upload dir", "", "SecUploadDir /x\n"},
		{"upload keep files", "", "SecUploadKeepFiles On\n"},
		{"upload file mode", "", "SecUploadFileMode 0600\n"},
		{"upload file limit", "", "SecUploadFileLimit 10\n"},
		{"audit log without an argument", "", "SecAuditLog\n"},
		{"audit log mixed case", "", "secAUDITlog /x\n"},
		{"debug log upper case", "", "SECDEBUGLOG /x\n"},
		{"upload dir mixed case", "", "sEcUpLoAdDiR /x\n"},
		{"audit log dotted capital I", "", "SecAudİtLog /x\n"},
		{"audit log split by a continuation", "", "SecAudit\\\nLog /x\n"},
		{"debug log split by a continuation", "", "SecDebug\\\nLog /x\n"},
		{"upload dir split by a continuation", "", "SecUpload\\\nDir /x\n"},
		{"audit log after a comment line", "", "# note\nSecAuditLog /x\n"},
		{"audit log after white space", "", " \t SecAuditLog /x\n"},
		{"audit log after rules", "", baseRules + "SecAuditLog /x\n"},
		// @inspectFile, @rbl, setenv: and ctl:requestBodyLimit: the word decides,
		// wherever it stands in the reduced text.
		{"@inspectFile", "", `SecRule ARGS "@inspectFile /x" "id:5,phase:1,pass"` + "\n"},
		{"@inspectFile negated", "", `SecRule ARGS "!@inspectFile /x" "id:5,phase:1,pass"` + "\n"},
		{"@inspectFile after a space", "", `SecRule ARGS " @inspectFile /x" "id:5,phase:1,pass"` + "\n"},
		{"@inspectFile split by a continuation", "", "SecRule ARGS \"@inspect\\\nFile /x\" \"id:5,phase:1,pass\"\n"},
		{"@inspectFile mixed case (a false reject: operator names have a case)", "", `SecRule ARGS "@InspectFILE /x" "id:5,phase:1,pass"` + "\n"},
		{"@rbl", "", `SecRule REMOTE_ADDR "@rbl sbl.example.net" "id:5,phase:1,pass"` + "\n"},
		{"@rbl negated", "", `SecRule REMOTE_ADDR "!@rbl sbl.example.net" "id:5,phase:1,pass"` + "\n"},
		{"setenv", "", act + "setenv:A=B\"\n"},
		{"setenv with single quotes", "", act + "setenv:'A=B'\"\n"},
		{"setenv with a space before the colon", "", act + "setenv :A=B\"\n"},
		{"setenv upper case with spaces", "", act + "SETENV : A=B\"\n"},
		{"setenv with a no-break space", "", act + "setenv: A=B\"\n"},
		{"setenv split by a continuation", "", act + "set\\\nenv:A=B\"\n"},
		{"setenv in a backtick block", "", "SecAction id:1,phase:1,pass,msg:'`\n',setenv:\nA=B,msg:'\n`'\n"},
		{"ctl requestBodyLimit", "", act + "ctl:requestBodyLimit=1\"\n"},
		{"ctl requestBodyLimit with spaces", "", act + "ctl : requestBodyLimit = 1\"\n"},
		{"ctl requestBodyLimit with single quotes", "", act + "ctl:'requestBodyLimit=1'\"\n"},
		{"ctl requestBodyLimit upper case key", "", act + "CTL:requestBodyLimit=1\"\n"},
		{"ctl requestBodyLimit split by a continuation", "", act + "ctl:requestBody\\\nLimit=1\"\n"},
		{"ctl requestBodyLimit in a backtick block", "", "SecAction id:1,phase:1,pass,msg:'`\n',ctl:\nrequestBodyLimit=1,msg:'\n`'\n"},
		{"ctl requestBodyLimit mixed case (a false reject: ctl names have a case)", "", act + "ctl:REQUESTbodyLIMIT=1\"\n"},
		{"setenv after rules", "", baseRules + act + "setenv:A=B\"\n"},
		{"word setenv: in a string (a false reject)", "", "SecRule ARGS \"@contains setenv:\" \"id:5,phase:1,pass\"\n"},
		{"word @rbl in msg (a false reject)", "", act + "msg:'see @rbl'\"\n"},
	}
	for _, c := range reject {
		t.Run("reject/"+c.name, func(t *testing.T) {
			if c.kind != "" && !rawEffect(t, c.kind, c.rules) {
				t.Fatal("the text has no effect in Coraza: it does not show the need for the guard")
			}
			if err := checkRules(c.rules); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	// Not closed: Coraza drops a continuation silently and fails on a block.
	for name, rules := range map[string]string{
		"open continuation": "SecRuleEngine On\nSecAction \"id:1,phase:1,pass\" \\",
		"lone backslash":    "SecRuleEngine On\n\\",
		"open backtick":     "SecDataset x `\na\n",
		"line over 64 KiB":  act + "msg:'" + strings.Repeat("a", 70000) + "'\"\n",
	} {
		t.Run("reject/"+name, func(t *testing.T) {
			if err := checkRules(rules); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	// Accepted: the same conditions as Coraza leave a comment line without
	// effect, and the other rows hold none of what the guards look for. The
	// file operators are accepted too: the root of newWAF stops them (see
	// TestNewWAFReadsNoFile).
	accept := []struct{ name, rules string }{
		{"base rules", baseRules},
		{"comment line", "# " + act + "ctl:ruleEngine=Off\"\n"},
		{"comment line in a continuation", act + "\\\n# ctl:ruleEngine=Off\npass\"\n"},
		{"engine and limit directives", "SecRuleEngine DetectionOnly\nSecRequestBodyLimitAction ProcessPartial\nSecRequestBodyAccess Off\n"},
		{"other ctl", act + "ctl:requestBodyProcessor=JSON\"\n"},
		{"JSON depth limit (the reserved directives replace it)", "SecRequestBodyJsonDepthLimit 1024\n"},
		{"word include as an argument", "SecRule ARGS \"@contains include\" \"id:5,phase:1,pass\"\n"},
		{"word SecIgnoreRuleCompilationErrors as an argument", "SecRule ARGS \"@contains SecIgnoreRuleCompilationErrors\" \"id:5,phase:1,pass\"\n"},
		{"comment line with the ignore errors directive", "# SecIgnoreRuleCompilationErrors On\n"},
		{"comment line with a SecAuditLog directive", "# SecAuditLog /x\n"},
		{"comment line with the operators", "# SecRule ARGS \"@inspectFile /x\" \"id:5,phase:1,pass\"\n# SecRule REMOTE_ADDR \"@rbl sbl.example.net\" \"id:6,phase:1,pass\"\n"},
		{"comment line with setenv", "# " + act + "setenv:A=B\"\n"},
		{"comment line with ctl requestBodyLimit", "# " + act + "ctl:requestBodyLimit=1\"\n"},
		{"comment line in a continuation with setenv", act + "\\\n# setenv:A=B\npass\"\n"},
		{"SecDefaultAction line", "SecDefaultAction \"phase:1,log,auditlog,pass\"\n"},
		{"SecAuditEngine line (not a name that starts with SecAuditLog)", "SecAuditEngine RelevantOnly\n"},
		{"word SecAuditLog as an argument", "SecRule ARGS \"@contains SecAuditLog\" \"id:5,phase:1,pass\"\n"},
		{"@pm", "SecRule ARGS \"@pm a b\" \"id:5,phase:1,pass\"\n"},
		{"@pmFromFile (newWAF stops it)", "SecRule ARGS \"@pmFromFile /x/words.data\" \"id:5,phase:1,pass\"\n"},
		{"ctl ruleRemoveByTag", act + "ctl:ruleRemoveByTag=x\"\n"},
		{"ctl forceRequestBodyVariable", act + "ctl:forceRequestBodyVariable=On\"\n"},
	}
	for _, c := range accept {
		t.Run("accept/"+c.name, func(t *testing.T) {
			if err := checkRules(c.rules); err != nil {
				t.Fatalf("rejected: %v", err)
			}
			if strings.HasPrefix(c.name, "comment") && (rawEffect(t, "engine", c.rules) || rawEffect(t, "body", c.rules) || rawEffect(t, "ignore", c.rules)) {
				t.Fatal("a comment line had an effect in Coraza")
			}
		})
	}
}

// Two rules of the operator with one id, after SecIgnoreRuleCompilationErrors
// On: Coraza builds the text and drops the second rule (the deny rule).
const (
	dupPass = `SecRule REQUEST_METHOD "@streq NEVER" "id:9202,phase:1,pass"` + "\n"
	dupDeny = `SecRule ARGS_POST:probe "@streq block" "id:9202,phase:2,deny"` + "\n"
	dupText = "SecIgnoreRuleCompilationErrors On\n" + dupPass + dupDeny
)

// With the directive, Coraza builds dupText and the deny rule is gone: a
// urlencoded body that it should block is not interrupted. Its own id gives a
// block, and without the directive the duplicate id stops NewWAF.
func TestCheckRulesDroppedRule(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	post := func(rules string) *types.Interruption {
		t.Helper()
		waf, err := newWAF(rules)
		if err != nil {
			t.Fatalf("Coraza does not accept the text: %v", err)
		}
		tx := waf.NewTransaction()
		defer tx.Close()
		tx.ProcessConnection("127.0.0.1", 1, "127.0.0.1", 2)
		tx.ProcessURI("/", "POST", "HTTP/1.1")
		tx.AddRequestHeader("Content-Type", "application/x-www-form-urlencoded")
		if it := tx.ProcessRequestHeaders(); it != nil {
			t.Fatalf("interrupted in phase 1: %+v", it)
		}
		if it, _, err := tx.WriteRequestBody([]byte("probe=block")); it != nil || err != nil {
			t.Fatalf("write: %+v %v", it, err)
		}
		it, err := tx.ProcessRequestBody()
		if err != nil {
			t.Fatal(err)
		}
		return it
	}
	if it := post(dupText); it != nil {
		t.Fatalf("the deny rule was not dropped: %+v", it)
	}
	if it := post(dupPass + strings.Replace(dupDeny, "9202", "9203", 1)); it == nil || it.RuleID != 9203 {
		t.Fatalf("the deny rule with its own id did not block: %+v", it)
	}
	if _, err := newWAF(dupPass + dupDeny); err == nil {
		t.Fatal("the duplicate id was accepted without the directive")
	}
	if err := checkRules(dupText); err == nil {
		t.Fatal("accepted")
	}
}

// The root of the rules answers every name with "does not exist" and never
// returns a file.
func TestNoFiles(t *testing.T) {
	for _, name := range []string{"", ".", "x", "/abs/x", "../x", "a/*.conf"} {
		f, err := noFiles{}.Open(name)
		var pe *os.PathError
		if f != nil || !errors.As(err, &pe) || pe.Op != "open" || pe.Path != name || pe.Err != os.ErrNotExist {
			t.Errorf("%q: %v %v", name, f, err)
		}
	}
}

// The rules read no file: newWAF gives them a root without files. Each row
// names a file that exists, and Coraza builds the same rule without that root,
// so the root is what stops the read; newWAF fails with the answer of the root.
// The relative name is found from the directory of the package, which is the
// directory of a test.
func TestNewWAFReadsNoFile(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	dir := t.TempDir()
	write := func(name, data string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	words := write("words.data", "attack\n")
	ips := write("ips.data", "192.0.2.1\n")
	schema := write("schema.json", "{}\n")
	rows := []struct{ name, rules string }{
		{"@pmFromFile by an absolute name", `SecRule ARGS "@pmFromFile ` + words + `" "id:5,phase:1,pass"` + "\n"},
		{"@pmFromFile by a relative name", `SecRule ARGS "@pmFromFile testdata/v0-golden.txt" "id:5,phase:1,pass"` + "\n"},
		{"@ipMatchFromFile", `SecRule REMOTE_ADDR "@ipMatchFromFile ` + ips + `" "id:5,phase:1,pass"` + "\n"},
		{"@validateSchema", `SecRule REQUEST_BODY "@validateSchema ` + schema + `" "id:5,phase:2,pass"` + "\n"},
	}
	for _, c := range rows {
		t.Run(c.name, func(t *testing.T) {
			if _, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives("SecRuleEngine On\n" + c.rules)); err != nil {
				t.Fatalf("Coraza does not build the rule without the root: %v", err)
			}
			_, err := newWAF(c.rules)
			if err == nil {
				t.Fatal("the rule that reads a file was built")
			}
			if !strings.Contains(err.Error(), "file does not exist") {
				t.Fatalf("not the answer of the root: %v", err)
			}
		})
	}
}

func TestProcessRejectedRules(t *testing.T) {
	p := startProc(t, procOpt{rules: baseRules + "SecAction \"id:1,phase:1,pass,ctl:ruleEngine=Off\"\n"})
	if got := p.exit(t); got != exitRules {
		t.Fatalf("exit %d stderr %q", got, p.stderr.String())
	}
	if s := p.stderr.String(); !strings.Contains(s, "start: rules rejected: ctl of ruleEngine") || strings.Contains(s, "rules.conf") {
		t.Fatalf("stderr %q", s)
	}
	if _, err := readOne(p.c); err == nil {
		t.Fatal("a frame was sent")
	}
}

// The directive stops the start although the rules would build.
func TestProcessRejectedRulesIgnoreErrors(t *testing.T) {
	p := startProc(t, procOpt{rules: dupText})
	if got := p.exit(t); got != exitRules {
		t.Fatalf("exit %d stderr %q", got, p.stderr.String())
	}
	if s := p.stderr.String(); !strings.Contains(s, "start: rules rejected: the SecIgnoreRuleCompilationErrors directive is not allowed") || strings.Contains(s, "rules.conf") {
		t.Fatalf("stderr %q", s)
	}
	if _, err := readOne(p.c); err == nil {
		t.Fatal("a frame was sent")
	}
}

// A rule that reaches outside the process stops the start: exit 11, no frame,
// and no path of the rules file in the diagnostic. The directive and the
// operator are stopped by checkRules (a fixed text), the read of an existing
// file by the root of newWAF (the text of Coraza, which names the data file).
func TestProcessRejectedRulesOutside(t *testing.T) {
	data := filepath.Join(t.TempDir(), "words.data")
	if err := os.WriteFile(data, []byte("attack\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ name, rules, want string }{
		{"audit log", baseRules + "SecAuditLog " + filepath.Join(t.TempDir(), "audit.log") + "\n", "start: rules rejected: the SecAuditLog, SecDebugLog and SecUpload directives are not allowed"},
		{"@inspectFile", baseRules + `SecRule ARGS "@inspectFile /bin/true" "id:5,phase:1,pass"` + "\n", "start: rules rejected: @inspectFile, @rbl, setenv and ctl of requestBodyLimit are not allowed"},
		{"@pmFromFile by an absolute name", baseRules + `SecRule ARGS "@pmFromFile ` + data + `" "id:5,phase:1,pass"` + "\n", "start: rules build failed: "},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := startProc(t, procOpt{rules: c.rules})
			if got := p.exit(t); got != exitRules {
				t.Fatalf("exit %d stderr %q", got, p.stderr.String())
			}
			if s := p.stderr.String(); !strings.Contains(s, c.want) || strings.Contains(s, "rules.conf") {
				t.Fatalf("stderr %q", s)
			}
			if _, err := readOne(p.c); err == nil {
				t.Fatal("a frame was sent")
			}
		})
	}
}

func TestWithoutPath(t *testing.T) {
	pe := &os.PathError{Op: "read", Path: "/secret/rules.conf", Err: syscall.EIO}
	if got := withoutPath(fmt.Errorf("wrapped: %w", pe)); got != syscall.EIO {
		t.Fatalf("got %v", got)
	}
	plain := errors.New("not a regular file")
	if got := withoutPath(plain); got != plain {
		t.Fatalf("got %v", got)
	}
}
