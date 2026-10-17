package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
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

// Two rules of the operator with one id, after SecIgnoreRuleCompilationErrors
// On: Coraza builds the text and drops the second rule (the deny rule).
const (
	dupPass = `SecRule REQUEST_METHOD "@streq NEVER" "id:9202,phase:1,pass"` + "\n"
	dupDeny = `SecRule ARGS_POST:probe "@streq block" "id:9202,phase:2,deny"` + "\n"
	dupText = "SecIgnoreRuleCompilationErrors On\n" + dupPass + dupDeny
)
