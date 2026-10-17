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
	get := func(k, v string) func(string) string {
		return func(key string) string {
			if key == k {
				return v
			}
			return env[key]
		}
	}
	c, err := parseConfig([]string{"/r/bundle"}, get("", ""))
	if err != nil || c.run != testRun || c.inc != testInc || c.nonce[15] != 0x0f || c.bundleDir != "/r/bundle" {
		t.Fatalf("%+v %v", c, err)
	}
	for name, kv := range map[string][2]string{
		"run upper case": {"TKV0_RUN_ID", "0102030405060A08"},
		"run short":      {"TKV0_RUN_ID", "010203040506070"},
		"inc short":      {"TKV0_INCARNATION", "7"},
		"nonce not hex":  {"TKV0_NONCE", "g00102030405060708090a0b0c0d0e0"},
		"tmp empty":      {"TMPDIR", ""},
		"tmp relative":   {"TMPDIR", "tmp"},
		"tmp unclean":    {"TMPDIR", tmp + "/"},
		"tmp missing":    {"TMPDIR", filepath.Join(tmp, "nope")},
	} {
		if _, err := parseConfig([]string{"/r/bundle"}, get(kv[0], kv[1])); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	const usage = "usage: inspector <absolute clean bundle directory>"
	for name, args := range map[string][]string{"none": nil, "two": {"/a", "/b"}, "relative": {"bundle"}, "unclean": {"/r/../bundle"}} {
		if _, err := parseConfig(args, get("", "")); err == nil || err.Error() != usage {
			t.Errorf("args %s: %v, want %q", name, err, usage)
		}
	}
}

func TestCheckTmpDir(t *testing.T) {
	base := t.TempDir()
	d := filepath.Join(base, "d")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	for mode, ok := range map[os.FileMode]bool{0o700: true, 0o500: true, 0o710: false, 0o701: false} {
		if err := os.Chmod(d, mode); err != nil {
			t.Fatal(err)
		}
		if err := checkTmpDir(d); ok != (err == nil) { // writability is NewWAF's check
			t.Errorf("mode %o: %v", mode, err)
		}
	}
	os.Chmod(d, 0o700)
	link, file := filepath.Join(base, "link"), filepath.Join(base, "file")
	if err := os.Symlink(d, link); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(file, nil, 0o600)
	for name, p := range map[string]string{"symlink": link, "file": file} {
		if err := checkTmpDir(p); err == nil {
			t.Errorf("%s accepted", name)
		}
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
