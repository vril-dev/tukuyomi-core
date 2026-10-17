package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"testing"
	"time"
)

// ---- the real process: fd 0 socketpair, peer check, exit codes ----

const testNonceHex = "000102030405060708090a0b0c0d0e0f"

type proc struct {
	cmd         *exec.Cmd
	c           net.Conn
	stderr      *syncBuf
	fingerprint [32]byte // sha256 of the manifest.json of the bundle: what the HELLO holds
	dir         string   // the directory of the process: its bundle and its TMPDIR
}

type procOpt struct {
	env    map[string]string // "\x00unset" removes a variable
	rules  string            // text of the one rule file of the bundle; "" means baseRules
	files  map[string]string // the files of the bundle, instead of rules
	load   []string          // their order of load
	stdin  *os.File          // overrides the socketpair
	dgram  bool
	stderr io.Writer
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
	files, load := map[string]string{ruleFile: rules}, []string{ruleFile}
	if o.files != nil {
		files, load = o.files, o.load
	}
	bp := filepath.Join(dir, "bundle")
	sum := writeBundle(t, bp, files, load...)
	env := map[string]string{
		"TKV0_TEST_MODE": "inspector", "TKV0_TEST_RULES": bp,
		"TKV0_RUN_ID": "0102030405060708", "TKV0_INCARNATION": "00000007", "TKV0_NONCE": testNonceHex,
		"TMPDIR": tmp, "GOMAXPROCS": "2", "GOMEMLIMIT": "256MiB",
	}
	for k, v := range o.env {
		if v == "\x00unset" {
			delete(env, k)
		} else {
			env[k] = v
		}
	}
	cmd := exec.Command(os.Args[0])
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	p := &proc{cmd: cmd, stderr: &syncBuf{}, fingerprint: sum, dir: dir}
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

// failsStart expects the exit code want, msg in the diagnostic, none of the
// directory of the process or of paths in it, and no frame on the socket.
func (p *proc) failsStart(t *testing.T, want int, msg string, paths ...string) {
	t.Helper()
	if got := p.exit(t); got != want {
		t.Fatalf("exit %d want %d stderr %q", got, want, p.stderr.String())
	}
	s := p.stderr.String()
	if !strings.Contains(s, msg) || strings.Contains(s, p.dir) {
		t.Fatalf("stderr %q, want %q and no directory of the process", s, msg)
	}
	for _, x := range paths {
		if strings.Contains(s, x) {
			t.Fatalf("the path %q in the diagnostic: %q", x, s)
		}
	}
	if p.c != nil {
		if _, err := readOne(p.c); err == nil {
			t.Fatal("a frame was sent")
		}
	}
}

// The acceptance run: the HELLO, a request without a body, and JSON bodies
// through the whole path (the start accepts the depth limit of the operator
// and newWAF replaces it; the rule of the operator on an argument blocks; the
// reserved rule blocks a body nested deeper than its limit), then DRAIN and
// BYE. The inspector works from "/", whatever directory the parent used.
func TestProcessHappyPath(t *testing.T) {
	p := startProc(t, procOpt{rules: baseRules + bigBody + "SecRequestBodyJsonDepthLimit 1024\n" + jsonProbeRule})
	bi, _ := debug.ReadBuildInfo()
	var dv, ds string
	for _, m := range bi.Deps {
		if m.Path == corazaModulePath {
			dv, ds = m.Version, m.Sum
		}
	}
	var nonce [16]byte
	for i := range nonce {
		nonce[i] = byte(i)
	}
	want, err := encodeHello(testRun, testInc, hello{pid: uint32(p.cmd.Process.Pid), nonce: nonce, goVersion: runtime.Version(),
		corazaVersion: dv, corazaSum: ds, rulesSHA256: p.fingerprint, memLimit: 256 << 20, gomaxprocs: 2})
	if b := p.frame(t); err != nil || !bytes.Equal(b, want) {
		t.Fatalf("HELLO %x, want %x (%v)", b, want, err)
	}
	if got, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", p.cmd.Process.Pid)); err != nil || got != "/" {
		t.Fatalf("working directory %q, err %v", got, err)
	}

	pr := &peer{t: t, c: p.c}
	deep := nestedJSON(65, "fine")
	cases := []struct {
		begin tBegin
		body  string
		rule  int64 // 0: Continue
	}{
		{defaultBegin(0), "", 0},
		{jsonBegin(uint64(len(jsonBody("block")))), jsonBody("block"), 9203},
		{jsonBegin(uint64(len(deep))), deep, 4000001},
	}
	for i, c := range cases {
		tx, msg := uint64(i+1), uint32(2)
		pr.send(tFrame(kindTxBegin, tx, 1, c.begin.payload()))
		expectVerdict(t, pr.recv(), tx, 1, 1, false)
		if c.body != "" {
			pr.send(tFrame(kindBody, tx, msg, []byte(c.body)))
			msg++
		}
		pr.send(tFrame(kindBodyEnd, tx, msg, nil))
		o := pr.recv()
		expectVerdict(t, o, tx, msg, 2, c.rule != 0)
		if c.rule != 0 && (o.rule != c.rule || o.stat != 403) {
			t.Fatalf("tx %d: %+v", tx, o)
		}
		pr.send(tFrame(kindTxEnd, tx, msg+1, []byte{endComplete}))
		expect(t, pr.recv(), kindClosed, tx, msg+1)
	}
	pr.send(tFrame(kindDrain, 0, 0, nil))
	if o := pr.recv(); o.kind != kindBye || o.bye != [3]uint64{3, 3, 0} {
		t.Fatalf("%+v", o)
	}
	if c := p.exit(t); c != exitOK {
		t.Fatalf("exit %d stderr %q", c, p.stderr.String())
	}
	if !strings.Contains(p.stderr.String(), "exit=0 started=3 closed=3 close_errors=0") {
		t.Fatalf("stderr %q", p.stderr.String())
	}
}

func TestProcessExitCodes(t *testing.T) {
	r, w, _ := os.Pipe()
	defer r.Close()
	defer w.Close()
	dir := t.TempDir()
	fifo := filepath.Join(dir, "bundle.fifo") // no writer ever opens it
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	ro := filepath.Join(dir, "ro")
	if err := os.Mkdir(ro, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(ro, 0o700) })
	cases := []struct {
		name string
		opt  procOpt
		want int
		msg  string
	}{
		{"stdin is a pipe", procOpt{stdin: r}, exitPeer, "start: peer check failed"},
		{"dgram socketpair", procOpt{dgram: true}, exitPeer, "start: peer check failed"},
		{"parent is not the creator", procOpt{env: map[string]string{"TKV0_TEST_MODE": "spawner"}}, exitPeer, "start: peer check failed"},
		{"no bundle arg", procOpt{env: map[string]string{"TKV0_TEST_RULES": "\x00unset"}}, exitStartup, "start: usage"},
		{"no tmpdir", procOpt{env: map[string]string{"TMPDIR": "\x00unset"}}, exitStartup, "start: TMPDIR"},
		{"missing bundle", procOpt{env: map[string]string{"TKV0_TEST_RULES": "/nonexistent/tkv0/bundle"}}, exitRules, "start: rules: "},
		{"bundle is a FIFO", procOpt{env: map[string]string{"TKV0_TEST_RULES": fifo}}, exitRules, "start: rules: not a directory"},
		{"bad directive", procOpt{rules: "SecRuleEngine On\nSecNoSuchDirective 1\n"}, exitRules, "start: rules build failed"},
		{"unwritable tmpdir", procOpt{env: map[string]string{"TMPDIR": ro}}, exitRules, "start: rules build failed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			startProc(t, c.opt).failsStart(t, c.want, c.msg, "/nonexistent", fifo)
		})
	}
}

// A rule that is rejected, or reaches outside the process, stops the start:
// exit 11, no frame, and no path in the diagnostic. The guards run on every
// rule file of load, one at a time, and name the file that they stopped at.
func TestProcessRejectedRules(t *testing.T) {
	data := filepath.Join(t.TempDir(), "words.data")
	if err := os.WriteFile(data, []byte("attack\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const ctl = "SecAction \"id:1,phase:1,pass,ctl:ruleEngine=Off\"\n"
	cases := []struct {
		name string
		opt  procOpt
		msg  string
	}{
		{"ctl ruleEngine", procOpt{rules: baseRules + ctl}, "start: rules rejected: rules/rules.conf: ctl of ruleEngine"},
		{"second file", procOpt{files: map[string]string{"rules/a.conf": baseRules, "rules/b.conf": ctl}, load: []string{"rules/a.conf", "rules/b.conf"}},
			"start: rules rejected: rules/b.conf: ctl of ruleEngine"},
		{"SecIgnoreRuleCompilationErrors", procOpt{rules: baseRules + "SecIgnoreRuleCompilationErrors On\n"},
			"start: rules rejected: rules/rules.conf: the SecIgnoreRuleCompilationErrors directive is not allowed"},
		{"file outside the bundle", procOpt{rules: baseRules + `SecRule ARGS "@pmFromFile ` + data + `" "id:5,phase:1,pass"` + "\n"},
			"start: rules build failed: "},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			startProc(t, c.opt).failsStart(t, exitRules, c.msg)
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
