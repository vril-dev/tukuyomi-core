package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
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
