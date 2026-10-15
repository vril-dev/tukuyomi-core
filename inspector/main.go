// Command inspector is the Go inspection process. It talks protocol 0 over a
// socketpair inherited as fd 0 and inspects requests with the Coraza Go API.
package main

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

// Exit codes (14: invalid start-up input).
const (
	exitOK          = 0
	exitPeer        = 10
	exitRules       = 11
	exitLostClean   = 12
	exitLostTimeout = 13
	exitStartup     = 14
)

const (
	corazaModulePath = "github.com/corazawaf/coraza/v3"
	maxRulesBytes    = 1 << 20
	lostTimeout      = 3 * time.Second // close-down deadline after connection loss
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	// Writes to a broken stderr must fail with EPIPE instead of killing the
	// process in the middle of closing transactions.
	signal.Notify(make(chan os.Signal, 1), syscall.SIGPIPE)
	d := &diag{w: os.Stderr}

	if err := checkPeer(0); err != nil {
		d.printf("start: peer check failed: %v", err)
		return exitPeer
	}
	cfg, err := parseConfig(args, os.Getenv)
	if err != nil {
		d.printf("start: %v", err)
		return exitStartup
	}
	ver, sum, err := corazaModule()
	if err != nil {
		d.printf("start: %v", err)
		return exitStartup
	}
	rules, err := readRules(cfg.rulesPath)
	if err != nil {
		d.printf("start: rules: %v", withoutPath(err))
		return exitRules
	}
	sha := sha256.Sum256(rules)
	if err := checkRules(string(rules)); err != nil {
		d.printf("start: rules rejected: %v", err)
		return exitRules
	}
	waf, err := newWAF(string(rules))
	if err != nil {
		d.printf("start: rules build failed: %v", err)
		return exitRules
	}
	conn, err := peerConn(0)
	if err != nil {
		d.printf("start: peer conn: %v", err)
		return exitPeer
	}
	procs := runtime.GOMAXPROCS(0)
	if procs > 0xffff {
		procs = 0xffff
	}
	h, err := encodeHello(cfg.run, cfg.inc, hello{
		pid: uint32(os.Getpid()), nonce: cfg.nonce, goVersion: runtime.Version(),
		corazaVersion: ver, corazaSum: sum, rulesSHA256: sha,
		memLimit: debug.SetMemoryLimit(-1), gomaxprocs: uint16(procs),
	})
	if err != nil {
		d.printf("start: hello: %v", err)
		return exitStartup
	}
	return serve(conn, cfg.run, cfg.inc, h, waf.NewTransactionWithID, d, lostTimeout)
}

type config struct {
	rulesPath string
	run       uint64
	inc       uint32
	nonce     [16]byte
}

// parseConfig validates argv and the binding variables. Formats are exact:
// lowercase hex of fixed width, one absolute rules path, and TMPDIR.
func parseConfig(args []string, getenv func(string) string) (config, error) {
	var c config
	if len(args) != 1 || !filepath.IsAbs(args[0]) || filepath.Clean(args[0]) != args[0] {
		return c, errors.New("usage: inspector <absolute clean rules path>")
	}
	c.rulesPath = args[0]
	var b [16]byte
	if err := parseHex(getenv("TKV0_RUN_ID"), b[:8]); err != nil {
		return c, fmt.Errorf("TKV0_RUN_ID: %w", err)
	}
	c.run = uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
	if err := parseHex(getenv("TKV0_INCARNATION"), b[:4]); err != nil {
		return c, fmt.Errorf("TKV0_INCARNATION: %w", err)
	}
	c.inc = uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	if err := parseHex(getenv("TKV0_NONCE"), c.nonce[:]); err != nil {
		return c, fmt.Errorf("TKV0_NONCE: %w", err)
	}
	if err := checkTmpDir(getenv("TMPDIR")); err != nil {
		return c, fmt.Errorf("TMPDIR: %w", err)
	}
	return c, nil
}

func parseHex(s string, dst []byte) error {
	if len(s) != 2*len(dst) {
		return fmt.Errorf("want %d lowercase hex digits", 2*len(dst))
	}
	for i := range dst {
		hi, ok1 := hexVal(s[2*i])
		lo, ok2 := hexVal(s[2*i+1])
		if !ok1 || !ok2 {
			return errors.New("not lowercase hex")
		}
		dst[i] = hi<<4 | lo
	}
	return nil
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	}
	return 0, false
}

// checkTmpDir requires the per-start directory created by Rust: absolute, a
// real directory (not a link), owned by us, no group/other permissions.
// Writability is left to NewWAF, so an unwritable directory is a rules build
// failure (exit 11).
func checkTmpDir(p string) error {
	if p == "" || !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return errors.New("must be an absolute clean path")
	}
	var st syscall.Stat_t
	if err := syscall.Lstat(p, &st); err != nil {
		return err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return errors.New("not a directory")
	}
	if st.Uid != uint32(os.Geteuid()) {
		return errors.New("not owned by this user")
	}
	if st.Mode&0o077 != 0 {
		return errors.New("group or other permission bits set")
	}
	return nil
}

// checkPeer requires fd to be a connected AF_UNIX stream socket whose peer is
// our parent process with our effective uid.
func checkPeer(fd int) error {
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFSOCK {
		return errors.New("fd is not a socket")
	}
	dom, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_DOMAIN)
	if err != nil {
		return err
	}
	typ, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
	if err != nil {
		return err
	}
	if dom != syscall.AF_UNIX || typ != syscall.SOCK_STREAM {
		return errors.New("fd is not a unix stream socket")
	}
	cred, err := syscall.GetsockoptUcred(fd, syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil {
		return err
	}
	if cred.Uid != uint32(os.Geteuid()) {
		return errors.New("peer uid differs")
	}
	if int(cred.Pid) != os.Getppid() {
		return errors.New("peer pid is not the parent")
	}
	return nil
}

// peerConn wraps fd as a net connection (net.FileConn dups the descriptor and
// makes it non-blocking) and closes the original descriptor.
func peerConn(fd int) (*net.UnixConn, error) {
	f := os.NewFile(uintptr(fd), "peer")
	c, err := net.FileConn(f)
	f.Close()
	if err != nil {
		return nil, err
	}
	uc, ok := c.(*net.UnixConn)
	if !ok {
		c.Close()
		return nil, errors.New("not a unix connection")
	}
	return uc, nil
}

// corazaModule reports the linked Coraza module version and checksum.
func corazaModule() (string, string, error) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "", "", errors.New("no build info")
	}
	for _, m := range bi.Deps {
		if m.Path != corazaModulePath {
			continue
		}
		if m.Replace != nil {
			return "", "", errors.New("coraza module is replaced")
		}
		if m.Version == "" || m.Sum == "" {
			return "", "", errors.New("coraza module version or sum missing")
		}
		return m.Version, m.Sum, nil
	}
	return "", "", errors.New("coraza module not in build info")
}

// readRules reads the rules file once: no symlink, a regular file, bounded
// size, and the bytes read must match the size seen by fstat.
func readRules(p string) ([]byte, error) {
	// O_NONBLOCK: opening a FIFO must not wait for a writer; the fstat check
	// below then rejects it. It does not affect reads of a regular file.
	fd, err := syscall.Open(p, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), p)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if st.Size() > maxRulesBytes {
		return nil, errors.New("too large")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxRulesBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) != st.Size() {
		return nil, errors.New("size changed while reading")
	}
	return b, nil
}

// withoutPath drops the path of an *os.PathError, so that the start-up
// diagnostic does not print where the rules file is.
func withoutPath(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// reservedDirectives follow the operator's rules in a separate WithDirectives
// call. Coraza parses every call apart from the others (no continuation
// or backtick state is carried over), and a later SecRuleEngine,
// SecRequestBodyAccess, SecRequestBodyLimitAction or
// SecRequestBodyJsonDepthLimit replaces an earlier one.
// So the engine is On, the body is accessible, a body over the limit is
// rejected and a JSON body nests at most 64 levels, whatever the operator's
// rules or a recommended configuration set (the recommended one sets 1024,
// and the JSON processor reads the nested parts of a body again at every
// level, so a deep body costs much more than a flat one).
// The last SecRuleEngine On also avoids the switch of the body limit action to
// ProcessPartial that NewWAF makes for DetectionOnly. A parse failure of the
// body (a JSON body nested deeper than the limit is one), a dropped argument
// and an unparsable URI become a block of phase 2.
// Ids 4000001 to 4000003 are reserved for these rules. The start path rejects
// SecIgnoreRuleCompilationErrors (checkRules) before newWAF, so a rule of the
// operator with one of these ids stops NewWAF instead of displacing a reserved rule
// silently. The rules can still be skipped at run time (allow, skipAfter,
// ctl:ruleRemoveById), so the owner reads the flags itself before a phase 2
// Continue (requestComplete). t:none keeps the rules independent of a default
// transformation (v3.8.1 refuses one in SecDefaultAction anyway).
const reservedDirectives = `SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimitAction Reject
SecRequestBodyJsonDepthLimit 64
SecRule REQBODY_ERROR "!@eq 0" "id:4000001,phase:2,t:none,deny"
SecRule ARGUMENTS_LIMIT_REACHED "!@eq 0" "id:4000002,phase:2,t:none,deny"
SecRule URI_PARSE_ERROR "!@eq 0" "id:4000003,phase:2,t:none,deny"
`

// newWAF builds the WAF from the operator's rules and the reserved directives.
func newWAF(rules string) (coraza.WAF, error) {
	return coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(rules).WithDirectives(reservedDirectives))
}

// checkRules is the start-up guard for the operator's rules. A ctl action
// can switch the rule engine or the request body access of one transaction
// (DetectionOnly never interrupts, so a match would read as Allow), Include
// reads files that rules_sha256 does not cover, and with
// SecIgnoreRuleCompilationErrors On a rule that fails to build (for example
// one with a duplicate id) is dropped silently: a deny rule of the operator
// can be missing, and nothing added after the operator's rules can bring it
// back. checkRules rejects rules that may contain any of the three.
//
// It is a textual over-approximation, not a SecLang parser. False rejects are
// accepted: a rejected text may be harmless in Coraza, for example the ctl
// name inside the argument of an operator or a spelling that Coraza would not
// read as a ctl action. SecIgnoreRuleCompilationErrors is rejected whatever
// its argument, Off (Coraza's default) too: telling On from Off would need a
// parser of the argument (case, quotes, continuation), and a later occurrence
// of the directive replaces an earlier one. Rejecting every argument keeps the
// guard independent of how the argument is read and of the directive order.
//
// The text is first reduced to the logical directives that Coraza v3.8.1
// evaluates, with the same conditions in the same order as its parseString:
// the same line splitting and per-line TrimSpace, a line that starts with "#"
// is skipped (also inside a continuation or a backtick block), a line that
// ends with a backtick opens and a line that starts with one closes a block,
// and a trailing backslash joins the next line without a separator. Coraza
// silently drops a continuation that is open at the end and stops at a line
// over the Scanner limit; both are rejected here. Coraza removes no backslash
// between the directive text and the comparison of a ctl name (a quoted action
// value is unquoted, only the argument of an operator has \" resolved), so the
// ctl check does not remove backslashes.
func checkRules(rules string) error {
	sc := bufio.NewScanner(strings.NewReader(rules))
	var logical []string
	var buf strings.Builder
	inBackticks, joined := false, false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		last := len(line) - 1
		if !inBackticks && line[last] == '`' {
			inBackticks = true
		} else if inBackticks && line[0] == '`' {
			inBackticks = false
		}
		if inBackticks {
			buf.WriteString(line)
			buf.WriteByte('\n')
			continue
		}
		if line[last] == '\\' {
			buf.WriteString(line[:last])
			joined = true
			continue
		}
		buf.WriteString(line)
		logical = append(logical, buf.String())
		buf.Reset()
		joined = false
	}
	if sc.Err() != nil {
		return errors.New("a line is too long")
	}
	if inBackticks || joined {
		return errors.New("a continuation or a backtick block is not closed")
	}
	for _, l := range logical {
		first := l
		if i := strings.IndexFunc(l, unicode.IsSpace); i >= 0 {
			first = l[:i]
		}
		// Coraza cuts at an ASCII space only and compares strings.ToLower
		// (which maps U+0130 to "i"); the first unicode.IsSpace is never later.
		if strings.ToLower(first) == "include" {
			return errors.New("the Include directive is not allowed")
		}
		if strings.ToLower(first) == "secignorerulecompilationerrors" {
			return errors.New("the SecIgnoreRuleCompilationErrors directive is not allowed")
		}
	}
	// Whole text, not per directive: no space, quote or line break is kept.
	text := strings.Map(func(r rune) rune {
		switch {
		case unicode.IsSpace(r), r == '\'', r == '"':
			return -1
		case 'A' <= r && r <= 'Z':
			return r + 'a' - 'A'
		}
		return r
	}, strings.Join(logical, "\n"))
	if strings.Contains(text, "ctl:ruleengine") || strings.Contains(text, "ctl:requestbodyaccess") {
		return errors.New("ctl of ruleEngine or requestBodyAccess is not allowed")
	}
	return nil
}

// conn is the part of the socket the session needs (net.UnixConn, net.Pipe).
type conn interface {
	readConn
	writeConn
	Close() error
}

type outFrame struct {
	b     []byte
	ack   chan error
	final bool // the writer stops after this frame (BYE is the last frame)
}

// linkEnd is how the session ends. The first of "BYE written" and "fatal"
// wins; link.mu guards it.
type linkEnd uint8

const (
	endOpen    linkEnd = iota // no outcome yet
	endBye                    // the writer started BYE; the write result decides
	endDrained                // BYE written: the normal end
	endFatal                  // connection-wide failure or loss
)

// errLinkLost is the ack of a frame that was taken after the end was fatal.
var errLinkLost = errors.New("connection lost before the frame was written")

// link owns the connection: one writer goroutine, and one loss signal that
// any of reader, writer or shutdown can raise once.
type link struct {
	c     conn
	out   chan outFrame
	lost  chan struct{}
	wdone chan struct{} // closed when the writer has returned
	once  sync.Once
	mu    sync.Mutex // guards end and why; never held across Close or I/O
	end   linkEnd
	why   string // the reason of endFatal
}

func newLink(c conn) *link {
	return &link{c: c, out: make(chan outFrame, 64), lost: make(chan struct{}), wdone: make(chan struct{})}
}

// fail closes the connection once. It makes the end fatal unless BYE is being
// written or was written: then the BYE write result (or the written BYE)
// stands and the close only stops the reader.
func (l *link) fail(why string) {
	l.once.Do(func() {
		l.mu.Lock()
		if l.end == endOpen {
			l.end, l.why = endFatal, why
		}
		close(l.lost)
		l.mu.Unlock()
		l.c.Close()
	})
}

// begin tells the writer whether it may start writing a frame: not after a
// fatal end. For the final frame (BYE) it records that the write started.
func (l *link) begin(final bool) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.end != endOpen {
		return false
	}
	if final {
		l.end = endBye
	}
	return true
}

// finish decides the end from the result of the BYE write.
func (l *link) finish(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err != nil {
		l.end, l.why = endFatal, "write: "+err.Error()
		return
	}
	l.end = endDrained
}

// result reports the end and, for a fatal end, its reason.
func (l *link) result() (linkEnd, string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.end, l.why
}

func (l *link) writer() {
	defer close(l.wdone)
	for {
		select {
		case f := <-l.out:
			if !l.begin(f.final) {
				if f.ack != nil {
					f.ack <- errLinkLost
				}
				return
			}
			err := writeFrame(l.c, f.b, frameTimeout)
			if f.final {
				l.finish(err)
			}
			if f.ack != nil {
				f.ack <- err
			}
			if err != nil {
				l.fail("write: " + err.Error())
				return
			}
			if f.final {
				return
			}
		case <-l.lost:
			return
		}
	}
}

// send hands one whole frame to the writer. After loss it never blocks.
func (l *link) send(b []byte) bool {
	select { // refuse after loss; a fail racing the enqueue below is dropped unwritten by begin
	case <-l.lost:
		return false
	default:
	}
	select {
	case l.out <- outFrame{b: b}:
		return true
	case <-l.lost:
		return false
	}
}

// sendWait returns after the frame was written (true) or the link was lost.
// With final set, nothing is written after this frame.
func (l *link) sendWait(b []byte, final bool) bool {
	select { // as in send: nothing is accepted after loss
	case <-l.lost:
		return false
	default:
	}
	ack := make(chan error, 1)
	select {
	case l.out <- outFrame{b: b, ack: ack, final: final}:
	case <-l.lost:
		return false
	}
	select {
	case err := <-ack:
		return err == nil
	case <-l.lost:
		return false
	}
}

// serve runs one session and returns the exit code.
func serve(c conn, run uint64, inc uint32, helloFrame []byte, newTx func(string) types.Transaction, d *diag, closeDeadline time.Duration) int {
	l := newLink(c)
	go l.writer()
	t := newTable(run, inc, newTx, l.send)
	drained := make(chan struct{})
	var dupDrains uint64
	var readerDone sync.WaitGroup
	if l.sendWait(helloFrame, false) {
		readerDone.Add(1)
		go func() {
			defer readerDone.Done()
			for {
				h, p, err := readFrame(l.c, run, inc, frameTimeout)
				if err != nil {
					l.fail("read: " + err.Error())
					return
				}
				if h.kind == kindDrain {
					if t.startDrain() {
						close(drained)
					} else {
						dupDrains++
					}
					continue
				}
				t.dispatch(h, p)
			}
		}()
	} else {
		l.fail("hello not written")
	}

	select {
	case <-drained:
		allClosed := make(chan struct{})
		go func() { t.wg.Wait(); close(allClosed) }()
		select {
		case <-allClosed:
			s, cl, ce, _, _ := t.counts()
			// Not the select branch of sendWait but the writer's end decides:
			// lost and ack can be ready together.
			l.sendWait(encodeBye(run, inc, s, cl, ce), true)
			<-l.wdone
			if end, _ := l.result(); end == endDrained {
				l.fail("bye written")
				readerDone.Wait()
				d.final(exitOK, t, dupDrains, "drained")
				return exitOK
			}
		case <-l.lost:
		}
	case <-l.lost:
	}

	l.fail("lost")
	readerDone.Wait()
	_, why := l.result()
	t.connLost()
	allClosed := make(chan struct{})
	go func() { t.wg.Wait(); close(allClosed) }()
	timer := time.NewTimer(closeDeadline)
	defer timer.Stop()
	select {
	case <-allClosed:
		d.final(exitLostClean, t, dupDrains, why)
		return exitLostClean
	case <-timer.C:
		d.final(exitLostTimeout, t, dupDrains, why)
		return exitLostTimeout
	}
}

// diag writes bounded, escaped diagnostic lines to stderr. It never writes
// request values. After the first write error it stops writing and counts.
type diag struct {
	mu      sync.Mutex
	w       io.Writer
	broken  bool
	dropped uint64
}

const maxDiagLine = 512

func (d *diag) printf(format string, a ...any) {
	s := fmt.Sprintf(format, a...)
	out := make([]byte, 0, len(s)+16)
	out = append(out, "tkv0-inspector: "...)
	for i := 0; i < len(s) && len(out) < maxDiagLine; i++ {
		c := s[i]
		if c < 0x20 || c >= 0x7f || c == '\\' {
			out = fmt.Appendf(out, "\\x%02x", c)
		} else {
			out = append(out, c)
		}
	}
	out = append(out, '\n')
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.broken {
		d.dropped++
		return
	}
	if _, err := d.w.Write(out); err != nil {
		d.broken = true
		d.dropped++
	}
}

func (d *diag) final(code int, t *table, dupDrains uint64, why string) {
	s, cl, ce, disc, bad := t.counts()
	d.mu.Lock()
	dropped := d.dropped
	d.mu.Unlock()
	d.printf("exit=%d started=%d closed=%d close_errors=%d discarded=%d bad_tx_end=%d dup_drain=%d diag_dropped=%d reason=%s",
		code, s, cl, ce, disc, bad, dupDrains, dropped, why)
}
