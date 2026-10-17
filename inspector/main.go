// Command inspector is the Go inspection process. It talks protocol 0 over a
// socketpair inherited as fd 0 and inspects requests with the Coraza Go API.
package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"
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
