package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

const (
	prGetNoNewPrivs   = 39 // PR_GET_NO_NEW_PRIVS
	prCapAmbientIsSet = 1  // PR_CAP_AMBIENT_IS_SET
	capNetBindService = 10 // CAP_NET_BIND_SERVICE

	// probeThreads is the number of threads that exist before the sandbox and
	// are probed after it, one goroutine each.
	probeThreads = 4
)

// The rights handled per ABI version, at the borders where a version adds
// some: 1 to 2 (REFER), 2 to 3 (TRUNCATE), 3 to 4 (TCP), 4 to 5 (IOCTL_DEV).
func TestHandledRights(t *testing.T) {
	for _, c := range []struct {
		abi     int
		fs, tcp uint64
	}{
		{1, 0x1fff, 0},
		{2, 0x3fff, 0},
		{3, 0x7fff, 0},
		{4, 0x7fff, 0x3},
		{5, 0xffff, 0x3},
		{8, 0xffff, 0x3},
	} {
		if fs, tcp := handledRights(c.abi); fs != c.fs || tcp != c.tcp {
			t.Errorf("abi %d: fs %#x tcp %#x, want fs %#x tcp %#x", c.abi, fs, tcp, c.fs, c.tcp)
		}
	}
}

// A kernel without Landlock (ENOSYS) or with it switched off (EOPNOTSUPP) is
// "not available"; any other errno is an error that keeps its errno.
func TestABIError(t *testing.T) {
	for _, e := range []syscall.Errno{syscall.ENOSYS, syscall.EOPNOTSUPP} {
		if err := abiError(e); !errors.Is(err, errNoLandlock) {
			t.Errorf("%v: %v", e, err)
		}
	}
	for _, e := range []syscall.Errno{syscall.EPERM, syscall.EINVAL} {
		if err := abiError(e); err == nil || errors.Is(err, errNoLandlock) || !errors.Is(err, e) {
			t.Errorf("%v: %v", e, err)
		}
	}
}

// The sandbox cannot be undone, so it is applied in a child process: the test
// binary runs itself in the mode "sandbox" (TestMain), which applies it to a
// fresh TMPDIR and prints one line "name=result" for each thing it then tries.
// The parent checks the lines. The child also tries from threads that existed
// before the sandbox, to see that every thread was restricted.
func TestSandbox(t *testing.T) {
	abi, err := landlockABI()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	tmp := filepath.Join(dir, "tmp")
	if err := os.Mkdir(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(dir, "outside")
	if err := os.WriteFile(outside, []byte("readable"), 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0])
	cmd.Env = []string{
		"TKV0_TEST_MODE=sandbox", "TKV0_TEST_OUTSIDE=" + outside, "TKV0_TEST_CONNECT=" + ln.Addr().String(),
		"TMPDIR=" + tmp, "GOMAXPROCS=2",
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("probe: %v (stdout %q, stderr %q)", err, out, stderr.String())
	}

	denied := syscall.EACCES.Error()
	tcp := "ok" // Landlock restricts TCP from ABI 4
	if abi >= 4 {
		tcp = denied
	}
	want := []string{
		"sandbox=ok",
		"read outside=" + denied,
		"files in TMPDIR=ok",
		"mkdir in TMPDIR=" + denied,
		"list TMPDIR=" + denied,
		"exec=" + denied,
		"listen=" + tcp,
		"connect=" + tcp,
		"capabilities=ok",
		"threads=ok",
	}
	if got := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n"); !slices.Equal(got, want) {
		t.Fatalf("abi %d: got\n%s\nwant\n%s\n(stderr %q)", abi, strings.Join(got, "\n"), strings.Join(want, "\n"), stderr.String())
	}
}

// sandboxProbe is the child of TestSandbox. It returns the exit code.
func sandboxProbe() int {
	tmp, outside, connect := os.Getenv("TMPDIR"), os.Getenv("TKV0_TEST_OUTSIDE"), os.Getenv("TKV0_TEST_CONNECT")

	// Threads that exist before the sandbox: each is held by a goroutine that
	// stays on its thread and waits.
	ready, start, done := make(chan struct{}), make(chan struct{}), make(chan string)
	for i := 0; i < probeThreads; i++ {
		go func() {
			runtime.LockOSThread()
			ready <- struct{}{}
			<-start
			done <- confined(outside)
		}()
	}
	for i := 0; i < probeThreads; i++ {
		<-ready
	}

	if err := sandbox(tmp); err != nil {
		fmt.Println("sandbox=" + result(err)) // the probes below would run unrestricted
		return 1
	}
	lines := []string{"sandbox=ok"}
	_, err := os.ReadFile(outside)
	lines = append(lines, "read outside="+result(err))
	lines = append(lines, "files in TMPDIR="+result(tmpFiles(tmp)))
	lines = append(lines, "mkdir in TMPDIR="+result(syscall.Mkdir(filepath.Join(tmp, "d"), 0o700)))
	_, err = os.ReadDir(tmp)
	lines = append(lines, "list TMPDIR="+result(err))
	lines = append(lines, "exec="+result(syscall.Exec("/bin/true", []string{"true"}, nil))) // returns only on an error
	lines = append(lines, "listen="+result(listenOnce()))
	lines = append(lines, "connect="+result(dialOnce(connect)))
	lines = append(lines, "capabilities="+capsLeft())

	close(start)
	threads := "ok"
	for i := 0; i < probeThreads; i++ {
		if r := <-done; r != "ok" {
			threads = r
		}
	}
	lines = append(lines, "threads="+threads)
	fmt.Println(strings.Join(lines, "\n"))
	return 0
}

// result is "ok" for nil, the errno text for an error that holds an errno (no
// path in it) and the text of the error otherwise.
func result(err error) string {
	var errno syscall.Errno
	switch {
	case err == nil:
		return "ok"
	case errors.As(err, &errno):
		return errno.Error()
	}
	return err.Error()
}

// tmpFiles does with a file in dir what Coraza does there: create and write it,
// cut it, read it and remove it.
func tmpFiles(dir string) error {
	p := filepath.Join(dir, "probe")
	if err := os.WriteFile(p, []byte("abc"), 0o600); err != nil {
		return err
	}
	if err := os.Truncate(p, 1); err != nil {
		return err
	}
	if b, err := os.ReadFile(p); err != nil || string(b) != "a" {
		return fmt.Errorf("read back %q: %v", b, err)
	}
	return os.Remove(p)
}

// listenOnce and dialOnce ask for plain TCP: Go listens with MPTCP when the
// host has it, and Landlock does not restrict MPTCP sockets.
func listenOnce() error {
	var lc net.ListenConfig
	lc.SetMultipathTCP(false)
	l, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err == nil {
		l.Close()
	}
	return err
}

func dialOnce(addr string) error {
	var d net.Dialer
	d.SetMultipathTCP(false)
	c, err := d.Dial("tcp", addr)
	if err == nil {
		c.Close()
	}
	return err
}

// confined checks, on the thread of the calling goroutine (which must be
// locked to it), the things that do not depend on the others: a file outside
// TMPDIR cannot be read, no_new_privs is set and no capability is left.
func confined(outside string) string {
	if _, err := os.ReadFile(outside); !errors.Is(err, syscall.EACCES) {
		return "read outside: " + result(err)
	}
	if v, _, _ := syscall.Syscall6(syscall.SYS_PRCTL, prGetNoNewPrivs, 0, 0, 0, 0, 0); v != 1 {
		return "no_new_privs is not set"
	}
	return capsLeft()
}

// capsLeft reads the capability sets of the calling thread: "ok" when the
// effective, permitted and inheritable sets are empty and CAP_NET_BIND_SERVICE
// is not ambient.
func capsLeft() string {
	var header [8]byte // version, pid 0 (this thread)
	binary.NativeEndian.PutUint32(header[0:], linuxCapabilityVersion3)
	var data [24]byte // two words of effective, permitted and inheritable
	if _, _, e := syscall.Syscall(syscall.SYS_CAPGET, uintptr(unsafe.Pointer(&header[0])), uintptr(unsafe.Pointer(&data[0])), 0); e != 0 {
		return "capget: " + e.Error()
	}
	if data != [24]byte{} {
		return fmt.Sprintf("capabilities left: %x", data)
	}
	set, _, e := syscall.Syscall6(syscall.SYS_PRCTL, prCapAmbient, prCapAmbientIsSet, capNetBindService, 0, 0, 0)
	if e != 0 || set != 0 {
		return fmt.Sprintf("ambient CAP_NET_BIND_SERVICE: %d, %v", set, e)
	}
	return "ok"
}
