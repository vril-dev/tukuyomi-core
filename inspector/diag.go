package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// diag writes bounded, escaped diagnostic lines to stderr. It never writes
// request values. After the first write error it stops writing and counts.
type diag struct {
	mu      sync.Mutex
	w       io.Writer
	broken  bool
	dropped uint64
	tmp     string // the TMPDIR that parseConfig accepted; empty until then
}

// maxDiagLine is the most bytes of one diagnostic line, the newline included.
const maxDiagLine = 512

// startFailureName is the file in TMPDIR that holds the line of a failed start,
// for the process that started this one.
const startFailureName = "start-failure"

// diagLine formats one diagnostic line: the prefix, the text with every byte
// outside 0x20 to 0x7e and the backslash written as \xNN, and a newline. The
// text is cut before an escape that would not fit, so the line has at most
// maxDiagLine bytes and no half of an escape.
func diagLine(format string, a ...any) []byte {
	s := fmt.Sprintf(format, a...)
	out := make([]byte, 0, maxDiagLine)
	out = append(out, "tkv0-inspector: "...)
	for i := 0; i < len(s); i++ {
		c := s[i]
		escape := c < 0x20 || c >= 0x7f || c == '\\'
		n := 1
		if escape {
			n = 4
		}
		if len(out)+n > maxDiagLine-1 { // one byte stays for the newline
			break
		}
		if escape {
			out = fmt.Appendf(out, "\\x%02x", c)
		} else {
			out = append(out, c)
		}
	}
	return append(out, '\n')
}

func (d *diag) printf(format string, a ...any) { d.write(diagLine(format, a...)) }

func (d *diag) write(line []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.broken {
		d.dropped++
		return
	}
	if _, err := d.w.Write(line); err != nil {
		d.broken = true
		d.dropped++
	}
}

// startFail reports a failure to start and returns code. The line goes to
// stderr and, once parseConfig has accepted TMPDIR, the same bytes go to the
// file start-failure in it. The file is for the process that started this one;
// when it cannot be written the start has failed anyway, so only a note is made.
func (d *diag) startFail(code int, format string, a ...any) int {
	line := diagLine(format, a...)
	d.write(line)
	if d.tmp != "" {
		if err := writeStartFailure(d.tmp, line); err != nil {
			d.printf("start: %s: %v", startFailureName, withoutPath(err))
		}
	}
	return code
}

// writeStartFailure creates start-failure in dir, which must be the TMPDIR that
// checkTmpDir accepted, and writes line to it. The file must not exist and a
// link in its place is not followed (O_EXCL, O_NOFOLLOW), and only we can read
// it (0600).
func writeStartFailure(dir string, line []byte) error {
	f, err := os.OpenFile(filepath.Join(dir, startFailureName), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(line); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func (d *diag) final(code int, t *table, dupDrains uint64, why string) {
	s, cl, ce, disc, bad := t.counts()
	d.mu.Lock()
	dropped := d.dropped
	d.mu.Unlock()
	d.printf("exit=%d started=%d closed=%d close_errors=%d discarded=%d bad_tx_end=%d dup_drain=%d diag_dropped=%d reason=%s",
		code, s, cl, ce, disc, bad, dupDrains, dropped, why)
}
