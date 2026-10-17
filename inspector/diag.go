package main

import (
	"fmt"
	"io"
	"sync"
)

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
