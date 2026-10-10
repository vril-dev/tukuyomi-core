package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// loadGolden reads testdata/v0-golden.txt, the fixed byte-layout test vectors
// of protocol 0.
func loadGolden(t *testing.T) map[string][]byte {
	t.Helper()
	f, err := os.Open("testdata/v0-golden.txt")
	if err != nil {
		t.Fatalf("golden: %v", err)
	}
	defer f.Close()
	g := map[string][]byte{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 64*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, hx, ok := strings.Cut(line, " ")
		if !ok {
			t.Fatalf("golden: bad line %q", line)
		}
		b, err := hex.DecodeString(strings.TrimSpace(hx))
		if err != nil {
			t.Fatalf("golden %s: %v", name, err)
		}
		if _, dup := g[name]; dup {
			t.Fatalf("golden: duplicate %s", name)
		}
		g[name] = b
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("golden: %v", err)
	}
	return g
}

func golden(t *testing.T, g map[string][]byte, name string) []byte {
	t.Helper()
	b, ok := g[name]
	if !ok {
		t.Fatalf("golden vector %s missing", name)
	}
	return b
}

func TestGoldenOutbound(t *testing.T) {
	g := loadGolden(t)
	var nonce [16]byte
	for i := range nonce {
		nonce[i] = byte(i)
	}
	var sha [32]byte
	for i := range sha {
		sha[i] = byte(0xa0 + i)
	}
	h, err := encodeHello(testRun, testInc, hello{pid: 4242, nonce: nonce, goVersion: "go1.27.2",
		corazaVersion: "v3.8.1", corazaSum: "h1:abc=", rulesSHA256: sha, memLimit: 268435456, gomaxprocs: 2})
	if err != nil {
		t.Fatal(err)
	}
	vc, ok1 := encodeVerdict(testRun, testInc, 0x10, 1, 1, 0, 0, "", "", false)
	vb, ok2 := encodeVerdict(testRun, testInc, 0x10, 2, 2, 1021, 403, "deny", "x", true)
	v0, ok3 := encodeVerdict(testRun, testInc, 0x10, 3, 2, 0, 413, "deny", "", true)
	vt, ok4 := encodeVerdict(testRun, testInc, 0x10, 6, 4, 1040, 403, strings.Repeat("a", 33), strings.Repeat("d", 300), true)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		t.Fatal("encodeVerdict failed")
	}
	cases := map[string][]byte{
		"hello":               h,
		"verdict_continue":    vc,
		"verdict_block":       vb,
		"verdict_block_rule0": v0,
		"verdict_truncated":   vt,
		"error_not_created":   encodeError(testRun, testInc, 0x11, 1, classNotCreated, codeLimit, "concurrency limit"),
		"error_tx_failed":     encodeError(testRun, testInc, 0x10, 3, classTxFailed, codeReqTruncated, "request body shorter than declared"),
		"closed":              encodeClosed(testRun, testInc, 0x10, 7, false),
		"bye":                 encodeBye(testRun, testInc, 3, 3, 0),
	}
	for name, got := range cases {
		if want := golden(t, g, name); !bytes.Equal(got, want) {
			t.Errorf("%s:\n got %x\nwant %x", name, got, want)
		}
	}
}

func TestGoldenInbound(t *testing.T) {
	g := loadGolden(t)
	// Every inbound golden frame passes the header check of this build.
	for _, name := range []string{"tx_begin", "body", "body_end", "resp_begin", "resp_body", "resp_end", "tx_end", "drain"} {
		b := golden(t, g, name)
		if len(b) < headerLen {
			t.Fatalf("%s too short", name)
		}
		var hb [headerLen]byte
		copy(hb[:], b)
		h, err := checkHeader(&hb, testRun, testInc)
		if err != nil {
			t.Fatalf("%s: header rejected: %v", name, err)
		}
		if int(h.length) != len(b)-headerLen {
			t.Fatalf("%s: length mismatch", name)
		}
	}
	tb, err := decodeTxBegin(golden(t, g, "tx_begin")[headerLen:])
	if err != nil {
		t.Fatalf("decode tx_begin: %v", err)
	}
	if tb.clientAddr != "127.0.0.1" || tb.clientPort != 40000 || tb.serverAddr != "127.0.0.1" || tb.serverPort != 8080 ||
		tb.method != "POST" || tb.uri != "/a?q=1" || tb.proto != "HTTP/1.1" || tb.declared != 5 || len(tb.headers) != 2 ||
		tb.headers[0] != (httpHeader{"Host", "example.test"}) ||
		tb.headers[1] != (httpHeader{"Content-Type", "application/x-www-form-urlencoded"}) {
		t.Fatalf("decoded tx_begin %+v", tb)
	}
	rb, err := decodeRespBegin(golden(t, g, "resp_begin")[headerLen:])
	if err != nil {
		t.Fatalf("decode resp_begin: %v", err)
	}
	if rb.status != 200 || rb.proto != "HTTP/1.1" || rb.declared != 3 || len(rb.headers) != 1 || rb.headers[0] != (httpHeader{"Content-Type", "text/plain"}) {
		t.Fatalf("decoded resp_begin %+v", rb)
	}
	if r, err := decodeTxEnd(golden(t, g, "tx_end")[headerLen:]); err != nil || r != endComplete {
		t.Fatalf("decode tx_end %d %v", r, err)
	}
	// The test-side encoders used by the other tests produce the same bytes.
	same := map[string][]byte{
		"tx_begin":   tFrame(kindTxBegin, 0x10, 1, defaultBegin(5).payload()),
		"body":       tFrame(kindBody, 0x10, 2, []byte("a=b&c")),
		"body_end":   tFrame(kindBodyEnd, 0x10, 3, nil),
		"resp_begin": tFrame(kindRespBegin, 0x10, 4, respPayload(200, "HTTP/1.1", 3, [][2]string{{"Content-Type", "text/plain"}})),
		"resp_body":  tFrame(kindRespBody, 0x10, 5, []byte("xyz")),
		"resp_end":   tFrame(kindRespEnd, 0x10, 6, nil),
		"tx_end":     tFrame(kindTxEnd, 0x10, 7, []byte{endComplete}),
		"drain":      tFrame(kindDrain, 0, 0, nil),
	}
	for name, got := range same {
		if want := golden(t, g, name); !bytes.Equal(got, want) {
			t.Errorf("test encoder %s:\n got %x\nwant %x", name, got, want)
		}
	}
	// The test-side decoder reads the outbound golden frames.
	for _, name := range []string{"verdict_continue", "verdict_block", "verdict_block_rule0", "verdict_truncated", "error_not_created", "error_tx_failed", "closed", "bye"} {
		if _, err := parseOut(golden(t, g, name)); err != nil {
			t.Errorf("parseOut %s: %v", name, err)
		}
	}
	o, _ := parseOut(golden(t, g, "verdict_truncated"))
	if o.flags != flagActionTruncated|flagDataTruncated || len(o.act) != maxAction || len(o.data) != maxData {
		t.Errorf("truncated verdict flags %d act %d data %d", o.flags, len(o.act), len(o.data))
	}
}

func TestCheckHeaderRejects(t *testing.T) {
	good := tHeader(kindBody, 1, 2, 10)
	mut := func(f func(b []byte)) [headerLen]byte {
		var b [headerLen]byte
		copy(b[:], good)
		f(b[:])
		return b
	}
	cases := map[string][headerLen]byte{
		"magic":         mut(func(b []byte) { b[3] = '1' }),
		"unknown kind":  mut(func(b []byte) { b[4] = 0x7e }),
		"fault kind":    mut(func(b []byte) { b[4] = 0x7f }),
		"zero kind":     mut(func(b []byte) { b[4] = 0 }),
		"hello in":      mut(func(b []byte) { b[4] = kindHello }),
		"verdict in":    mut(func(b []byte) { b[4] = kindVerdict }),
		"error in":      mut(func(b []byte) { b[4] = kindError }),
		"closed in":     mut(func(b []byte) { b[4] = kindClosed }),
		"bye in":        mut(func(b []byte) { b[4] = kindBye }),
		"flags":         mut(func(b []byte) { b[5] = 1 }),
		"reserved hi":   mut(func(b []byte) { b[6] = 1 }),
		"reserved lo":   mut(func(b []byte) { b[7] = 1 }),
		"body len+1":    mut(func(b []byte) { binary.BigEndian.PutUint32(b[8:], maxBody+1) }),
		"body len max":  mut(func(b []byte) { binary.BigEndian.PutUint32(b[8:], 0xffffffff) }),
		"bodyend len 1": mut(func(b []byte) { b[4] = kindBodyEnd; binary.BigEndian.PutUint32(b[8:], 1) }),
		"txend len 9":   mut(func(b []byte) { b[4] = kindTxEnd; binary.BigEndian.PutUint32(b[8:], 9) }),
		"begin len+1":   mut(func(b []byte) { b[4] = kindTxBegin; binary.BigEndian.PutUint32(b[8:], maxTxBegin+1) }),
		"run":           mut(func(b []byte) { b[19] ^= 1 }),
		"incarnation":   mut(func(b []byte) { b[23] ^= 1 }),
		"tx zero":       mut(func(b []byte) { binary.BigEndian.PutUint64(b[24:], 0) }),
		"msg zero":      mut(func(b []byte) { binary.BigEndian.PutUint32(b[32:], 0) }),
		"drain tx": mut(func(b []byte) {
			b[4] = kindDrain
			binary.BigEndian.PutUint32(b[8:], 0)
			binary.BigEndian.PutUint32(b[32:], 0)
		}),
		"drain msg": mut(func(b []byte) {
			b[4] = kindDrain
			binary.BigEndian.PutUint32(b[8:], 0)
			binary.BigEndian.PutUint64(b[24:], 0)
		}),
		"drain len": mut(func(b []byte) {
			b[4] = kindDrain
			binary.BigEndian.PutUint64(b[24:], 0)
			binary.BigEndian.PutUint32(b[32:], 0)
		}),
	}
	for name, b := range cases {
		_, err := checkHeader(&b, testRun, testInc)
		var ce *errConn
		if !errors.As(err, &ce) {
			t.Errorf("%s: got %v, want connection-wide error", name, err)
		}
	}
	// Boundaries that are accepted.
	ok := map[string][headerLen]byte{
		"body len max":  mut(func(b []byte) { binary.BigEndian.PutUint32(b[8:], maxBody) }),
		"begin len max": mut(func(b []byte) { b[4] = kindTxBegin; binary.BigEndian.PutUint32(b[8:], maxTxBegin) }),
		"txend len 8":   mut(func(b []byte) { b[4] = kindTxEnd; binary.BigEndian.PutUint32(b[8:], 8) }),
		"drain": mut(func(b []byte) {
			b[4] = kindDrain
			binary.BigEndian.PutUint32(b[8:], 0)
			binary.BigEndian.PutUint64(b[24:], 0)
			binary.BigEndian.PutUint32(b[32:], 0)
		}),
		"tx max":         mut(func(b []byte) { binary.BigEndian.PutUint64(b[24:], ^uint64(0)) }),
		"resp body max":  mut(func(b []byte) { b[4] = kindRespBody; binary.BigEndian.PutUint32(b[8:], maxBody) }),
		"resp begin max": mut(func(b []byte) { b[4] = kindRespBegin; binary.BigEndian.PutUint32(b[8:], maxTxBegin) }),
	}
	for name, b := range ok {
		if _, err := checkHeader(&b, testRun, testInc); err != nil {
			t.Errorf("%s: unexpected %v", name, err)
		}
	}
}

// countingReader serves fixed bytes and records how many were consumed.
type countingReader struct {
	r        *bytes.Reader
	read     int
	deadline []time.Time
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read += n
	return n, err
}

func (c *countingReader) SetReadDeadline(t time.Time) error {
	c.deadline = append(c.deadline, t)
	return nil
}

func TestReadFrameRejectsBeforeAllocation(t *testing.T) {
	// A header announcing 4 GiB is rejected after exactly 36 bytes; no payload
	// read is attempted (the reader has more bytes than that available).
	b := tHeader(kindBody, 1, 2, 0)
	binary.BigEndian.PutUint32(b[8:], 0xffffffff)
	cr := &countingReader{r: bytes.NewReader(append(b, make([]byte, 100)...))}
	_, _, err := readFrame(cr, testRun, testInc, time.Second)
	var ce *errConn
	if !errors.As(err, &ce) || cr.read != headerLen {
		t.Fatalf("err %v read %d", err, cr.read)
	}
	// One clear before the first byte, one absolute deadline after it.
	if len(cr.deadline) != 2 || !cr.deadline[0].IsZero() || cr.deadline[1].IsZero() {
		t.Fatalf("deadlines %v", cr.deadline)
	}
}

func TestReadFrameEOF(t *testing.T) {
	full := tFrame(kindBody, 1, 2, []byte("hello"))
	if _, _, err := readFrame(&countingReader{r: bytes.NewReader(nil)}, testRun, testInc, time.Second); !errors.Is(err, errPeerEOF) {
		t.Fatalf("clean EOF: %v", err)
	}
	for _, n := range []int{1, 2, 35, 36, 37, len(full) - 1} {
		_, _, err := readFrame(&countingReader{r: bytes.NewReader(full[:n])}, testRun, testInc, time.Second)
		var ce *errConn
		if !errors.As(err, &ce) {
			t.Errorf("cut at %d: %v, want connection-wide", n, err)
		}
	}
	h, p, err := readFrame(&countingReader{r: bytes.NewReader(full)}, testRun, testInc, time.Second)
	if err != nil || h.kind != kindBody || string(p) != "hello" {
		t.Fatalf("full frame: %v %v %q", err, h, p)
	}
}

func TestReadFrameDeadlines(t *testing.T) {
	const timeout = 150 * time.Millisecond
	frame := tFrame(kindBody, 1, 2, []byte("abcdefgh"))

	t.Run("no deadline before first byte", func(t *testing.T) {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		go func() {
			time.Sleep(3 * timeout)
			b.Write(frame)
		}()
		if _, _, err := readFrame(a, testRun, testInc, timeout); err != nil {
			t.Fatalf("idle before the first byte must not time out: %v", err)
		}
	})
	t.Run("stall after first byte", func(t *testing.T) {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		go b.Write(frame[:1])
		start := time.Now()
		_, _, err := readFrame(a, testRun, testInc, timeout)
		var ce *errConn
		if !errors.As(err, &ce) || !strings.Contains(err.Error(), "timeout") {
			t.Fatalf("got %v", err)
		}
		if el := time.Since(start); el < timeout || el > 10*timeout {
			t.Fatalf("elapsed %v", el)
		}
	})
	t.Run("absolute deadline with dripping bytes", func(t *testing.T) {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		go func() {
			for i := range frame {
				if _, err := b.Write(frame[i : i+1]); err != nil {
					return
				}
				time.Sleep(timeout / 5) // each byte is well within the timeout
			}
		}()
		_, _, err := readFrame(a, testRun, testInc, timeout)
		var ce *errConn
		if !errors.As(err, &ce) {
			t.Fatalf("a frame slower than the absolute deadline must fail, got %v", err)
		}
	})
}

// scriptWriter returns scripted (n, err) results and records deadlines.
type scriptWriter struct {
	steps     []func(p []byte) (int, error)
	buf       bytes.Buffer
	deadlines int
}

func (w *scriptWriter) Write(p []byte) (int, error) {
	if len(w.steps) == 0 {
		w.buf.Write(p)
		return len(p), nil
	}
	s := w.steps[0]
	w.steps = w.steps[1:]
	n, err := s(p)
	if n > 0 && n <= len(p) {
		w.buf.Write(p[:n])
	}
	return n, err
}

func (w *scriptWriter) SetWriteDeadline(time.Time) error { w.deadlines++; return nil }

func TestWriteFrameShortWrites(t *testing.T) {
	frame := tFrame(kindBody, 1, 2, bytes.Repeat([]byte("x"), 100))
	one := func(p []byte) (int, error) { return 1, nil }
	w := &scriptWriter{steps: []func([]byte) (int, error){one, one, one, func(p []byte) (int, error) { return 50, nil }}}
	if err := writeFrame(w, frame, time.Second); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(w.buf.Bytes(), frame) || w.deadlines != 1 {
		t.Fatalf("written %d bytes, deadlines %d", w.buf.Len(), w.deadlines)
	}
	w = &scriptWriter{steps: []func([]byte) (int, error){one, func(p []byte) (int, error) { return 0, nil }}}
	if err := writeFrame(w, frame, time.Second); !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("zero progress: %v", err)
	}
	boom := errors.New("boom")
	w = &scriptWriter{steps: []func([]byte) (int, error){func(p []byte) (int, error) { return 3, boom }}}
	if err := writeFrame(w, frame, time.Second); !errors.Is(err, boom) {
		t.Fatalf("mid-frame error: %v", err)
	}
	w = &scriptWriter{steps: []func([]byte) (int, error){func(p []byte) (int, error) { return len(p) + 1, nil }}}
	if err := writeFrame(w, frame, time.Second); err == nil {
		t.Fatal("over-count accepted")
	}
}

func TestWriteFrameDeadline(t *testing.T) {
	a, b := net.Pipe() // nobody reads b: the write must fail at the deadline
	defer a.Close()
	defer b.Close()
	start := time.Now()
	err := writeFrame(a, tFrame(kindBody, 1, 2, []byte("x")), 100*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("got %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("deadline not applied")
	}
}

func beginWith(f func(b *tBegin)) []byte {
	b := defaultBegin(0)
	f(&b)
	return b.payload()
}

func TestDecodeTxBeginBounds(t *testing.T) {
	s := strings.Repeat
	many := func(n int, name, value string) [][2]string {
		hs := make([][2]string, n)
		for i := range hs {
			hs[i] = [2]string{name, value}
		}
		return hs
	}
	accept := map[string][]byte{
		"min fields": beginWith(func(b *tBegin) {
			b.client, b.server, b.method, b.uri, b.proto, b.headers = "a", "b", "G", "/", "H", nil
		}),
		"max addr":     beginWith(func(b *tBegin) { b.client, b.server = s("1", maxAddr), s("2", maxAddr) }),
		"max method":   beginWith(func(b *tBegin) { b.method = s("M", maxMethod) }),
		"max uri":      beginWith(func(b *tBegin) { b.uri = s("u", maxURI) }),
		"max proto":    beginWith(func(b *tBegin) { b.proto = s("p", maxProto) }),
		"max declared": beginWith(func(b *tBegin) { b.declared = maxDeclared }),
		"64 headers":   beginWith(func(b *tBegin) { b.headers = many(maxHeaders, "n", "v") }),
		"max name":     beginWith(func(b *tBegin) { b.headers = [][2]string{{s("n", maxHdrName), ""}} }),
		"max value":    beginWith(func(b *tBegin) { b.headers = [][2]string{{"n", s("v", maxHdrValue)}} }),
		// 6 x (256 + 3840) = 24576 exactly.
		"max total": beginWith(func(b *tBegin) { b.headers = many(6, s("n", 256), s("v", 3840)) }),
	}
	for name, p := range accept {
		if _, err := decodeTxBegin(p); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	reject := map[string][]byte{
		"empty client":   beginWith(func(b *tBegin) { b.client = "" }),
		"long client":    beginWith(func(b *tBegin) { b.client = s("1", maxAddr+1) }),
		"empty server":   beginWith(func(b *tBegin) { b.server = "" }),
		"empty method":   beginWith(func(b *tBegin) { b.method = "" }),
		"long method":    beginWith(func(b *tBegin) { b.method = s("M", maxMethod+1) }),
		"empty uri":      beginWith(func(b *tBegin) { b.uri = "" }),
		"long uri":       beginWith(func(b *tBegin) { b.uri = s("u", maxURI+1) }),
		"empty proto":    beginWith(func(b *tBegin) { b.proto = "" }),
		"long proto":     beginWith(func(b *tBegin) { b.proto = s("p", maxProto+1) }),
		"declared+1":     beginWith(func(b *tBegin) { b.declared = maxDeclared + 1 }),
		"declared max64": beginWith(func(b *tBegin) { b.declared = ^uint64(0) }),
		"65 headers":     beginWith(func(b *tBegin) { b.headers = many(maxHeaders+1, "n", "v") }),
		"empty name":     beginWith(func(b *tBegin) { b.headers = [][2]string{{"", "v"}} }),
		"long name":      beginWith(func(b *tBegin) { b.headers = [][2]string{{s("n", maxHdrName+1), ""}} }),
		"long value":     beginWith(func(b *tBegin) { b.headers = [][2]string{{"n", s("v", maxHdrValue+1)}} }),
		"total+1":        beginWith(func(b *tBegin) { b.headers = append(many(6, s("n", 256), s("v", 3840)), [2]string{"x", ""}) }),
		"trailing byte":  append(defaultBegin(0).payload(), 0),
		"truncated":      defaultBegin(0).payload()[:20],
		"empty payload":  {},
	}
	for name, p := range reject {
		if _, err := decodeTxBegin(p); !errors.Is(err, errContent) {
			t.Errorf("%s: got %v, want errContent", name, err)
		}
	}
	// A count of 65 is rejected before any header is read, even with the
	// payload cut right after the count.
	c := defaultBegin(0)
	c.headers = nil
	p := c.payload()
	binary.BigEndian.PutUint16(p[len(p)-2:], maxHeaders+1)
	if _, err := decodeTxBegin(p); !errors.Is(err, errContent) {
		t.Errorf("count 65 without headers: %v", err)
	}
	// A string length pointing past the end of the payload.
	q := defaultBegin(0).payload()
	binary.BigEndian.PutUint16(q[0:], 0xffff)
	if _, err := decodeTxBegin(q); !errors.Is(err, errContent) {
		t.Errorf("length past end: %v", err)
	}
}

func TestDecodeRespBeginAndTxEnd(t *testing.T) {
	for _, st := range []uint16{100, 200, 999} {
		if _, err := decodeRespBegin(respPayload(st, "HTTP/1.1", 0, nil)); err != nil {
			t.Errorf("status %d: %v", st, err)
		}
	}
	bad := map[string][]byte{
		"status 99":   respPayload(99, "HTTP/1.1", 0, nil),
		"status 1000": respPayload(1000, "HTTP/1.1", 0, nil),
		"empty proto": respPayload(200, "", 0, nil),
		"declared+1":  respPayload(200, "HTTP/1.1", maxDeclared+1, nil),
		"trailing":    append(respPayload(200, "HTTP/1.1", 0, nil), 1),
		"empty name":  respPayload(200, "HTTP/1.1", 0, [][2]string{{"", "x"}}),
		"empty":       {},
	}
	for name, p := range bad {
		if _, err := decodeRespBegin(p); !errors.Is(err, errContent) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for r := endComplete; r <= endDeadline; r++ {
		if got, err := decodeTxEnd([]byte{r}); err != nil || got != r {
			t.Errorf("reason %d: %v", r, err)
		}
	}
	for name, p := range map[string][]byte{"zero": {0}, "six": {6}, "empty": {}, "two bytes": {1, 0}} {
		if _, err := decodeTxEnd(p); !errors.Is(err, errContent) {
			t.Errorf("tx_end %s: %v", name, err)
		}
	}
}

func TestEncodeLimits(t *testing.T) {
	if _, ok := encodeVerdict(testRun, testInc, 1, 1, 1, 1, 65536, "deny", "", true); ok {
		t.Error("status 65536 accepted")
	}
	if _, ok := encodeVerdict(testRun, testInc, 1, 1, 1, 1, -1, "deny", "", true); ok {
		t.Error("status -1 accepted")
	}
	b, ok := encodeVerdict(testRun, testInc, 1, 1, 1, -7, 65535, strings.Repeat("a", 32), strings.Repeat("d", 256), true)
	o, err := parseOut(b)
	if !ok || err != nil || o.flags != 0 || o.rule != -7 || o.stat != 65535 {
		t.Errorf("boundary verdict: ok %v err %v %+v", ok, err, o)
	}
	e := encodeError(testRun, testInc, 1, 1, classTxFailed, codeOrder, strings.Repeat("x", 1000))
	if o, err := parseOut(e); err != nil || len(o.text) != maxErrMsg || len(e)-headerLen > maxError {
		t.Errorf("long error text: %v %d", err, len(o.text))
	}
	long := hello{pid: 1, goVersion: strings.Repeat("g", 65), corazaVersion: "v", corazaSum: "s"}
	if _, err := encodeHello(1, 1, long); err == nil {
		t.Error("long go version accepted")
	}
	maxed := hello{pid: 1, goVersion: strings.Repeat("g", 64), corazaVersion: strings.Repeat("v", 64), corazaSum: strings.Repeat("s", 128), memLimit: 1 << 62}
	if b, err := encodeHello(1, 1, maxed); err != nil || len(b)-headerLen > maxHello {
		t.Errorf("max hello: %v", err)
	}
}
