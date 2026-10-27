package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// loadGolden reads testdata/v1-golden.txt, the fixed byte-layout test vectors
// of protocol 1.
func loadGolden(t *testing.T) map[string][]byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/v1-golden.txt")
	if err != nil {
		t.Fatalf("golden: %v", err)
	}
	g := map[string][]byte{}
	for _, line := range strings.Split(string(raw), "\n") {
		if line = strings.TrimSpace(line); line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, hx, _ := strings.Cut(line, " ")
		b, err := hex.DecodeString(strings.TrimSpace(hx))
		if err != nil {
			t.Fatalf("golden %s: %v", name, err)
		}
		g[name] = b
	}
	return g
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
	verdict := func(msg uint32, phase uint8, rule, status int, action, data string, block bool, d ruleDetail) []byte {
		b, ok := encodeVerdict(testRun, testInc, 0x10, msg, phase, rule, status, action, data, block, d)
		if !ok {
			t.Fatalf("encodeVerdict of msg %d failed", msg)
		}
		return b
	}
	rules := func(ids []int64, severity uint8, score int32) ruleDetail {
		return ruleDetail{ids: ids, severity: severity, score: score}
	}
	var many []int64
	for i := range int64(maxRuleIDs) {
		many = append(many, 930100+i)
	}
	vd, ok := encodeDetected(testRun, testInc, 0x10, 4, 949110, 403, "deny", "", rules([]int64{942100, 941100}, 2, 10))
	if !ok {
		t.Fatal("encodeDetected failed")
	}
	more := rules(many, 2, 80)
	more.more = true
	cases := map[string][]byte{
		"hello":                  h,
		"verdict_continue":       verdict(1, 1, 0, 0, "", "", false, noDetail),
		"verdict_block":          verdict(2, 2, 1021, 403, "deny", "x", true, rules([]int64{942100}, 2, 5)),
		"verdict_block_rule0":    verdict(3, 2, 0, 413, "deny", "", true, noDetail),
		"verdict_truncated":      verdict(6, 4, 1040, 403, strings.Repeat("a", 33), strings.Repeat("d", 300), true, noDetail),
		"verdict_detected":       vd,
		"verdict_allow_rules":    verdict(5, 2, 0, 0, "", "", false, rules([]int64{920280, 942100, 7000005}, 5, 0)),
		"verdict_rules_more":     verdict(7, 2, 949110, 403, "deny", "", true, more),
		"verdict_rules_severity": verdict(8, 1, 7000006, 403, "deny", "", true, rules(nil, 3, scoreNone)),
		"error_not_created":      encodeError(testRun, testInc, 0x11, 1, classNotCreated, codeLimit, "concurrency limit"),
		"error_tx_failed":        encodeError(testRun, testInc, 0x10, 3, classTxFailed, codeReqTruncated, "request body shorter than declared"),
		"closed":                 encodeClosed(testRun, testInc, 0x10, 7, false),
		"bye":                    encodeBye(testRun, testInc, 3, 3, 0),
	}
	// Every valid VERDICT of the golden file is made here. The bad_ ones are
	// not the output of an encoder: TestEncodeDetailLimits refuses their values.
	for name, b := range g {
		if b[4] == kindVerdict && !strings.HasPrefix(name, "bad_") && cases[name] == nil {
			t.Errorf("%s: no encoder case", name)
		}
	}
	for name, got := range cases {
		if want := g[name]; !bytes.Equal(got, want) {
			t.Errorf("%s:\n got %x\nwant %x", name, got, want)
		}
	}
}

func TestGoldenInbound(t *testing.T) {
	g := loadGolden(t)
	// Every inbound golden frame passes the header check of this build.
	for _, name := range []string{"tx_begin", "tx_begin_cut", "body", "body_end", "resp_begin", "resp_body", "resp_end", "tx_end", "drain"} {
		b := g[name]
		var hb [headerLen]byte
		copy(hb[:], b)
		h, err := checkHeader(&hb, testRun, testInc)
		if err != nil || int(h.length) != len(b)-headerLen {
			t.Fatalf("%s: header %v, length %d of %d bytes", name, err, h.length, len(b))
		}
	}
	tb, err := decodeTxBegin(g["tx_begin"][headerLen:])
	if err != nil {
		t.Fatalf("decode tx_begin: %v", err)
	}
	if tb.clientAddr != "127.0.0.1" || tb.clientPort != 40000 || tb.serverAddr != "127.0.0.1" || tb.serverPort != 8080 ||
		tb.method != "POST" || tb.uri != "/a?q=1" || tb.proto != "HTTP/1.1" || tb.declared != 5 || len(tb.headers) != 2 ||
		tb.headers[0] != (httpHeader{"Host", "example.test"}) ||
		tb.headers[1] != (httpHeader{"Content-Type", "application/x-www-form-urlencoded"}) {
		t.Fatalf("decoded tx_begin %+v", tb)
	}
	// tx_begin_cut is tx_begin with the header flag of a body that goes on past
	// the declared bytes: the flag is read from the header, the payload is the
	// same.
	var hb, hc [headerLen]byte
	copy(hb[:], g["tx_begin"])
	copy(hc[:], g["tx_begin_cut"])
	h, _ := checkHeader(&hb, testRun, testInc)
	hCut, _ := checkHeader(&hc, testRun, testInc)
	if h.cut || !hCut.cut || !bytes.Equal(g["tx_begin"][headerLen:], g["tx_begin_cut"][headerLen:]) {
		t.Fatalf("tx_begin cut %v, tx_begin_cut cut %v, same payload %v", h.cut, hCut.cut,
			bytes.Equal(g["tx_begin"][headerLen:], g["tx_begin_cut"][headerLen:]))
	}
	if cb, err := decodeTxBegin(g["tx_begin_cut"][headerLen:]); err != nil || cb.declared != tb.declared || cb.uri != tb.uri {
		t.Fatalf("decode tx_begin_cut: %v %+v", err, cb)
	}
}

func TestCheckHeaderRejects(t *testing.T) {
	check := func(mutate func(b []byte)) error {
		var b [headerLen]byte
		copy(b[:], tHeader(kindBody, 1, 2, 10))
		mutate(b[:])
		_, err := checkHeader(&b, testRun, testInc)
		return err
	}
	setLen := func(kind uint8, n uint32) func(b []byte) {
		return func(b []byte) { b[4] = kind; binary.BigEndian.PutUint32(b[8:], n) }
	}
	// A control frame has no length, tx or msg; f then breaks one of them.
	control := func(f func(b []byte)) func(b []byte) {
		return func(b []byte) {
			b[4] = kindDrain
			binary.BigEndian.PutUint32(b[8:], 0)
			binary.BigEndian.PutUint64(b[24:], 0)
			binary.BigEndian.PutUint32(b[32:], 0)
			f(b)
		}
	}
	reject := map[string]func(b []byte){
		"magic":         func(b []byte) { b[3] = '1' },
		"unknown kind":  func(b []byte) { b[4] = 0x7e },
		"fault kind":    func(b []byte) { b[4] = 0x7f },
		"hello in":      func(b []byte) { b[4] = kindHello },
		"verdict in":    func(b []byte) { b[4] = kindVerdict },
		"flags":         func(b []byte) { b[5] = 1 },
		"flags 2 begin": func(b []byte) { b[4], b[5] = kindTxBegin, 2 },
		"flags 3 begin": func(b []byte) { b[4], b[5] = kindTxBegin, 3 },
		"flags tx end":  func(b []byte) { setLen(kindTxEnd, 1)(b); b[5] = 1 },
		"reserved":      func(b []byte) { b[7] = 1 },
		"body len+1":    setLen(kindBody, maxBody+1),
		"bodyend len 1": setLen(kindBodyEnd, 1),
		"txend len 9":   setLen(kindTxEnd, 9),
		"begin len+1":   setLen(kindTxBegin, maxTxBegin+1),
		"run":           func(b []byte) { b[19] ^= 1 },
		"incarnation":   func(b []byte) { b[23] ^= 1 },
		"tx zero":       func(b []byte) { binary.BigEndian.PutUint64(b[24:], 0) },
		"msg zero":      func(b []byte) { binary.BigEndian.PutUint32(b[32:], 0) },
		"drain tx":      control(func(b []byte) { b[31] = 1 }),
		"drain msg":     control(func(b []byte) { b[35] = 1 }),
		"drain len":     control(func(b []byte) { b[11] = 1 }),
	}
	for name, f := range reject {
		var ce *errConn
		if err := check(f); !errors.As(err, &ce) {
			t.Errorf("%s: got %v, want connection-wide error", name, err)
		}
	}
	// The limits themselves are accepted.
	accept := map[string]func(b []byte){
		"body len max":  setLen(kindBody, maxBody),
		"begin len max": setLen(kindTxBegin, maxTxBegin),
		"txend len 8":   setLen(kindTxEnd, 8),
		"drain":         control(func([]byte) {}),
		"tx max":        func(b []byte) { binary.BigEndian.PutUint64(b[24:], ^uint64(0)) },
		"flags 1 begin": func(b []byte) { b[4], b[5] = kindTxBegin, 1 },
	}
	for name, f := range accept {
		if err := check(f); err != nil {
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

// stepWriter takes at most max bytes per Write and records them.
type stepWriter struct {
	max       int
	buf       bytes.Buffer
	deadlines int
}

func (w *stepWriter) Write(p []byte) (int, error) {
	p = p[:min(len(p), w.max)]
	return w.buf.Write(p)
}

func (w *stepWriter) SetWriteDeadline(time.Time) error { w.deadlines++; return nil }

func TestWriteFrameShortWrites(t *testing.T) {
	frame := tFrame(kindBody, 1, 2, bytes.Repeat([]byte("x"), 100))
	w := &stepWriter{max: 7}
	if err := writeFrame(w, frame, time.Second); err != nil || !bytes.Equal(w.buf.Bytes(), frame) || w.deadlines != 1 {
		t.Fatalf("short writes: %v, written %d bytes, deadlines %d", err, w.buf.Len(), w.deadlines)
	}
	if err := writeFrame(&stepWriter{}, frame, time.Second); !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("zero progress: %v", err)
	}
}

func TestDecodeTxBeginBounds(t *testing.T) {
	rep := strings.Repeat
	many := func(n int, name, value string) [][2]string {
		hs := make([][2]string, n)
		for i := range hs {
			hs[i] = [2]string{name, value}
		}
		return hs
	}
	decode := func(set func(b *tBegin)) error {
		b := defaultBegin(0)
		set(&b)
		_, err := decodeTxBegin(b.payload())
		return err
	}
	// Each variable part is accepted at both of its limits and rejected one
	// past either.
	for _, c := range []struct {
		name   string
		lo, hi int
		set    func(b *tBegin, n int)
	}{
		{"client", 1, maxAddr, func(b *tBegin, n int) { b.client = rep("1", n) }},
		{"server", 1, maxAddr, func(b *tBegin, n int) { b.server = rep("2", n) }},
		{"method", 1, maxMethod, func(b *tBegin, n int) { b.method = rep("M", n) }},
		{"uri", 1, maxURI, func(b *tBegin, n int) { b.uri = rep("u", n) }},
		{"proto", 1, maxProto, func(b *tBegin, n int) { b.proto = rep("p", n) }},
		{"header count", 0, maxHeaders, func(b *tBegin, n int) { b.headers = many(n, "n", "v") }},
		{"header name", 1, maxHdrName, func(b *tBegin, n int) { b.headers = [][2]string{{rep("n", n), ""}} }},
		{"header value", 0, maxHdrValue, func(b *tBegin, n int) { b.headers = [][2]string{{"n", rep("v", n)}} }},
	} {
		for _, n := range []int{c.lo - 1, c.lo, c.hi, c.hi + 1} {
			if n < 0 {
				continue
			}
			err := decode(func(b *tBegin) { c.set(b, n) })
			if ok := n >= c.lo && n <= c.hi; ok != (err == nil) {
				t.Errorf("%s of %d: %v", c.name, n, err)
			}
		}
	}
	for name, c := range map[string]struct {
		set func(b *tBegin)
		ok  bool
	}{
		"declared max":    {func(b *tBegin) { b.declared = maxDeclared }, true},
		"declared max+1":  {func(b *tBegin) { b.declared = maxDeclared + 1 }, false},
		"headers total":   {func(b *tBegin) { b.headers = many(6, rep("n", 256), rep("v", 3840)) }, true}, // 24576 exactly
		"headers total+1": {func(b *tBegin) { b.headers = append(many(6, rep("n", 256), rep("v", 3840)), [2]string{"x", ""}) }, false},
	} {
		if err := decode(c.set); c.ok != (err == nil) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A trailing byte, and a string length that points past the end.
	good := defaultBegin(0).payload()
	past := defaultBegin(0).payload()
	binary.BigEndian.PutUint16(past, 0xffff)
	for name, p := range map[string][]byte{"trailing byte": append(good[:len(good):len(good)], 0), "length past end": past} {
		if _, err := decodeTxBegin(p); !errors.Is(err, errContent) {
			t.Errorf("%s: got %v, want errContent", name, err)
		}
	}
}

func TestDecodeRespBeginAndTxEnd(t *testing.T) {
	for st, ok := range map[uint16]bool{99: false, 100: true, 999: true, 1000: false} {
		if _, err := decodeRespBegin(respPayload(st, "HTTP/1.1", 0, nil)); ok != (err == nil) {
			t.Errorf("status %d: %v", st, err)
		}
	}
	for name, p := range map[string][]byte{
		"declared+1": respPayload(200, "HTTP/1.1", maxDeclared+1, nil),
		"trailing":   append(respPayload(200, "HTTP/1.1", 0, nil), 1),
	} {
		if _, err := decodeRespBegin(p); !errors.Is(err, errContent) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for r := byte(0); r <= endDeadline+1; r++ {
		if got, err := decodeTxEnd([]byte{r}); (err == nil) != (r >= endComplete && r <= endDeadline) || err == nil && got != r {
			t.Errorf("reason %d: %v", r, err)
		}
	}
}

func TestEncodeLimits(t *testing.T) {
	for _, st := range []int{65536, -1} {
		if _, ok := encodeVerdict(testRun, testInc, 1, 1, 1, 1, st, "deny", "", true, noDetail); ok {
			t.Errorf("status %d accepted", st)
		}
	}
	b, ok := encodeVerdict(testRun, testInc, 1, 1, 1, -7, 65535, strings.Repeat("a", 32), strings.Repeat("d", 256), true, noDetail)
	o, err := parseOut(b)
	if !ok || err != nil || o.flags != 0 || o.rule != -7 || o.stat != 65535 {
		t.Errorf("boundary verdict: ok %v err %v %+v", ok, err, o)
	}
	// A detection is cut like a block, and its flag stays beside the cut flags.
	if _, ok := encodeDetected(testRun, testInc, 1, 1, 1, 65536, "deny", "", noDetail); ok {
		t.Error("status 65536 accepted")
	}
	b, ok = encodeDetected(testRun, testInc, 1, 1, 1, 403, strings.Repeat("a", 33), strings.Repeat("d", 257), noDetail)
	o, err = parseOut(b)
	if !ok || err != nil || o.phase != 2 || o.block || o.flags != flagDetected|flagActionTruncated|flagDataTruncated || len(o.act) != maxAction || len(o.data) != maxData {
		t.Errorf("cut detection: ok %v err %v %+v", ok, err, o)
	}
	e := encodeError(testRun, testInc, 1, 1, classTxFailed, codeOrder, strings.Repeat("x", 1000))
	if o, err := parseOut(e); err != nil || len(o.text) != maxErrMsg || len(e)-headerLen > maxError {
		t.Errorf("long error text: %v %d", err, len(o.text))
	}
}

// The detail at the end of a VERDICT is accepted at each of its limits and
// refused one past it, as the bad_ vectors of the golden file are, and phases
// 3 and 4 carry nothing. A detail with nothing to carry is written as none.
func TestEncodeDetailLimits(t *testing.T) {
	ids := func(n int) []int64 {
		l := make([]int64, n)
		for i := range l {
			l[i] = 930100 + int64(i)
		}
		return l
	}
	with := func(f func(d *ruleDetail)) ruleDetail {
		d := noDetail
		f(&d)
		return d
	}
	for name, c := range map[string]struct {
		phase uint8
		d     ruleDetail
		ok    bool
	}{
		"16 ids":              {2, with(func(d *ruleDetail) { d.ids = ids(16) }), true},
		"16 ids and more":     {2, with(func(d *ruleDetail) { d.ids, d.more = ids(16), true }), true},
		"17 ids":              {2, with(func(d *ruleDetail) { d.ids = ids(17) }), false},
		"17 ids and more":     {2, with(func(d *ruleDetail) { d.ids, d.more = ids(17), true }), false},
		"more with 15 ids":    {2, with(func(d *ruleDetail) { d.ids, d.more = ids(15), true }), false},
		"id 1":                {1, with(func(d *ruleDetail) { d.ids = []int64{1} }), true},
		"id 0":                {2, with(func(d *ruleDetail) { d.ids = []int64{930100, 0} }), false},
		"severity 7":          {2, with(func(d *ruleDetail) { d.severity = 7 }), true},
		"severity 8":          {2, with(func(d *ruleDetail) { d.severity = 8 }), false},
		"score 0":             {2, with(func(d *ruleDetail) { d.score = 0 }), true},
		"score max":           {2, with(func(d *ruleDetail) { d.score = math.MaxInt32 }), true},
		"score -2":            {2, with(func(d *ruleDetail) { d.score = -2 }), false},
		"nothing in phase 3":  {3, noDetail, true},
		"score 0 in phase 4":  {4, with(func(d *ruleDetail) { d.score = 0 }), true},
		"id in phase 3":       {3, with(func(d *ruleDetail) { d.ids = ids(1) }), false},
		"severity in phase 4": {4, with(func(d *ruleDetail) { d.severity = 2 }), false},
		"score in phase 4":    {4, with(func(d *ruleDetail) { d.score = 1 }), false},
	} {
		b, ok := encodeVerdict(testRun, testInc, 1, 1, c.phase, 0, 0, "", "", false, c.d)
		if ok != c.ok {
			t.Errorf("%s: ok %v, want %v", name, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		o, err := parseOut(b)
		if err != nil || !slices.Equal(o.ids, c.d.ids) || o.sev != c.d.severity || (o.flags&flagMoreRules != 0) != c.d.more {
			t.Errorf("%s: %v %+v", name, err, o)
		}
	}
	// Nothing to carry is none; a score of 0 beside an id or a severity is kept.
	for name, c := range map[string]struct {
		d     ruleDetail
		score int32
	}{
		"nothing":         {with(func(d *ruleDetail) { d.score = 0 }), scoreNone},
		"with a severity": {with(func(d *ruleDetail) { d.severity, d.score = 3, 0 }), 0},
		"with an id":      {with(func(d *ruleDetail) { d.ids, d.score = ids(1), 0 }), 0},
	} {
		b, _ := encodeVerdict(testRun, testInc, 1, 1, 2, 0, 0, "", "", false, c.d)
		if o, err := parseOut(b); err != nil || o.score != c.score {
			t.Errorf("%s: %v score %d, want %d", name, err, o.score, c.score)
		}
	}
}
