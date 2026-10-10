// Wire protocol 0. Every multi-byte integer is big-endian. The byte layout is
// fixed by testdata/v0-golden.txt.
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

const headerLen = 36

var magic = [4]byte{'T', 'K', 'V', '0'}

// Frame kinds. FAULT (0x7f) is reserved and rejected by this build.
const (
	kindHello     uint8 = 0x01
	kindDrain     uint8 = 0x02
	kindBye       uint8 = 0x03
	kindTxBegin   uint8 = 0x10
	kindBody      uint8 = 0x11
	kindBodyEnd   uint8 = 0x12
	kindRespBegin uint8 = 0x13
	kindRespBody  uint8 = 0x14
	kindRespEnd   uint8 = 0x15
	kindTxEnd     uint8 = 0x16
	kindVerdict   uint8 = 0x20
	kindError     uint8 = 0x21
	kindClosed    uint8 = 0x22
)

// Payload limits per kind (bytes).
const (
	maxHello     = 1024
	maxTxBegin   = 32 * 1024
	maxBody      = 64 * 1024
	maxVerdict   = 1024
	maxError     = 512
	maxTxEnd     = 8
	maxClosed    = 8
	maxBye       = 64
	maxDeclared  = 1 << 20 // declared body limit (1 MiB)
	maxAddr      = 64
	maxMethod    = 32
	maxURI       = 4096
	maxProto     = 16
	maxHeaders   = 64
	maxHdrName   = 256
	maxHdrValue  = 4096
	maxHdrTotal  = 24 * 1024
	maxAction    = 32
	maxData      = 256
	maxErrMsg    = 256
	maxConcurTx  = 4
	queueDepth   = 17
	frameTimeout = 3 * time.Second
)

// inboundMax is the payload limit of every kind this build accepts from Rust.
// A kind absent from this map is unknown or has the wrong direction.
var inboundMax = map[uint8]uint32{
	kindDrain:     0,
	kindTxBegin:   maxTxBegin,
	kindBody:      maxBody,
	kindBodyEnd:   0,
	kindRespBegin: maxTxBegin,
	kindRespBody:  maxBody,
	kindRespEnd:   0,
	kindTxEnd:     maxTxEnd,
}

// outbound kinds; receiving one of them is a direction violation.
var outboundKinds = map[uint8]bool{
	kindHello: true, kindBye: true, kindVerdict: true, kindError: true, kindClosed: true,
}

// TX_END reasons (informational for Go; they do not change Go's handling).
const (
	endComplete      uint8 = 1
	endBlocked       uint8 = 2
	endUninspectable uint8 = 3
	endDisconnect    uint8 = 4
	endDeadline      uint8 = 5
)

// ERROR classes and codes. Class notCreated means no transaction exists for
// the id (a legitimate not-created reply returns the concurrency slot); class
// txFailed means a created transaction failed (the slot is returned by CLOSED
// or exit).
const (
	classNotCreated uint8 = 1
	classTxFailed   uint8 = 2

	codeLimit          uint16 = 1  // concurrency limit
	codeDraining       uint16 = 2  // DRAIN received
	codeBadBegin       uint16 = 3  // TX_BEGIN payload or msg number invalid
	codeUnstarted      uint16 = 4  // frame for an id that was never started
	codeOrder          uint16 = 16 // frame not allowed in this state, msg gap/duplicate
	codeBadContent     uint16 = 17 // payload of a created transaction's frame invalid
	codeReqNotInspect  uint16 = 18 // request body present but not accessible
	codeReqWrite       uint16 = 19 // WriteRequestBody error
	codeReqShort       uint16 = 20 // WriteRequestBody wrote fewer bytes
	codeReqOver        uint16 = 21 // more body than declared
	codeReqTruncated   uint16 = 22 // BODY_END with total != declared
	codeReqProcess     uint16 = 23 // ProcessRequestBody error
	codeOverflow       uint16 = 24 // receive queue overflow
	codeRespNotInspect uint16 = 25 // response body present but not accessible/processable
	codeIncomplete     uint16 = 25 // request inspection not complete; shares the value of codeRespNotInspect, 16..31 are all taken
	codeRespWrite      uint16 = 26 // WriteResponseBody error
	codeRespShort      uint16 = 27 // WriteResponseBody wrote fewer bytes
	codeRespProcess    uint16 = 28 // ProcessResponseBody error
	codeBadVerdict     uint16 = 29 // interruption fields out of the encodable range
	codeRespOver       uint16 = 30 // more response body than declared
	codeRespTruncated  uint16 = 31 // RESP_END with total != declared
)

const (
	decisionContinue uint8 = 0
	decisionBlock    uint8 = 1

	flagActionTruncated uint8 = 1 << 0
	flagDataTruncated   uint8 = 1 << 1
)

// header is the fixed 36-byte frame header.
type header struct {
	kind   uint8
	length uint32
	run    uint64
	inc    uint32
	tx     uint64
	msg    uint32
}

// errConn marks a connection-wide violation: the frame boundary can no longer
// be trusted, so the connection is abandoned.
type errConn struct{ reason string }

func (e *errConn) Error() string { return "connection-wide: " + e.reason }

func connErr(format string, a ...any) error { return &errConn{reason: fmt.Sprintf(format, a...)} }

// errContent marks an invalid payload behind a valid header; it affects only
// the transaction that the frame belongs to.
var errContent = errors.New("invalid payload content")

func isControl(kind uint8) bool { return kind == kindDrain || kind == kindHello || kind == kindBye }

// checkHeader validates an inbound header before the payload is allocated.
func checkHeader(b *[headerLen]byte, run uint64, inc uint32) (header, error) {
	var h header
	if b[0] != magic[0] || b[1] != magic[1] || b[2] != magic[2] || b[3] != magic[3] {
		return h, connErr("bad magic")
	}
	h.kind = b[4]
	if b[5] != 0 {
		return h, connErr("flags not zero")
	}
	if binary.BigEndian.Uint16(b[6:8]) != 0 {
		return h, connErr("reserved not zero")
	}
	h.length = binary.BigEndian.Uint32(b[8:12])
	h.run = binary.BigEndian.Uint64(b[12:20])
	h.inc = binary.BigEndian.Uint32(b[20:24])
	h.tx = binary.BigEndian.Uint64(b[24:32])
	h.msg = binary.BigEndian.Uint32(b[32:36])
	limit, ok := inboundMax[h.kind]
	if !ok {
		if outboundKinds[h.kind] {
			return h, connErr("wrong direction kind 0x%02x", h.kind)
		}
		return h, connErr("unknown kind 0x%02x", h.kind)
	}
	if h.length > limit {
		return h, connErr("length %d over limit %d for kind 0x%02x", h.length, limit, h.kind)
	}
	if h.run != run || h.inc != inc {
		return h, connErr("run id or incarnation mismatch")
	}
	if isControl(h.kind) {
		if h.tx != 0 || h.msg != 0 {
			return h, connErr("control frame with tx or msg")
		}
	} else if h.tx == 0 || h.msg == 0 {
		return h, connErr("transaction frame with zero tx or msg")
	}
	return h, nil
}

func putHeader(b []byte, h header) {
	copy(b[0:4], magic[:])
	b[4] = h.kind
	b[5] = 0
	b[6], b[7] = 0, 0
	binary.BigEndian.PutUint32(b[8:12], h.length)
	binary.BigEndian.PutUint64(b[12:20], h.run)
	binary.BigEndian.PutUint32(b[20:24], h.inc)
	binary.BigEndian.PutUint64(b[24:32], h.tx)
	binary.BigEndian.PutUint32(b[32:36], h.msg)
}

// readConn is the part of net.Conn the reader needs.
type readConn interface {
	io.Reader
	SetReadDeadline(time.Time) error
}

// errPeerEOF is a clean EOF before the first byte of a frame.
var errPeerEOF = errors.New("peer closed the connection")

// readFrame waits for the first byte without a deadline, then reads the whole
// frame (header and payload) under one absolute deadline. The payload is
// allocated only after the header passed checkHeader.
func readFrame(c readConn, run uint64, inc uint32, timeout time.Duration) (header, []byte, error) {
	var b [headerLen]byte
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		return header{}, nil, connErr("clear read deadline: %v", err)
	}
	if _, err := io.ReadFull(c, b[:1]); err != nil {
		if errors.Is(err, io.EOF) {
			return header{}, nil, errPeerEOF
		}
		return header{}, nil, connErr("read first byte: %v", err)
	}
	if err := c.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return header{}, nil, connErr("set read deadline: %v", err)
	}
	if _, err := io.ReadFull(c, b[1:]); err != nil {
		return header{}, nil, connErr("read header: %v", err)
	}
	h, err := checkHeader(&b, run, inc)
	if err != nil {
		return h, nil, err
	}
	p := make([]byte, h.length)
	if _, err := io.ReadFull(c, p); err != nil {
		return h, nil, connErr("read payload: %v", err)
	}
	return h, p, nil
}

// writeConn is the part of net.Conn the writer needs.
type writeConn interface {
	io.Writer
	SetWriteDeadline(time.Time) error
}

// writeFrame writes one complete frame under one absolute deadline. Short
// writes continue with the rest; the deadline is never extended.
func writeFrame(c writeConn, b []byte, timeout time.Duration) error {
	if err := c.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	for off := 0; off < len(b); {
		n, err := c.Write(b[off:])
		if n < 0 || n > len(b)-off {
			return fmt.Errorf("write returned invalid count %d", n)
		}
		off += n
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

// frameBuilder appends an outbound frame. The header length is patched by
// finish, which also enforces the kind's payload limit.
type frameBuilder struct{ b []byte }

func newFrame(h header) *frameBuilder {
	f := &frameBuilder{b: make([]byte, headerLen, headerLen+64)}
	putHeader(f.b, h)
	return f
}

func (f *frameBuilder) u8(v uint8)   { f.b = append(f.b, v) }
func (f *frameBuilder) u16(v uint16) { f.b = binary.BigEndian.AppendUint16(f.b, v) }
func (f *frameBuilder) u32(v uint32) { f.b = binary.BigEndian.AppendUint32(f.b, v) }
func (f *frameBuilder) u64(v uint64) { f.b = binary.BigEndian.AppendUint64(f.b, v) }
func (f *frameBuilder) raw(v []byte) { f.b = append(f.b, v...) }

// str16 appends a u16 length and the bytes. Callers bound len(s) first.
func (f *frameBuilder) str16(s string) {
	f.u16(uint16(len(s)))
	f.b = append(f.b, s...)
}

func (f *frameBuilder) finish(limit int) ([]byte, error) {
	n := len(f.b) - headerLen
	if n > limit {
		return nil, fmt.Errorf("outbound payload %d over limit %d", n, limit)
	}
	binary.BigEndian.PutUint32(f.b[8:12], uint32(n))
	return f.b, nil
}

// cursor decodes a payload. Every read is bounds-checked; done() requires the
// payload to be consumed exactly.
type cursor struct {
	p   []byte
	off int
	bad bool
}

func (c *cursor) take(n int) []byte {
	if c.bad || n < 0 || len(c.p)-c.off < n {
		c.bad = true
		return nil
	}
	v := c.p[c.off : c.off+n]
	c.off += n
	return v
}

func (c *cursor) u8() uint8 {
	if v := c.take(1); v != nil {
		return v[0]
	}
	return 0
}

func (c *cursor) u16() uint16 {
	if v := c.take(2); v != nil {
		return binary.BigEndian.Uint16(v)
	}
	return 0
}

func (c *cursor) u64() uint64 {
	if v := c.take(8); v != nil {
		return binary.BigEndian.Uint64(v)
	}
	return 0
}

// str16 reads a u16-prefixed byte string whose length must be in [lo, hi].
// The range is checked before the bytes are copied.
func (c *cursor) str16(lo, hi int) string {
	n := int(c.u16())
	if c.bad || n < lo || n > hi {
		c.bad = true
		return ""
	}
	v := c.take(n)
	if v == nil {
		return ""
	}
	return string(v)
}

func (c *cursor) done() bool { return !c.bad && c.off == len(c.p) }

type httpHeader struct{ name, value string }

// readHeaders reads a u16 count and the (name, value) list; the count and the
// running name+value total are checked before allocation and use.
func (c *cursor) readHeaders() []httpHeader {
	n := int(c.u16())
	if c.bad || n > maxHeaders {
		c.bad = true
		return nil
	}
	hs := make([]httpHeader, 0, n)
	total := 0
	for range n {
		name := c.str16(1, maxHdrName)
		value := c.str16(0, maxHdrValue)
		if c.bad {
			return nil
		}
		total += len(name) + len(value)
		if total > maxHdrTotal {
			c.bad = true
			return nil
		}
		hs = append(hs, httpHeader{name, value})
	}
	return hs
}

type txBegin struct {
	clientAddr string
	clientPort uint16
	serverAddr string
	serverPort uint16
	method     string
	uri        string
	proto      string
	declared   uint64
	headers    []httpHeader
}

func decodeTxBegin(p []byte) (txBegin, error) {
	c := cursor{p: p}
	var t txBegin
	t.clientAddr = c.str16(1, maxAddr)
	t.clientPort = c.u16()
	t.serverAddr = c.str16(1, maxAddr)
	t.serverPort = c.u16()
	t.method = c.str16(1, maxMethod)
	t.uri = c.str16(1, maxURI)
	t.proto = c.str16(1, maxProto)
	t.declared = c.u64()
	if !c.bad && t.declared > maxDeclared {
		c.bad = true
	}
	t.headers = c.readHeaders()
	if !c.done() {
		return txBegin{}, errContent
	}
	return t, nil
}

type respBegin struct {
	status   uint16
	proto    string
	declared uint64
	headers  []httpHeader
}

func decodeRespBegin(p []byte) (respBegin, error) {
	c := cursor{p: p}
	var r respBegin
	r.status = c.u16()
	if !c.bad && (r.status < 100 || r.status > 999) {
		c.bad = true
	}
	r.proto = c.str16(1, maxProto)
	r.declared = c.u64()
	if !c.bad && r.declared > maxDeclared {
		c.bad = true
	}
	r.headers = c.readHeaders()
	if !c.done() {
		return respBegin{}, errContent
	}
	return r, nil
}

// decodeTxEnd returns the reason; the payload must be exactly one known byte.
func decodeTxEnd(p []byte) (uint8, error) {
	if len(p) != 1 || p[0] < endComplete || p[0] > endDeadline {
		return 0, errContent
	}
	return p[0], nil
}

type hello struct {
	pid           uint32
	nonce         [16]byte
	goVersion     string
	corazaVersion string
	corazaSum     string
	rulesSHA256   [32]byte
	memLimit      int64
	gomaxprocs    uint16
}

func encodeHello(run uint64, inc uint32, v hello) ([]byte, error) {
	if len(v.goVersion) < 1 || len(v.goVersion) > 64 || len(v.corazaVersion) < 1 || len(v.corazaVersion) > 64 ||
		len(v.corazaSum) < 1 || len(v.corazaSum) > 128 || v.memLimit < 0 {
		return nil, errors.New("hello field out of range")
	}
	f := newFrame(header{kind: kindHello, run: run, inc: inc})
	f.u16(0) // protocol version 0
	f.u32(v.pid)
	f.raw(v.nonce[:])
	f.u64(run)
	f.u32(inc)
	f.str16(v.goVersion)
	f.str16(v.corazaVersion)
	f.str16(v.corazaSum)
	f.raw(v.rulesSHA256[:])
	f.u32(maxDeclared)
	f.u64(uint64(v.memLimit))
	f.u16(v.gomaxprocs)
	f.u16(maxConcurTx)
	f.u16(queueDepth)
	return f.finish(maxHello)
}

// encodeVerdict encodes a VERDICT. A nil interruption is "continue". Action
// and data are cut to their limits with a flag; a rule id or status outside the
// encodable range is reported by ok=false so the caller sends an ERROR instead.
func encodeVerdict(run uint64, inc uint32, tx uint64, msg uint32, phase uint8, ruleID int, status int, action, data string, block bool) ([]byte, bool) {
	if status < 0 || status > 0xffff {
		return nil, false
	}
	var flags uint8
	if len(action) > maxAction {
		action, flags = action[:maxAction], flags|flagActionTruncated
	}
	if len(data) > maxData {
		data, flags = data[:maxData], flags|flagDataTruncated
	}
	d := decisionContinue
	if block {
		d = decisionBlock
	}
	f := newFrame(header{kind: kindVerdict, run: run, inc: inc, tx: tx, msg: msg})
	f.u8(phase)
	f.u8(d)
	f.u8(flags)
	f.u8(0)
	f.u64(uint64(int64(ruleID)))
	f.u16(uint16(status))
	f.str16(action)
	f.str16(data)
	b, err := f.finish(maxVerdict)
	return b, err == nil
}

// encodeError encodes an ERROR. msg is an inspector-chosen ASCII text and never
// carries request values.
func encodeError(run uint64, inc uint32, tx uint64, msg uint32, class uint8, code uint16, text string) []byte {
	if len(text) > maxErrMsg {
		text = text[:maxErrMsg]
	}
	f := newFrame(header{kind: kindError, run: run, inc: inc, tx: tx, msg: msg})
	f.u8(class)
	f.u8(0)
	f.u16(code)
	f.str16(text)
	b, err := f.finish(maxError)
	if err != nil {
		panic(err) // unreachable: 4 + 2 + 256 < 512
	}
	return b
}

func encodeClosed(run uint64, inc uint32, tx uint64, msg uint32, closeErr bool) []byte {
	f := newFrame(header{kind: kindClosed, run: run, inc: inc, tx: tx, msg: msg})
	if closeErr {
		f.u8(1)
	} else {
		f.u8(0)
	}
	b, _ := f.finish(maxClosed)
	return b
}

func encodeBye(run uint64, inc uint32, started, closed, closeErrs uint64) []byte {
	f := newFrame(header{kind: kindBye, run: run, inc: inc})
	f.u64(started)
	f.u64(closed)
	f.u64(closeErrs)
	b, _ := f.finish(maxBye)
	return b
}
