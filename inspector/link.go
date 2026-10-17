package main

import (
	"errors"
	"sync"
	"time"

	"github.com/corazawaf/coraza/v3/types"
)

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
