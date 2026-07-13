//go:build darwin

package network

import (
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// blockingReader feeds loop() controlled data then an EOF, standing in
// for the `route -n monitor` stdout pipe without spawning a subprocess.
type blockingReader struct {
	mu     sync.Mutex
	data   []byte
	closed bool
	ch     chan struct{}
}

func newBlockingReader() *blockingReader { return &blockingReader{ch: make(chan struct{}, 1)} }

func (b *blockingReader) feed(s string) {
	b.mu.Lock()
	b.data = append(b.data, s...)
	b.mu.Unlock()
	select {
	case b.ch <- struct{}{}:
	default:
	}
}

func (b *blockingReader) eof() {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	select {
	case b.ch <- struct{}{}:
	default:
	}
}

func (b *blockingReader) Read(p []byte) (int, error) {
	for {
		b.mu.Lock()
		if len(b.data) > 0 {
			n := copy(p, b.data)
			b.data = b.data[n:]
			b.mu.Unlock()
			return n, nil
		}
		closed := b.closed
		b.mu.Unlock()
		if closed {
			return 0, io.EOF
		}
		<-b.ch
	}
}

// TestLoop_TriggersOnRTMEvent confirms a matching RTM line reaches the
// reapply callback, and a noise line does not.
func TestLoop_TriggersOnRTMEvent(t *testing.T) {
	var calls int32
	rm := newRouteMonitor(func() { atomic.AddInt32(&calls, 1) })
	// Hand-wire the running state loop() and the debouncer expect,
	// without spawning the real subprocess.
	rm.stopCh = make(chan struct{})
	rm.kick = make(chan struct{}, 1)
	rm.running = true
	rm.startedAt = time.Now()
	rm.stopped = true // prevent loop() from restarting a real subprocess on EOF

	go rm.debounceLoop()

	r := newBlockingReader()
	done := make(chan struct{})
	go func() { rm.loop(r); close(done) }()

	r.feed("got message of size 1 on ...\n")   // noise
	r.feed("RTM_NEWADDR: address being added\n") // triggers
	time.Sleep(700 * time.Millisecond)           // > debounce window

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected exactly 1 reapply, got %d", got)
	}

	r.eof()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("loop did not return after EOF")
	}
	// stopped=true means loop() takes the early-return branch and must
	// NOT arm a restart (that path is exercised by TestLoop_CrashRestarts).
	rm.mu.Lock()
	armed := rm.pendingStart != nil
	rm.mu.Unlock()
	if armed {
		t.Error("loop must not restart when stopped=true")
	}
	close(rm.stopCh)
}

// TestLoop_CrashRestarts confirms an unexpected EOF (subprocess died,
// not Stop()) resets running and schedules a restart via pendingStart,
// rather than leaving the monitor wedged.
func TestLoop_CrashRestarts(t *testing.T) {
	rm := newRouteMonitor(func() {})
	rm.stopCh = make(chan struct{})
	rm.kick = make(chan struct{}, 1)
	rm.running = true
	rm.startedAt = time.Now()
	// stopped stays false → the crash path runs its restart logic.

	go rm.debounceLoop()

	r := newBlockingReader()
	go rm.loop(r)
	r.eof() // simulate the subprocess dying on its own

	// The loop should observe EOF, flip running false, and arm a
	// delayed restart. Poll for the restart timer.
	deadline := time.Now().Add(2 * time.Second)
	for {
		rm.mu.Lock()
		armed := rm.pendingStart != nil
		restarts := rm.restarts
		rm.mu.Unlock()
		if armed && restarts == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("crash restart not armed: pendingStart set=%v restarts=%d", armed, restarts)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Stop() must cancel the pending restart and latch stopped so the
	// timer can't spawn a real subprocess after the test ends.
	rm.Stop()
	rm.mu.Lock()
	if rm.pendingStart != nil {
		t.Error("Stop did not cancel the pending restart timer")
	}
	if !rm.stopped {
		t.Error("Stop did not latch stopped")
	}
	rm.mu.Unlock()
}
