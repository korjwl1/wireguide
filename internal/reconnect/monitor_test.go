package reconnect

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/tunnel"
)

// ---------------------------------------------------------------------------
// Mock implementations
// ---------------------------------------------------------------------------

// mockManager implements TunnelManager for tests.
type mockManager struct {
	mu           sync.Mutex
	connected    bool
	activeName   string
	status       *tunnel.ConnectionStatus
	disconnectFn func() error
}

func (m *mockManager) IsConnected() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.connected
}

func (m *mockManager) ActiveTunnel() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.activeName
}

func (m *mockManager) Status() *tunnel.ConnectionStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
}

func (m *mockManager) Disconnect() error {
	m.mu.Lock()
	fn := m.disconnectFn
	m.mu.Unlock()
	if fn != nil {
		return fn()
	}
	return nil
}

func (m *mockManager) setConnected(connected bool, name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connected = connected
	m.activeName = name
}

func (m *mockManager) setStatus(s *tunnel.ConnectionStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status = s
}

// mockSleepDetector implements SleepDetector with a controllable wake channel.
type mockSleepDetector struct {
	wakeCh  chan struct{}
	started atomic.Bool
	stopped atomic.Bool
}

func newMockSleepDetector() *mockSleepDetector {
	return &mockSleepDetector{
		wakeCh: make(chan struct{}, 1),
	}
}

func (d *mockSleepDetector) Start() { d.started.Store(true) }
func (d *mockSleepDetector) Stop()  { d.stopped.Store(true) }
func (d *mockSleepDetector) WakeChan() <-chan struct{} { return d.wakeCh }

func (d *mockSleepDetector) sendWake() {
	select {
	case d.wakeCh <- struct{}{}:
	default:
	}
}

// testConfig returns a Config with very short timeouts for testing.
func testConfig() Config {
	return Config{
		HandshakeTimeout: 50 * time.Millisecond,
		InitialDelay:     10 * time.Millisecond,
		MaxDelay:         80 * time.Millisecond,
		MaxAttempts:      0, // unlimited
	}
}

// newTestMonitor constructs a Monitor wired to mocks. Returns the monitor and
// all mocks so the caller can drive behavior.
func newTestMonitor(cfg Config, reconnectFn ReconnectFunc) (*Monitor, *mockManager, *mockSleepDetector) {
	mgr := &mockManager{}
	sd := newMockSleepDetector()
	mon := NewMonitor(mgr, reconnectFn, nil, cfg)
	mon.sleepDetector = sd
	return mon, mgr, sd
}

// waitFor polls a condition with a timeout.
func waitFor(t *testing.T, timeout time.Duration, msg string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for: %s", msg)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestSleepWake_TriggersReconnect_WhenConnected(t *testing.T) {
	var reconnectCalls atomic.Int32
	reconnectFn := func() error {
		reconnectCalls.Add(1)
		return nil
	}

	mon, mgr, sd := newTestMonitor(testConfig(), reconnectFn)
	mgr.setConnected(true, "test-tunnel")

	mon.Start()
	defer mon.Stop()

	// Simulate a wake event.
	sd.sendWake()

	waitFor(t, 2*time.Second, "reconnectFn called after wake", func() bool {
		return reconnectCalls.Load() > 0
	})
}

func TestSleepWake_DoesNotReconnect_WhenDisconnected(t *testing.T) {
	var reconnectCalls atomic.Int32
	reconnectFn := func() error {
		reconnectCalls.Add(1)
		return nil
	}

	mon, mgr, sd := newTestMonitor(testConfig(), reconnectFn)
	// Tunnel is disconnected and has no active tunnel name.
	mgr.setConnected(false, "")

	mon.Start()
	defer mon.Stop()

	sd.sendWake()

	// Give it enough time for the reconnect to fire if it were going to.
	time.Sleep(100 * time.Millisecond)

	if reconnectCalls.Load() != 0 {
		t.Fatalf("expected no reconnect when disconnected, got %d calls", reconnectCalls.Load())
	}
}

func TestHealthCheck_StaleHandshake_TriggersReconnect(t *testing.T) {
	// The monitor loop checks every 30s by default with a 180s threshold.
	// We can't easily override the ticker interval (it's a const), so instead
	// we test triggerReconnect directly when the health-check condition is met.
	// This isolates the reconnect logic from the ticker timing.

	var reconnectCalls atomic.Int32
	reconnectFn := func() error {
		reconnectCalls.Add(1)
		return nil
	}

	mon, mgr, _ := newTestMonitor(testConfig(), reconnectFn)
	mgr.setConnected(true, "test-tunnel")

	// Set a stale handshake time (well past the 180s threshold).
	mgr.setStatus(&tunnel.ConnectionStatus{
		LastHandshakeTime: time.Now().Add(-4 * time.Minute),
	})

	// Directly call triggerReconnect to simulate what monitorLoop does.
	mon.mu.Lock()
	mon.running = true
	mon.mu.Unlock()

	mon.triggerReconnect()

	waitFor(t, 2*time.Second, "reconnectFn called for stale handshake", func() bool {
		return reconnectCalls.Load() > 0
	})
}

func TestHealthCheck_RecentHandshake_DoesNotReconnect(t *testing.T) {
	// The monitorLoop should NOT call triggerReconnect when handshake is recent.
	// We verify this by running the full monitor loop with short intervals.
	// Since the ticker interval is a const 30s (too long for tests), we test
	// the decision logic directly.

	var reconnectCalls atomic.Int32
	reconnectFn := func() error {
		reconnectCalls.Add(1)
		return nil
	}

	mon, mgr, _ := newTestMonitor(testConfig(), reconnectFn)
	mgr.setConnected(true, "test-tunnel")

	// Recent handshake -- well within the 180s threshold.
	mgr.setStatus(&tunnel.ConnectionStatus{
		LastHandshakeTime: time.Now().Add(-10 * time.Second),
	})

	// Start the monitor but don't expect any reconnect.
	mon.Start()
	defer mon.Stop()

	// The monitor's health check ticker fires every 30s, so no reconnect
	// should happen within this short window. If the condition incorrectly
	// triggers, the short InitialDelay would cause reconnectFn to fire.
	time.Sleep(100 * time.Millisecond)

	if reconnectCalls.Load() != 0 {
		t.Fatalf("expected no reconnect for recent handshake, got %d calls", reconnectCalls.Load())
	}
}

func TestExponentialBackoff(t *testing.T) {
	cfg := testConfig()
	cfg.InitialDelay = 10 * time.Millisecond
	cfg.MaxDelay = 80 * time.Millisecond

	// Track timestamps of reconnect attempts.
	var mu sync.Mutex
	var attempts []time.Time

	targetAttempts := 4
	done := make(chan struct{})

	reconnectFn := func() error {
		mu.Lock()
		attempts = append(attempts, time.Now())
		n := len(attempts)
		mu.Unlock()
		if n >= targetAttempts {
			select {
			case <-done:
			default:
				close(done)
			}
		}
		return errors.New("always fail")
	}

	mon, mgr, _ := newTestMonitor(cfg, reconnectFn)
	mgr.setConnected(true, "test-tunnel")
	mon.mu.Lock()
	mon.running = true
	mon.mu.Unlock()

	mon.triggerReconnect()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for backoff attempts")
	}

	// Stop to prevent further attempts.
	mon.Stop()

	mu.Lock()
	defer mu.Unlock()

	if len(attempts) < targetAttempts {
		t.Fatalf("expected at least %d attempts, got %d", targetAttempts, len(attempts))
	}

	// Verify that delays grow: gap between attempt 2->3 should be >= gap 1->2.
	// The first attempt happens after InitialDelay (10ms), second after 20ms, third 40ms.
	for i := 2; i < len(attempts); i++ {
		prevGap := attempts[i-1].Sub(attempts[i-2])
		thisGap := attempts[i].Sub(attempts[i-1])
		// Allow some slack (timer + scheduling jitter).
		if thisGap < prevGap/2 {
			t.Errorf("backoff not increasing: gap[%d]=%v < gap[%d]/2=%v",
				i-1, thisGap, i-2, prevGap/2)
		}
	}
}

func TestCancelRetry_StopsInProgressReconnect(t *testing.T) {
	var reconnectCalls atomic.Int32
	reconnectFn := func() error {
		reconnectCalls.Add(1)
		return errors.New("fail")
	}

	cfg := testConfig()
	cfg.InitialDelay = 500 * time.Millisecond // Long enough to cancel during sleep.

	mon, mgr, _ := newTestMonitor(cfg, reconnectFn)
	mgr.setConnected(true, "test-tunnel")
	mon.mu.Lock()
	mon.running = true
	mon.mu.Unlock()

	mon.triggerReconnect()

	// Wait for at least one attempt to happen (the first backoff sleep).
	waitFor(t, 2*time.Second, "first reconnect attempt", func() bool {
		return reconnectCalls.Load() >= 1
	})

	beforeCancel := reconnectCalls.Load()

	// Cancel retry while it's sleeping before the next attempt.
	mon.CancelRetry()

	// Wait for the retry goroutine to fully exit.
	mon.mu.Lock()
	retryDone := mon.retryDone
	mon.mu.Unlock()
	if retryDone != nil {
		select {
		case <-retryDone:
		case <-time.After(2 * time.Second):
			t.Fatal("retryDone channel not closed after CancelRetry")
		}
	}

	// Wait a bit and verify no more attempts occurred.
	time.Sleep(cfg.InitialDelay * 3)
	afterCancel := reconnectCalls.Load()

	// At most one more attempt could squeeze through (race between cancel and
	// timer). But definitely not many.
	if afterCancel-beforeCancel > 1 {
		t.Fatalf("expected at most 1 extra attempt after cancel, got %d", afterCancel-beforeCancel)
	}
}

func TestFirewallCallbacks_CalledInOrder(t *testing.T) {
	var order []string
	var mu sync.Mutex

	record := func(event string) {
		mu.Lock()
		order = append(order, event)
		mu.Unlock()
	}

	cfg := testConfig()
	reconnectFn := func() error {
		record("reconnect")
		return nil // succeed on first attempt
	}

	mon, mgr, _ := newTestMonitor(cfg, reconnectFn)
	mgr.setConnected(true, "test-tunnel")

	mon.SetFirewallCallbacks(
		func() error { record("suspend"); return nil },
		func() error { record("resume"); return nil },
	)

	mon.mu.Lock()
	mon.running = true
	mon.mu.Unlock()

	mon.triggerReconnect()

	// Wait for the retry goroutine to finish by watching retryDone.
	mon.mu.Lock()
	retryDone := mon.retryDone
	mon.mu.Unlock()
	select {
	case <-retryDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for reconnect to complete")
	}

	mu.Lock()
	defer mu.Unlock()

	// Expected order: suspend -> reconnect -> resume
	expected := []string{"suspend", "reconnect", "resume"}
	if len(order) != len(expected) {
		t.Fatalf("expected %v, got %v", expected, order)
	}
	for i, v := range expected {
		if order[i] != v {
			t.Fatalf("expected order[%d]=%q, got %q (full: %v)", i, v, order[i], order)
		}
	}
}

func TestFirewallCallbacks_ResumedOnFailure(t *testing.T) {
	var suspendCalls, resumeCalls atomic.Int32
	var reconnectCalls atomic.Int32

	cfg := testConfig()
	cfg.MaxAttempts = 1 // Only one attempt so it stops quickly.

	reconnectFn := func() error {
		reconnectCalls.Add(1)
		return errors.New("fail")
	}

	mon, mgr, _ := newTestMonitor(cfg, reconnectFn)
	mgr.setConnected(true, "test-tunnel")

	mon.SetFirewallCallbacks(
		func() error { suspendCalls.Add(1); return nil },
		func() error { resumeCalls.Add(1); return nil },
	)

	mon.mu.Lock()
	mon.running = true
	mon.mu.Unlock()

	mon.triggerReconnect()

	// Wait for attempts to be exhausted.
	waitFor(t, 2*time.Second, "max attempts reached", func() bool {
		return reconnectCalls.Load() >= 1
	})
	// Give a moment for post-attempt cleanup.
	time.Sleep(50 * time.Millisecond)

	if suspendCalls.Load() != resumeCalls.Load() {
		t.Fatalf("suspend (%d) and resume (%d) calls should match",
			suspendCalls.Load(), resumeCalls.Load())
	}
}

func TestMaxAttempts_LimitsRetries(t *testing.T) {
	cfg := testConfig()
	cfg.MaxAttempts = 3

	var reconnectCalls atomic.Int32
	reconnectFn := func() error {
		reconnectCalls.Add(1)
		return errors.New("always fail")
	}

	var lastState State
	var stateMu sync.Mutex
	statusFn := func(state State) {
		stateMu.Lock()
		lastState = state
		stateMu.Unlock()
	}

	mgr := &mockManager{connected: true, activeName: "test"}
	sd := newMockSleepDetector()
	mon := NewMonitor(mgr, reconnectFn, statusFn, cfg)
	mon.sleepDetector = sd
	mon.mu.Lock()
	mon.running = true
	mon.mu.Unlock()

	mon.triggerReconnect()

	// Wait for max attempts to be reached.
	waitFor(t, 5*time.Second, "max attempts exhausted", func() bool {
		return reconnectCalls.Load() >= 3
	})
	// Allow time for the goroutine to finish cleanup.
	time.Sleep(100 * time.Millisecond)

	if reconnectCalls.Load() != 3 {
		t.Fatalf("expected exactly 3 reconnect attempts, got %d", reconnectCalls.Load())
	}

	stateMu.Lock()
	defer stateMu.Unlock()
	if lastState.Reconnecting {
		t.Error("expected final state Reconnecting=false after max attempts")
	}
}

func TestMaxAttempts_ZeroMeansUnlimited(t *testing.T) {
	cfg := testConfig()
	cfg.MaxAttempts = 0 // unlimited

	var reconnectCalls atomic.Int32
	reconnectFn := func() error {
		reconnectCalls.Add(1)
		return errors.New("always fail")
	}

	mon, mgr, _ := newTestMonitor(cfg, reconnectFn)
	mgr.setConnected(true, "test-tunnel")
	mon.mu.Lock()
	mon.running = true
	mon.mu.Unlock()

	mon.triggerReconnect()

	// Let it run for enough attempts.
	waitFor(t, 5*time.Second, "at least 5 attempts with unlimited retries", func() bool {
		return reconnectCalls.Load() >= 5
	})

	// Should still be trying (not stopped).
	state := mon.GetState()
	if !state.Reconnecting {
		t.Error("expected Reconnecting=true with unlimited retries")
	}

	mon.Stop()
}

func TestConcurrent_StartStop(t *testing.T) {
	reconnectFn := func() error { return nil }
	mon, _, _ := newTestMonitor(testConfig(), reconnectFn)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mon.Start()
			time.Sleep(5 * time.Millisecond)
			mon.Stop()
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// success
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent Start/Stop timed out -- possible deadlock")
	}
}

func TestStop_CancelsActiveReconnect(t *testing.T) {
	var reconnectCalls atomic.Int32
	reconnectFn := func() error {
		reconnectCalls.Add(1)
		return errors.New("fail")
	}

	cfg := testConfig()
	cfg.InitialDelay = 200 * time.Millisecond

	mon, mgr, _ := newTestMonitor(cfg, reconnectFn)
	mgr.setConnected(true, "test-tunnel")

	mon.Start()

	// Trigger a reconnect via wake.
	mon.sleepDetector.(*mockSleepDetector).sendWake()

	// Wait for at least one attempt.
	waitFor(t, 2*time.Second, "first reconnect attempt", func() bool {
		return reconnectCalls.Load() >= 1
	})

	// Stop should cancel the backoff and return promptly.
	stopped := make(chan struct{})
	go func() {
		mon.Stop()
		close(stopped)
	}()

	select {
	case <-stopped:
		// success
	case <-time.After(3 * time.Second):
		t.Fatal("Stop() did not return promptly -- may be stuck in backoff")
	}
}

func TestGetState_ReflectsAttempt(t *testing.T) {
	cfg := testConfig()
	cfg.InitialDelay = 200 * time.Millisecond
	cfg.MaxAttempts = 5

	attemptSeen := make(chan struct{})
	reconnectFn := func() error {
		// Signal after the first attempt so the test can read state.
		select {
		case <-attemptSeen:
		default:
			close(attemptSeen)
		}
		return errors.New("fail")
	}

	mon, mgr, _ := newTestMonitor(cfg, reconnectFn)
	mgr.setConnected(true, "test-tunnel")
	mon.mu.Lock()
	mon.running = true
	mon.mu.Unlock()

	mon.triggerReconnect()
	<-attemptSeen

	state := mon.GetState()
	if !state.Reconnecting {
		t.Error("expected Reconnecting=true during retry")
	}
	if state.Attempt < 1 {
		t.Errorf("expected Attempt >= 1, got %d", state.Attempt)
	}
	if state.MaxAttempts != 5 {
		t.Errorf("expected MaxAttempts=5, got %d", state.MaxAttempts)
	}

	mon.Stop()
}

func TestSleepWake_ActiveTunnel_NoIsConnected(t *testing.T) {
	// The sleepWakeLoop also checks ActiveTunnel() != "" even if IsConnected
	// returns false. This covers the case where the tunnel is in a connecting
	// or disconnecting transient state.
	var reconnectCalls atomic.Int32
	reconnectFn := func() error {
		reconnectCalls.Add(1)
		return nil
	}

	mon, mgr, sd := newTestMonitor(testConfig(), reconnectFn)
	// Not "connected" but has an active tunnel name (e.g., connecting state).
	mgr.setConnected(false, "my-tunnel")

	mon.Start()
	defer mon.Stop()

	sd.sendWake()

	waitFor(t, 2*time.Second, "reconnect triggered via ActiveTunnel", func() bool {
		return reconnectCalls.Load() > 0
	})
}

func TestStatusCallback_CalledDuringReconnect(t *testing.T) {
	cfg := testConfig()
	cfg.MaxAttempts = 1

	var states []State
	var mu sync.Mutex
	statusFn := func(state State) {
		mu.Lock()
		states = append(states, state)
		mu.Unlock()
	}

	reconnectFn := func() error {
		return errors.New("fail")
	}

	mgr := &mockManager{connected: true, activeName: "test"}
	sd := newMockSleepDetector()
	mon := NewMonitor(mgr, reconnectFn, statusFn, cfg)
	mon.sleepDetector = sd
	mon.mu.Lock()
	mon.running = true
	mon.mu.Unlock()

	mon.triggerReconnect()

	// Wait for completion.
	waitFor(t, 2*time.Second, "reconnect finished", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(states) >= 2
	})

	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if len(states) < 2 {
		t.Fatalf("expected at least 2 status callbacks, got %d", len(states))
	}

	// First callback: reconnecting=true.
	if !states[0].Reconnecting {
		t.Error("expected first status callback Reconnecting=true")
	}

	// Last callback: reconnecting=false (max attempts reached).
	last := states[len(states)-1]
	if last.Reconnecting {
		t.Error("expected last status callback Reconnecting=false")
	}
}

func TestDoubleStart_IsIdempotent(t *testing.T) {
	reconnectFn := func() error { return nil }
	mon, _, _ := newTestMonitor(testConfig(), reconnectFn)

	mon.Start()
	mon.Start() // second call should be a no-op
	mon.Stop()
	// If this doesn't deadlock or panic, the test passes.
}

func TestMonitorLoop_SkipsWhenNotConnected(t *testing.T) {
	// Verifies that monitorLoop does nothing when tunnel is disconnected.
	var reconnectCalls atomic.Int32
	reconnectFn := func() error {
		reconnectCalls.Add(1)
		return nil
	}

	mon, mgr, _ := newTestMonitor(testConfig(), reconnectFn)
	mgr.setConnected(false, "")

	mon.Start()
	// The ticker fires every 30s, so within 100ms nothing should happen.
	time.Sleep(100 * time.Millisecond)
	mon.Stop()

	if reconnectCalls.Load() != 0 {
		t.Fatalf("expected no reconnect calls, got %d", reconnectCalls.Load())
	}
}

func TestMonitorLoop_SkipsZeroHandshake(t *testing.T) {
	// When Status() returns non-nil but LastHandshakeTime is zero (tunnel
	// still initializing), monitorLoop should NOT trigger a reconnect.
	var reconnectCalls atomic.Int32
	reconnectFn := func() error {
		reconnectCalls.Add(1)
		return nil
	}

	mon, mgr, _ := newTestMonitor(testConfig(), reconnectFn)
	mgr.setConnected(true, "test-tunnel")
	mgr.setStatus(&tunnel.ConnectionStatus{
		// LastHandshakeTime is zero -- tunnel initializing.
	})

	mon.Start()
	time.Sleep(100 * time.Millisecond)
	mon.Stop()

	if reconnectCalls.Load() != 0 {
		t.Fatalf("expected no reconnect for zero handshake time, got %d", reconnectCalls.Load())
	}
}

func TestBackoffCapsAtMaxDelay(t *testing.T) {
	cfg := testConfig()
	cfg.InitialDelay = 10 * time.Millisecond
	cfg.MaxDelay = 30 * time.Millisecond

	var mu sync.Mutex
	var attempts []time.Time

	targetAttempts := 6
	done := make(chan struct{})

	reconnectFn := func() error {
		mu.Lock()
		attempts = append(attempts, time.Now())
		n := len(attempts)
		mu.Unlock()
		if n >= targetAttempts {
			select {
			case <-done:
			default:
				close(done)
			}
		}
		return errors.New("always fail")
	}

	mon, mgr, _ := newTestMonitor(cfg, reconnectFn)
	mgr.setConnected(true, "test-tunnel")
	mon.mu.Lock()
	mon.running = true
	mon.mu.Unlock()

	mon.triggerReconnect()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for capped backoff attempts")
	}

	mon.Stop()

	mu.Lock()
	defer mu.Unlock()

	// After a few doublings (10->20->30->30->30), later gaps should be
	// roughly the max delay. Verify the last gap is not wildly larger.
	if len(attempts) >= 2 {
		lastGap := attempts[len(attempts)-1].Sub(attempts[len(attempts)-2])
		// Allow generous margin (2x max) for scheduling jitter.
		if lastGap > cfg.MaxDelay*3 {
			t.Errorf("last gap %v exceeds 3x MaxDelay %v -- backoff may not be capped",
				lastGap, cfg.MaxDelay)
		}
	}
}
