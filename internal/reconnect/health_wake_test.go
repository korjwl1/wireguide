package reconnect

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/tunnel"
)

// onlineDetector is a NetworkChangeDetector that also reports Online.
type onlineDetector struct {
	online atomic.Bool
	ch     chan struct{}
}

func newOnlineDetector(online bool) *onlineDetector {
	d := &onlineDetector{ch: make(chan struct{}, 1)}
	d.online.Store(online)
	return d
}

func (d *onlineDetector) Start()                      {}
func (d *onlineDetector) Stop()                       {}
func (d *onlineDetector) ChangeChan() <-chan struct{} { return d.ch }
func (d *onlineDetector) Online() bool                { return d.online.Load() }

// plainDetector has no Online method.
type plainDetector struct{}

func (plainDetector) Start()                      {}
func (plainDetector) Stop()                       {}
func (plainDetector) ChangeChan() <-chan struct{} { return nil }

// fakeClock is safe to read from the monitor's goroutines while a test
// advances it.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}

type reconnectRecorder struct {
	mu    sync.Mutex
	calls []string
}

func (r *reconnectRecorder) fn(_ context.Context, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, name)
	return nil
}

func (r *reconnectRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func (r *reconnectRecorder) sawName(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.calls {
		if c == name {
			return true
		}
	}
	return false
}

// healthMonitor builds a running-flagged monitor (no ticker or trigger
// goroutines) with a fake clock and a connected tunnel "t1" whose last
// handshake is hs. The network detector is always replaced so the real
// poller never reports the host's actual network state.
func healthMonitor(t *testing.T, rec *reconnectRecorder, clk *fakeClock, hs time.Time, nd NetworkChangeDetector) (*Monitor, *mockManager) {
	t.Helper()
	mon, mgr, _ := newTestMonitor(testConfig(), rec.fn)
	mon.networkDetector = nd
	mon.now = clk.Now
	mon.SetHealthCheck(true)
	mgr.setConnected(true, "t1")
	mgr.setStatus(&tunnel.ConnectionStatus{
		TunnelName:        "t1",
		State:             domain.StateConnected,
		LastHandshakeTime: hs,
	})
	mon.mu.Lock()
	mon.running = true
	mon.stopCh = make(chan struct{})
	mon.mu.Unlock()
	t.Cleanup(func() {
		mon.CancelRetry()
		mon.mu.Lock()
		mon.running = false
		close(mon.stopCh)
		mon.mu.Unlock()
		mon.wg.Wait()
	})
	return mon, mgr
}

func TestHealthCheck_StaleHandshakeTriggers(t *testing.T) {
	rec := &reconnectRecorder{}
	now := time.Unix(1_000_000, 0)
	clk := &fakeClock{t: now}
	mon, _ := healthMonitor(t, rec, clk, now.Add(-4*time.Minute), newOnlineDetector(true))
	mon.checkHandshakes(now)
	waitFor(t, 2*time.Second, "stale handshake reconnect", func() bool { return rec.sawName("t1") })
}

func TestHealthCheck_WakeGraceSkipsThenDeadTunnelTriggers(t *testing.T) {
	rec := &reconnectRecorder{}
	wake := time.Unix(2_000_000, 0)
	clk := &fakeClock{t: wake}
	// Handshake from long before sleep.
	mon, _ := healthMonitor(t, rec, clk, wake.Add(-2*time.Hour), newOnlineDetector(true))
	mon.noteWake()

	// Inside the grace window: skipped.
	mon.checkHandshakes(wake.Add(60 * time.Second))
	// Just after grace, but less than the threshold since the wake: age is
	// measured from the wake, so still not stale (without the fix the
	// pre-sleep handshake makes it two hours old).
	mon.checkHandshakes(wake.Add(120 * time.Second))
	time.Sleep(50 * time.Millisecond)
	if rec.count() != 0 {
		t.Fatalf("health check fired within wake grace / threshold-since-wake: %d calls", rec.count())
	}

	// A genuinely dead tunnel (no handshake since wake) triggers once the
	// threshold has elapsed since the wake, i.e. within threshold + grace.
	now := wake.Add(handshakeStaleThreshold + time.Second)
	if now.Sub(wake) > handshakeStaleThreshold+wakeGrace {
		t.Fatal("test setup: beyond threshold + grace")
	}
	mon.checkHandshakes(now)
	waitFor(t, 2*time.Second, "dead tunnel reconnect after grace", func() bool { return rec.sawName("t1") })
}

func TestHealthCheck_RecentHandshakeAfterWakeNotStale(t *testing.T) {
	rec := &reconnectRecorder{}
	wake := time.Unix(3_000_000, 0)
	clk := &fakeClock{t: wake}
	mon, mgr := healthMonitor(t, rec, clk, wake.Add(-2*time.Hour), newOnlineDetector(true))
	mon.noteWake()
	// Tunnel handshook after the wake.
	mgr.setStatus(&tunnel.ConnectionStatus{TunnelName: "t1", State: domain.StateConnected, LastHandshakeTime: wake.Add(100 * time.Second)})
	mon.checkHandshakes(wake.Add(200 * time.Second))
	time.Sleep(50 * time.Millisecond)
	if rec.count() != 0 {
		t.Fatal("fresh post-wake handshake treated as stale")
	}
}

func TestHealthCheck_OfflineSuppressed(t *testing.T) {
	rec := &reconnectRecorder{}
	now := time.Unix(4_000_000, 0)
	clk := &fakeClock{t: now}
	nd := newOnlineDetector(false)
	mon, _ := healthMonitor(t, rec, clk, now.Add(-10*time.Minute), nd)
	mon.checkHandshakes(now)
	time.Sleep(50 * time.Millisecond)
	if rec.count() != 0 {
		t.Fatal("health check ran while offline")
	}
	mon.mu.Lock()
	queued := len(mon.retries)
	mon.mu.Unlock()
	if queued != 0 {
		t.Fatalf("offline health check queued %d retries", queued)
	}
	nd.online.Store(true)
	mon.checkHandshakes(now)
	waitFor(t, 2*time.Second, "reconnect once back online", func() bool { return rec.sawName("t1") })
}

func TestHealthCheck_DetectorWithoutOnlineCountsAsOnline(t *testing.T) {
	rec := &reconnectRecorder{}
	now := time.Unix(5_000_000, 0)
	clk := &fakeClock{t: now}
	mon, _ := healthMonitor(t, rec, clk, now.Add(-10*time.Minute), plainDetector{})
	mon.checkHandshakes(now)
	waitFor(t, 2*time.Second, "reconnect without online reporter", func() bool { return rec.sawName("t1") })
}

func TestHealthCheck_NilDetectorCountsAsOnline(t *testing.T) {
	rec := &reconnectRecorder{}
	now := time.Unix(5_500_000, 0)
	clk := &fakeClock{t: now}
	mon, _ := healthMonitor(t, rec, clk, now.Add(-10*time.Minute), nil)
	mon.checkHandshakes(now)
	waitFor(t, 2*time.Second, "reconnect without detector", func() bool { return rec.sawName("t1") })
}

func TestWakeRecordedForHealthCheckGrace(t *testing.T) {
	for _, connected := range []bool{true, false} {
		name := "connected"
		if !connected {
			name = "disconnected"
		}
		t.Run(name, func(t *testing.T) {
			rec := &reconnectRecorder{}
			wake := time.Unix(6_000_000, 0)
			clk := &fakeClock{t: wake}
			mon, mgr, sd := newTestMonitor(testConfig(), rec.fn)
			mon.networkDetector = newOnlineDetector(true)
			mon.now = clk.Now
			if connected {
				mgr.setConnected(true, "t1")
			}
			mon.Start()
			defer mon.Stop()

			sd.sendWake()
			waitFor(t, 2*time.Second, "wake recorded", func() bool {
				mon.mu.Lock()
				defer mon.mu.Unlock()
				return mon.lastWake.Equal(wake)
			})
		})
	}
}

// A stale tick during the wake retry's InitialDelay / route preflight must
// not start a per-tunnel retry alongside it: each retry suspends DNS
// protection and the kill switch independently.
func TestHealthCheck_StaleTickDuringWakeRetryStartsNoTunnelRetry(t *testing.T) {
	rec := &reconnectRecorder{}
	wake := time.Unix(7_000_000, 0)
	clk := &fakeClock{t: wake}
	mon, mgr, sd := newTestMonitor(testConfig(), rec.fn)
	mon.networkDetector = newOnlineDetector(true)
	mon.now = clk.Now
	mon.SetHealthCheck(true)
	mgr.setConnected(true, "t1")
	mgr.setStatus(&tunnel.ConnectionStatus{
		TunnelName:        "t1",
		State:             domain.StateConnected,
		LastHandshakeTime: wake.Add(-2 * time.Hour),
	})

	var preflightNames sync.Map
	waiting, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	mon.SetReconnectPreflight(func(ctx context.Context, name string) error {
		preflightNames.Store(name, true)
		if name == "" {
			once.Do(func() { close(waiting) })
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-release:
			}
		}
		return nil
	})
	mon.Start()
	defer mon.Stop()
	defer close(release)

	sd.sendWake()
	select {
	case <-waiting:
	case <-time.After(2 * time.Second):
		t.Fatal("wake retry never reached preflight")
	}

	// Tick while the "" retry is still in flight, past threshold + grace so
	// the tunnel is genuinely stale by the wake-relative measure.
	now := wake.Add(handshakeStaleThreshold + wakeGrace + time.Second)
	clk.Set(now)
	mon.checkHandshakes(now)

	mon.mu.Lock()
	tunnelRetry := mon.retries["t1"]
	wakeRetry := mon.retries[""]
	mon.mu.Unlock()
	if tunnelRetry != nil {
		t.Fatal("stale tick started a per-tunnel retry alongside the wake retry")
	}
	if wakeRetry == nil {
		t.Fatal("stale tick displaced the in-flight wake retry")
	}
	time.Sleep(50 * time.Millisecond)
	if _, ok := preflightNames.Load("t1"); ok || rec.sawName("t1") {
		t.Fatal("per-tunnel retry ran during the wake retry")
	}
}

// A stale tick must leave an existing per-tunnel retry alone: restarting it
// would reset its backoff and re-suspend DNS protection and the kill switch.
func TestHealthCheck_StaleTickKeepsExistingTunnelRetry(t *testing.T) {
	rec := &reconnectRecorder{}
	now := time.Unix(8_000_000, 0)
	clk := &fakeClock{t: now}
	mon, _ := healthMonitor(t, rec, clk, now.Add(-4*time.Minute), newOnlineDetector(true))

	cancelled := false
	existing := &retryState{cancel: func() { cancelled = true }, done: make(chan struct{})}
	mon.mu.Lock()
	mon.retries["t1"] = existing
	mon.mu.Unlock()
	t.Cleanup(func() {
		mon.mu.Lock()
		delete(mon.retries, "t1")
		mon.mu.Unlock()
	})

	mon.checkHandshakes(now)

	mon.mu.Lock()
	current := mon.retries["t1"]
	mon.mu.Unlock()
	if current != existing {
		t.Fatal("stale tick replaced the existing per-tunnel retry")
	}
	if cancelled {
		t.Fatal("stale tick cancelled the existing per-tunnel retry")
	}
	time.Sleep(50 * time.Millisecond)
	if rec.sawName("t1") {
		t.Fatal("stale tick started a reconnect alongside the existing retry")
	}
}
